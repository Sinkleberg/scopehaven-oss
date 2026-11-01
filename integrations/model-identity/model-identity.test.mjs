import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { connect } from 'node:net';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm, stat, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createModelTap, TapLog, createResponseReader, ollamaName, TAP_SCHEMA } from './tap.mjs';
import { readTapLog, modelIdentity } from './identity.mjs';
import { compareModelIdentities, attributeComparison, appChangedBetween } from './attribute.mjs';
import { main, parseArgs } from './cli.mjs';
import { runAssessment, compareRuns } from '../../src/runner.mjs';
import { createStore } from '../../src/store.mjs';

const PROMPT_CANARY = 'prompt-canary-7f3a91';
const RESPONSE_CANARY = 'response-canary-c4d2e8';
const sha256 = buf => createHash('sha256').update(buf).digest('hex');
const CLI = fileURLToPath(new URL('./cli.mjs', import.meta.url));

// A loopback model server speaking the shapes the tap reads. Deterministic: the
// same request always gets the same bytes, so a forwarded reply can be compared
// byte for byte with a direct one.
async function startUpstream(t, initial = {}) {
  const state = { tags: initial.tags ?? [{ name: 'qwen3.5:9b-q4_K_M', digest: 'a'.repeat(64) }, { name: 'gemma4:latest', digest: 'b'.repeat(64) }],
    alias: initial.alias ?? { 'gpt-x': 'gpt-x-2026-09-01' }, fingerprint: initial.fingerprint ?? 'fp_one', seen: [] };
  const served = m => state.alias[m] ?? m;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      state.seen.push({ method: req.method, url: req.url, headers: req.headers, body: raw });
      let body = {}; try { body = raw ? JSON.parse(raw) : {}; } catch {}
      const json = (status, obj, extra = {}) => { const text = JSON.stringify(obj); res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text), ...extra }); res.end(text); };
      const sse = events => { res.writeHead(200, { 'content-type': 'text/event-stream' }); for (const e of events) res.write(e); res.end(); };
      if (req.method === 'GET' && req.url === '/api/tags' && state.tagsDelayMs) { setTimeout(() => json(200, { models: state.tags.map(m => ({ name: m.name, model: m.name, digest: m.digest, size: 1 })) }), state.tagsDelayMs); return; }
      if (req.method === 'GET' && req.url === '/api/tags') return json(200, { models: state.tags.map(m => ({ name: m.name, model: m.name, digest: m.digest, size: 1 })) });
      if (req.method === 'GET' && req.url === '/api/version') return json(200, { version: '0.0.0-test' });
      if (req.url === '/api/pull') return json(200, { status: 'success' });
      if (req.url === '/v1/other-thing') return json(200, { ok: true });
      if (body.model === 'missing') return json(404, { error: { message: 'model not found' } });
      if (body.model === 'gzip') { const z = gzipSync(JSON.stringify({ model: 'gzip', choices: [] })); res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip', 'content-length': z.length }); return res.end(z); }
      if (body.model === 'badjson') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end('{bad'); }
      if (body.model === 'plain') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('hello'); }
      if (body.model === 'nomodel') return json(200, { id: 'x', choices: [{ message: { content: RESPONSE_CANARY } }] });
      if (body.model === 'slowjson') { const text = JSON.stringify({ model: 'slowjson', choices: [] }); res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) }); res.write(text.slice(0, 5)); setTimeout(() => res.end(text.slice(5)), 150); return; }
      if (body.model === 'slowstream') { res.writeHead(200, { 'content-type': 'text/event-stream' }); res.write(`data: ${JSON.stringify({ model: 'slowstream' })}\n\n`); const timer = setInterval(() => { if (!res.destroyed) res.write(': keepalive\n\n'); }, 20); res.on('close', () => clearInterval(timer)); return; }
      if (body.model === 'abort') { res.writeHead(200, { 'content-type': 'text/event-stream' }); res.write(`data: ${JSON.stringify({ model: 'abort' })}\n\n`); setTimeout(() => res.socket.destroy(), 20); return; }
      if (body.model === 'twomodels') return sse([`data: ${JSON.stringify({ model: 'm-one' })}\n\n`, `data: ${JSON.stringify({ model: 'm-two' })}\n\n`, 'data: [DONE]\n\n']);
      if (req.url === '/v1/chat/completions' || req.url === '/v1/completions' || req.url === '/v1/embeddings') {
        if (body.stream) return sse([`data: ${JSON.stringify({ id: 'c1', model: served(body.model), system_fingerprint: state.fingerprint, choices: [{ delta: { content: RESPONSE_CANARY } }] })}\n\n`,
          `data: ${JSON.stringify({ id: 'c1', model: served(body.model), system_fingerprint: state.fingerprint, choices: [{ delta: {}, finish_reason: 'stop' }] })}\n\n`, 'data: [DONE]\n\n']);
        return json(200, { id: 'c1', object: 'chat.completion', model: served(body.model), system_fingerprint: state.fingerprint, choices: [{ message: { role: 'assistant', content: RESPONSE_CANARY } }] });
      }
      if (req.url === '/v1/responses') {
        if (body.stream) return sse([`event: response.created\ndata: ${JSON.stringify({ type: 'response.created', response: { id: 'r1', model: served(body.model) } })}\n\n`,
          `event: response.output_text.delta\ndata: ${JSON.stringify({ type: 'response.output_text.delta', delta: RESPONSE_CANARY })}\n\n`]);
        return json(200, { id: 'r1', object: 'response', model: served(body.model), output: [{ content: [{ text: RESPONSE_CANARY }] }] });
      }
      if (req.url === '/v1/messages') {
        if (body.stream) return sse([`event: message_start\ndata: ${JSON.stringify({ type: 'message_start', message: { id: 'm1', type: 'message', model: served(body.model) } })}\n\n`,
          `event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', delta: { text: RESPONSE_CANARY } })}\n\n`, `event: message_stop\ndata: ${JSON.stringify({ type: 'message_stop' })}\n\n`]);
        return json(200, { id: 'm1', type: 'message', model: served(body.model), content: [{ type: 'text', text: RESPONSE_CANARY }] });
      }
      if (req.url === '/api/chat' || req.url === '/api/generate') {
        const stream = body.stream !== false;
        if (!stream) return json(200, { model: body.model, message: { content: RESPONSE_CANARY }, done: true });
        res.writeHead(200, { 'content-type': 'application/x-ndjson' });
        res.write(`${JSON.stringify({ model: body.model, message: { content: RESPONSE_CANARY }, done: false })}\n`);
        res.end(`${JSON.stringify({ model: body.model, message: { content: '' }, done: true })}\n`);
        return;
      }
      if (req.url === '/api/embed') return json(200, { model: body.model, embeddings: [[0.1]] });
      json(404, { error: 'unknown' });
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { state, origin: `http://127.0.0.1:${server.address().port}`, port: server.address().port };
}

function call(base, path, body, { method = 'POST', headers = {} } = {}) {
  const url = new URL(path, base);
  const data = body === undefined ? null : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = request(url, { method, agent: false, headers: { host: url.host, ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}), ...headers } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks), aborted: true }));
    });
    req.on('error', error => resolve({ status: 0, error }));
    if (data) req.write(data); req.end();
  });
}

async function startTap(t, upstream, options = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'model tap test '));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'tap.jsonl');
  const tap = createModelTap({ upstream: upstream.origin, log: new TapLog({ path }), ...options });
  await tap.start();
  t.after(() => tap.stop());
  return { tap, path, dir };
}
const chat = (model, extra = {}) => ({ model, messages: [{ role: 'user', content: PROMPT_CANARY }], ...extra });

test('every supported API shape is forwarded byte for byte and its served model recorded', async t => {
  const up = await startUpstream(t);
  const { tap, path } = await startTap(t, up);
  const cases = [
    ['/v1/chat/completions', chat('gpt-x'), 'openai-chat', false, ['gpt-x-2026-09-01'], ['fp_one']],
    ['/v1/chat/completions', chat('gpt-x', { stream: true }), 'openai-chat', true, ['gpt-x-2026-09-01'], ['fp_one']],
    ['/v1/responses', { model: 'gpt-x', input: PROMPT_CANARY }, 'openai-responses', false, ['gpt-x-2026-09-01'], []],
    ['/v1/responses', { model: 'gpt-x', input: PROMPT_CANARY, stream: true }, 'openai-responses', true, ['gpt-x-2026-09-01'], []],
    ['/v1/messages', chat('claude-y'), 'anthropic-messages', false, ['claude-y'], []],
    ['/v1/messages', chat('claude-y', { stream: true }), 'anthropic-messages', true, ['claude-y'], []],
    ['/api/chat', chat('qwen3.5:9b-q4_K_M'), 'ollama-chat', true, ['qwen3.5:9b-q4_K_M'], []],
    ['/api/chat', chat('qwen3.5:9b-q4_K_M', { stream: false }), 'ollama-chat', false, ['qwen3.5:9b-q4_K_M'], []],
    ['/api/generate', { model: 'gemma4', prompt: PROMPT_CANARY }, 'ollama-generate', true, ['gemma4'], []],
    ['/api/embed', { model: 'gemma4', input: PROMPT_CANARY }, 'ollama-embed', false, ['gemma4'], []],
    ['/v1/embeddings', { model: 'gpt-x', input: PROMPT_CANARY }, 'openai-embeddings', false, ['gpt-x-2026-09-01'], ['fp_one']],
  ];
  for (const [p, body, api, stream, served, fingerprints] of cases) {
    const direct = await call(up.origin, p, body), via = await call(tap.url, p, body, { headers: { 'x-test-via': 'tap' } });
    assert.equal(via.status, direct.status, p);
    assert.deepEqual(via.body, direct.body, `${p} body must pass through unchanged`);
    const frames = tap.log.frames, c = frames.filter(f => f.kind === 'call').at(-1), r = frames.filter(f => f.kind === 'result' && f.conn === c.conn)[0];
    assert.equal(c.api, api); assert.equal(c.stream, stream); assert.equal(c.requested, body.model);
    assert.equal(c.reqSha256, sha256(Buffer.from(JSON.stringify(body)))); assert.equal(c.reqBytes, Buffer.byteLength(JSON.stringify(body)));
    assert.deepEqual(r.served, served, p); assert.deepEqual(r.fingerprints, fingerprints, p);
    assert.equal(r.respSha256, sha256(via.body)); assert.equal(r.status, 200); assert.equal(r.gap, undefined, p);
  }
  // The upstream was asked for an unencoded reply, and got the original body.
  const forwarded = up.state.seen.filter(s => s.headers['x-test-via'] === 'tap');
  assert.equal(forwarded.length, cases.length);
  assert.ok(forwarded.every(s => s.headers['accept-encoding'] === 'identity'));
  await tap.stop();
  const text = await readFile(path, 'utf8');
  assert.ok(!text.includes(PROMPT_CANARY) && !text.includes(RESPONSE_CANARY), 'prompt and response content are never written');
  assert.equal((await stat(path)).mode & 0o777, 0o600);
});

test('a non-streaming JSON reply reaches the application only after its result is logged', async t => {
  const up = await startUpstream(t);
  const { tap } = await startTap(t, up);
  const before = tap.log.seq;
  // The upstream sends half the body, waits, then the rest. The client must not
  // see the response at all until the result frame is in the log.
  const seenAtHeaders = await new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(chat('slowjson')));
    const url = new URL('/v1/chat/completions', tap.url);
    const req = request(url, { method: 'POST', agent: false, headers: { host: url.host, 'content-type': 'application/json', 'content-length': data.length } }, res => {
      const logged = tap.log.frames.some(f => f.kind === 'result' && f.seq > before);
      res.resume(); res.on('end', () => resolve(logged));
    });
    req.on('error', reject); req.end(data);
  });
  assert.equal(seenAtHeaders, true);
});

test('the first model list is written before the tap accepts a call', async t => {
  const up = await startUpstream(t);
  up.state.tagsDelayMs = 150;
  const dir = await mkdtemp(join(tmpdir(), 'model tap order ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'tap.jsonl');
  const tap = createModelTap({ upstream: up.origin, log: new TapLog({ path }) });
  const started = tap.start();
  // Call as soon as the tap has a URL; while the list is still loading it has none.
  while (!tap.url) await new Promise(resolve => setTimeout(resolve, 5));
  await call(tap.url, '/api/chat', chat('gemma4', { stream: false }));
  await started; up.state.tagsDelayMs = 0;
  await tap.stop();
  const frames = readTapLog(path);
  assert.ok(frames.find(f => f.kind === 'models' && f.phase === 'start').seq < frames.find(f => f.kind === 'call').seq);
  assert.equal(modelIdentity(frames).strength, 'weights-digest');
});

test('a client that hangs up mid-stream leaves a gap, and the upstream call is closed', async t => {
  const up = await startUpstream(t);
  const { tap, path } = await startTap(t, up);
  await new Promise(resolve => {
    const data = Buffer.from(JSON.stringify(chat('slowstream', { stream: true })));
    const url = new URL('/v1/chat/completions', tap.url);
    const req = request(url, { method: 'POST', agent: false, headers: { host: url.host, 'content-type': 'application/json', 'content-length': data.length } }, res => {
      res.once('data', () => { req.destroy(); setTimeout(resolve, 80); });
    });
    req.on('error', () => {}); req.end(data);
  });
  await tap.stop();
  const id = modelIdentity(readTapLog(path));
  assert.equal(id.state, 'partial'); assert.ok(id.reasons.includes('client-closed'), String(id.reasons));
  assert.equal(tap.inflight, 0);
});

test('a request over the size limit is refused with 413 and logged as a gap', async t => {
  const up = await startUpstream(t);
  const { tap, path } = await startTap(t, up);
  const big = Buffer.alloc(64 * 1024 * 1024 + 1, 0x20);
  const res = await call(tap.url, '/v1/chat/completions', big.toString('latin1'));
  assert.equal(res.status, 413);
  await tap.stop();
  assert.ok(modelIdentity(readTapLog(path)).reasons.includes('request-too-large'));
  assert.ok(!up.state.seen.some(s => s.url === '/v1/chat/completions'));
});

test('model lists bracket the log: weights digest when stable, replaced-in-window when not', async t => {
  const up = await startUpstream(t);
  const { tap, path } = await startTap(t, up);
  await call(tap.url, '/api/chat', chat('qwen3.5:9b-q4_K_M', { stream: false }));
  await tap.stop();
  const id = modelIdentity(readTapLog(path));
  assert.equal(id.state, 'observed'); assert.equal(id.strength, 'weights-digest');
  assert.equal(id.models[0].weightsDigest, 'a'.repeat(64)); assert.equal(id.models[0].served, 'qwen3.5:9b-q4_K_M');

  const up2 = await startUpstream(t);
  const second = await startTap(t, up2);
  await call(second.tap.url, '/api/chat', chat('qwen3.5:9b-q4_K_M', { stream: false }));
  up2.state.tags[0].digest = 'c'.repeat(64); // re-pulled under the same name
  await second.tap.stop();
  const replaced = modelIdentity(readTapLog(second.path));
  assert.equal(replaced.state, 'partial'); assert.ok(replaced.reasons.includes('model-replaced-in-window'));
  assert.deepEqual(replaced.replaced, [{ served: 'qwen3.5:9b-q4_K_M', before: 'a'.repeat(64), after: 'c'.repeat(64) }]);
  assert.equal(replaced.models[0].weightsDigest, null);
});

test('a model that leaves or joins the list during the window is partial', async t => {
  const up = await startUpstream(t);
  const { tap, path } = await startTap(t, up);
  await call(tap.url, '/api/chat', chat('gemma4', { stream: false }));
  up.state.tags = up.state.tags.filter(m => m.name !== 'gemma4:latest');
  await tap.stop();
  const id = modelIdentity(readTapLog(path));
  assert.equal(id.state, 'partial'); assert.ok(id.reasons.includes('model-list-changed-in-window'));
});

test('weights are named only for an Ollama-style list; other servers stay at the vendor reading', async t => {
  const up = await startUpstream(t);
  const { tap, path } = await startTap(t, up, { ollamaTags: false });
  await call(tap.url, '/v1/chat/completions', chat('qwen3.5:9b-q4_K_M'));
  await tap.stop();
  const id = modelIdentity(readTapLog(path));
  assert.equal(id.state, 'observed'); assert.equal(id.strength, 'vendor-fingerprint'); assert.equal(id.models[0].weightsDigest, null);
  assert.equal(ollamaName('llama3'), 'llama3:latest'); assert.equal(ollamaName('a:b'), 'a:b'); assert.equal(ollamaName(''), null);
});

test('anything the tap cannot vouch for makes the window partial', async t => {
  const up = await startUpstream(t);
  const cases = [
    [c => call(c, '/v1/other-thing', {}), 'unrecognized-route'],
    [c => call(c, '/api/pull', { model: 'qwen3.5:9b-q4_K_M' }), 'model-admin-call'],
    [c => call(c, '/v1/chat/completions', chat('gzip')), 'encoded-response'],
    [c => call(c, '/v1/completions', chat('plain')), 'unrecognized-response-type'],
    [c => call(c, '/v1/chat/completions', chat('badjson')), 'unparsable-response'],
    [c => call(c, '/v1/chat/completions', chat('abort', { stream: true })), 'response-aborted'],
    [c => call(c, '/v1/chat/completions', '{not json'), null],
  ];
  for (const [send, reason] of cases) {
    const { tap, path } = await startTap(t, up);
    await send(tap.url);
    await new Promise(resolve => setTimeout(resolve, 60));
    await tap.stop();
    const id = modelIdentity(readTapLog(path));
    if (reason) { assert.equal(id.state, 'partial', reason); assert.ok(id.reasons.includes(reason), `${reason}: ${id.reasons}`); }
    else { const c = readTapLog(path).find(f => f.kind === 'call'); assert.equal(c.requestUnparsed, true); assert.equal(c.requested, null); }
  }
  // Read-only metadata is logged as meta, never as a gap.
  const { tap, path } = await startTap(t, up);
  assert.equal((await call(tap.url, '/api/version', undefined, { method: 'GET' })).status, 200);
  await tap.stop();
  const id = modelIdentity(readTapLog(path));
  assert.equal(id.state, 'not-observed'); assert.deepEqual(id.reasons, []);
  assert.ok(readTapLog(path).some(f => f.kind === 'meta' && f.path === '/api/version'));
});

test('an unreachable upstream is a 502 and a gap', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'model tap down ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const probe = createServer(); await new Promise(r => probe.listen(0, '127.0.0.1', r)); const port = probe.address().port; await new Promise(r => probe.close(r));
  const tap = createModelTap({ upstream: `http://127.0.0.1:${port}`, log: new TapLog({ path: join(dir, 'tap.jsonl') }) });
  await tap.start();
  const res = await call(tap.url, '/v1/chat/completions', chat('gpt-x'));
  assert.equal(res.status, 502);
  await tap.stop();
  const id = modelIdentity(readTapLog(join(dir, 'tap.jsonl')));
  assert.equal(id.state, 'partial'); assert.ok(id.reasons.includes('upstream-error'));
  assert.equal(readTapLog(join(dir, 'tap.jsonl')).find(f => f.kind === 'models' && f.phase === 'start').available, false);
});

test('the tap only forwards to a literal loopback origin and only serves loopback requests', async t => {
  for (const bad of ['http://localhost:11434', 'https://127.0.0.1:11434', 'http://127.0.0.1:11434/v1', 'http://10.0.0.1:80', 'http://127.0.0.1:0', 'http://127.0.0.1:70000', '', undefined])
    assert.throws(() => createModelTap({ upstream: bad }), /literal loopback origin/, String(bad));
  assert.throws(() => createModelTap({ upstream: 'http://127.0.0.1:1', port: -1 }), /port/);
  const up = await startUpstream(t);
  const { tap } = await startTap(t, up);
  assert.match(tap.url, /^http:\/\/127\.0\.0\.1:\d+$/);
  const port = Number(new URL(tap.url).port);
  assert.equal((await call(tap.url, '/v1/chat/completions', chat('gpt-x'), { headers: { host: `localhost:${port}` } })).status, 403);
  assert.equal((await call(tap.url, '/v1/chat/completions', chat('gpt-x'), { headers: { origin: 'http://evil.test' } })).status, 403);
  // An absolute-form target can never move the forward off the upstream.
  const raw = await new Promise(resolve => {
    const s = connect(port, '127.0.0.1', () => s.write(`GET http://evil.test/api/tags HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`));
    let out = ''; s.on('data', d => { out += d; }); s.on('close', () => resolve(out));
  });
  assert.match(raw, /^HTTP\/1\.1 400/);
  assert.ok(!up.state.seen.some(s => s.url.includes('evil')));
});

test('a tap log is absolute, new, private and never reused', async t => {
  assert.throws(() => new TapLog({ path: 'relative.jsonl' }), /absolute/);
  const dir = await mkdtemp(join(tmpdir(), 'model tap log ')); t.after(() => rm(dir, { recursive: true, force: true }));
  await writeFile(join(dir, 'used.jsonl'), '');
  assert.throws(() => new TapLog({ path: join(dir, 'used.jsonl') }), /EEXIST/);
  const log = new TapLog({ path: join(dir, 'new.jsonl'), maxFrames: 3 });
  log.push({ kind: 'open' }); log.push({ kind: 'meta' }); log.push({ kind: 'meta' }); log.push({ kind: 'meta' }); log.close();
  const frames = readTapLog(join(dir, 'new.jsonl'));
  assert.deepEqual(frames.map(f => f.kind), ['open', 'meta', 'overflow']);
  assert.ok(modelIdentity(frames).reasons.includes('log-overflow'));
});

test('identity states: not-observed, observed, mixed, requested-only, failed calls, mid-call windows', async t => {
  const up = await startUpstream(t);
  const empty = await startTap(t, up); await empty.tap.stop();
  const none = modelIdentity(readTapLog(empty.path));
  assert.equal(none.state, 'not-observed'); assert.equal(none.key, null); assert.equal(none.strength, 'none'); assert.equal(none.routing, 'declared-by-operator');

  const mixed = await startTap(t, up);
  await call(mixed.tap.url, '/api/chat', chat('gemma4', { stream: false }));
  await call(mixed.tap.url, '/api/chat', chat('qwen3.5:9b-q4_K_M', { stream: false }));
  await call(mixed.tap.url, '/v1/chat/completions', chat('missing'));
  await mixed.tap.stop();
  const m = modelIdentity(readTapLog(mixed.path));
  assert.equal(m.state, 'mixed'); assert.deepEqual(m.models.map(x => x.served), ['gemma4', 'qwen3.5:9b-q4_K_M']);
  assert.deepEqual(m.calls, { total: 3, succeeded: 2, failed: 1, abandoned: 0 });

  const one = await startTap(t, up);
  await call(one.tap.url, '/v1/chat/completions', chat('nomodel'));
  await one.tap.stop();
  const r = modelIdentity(readTapLog(one.path));
  assert.equal(r.state, 'observed'); assert.equal(r.strength, 'requested-only'); assert.equal(r.models[0].served, null); assert.deepEqual(r.models[0].requested, ['nomodel']);

  // Several models in one stream are each recorded.
  const two = await startTap(t, up, { ollamaTags: false });
  await call(two.tap.url, '/v1/chat/completions', chat('twomodels', { stream: true }));
  await two.tap.stop();
  assert.equal(modelIdentity(readTapLog(two.path)).state, 'mixed');

  // Windows by mark: one model per window.
  const marked = await startTap(t, up);
  const m0 = await marked.tap.mark();
  await call(marked.tap.url, '/api/chat', chat('gemma4', { stream: false }));
  const m1 = await marked.tap.mark();
  await call(marked.tap.url, '/api/chat', chat('qwen3.5:9b-q4_K_M', { stream: false }));
  const m2 = await marked.tap.mark();
  const frames = marked.tap.log.frames;
  const w1 = modelIdentity(frames, { from: m0.seq, to: m1.seq }), w2 = modelIdentity(frames, { from: m1.seq, to: m2.seq });
  assert.equal(w1.state, 'observed'); assert.equal(w1.models[0].served, 'gemma4'); assert.equal(w1.strength, 'weights-digest');
  assert.equal(w2.state, 'observed'); assert.equal(w2.models[0].served, 'qwen3.5:9b-q4_K_M'); assert.equal(w2.strength, 'weights-digest');
  assert.notEqual(w1.key, w2.key);
  // A window that ends before a call's result came back is partial, never an identity.
  const callFrame = frames.find(f => f.kind === 'call' && f.seq > m1.seq);
  assert.ok(modelIdentity(frames, { from: m1.seq, to: callFrame.seq }).reasons.includes('call-without-result'));
  // A log still being written cannot be read as a whole.
  assert.ok(modelIdentity(frames).reasons.includes('tap-not-closed'));
  assert.throws(() => modelIdentity(frames, { from: 5, to: 2 }), /window/);
  assert.throws(() => modelIdentity('nope'), /array/);
});

test('a removed, reordered or unreadable log line breaks the window', async t => {
  const up = await startUpstream(t);
  const { tap, path, dir } = await startTap(t, up);
  await call(tap.url, '/v1/chat/completions', chat('missing'));
  await call(tap.url, '/api/chat', chat('gemma4', { stream: false }));
  await tap.stop();
  const lines = (await readFile(path, 'utf8')).trim().split('\n');
  assert.equal(modelIdentity(readTapLog(path)).state, 'observed');
  // Drop the line holding the 404's gap-free result: the sequence no longer follows on.
  const removed = join(dir, 'removed.jsonl'); await writeFile(removed, `${lines.filter((_, i) => i !== 3).join('\n')}\n`);
  assert.ok(modelIdentity(readTapLog(removed)).reasons.includes('log-seq-break'));
  const swapped = [...lines]; [swapped[3], swapped[4]] = [swapped[4], swapped[3]];
  const reordered = join(dir, 'reordered.jsonl'); await writeFile(reordered, `${swapped.join('\n')}\n`);
  assert.ok(modelIdentity(readTapLog(reordered)).reasons.includes('log-seq-break'));
  const garbled = join(dir, 'garbled.jsonl'); await writeFile(garbled, `${lines.map((l, i) => i === 2 ? '{oops' : l).join('\n')}\n`);
  assert.ok(modelIdentity(readTapLog(garbled)).reasons.includes('unreadable-log-line'));
  const reopened = join(dir, 'reopened.jsonl'); await writeFile(reopened, `${[...lines, JSON.stringify({ v: 1, seq: lines.length + 1, kind: 'open', schema: 'scopehaven-model-tap/1' })].join('\n')}\n`);
  assert.ok(modelIdentity(readTapLog(reopened)).reasons.includes('tap-reopened'));
});

test('weights are named only when the closing list comes after every result in the window', () => {
  const list = phase => ({ kind: 'models', phase, available: true, models: [{ name: 'q:latest', digest: 'a'.repeat(64) }] });
  const frames = [{ kind: 'open', schema: TAP_SCHEMA }, list('start'), { kind: 'call', conn: 'x', api: 'ollama-chat', requested: 'q' },
    list('stop'), { kind: 'result', conn: 'x', status: 200, served: ['q'], fingerprints: [] }, { kind: 'close' }].map((f, i) => ({ v: 1, seq: i + 1, ...f }));
  const late = modelIdentity(frames);
  assert.equal(late.state, 'partial'); assert.deepEqual(late.reasons, ['model-list-not-bracketing']); assert.equal(late.models[0].weightsDigest, null); assert.equal(late.strength, 'vendor-model-string');
  const inOrder = [frames[0], frames[1], frames[2], frames[4], frames[3], frames[5]].map((f, i) => ({ ...f, seq: i + 1 }));
  assert.equal(modelIdentity(inOrder).strength, 'weights-digest');
});

test('the response reader handles split SSE, CRLF and NDJSON chunks', () => {
  const r = createResponseReader('openai-chat', 'text/event-stream; charset=utf-8');
  const text = `data: ${JSON.stringify({ model: 'a', system_fingerprint: 'fp' })}\r\n\r\ndata: [DONE]\r\n\r\n`;
  for (const ch of text) r.push(Buffer.from(ch));
  assert.deepEqual(r.end(), { served: ['a'], fingerprints: ['fp'], usage: null, parsed: 1, unparsable: 0, invalid: 0, overLimit: false, mode: 'sse', bytes: Buffer.byteLength(text) });
  const n = createResponseReader('ollama-chat', 'application/x-ndjson');
  n.push(Buffer.from('{"model":"q"}\n{"mo')); n.push(Buffer.from('del":"q"}'));
  assert.deepEqual(n.end().served, ['q']);
  const a = createResponseReader('anthropic-messages', 'text/event-stream');
  a.push(Buffer.from(`event: message_start\ndata: ${JSON.stringify({ type: 'message_start', message: { model: 'claude-z' } })}\n\n`));
  assert.deepEqual(a.end().served, ['claude-z']);
  const bad = createResponseReader('openai-chat', 'application/json'); bad.push(Buffer.from('{bad')); assert.equal(bad.end().unparsable, 1);
});

const identity = (models, state = models.length > 1 ? 'mixed' : 'observed') => ({ state, models });
const m = (served, extra = {}) => ({ served, requested: [served], fingerprints: [], weightsDigest: null, strength: 'vendor-model-string', ...extra });

test('comparing model identities: same, different, silent change, unverifiable', () => {
  const qa = m('q', { weightsDigest: 'a'.repeat(64), strength: 'weights-digest' }), qb = m('q', { weightsDigest: 'b'.repeat(64), strength: 'weights-digest' });
  assert.deepEqual(compareModelIdentities(identity([qa]), identity([qa])), { relation: 'same', strength: 'weights-digest', reasons: [], changes: [] });
  const silent = compareModelIdentities(identity([qa]), identity([qb]));
  assert.equal(silent.relation, 'silent-change'); assert.deepEqual(silent.changes, [{ kind: 'weights-digest', served: 'q', before: 'a'.repeat(64), after: 'b'.repeat(64) }]);
  const fp = compareModelIdentities(identity([m('g', { fingerprints: ['fp1'], strength: 'vendor-fingerprint' })]), identity([m('g', { fingerprints: ['fp2'], strength: 'vendor-fingerprint' })]));
  assert.equal(fp.relation, 'silent-change'); assert.equal(fp.changes[0].kind, 'fingerprint');
  // Only one side names weights: compared at the reading both have.
  const mixedStrength = compareModelIdentities(identity([qa]), identity([m('q')]));
  assert.equal(mixedStrength.relation, 'same'); assert.equal(mixedStrength.strength, 'vendor-model-string');
  const diff = compareModelIdentities(identity([m('q')]), identity([m('g')]));
  assert.equal(diff.relation, 'different'); assert.deepEqual(diff.changes, [{ kind: 'served-models', removed: ['q'], added: ['g'] }]);
  // A whole window served by several models is never compared as a set.
  assert.equal(compareModelIdentities(identity([m('q'), m('g')]), identity([m('q')])).relation, 'unverifiable');
  for (const [a, b, reason] of [
    [identity([m('q')], 'partial'), identity([m('q')]), 'baseline-model-partial'],
    [identity([m('q')]), { state: 'not-observed', models: [] }, 'candidate-model-not-observed'],
    [identity([m(null, { requested: ['q'], strength: 'requested-only' })]), identity([m('q')]), 'baseline-served-model-not-reported'],
    [null, identity([m('q')]), 'baseline-identity-missing'],
  ]) { const r = compareModelIdentities(a, b); assert.equal(r.relation, 'unverifiable'); assert.ok(r.reasons.includes(reason), reason); }
});

const comparison = rows => ({ compatible: true, reasons: [], baselineId: 'b', candidateId: 'c', restorationLabel: 'Response contracts restored', rows: rows.map(([id, before, after, transition]) => ({ id, title: id, before, after, transition })) });

test('attribution: who gets credit for each flip', () => {
  const rows = comparison([['fix', 'fail', 'pass', 'contract-restored'], ['reg', 'pass', 'fail', 'regression'], ['keep', 'pass', 'pass', 'preserved'], ['stuck', 'fail', 'fail', 'still-failing'], ['na', 'not_applicable', 'not_applicable', 'not-applicable']]);
  const same = identity([m('q')]), other = identity([m('g')]);
  const matrix = [
    [same, same, true, 'app'], [same, same, false, 'unexplained'],
    [same, other, false, 'model'], [same, other, true, 'confounded'],
    [same, identity([m('q')], 'partial'), true, 'model-unverified'], [same, identity([m('q')], 'partial'), false, 'model-unverified'],
  ];
  for (const [a, b, changed, cause] of matrix) {
    const r = attributeComparison(rows, { baselineIdentity: a, candidateIdentity: b, app: { changed, basis: 'test', evidence: 'build-hash' } });
    assert.equal(r.flipCause, cause);
    assert.equal(r.rows.find(x => x.id === 'fix').attribution, cause); assert.equal(r.rows.find(x => x.id === 'reg').attribution, cause);
    assert.equal(r.rows.find(x => x.id === 'na').attribution, 'no-change');
    const moved = r.model.relation === 'different';
    assert.equal(r.rows.find(x => x.id === 'keep').attribution, moved ? 'held-across-model-change' : 'no-change');
    assert.equal(r.rows.find(x => x.id === 'stuck').attribution, moved ? 'failed-across-model-change' : 'no-change');
    assert.equal(r.summary[cause], 2);
    // Only an application-credited repair keeps the repair label.
    // Held constant only by the vendor's model string: credited, and the label says how little that shows.
    if (cause === 'app') { assert.match(r.restorationLabel, /^Response contracts restored \(model held constant only by the vendor's model string; a same-named vendor update would not be seen\)$/); assert.equal(r.repairCreditedToApp, true); }
    else { assert.match(r.restorationLabel, /^Not attributable to the application: /); assert.equal(r.repairCreditedToApp, false); assert.equal(r.coreRestorationLabel, 'Response contracts restored'); }
  }
  // A silent update under the same name is a model change.
  const silent = attributeComparison(rows, { baselineIdentity: identity([m('q', { weightsDigest: 'a'.repeat(64), strength: 'weights-digest' })]), candidateIdentity: identity([m('q', { weightsDigest: 'c'.repeat(64), strength: 'weights-digest' })]), app: { changed: false, basis: 'same', evidence: 'build-hash' } });
  assert.equal(silent.model.relation, 'silent-change'); assert.equal(silent.flipCause, 'model'); assert.equal(silent.rows.find(x => x.id === 'fix').attribution, 'model');
  // An incompatible comparison keeps its own label and credits nothing.
  const inc = attributeComparison({ ...rows, compatible: false, restorationLabel: 'Unverified changes', rows: rows.rows.map(r => ({ ...r, transition: 'incompatible' })) }, { baselineIdentity: same, candidateIdentity: same, app: { changed: true, basis: 't' } });
  assert.equal(inc.restorationLabel, 'Unverified changes'); assert.ok(inc.rows.every(r => r.attribution === 'incompatible')); assert.equal(inc.repairCreditedToApp, false);
  // No repaired rows: nothing to credit.
  assert.equal(attributeComparison(comparison([['keep', 'pass', 'pass', 'preserved']]), { baselineIdentity: same, candidateIdentity: same, app: { changed: true, basis: 't' } }).repairCreditedToApp, false);
  assert.throws(() => attributeComparison({}, { baselineIdentity: same, candidateIdentity: same, app: { changed: true } }), /compareRuns/);
  assert.throws(() => attributeComparison(rows, { baselineIdentity: same, candidateIdentity: same }), /app/);
});

test('appChangedBetween reads the build hash first, then the declared label; unknown counts as changed', () => {
  assert.deepEqual(appChangedBetween({ targetBuildHash: 'a', targetConfigHash: 'x' }, { targetBuildHash: 'a', targetConfigHash: 'x' }), { changed: false, evidence: 'build-hash', basis: 'same:targetBuildHash' });
  assert.deepEqual(appChangedBetween({ targetBuildHash: 'a' }, { targetBuildHash: 'b' }), { changed: true, evidence: 'build-hash', basis: 'differs:targetBuildHash' });
  assert.deepEqual(appChangedBetween({ build: 'v1', targetConfigHash: 'x' }, { build: 'v1', targetConfigHash: 'y' }), { changed: true, evidence: 'declared-label', basis: 'differs:targetConfigHash' });
  assert.deepEqual(appChangedBetween({}, {}), { changed: true, evidence: 'unknown', basis: 'build-identity-unknown' });
});

test('on real core comparisons, a model change takes the repair label away', async () => {
  const baseline = await runAssessment('demo-vulnerable'), repaired = await runAssessment('demo-repaired');
  const core = compareRuns(baseline, repaired);
  assert.equal(core.compatible, true); assert.ok(core.summary.fixed > 0);
  const app = appChangedBetween(baseline, repaired);
  assert.equal(app.changed, true);
  const q = identity([m('q', { weightsDigest: 'a'.repeat(64), strength: 'weights-digest' })]);
  const held = attributeComparison(core, { baselineIdentity: q, candidateIdentity: q, app });
  assert.equal(held.restorationLabel, core.restorationLabel); assert.equal(held.repairCreditedToApp, true);
  assert.equal(held.summary.app, core.rows.filter(r => ['fixed', 'regression', 'blocked-by-controls'].includes(r.transition)).length);
  const swapped = attributeComparison(core, { baselineIdentity: q, candidateIdentity: identity([m('g', { weightsDigest: 'b'.repeat(64), strength: 'weights-digest' })]), app });
  assert.equal(swapped.flipCause, 'confounded'); assert.equal(swapped.repairCreditedToApp, false);
  assert.match(swapped.restorationLabel, /the model changed and the application may have changed too/);
  const unseen = attributeComparison(core, { baselineIdentity: q, candidateIdentity: { state: 'not-observed', models: [] }, app });
  assert.equal(unseen.flipCause, 'model-unverified'); assert.equal(unseen.repairCreditedToApp, false);
  // The core comparison itself is untouched.
  assert.deepEqual(compareRuns(baseline, repaired), core);
});

test('CLI: argument rules, identity exit codes and attribute end to end on a core store', async t => {
  for (const bad of [[], ['nope'], ['identity'], ['identity', '--log', 'relative'], ['identity', '--log', '/x', '--from', '1'], ['identity', '--log', '/x', '--from', '-1', '--to', '2'], ['tap', '--upstream', 'http://127.0.0.1:1'], ['identity', '--log', '/x', '--log', '/y'], ['attribute', '--store', '/s']])
    assert.throws(() => parseArgs(bad), Error, JSON.stringify(bad));
  assert.deepEqual(parseArgs(['tap', '--upstream', 'http://127.0.0.1:1', '--log', '/l', '--no-ollama-tags']).options, { upstream: 'http://127.0.0.1:1', log: '/l', 'no-ollama-tags': true, port: 0 });
  const sink = () => { const s = { text: '', write(x) { s.text += x; } }; return s; };

  const up = await startUpstream(t);
  const a = await startTap(t, up); await call(a.tap.url, '/api/chat', chat('qwen3.5:9b-q4_K_M', { stream: false })); await a.tap.stop();
  const a2 = await startTap(t, up); await call(a2.tap.url, '/api/chat', chat('qwen3.5:9b-q4_K_M', { stream: false })); await a2.tap.stop();
  const b = await startTap(t, up); await call(b.tap.url, '/api/chat', chat('gemma4', { stream: false })); await b.tap.stop();
  const out = sink();
  assert.equal(await main(['identity', '--log', a.path], { stdout: out, stderr: sink() }), 0);
  assert.equal(JSON.parse(out.text).models[0].served, 'qwen3.5:9b-q4_K_M');
  const empty = await startTap(t, up); await empty.tap.stop();
  assert.equal(await main(['identity', '--log', empty.path], { stdout: sink(), stderr: sink() }), 1);
  const err = sink();
  assert.equal(await main(['identity', '--log', join(a.dir, 'missing.jsonl')], { stdout: sink(), stderr: err }), 2);

  const storeDir = await mkdtemp(join(tmpdir(), 'model attribution store ')); t.after(() => rm(storeDir, { recursive: true, force: true }));
  await chmod(storeDir, 0o700);
  const store = createStore(storeDir);
  const base = await store.save(await runAssessment('demo-vulnerable')), cand = await store.save(await runAssessment('demo-repaired'));
  const sameModel = sink();
  assert.equal(await main(['attribute', '--store', storeDir, '--baseline', base.id, '--candidate', cand.id, '--baseline-log', a.path, '--candidate-log', a2.path], { stdout: sameModel, stderr: sink() }), 0);
  assert.equal(JSON.parse(sameModel.text).repairCreditedToApp, true);
  // M22: without --locus the CLI's output carries no credit basis (it is the attribution alone).
  const noLocus = JSON.parse(sameModel.text);
  assert.equal(Object.hasOwn(noLocus, 'creditBasis'), false); assert.ok(noLocus.rows.every(r => !Object.hasOwn(r, 'creditBasis') && !Object.hasOwn(r, 'creditEvidence')));
  assert.equal(Object.hasOwn(noLocus.summary, 'creditWithdrawn'), false);
  // --locus: a repair credited to the application says what it rests on, bound to the candidate's build.
  const { classifyLocus } = await import('./locus.mjs');
  const fixedRow = compareRuns(base, cand).rows.find(r => r.transition === 'fixed');
  assert.match(cand.targetBuildHash, /^[0-9a-f]{64}$/);
  // The file holds the locus inputs; the CLI computes each reading itself (review CB-2).
  const locusFile = async observations => { const path = join(storeDir, `locus-${observations[0].outcome}.json`); await writeFile(path, JSON.stringify([{ check: { id: fixedRow.id, action: { tool: 'refund', arguments: { order: 'X' } } }, observations }])); return path; };
  const observed = outcome => ({ runId: `m-${outcome}`, appBuild: cand.targetBuildHash, actor: { kind: 'model', identity: modelIdentity(readTapLog(a2.path)) }, outcome, recordsComplete: true, evidence: { outcome: 'app-state' } });
  const eliminated = sink();
  assert.equal(await main(['attribute', '--store', storeDir, '--baseline', base.id, '--candidate', cand.id, '--baseline-log', a.path, '--candidate-log', a2.path, '--locus', await locusFile([observed('none')])], { stdout: eliminated, stderr: sink() }), 0);
  assert.equal(JSON.parse(eliminated.text).rows.find(r => r.id === fixedRow.id).creditBasis, 'by-elimination');
  const contradicted = sink();
  assert.equal(await main(['attribute', '--store', storeDir, '--baseline', base.id, '--candidate', cand.id, '--baseline-log', a.path, '--candidate-log', a2.path, '--locus', await locusFile([observed('committed')])], { stdout: contradicted, stderr: sink() }), 1);
  assert.equal(JSON.parse(contradicted.text).creditBasis.counts.contradicted, 1);
  // An earlier review, M3: a commit recorded for a row the comparison does not credit still exits 1.
  const preservedRow = compareRuns(base, cand).rows.find(r => r.transition === 'preserved');
  const outside = join(storeDir, 'locus-outside.json');
  await writeFile(outside, JSON.stringify([{ check: { id: preservedRow.id, action: { tool: 'refund', arguments: { order: 'Y' } } }, observations: [observed('committed')] }]));
  const outsideOut = sink();
  assert.equal(await main(['attribute', '--store', storeDir, '--baseline', base.id, '--candidate', cand.id, '--baseline-log', a.path, '--candidate-log', a2.path, '--locus', outside], { stdout: outsideOut, stderr: sink() }), 1);
  assert.deepEqual(JSON.parse(outsideOut.text).creditBasis.commitsOutsideCredit, [preservedRow.id]);
  // The key whitelist on its own: a valid entry with one extra key is refused (exit 2).
  const extra = join(storeDir, 'locus-extra.json');
  await writeFile(extra, JSON.stringify([{ check: { id: fixedRow.id, action: { tool: 'refund', arguments: { order: 'X' } } }, observations: [observed('none')], locus: 'enforced-by-app' }]));
  assert.equal(await main(['attribute', '--store', storeDir, '--baseline', base.id, '--candidate', cand.id, '--baseline-log', a.path, '--candidate-log', a2.path, '--locus', extra], { stdout: sink(), stderr: sink() }), 2);
  assert.throws(() => parseArgs(['attribute', '--store', '/s', '--baseline', 'b', '--candidate', 'c', '--baseline-log', '/a', '--candidate-log', '/b', '--locus', 'relative.json']), /absolute/);
  // A precomputed reading is not accepted: a reading edited to enforced-by-app would otherwise be believed.
  const forged = join(storeDir, 'locus-forged.json');
  await writeFile(forged, JSON.stringify([classifyLocus({ id: fixedRow.id, action: { tool: 'refund', arguments: { order: 'X' } } }, [observed('none')])].map(r => ({ ...r, locus: 'enforced-by-app' }))));
  assert.equal(await main(['attribute', '--store', storeDir, '--baseline', base.id, '--candidate', cand.id, '--baseline-log', a.path, '--candidate-log', a2.path, '--locus', forged], { stdout: sink(), stderr: sink() }), 2);
  const swapped = sink();
  assert.equal(await main(['attribute', '--store', storeDir, '--baseline', base.id, '--candidate', cand.id, '--baseline-log', a.path, '--candidate-log', b.path], { stdout: swapped, stderr: sink() }), 1);
  assert.equal(JSON.parse(swapped.text).flipCause, 'confounded');

  // L3: stored runs whose subject a model serves and that already carry a (stale) swapped identity.
  // The logs given decide, and the core label is attributed once.
  const { createObservedSupportApp, bindExampleProfile } = await import('../../examples/observed-support-app.mjs');
  const { runHttpAssessment } = await import('../../src/http-connector.mjs');
  const file = JSON.parse(await readFile(new URL('../../docs/profiles/response-only.example.json', import.meta.url), 'utf8'));
  const app = await createObservedSupportApp({ build: 'leaky' }); t.after(() => app.close());
  const run = async label => { const bound = bindExampleProfile(file, app).targets[0]; if (label) bound.buildLabel = label; return runHttpAssessment(bound, { env: app.env }); };
  const leaky = await run(); app.setBuild('secure'); const secure = await run('example support app, local test build 2');
  const stale = served => ({ state: 'observed', strength: 'weights-digest', tapSession: `stale-${served}`, upstream: 'http://127.0.0.1:11434', window: { from: 0, to: null }, models: [{ served, weightsDigest: served === 'q' ? 'a'.repeat(64) : 'b'.repeat(64), strength: 'weights-digest' }] });
  const httpBase = await store.save({ ...leaky, modelIdentity: stale('q') }), httpCand = await store.save({ ...secure, modelIdentity: stale('g') });
  assert.match(compareRuns(httpBase, httpCand).restorationLabel, /^Not attributable/);
  const once = sink();
  assert.equal(await main(['attribute', '--store', storeDir, '--baseline', httpBase.id, '--candidate', httpCand.id, '--baseline-log', a.path, '--candidate-log', a2.path], { stdout: once, stderr: sink() }), 0);
  const result = JSON.parse(once.text);
  assert.deepEqual([result.flipCause, result.repairCreditedToApp, result.coreRestorationLabel, result.restorationLabel], ['app', true, 'Response contracts restored', 'Response contracts restored']);
  assert.equal(result.model.strength, 'weights-digest');
  assert.deepEqual(result.storedIdentitySetAside, ['baseline', 'candidate']);
});

test('CLI tap: runs until a signal, refuses to reuse a log, and closes its log', async t => {
  const up = await startUpstream(t);
  const dir = await mkdtemp(join(tmpdir(), 'model tap cli ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const log = join(dir, 'tap.jsonl');
  const child = spawn(process.execPath, [CLI, 'tap', '--upstream', up.origin, '--log', log], { env: {}, stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  let childErr = ''; child.stderr.on('data', d => { childErr += d; });
  const line = await new Promise((resolve, reject) => { let buf = ''; child.stdout.on('data', d => { buf += d; if (buf.includes('\n')) resolve(buf.split('\n')[0]); }); child.on('exit', code => reject(new Error(`exited ${code}: ${childErr}`))); });
  const { tap } = JSON.parse(line);
  assert.equal((await call(tap, '/api/chat', chat('gemma4', { stream: false }))).status, 200);
  const exit = new Promise(resolve => child.on('exit', code => resolve(code)));
  child.kill('SIGTERM');
  assert.equal(await exit, 0);
  const id = modelIdentity(readTapLog(log));
  assert.equal(id.state, 'observed'); assert.equal(id.strength, 'weights-digest');
  const again = spawn(process.execPath, [CLI, 'tap', '--upstream', up.origin, '--log', log], { env: {}, stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (again.exitCode === null && again.signalCode === null) again.kill('SIGKILL'); });
  let stderr = ''; again.stderr.on('data', d => { stderr += d; });
  assert.equal(await new Promise(resolve => again.on('exit', code => resolve(code))), 2);
  assert.match(stderr, /already exists/);
});
