// Hosted vendor upstreams (OpenAI, Anthropic), tested without leaving the machine: each hosted
// origin is pinned to a loopback TLS server whose certificate names the vendor's host and is
// signed by a CA made for the test. No provider key, no hosted call, no spend.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { request } from 'node:http';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createModelTap, TapLog, HOSTED_ORIGINS, upstreamKind } from './tap.mjs';
import { readTapLog, modelIdentity } from './identity.mjs';
import { compareModelIdentities, attributeComparison } from './attribute.mjs';

const OPENAI_KEY = 'sk-test-not-a-real-key-4f2a';
const ANTHROPIC_KEY = 'anthropic-test-not-a-real-key-9c1e';
const PROMPT = 'hosted-prompt-canary-61d0';
const REPLY = 'hosted-reply-canary-b7e3';

// One self-signed certificate naming both vendor hosts, trusted only by these tests.
let tls = null;
test.before(async () => {
  const dir = await mkdtemp(join(tmpdir(), 'w6 hosted tls '));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'), '-days', '1',
    '-subj', '/CN=scopehaven-test', '-addext', 'subjectAltName=DNS:api.openai.com,DNS:api.anthropic.com'], { stdio: 'ignore' });
  tls = { dir, key: await readFile(join(dir, 'key.pem')), cert: await readFile(join(dir, 'cert.pem')) };
});
test.after(async () => { if (tls) await rm(tls.dir, { recursive: true, force: true }); });

// A loopback TLS server standing in for a vendor; it records what reached it.
async function fakeVendor(t, handler) {
  const seen = [];
  const server = createServer({ key: tls.key, cert: tls.cert }, (req, res) => {
    const chunks = []; req.on('data', c => chunks.push(c));
    req.on('end', () => { const body = Buffer.concat(chunks); seen.push({ method: req.method, url: req.url, headers: req.headers, body }); handler(req, res, body); });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections?.(); server.close(resolve); }));
  return { port: server.address().port, seen };
}
async function hostedTap(t, origin, vendor, options = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'w6 hosted tap ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'tap.jsonl');
  const tap = createModelTap({ upstream: origin, log: new TapLog({ path }), testPinToLoopback: { port: vendor.port, ca: tls.cert }, ...options });
  await tap.start(); t.after(() => tap.stop());
  return { tap, path };
}
function send(base, path, body, headers = {}) {
  const url = new URL(path, base), data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = request(url, { method: 'POST', agent: false, headers: { host: url.host, 'content-type': 'application/json', 'content-length': data.length, ...headers } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject); req.end(data);
  });
}
const json = (res, obj) => { const text = JSON.stringify(obj); res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) }); res.end(text); };
const sse = (res, events) => { res.writeHead(200, { 'content-type': 'text/event-stream' }); res.end(events.map(e => `data: ${typeof e === 'string' ? e : JSON.stringify(e)}\n\n`).join('')); };

test('only the declared vendor origins are accepted as hosted upstreams', () => {
  assert.deepEqual([...HOSTED_ORIGINS], ['https://api.openai.com', 'https://api.anthropic.com']);
  assert.equal(upstreamKind('https://api.openai.com'), 'hosted');
  assert.equal(upstreamKind('https://api.anthropic.com'), 'hosted');
  assert.equal(upstreamKind('http://127.0.0.1:11434'), 'loopback');
  for (const bad of ['https://api.openai.com/', 'https://api.openai.com/v1', 'http://api.openai.com', 'https://api.openai.com:8443', 'https://API.OPENAI.COM',
    'https://evil.example', 'https://api.openai.com.evil.example', 'https://127.0.0.1:443', 'https://user@api.openai.com', 'http://localhost:11434', '',
    // Accepted only when the declared string is already its own origin: :80 would be logged without its port.
    'http://127.0.0.1:80']) {
    assert.equal(upstreamKind(bad), null, bad);
    assert.throws(() => createModelTap({ upstream: bad }), /upstream/, bad);
  }
});

test('a hosted upstream has no model list, and the loopback pin is for hosted upstreams only', async t => {
  assert.throws(() => createModelTap({ upstream: 'https://api.openai.com', ollamaTags: true }), /no model list/);
  assert.throws(() => createModelTap({ upstream: 'http://127.0.0.1:11434', testPinToLoopback: { port: 1, ca: 'x' } }), /hosted upstream/);
  for (const pin of [null, { port: 0, ca: 'x' }, { port: 70000, ca: 'x' }, { port: 1.5, ca: 'x' }, { port: '443', ca: 'x' }, { port: 443 }, { port: 443, ca: '' }, { port: 443, ca: 7 }]) assert.throws(() => createModelTap({ upstream: 'https://api.openai.com', testPinToLoopback: pin }), /testPinToLoopback/);
  // Starting a hosted tap makes no outbound request: the model list is not asked for.
  const dir = await mkdtemp(join(tmpdir(), 'w6 hosted start ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const tap = createModelTap({ upstream: 'https://api.openai.com', log: new TapLog({ path: join(dir, 'tap.jsonl') }) });
  await tap.start(); await tap.stop();
  const frames = readTapLog(join(dir, 'tap.jsonl'));
  assert.equal(frames[0].upstream, 'https://api.openai.com'); assert.equal(frames[0].ollamaTags, false);
  assert.deepEqual(frames.filter(f => f.kind === 'models').map(f => f.reason), ['not-requested', 'not-requested']);
});

test('OpenAI over the hosted path: keys pass through untouched, nothing but readings is logged', async t => {
  let fingerprint = 'fp_a1';
  const vendor = await fakeVendor(t, (req, res, body) => {
    const j = JSON.parse(body.toString());
    if (req.url === '/v1/responses') return sse(res, [{ type: 'response.created', response: { model: 'gpt-x-2026-09-01' } }, { type: 'response.output_text.delta', delta: REPLY }]);
    if (j.stream) return sse(res, [{ id: 'c', model: 'gpt-x-2026-09-01', system_fingerprint: fingerprint, choices: [{ delta: { content: REPLY } }] }, '[DONE]']);
    json(res, { id: 'c', model: 'gpt-x-2026-09-01', system_fingerprint: fingerprint, choices: [{ message: { content: REPLY } }] });
  });
  const { tap, path } = await hostedTap(t, 'https://api.openai.com', vendor);
  const auth = { authorization: `Bearer ${OPENAI_KEY}` };
  assert.equal((await send(tap.url, '/v1/chat/completions', { model: 'gpt-x', messages: [{ role: 'user', content: PROMPT }] }, auth)).status, 200);
  const streamed = await send(tap.url, '/v1/chat/completions', { model: 'gpt-x', stream: true, messages: [{ role: 'user', content: PROMPT }] }, auth);
  assert.match(streamed.body, new RegExp(REPLY));
  await tap.stop();
  // The vendor saw its own Host, the caller's key and the exact body; the tap kept none of them.
  for (const s of vendor.seen) { assert.equal(s.headers.host, 'api.openai.com'); assert.equal(s.headers.authorization, `Bearer ${OPENAI_KEY}`); assert.equal(s.headers['accept-encoding'], 'identity'); }
  assert.match(vendor.seen[0].body.toString(), new RegExp(PROMPT));
  const raw = await readFile(path, 'utf8');
  for (const secret of [OPENAI_KEY, PROMPT, REPLY]) assert.ok(!raw.includes(secret), secret);
  const id = modelIdentity(readTapLog(path));
  assert.equal(id.state, 'observed'); assert.equal(id.strength, 'vendor-fingerprint'); assert.equal(id.upstreamKind, 'hosted');
  assert.equal(id.upstream, 'https://api.openai.com'); assert.deepEqual(id.models.map(m => [m.served, m.weightsDigest]), [['gpt-x-2026-09-01', null]]);

  // The Responses API names its model in response.created.
  const second = await hostedTap(t, 'https://api.openai.com', vendor);
  await send(second.tap.url, '/v1/responses', { model: 'gpt-x', stream: true, input: PROMPT }, auth);
  await second.tap.stop();
  assert.deepEqual(modelIdentity(readTapLog(second.path)).models.map(m => m.served), ['gpt-x-2026-09-01']);
});

test('Anthropic over the hosted path: x-api-key and anthropic-version pass through; message_start names the model', async t => {
  const vendor = await fakeVendor(t, (req, res, body) => {
    const j = JSON.parse(body.toString());
    if (j.stream) return sse(res, [{ type: 'message_start', message: { id: 'm', model: 'claude-x-20260901' } }, { type: 'content_block_delta', delta: { text: REPLY } }, { type: 'message_stop' }]);
    json(res, { id: 'm', type: 'message', model: 'claude-x-20260901', content: [{ type: 'text', text: REPLY }] });
  });
  const { tap, path } = await hostedTap(t, 'https://api.anthropic.com', vendor);
  const headers = { 'x-api-key': ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' };
  await send(tap.url, '/v1/messages', { model: 'claude-x', max_tokens: 10, messages: [{ role: 'user', content: PROMPT }] }, headers);
  await send(tap.url, '/v1/messages', { model: 'claude-x', max_tokens: 10, stream: true, messages: [{ role: 'user', content: PROMPT }] }, headers);
  await tap.stop();
  for (const s of vendor.seen) { assert.equal(s.headers.host, 'api.anthropic.com'); assert.equal(s.headers['x-api-key'], ANTHROPIC_KEY); assert.equal(s.headers['anthropic-version'], '2023-06-01'); }
  const raw = await readFile(path, 'utf8');
  for (const secret of [ANTHROPIC_KEY, PROMPT, REPLY]) assert.ok(!raw.includes(secret), secret);
  const id = modelIdentity(readTapLog(path));
  assert.equal(id.state, 'observed'); assert.equal(id.strength, 'vendor-model-string'); assert.equal(id.upstreamKind, 'hosted');
  assert.deepEqual(id.models.map(m => m.served), ['claude-x-20260901']); assert.equal(id.calls.succeeded, 2);
});

test('a silent hosted update is seen by its fingerprint, and the credit says it rests on the vendor\'s reading', async t => {
  let fingerprint = 'fp_a1';
  const vendor = await fakeVendor(t, (req, res) => json(res, { model: 'gpt-x-2026-09-01', system_fingerprint: fingerprint, choices: [] }));
  const run = async () => { const h = await hostedTap(t, 'https://api.openai.com', vendor); await send(h.tap.url, '/v1/chat/completions', { model: 'gpt-x', messages: [] }); await h.tap.stop(); return modelIdentity(readTapLog(h.path)); };
  const before = await run(); fingerprint = 'fp_b2'; const after = await run();
  const cmp = compareModelIdentities(before, after);
  assert.equal(cmp.relation, 'silent-change'); assert.equal(cmp.strength, 'vendor-fingerprint');
  const rows = { compatible: true, controlsPass: true, reasons: [], baselineId: 'b', candidateId: 'c', restorationLabel: 'Restored', rows: [{ id: 'x', title: 'x', before: 'fail', after: 'pass', transition: 'contract-restored' }] };
  assert.equal(attributeComparison(rows, { baselineIdentity: before, candidateIdentity: after, app: { changed: false, evidence: 'build-hash', basis: 't' } }).flipCause, 'model');
  // Same name, same fingerprint: credited to the app, with the vendor-reading caveat in the label.
  const same = attributeComparison(rows, { baselineIdentity: after, candidateIdentity: await run(), app: { changed: true, evidence: 'build-hash', basis: 't' } });
  assert.equal(same.flipCause, 'app'); assert.match(same.restorationLabel, /vendor's model string and fingerprint/);
});

test('the same model name served locally and by a vendor is never the same model', async t => {
  const vendor = await fakeVendor(t, (req, res) => json(res, { model: 'gpt-oss:20b', choices: [] }));
  const h = await hostedTap(t, 'https://api.openai.com', vendor);
  await send(h.tap.url, '/v1/chat/completions', { model: 'gpt-oss:20b', messages: [] }); await h.tap.stop();
  const hosted = modelIdentity(readTapLog(h.path));
  const local = { ...hosted, upstream: 'http://127.0.0.1:11434', upstreamKind: 'loopback', tapSession: 'local-session' };
  assert.equal(compareModelIdentities(local, hosted).relation, 'different');
});

test('a TLS certificate the tap does not trust is an upstream error, never a pass-through', async t => {
  const vendor = await fakeVendor(t, (req, res) => json(res, { model: 'gpt-x', choices: [] }));
  const dir = await mkdtemp(join(tmpdir(), 'w6 hosted badca ')); t.after(() => rm(dir, { recursive: true, force: true }));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'), '-days', '1', '-subj', '/CN=other', '-addext', 'subjectAltName=DNS:api.openai.com'], { stdio: 'ignore' });
  const { tap, path } = await hostedTap(t, 'https://api.openai.com', vendor, { testPinToLoopback: { port: vendor.port, ca: await readFile(join(dir, 'c.pem')) } });
  assert.equal((await send(tap.url, '/v1/chat/completions', { model: 'gpt-x', messages: [] })).status, 502);
  await tap.stop();
  assert.equal(vendor.seen.length, 0);
  const id = modelIdentity(readTapLog(path));
  assert.equal(id.state, 'partial'); assert.ok(id.reasons.includes('upstream-error'));
});

test('the CLI accepts a declared vendor origin and refuses any other https host', async t => {
  const cli = fileURLToPath(new URL('./cli.mjs', import.meta.url));
  const dir = await mkdtemp(join(tmpdir(), 'w6 hosted cli ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const run = (args, wait) => new Promise(resolve => {
    const child = spawn(process.execPath, [cli, 'tap', ...args], { env: {}, stdio: ['ignore', 'pipe', 'pipe'] });
    t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
    let out = '', err = '';
    child.stdout.on('data', d => { out += d; if (wait && out.includes('\n')) child.kill('SIGTERM'); });
    child.stderr.on('data', d => { err += d; });
    child.on('exit', code => resolve({ code, out, err }));
  });
  const bad = await run(['--upstream', 'https://evil.example', '--log', join(dir, 'bad.jsonl')], false);
  assert.equal(bad.code, 2); assert.match(bad.err, /upstream/);
  const ok = await run(['--upstream', 'https://api.anthropic.com', '--log', join(dir, 'ok.jsonl')], true);
  assert.equal(ok.code, 0); assert.equal(JSON.parse(ok.out.split('\n')[0]).upstream, 'https://api.anthropic.com');
  assert.equal(readTapLog(join(dir, 'ok.jsonl'))[0].ollamaTags, false);
});

test('certificate checking stays on whatever the environment says', async t => {
  const vendor = await fakeVendor(t, (req, res) => json(res, { model: 'gpt-x', choices: [] }));
  const dir = await mkdtemp(join(tmpdir(), 'w6 hosted envca ')); t.after(() => rm(dir, { recursive: true, force: true }));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'), '-days', '1', '-subj', '/CN=other', '-addext', 'subjectAltName=DNS:api.openai.com'], { stdio: 'ignore' });
  const previous = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  t.after(() => { if (previous === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED; else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previous; });
  const { tap } = await hostedTap(t, 'https://api.openai.com', vendor, { testPinToLoopback: { port: vendor.port, ca: await readFile(join(dir, 'c.pem')) } });
  assert.equal((await send(tap.url, '/v1/chat/completions', { model: 'gpt-x', messages: [] })).status, 502);
  assert.equal(vendor.seen.length, 0);
});

test('each call records the token counts its reply reports, never more', async t => {
  const vendor = await fakeVendor(t, (req, res, body) => {
    const j = JSON.parse(body.toString());
    if (req.url === '/v1/messages') return j.stream
      // A later event reporting a smaller count never lowers what was already reported (the largest is kept).
      ? sse(res, [{ type: 'message_start', message: { model: 'claude-x', usage: { input_tokens: 120, output_tokens: 1 } } }, { type: 'content_block_delta', delta: { text: REPLY } }, { type: 'message_delta', usage: { input_tokens: 5, output_tokens: 33 } }, { type: 'message_stop' }])
      : json(res, { model: 'claude-x', usage: { input_tokens: 110, output_tokens: 22, cache_creation_input_tokens: 7, cache_read_input_tokens: 300 } });
    if (req.url === '/v1/responses') return j.stream
      ? sse(res, [{ type: 'response.created', response: { model: 'gpt-x' } }, { type: 'response.completed', response: { model: 'gpt-x', usage: { input_tokens: 210, output_tokens: 44 } } }])
      : json(res, { model: 'gpt-x', usage: { input_tokens: 200, output_tokens: 40 } });
    if (j.stream) return sse(res, [{ model: 'gpt-x', choices: [{ delta: { content: REPLY } }] }, { model: 'gpt-x', choices: [], usage: { prompt_tokens: 310, completion_tokens: 55 } }, '[DONE]']);
    if (j.model === 'no-usage') return json(res, { model: 'gpt-x', choices: [] });
    if (j.model === 'bad-usage') return json(res, { model: 'gpt-x', usage: { prompt_tokens: -5, completion_tokens: 'many' }, choices: [] });
    if (j.model === 'half-usage') return json(res, { model: 'gpt-x', usage: { completion_tokens: 9 }, choices: [] });
    json(res, { model: 'gpt-x', usage: { prompt_tokens: 300, completion_tokens: 50 }, choices: [] });
  });
  const usageOf = async (origin, calls) => {
    const { tap, path } = await hostedTap(t, origin, vendor);
    for (const [route, body] of calls) await send(tap.url, route, body);
    await tap.stop();
    return readTapLog(path).filter(f => f.kind === 'result').map(f => f.usage ?? null);
  };
  assert.deepEqual(await usageOf('https://api.openai.com', [
    ['/v1/chat/completions', { model: 'gpt-x', messages: [] }], ['/v1/chat/completions', { model: 'gpt-x', stream: true, messages: [] }],
    ['/v1/responses', { model: 'gpt-x', input: 'x' }], ['/v1/responses', { model: 'gpt-x', stream: true, input: 'x' }],
    ['/v1/chat/completions', { model: 'no-usage', messages: [] }], ['/v1/chat/completions', { model: 'bad-usage', messages: [] }],
    ['/v1/chat/completions', { model: 'half-usage', messages: [] }],
  ]), [{ input: 300, output: 50 }, { input: 310, output: 55 }, { input: 200, output: 40 }, { input: 210, output: 44 }, null, null, { input: null, output: 9 }]);
  assert.deepEqual(await usageOf('https://api.anthropic.com', [
    ['/v1/messages', { model: 'claude-x', max_tokens: 5, messages: [] }], ['/v1/messages', { model: 'claude-x', max_tokens: 5, stream: true, messages: [] }],
  ]), [{ input: 417, output: 22 }, { input: 120, output: 33 }]);
});
