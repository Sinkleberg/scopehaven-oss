// PUT / PATCH / DELETE sequence steps through the loopback-only transport.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startMiniHelpdesk, startFakeModel } from './fixtures/mini-helpdesk.mjs';
import { createHoldGate } from './gate.mjs';
import { runSequence, validateSequence, SEQUENCE_SCHEMA } from './sequence.mjs';
import { validateSequenceRun } from './run-validator.mjs';
// Every run a test produces is also recomputed from the windows it sealed, as a saved run would be.
const recheck = (run, seq) => assert.deepEqual(validateSequenceRun(JSON.parse(JSON.stringify(run)), { expectedSequence: seq }).results.map(r => r.verdict), run.results.map(r => r.verdict));
import { observeHttpMethod, sequenceTransport, actorCsrf, withActorCsrf } from './transport.mjs';
import { createSqliteAuditObserver } from '../observers/sqlite.mjs';

const env = { SCOPEHAVEN_TARGET_SAM: 'synthetic-sam-token-3', SCOPEHAVEN_TARGET_OLGA: 'synthetic-olga-token-3' };
const actors = { sam: { principalId: 'agent-sam', credentialEnv: 'SCOPEHAVEN_TARGET_SAM' }, olga: { principalId: 'owner-olga', credentialEnv: 'SCOPEHAVEN_TARGET_OLGA' } };
const patchSequence = () => ({
  schema: SEQUENCE_SCHEMA, id: 'MIDTASK-PATCH', actors,
  steps: [
    { request: { id: 'task', actorId: 'sam', method: 'POST', path: '/api/assistant/run', body: {}, timeoutMs: 15000 }, background: true },
    { awaitHold: { rule: 'model', as: 'plan' } },
    { request: { id: 'suspend', actorId: 'olga', method: 'PATCH', path: '/api/users/agent-sam', body: { suspended: true } } },
    { expectStatus: { request: 'suspend', in: [200] } },
    { mark: 'revoked' }, { release: { hold: 'plan' } }, { awaitResponse: { request: 'task' } }, { mark: 'after' },
  ],
  assertions: [{ id: 'MIDTASK-NOTE', title: 'No note after a PATCH suspension', severity: 'critical', from: 'revoked', to: 'after',
    effect: { kind: 'effect.none', select: { source: 'sql-audit-table', actor: 'agent-sam', name: 'note.create' } } }],
});
async function harness(t, recheckAtCommit) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-methods-'));
  const model = await startFakeModel();
  const gate = createHoldGate({ upstream: model.url, rules: [{ id: 'model', method: 'POST', pathPrefix: '/v1/chat' }] }); await gate.start();
  const dbPath = join(dir, 'helpdesk.db');
  const app = await startMiniHelpdesk({ dbPath, modelUrl: `${gate.url}/v1/chat`, recheckAtCommit, tokens: { 'agent-sam': env.SCOPEHAVEN_TARGET_SAM, 'owner-olga': env.SCOPEHAVEN_TARGET_OLGA } });
  const audit = createSqliteAuditObserver({ path: dbPath, principals: ['agent-sam', 'owner-olga'], audit: { table: 'audit_log', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', actions: { 'note.create': 'insert' } } });
  t.after(async () => { await gate.stop(); await app.stop(); await model.stop(); rmSync(dir, { recursive: true, force: true }); });
  return { app, gate, audit };
}

// The repaired build's absence rests only on the app's audit table, so custody holds it at inconclusive (src/custody.mjs).
test('a PATCH access change between hold and release: the defective build fails, the repaired build fails nothing', async t => {
  for (const [recheckAtCommit, expected] of [[false, 'fail'], [true, 'inconclusive']]) {
    const { app, gate, audit } = await harness(t, recheckAtCommit);
    const run = await runSequence(patchSequence(), { origin: app.origin, observers: [audit], gate, env });
    recheck(run, patchSequence());
    assert.equal(run.aborted, null);
    assert.ok(run.timeline.some(e => e.step === 'response' && e.request === 'suspend' && e.status === 200));
    assert.equal(run.results[0].verdict, expected);
  }
});

test('a PATCH the app refuses stops the sequence before release (the access change must take effect)', async t => {
  const { app, gate, audit } = await harness(t, false);
  const seq = patchSequence();
  seq.steps[2] = { request: { id: 'suspend', actorId: 'sam', method: 'PATCH', path: '/api/users/agent-sam', body: { suspended: true } } }; // not an owner: 403
  const run = await runSequence(seq, { origin: app.origin, observers: [audit], gate, env });
  recheck(run, seq);
  assert.equal(run.aborted, 'precondition-failed:suspend');
  assert.notEqual(run.results[0].verdict, 'pass');
});

test('validation accepts GET, POST, PUT, PATCH and DELETE request steps only', () => {
  const seq = patchSequence();
  for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) validateSequence({ ...seq, steps: [{ request: { id: 'r', actorId: 'sam', method, path: '/x' } }, { mark: 'revoked' }, { mark: 'after' }] });
  for (const method of ['TRACE', 'CONNECT', 'patch']) assert.throws(() => validateSequence({ ...seq, steps: [{ request: { id: 'r', actorId: 'sam', method, path: '/x' } }, { mark: 'revoked' }, { mark: 'after' }] }), /request/);
});

test('the PUT/PATCH/DELETE transport keeps the connector bounds: loopback only, no redirects, size caps, timeout, credentials', async t => {
  let seen = [];
  const server = createServer((req, res) => {
    const c = []; req.on('data', d => c.push(d)); req.on('end', () => {
      seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, cookie: req.headers.cookie, body: Buffer.concat(c).toString() });
      if (req.url === '/redirect') { res.writeHead(302, { Location: 'http://example.com/' }).end(); return; }
      if (req.url === '/big') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ x: 'y'.repeat(70000) })); return; }
      if (req.url === '/slow') return; // never answers
      if (req.url === '/empty') { res.writeHead(204).end(); return; }
      res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  const origin = `http://127.0.0.1:${server.address().port}`;
  let r = await observeHttpMethod(origin, { method: 'PATCH', path: '/users/1', body: { suspended: true } }, { credential: 'tok-1' });
  assert.equal(r.status, 200); assert.equal(r.json.ok, true);
  assert.deepEqual([seen.at(-1).method, seen.at(-1).auth, seen.at(-1).body], ['PATCH', 'Bearer tok-1', '{"suspended":true}']);
  await observeHttpMethod(origin, { method: 'DELETE', path: '/sessions/1' }, { credential: 'c1', credentialCookie: 'sid' });
  assert.deepEqual([seen.at(-1).method, seen.at(-1).cookie], ['DELETE', 'sid=c1']);
  r = await observeHttpMethod(origin, { method: 'PUT', path: '/redirect' });
  assert.equal(r.status, 302); assert.equal(seen.filter(s => s.url === '/').length, 0); // not followed
  r = await observeHttpMethod(origin, { method: 'PUT', path: '/big' });
  assert.equal(r.error, 'too-large');
  r = await observeHttpMethod(origin, { method: 'PUT', path: '/slow' }, { timeoutMs: 200 });
  assert.equal(r.error, 'timeout');
  r = await observeHttpMethod(origin, { method: 'DELETE', path: '/empty' });
  assert.deepEqual([r.status, r.complete, r.jsonParsed], [204, true, false]);
  for (const bad of ['http://localhost:9', 'http://example.com:80', 'http://127.0.0.1:0']) assert.throws(() => observeHttpMethod(bad, { method: 'PUT', path: '/' }), /local origin/);
  assert.throws(() => observeHttpMethod(origin, { method: 'PUT', path: '//evil.example/x' }), /local origin/);
  assert.throws(() => observeHttpMethod(origin, { method: 'PUT', path: 'http://evil.example/x' }), /local origin/);
  assert.throws(() => observeHttpMethod(origin, { method: 'GET', path: '/' }), /method/);
  assert.throws(() => observeHttpMethod(origin, { method: 'PUT', path: '/', body: { x: 'y'.repeat(9000) } }), /limit/);
  assert.throws(() => observeHttpMethod(origin, { method: 'PUT', path: '/' }, { credential: 'bad value' }), /Credential/);
  assert.throws(() => observeHttpMethod(origin, { method: 'PUT', path: '/' }, { credential: 'x', credentialCookie: 'bad name' }), /cookie/);
  // GET and POST still go through the connector's observeHttp.
  r = await sequenceTransport(origin, { method: 'GET', path: '/ok' }, {});
  assert.equal(r.status, 200);
});

test('L8 fix 6a: an actor\'s CSRF pair goes out as its header and its cookie on every method; nothing else changes', async t => {
  const seen = [];
  const server = createServer((req, res) => { const c = []; req.on('data', d => c.push(d)); req.on('end', () => {
    seen.push({ method: req.method, auth: req.headers.authorization, cookie: req.headers.cookie, csrf: req.headers['x-csrf-token'], body: Buffer.concat(c).toString() });
    res.writeHead(200, { 'Content-Type': 'application/json' }).end('{"ok":true}'); }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  const origin = `http://127.0.0.1:${server.address().port}`, csrf = { header: 'X-CSRF-Token', cookie: 'csrf_token', value: 'csrf-1' };
  for (const [method, body] of [['GET', undefined], ['POST', { q: 1 }], ['PATCH', { s: true }], ['DELETE', undefined]]) {
    const r = await observeHttpMethod(origin, { method, path: '/x', ...(body ? { body } : {}) }, { credential: 'tok-1', csrf });
    assert.equal(r.status, 200, method);
    assert.deepEqual(seen.at(-1), { method, auth: 'Bearer tok-1', cookie: 'csrf_token=csrf-1', csrf: 'csrf-1', body: body ? JSON.stringify(body) : '' });
  }
  // With a cookie login, one Cookie header carries both, the credential's first.
  await observeHttpMethod(origin, { method: 'POST', path: '/x', body: {} }, { credential: 'c1', credentialCookie: 'sid', csrf });
  assert.deepEqual([seen.at(-1).auth, seen.at(-1).cookie, seen.at(-1).csrf], [undefined, 'sid=c1; csrf_token=csrf-1', 'csrf-1']);
  // Without a pair the transport is as it was: GET is refused here and goes through the connector's observeHttp instead.
  assert.throws(() => observeHttpMethod(origin, { method: 'GET', path: '/' }), /method/);
  for (const [options, check, pattern] of [
    [{ credential: 'tok', csrf: { ...csrf, header: 'Authorization' } }, { method: 'GET', path: '/' }, /CSRF/],
    [{ credential: 'tok', csrf: { ...csrf, header: 'x-http-method-override' } }, { method: 'GET', path: '/' }, /CSRF/],
    [{ credential: 'tok', credentialCookie: 'csrf_token', csrf }, { method: 'GET', path: '/' }, /CSRF/],
    [{ credential: 'tok', csrf: { ...csrf, value: 'a;b' } }, { method: 'GET', path: '/' }, /CSRF/],
    [{ csrf }, { method: 'GET', path: '/' }, /CSRF/],
    [{ credential: 'tok', csrf }, { method: 'GET', path: '/', body: {} }, /GET/]]) assert.throws(() => observeHttpMethod(origin, check, options), pattern, JSON.stringify(options));
  // actorCsrf: one pair per declaring actor, keyed by how its credential is presented; refusals name the actor.
  const env = { SCOPEHAVEN_TARGET_A: 'tok-a', SCOPEHAVEN_TARGET_B: 'tok-b', SCOPEHAVEN_TARGET_A_CSRF: 'csrf-a' };
  const decl = { env: 'SCOPEHAVEN_TARGET_A_CSRF', header: 'X-CSRF-Token', cookie: 'csrf_token' };
  const seq = actors => ({ actors });
  assert.equal(actorCsrf(seq({ a: { principalId: 'a', credentialEnv: 'SCOPEHAVEN_TARGET_A' } }), env), null);
  const pairs = actorCsrf(seq({ a: { principalId: 'a', credentialEnv: 'SCOPEHAVEN_TARGET_A', csrf: decl }, b: { principalId: 'b', credentialEnv: 'SCOPEHAVEN_TARGET_B' } }), env);
  assert.deepEqual([...pairs], [['\ntok-a', { header: 'X-CSRF-Token', cookie: 'csrf_token', value: 'csrf-a' }]]);
  for (const [actors, pattern] of [
    [{ a: { principalId: 'a', credentialEnv: 'SCOPEHAVEN_TARGET_A', csrf: { ...decl, extra: 1 } } }, /exactly env, header and cookie/],
    [{ a: { principalId: 'a', credentialEnv: 'SCOPEHAVEN_TARGET_A', csrf: { ...decl, env: 'HOME' } } }, /namespace/],
    [{ a: { principalId: 'a', csrf: decl } }, /needs a credentialEnv/],
    [{ a: { principalId: 'a', credentialEnv: 'SCOPEHAVEN_TARGET_A', csrf: { ...decl, env: 'SCOPEHAVEN_TARGET_UNSET' } } }, /not set/],
    [{ a: { principalId: 'a', credentialEnv: 'SCOPEHAVEN_TARGET_A', csrf: { ...decl, header: 'Cookie' } } }, /header/],
    [{ a: { principalId: 'a', credentialEnv: 'SCOPEHAVEN_TARGET_A', csrf: decl }, a2: { principalId: 'a2', credentialEnv: 'SCOPEHAVEN_TARGET_A', csrf: { ...decl, env: 'SCOPEHAVEN_TARGET_B' } } }, /same credential/]])
    assert.throws(() => actorCsrf(seq(actors), env), pattern, JSON.stringify(actors));
  assert.throws(() => actorCsrf(seq({ a: { principalId: 'a', credentialEnv: 'SCOPEHAVEN_TARGET_A', csrf: decl } }), { ...env, SCOPEHAVEN_TARGET_A_CSRF: 'has space' }), /format/);
  // withActorCsrf: the declaring actor's requests carry the pair; another actor's go to the base transport unchanged.
  const base = []; const send = withActorCsrf(pairs, (o, c, opts) => { base.push(opts.credential); return sequenceTransport(o, c, opts); });
  await send(origin, { method: 'GET', path: '/a' }, { credential: 'tok-a' });
  assert.equal(seen.at(-1).csrf, 'csrf-a');
  await send(origin, { method: 'GET', path: '/b' }, { credential: 'tok-b' });
  assert.deepEqual([seen.at(-1).csrf, seen.at(-1).cookie, base], [undefined, undefined, ['tok-b']]);
  assert.equal(withActorCsrf(null, sequenceTransport), sequenceTransport);
});
