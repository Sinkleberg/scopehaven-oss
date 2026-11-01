// L8 fix 4: the websocket step, captures and {name} paths, and the scopehaven-sequence-run/4 record. The transport tests
// and the end-to-end runs use the owned loopback desk (fixtures/ws-desk.mjs); observers are scripted, so no other network.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { observeWebsocket, websocketWithActorCsrf, withActorCsrf, sequenceTransport } from './transport.mjs';
import { runSequence, validateSequence, websocketsOf, capturesOf, runSchemaOf, SEQUENCE_SCHEMA, SEQUENCE_RUN_SCHEMA, SEQUENCE_RUN_SCHEMA_V4 } from './sequence.mjs';
import { validateSequenceRun } from './run-validator.mjs';
import { sequenceNativeRun, exportSequenceSuite, validateSequenceNativeRun } from './native.mjs';
import { startWsDesk } from './fixtures/ws-desk.mjs';
import { main } from './cli.mjs';
import { makeEffect } from '../observers/events.mjs';
import { validateRun } from '../regression-gate/gate.mjs';
import { stampProducer } from '../../src/producer.mjs';
import { createStore } from '../../src/store.mjs';
import { digest } from '../../src/domain.mjs';
import { sequenceAuthorizationArgs } from '../../test/support/authorization.mjs';

const sha256 = text => createHash('sha256').update(text).digest('hex');
const saved = run => JSON.parse(JSON.stringify(run));
const reseal = r => { const { timeline: _t, gateTimeline: _g, createdAt: _c, durationMs: _d, runDigest: _r, ...sealed } = r; r.runDigest = digest(sealed); return r; };
const refuse = (r, code, detail, options) => assert.throws(() => validateSequenceRun(r, options), e => e.code === code && (detail === undefined || e.detail === detail), `${code} ${detail ?? ''}`);
const settle = () => new Promise(resolve => setTimeout(resolve, 100));
const env = { SCOPEHAVEN_TARGET_SAM: 'desk-token', SCOPEHAVEN_TARGET_OLGA: 'not-the-desk-token' };

// A scripted gate observer: the agent's approve call is seen in every window; nothing else.
const gateObserver = () => { let at = 0; const observer = { kind: 'hold-gate', instanceId: 'gate-1' };
  return { kind: 'hold-gate', instanceId: 'gate-1', source: 'hold-proxy', scope: Object.freeze({ operations: ['tool-call'], names: ['approve', 'refund'], actorAttribution: 'none', evidence: 'authoritative' }),
    async start() {}, async stop() {}, async mark() { return { at: ++at }; },
    async collect() { return { events: [makeEffect({ source: 'hold-proxy', observer, seq: 1, observedAt: '2026-10-30T00:00:00.000Z', operation: 'tool-call', name: 'approve', outcome: 'committed' })], coverage: 'complete', reason: null }; } }; };
const wsSequence = ({ capture = { invocation: '/websocketUUID' }, websocket = {}, wsActor = 'sam', background = false, extra = [] } = {}) => ({ schema: SEQUENCE_SCHEMA, id: 'WS-AGENT', applicationId: 'ws-desk', contextId: 'ws-desk-synthetic-v1',
  actors: { sam: { principalId: 'agent-sam', credentialEnv: 'SCOPEHAVEN_TARGET_SAM' }, olga: { principalId: 'agent-olga', credentialEnv: 'SCOPEHAVEN_TARGET_OLGA' } },
  steps: [{ mark: 'start' }, { request: { id: 'chat', actorId: 'sam', method: 'POST', path: '/api/chat', body: { text: 'approve the order' }, capture } },
    { websocket: { id: 'agent-ws', actorId: wsActor, path: '/api/agent-invocation/{invocation}', send: [{ type: 'start' }], until: { messages: 2 }, timeoutMs: 5000, ...websocket }, ...(background ? { background: true } : {}) },
    ...extra, { mark: 'end' }],
  assertions: [{ id: 'AGENT-RAN', title: 'The agent approved', severity: 'control', from: 'start', to: 'end', effect: { kind: 'effect.exists', select: { source: 'hold-proxy', operation: 'tool-call', name: 'approve' } } },
    { id: 'NO-REFUND', title: 'No refund', severity: 'critical', from: 'start', to: 'end', effect: { kind: 'effect.none', select: { source: 'hold-proxy', operation: 'tool-call', name: 'refund' } } }] });
const runOn = async (desk, seq) => saved(await runSequence(seq, { origin: desk.origin, observers: [gateObserver()], env }));
const deskFor = async (t, options) => { const desk = await startWsDesk(options); t.after(() => desk.stop()); return desk; };
const invocation = async desk => (await sequenceTransport(desk.origin, { method: 'POST', path: '/api/chat', body: {} }, { credential: 'desk-token' })).json.websocketUUID;

test('L8 fix 4: the websocket client presents the actor, offers no extension, masks what it sends and keeps only digests', async t => {
  const desk = await deskFor(t);
  const id = await invocation(desk), path = `/api/agent-invocation/${id}`;
  const all = await observeWebsocket(desk.origin, { path, send: [{ type: 'start' }] }, { credential: 'desk-token', timeoutMs: 5000 });
  const texts = [1, 2, 3].map(step => JSON.stringify({ step, invocation: id }));
  assert.deepEqual(all, { status: 101, transport: 'complete', messages: 3, closeCode: 1000, bytes: texts.join('').length, digests: texts.map(sha256) });
  assert.ok(!JSON.stringify(all).includes(id), 'message content is never returned');
  const [handshake] = desk.handshakes;
  assert.equal(handshake.headers.authorization, 'Bearer desk-token');
  assert.equal(handshake.headers['sec-websocket-extensions'], undefined, 'no permessage-deflate is offered');
  assert.equal(handshake.headers.origin, undefined);
  await settle();
  assert.deepEqual(desk.received[0], { opcode: 1, masked: true, text: '{"type":"start"}' });
  // until: { messages: 2 } ends the step at the second message; the server's close then never counts.
  const two = await observeWebsocket(desk.origin, { path, send: [{ type: 'start' }], until: { messages: 2 } }, { credential: 'desk-token', timeoutMs: 5000 });
  assert.deepEqual([two.transport, two.messages, two.closeCode, two.digests], ['complete', 2, null, texts.slice(0, 2).map(sha256)]);
  // A cookie credential and a CSRF pair ride the handshake as they ride a request.
  const csrf = { header: 'X-CSRF-Token', cookie: 'csrf_token', value: 'csrf-1' };
  const cookieDesk = await deskFor(t, { cookie: 'session', csrf });
  const pairs = new Map([['session\ndesk-token', Object.freeze(csrf)]]);
  const chat = await withActorCsrf(pairs)(cookieDesk.origin, { method: 'POST', path: '/api/chat', body: {} }, { credential: 'desk-token', credentialCookie: 'session' });
  assert.equal(chat.status, 200);
  const viaPair = await websocketWithActorCsrf(pairs)(cookieDesk.origin, { path: `/api/agent-invocation/${chat.json.websocketUUID}`, send: [{ type: 'start' }] }, { credential: 'desk-token', credentialCookie: 'session', timeoutMs: 5000 });
  assert.deepEqual([viaPair.status, viaPair.messages], [101, 3]);
  assert.deepEqual([cookieDesk.handshakes[0].headers.cookie, cookieDesk.handshakes[0].headers['x-csrf-token'], cookieDesk.handshakes[0].headers.authorization], ['session=desk-token; csrf_token=csrf-1', 'csrf-1', undefined]);
  const withoutPair = await observeWebsocket(cookieDesk.origin, { path: `/api/agent-invocation/${chat.json.websocketUUID}` }, { credential: 'desk-token', credentialCookie: 'session', timeoutMs: 5000 });
  assert.deepEqual([withoutPair.status, withoutPair.transport], [403, 'refused']);
});

test('L8 fix 4: the websocket client ends a step on its bounds, a refusal, a timeout or a frame no server may send', async t => {
  const open = async (mode, options = {}) => {
    const desk = await deskFor(t, { mode });
    const id = await invocation(desk);
    return { desk, r: await observeWebsocket(desk.origin, { path: `/api/agent-invocation/${id}`, send: [{ type: 'start' }], ...options }, { credential: 'desk-token', timeoutMs: 600 }) };
  };
  const pick = r => [r.status, r.transport, r.messages, r.closeCode];
  assert.deepEqual(pick((await open('big')).r), [101, 'too-large', 0, null], 'a message over 1 MiB');
  assert.deepEqual(pick((await open('split')).r), [101, 'too-large', 0, null], 'a message over 1 MiB in two frames');
  const flood = (await open('flood', { until: { messages: 20 } })).r;
  assert.deepEqual([flood.transport, flood.messages, flood.bytes], ['too-large', 8, 8000000], 'over 8 MiB in one step');
  assert.deepEqual(pick((await open('masked')).r), [101, 'protocol', 0, null], 'a masked server frame');
  assert.deepEqual(pick((await open('deflate')).r), [101, 'protocol', 0, null], 'an extension the client never offered');
  assert.deepEqual(pick((await open('silent')).r), [101, 'timeout', 0, null]);
  assert.deepEqual(pick((await open('drop')).r), [101, 'network', 1, null], 'ended without a close frame');
  // A ping is answered with a pong carrying its payload; the data messages still count.
  const pinged = await open('ping');
  assert.deepEqual(pick(pinged.r), [101, 'complete', 3, 1000]);
  await settle();
  assert.ok(pinged.desk.received.some(f => f.opcode === 10 && f.masked), 'a masked pong');
  // Refusals: a handshake answered 403 or 404 carries no messages; a closed port has no status.
  const desk = await deskFor(t);
  const refused = await observeWebsocket(desk.origin, { path: '/api/agent-invocation/unknown' }, { credential: 'not-the-desk-token' });
  const unknown = await observeWebsocket(desk.origin, { path: '/api/agent-invocation/unknown' }, { credential: 'desk-token' });
  assert.deepEqual([pick(refused), pick(unknown)], [[403, 'refused', 0, null], [404, 'refused', 0, null]]);
  const closed = await startWsDesk(); await closed.stop();
  assert.deepEqual(pick(await observeWebsocket(closed.origin, { path: '/x' }, {})), [null, 'network', 0, null]);
  // The origin, path and messages are checked before anything connects.
  for (const [origin, step] of [['http://localhost:1', { path: '/x' }], ['http://127.0.0.1:1', { path: '//evil.example/x' }], ['http://127.0.0.1:1', { path: 'x' }], ['http://127.0.0.1:1', { path: '/x', send: Array(17).fill({}) }]])
    assert.throws(() => observeWebsocket(origin, step, {}), /outside the configured local origin|exceed the local connector limit/, JSON.stringify([origin, step]));
  assert.throws(() => observeWebsocket(desk.origin, { path: '/x' }, { credential: 'has space' }), /unsupported format/);
});

test('L8 fix 4: a sequence declares websocket steps, captures and {name} paths under these rules', () => {
  const ok = wsSequence();
  assert.equal(validateSequence(ok), ok);
  assert.deepEqual([websocketsOf(ok), capturesOf(ok), runSchemaOf(ok)], [[{ id: 'agent-ws', actorId: 'sam' }], [{ name: 'invocation', request: 'chat' }], SEQUENCE_RUN_SCHEMA_V4]);
  // awaitResponse may wait for a background websocket; expectStatus judges requests only.
  validateSequence(wsSequence({ background: true, extra: [{ awaitResponse: { request: 'agent-ws' } }] }));
  const withSteps = steps => ({ ...ok, steps: [{ mark: 'start' }, ...steps, { mark: 'end' }] });
  const chat = (capture, path = '/api/chat') => ({ request: { id: 'chat', actorId: 'sam', method: 'POST', path, ...(capture ? { capture } : {}) } });
  const ws = (v = {}, extra = {}) => ({ websocket: { id: 'agent-ws', actorId: 'sam', path: '/api/agent-invocation/{invocation}', ...v }, ...extra });
  for (const [steps, pattern] of [
    [[ws()], /no earlier request captures/],
    [[ws(), chat({ invocation: '/websocketUUID' })], /no earlier request captures/],
    [[chat({ invocation: '/id' }, '/api/{invocation}')], /no earlier request captures/],
    [[chat({ invocation: '/id' }), ws({ path: '/api/{invocation' })], /brace outside/],
    [[chat({ invocation: '/id' }), ws({ path: '/api/}{invocation}' })], /brace outside/],
    [[chat({ invocation: '/id' }), ws({ path: '/api/{invocation}}' })], /brace outside/],
    [[chat({ invocation: '/id' }), ws({ path: '/api/{{invocation}' })], /brace outside/],
    [[chat({})], /capture needs 1 to 8/],
    [[chat({ '1bad': '/id' })], /needs a new name/],
    [[chat({ invocation: 'id' })], /JSON pointer/],
    [[chat({ invocation: '/__proto__' })], /JSON pointer/],
    [[chat({ invocation: '/id', other: '/x' }), { request: { id: 'again', actorId: 'sam', method: 'POST', path: '/api/chat', capture: { invocation: '/id' } } }], /needs a new name/],
    [[chat({ invocation: '/id' }), ws({ extra: 1 })], /websocket needs an id/],
    [[chat({ invocation: '/id' }), ws({ id: 'chat' })], /websocket needs an id/],
    [[chat({ invocation: '/id' }), ws({ actorId: 'nobody' })], /websocket needs an id/],
    [[chat({ invocation: '/id' }), ws({ path: '//evil.example/x' })], /websocket needs an id/],
    [[chat({ invocation: '/id' }), ws({ until: { messages: 0 } })], /until is/],
    [[chat({ invocation: '/id' }), ws({ until: { close: false } })], /until is/],
    [[chat({ invocation: '/id' }), ws({ until: { messages: 2, close: true } })], /until is/],
    [[chat({ invocation: '/id' }), ws({ send: Array(17).fill({}) })], /send lists up to 16/],
    [[chat({ invocation: '/id' }), ws({ timeoutMs: 600001 })], /timeoutMs/],
    [[chat({ invocation: '/id' }), ws({}, { assertStatus: { id: 'WS-OK', title: 'ok', severity: 'control', in: [101] } })], /assertStatus belongs on a request step/],
    [[chat({ invocation: '/id' }), ws(), { expectStatus: { request: 'agent-ws', in: [101] } }], /names an unknown request/],
    [[chat({ invocation: '/id' }), ws(), { request: { id: 'agent-ws', actorId: 'sam', method: 'GET', path: '/x' } }], /request/]])
    assert.throws(() => validateSequence(withSteps(steps)), pattern, JSON.stringify(steps));
  // {{name}} in double braces is left for a caller's own transport (multiturn): never read as a capture here.
  const caller = withSteps([{ request: { id: 'chat', actorId: 'sam', method: 'GET', path: '/api/tickets/{{ticketA}}' } }]);
  assert.equal(runSchemaOf(validateSequence(caller)), SEQUENCE_RUN_SCHEMA);
  // A sequence with neither writes /3, as before.
  assert.equal(runSchemaOf({ ...ok, steps: [{ mark: 'start' }, chat(), { mark: 'end' }] }), SEQUENCE_RUN_SCHEMA);
});

test('L8 fix 4: a websocket at a path built from a captured value drives the agent; the /4 run seals digests and re-validates', async t => {
  const desk = await deskFor(t);
  const seq = wsSequence();
  const run = await runOn(desk, seq);
  assert.equal(run.aborted, null);
  const [id] = desk.invocations;
  assert.equal(desk.handshakes[0].url, `/api/agent-invocation/${id}`);
  assert.equal(run.schema, SEQUENCE_RUN_SCHEMA_V4);
  assert.deepEqual(run.results.map(r => [r.id, r.status]), [['AGENT-RAN', 'pass'], ['NO-REFUND', 'pass']]);
  assert.deepEqual(run.websockets, [{ id: 'agent-ws', actorId: 'sam' }]);
  assert.deepEqual(run.websocketRecords['agent-ws'], { status: 101, transport: 'complete', messages: 2, closeCode: null, bytes: [1, 2].map(step => JSON.stringify({ step, invocation: id })).join('').length, digests: [1, 2].map(step => sha256(JSON.stringify({ step, invocation: id }))) });
  assert.deepEqual(run.captures, [{ name: 'invocation', request: 'chat', digest: digest(id) }]);
  assert.ok(!JSON.stringify(run).includes(id), 'the captured value is sealed by digest only');
  assert.match(run.limitations.at(-1), /never the content/);
  validateSequenceRun(run, { expectedSequence: seq });
  // A background websocket that the sequence awaits.
  const background = wsSequence({ background: true, extra: [{ awaitResponse: { request: 'agent-ws' } }] });
  const awaited = await runOn(desk, background);
  assert.deepEqual([awaited.aborted, awaited.websocketRecords['agent-ws'].messages], [null, 2]);
  validateSequenceRun(awaited, { expectedSequence: background });
  // Edits are refused: a record whose count disagrees with its digests, a record for an undeclared step, a refusal that
  // carries messages, a capture with no request, a /4 run with neither list, /4 fields in a /3 run.
  const edit = change => { const copy = saved(run); change(copy); return reseal(copy); };
  refuse(edit(r => { r.websocketRecords['agent-ws'].messages = 3; }), 'invalid-sequence-run', 'websocket-records');
  refuse(edit(r => { r.websocketRecords['agent-ws'].body = 'x'; }), 'invalid-sequence-run', 'websocket-records');
  refuse(edit(r => { r.websocketRecords.other = r.websocketRecords['agent-ws']; }), 'invalid-sequence-run', 'websocket-records');
  refuse(edit(r => { Object.assign(r.websocketRecords['agent-ws'], { status: 403, transport: 'refused' }); }), 'invalid-sequence-run', 'websocket-records');
  refuse(edit(r => { r.captures[0].request = 'nobody'; }), 'invalid-sequence-run', 'captures');
  refuse(edit(r => { r.captures[0].digest = 'abc'; }), 'invalid-sequence-run', 'captures');
  refuse(edit(r => { r.websockets.push({ id: 'chat', actorId: 'sam' }); }), 'invalid-sequence-run', 'websockets');
  refuse(edit(r => { r.websockets = []; r.websocketRecords = {}; r.captures = []; }), 'invalid-sequence-run', 'schema');
  refuse(edit(r => { r.schema = SEQUENCE_RUN_SCHEMA; }), 'invalid-sequence-run', 'schema');
  // Bound to the sequence: another sequence's websockets or the /3 schema for a sequence that writes /4.
  refuse(run, 'unexpected-sequence', undefined, { expectedSequence: wsSequence({ websocket: { until: { messages: 3 } } }) });
  // A sequence with neither still writes /3, with none of the /4 fields, and validates as before.
  const plain = { ...seq, steps: [{ mark: 'start' }, { request: { id: 'chat', actorId: 'sam', method: 'POST', path: '/api/chat' } }, { mark: 'end' }] };
  const v3 = await runOn(desk, plain);
  assert.equal(v3.schema, SEQUENCE_RUN_SCHEMA);
  assert.ok(['websockets', 'websocketRecords', 'captures'].every(key => !Object.hasOwn(v3, key)));
  validateSequenceRun(v3, { expectedSequence: plain });
  const stamped = saved(v3); stamped.captures = []; refuse(reseal(stamped), 'invalid-sequence-run', 'schema');
  // A saved /4 run is a native run the regression gate reads; its suite carries the /4 version.
  const native = sequenceNativeRun({ sequence: seq, run, build: 'b1' });
  assert.doesNotThrow(() => validateSequenceNativeRun(native));
  assert.equal(exportSequenceSuite(seq, [gateObserver()]).version, SEQUENCE_RUN_SCHEMA_V4);
  assert.equal(native.assertionSchemaVersion, SEQUENCE_RUN_SCHEMA_V4);
  // As the CLI saves it: the build stamp sits outside the sealed /4 run, and the stored run reads back valid with the same digest.
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven websocket store '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const store = createStore(dir);
  await store.ready;
  const stored = await store.save(stampProducer({ ...native }));
  const back = await store.get(stored.runId ?? stored.id);
  assert.ok(back.producer?.release, 'the build stamp is kept');
  assert.equal(back.sequenceEvidence.run.schema, SEQUENCE_RUN_SCHEMA_V4);
  assert.equal(back.sequenceEvidence.run.runDigest, run.runDigest);
  assert.doesNotThrow(() => validateSequenceNativeRun(back));
  assert.doesNotThrow(() => validateRun(back));
});

test('L8 fix 4: a refused handshake, an unusable capture or a broken bound stops the run, and nothing after it is judged', async t => {
  const desk = await deskFor(t);
  // Olga's credential is not the desk's: the chat (as Sam) captures the invocation, and Olga's handshake is refused.
  const refused = await runOn(desk, wsSequence({ wsActor: 'olga' }));
  assert.deepEqual([refused.aborted, refused.websocketRecords['agent-ws'].status, refused.websocketRecords['agent-ws'].transport], ['websocket-refused:agent-ws', 403, 'refused']);
  // The end mark is never reached, so neither row has a window: neither can pass.
  assert.deepEqual(refused.results.map(r => [r.id, r.verdict, r.status]), [['AGENT-RAN', 'observer-failure', 'error'], ['NO-REFUND', 'observer-failure', 'error']]);
  validateSequenceRun(refused, { expectedSequence: wsSequence({ wsActor: 'olga' }) });
  // A value that is "..", that holds a "/" or that is missing is no capture: the websocket is never opened.
  desk.handshakes.length = 0;
  for (const pointer of ['/nested/dots', '/nested/odd', '/absent', '/nested']) {
    const seq = wsSequence({ capture: { invocation: pointer } });
    const stopped = await runOn(desk, seq);
    assert.equal(stopped.aborted, 'capture-missing:invocation', pointer);
    assert.deepEqual([stopped.captures, stopped.websocketRecords], [[{ name: 'invocation', request: 'chat', digest: null }], {}], pointer);
    validateSequenceRun(stopped, { expectedSequence: seq });
  }
  assert.deepEqual(desk.handshakes, [], 'no websocket was opened without its capture');
  // A message over the bound ends the step and stops the run.
  const big = await deskFor(t, { mode: 'big' });
  const tooLarge = await runOn(big, wsSequence());
  assert.deepEqual([tooLarge.aborted, tooLarge.websocketRecords['agent-ws'].transport], ['websocket-failed:agent-ws', 'too-large']);
  validateSequenceRun(tooLarge, { expectedSequence: wsSequence() });
  // A timeout or a connection that ends after the handshake is recorded and does not stop the run: observers judge it.
  const silent = await deskFor(t, { mode: 'silent' });
  const timedOut = await runOn(silent, wsSequence({ websocket: { timeoutMs: 300 } }));
  assert.deepEqual([timedOut.aborted, timedOut.websocketRecords['agent-ws'].transport, timedOut.results.map(r => r.status)], [null, 'timeout', ['pass', 'pass']]);
});

test('L8 fix 4: through the CLI, the websocket rides the actor\'s session and CSRF pair; the run file keeps no value', async t => {
  const csrf = { header: 'X-CSRF-Token', cookie: 'csrf_token', value: 'csrf-sam-ws' };
  const desk = await deskFor(t, { cookie: 'session', csrf });
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven cli websocket '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const dbPath = join(dir, 'audit.db');
  const { DatabaseSync } = await import('node:sqlite');
  const db = new DatabaseSync(dbPath); db.exec('CREATE TABLE audit_log (id INTEGER PRIMARY KEY, actor TEXT, action TEXT)'); db.close();
  const seq = { ...wsSequence(), actors: { sam: { principalId: 'agent-sam', credentialEnv: 'SCOPEHAVEN_TARGET_SAM', credentialCookie: 'session', csrf: { env: 'SCOPEHAVEN_TARGET_SAM_CSRF', header: 'X-CSRF-Token', cookie: 'csrf_token' } } },
    assertions: [{ id: 'NO-AUDIT', title: 'No audit row', severity: 'high', from: 'start', to: 'end', effect: { kind: 'effect.none', select: { source: 'sql-audit-table', name: 'note.delete' } } }] };
  writeFileSync(join(dir, 'seq.json'), JSON.stringify(seq));
  writeFileSync(join(dir, 'observers.json'), JSON.stringify([{ type: 'sqlite-audit', path: dbPath, principals: ['agent-sam'], audit: { table: 'audit_log', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', actions: { 'note.delete': 'delete' } } }]));
  const lines = [];
  const code = await main(['--sequence', join(dir, 'seq.json'), '--origin', desk.origin, '--observers', join(dir, 'observers.json'), '--out', join(dir, 'runs'), ...sequenceAuthorizationArgs(join(dir, 'authorization.json'), seq, { origin: desk.origin })],
    { env: { SCOPEHAVEN_TARGET_SAM: 'desk-token', SCOPEHAVEN_TARGET_SAM_CSRF: 'csrf-sam-ws' }, log: s => lines.push(s) });
  const out = lines.join('\n');
  assert.notEqual(code, 2, out);
  assert.doesNotMatch(out, /stopped/);
  const [handshake] = desk.handshakes;
  assert.deepEqual([handshake.headers.cookie, handshake.headers['x-csrf-token']], ['session=desk-token; csrf_token=csrf-sam-ws', 'csrf-sam-ws'], out);
  const [file] = readdirSync(join(dir, 'runs')).filter(f => f.endsWith('.json'));
  const text = readFileSync(join(dir, 'runs', file), 'utf8'), run = JSON.parse(text);
  assert.deepEqual([run.schema, run.websocketRecords['agent-ws'].messages], [SEQUENCE_RUN_SCHEMA_V4, 2]);
  for (const value of ['csrf-sam-ws', 'desk-token', ...desk.invocations]) assert.ok(!text.includes(value), 'no credential, CSRF value or captured value in the run file');
});
