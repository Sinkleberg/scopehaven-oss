// Fail-open #3 with a lifecycle (an earlier review): a change control whose positive pass settlement withholds because its effect
// carries another check's correlation token (effect-correlated-elsewhere) is not attributed to its check. The connector reads it
// unconfirmed after the fact, its already-sent post-change check reads change-not-attributed and never passes, and the validator
// accepts that run, with and without the exported suite. Injected transport, clock and sink: no socket.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, withheldByAttribution, passedAtSend, PRECONDITION_ASSERTION, PRECONDITION_REASONS } from '../src/contracts.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { createRegistry } from '../src/registry.mjs';
const SYNC_HOST = 'sync.desk.example', HOOK_HOST = 'hooks.desk.example', SINK = 'egress-recorder-sink';
const ENV = { SCOPEHAVEN_TARGET_A: 'tok-admin', SCOPEHAVEN_TARGET_C: 'tok-carol' };
const WHO = { 'tok-admin': 'admin', 'tok-carol': 'carol' };
const send = (name, resource) => ({ source: 'http-egress', operation: 'send', name, ...(resource ? { resource } : {}) });
const control = (id, actorId, method, path, extra = {}) => ({ id, title: id, category: 'Allowed use', severity: 'control', actorId, method, path, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], ...extra });
const me = (id, actorId) => control(id, actorId, 'GET', '/me', { assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: actorId }] });
const reuse = { id: 'REUSE', title: 'REUSE', category: 'Lifecycle', severity: 'high', actorId: 'carol', method: 'GET', path: '/notes', evidenceRequirement: 'backend', assertions: [{ kind: 'status.in', expected: [401, 403] }], effects: [{ kind: 'effect.none', select: send(HOOK_HOST) }] };
const p = { id: 'lc-elsewhere', name: 'lc', applicationId: 'lc', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
  actors: { admin: { principalId: 'admin', credentialEnv: 'SCOPEHAVEN_TARGET_A', identityValue: 'admin' }, carol: { principalId: 'carol', credentialEnv: 'SCOPEHAVEN_TARGET_C', identityValue: 'carol' } },
  observers: [{ id: 'sink', type: 'egress-recorder', port: 40998, destinations: [{ host: SYNC_HOST, paths: ['/suspend/'], correlation: { header: 'traceparent' } }, { host: HOOK_HOST, paths: ['/notes'], correlation: { header: 'traceparent' } }], settleMs: 250 }],
  correlation: { header: 'traceparent' },
  requiredControlIds: ['ADMIN-ME', 'CAROL-ME', 'CAROL-NOTES', 'SUSPEND'], lifecycle: [{ changeCheckId: 'SUSPEND', actorId: 'carol', after: 'refused' }],
  checks: [me('ADMIN-ME', 'admin'), me('CAROL-ME', 'carol'), control('CAROL-NOTES', 'carol', 'GET', '/notes'),
    control('SUSPEND', 'admin', 'POST', '/users/carol/suspend', { body: {}, effects: [{ kind: 'effect.exists', select: send(SYNC_HOST, 'POST /suspend/') }] }), reuse] };
let suspended = false, now = 0, seq = 0, notesToken = null; const events = [];
const clock = { now: () => now, sleep: async ms => { now += ms; } };
const transport = async (origin, check, { credential, correlationHeader }) => {
  now += 10; const who = WHO[credential] ?? null, path = check.path.split('?')[0];
  const tok = correlationHeader ? correlationHeader.value.split('-')[1] : null;
  if (path === '/me') return who ? { status: 200, complete: true, jsonParsed: true, json: { user: who }, bytes: 10 } : { status: 401, complete: true, jsonParsed: true, json: {}, bytes: 2 };
  if (!who || (who === 'carol' && suspended)) return { status: 401, complete: true, jsonParsed: true, json: {}, bytes: 2 };
  if (path === '/notes' && who === 'carol' && !notesToken) notesToken = tok;
  // The app stamps the suspension's send with CAROL-NOTES's token (another check's).
  if (path === '/users/carol/suspend') { suspended = true; events.push({ at: now, name: SYNC_HOST, resource: 'POST /suspend/', token: notesToken }); }
  return { status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 };
};
const factory = configs => configs.map(c => ({ kind: 'http-egress-recorder', instanceId: `${c.type}-${c.id}`, source: 'http-egress', witnessRequest: null,
  scope: { operations: ['send'], names: [SYNC_HOST, HOOK_HOST], actorAttribution: 'none', evidence: 'authoritative' },
  async start() {}, async stop() {}, async mark() { return { at: now }; },
  async collect(from, to) { return { events: events.filter(e => e.at > from.at && e.at <= to.at).map(e => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: SINK }, seq: ++seq, operation: 'send', name: e.name, resource: e.resource, outcome: 'committed', correlation: { settlementToken: e.token } })), coverage: 'complete', reason: null }; } }));
test('a lifecycle change withheld by correlation settlement is not attributed, and the connector\'s run validates', async () => {
  const run = await runHttpAssessment(p, { env: ENV, clock, transport, observerFactory: factory });
  const row = id => run.results.find(r => r.id === id);
  const s = row('SUSPEND'), r = row('REUSE');
  assert.deepEqual(s.trace[1].data.effects.map(e => [e.verdict, e.settlement]), [['inconclusive', 'effect-correlated-elsewhere']]);
  assert.deepEqual([s.status, passedAtSend(s), withheldByAttribution(s)], ['inconclusive', false, true]);
  assert.equal(r.trace[0].data.transportOutcome, 'complete', 'the post-change check was sent');
  assert.notEqual(r.status, 'pass');
  assert.deepEqual(r.assertions.filter(a => a.name === PRECONDITION_ASSERTION).map(a => a.actual), [PRECONDITION_REASONS['change-not-attributed']]);
  assert.equal(run.identityEvidence.actors.find(a => a.actorId === 'carol').lifecycle.changeConfirmed, false);
  validateHttpRunEvidence(run);
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env: ENV }).exportSuite(p.id) });
});
