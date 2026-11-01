// A lifecycle change whose own pass the run's background attribution withholds (src/http-attribution.mjs) is not attributed
// to its change check: the live run and the saved-run validator agree that it reads unconfirmed and that every post-change
// check already sent reads inconclusive (change-not-attributed), never pass. Injected transport, injected observer and a
// virtual clock: no socket, no database, no model, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, withheldByAttribution, PRECONDITION_ASSERTION, PRECONDITION_REASONS, IDENTITY_ASSERTION } from '../src/contracts.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';

const SYNC_HOST = 'sync.desk.example', HOOK_HOST = 'hooks.desk.example', SINK = 'egress-recorder-sink';
const ENV = Object.freeze({ SCOPEHAVEN_TARGET_A: 'tok-admin', SCOPEHAVEN_TARGET_C: 'tok-carol', SCOPEHAVEN_TARGET_D: 'tok-dave' });
const WHO = { 'tok-admin': 'admin', 'tok-carol': 'carol', 'tok-dave': 'dave' };
const send = (name, resource) => ({ source: 'http-egress', operation: 'send', name, ...(resource ? { resource } : {}) });
const control = (id, actorId, method, path, extra = {}) => ({ id, title: id, category: 'Allowed use', severity: 'control', actorId, method, path, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], ...extra });
const me = (id, actorId) => control(id, actorId, 'GET', '/me', { assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: actorId }] });
// The administrator suspends carol; the suspension's own send goes to the sync host, which a declared background source
// names, so attribution withholds the change control's positive pass. carol's pre-change credential is then re-sent.
function profile({ attribution = true, capture = false } = {}) {
  const reuse = { id: 'REUSE', title: 'REUSE', category: 'Lifecycle', severity: 'high', actorId: 'carol', method: 'GET', path: capture ? '/notes/{{noteId}}' : '/notes', evidenceRequirement: 'backend',
    assertions: [{ kind: 'status.in', expected: [401, 403] }], effects: [{ kind: 'effect.none', select: send(HOOK_HOST) }], ...(capture ? { precondition: [{ name: 'noteId', type: 'id', createdBy: 'dave' }] } : {}) };
  const daveChecks = capture ? [me('DAVE-ME', 'dave'), control('DAVE-CREATE', 'dave', 'POST', '/notes', { body: {}, capture: { noteId: { pointer: '/id', type: 'id' } }, effects: [{ kind: 'effect.exists', select: send(HOOK_HOST, 'POST /notes') }] })] : [];
  return { id: 'lifecycle-attribution', name: 'Lifecycle and attribution', applicationId: 'lifecycle-attribution', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { admin: { principalId: 'admin', credentialEnv: 'SCOPEHAVEN_TARGET_A', identityValue: 'admin' }, carol: { principalId: 'carol', credentialEnv: 'SCOPEHAVEN_TARGET_C', identityValue: 'carol' },
      ...(capture ? { dave: { principalId: 'dave', credentialEnv: 'SCOPEHAVEN_TARGET_D', identityValue: 'dave' } } : {}) },
    observers: [{ id: 'sink', type: 'egress-recorder', port: 40998, destinations: [{ host: SYNC_HOST, paths: ['/suspend/'] }, { host: HOOK_HOST, paths: ['/notes'] }], settleMs: 250 }],
    ...(attribution ? { attribution: { background: [{ id: 'sync', select: { operation: 'send', name: SYNC_HOST } }] } } : {}),
    requiredControlIds: ['ADMIN-ME', 'CAROL-ME', 'CAROL-NOTES', ...daveChecks.map(c => c.id), 'SUSPEND'], lifecycle: [{ changeCheckId: 'SUSPEND', actorId: 'carol', after: 'refused' }],
    checks: [me('ADMIN-ME', 'admin'), me('CAROL-ME', 'carol'), control('CAROL-NOTES', 'carol', 'GET', '/notes'), ...daveChecks,
      control('SUSPEND', 'admin', 'POST', '/users/carol/suspend', { body: {}, effects: [{ kind: 'effect.exists', select: send(SYNC_HOST, 'POST /suspend/') }] }), reuse] };
}
// The app: a suspended carol is refused; the suspension sends one request to the sync host. With dave, his login is never
// proven (the app names him for any request to /me, even without a credential), and he creates note n1.
function app({ dave = false, noId = false, suspendCut = false, ignoresSuspension = false } = {}) {
  let suspended = false, now = 0, seq = 0;
  const events = [];
  const clock = { now: () => now, sleep: async ms => { now += ms; } };
  const transport = async (origin, check, { credential }) => {
    now += 10;
    const who = WHO[credential] ?? null, path = check.path.split('?')[0];
    if (path === '/me') return who || dave ? { status: 200, complete: true, jsonParsed: true, json: { user: who ?? 'dave' }, bytes: 10 } : { status: 401, complete: true, jsonParsed: true, json: {}, bytes: 2 };
    if (!who || (who === 'carol' && suspended && !ignoresSuspension)) return { status: 401, complete: true, jsonParsed: true, json: {}, bytes: 2 };
    if (path === '/users/carol/suspend') { suspended = true; events.push({ at: now, name: SYNC_HOST, resource: 'POST /suspend/' });
      if (suspendCut) return { status: 200, complete: false, jsonParsed: false, json: undefined, bytes: 70000, error: 'too-large' }; }
    if (path === '/notes' && check.method === 'POST') { events.push({ at: now, name: HOOK_HOST, resource: 'POST /notes' }); return { status: 200, complete: true, jsonParsed: true, json: noId ? {} : { id: 'n1' }, bytes: 10 }; }
    return { status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 };
  };
  const factory = configs => configs.map(c => ({ kind: 'http-egress-recorder', instanceId: `${c.type}-${c.id}`, source: 'http-egress', witnessRequest: null,
    scope: { operations: ['send'], names: [SYNC_HOST, HOOK_HOST], actorAttribution: 'none', evidence: 'authoritative' },
    async start() {}, async stop() {}, async mark() { return { at: now }; },
    async collect(from, to) { return { events: events.filter(e => e.at > from.at && e.at <= to.at).map(e => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: SINK }, seq: ++seq, operation: 'send', name: e.name, resource: e.resource, outcome: 'committed' })), coverage: 'complete', reason: null }; } }));
  return { clock, transport, factory };
}
const assess = (p, options) => { const a = app(options); return runHttpAssessment(p, { env: ENV, clock: a.clock, transport: a.transport, observerFactory: a.factory }); };
const row = (run, id) => run.results.find(r => r.id === id);
const carol = run => run.identityEvidence.actors.find(a => a.actorId === 'carol');
const suiteOf = p => createRegistry({ profiles: [p], env: ENV }).exportSuite(p.id);
const preconditions = r => r.assertions.filter(a => a.name === PRECONDITION_ASSERTION).map(a => a.actual);
const reseal = r => { r.evidenceDigest = digest(r.trace.length === 2 ? { evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions } : { evidence: r.trace[0].data, assertions: r.assertions }); };

test('a change whose pass attribution withholds is not attributed: live and saved runs read it unconfirmed and the post-change check inconclusive', async () => {
  const p = profile();
  const run = await assess(p);
  const suspend = row(run, 'SUSPEND'), reuse = row(run, 'REUSE');
  assert.deepEqual([suspend.status, suspend.trace[1].data.effects[0].attribution], ['inconclusive', 'background-unattributed']);
  assert.equal(withheldByAttribution(suspend), true);
  assert.equal(reuse.trace[0].data.httpStatus, 401, 'the post-change check was sent and refused');
  assert.deepEqual([reuse.status, preconditions(reuse)], ['inconclusive', [PRECONDITION_REASONS['change-not-attributed']]]);
  assert.equal(carol(run).lifecycle.changeConfirmed, false);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  validateHttpRunEvidence(JSON.parse(JSON.stringify(run)));
  assert.ok(run.limitations.some(l => l.includes('the change is not attributed: it reads unconfirmed')));
});

test('the allowed neighbour: without the background source the change is attributed, and the post-change refusal passes', async () => {
  const p = profile({ attribution: false });
  const run = await assess(p);
  assert.deepEqual([row(run, 'SUSPEND').status, row(run, 'REUSE').status, carol(run).lifecycle.changeConfirmed], ['pass', 'pass', true]);
  assert.deepEqual(preconditions(row(run, 'REUSE')), []);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
});

test('the validator refuses a withheld change edited back to confirmed, a post-change pass without the precondition, or the precondition on an attributed change', async () => {
  const withheld = await assess(profile()), attributed = await assess(profile({ attribution: false }));
  const edit = (run, change) => { const r = structuredClone(run); change(r); return r; };
  const strip = r => { const x = row(r, 'REUSE'); x.assertions = x.assertions.filter(a => a.name !== PRECONDITION_ASSERTION); x.status = 'pass'; x.decision = 'pass'; reseal(x); };
  for (const [name, run] of Object.entries({
    'confirmed again': edit(withheld, r => { carol(r).lifecycle.changeConfirmed = true; }),
    'confirmed again, precondition removed': edit(withheld, r => { carol(r).lifecycle.changeConfirmed = true; strip(r); }),
    'precondition removed': edit(withheld, strip),
    'precondition on an attributed change': edit(attributed, r => { const x = row(r, 'REUSE'); x.assertions.push({ name: PRECONDITION_ASSERTION, status: 'inconclusive', expected: x.assertions.find(a => a.name === PRECONDITION_ASSERTION)?.expected ?? 'Every value this check uses was captured from its declared creator, and any declared account change took effect', actual: PRECONDITION_REASONS['change-not-attributed'] }); x.status = 'inconclusive'; x.decision = 'inconclusive'; reseal(x); }),
  })) assert.throws(() => validateHttpRunEvidence(run), /invalid-run-evidence/, name);
});

test('an unattributed change charges no pass: a credential that still works still fails; a change cut off at send stays unconfirmed and unsent', async () => {
  const p = profile();
  const still = await assess(p, { ignoresSuspension: true });
  assert.deepEqual([row(still, 'REUSE').trace[0].data.httpStatus, row(still, 'REUSE').status, preconditions(row(still, 'REUSE'))], [200, 'fail', [PRECONDITION_REASONS['change-not-attributed']]]);
  validateHttpRunEvidence(still, { expectedSuite: suiteOf(p) });
  // The change's reply was cut off (an error at send), so no post-change check was sent; attribution then tags the change too.
  const cut = await assess(p, { suspendCut: true });
  assert.deepEqual([row(cut, 'SUSPEND').status, row(cut, 'SUSPEND').trace[1].data.effects[0].attribution, row(cut, 'REUSE').trace[0].data.notSent], ['error', 'background-unattributed', 'change-not-confirmed']);
  assert.equal(withheldByAttribution(row(cut, 'SUSPEND')), false);
  validateHttpRunEvidence(cut, { expectedSuite: suiteOf(p) });
});

test('a post-change check that also uses a value whose creator\'s login was not proven carries the one precondition the validator expects', async () => {
  const p = profile({ capture: true });
  const run = await assess(p, { dave: true });
  assert.ok(run.identityEvidence.actors.find(a => a.actorId === 'dave').loginProven === false, 'dave\'s login is not proven');
  assert.deepEqual(preconditions(row(run, 'REUSE')), [PRECONDITION_REASONS['change-not-attributed']]);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  // A post-change check not sent because its captured value missed keeps that reason (capture-unavailable), and no other.
  const missed = await assess(p, { dave: true, noId: true });
  assert.deepEqual([row(missed, 'REUSE').trace[0].data.notSent, preconditions(row(missed, 'REUSE'))], ['capture-unavailable', [PRECONDITION_REASONS['capture-unavailable']]]);
  assert.equal(carol(missed).lifecycle.changeConfirmed, false);
  validateHttpRunEvidence(missed, { expectedSuite: suiteOf(p) });
});

test('withheldByAttribution reads only an inconclusive change whose non-passing rows are attribution-tagged effect or claim rows', () => {
  const effect = (status, tag) => ({ name: 'Observed effect 1 (effect.exists)', status, ...(tag ? { attribution: 'background-unattributed' } : {}) });
  const ok = { name: 'HTTP status matches contract', status: 'pass' };
  assert.equal(withheldByAttribution({ status: 'inconclusive', assertions: [ok, effect('inconclusive', true)] }), true);
  assert.equal(withheldByAttribution({ status: 'inconclusive', assertions: [ok, effect('inconclusive', true), { name: IDENTITY_ASSERTION, status: 'inconclusive' }] }), true);
  for (const assertions of [[ok, effect('inconclusive', false)], [ok, effect('pass', true)], [{ ...ok, status: 'inconclusive', attribution: 'background-unattributed' }, effect('inconclusive', true)],
    [ok, effect('inconclusive', true), { name: 'json.equals predicate 1', status: 'inconclusive' }], [ok, { name: 'json.equals predicate 1', status: 'inconclusive', attribution: 'background-unattributed' }],
    [ok, effect('inconclusive', true), { ...effect('inconclusive', false), name: 'Observed effect 2 (effect.none)' }]])
    assert.equal(withheldByAttribution({ status: 'inconclusive', assertions }), false, JSON.stringify(assertions));
  assert.equal(withheldByAttribution({ status: 'fail', assertions: [{ ...ok, status: 'fail' }, effect('inconclusive', true)] }), false);
  assert.equal(withheldByAttribution({ status: 'error', assertions: [ok, effect('inconclusive', true)] }), false);
  assert.equal(withheldByAttribution({ status: 'inconclusive', assertions: [{ ...ok, attribution: 'background-unattributed' }, { name: IDENTITY_ASSERTION, status: 'inconclusive', attribution: 'background-unattributed' }] }), false);
});
