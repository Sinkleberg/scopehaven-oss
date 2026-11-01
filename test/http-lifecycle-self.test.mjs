// Self-change lifecycle (src/http-lifecycle.mjs): the changed user makes the change herself (signs out, revokes her own
// access), and her pre-change credential must be refused after it. Owned loopback practice app
// (integrations/core-practice/app.mjs, POST /api/sign-out) with synthetic users and a loopback egress recorder, and an
// injected transport with an empty authoritative sink for the identity cases: no model, no provider, no network beyond 127.0.0.1.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateTargetFile, validateHttpRunEvidence, PRECONDITION_ASSERTION, IDENTITY_ASSERTION, IDENTITY_REASONS, IDENTITY_UNPROVEN_DECISION, identityPlanShape } from '../src/contracts.mjs';
import { selfChangeIds } from '../src/http-lifecycle.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { createCorePracticeApp } from '../integrations/core-practice/app.mjs';
import { lifecycleProfile, selfLifecycleProfile } from '../integrations/core-practice/profiles.mjs';
import { freePorts } from '../integrations/observers/fixtures/free-port.mjs';

const row = (run, id) => run.results.find(r => r.id === id);
const carol = run => run.identityEvidence.actors.find(a => a.actorId === 'carol');
const suiteOf = (profile, env) => createRegistry({ profiles: [profile], env }).exportSuite(profile.id);
const reseal = r => { r.evidenceDigest = digest(r.trace.length === 2 ? { evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions } : { evidence: r.trace[0].data, assertions: r.assertions }); };
const identity = (run, id) => row(run, id).assertions.find(a => a.name === IDENTITY_ASSERTION)?.actual;
async function assess(t, build = {}, { edit = p => p } = {}) {
  const [sinkPort] = await freePorts(1);
  const app = await createCorePracticeApp({ sinkPort, ...build }); t.after(() => app.close());
  const profile = edit(selfLifecycleProfile({ origin: app.origin, sinkPort }));
  const run = await runHttpAssessment(profile, { env: app.env });
  return { app, profile, run };
}
const SIGN_OUT = 'POST /api/sign-out';

test('self-change validation: the changed actor may send its own change, never as a GET and never for another entry', () => {
  const base = selfLifecycleProfile({ origin: 'http://127.0.0.1:9', sinkPort: 40999 });
  validateTargetFile({ schemaVersion: 1, targets: [base] });
  assert.deepEqual([...selfChangeIds(base)], ['CAROL-SIGN-OUT']);
  // The sign-out check is outside carol's brackets, as her post-change checks are; it is bracketed in no plan.
  const shape = identityPlanShape(base).find(s => s.actorId === 'carol');
  assert.ok(!shape.others.map(i => base.checks[i].id).includes('CAROL-SIGN-OUT'));
  assert.deepEqual(shape.others.map(i => base.checks[i].id), ['CAROL-NOTES', 'CAROL-NOTE-1', 'CAROL-NOTE-2', 'CAROL-DELETE-OWN']);
  const refuse = (edit, pattern) => { const p = structuredClone(base); edit(p); assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [p] }), pattern); };
  // A required GET of the actor is a surface control, re-sent at every probe point: it can never be the self-change.
  refuse(p => { Object.assign(p.checks.find(c => c.id === 'CAROL-SIGN-OUT'), { method: 'GET' }); delete p.checks.find(c => c.id === 'CAROL-SIGN-OUT').body; }, /a self-change check \(sent by the changed actor\) must use POST, PUT, PATCH or DELETE/);
  // A self-change serves no other entry: bob cannot be "changed" by carol signing herself out.
  refuse(p => { p.checks.push({ ...structuredClone(p.checks.find(c => c.id === 'CAROL-REUSE-ME')), id: 'BOB-REUSE-ME', actorId: 'bob' }); p.lifecycle.push({ changeCheckId: 'CAROL-SIGN-OUT', actorId: 'bob', after: 'refused' }); },
    /a self-change check cannot be another entry's change check/);
  // Every other lifecycle rule still applies: the post-change checks expect only the refusal and pair it with an effect.none.
  refuse(p => { p.checks.find(c => c.id === 'CAROL-REUSE-ME').assertions = [{ kind: 'status.equals', expected: 200 }]; }, /must expect only the declared refusal/);
  refuse(p => { p.requiredControlIds = p.requiredControlIds.filter(id => id !== 'CAROL-SIGN-OUT'); }, /the change check must be an applicable required allowed-use control/);
  refuse(p => { p.requiredControlIds = p.requiredControlIds.filter(id => id !== 'CAROL-NOTES'); Object.assign(p.checks.find(c => c.id === 'CAROL-NOTES'), { severity: 'low' }); }, /needs a surface control before the change/);
  // The suite binds the declaration, as it does for a change by another actor.
  assert.deepEqual(suiteOf(base, {}).lifecycle, [{ changeCheckId: 'CAROL-SIGN-OUT', actorId: 'carol', after: 'refused' }]);
});

test('self-change allowed: carol signs herself out; every probe carrying her credential precedes the sign-out, and her old credential is refused after it', async t => {
  const { app, profile, run } = await assess(t);
  assert.deepEqual(run.counts, { pass: 12, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }, JSON.stringify(run.results.map(r => [r.id, r.status])));
  const entry = carol(run);
  assert.equal(entry.reason, 'established');
  assert.deepEqual(entry.lifecycle, { changeCheckId: 'CAROL-SIGN-OUT', after: 'refused', changeConfirmed: true, changerLoginProven: true, postChangeCheckIds: ['CAROL-REUSE-ME', 'CAROL-REUSE-DELETE'] });
  // No probe point names the sign-out: the last one closes after her last bracketed check, before the change.
  assert.ok(!entry.between.some(point => point.afterCheckId === 'CAROL-SIGN-OUT'));
  assert.equal(entry.between.at(-1).afterCheckId, 'CAROL-NOTE-2');
  // The only requests carrying carol's credential after the sign-out are her two post-change checks.
  const at = app.requests.findIndex(r => `${r.method} ${r.path}` === SIGN_OUT);
  assert.ok(at > 0 && app.requests[at].user === 'carol');
  assert.deepEqual(app.requests.slice(at + 1).filter(r => r.user === 'carol').map(r => `${r.method} ${r.path}`), ['GET /api/me', 'POST /api/notes/n-2/delete']);
  for (const id of ['CAROL-REUSE-ME', 'CAROL-REUSE-DELETE']) {
    const r = row(run, id);
    assert.deepEqual([r.trace[0].data.httpStatus, r.status, r.trace[1].data.effects[0].custody], [401, 'pass', 'independent'], id);
  }
  // Unchanged actors keep working after the sign-out.
  assert.deepEqual(['BOB-WHOAMI-AFTER', 'BOB-NOTE-AFTER'].map(id => row(run, id).status), ['pass', 'pass']);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
  assert.equal(summarizeGate({ candidate: run, expectedSuite: suiteOf(profile, app.env) }).exitCode, 0);
});

test('self-change forbidden: a sign-out that leaves the session valid fails from the harness\'s own records', async t => {
  const { app, profile, run } = await assess(t, { signOutKeepsSession: true });
  assert.equal(row(run, 'CAROL-SIGN-OUT').status, 'pass', 'the app said she was signed out');
  const me = row(run, 'CAROL-REUSE-ME'), del = row(run, 'CAROL-REUSE-DELETE');
  assert.deepEqual([me.trace[0].data.httpStatus, me.status], [200, 'fail']);
  assert.deepEqual([del.trace[0].data.httpStatus, del.status, del.assertions.find(a => a.name.startsWith('Observed effect')).status], [200, 'fail', 'fail']);
  assert.deepEqual([carol(run).reason, carol(run).lifecycle.changerLoginProven], ['established', true], 'the proof closed before the change, so the failure is carol\'s');
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
  const gate = summarizeGate({ candidate: run, expectedSuite: suiteOf(profile, app.env) });
  assert.equal(gate.exitCode, 1); assert.ok(gate.reasons.includes('checks-failed'));
});

test('self-change failed control: a sign-out that does not pass sends no pre-change credential afterwards, and the post-change rows are inconclusive', async t => {
  const { app, profile, run } = await assess(t, { signOutBroken: true });
  assert.equal(row(run, 'CAROL-SIGN-OUT').status, 'fail');
  assert.equal(carol(run).lifecycle.changeConfirmed, false);
  for (const id of ['CAROL-REUSE-ME', 'CAROL-REUSE-DELETE']) {
    const r = row(run, id);
    assert.deepEqual([r.status, r.trace[0].data.transportOutcome, r.trace[0].data.notSent], ['inconclusive', 'not-sent', 'change-not-confirmed'], id);
    assert.match(r.assertions.find(a => a.name === PRECONDITION_ASSERTION).actual, /declared account change did not pass/);
  }
  const at = app.requests.findIndex(r => `${r.method} ${r.path}` === SIGN_OUT);
  assert.deepEqual(app.requests.slice(at + 1).filter(r => r.user === 'carol'), []);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
  assert.notEqual(summarizeGate({ candidate: run, expectedSuite: suiteOf(profile, app.env) }).exitCode, 0);
});

test('known negative: without the declaration the sign-out is bracketed, the point after it refuses carol, and no check of hers is credited', async t => {
  const { run } = await assess(t, {}, { edit: p => { delete p.lifecycle; return p; } });
  assert.equal(carol(run).reason, 'bracket-not-passed');
  assert.ok(carol(run).between.some(point => point.afterCheckId === 'CAROL-SIGN-OUT' && point.probes.some(p => p.httpStatus === 401)));
  for (const id of ['CAROL-WHOAMI', 'CAROL-NOTES', 'CAROL-NOTE-1', 'CAROL-DELETE-OWN', 'CAROL-SIGN-OUT']) assert.deepEqual([row(run, id).status, identity(run, id)], ['inconclusive', IDENTITY_REASONS['bracket-not-passed']], id);
  assert.deepEqual([row(run, 'CAROL-REUSE-ME').status, row(run, 'CAROL-REUSE-ME').decision], ['inconclusive', IDENTITY_UNPROVEN_DECISION]);
  validateHttpRunEvidence(run);
  // The suspension profile is unchanged: the same app without a sign-out keeps its administrator-made change.
  validateTargetFile({ schemaVersion: 1, targets: [lifecycleProfile({ origin: 'http://127.0.0.1:9', sinkPort: 40999 })] });
});

// Injected transport and an authoritative empty sink, so one probe point can be made to fail.
const SINK_HOST = 'hooks.desk.example', SELECT = { source: 'http-egress', operation: 'send', name: SINK_HOST };
const emptySink = configs => configs.map(c => ({ kind: 'http-egress-recorder', instanceId: `${c.type}-${c.id}`, source: 'http-egress', scope: { operations: ['send'], names: [SINK_HOST], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
  async start() {}, async stop() {}, async mark() { return {}; }, async collect() { return { events: [], coverage: 'complete', reason: null }; } }));
const reply = (status, json = {}) => ({ status, complete: true, jsonParsed: true, json, bytes: 2 });
const ctl = (id, actorId, path, extra = []) => ({ id, title: id, category: 'Allowed use', severity: 'control', actorId, method: 'GET', path, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, ...extra] });
const me = (id, actorId) => ctl(id, actorId, '/me', [{ kind: 'json.equals', pointer: '/user', expected: actorId }]);
const ENV = { SCOPEHAVEN_TARGET_A: 'tok-admin', SCOPEHAVEN_TARGET_C: 'tok-carol' };
function signOutProfile() {
  return { id: 'self-sign-out', name: 'Self sign-out', applicationId: 'self-sign-out', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { admin: { principalId: 'admin', credentialEnv: 'SCOPEHAVEN_TARGET_A', identityValue: 'admin' }, carol: { principalId: 'carol', credentialEnv: 'SCOPEHAVEN_TARGET_C', identityValue: 'carol' } },
    observers: [{ id: 'sink', type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [{ host: SINK_HOST }], witness: { actorId: 'admin', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250, quietMs: 150 }],
    requiredControlIds: ['ADMIN-ME', 'CAROL-ME', 'CAROL-NOTES', 'CAROL-SAVE', 'SIGN-OUT'], lifecycle: [{ changeCheckId: 'SIGN-OUT', actorId: 'carol', after: 'refused' }],
    checks: [me('ADMIN-ME', 'admin'), me('CAROL-ME', 'carol'), ctl('CAROL-NOTES', 'carol', '/notes'), { ...ctl('CAROL-SAVE', 'carol', '/notes'), method: 'POST', body: {} },
      { ...ctl('SIGN-OUT', 'carol', '/sign-out'), method: 'POST', body: {} },
      { id: 'REUSE', title: 'r', category: 'Lifecycle', severity: 'high', actorId: 'carol', method: 'GET', path: '/notes', evidenceRequirement: 'backend', assertions: [{ kind: 'status.in', expected: [401, 403] }], effects: [{ kind: 'effect.none', select: SELECT }] }] };
}
// state.carolMeFailsAt: the n-th answer of carol's identity control to her own credential is a 500 (not a refusal).
function signOutApp(state = {}) {
  let out = false, n = 0;
  return async (_origin, check, { credential }) => {
    const who = { 'tok-admin': 'admin', 'tok-carol': 'carol' }[credential] ?? null;
    if (check.path === '/me') {
      if (check.id === 'CAROL-ME' && who === 'carol' && ++n === state.carolMeFailsAt) return reply(500);
      return who && !(who === 'carol' && out) ? reply(200, { user: who }) : reply(401);
    }
    if (!who || (who === 'carol' && out)) return reply(401);
    if (check.path === '/sign-out') { out = who === 'carol'; return reply(200); }
    return reply(200, { items: [] });
  };
}

test('the self-change is attributed only when carol\'s whole pre-change proof holds: a failed point before it leaves the refusal unpassed', async () => {
  const profile = signOutProfile(), suite = suiteOf(profile, ENV);
  const clean = await runHttpAssessment(profile, { env: ENV, transport: signOutApp(), observerFactory: emptySink });
  assert.deepEqual([carol(clean).reason, carol(clean).lifecycle.changerLoginProven, row(clean, 'REUSE').status], ['established', true, 'pass']);
  validateHttpRunEvidence(clean, { expectedSuite: suite });
  // CAROL-ME with carol's credential: the control row (1), the point before CAROL-NOTES (2), the point after it (3), and the
  // closing point after CAROL-SAVE (4), the last before the sign-out. A 500 there is not a refusal: the change still passes when
  // sent, but carol's login is not proven for it, so the change is not attributed and the refusal after it is never a pass.
  const run = await runHttpAssessment(profile, { env: ENV, transport: signOutApp({ carolMeFailsAt: 4 }), observerFactory: emptySink });
  assert.deepEqual([carol(run).after[0].httpStatus, carol(run).reason], [500, 'bracket-not-passed']);
  assert.deepEqual([carol(run).lifecycle.changeConfirmed, carol(run).lifecycle.changerLoginProven], [true, false]);
  assert.deepEqual([row(run, 'SIGN-OUT').status, identity(run, 'SIGN-OUT')], ['inconclusive', IDENTITY_REASONS['bracket-not-passed']]);
  const reuse = row(run, 'REUSE');
  assert.deepEqual([reuse.trace[0].data.httpStatus, reuse.status, reuse.decision], [401, 'inconclusive', IDENTITY_UNPROVEN_DECISION]);
  validateHttpRunEvidence(run, { expectedSuite: suite });
});

test('self-change evidence is recomputed: a forged attribution, a probe point after the sign-out, a GET sign-out or an earlier rule version is refused', async () => {
  const run = await runHttpAssessment(signOutProfile(), { env: ENV, transport: signOutApp(), observerFactory: emptySink });
  validateHttpRunEvidence(run);
  const edit = change => { const copy = structuredClone(run); change(copy); return copy; };
  // The attribution flag is recomputed from the sign-out row's own identity reason.
  const unproven = await runHttpAssessment(signOutProfile(), { env: ENV, transport: signOutApp({ carolMeFailsAt: 4 }), observerFactory: emptySink });
  const flagged = structuredClone(unproven); carol(flagged).lifecycle.changerLoginProven = true;
  assert.throws(() => validateHttpRunEvidence(flagged), /invalid-run-evidence/);
  // A probe point recorded after the sign-out (as if the sign-out were bracketed) does not match the plan.
  assert.throws(() => validateHttpRunEvidence(edit(c => { const e = carol(c); e.between.push({ afterCheckId: 'SIGN-OUT', probes: structuredClone(e.after) }); })), /invalid-run-evidence/);
  // A self-change recorded as a GET is refused, even resealed.
  assert.throws(() => validateHttpRunEvidence(edit(c => { const r = row(c, 'SIGN-OUT'); r.trace[0].data.method = 'GET'; reseal(r); })), /invalid-run-evidence/);
  // Earlier rule versions never carry a self-change.
  assert.throws(() => validateHttpRunEvidence(edit(c => { c.identityEvidence.schema = 'actor-identity/5'; })), /invalid-run-evidence/);
});
