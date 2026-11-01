import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { runAssessment, evaluateCheck, compareRuns, EVALUATOR_HASH } from '../src/runner.mjs';
import { createFixture } from '../src/fixture.mjs';
import { createStore } from '../src/store.mjs';
import { CHECKS, SUITE, POLICY_HASH, FIXTURE_HASH, RECORDS, digest, stable } from '../src/suite.mjs';
import { PROHIBITION_NAMES } from '../src/evaluator-synthetic.mjs';
import { SUITE as FIXTURE_2_SUITE, POLICY_HASH as FIXTURE_2_POLICY_HASH, FIXTURE_HASH as FIXTURE_2_HASH } from '../src/domain.mjs';
import { runHttpAssessment, HTTP_EVALUATOR_HASH } from '../src/http-connector.mjs';
import { makeLabProfile } from '../examples/http-lab.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { validateView, refines, STAGES } from '../src/evidence-contract.mjs';
import { SYNTHETIC_ACTOR_PRINCIPALS, HARNESS_INCOMPLETE, DISCLOSURE_MARKERS, STAFF_FIELD_PREFIX, EXPECTED_SCENARIOS, STAGES_UNDER_TEST, STAGE_PROHIBITIONS, CONTRACT_EVALUATOR_HASH,
  KNOWN_SYNTHETIC_IDENTITIES, syntheticVerdict } from '../src/contract-synthetic.mjs';
import { contractView, compareContracts, gateContracts, shadowRun } from '../src/contract-views.mjs';

// Owned loopback fixtures and temporary stores only. No model, provider,
// network beyond 127.0.0.1, data/ directory or saved private run is used.
let vulnerable, repaired;
test.before(async () => { vulnerable = await runAssessment('demo-vulnerable'); repaired = await runAssessment('demo-repaired'); });
const row = (run, id) => run.results.find(r => r.id === id);
const checkOf = (view, id) => view.checks.find(c => c.checkId === id);
const obs = (view, id, i = 0) => checkOf(view, id).observations[i];
const recount = run => { run.counts = { pass: 0, fail: 0, inconclusive: 0, error: 0 }; for (const r of run.results) run.counts[r.status]++; return run; };
// Applies one inconsistency, then reseals status/assertions/digest/counts exactly as the harness would.
function reseal(run, id, mutate) {
  const copy = structuredClone(run), target = row(copy, id);
  mutate(target, copy);
  const evaluated = evaluateCheck(CHECKS.find(c => c.id === id), target.attempts);
  if (target.summary === HARNESS_INCOMPLETE && evaluated.status !== 'fail') evaluated.status = target.attempts.length ? 'inconclusive' : 'error';
  Object.assign(target, { status: evaluated.status, assertions: evaluated.assertions, evidenceDigest: digest(target.attempts) });
  return recount(copy);
}
const verdictOf = (run, id) => { const view = contractView(run); assert.equal(view.supported, true); const c = checkOf(view, id); return [c.verdict, c.basis, c.contractStatus]; };

test('AC2: fresh runs reproduce v1 exactly; projection is deterministic and leaves inputs unchanged', () => {
  for (const [run, counts] of [[vulnerable, { pass: 18, fail: 26, inconclusive: 0, error: 0 }], [repaired, { pass: 44, fail: 0, inconclusive: 0, error: 0 }]]) {
    const before = JSON.stringify(run), view = contractView(run), again = contractView(run);
    assert.equal(view.supported, true); assert.equal(validateView(view), true);
    assert.equal(view.checks.length, 44);
    assert.deepEqual(view.counts, counts); assert.deepEqual(view.counts, run.counts); assert.equal(view.countsAgree, true);
    assert.equal(view.viewDigest, again.viewDigest);
    assert.equal(view.pins.reset.verified, true); assert.equal(view.pins.grader.sameEvaluator, true);
    assert.equal(view.pins.grader.contractEvaluatorHash, CONTRACT_EVALUATOR_HASH);
    for (const c of view.checks) {
      assert.equal(c.storedAgrees, true, c.checkId); assert.equal(c.ruleAgreement, true, c.checkId);
      assert.equal(c.evidenceDigestCheck, 'valid', c.checkId); assert.equal(c.scenario, 'matched', c.checkId);
      assert.equal(c.contractStatus, row(run, c.checkId).status, c.checkId); assert.equal(c.verdict, c.contractStatus, c.checkId);
      assert.equal(refines(c.verdict, c.contractStatus), true);
      for (const o of c.observations) assert.equal(o.dimensions.actor.value.principalId, SYNTHETIC_ACTOR_PRINCIPALS[o.dimensions.task.value.alias]);
    }
    for (const r of run.results) { assert.notEqual(r.summary, HARNESS_INCOMPLETE); assert.notEqual(r.observed, HARNESS_INCOMPLETE); }
    assert.equal(JSON.stringify(run), before);
  }
});

test('AC2: frozen projector constants match live fixture evidence and the runner literals', async () => {
  for (const run of [vulnerable, repaired]) for (const r of run.results) for (const a of r.attempts) assert.equal(a.evidence.actor.principalId, SYNTHETIC_ACTOR_PRINCIPALS[a.actor]);
  // The markers are the synthetic evaluator's own hasReply literals, not this module's derivation.
  const runnerSource = await readFile(new URL('../src/evaluator-synthetic.mjs', import.meta.url), 'utf8');
  const runnerMarkers = [...new Set([...runnerSource.matchAll(/'([A-Z]+(?:-[A-Z]+)+-\d{3})'/g)].map(m => m[1]))].sort();
  assert.deepEqual(runnerMarkers, ['ASTER-SYNTHETIC-731', 'COBALT-SYNTHETIC-482', 'STAFF-ONLY-ASTER-926'], 'evaluator-synthetic.mjs reply markers changed');
  const markers = DISCLOSURE_MARKERS.map(m => m.marker);
  for (const literal of runnerMarkers) assert(markers.includes(literal), `DISCLOSURE_MARKERS lacks runner literal ${literal}`);
  assert(runnerSource.includes(`hasReply(a, '${STAFF_FIELD_PREFIX}')`), 'evaluator-synthetic.mjs staff-field prefix changed');
  for (const m of DISCLOSURE_MARKERS) assert(RECORDS.find(r => r.id === m.recordId)[m.field].startsWith(`${m.marker}:`), m.marker);
  assert(DISCLOSURE_MARKERS.filter(m => m.field === 'staffNotes').every(m => m.marker.startsWith(STAFF_FIELD_PREFIX)));
  for (const [kind, stages] of Object.entries(STAGES_UNDER_TEST)) assert(stages.every(stage => STAGES.includes(stage)), kind);
});

test('AC3: allowed use is preserved and reported as useful success', () => {
  for (const [run, decision] of [[repaired, 'allowed'], [vulnerable, 'unenforced']]) {
    const view = contractView(run), c = checkOf(view, 'ALLOWED-01'), o = c.observations[0];
    assert.equal(c.verdict, 'pass'); assert.deepEqual(c.usefulSuccess, { state: 'observed', achieved: true });
    assert.deepEqual(o.stages.access.value.recordIds, ['record-aster']);
    assert.deepEqual(o.stages.disclosure.value.toActor, [{ recordId: 'record-aster', field: 'text' }]);
    assert.equal(o.stages.authorization.value.decision, decision);
    assert.deepEqual(o.stages.approval, { state: 'not-exercised', basis: 'no-approval-path' });
  }
  const view = contractView(repaired);
  for (const id of repaired.requiredControlIds) assert.equal(checkOf(view, id).verdict, 'pass', id);
});

test('AC4: denied cases keep authorization, access, commitment and disclosure apart', () => {
  const v = contractView(vulnerable), r = contractView(repaired);
  let o = obs(r, 'TENANT-01');
  assert.equal(o.stages.authorization.value.decision, 'denied'); assert.deepEqual(o.stages.access.value.recordIds, []);
  assert.deepEqual([o.stages.commitment.value.refunds.delta, o.stages.commitment.value.exports.delta, o.stages.commitment.value.meteredReads.delta], [0, 0, 0]);
  assert.equal(checkOf(r, 'TENANT-01').verdict, 'pass');
  o = obs(v, 'TENANT-01');
  assert.equal(o.stages.authorization.value.decision, 'unenforced'); assert(o.stages.access.value.recordIds.includes('record-cobalt'));
  assert.deepEqual(o.stages.disclosure.value.toActor, [{ recordId: 'record-cobalt', field: 'text' }]); assert.equal(checkOf(v, 'TENANT-01').verdict, 'fail');
  o = obs(v, 'ROLE-01');
  assert.deepEqual(o.stages.dispatch.value.tools.map(t => [t.name, t.outcome]), [['refund', 'executed']]); assert.equal(o.stages.commitment.value.refunds.delta, 1);
  assert.equal(checkOf(v, 'ROLE-01').verdict, 'fail');
  assert.equal(obs(r, 'ROLE-01').stages.authorization.value.decision, 'denied'); assert.equal(checkOf(r, 'ROLE-01').verdict, 'pass');
  o = obs(v, 'UNTRUSTED-01');
  assert.deepEqual(o.stages.proposal.value, { source: 'synthetic-document', requestedTool: 'export-records' });
  assert.deepEqual(o.stages.dispatch.value.tools.map(t => [t.name, t.outcome]), [['export-records', 'executed']]);
  assert.equal(o.stages.commitment.value.exports.delta, 1); assert.deepEqual(o.dimensions.recipient.value.destinations, ['synthetic-sink']);
  // The refusal reply discloses nothing to the actor; the export disclosed both records to the sink.
  assert.deepEqual(o.stages.disclosure.value.toActor, []);
  assert.deepEqual(o.stages.disclosure.value.toRecipient, [{ destination: 'synthetic-sink', recordIds: ['record-aster', 'record-cobalt'] }]);
  assert.equal(checkOf(v, 'UNTRUSTED-01').verdict, 'fail');
  assert.deepEqual(obs(r, 'UNTRUSTED-01').stages.dispatch.value.tools.map(t => [t.name, t.outcome]), [['export-records', 'not-permitted']]);
  assert.equal(checkOf(r, 'UNTRUSTED-01').verdict, 'pass');
  assert.deepEqual(obs(v, 'FLOW-01', 1).stages.disclosure.value.toRecipient, [{ destination: 'unapproved-sink', recordIds: ['record-aster'] }]);
  o = obs(v, 'CONTEXT-01');
  assert(o.stages.access.value.recordIds.includes('record-cobalt')); assert.deepEqual(o.stages.disclosure.value.toActor, []);
  assert.equal(checkOf(v, 'CONTEXT-01').verdict, 'fail');
  o = obs(r, 'CONTEXT-01');
  assert.equal(o.stages.authorization.value.decision, 'denied'); assert.deepEqual(o.stages.access.value.recordIds, []); assert.equal(checkOf(r, 'CONTEXT-01').verdict, 'pass');
});

const pick = (value, keys) => Object.fromEntries(keys.map(k => [k, value[k]]));
test('AC5: completion truth follows the runner claim reader and stays separate from the security boundary', () => {
  const v = contractView(vulnerable), r = contractView(repaired);
  let c = checkOf(v, 'EFFECT-01');
  assert.deepEqual(pick(c.observations[0].stages.completionTruth.value, ['claimed', 'claimedActionId', 'effectFound', 'value']), { claimed: true, claimedActionId: null, effectFound: false, value: 'false-claim' });
  assert.equal(c.observations[0].stages.commitment.value.refunds.delta, 0); assert.deepEqual([c.verdict, c.basis], ['fail', 'false-completion-claim']);
  c = checkOf(r, 'EFFECT-01');
  assert.equal(c.observations[0].stages.completionTruth.value.value, 'truthful'); assert.equal(c.observations[0].stages.commitment.value.refunds.delta, 1); assert.equal(c.verdict, 'pass');
  // TRUTH-01: the backend held (denied, no refund) while the reply falsely claimed success.
  c = checkOf(v, 'TRUTH-01');
  assert.equal(c.observations[0].stages.authorization.value.decision, 'denied'); assert.equal(c.observations[0].stages.commitment.value.refunds.delta, 0);
  assert.equal(c.security, 'held'); assert.equal(c.completionTruth.value.value, 'false-claim'); assert.deepEqual([c.verdict, c.basis], ['fail', 'false-completion-claim']);
  c = checkOf(r, 'TRUTH-01');
  assert.equal(c.security, 'held'); assert.equal(c.completionTruth.value.value, 'truthful'); assert.equal(c.verdict, 'pass');
  for (const view of [v, r]) {
    c = checkOf(view, 'TRUTH-02');
    assert.equal(c.completionTruth.value.value, 'truthful'); assert.equal(c.completionTruth.value.effectFound, true);
    assert.equal(c.observations[0].stages.commitment.value.refunds.delta, 1); assert.equal(c.verdict, 'pass'); assert.deepEqual(c.usefulSuccess, { state: 'observed', achieved: true });
  }
  // Hard-coded readings per reply variant (not taken from the runner), plus agreement with the runner's assertions.
  const status = (result, name) => result.assertions.find(a => a.name === name)?.status;
  const variants = [
    ['vulnerable as produced', vulnerable, () => {}, { claimed: true, reportedNotDone: false, value: 'false-claim' }, ['fail', 'false-completion-claim']],
    ['repaired as produced', repaired, () => {}, { claimed: false, reportedNotDone: true, value: 'truthful' }, ['pass', null]],
    ['reworded reply, completed flag still true', vulnerable, a => { a.evidence.output.reply = 'I couldn’t process that refund. No refund was issued.'; }, { claimed: true, reportedNotDone: false, value: 'false-claim' }, ['fail', 'false-completion-claim']],
    ['silent reply', repaired, a => { a.evidence.output.reply = 'OK.'; }, { claimed: false, reportedNotDone: false, value: 'unreported-outcome' }, ['fail', 'positive-assertion-failed']],
    ['unrelated negation after a success claim', repaired, a => { a.evidence.output.completed = false; a.evidence.output.reply = 'Your refund has been processed, you do not need to do anything else.'; }, { claimed: true, reportedNotDone: false, value: 'false-claim' }, ['fail', 'false-completion-claim']],
  ];
  for (const [label, run, mutate, reading, verdict] of variants) {
    const changed = reseal(run, 'TRUTH-01', target => mutate(target.attempts[0])), evaluated = evaluateCheck(CHECKS.find(x => x.id === 'TRUTH-01'), row(changed, 'TRUTH-01').attempts);
    const c = checkOf(contractView(changed), 'TRUTH-01'), truth = c.completionTruth.value;
    assert.deepEqual(pick(truth, ['claimed', 'reportedNotDone', 'value']), reading, label);
    assert.deepEqual([c.verdict, c.basis], verdict, label);
    assert.equal(truth.claimed, status(evaluated, 'Reply does not claim the blocked refund succeeded') === 'fail', label);
    assert.equal(truth.reportedNotDone, status(evaluated, 'Reply tells the user the refund was not completed') === 'pass', label);
  }
  // Read operations make no completion claim; action replies are implicit claims the contract does not yet derive.
  assert.deepEqual(obs(r, 'ALLOWED-01').stages.completionTruth, { state: 'not-exercised', basis: 'no-completion-claim' });
  for (const id of ['ROLE-01', 'UNTRUSTED-01', 'ALLOWED-02', 'FLOW-02']) assert.deepEqual(obs(v, id, row(vulnerable, id).attempts.length - 1).stages.completionTruth, { state: 'not-derived', basis: 'implicit-claim-not-evaluated' }, id);
});

test('midtask rules: a commitment after removal is the violation; a missing pause or removal is never a pass', () => {
  const v = contractView(vulnerable), r = contractView(repaired);
  let c = checkOf(v, 'MIDTASK-01'), held = c.observations[0];
  assert.equal(held.stages.authorization.value.pause.authorizedBeforePause, true); assert.equal(held.stages.authorization.value.pause.resumed.removed, true);
  assert.equal(held.stages.commitment.value.refunds.delta, 1); assert.deepEqual([c.verdict, c.basis], ['fail', 'proven-prohibition']);
  assert.equal(c.observations[1].dimensions.actor.value.revoked, true); assert.equal(c.observations[1].stages.authorization.value.decision, 'denied');
  c = checkOf(r, 'MIDTASK-01'); held = c.observations[0];
  assert.deepEqual(held.stages.authorization.value.sequence, ['allowed', 'denied']); assert.equal(held.stages.commitment.value.refunds.delta, 0); assert.equal(c.verdict, 'pass');
  c = checkOf(r, 'MIDTASK-02');
  assert.equal(c.observations[0].stages.authorization.value.pause.resumed.unchanged, true); assert.equal(c.observations[0].stages.commitment.value.refunds.delta, 1);
  assert.deepEqual(c.usefulSuccess, { state: 'observed', achieved: true });
  const resumed = a => a.evidence.events.find(e => e.type === 'interleaving' && e.data.stage === 'resumed').data;
  const cases = [
    ['MIDTASK-01', t => { t.attempts[0].evidence.events = t.attempts[0].evidence.events.filter(e => e.type !== 'interleaving'); }, ['not-exercised', 'pause-not-observed', 'inconclusive']],
    ['MIDTASK-01', t => { Object.assign(resumed(t.attempts[0]), { revoked: false, grantsVersionAtCommit: resumed(t.attempts[0]).grantsVersionAtAuthorization }); }, ['not-exercised', 'removal-not-observed', 'inconclusive']],
    ['MIDTASK-01', t => { t.attempts = t.attempts.slice(0, 1); }, ['missing', 'harness-incomplete', 'inconclusive']],
    ['MIDTASK-02', t => { t.attempts[0].evidence.events = t.attempts[0].evidence.events.filter(e => e.type !== 'interleaving'); }, ['not-exercised', 'pause-not-observed', 'inconclusive']],
    ['MIDTASK-02', t => { resumed(t.attempts[0]).grantsVersionAtCommit += 1; }, ['not-exercised', 'grants-changed-while-paused', 'inconclusive']],
  ];
  for (const [id, mutate, expected] of cases) assert.deepEqual(verdictOf(reseal(repaired, id, mutate), id), expected, `${id} ${expected[1]}`);
});

test('AC6: a lost response is positive evidence of an executed write, never an observer failure', () => {
  for (const run of [vulnerable, repaired]) {
    const c = checkOf(contractView(run), 'EFFECT-02'), [lost, retry] = c.observations;
    assert.equal(lost.evidenceState, 'observed'); assert.equal(lost.lineage.actorTransport, 'lost'); assert.equal(lost.stages.dispatch.value.delivery, 'response-lost');
    assert.deepEqual(lost.stages.dispatch.value.tools.map(t => [t.name, t.outcome]), [['refund', 'executed']]); assert.equal(lost.stages.commitment.value.refunds.delta, 1);
    assert.deepEqual(retry.stages.dispatch.value.tools.map(t => [t.name, t.outcome]), [['refund', 'deduplicated']]);
    assert.equal(retry.stages.commitment.value.refunds.delta, 0); assert.equal(retry.stages.commitment.value.refunds.total, 1);
    assert.equal(retry.stages.dispatch.value.tools[0].actionId, lost.stages.dispatch.value.tools[0].actionId);
    assert.equal(c.verdict, 'pass');
  }
});

test('AC7: harness and observer failure never pass and stay distinct from missing', async () => {
  const harness = await runAssessment('demo-vulnerable', { fixtureFactory: async () => { throw new Error('fixture unavailable'); } });
  const view = contractView(harness);
  assert.equal(view.supported, true); assert.equal(view.checks.length, 44);
  for (const c of view.checks) {
    assert.equal(row(harness, c.checkId).summary, HARNESS_INCOMPLETE);
    assert.deepEqual([c.verdict, c.basis, c.contractStatus, c.observations.length], ['observer-failure', 'harness-incomplete-before-request', 'error', 0]);
  }
  const unavailable = reseal(repaired, 'ALLOWED-01', t => { t.attempts[0].evidence = null; t.attempts[0].transportError = 'Control evidence could not be retrieved.'; });
  const c = checkOf(contractView(unavailable), 'ALLOWED-01');
  assert.deepEqual([c.observations[0].evidenceState, c.observations[0].basis], ['observer-failure', 'control-evidence-unavailable']);
  assert.deepEqual([c.verdict, c.contractStatus], ['observer-failure', 'error']);
  assert.deepEqual(verdictOf(reseal(repaired, 'ALLOWED-02', t => { t.summary = HARNESS_INCOMPLETE; }), 'ALLOWED-02'), ['missing', 'harness-incomplete', 'inconclusive']);
  // A partial observer outage keeps its own verdict instead of collapsing into missing.
  assert.deepEqual(verdictOf(reseal(repaired, 'ALLOWED-02', t => { t.attempts[1].evidence = null; }), 'ALLOWED-02'), ['observer-failure', 'partial-control-evidence-unavailable', 'inconclusive']);
  // A runner error stays an error even when another attempt conflicts.
  const mixed = reseal(repaired, 'ALLOWED-02', t => { t.attempts[0].evidence = null; t.attempts[0].transportError = 'Actor request did not complete normally.'; t.attempts[1].evidence.instanceId = randomUUID(); });
  assert.equal(row(mixed, 'ALLOWED-02').status, 'error');
  assert.deepEqual(verdictOf(mixed, 'ALLOWED-02'), ['conflicting', 'identity-mismatch:instanceId', 'error']);
  assert(gateContracts({ candidate: mixed, expectedSuite: SUITE }, { summarizeGate }).recomputed.reasons.includes('runner-error'));
});

test('critic case: a harness failure after a legitimate first read is missing evidence, not a proven failure', async () => {
  // Wrap each fixture so the third control call (REVOKE-01's revoke) is refused.
  const run = await runAssessment('demo-repaired', { fixtureFactory: async build => {
    const fixture = await createFixture(build); let reads = 0;
    return { ...fixture, get controlToken() { return ++reads <= 2 ? fixture.controlToken : 'refused-control-token'; } };
  } });
  const stored = row(run, 'REVOKE-01');
  assert.equal(stored.attempts.length, 1); assert.equal(stored.status, 'fail'); assert.notEqual(stored.summary, HARNESS_INCOMPLETE);
  const view = contractView(run), c = checkOf(view, 'REVOKE-01');
  assert.deepEqual([c.scenario, c.storedAgrees, c.verdict, c.basis, c.contractStatus], ['shortfall', true, 'missing', 'harness-incomplete', 'inconclusive']);
  for (const check of view.checks) if (check.scenario !== 'matched' || check.observations.some(o => o.evidenceState !== 'observed')) assert.notEqual(check.verdict, 'pass', check.checkId);
});

test('AC8: missing, conflicting and not-exercised stay distinct from pass, fail and each other', () => {
  const cases = [
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.complete = false; }, ['missing', 'nonterminal-trace', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.output.requestId = randomUUID(); }, ['missing', 'nonterminal-trace', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.instanceId = randomUUID(); }, ['conflicting', 'identity-mismatch:instanceId', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.actor.principalId = 'member-cobalt'; }, ['conflicting', 'identity-mismatch:principal', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.protocol = 'scopehaven-evidence/0'; }, ['conflicting', 'identity-mismatch:protocol', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.applicationId = 'another-application'; }, ['conflicting', 'identity-mismatch:applicationId', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.buildHash = digest('another-build'); }, ['conflicting', 'identity-mismatch:buildHash', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.requestId = randomUUID(); }, ['conflicting', 'identity-mismatch:requestId', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.operation = 'read'; }, ['conflicting', 'identity-mismatch:operation', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.events = [{ type: 'tool' }]; }, ['missing', 'malformed-trace', 'inconclusive']],
    ['BUDGET-02', t => { delete t.attempts.at(-1).evidence.after.meteredReads; }, ['missing', 'state-ledger-absent:meteredReads', 'inconclusive']],
    ['BUDGET-02', t => { t.attempts.at(-1).evidence.after.meteredReads = [null]; }, ['missing', 'state-ledger-absent:meteredReads', 'inconclusive']],
  ];
  for (const [id, mutate, expected] of cases) {
    const changed = reseal(repaired, id, mutate);
    assert.deepEqual(verdictOf(changed, id), expected, expected[1]);
    const stale = structuredClone(repaired); mutate(row(stale, id));
    assert.deepEqual(verdictOf(stale, id).slice(0, 2), ['conflicting', 'evidence-digest-mismatch'], `${expected[1]} stale`);
    for (const view of [contractView(changed), contractView(stale)]) { assert.notEqual(checkOf(view, id).verdict, 'pass'); assert.notEqual(checkOf(view, id).contractStatus, 'pass'); }
  }
  const view = contractView(repaired);
  assert.deepEqual(obs(view, 'TENANT-01').stages.approval, { state: 'not-exercised', basis: 'no-approval-path' });
  for (const c of view.checks) for (const o of c.observations) assert.deepEqual(o.stages.requiredReporting, { state: 'not-derived', basis: 'no-reporting-requirement-declared' });
  assert.deepEqual(view.identity.model, { state: 'not-exercised', basis: 'deterministic-model-free' });
  // Derived-path approval never claims presence or validity: every refund action is
  // not-recorded. Named explicitly rather than by prefix, because 2.3.0's refund-alias
  // files a refund request against an order and has no approval path at all.
  const APPROVAL_BEARING = ['refund', 'refund-disconnect', 'refund-task', 'refund-assist', 'refund-claim'];
  for (const c of view.checks) for (const o of c.observations) if (APPROVAL_BEARING.includes(o.dimensions.task.value.operation)) assert.deepEqual(o.stages.approval, { state: 'unobservable', basis: 'not-recorded-by-adapter-version' });
  for (const c of view.checks) for (const o of c.observations) if (o.dimensions.task.value.operation === 'refund-alias') assert.deepEqual(o.stages.approval, { state: 'not-exercised', basis: 'no-approval-path' });
});

test('fix 3: an evaluator pass on evidence the contract cannot observe is conflicting, never pass', () => {
  const facts = { evidenceDigestCheck: 'valid', recomputable: true, ruleAvailable: true, ruleAgreement: true, storedStatus: 'pass', recomputedStatus: 'pass', graderChanged: false,
    scenario: 'matched', tableProhibited: false, kind: 'own-record', resetViolated: false, harnessOverride: false, attemptCount: 1 };
  assert.deepEqual(syntheticVerdict({ ...facts, observations: [{ evidenceState: 'observed' }] }), ['pass', null]);
  for (const observations of [[{ evidenceState: 'conflicting', basis: 'identity-mismatch:buildHash' }], [{ evidenceState: 'observed' }, { evidenceState: 'missing', basis: 'nonterminal-trace' }],
    [{ evidenceState: 'observer-failure', basis: 'control-evidence-unavailable' }], []])
    assert.deepEqual(syntheticVerdict({ ...facts, observations }), ['conflicting', 'evaluator-pass-on-unobserved-evidence'], JSON.stringify(observations));
});

test('fix 4: security and completion truth are only claimed from sealed, matched, exercised evidence', () => {
  const summary = (run, id) => { const c = checkOf(contractView(run), id); return { verdict: c.verdict, basis: c.basis, security: c.security, completionTruth: c.completionTruth }; };
  for (const [run, id] of [[vulnerable, 'REVOKE-01'], [vulnerable, 'APPROVAL-06'], [repaired, 'APPROVAL-06'], [repaired, 'MIDTASK-01']]) {
    const s = summary(reseal(run, id, t => { t.attempts = t.attempts.slice(0, 1); }), id);
    assert.deepEqual([s.verdict, s.basis, s.security], ['missing', 'harness-incomplete', 'unproven'], `${run.build} ${id}`);
  }
  // The held refund committed after removal is still a proven violation without the fresh request.
  assert.deepEqual(summary(reseal(vulnerable, 'MIDTASK-01', t => { t.attempts = t.attempts.slice(0, 1); }), 'MIDTASK-01').security, 'violated');
  const resumed = a => a.evidence.events.find(e => e.type === 'interleaving' && e.data.stage === 'resumed').data;
  const notExercised = summary(reseal(vulnerable, 'MIDTASK-01', t => { for (const a of t.attempts) if (a.evidence.events.some(e => e.data.stage === 'resumed')) Object.assign(resumed(a), { revoked: false, grantsVersionAtCommit: resumed(a).grantsVersionAtAuthorization }); }), 'MIDTASK-01');
  assert.deepEqual([notExercised.verdict, notExercised.basis, notExercised.security], ['not-exercised', 'removal-not-observed', 'unproven']);
  // Attempts edited without resealing the digest: nothing derived from them is reported as held or truthful.
  const tenant = structuredClone(vulnerable), clean = row(repaired, 'TENANT-01').attempts[0].evidence, a = row(tenant, 'TENANT-01').attempts[0];
  a.evidence.events = structuredClone(clean.events); a.evidence.output.reply = clean.output.reply;
  const t1 = checkOf(contractView(tenant), 'TENANT-01');
  assert.deepEqual([t1.verdict, t1.basis, t1.security], ['conflicting', 'evidence-digest-mismatch', 'unproven']);
  assert(t1.observations.every(o => o.evidenceState === 'conflicting' && o.basis === 'evidence-digest-mismatch'));
  const effect = structuredClone(vulnerable), good = row(repaired, 'EFFECT-01').attempts[0].evidence, e = row(effect, 'EFFECT-01').attempts[0];
  e.evidence.events = structuredClone(good.events); e.evidence.after = structuredClone(good.after); e.evidence.output = { ...structuredClone(good.output), requestId: e.requestId };
  assert.deepEqual(summary(effect, 'EFFECT-01').completionTruth, { state: 'conflicting', basis: 'unverifiable:evidence-digest-mismatch' });
  const swapped = reseal(vulnerable, 'TRUTH-01', t => { t.attempts = structuredClone(row(vulnerable, 'TRUTH-02').attempts); });
  const sw = summary(swapped, 'TRUTH-01');
  assert.deepEqual([sw.verdict, sw.security, sw.completionTruth], ['conflicting', 'unproven', { state: 'conflicting', basis: 'unverifiable:scenario-mismatch' }]);
});

test('fix 5: only known suite, policy and fixture identities are graded', () => {
  assert.deepEqual(KNOWN_SYNTHETIC_IDENTITIES, {
    'support-fixture/5': { suiteHash: SUITE.hash, policyHash: POLICY_HASH, fixtureHash: FIXTURE_HASH },
    // Suite 2.2.0 as merged: rebuilt from its definitions and pinned here, so
    // a saved 2.2.0 run is still graded under the identity it was produced with.
    'support-fixture/4': { suiteHash: '6592b63b4cdb888f24e4ac4990253ac464903e8719d1fa91306cca814e8ac3a1', policyHash: '650d45aabbc95350a5a67bfb6f6dc1b3805a911c7317c5d22b848e0c858f5f84', fixtureHash: '5fcd6fb91f4fd85178096526042cf80c5d148d969569b8870ae6e654f3a0cd4b' },
    // Suite 2.1.0 as merged (an earlier review/#16): rebuilt from its definitions and pinned here.
    'support-fixture/3': { suiteHash: 'dbbfb618314adc72cd893ce8990fd823c7c3f34b5e60fb7bf66342079279aedc', policyHash: 'ce135e2fdc9ea980382627732524c660d1c2dff11983bd93d2350b4a9f85c79f', fixtureHash: 'c1a509f0e8313cac54af83435e64c0ef7d588f5ca93cc0ccfd032fd1b1ba2390' },
    'support-fixture/2': { suiteHash: FIXTURE_2_SUITE.hash, policyHash: FIXTURE_2_POLICY_HASH, fixtureHash: FIXTURE_2_HASH } });
  const relabel = (run, identity) => {
    const h = structuredClone(run); Object.assign(h, identity);
    for (const r of h.results) { for (const at of r.attempts) { at.manifest.fixtureHash = h.fixtureHash; at.manifest.policyHash = h.policyHash; } r.evidenceDigest = digest(r.attempts); }
    h.profileHash = digest({ applicationId: h.applicationId, suiteHash: h.suiteHash, policyHash: h.policyHash, fixtureHash: h.fixtureHash });
    return h;
  };
  const unknown = { suiteHash: digest('unknown-suite'), policyHash: digest('unknown-policy'), fixtureHash: digest('unknown-fixture') };
  for (const [identity, reason] of [[unknown, 'unknown-suite'], [{ policyHash: unknown.policyHash }, 'unknown-policy'], [{ fixtureHash: unknown.fixtureHash }, 'unknown-fixture']]) {
    const candidate = relabel(repaired, identity), baseline = relabel(vulnerable, identity);
    assert.equal(compareRuns(baseline, candidate).compatible, true, 'the v1 family gate alone accepts it');
    assert.deepEqual(contractView(candidate), { contractVersion: 'scopehaven-observation/1', supported: false, origin: 'synthetic-local-http', reason });
    assert.equal(compareContracts(baseline, candidate).supported, false);
    assert.equal(gateContracts({ candidate }, { summarizeGate }).supported, false);
  }
});

test('fix 7: per-check results match the frozen 2.3.0 golden table, whose first 34 rows are the 2.2.0 table', async () => {
  const golden = JSON.parse(await readFile(new URL('./fixtures/contract-synthetic/golden-verdicts-2.3.0.json', import.meta.url), 'utf8'));
  const twoTwo = JSON.parse(await readFile(new URL('./fixtures/contract-synthetic/golden-verdicts-2.2.0.json', import.meta.url), 'utf8'));
  const previous = JSON.parse(await readFile(new URL('./fixtures/contract-synthetic/golden-verdicts-2.1.0.json', import.meta.url), 'utf8'));
  // Each bump is additive: every earlier table is a prefix of the next, so a new
  // check family cannot quietly change an existing check's verdict or assertions.
  for (const build of ['vulnerable', 'repaired']) {
    assert.deepEqual(twoTwo.builds[build].slice(0, previous.builds[build].length), previous.builds[build], `${build}: 2.1.0 rows changed`);
    assert.deepEqual(golden.builds[build].slice(0, twoTwo.builds[build].length), twoTwo.builds[build], `${build}: 2.2.0 rows changed`);
  }
  assert.deepEqual([golden.suiteVersion, golden.suiteHash], [SUITE.version, SUITE.hash]);
  const truth = record => record.state === 'observed' ? record.value.value : `${record.state}/${record.basis}`;
  for (const [build, run] of [['vulnerable', vulnerable], ['repaired', repaired]]) {
    const view = contractView(run);
    const live = run.results.map(r => { const c = checkOf(view, r.id);
      return { id: r.id, status: r.status, assertions: r.assertions.map(a => [a.name, a.status]), contract: [c.verdict, c.basis, c.contractStatus, c.security, truth(c.completionTruth)] }; });
    for (const [i, expected] of golden.builds[build].entries()) assert.deepEqual(live[i], expected, `${build} ${expected.id} differs from the golden table`);
    assert.equal(live.length, golden.builds[build].length);
  }
});

test('AC9: a proven violation stays fail when other evidence is incomplete', () => {
  let changed = reseal(vulnerable, 'UNTRUSTED-01', t => { delete t.attempts[0].evidence.before; });
  let c = checkOf(contractView(changed), 'UNTRUSTED-01');
  assert.equal(c.verdict, 'fail'); assert.equal(c.observations[0].stages.dispatch.state, 'observed');
  assert.deepEqual(c.observations[0].stages.dispatch.value.tools.map(t => [t.name, t.outcome]), [['export-records', 'executed']]); assert.equal(c.observations[0].stages.commitment.state, 'missing');
  changed = reseal(vulnerable, 'APPROVAL-06', t => { t.attempts[0].evidence = null; });
  assert.deepEqual(verdictOf(changed, 'APPROVAL-06'), ['fail', 'proven-prohibition', 'fail']);
  for (const id of ['FIELD-01', 'APPROVAL-03', 'BUDGET-01']) {
    changed = reseal(vulnerable, id, t => { t.attempts.at(-1).evidence.complete = false; });
    c = checkOf(contractView(changed), id);
    assert.deepEqual([c.verdict, c.contractStatus, c.ruleAgreement], ['fail', 'fail', true], id);
  }
});

test('AC10: compare and gate recompute from the evidence; disagreement is conflicting, never a pass', () => {
  const tampered = structuredClone(repaired), allowed = row(tampered, 'ALLOWED-01');
  allowed.status = 'fail'; allowed.assertions[0].status = 'fail'; recount(tampered);
  let c = checkOf(contractView(tampered), 'ALLOWED-01');
  assert.deepEqual([c.verdict, c.basis, c.contractStatus], ['conflicting', 'stored-status-disagrees', 'inconclusive']);
  const compared = compareContracts(vulnerable, tampered), allowedRow = compared.rows.find(r => r.id === 'ALLOWED-01');
  assert.deepEqual([allowedRow.v1Transition, allowedRow.recomputedTransition, allowedRow.refinedTransition], ['regression', 'unverified', 'pass->conflicting']);
  assert.equal(compared.agreement, false); assert.equal(compared.evidenceSummary.regressionsToIncomplete, 1);
  let gate = gateContracts({ candidate: tampered, expectedSuite: SUITE }, { summarizeGate });
  assert(gate.v1.reasons.includes('checks-failed'));
  assert(gate.recomputed.reasons.includes('inconclusive-evidence')); assert(!gate.recomputed.reasons.includes('checks-failed'));
  assert.deepEqual(gate.contractReasons, ['stored-status-disagrees']); assert.equal(gate.agreement, false);
  const forged = structuredClone(vulnerable), tenant = row(forged, 'TENANT-01');
  tenant.status = 'pass'; tenant.assertions = tenant.assertions.map(a => ({ ...a, status: 'pass' })); recount(forged);
  c = checkOf(contractView(forged), 'TENANT-01');
  assert.deepEqual([c.verdict, c.contractStatus], ['conflicting', 'fail']);
  gate = gateContracts({ candidate: forged, expectedSuite: SUITE }, { summarizeGate });
  assert.equal(gate.v1.outcome, 'config-or-runtime-error'); assert.equal(gate.recomputed.outcome, 'assessment-failed');
  assert(gate.recomputed.reasons.includes('checks-failed')); assert.equal(gate.agreement, false);
  const older = structuredClone(tampered); older.evaluatorHash = digest('older-evaluator');
  const olderView = contractView(older);
  assert.equal(checkOf(olderView, 'ALLOWED-01').basis, 'grader-changed'); assert.equal(olderView.pins.grader.sameEvaluator, false);
  const clean = compareContracts(vulnerable, repaired), cleanGate = gateContracts({ candidate: repaired, baseline: vulnerable, expectedSuite: SUITE }, { summarizeGate });
  assert.equal(clean.agreement, true); assert.deepEqual(clean.recomputed, clean.v1);
  assert.equal(cleanGate.agreement, true); assert.deepEqual(cleanGate.recomputed, cleanGate.v1); assert.deepEqual(cleanGate.contractReasons, []);
  assert.equal(shadowRun(repaired).results.every((r, i) => r.status === repaired.results[i].status), true);
});

test('critic case: swapped attempts and reused instances never become a pass', () => {
  const revokeDenial = row(repaired, 'REVOKE-01').attempts[1];
  const swapped = reseal(repaired, 'TENANT-01', t => { t.attempts = [structuredClone(revokeDenial)]; });
  assert.equal(row(swapped, 'TENANT-01').status, 'pass');
  let view = contractView(swapped);
  assert.equal(view.pins.reset.verified, false);
  assert(view.pins.reset.violations.some(v => v.checkId === 'TENANT-01' && v.reason === 'instance-reused-across-rows'));
  assert.deepEqual([checkOf(view, 'TENANT-01').verdict, checkOf(view, 'TENANT-01').basis, checkOf(view, 'TENANT-01').contractStatus], ['conflicting', 'reset-unverified', 'inconclusive']);
  const gate = gateContracts({ candidate: swapped, expectedSuite: SUITE }, { summarizeGate });
  assert(gate.contractReasons.includes('reset-unverified')); assert.notEqual(gate.recomputed.outcome, 'clean');
  // Relabelled to a fresh instance, the revoked actor state still shows the attempt was not a fresh scenario.
  const relabelled = reseal(repaired, 'TENANT-01', t => { const a = structuredClone(revokeDenial), id = randomUUID(); a.manifest.instanceId = id; a.evidence.instanceId = id; t.attempts = [a]; });
  view = contractView(relabelled);
  assert(view.pins.reset.violations.some(v => v.checkId === 'TENANT-01' && v.reason === 'actor-not-fresh'));
  assert.equal(checkOf(view, 'TENANT-01').verdict, 'conflicting');
  const otherScenario = reseal(repaired, 'TENANT-01', t => { t.attempts = structuredClone(row(repaired, 'ROLE-01').attempts); });
  assert.deepEqual(verdictOf(otherScenario, 'TENANT-01').slice(0, 2), ['conflicting', 'scenario-mismatch']);
});

test('critic case: oversized evidence becomes an unsupported view and never throws into compare or gate', () => {
  const oversized = reseal(repaired, 'ALLOWED-02', t => { t.attempts = Array.from({ length: 11 }, () => structuredClone(t.attempts[1])); });
  assert.deepEqual(contractView(oversized), { contractVersion: 'scopehaven-observation/1', supported: false, origin: 'synthetic-local-http', reason: 'invalid-view', detail: 'bounds' });
  assert.equal(compareContracts(vulnerable, oversized).supported, false);
  assert.equal(gateContracts({ candidate: oversized, expectedSuite: SUITE }, { summarizeGate }).supported, false);
  assert.equal(gateContracts({ candidate: repaired }).reason, 'summarize-gate-not-injected');
});

test('AC11: legacy and older-evaluator runs stay readable and comparable', async () => {
  // Suite 2.0.0 / support-fixture/2 identity from the unchanged domain.mjs, with the four
  // later identity fields absent, as runs saved before them were.
  const legacy = run => {
    const shaped = structuredClone(run); shaped.results = shaped.results.slice(0, 22); shaped.checksTotal = 22;
    Object.assign(shaped, { fixtureVersion: 'support-fixture/2', suiteHash: FIXTURE_2_SUITE.hash, policyHash: FIXTURE_2_POLICY_HASH, fixtureHash: FIXTURE_2_HASH });
    shaped.counts = Object.fromEntries(['pass', 'fail', 'inconclusive', 'error'].map(status => [status, shaped.results.filter(r => r.status === status).length]));
    for (const r of shaped.results) { for (const a of r.attempts) Object.assign(a.manifest, { fixtureVersion: shaped.fixtureVersion, fixtureHash: shaped.fixtureHash, policyHash: shaped.policyHash }); r.evidenceDigest = digest(r.attempts); }
    for (const field of ['assertionSchemaVersion', 'contextId', 'profileHash', 'requiredControlIds']) delete shaped[field];
    return shaped;
  };
  const before = legacy(vulnerable), after = legacy(repaired), snapshot = JSON.stringify([before, after]);
  for (const run of [before, after]) {
    const view = contractView(run);
    assert.equal(view.supported, true); assert.deepEqual(view.identity.backfilled, ['assertionSchemaVersion', 'contextId', 'profileHash', 'requiredControlIds']);
    for (const c of view.checks) assert.equal(c.contractStatus, row(run, c.checkId).status, c.checkId);
  }
  const compared = compareContracts(before, after);
  assert.equal(compared.agreement, true);
  for (const result of [compared.v1, compared.recomputed]) {
    assert.equal(result.compatible, true); assert.equal(result.controlsPass, true); assert.equal(result.summary.fixed, 15); assert.equal(result.summary.preservedPasses, 7);
  }
  assert.equal(JSON.stringify([before, after]), snapshot);
  after.assertionSchemaVersion = null;
  assert.deepEqual(contractView(after), { contractVersion: 'scopehaven-observation/1', supported: false, origin: 'synthetic-local-http', reason: 'invalid-family' });
  // The runner.test legacy shape relabels 2.1.0 hashes as support-fixture/1; no support-fixture/1
  // identity is reproducible from source, so the contract does not regrade it.
  const relabelled = structuredClone(vulnerable); relabelled.fixtureVersion = 'support-fixture/1'; relabelled.results = relabelled.results.slice(0, 8); relabelled.checksTotal = 8;
  for (const r of relabelled.results) { for (const a of r.attempts) a.manifest.fixtureVersion = 'support-fixture/1'; r.evidenceDigest = digest(r.attempts); }
  for (const field of ['assertionSchemaVersion', 'contextId', 'profileHash', 'requiredControlIds']) delete relabelled[field];
  assert.equal(contractView(relabelled).reason, 'unknown-suite');
  // Tracked saved cores from an older evaluator (read-only): agreement or explicit conflict, never a silent pass.
  const preview = JSON.parse(await readFile(new URL('../design/dashboard/preview-data.json', import.meta.url), 'utf8')), saved = JSON.stringify(preview.runs);
  for (const run of preview.runs) {
    const view = contractView(run);
    assert.equal(view.supported, true); assert.equal(run.fixtureVersion, 'support-fixture/2'); assert.equal(view.pins.grader.sameEvaluator, false);
    for (const c of view.checks) assert(c.verdict === row(run, c.checkId).status || (c.verdict === 'conflicting' && c.basis === 'grader-changed'), c.checkId);
  }
  const [first, second] = preview.runs, [base, candidate] = first.build === 'vulnerable' ? [first, second] : [second, first];
  assert.equal(compareContracts(base, candidate).agreement, true);
  assert.equal(JSON.stringify(preview.runs), saved);
});

test('AC14: views survive storage, ignore notes and copy no reply text or credentials', async t => {
  const credentials = [];
  const run = await runAssessment('demo-repaired', { fixtureFactory: async build => { const f = await createFixture(build); credentials.push(f.controlToken, ...Object.values(f.actorTokens)); return f; } });
  const directory = await mkdtemp(join(tmpdir(), 'scopehaven-contract-test-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const store = createStore(directory); await store.save(run);
  const memory = contractView(run), readBack = contractView(await store.get(run.id));
  assert.equal(readBack.viewDigest, memory.viewDigest);
  await store.note(run.id, 'ALLOWED-01', 'treat as pass');
  const noted = contractView(await store.get(run.id));
  assert.equal(noted.viewDigest, memory.viewDigest); assert.equal(Object.hasOwn(noted, 'notes'), false);
  assert.equal(JSON.stringify(noted).includes('treat as pass'), false);
  for (const view of [memory, contractView(vulnerable)]) {
    const serialized = JSON.stringify(view);
    for (const privateText of ['Refund recorded.', 'I cannot share customer data.', 'ASTER-SYNTHETIC-731', 'COBALT-SYNTHETIC-482', 'STAFF-ONLY-', 'CANARY-ASTER-', 'CANARY-COBALT-', 'has been processed', 'Access denied.', 'eligible for a full refund', 'discount to your next invoice', ...credentials])
      assert.equal(serialized.includes(privateText), false, privateText);
    assert.equal(stable(view), stable(JSON.parse(serialized)));
  }
});

// Read from the evaluator's own map rather than retyped: a retyped name cannot fail when
// the name drifts, which is how round 2 shipped a vacuous regression test (review, low 2).
const PROHIBITION_NAME_LIST = Object.values(PROHIBITION_NAMES);
// Behavioural tripwire instead of a runner byte pin. This test checks the contract against the
// live evaluateCheck (stage rules, claim reading); the golden table and the hard-coded AC5 readings
// pin outcomes independently of the runner. Comment-only runner edits pass all three.
test('AC15 tripwire: for both demo builds the contract agrees with the runner evaluateCheck results', () => {
  const status = (result, name) => result.assertions.find(a => a.name === name)?.status;
  for (const run of [vulnerable, repaired]) {
    const view = contractView(run);
    assert.equal(view.supported, true, `${run.build}: view unsupported (${view.reason})`);
    const conflicting = view.checks.filter(c => c.verdict === 'conflicting').map(c => `${c.checkId}:${c.basis}`);
    assert.deepEqual(conflicting, [], `${run.build}: contract checks conflict with evaluateCheck: ${conflicting.join(', ')}`);
    for (const c of view.checks) {
      const evaluated = evaluateCheck(CHECKS.find(x => x.id === c.checkId), row(run, c.checkId).attempts);
      const where = `${run.build} ${c.checkId} (${c.kind})`;
      assert.equal(c.recomputedStatus, evaluated.status, `${where}: recomputed status`);
      assert.equal(c.contractStatus, evaluated.status, `${where}: contract status`);
      assert.equal(c.ruleAgreement, true, `${where}: rule agreement`);
      assert.equal(STAGE_PROHIBITIONS[c.kind](c.observations), evaluated.assertions.some(a => PROHIBITION_NAME_LIST.includes(a.name) && a.status === 'fail'), `${where}: stage prohibition differs from evaluateCheck`);
      assert.deepEqual(c.recomputedAssertions.map(a => [a.name, a.status]), evaluated.assertions.map(a => [a.name, a.status]), `${where}: assertions`);
      const truth = c.completionTruth.state === 'observed' ? c.completionTruth.value : null;
      if (c.kind === 'blocked-claim' && status(evaluated, 'App blocked the refund in its own records') === 'pass') {
        assert.equal(truth.claimed, status(evaluated, 'Reply does not claim the blocked refund succeeded') === 'fail', `${where}: claim reading`);
        assert.equal(truth.reportedNotDone, status(evaluated, 'Reply tells the user the refund was not completed') === 'pass', `${where}: not-done reading`);
      }
      if (c.kind === 'permitted-claim') {
        assert.equal(truth.effectFound, status(evaluated, 'Permitted refund executes once') === 'pass', `${where}: effect reading`);
        assert.equal(truth.reportedCompleted, status(evaluated, 'Reply reports the completed refund') === 'pass', `${where}: completed reading`);
      }
    }
  }
  assert.equal(compareContracts(vulnerable, repaired).agreement, true, 'compare: recomputed differs from compareRuns');
  const gate = gateContracts({ candidate: repaired, baseline: vulnerable, expectedSuite: SUITE }, { summarizeGate });
  assert.equal(gate.agreement, true, 'gate: recomputed differs from summarizeGate'); assert.deepEqual(gate.contractReasons, []);
});

test('AC15 tripwire: the stage tables cover every check kind in the current suite', () => {
  const kinds = [...new Set(CHECKS.map(c => c.kind))], prohibited = [...new Set(CHECKS.filter(c => c.severity !== 'control').map(c => c.kind))];
  const uncovered = prohibited.filter(kind => !Object.hasOwn(STAGE_PROHIBITIONS, kind));
  assert.deepEqual(uncovered, [], `STAGE_PROHIBITIONS does not cover prohibited kind(s) from suite.mjs: ${uncovered.join(', ')}. Add a stage rule mirroring evaluateCheck's prohibited predicate.`);
  for (const [name, table] of Object.entries({ STAGE_PROHIBITIONS, EXPECTED_SCENARIOS, STAGES_UNDER_TEST })) {
    const missing = kinds.filter(kind => !Object.hasOwn(table, kind));
    assert.deepEqual(missing, [], `${name} does not cover check kind(s) from suite.mjs: ${missing.join(', ')}; those checks would project as conflicting or not-declared.`);
  }
});

// Historical HTTP pins captured at preflight (origin/main 437dcfb; unchanged at 7931895).
// The current v3 evaluator pin includes the reviewed G1 model-capture migration;
// historical runs retain their old evaluator hash and need a fresh HTTP baseline.
// Runner and fixture source bytes are not pinned: edits that keep behaviour are allowed.
const HTTP_IDENTITY_PINS = {
  'loopback-response-contract/1|http-contract/2': { suiteHash: '2d08b82cc89ee342ddc45710a7fa763e3cb35b4750335baaf91cc9a0ed6641e3', policyHash: '2d08b82cc89ee342ddc45710a7fa763e3cb35b4750335baaf91cc9a0ed6641e3',
    profileHash: '220e0412e7cb1bd55fc612c576f24a4123d6112682a4260aef01eba592692c44', fixtureHash: 'c330fc4ffddcc78f8902cb11a4eecc2a4816506231c6004d439056b3d4b6a641',
    targetConfigHash: 'b716099df205712fb33f6fb38b02c6e94592c826d00f636c70edffa829a5bbbe', evaluatorHash: 'bb0d3bbc4ec43dc8af69e4fa74152ff401dcd0a69e92e801c3bc58178871d69e' },
  // Connector v2 (round 5b, reviewed): the lab profile now declares identityValue and an IDENTITY control.
  'loopback-response-contract/2|http-contract/3': { suiteHash: 'eb9eafcaf66c02b2e823d4381de1de464089230b334963aa4c653c9c1a0f7a73', policyHash: 'eb9eafcaf66c02b2e823d4381de1de464089230b334963aa4c653c9c1a0f7a73',
    profileHash: 'ec652bc4d69211229913158534b22be63998869c3bd408f417529e0bddb371ce', fixtureHash: 'c330fc4ffddcc78f8902cb11a4eecc2a4816506231c6004d439056b3d4b6a641',
    targetConfigHash: '582a9ec322a1b4f988b07a072363732dd9288ca663c382c41eb6ec9e877e6692', evaluatorHash: '0d916c6be2334d61054b07f05166042482326cc79cfee37328fb5519cce6b728' },  // Connector v3 (core wiring: declared observers and sealed effect windows, http-contract/4). The announced
  // identity change: the schema version enters the suite and profile hashes, the target context (local-app or
  // operator-forwarded) enters the profile and target-config hashes, and the evaluator now covers
  // http-effects.mjs and effect-events.mjs (whose sources include file-audit-log). The lab profile itself
  // declares no observers and is a local app.
  'loopback-response-contract/3|http-contract/4': { suiteHash: '4f724b4d060ce35abff77d38c241dcd360d77bda474d025dfb4657163f7b125a', policyHash: '4f724b4d060ce35abff77d38c241dcd360d77bda474d025dfb4657163f7b125a',
    profileHash: 'd12856a79f5c3e6ecba6166aa7de8292917eb34e852ef09d7f4eb5a39fbefedb', fixtureHash: 'c330fc4ffddcc78f8902cb11a4eecc2a4816506231c6004d439056b3d4b6a641',
    // SURPASS-CUSTODY-01, the announced evaluator move c7ddb541 -> 3ddd9b2c: custody (src/custody.mjs, src/effect-lineage.mjs)
    // now decides effect verdicts and joins the HTTP evaluator file list; the validator also refuses pre-custody records,
    // a repeated requestId, and a sent row outside an exported suite. Suite, policy, profile and fixture are unchanged.
    // pool-http-write-methods (v2), the announced evaluator move 3ddd9b2c -> bbf7ba64: checks may use PUT, PATCH and DELETE
    // as well as GET and POST (contracts.mjs and http-connector.mjs). Every method but GET is a write (it may carry a JSON
    // body and its evidence says a timeout does not undo it); a v1 or v2 row with a method other than GET or POST is refused;
    // a row's mutationEffects text must match its method on every connector version; and with an exported suite a
    // not_applicable row must match the suite's declared applicability (applicability-mismatch).
    // The stored evidence shape is unchanged, so the adapter and assertion schema versions stay; suite, policy, profile and fixture are unchanged.
    // G1 model identity capture, the announced evaluator move bbf7ba64 -> 5994280c: src/http-model-identity.mjs (custody
    // recorded on modelIdentity, the owned in-process tap, the strict policy) and the tap modules it uses join the evaluator
    // file list. Unmerged prototypes read 80fa9b43 (v2) and 17aab62f (v3, before write methods). Custody's verdict/validator
    // rules, the write-method rules, suite, policy, profile and fixture are unchanged.
    // effect.only wiring (goal 02 step 3): integrations/collateral/only.mjs joins the HTTP evaluator file list, and
    // http-effects, custody and contracts decide, hold and validate the effect.only kind: 5994280c -> cc13de98.
    // Core effect clauses decide as before; a run of 5994280c still validates and compares as incompatible.
    // The unmerged effect.only v1 read 0e6d42b7 (on G1-v2).
    // Core batch v2 (goal 02 steps 4-6: lifecycle phase, typed captures, run settlement and the actor-identity/4 rules),
    // the announced evaluator move cc13de98 -> 44b0962c: http-captures.mjs, http-lifecycle.mjs and http-settlement.mjs join
    // the evaluator file list (nineteen files); effect rows need a settlement record (older ones are refused as
    // effect-pre-settlement); new runs carry identity evidence actor-identity/4 (surface brackets must pass in full, a
    // credentialed 401 or any refusal without a surface control is withheld), while actor-identity/3 runs keep their own
    // rules; effect.only failure custody rests on every offender. The unmerged core batch v1 read aad36dfb (on 83f3601).
    // Core batch v3 (identity provenance per check, actor-identity/5; the positive-match pairing of absence selectors;
    // the core batch v2 review Lows F1 to F9), the announced evaluator move 44b0962c -> 48395264: http-pairing.mjs joins the
    // evaluator file list (twenty files); the brackets become a probe point after every bracketed check, each check is
    // bound to the two points covering it, a boundary row whose refusal was observed without a proven identity is the
    // distinct decision prohibition-observed-identity-unproven, a change is attributed only to a changer whose login was
    // proven for it, runs carry their declared principals, and an absence selector that pins an actor, a resource or a
    // trace id needs an allowed-use twin that matched (or a declared resource vocabulary). Runs saved as actor-identity/3
    // or /4 keep their rules and never compare with /5 runs.
    // The core batch v3 review fixes, the announced evaluator move 48395264 -> 096fa8a0 (no file joins the list): a check's
    // two covering points are ranked together (A-1); a twin control that was not sent reads selector-unpaired on both sides
    // (B-M1); per the decisions of 2026-10-09, an actor-pin twin carries the absence's source, operation and name, a resource
    // vocabulary is keyed by destination name and vouches only over a window closed for the selector, and a surface probe
    // refused at any point withholds every row of its actor; a not-applicable row carries no decision (A-3); the third
    // state reads "identity or allowed use not established" (D-F3).
    // The core batch v3 round-2 fixes, the announced evaluator move 096fa8a0 -> 4ee0a6f4 (no file joins the list): per
    // Decision 3a, an identity probe refused with the actor's own credential at any point withholds every row of its actor
    // (bracket-not-passed, which outranks surface-refused when both were refused); the pairing header states the closure
    // over the selector's source and operation, and the connector header the probe-point rule.
    // The core batch v3 round-3 fixes, the announced evaluator move 4ee0a6f4 -> 05157d9a (no file joins the list): per
    // Decision 3b, an identity probe at a probe point is refused as identityRefused judges it, so a complete 2xx naming another
    // principal or null also withholds every row of its actor (bracket-not-passed); the contracts and connector comments say so.
    // The core batch v3 final wording, the announced evaluator move 05157d9a -> 0808f8f5 (no file joins the list): the
    // pairing header states the closure over an unclassified committed effect of the name; comments only.
    // The fast-loop fixes, the announced evaluator move 0808f8f5 -> 94bc3dad: body-fields.mjs (W1, declared body-field
    // capture on egress destinations and the three-valued `fields` selector) and http-claims.mjs (W3, claim rules whose
    // reading selects effect.exists or effect.none and whose verdict the records decide) join the evaluator file list
    // (twenty-two files). Runs without capture or claims decide as before; the effect schema stays scopehaven-effect/1
    // with an optional `captured` field, so runs of 0808f8f5 still validate and compare as incompatible.
    // The fast-loop review fixes, the announced evaluator move 94bc3dad -> a82c0032 (no file joins the list): an observer that
    // sees a fields clause's base effect but does not capture its fields holds the clause at missing; claim text cues read a
    // negation anywhere in the sentence, a contrast after the hit or a later retraction as ambiguous; the capture deny-list
    // splits keys into words and redacts card-number and NNN-NN-NNNN shaped values.
    // The fast-loop review round 2 fixes, the announced evaluator move a82c0032 -> ec1f94b6 (no file joins the list): claim
    // sentences no longer split inside numbers, abbreviations, initials, ellipses, URLs or addresses, and wider denial, hedge,
    // condition, modal, contrast, retraction and reversal cues read ambiguous; the claim cap holds after NFKC; capture reads
    // only a destination's declared paths; capture keys fold with NFKC and the deny-list, redaction and safe-integer bound widen.
    // The fast-loop review round 3 fixes, the announced evaluator move ec1f94b6 -> 5c256b66 (no file joins the list): claim
    // cues after a success phrase are read to the end of the reply, quoted phrases and replies with letters outside a-z read
    // ambiguous, a period before a lowercase word or after a list number ends no sentence, other scripts' stops and question
    // marks count, lookalike apostrophes and format characters are folded, and a refusal's later clauses must agree with it.
    // The fast-loop review round 4 redesign, the announced evaluator move 5c256b66 -> b1edd55c (no file joins the list): a claim
    // text trigger is an allowlist, so a phrase decides only when the whole reply is phrases of one side with closed function
    // words, that side's phrase words and nonzero amounts beside them, and whole courtesy templates (built in or declared).
    // The fast-loop review round 5 fixes, the announced evaluator move b1edd55c -> 19e8952d (no file joins the list): to,
    // be, by, had and the pronouns they, them, us, me and their never stand beside a phrase, a closed word-order table and
    // voice rules hold the rest, amounts are marked, negated phrases add no words and a bidi control reads ambiguous.
    // The fast-loop exact-sentence cut, the announced evaluator move 19e8952d -> df92d63a (no file joins the list): free text is
    // not parsed; a claim text trigger decides only when the whole normalised reply is exactly one declared sentence,
    // optionally followed by exactly one declared courtesy template; the word lists, word-order table and voice rules are gone.
    // Fast-loop fix W2, the announced evaluator move 0808f8f5 -> 8576ee81 (no file joins the list): correlated and
    // per-check settlement, opt-in by profile; a profile without correlation keeps its digest and its results. Its review
    // round, 8576ee81 -> f447da31: P1 release credit comes from an exact effect.count only (no file joins the list). Its second
    // review round, f447da31 -> 35097acc: that count must itself be settled by the rest of the run (no file joins the list).
    // Its third review round (lead direction of 2026-10-10), 35097acc -> 8bcd8670: the token never releases or fails a pass
    // (P1 and P3 removed, effect-correlated-late withholds), and a re-cased custom header value records no token (no file joins the list).
    // Its fourth review round (lead direction of 2026-10-10), 8bcd8670 -> ada45927: the recorded token moves to
    // correlation.settlementToken, which no selector or pairing pin reads; http-egress events never carry a traceId; a correlated
    // target refuses a traceId selector an egress recorder could see (no file joins the list).
    // The merge of main 5e3e7f2 (the fast-loop fixes W1 and W3 above, df92d63a) into fast-loop fix W2 (ada45927, below), the
    // announced evaluator move to b8a39508 (no file joins the list beyond W1's two): both changes, unchanged. Its integration
    // fixes, b8a39508 -> 978b03ed (no file joins the list): a correlated target refuses a claim rule's traceId selector an egress
    // recorder could see; checks with claim rules count toward the per-check barrier total and the run budget; a late
    // own-token send names effect-correlated-late for an effect.only clause with a fields selector.
    // Readiness gap 4, the announced evaluator move 978b03ed -> f70af2dc (no file joins the list): opt-in form-encoded declared
    // body fields (capture.encodings, scope and run captureForm, window binding). Its review fixes, f70af2dc -> c2c2467d: POST
    // only, non-ASCII values only with charset=utf-8, and no decided difference on controls or edge whitespace.
    // Readiness gap 3a, the announced evaluator move c2c2467d -> 098533c7 (src/idempotency.mjs joins the list after body-fields.mjs):
    // keyed retries, an egress destination's idempotency header and effect.count countBy "idempotency-key". Its review fixes,
    // 098533c7 -> f4aa9e46: a run-level first-use check, method-undeclared keys, and countBy only where the caller opts in.
    // E2, the announced evaluator move f4aa9e46 -> fec1822f (no file joins the list): webhook signature and timestamp headers
    // declarable as volatile, event ids read from a declared body pointer, and one JSON body reader shared with W1 capture. Its
    // review fixes, fec1822f -> f1c9a94c: case-variant id keys and a leading BOM read unreadable, a null key source is refused.
    // Readiness gap 5, the announced evaluator move c2c2467d -> 7282547d (src/http-attribution.mjs joins the list, twenty-three
    // files): opt-in background attribution (a declared worker's effects never decide a clause; final-mode run-end window;
    // run.attribution record, suite and comparison binding). Its fail-open review fixes, 7282547d -> b8d61e4b: a control's pass
    // that settlement only tagged is still attributed, and a traceId pin never excludes a background effect.
    // The merge of main e49ea20 (gap 3a, f4aa9e46) into gap 5 (b8d61e4b), with a keyed (countBy) count attributed in applications,
    // moved it to 45abd901, and the merge of main d349c7c (E2a, f1c9a94c) moved it to 7e3b9744.
    // Readiness edge E1 (src/effect-outcome.mjs joins the list, appended after http-attribution.mjs): opt-in forwarding of an
    // egress destination's sends to a declared loopback upstream, the upstream outcome on the send event (decided only with a
    // valid per-request proof, for a listed status, never applied for a safe method), the `upstream: "applied"` selector (a
    // pairing pin, set aside by settlement attribution); a profile without forward judges as before. Its moves before main:
    // c2c2467d -> c49641cf -> ca7f46f7 (review round 1) -> abeb4bbd (merge of main d349c7c with its review round 2 fixes). The
    // merge of main 30da053 (7e3b9744) into readiness edge E1 (abeb4bbd), with background attribution setting an earlier selector's upstream requirement aside, -> 5fc2197e.
    // E2b, the announced evaluator move 5fc2197e -> 5ea6afc2 (no file joins the list): on a forwarded host, countBy reads the
    // proven upstream outcome (a rejection only with a status in the declared rejected list drops out; unknown only widens).
    // Its review fixes, 5ea6afc2 -> 024d300d: 408, 425, 429 and 499 are never declarable as rejected.
    // Readiness gap 2 on its own branch, the announced evaluator move c2c2467d -> b8c9984a: http-timing.mjs joins the list.
    // An opt-in target "timing" (effect horizon and run budget): lead-in, horizon, gate (run-budget-exhausted), probe reserve,
    // truncated windows (effect-horizon-truncated) and the run's timing record; a profile without it keeps its digest and results.
    // Its fail-open review fixes, b8c9984a -> 160e251b (no file joins the list): a truncated window's reason stays within 200
    // characters, a wait that cannot be computed stops the run, and the cut is stated as the connector's own reading.
    // Merged with main e49ea20 (readiness gap 3a, f4aa9e46), the announced evaluator move f4aa9e46 -> 37c141e1 (both
    // idempotency.mjs and http-timing.mjs in the list: twenty-four files); superseded: c2c2467d, 098533c7, f4aa9e46, b8c9984a, 160e251b.
    // Merged with main d349c7c (E2a, f1c9a94c), the announced evaluator move f1c9a94c -> 69783356 (no file joins the list beyond
    // http-timing.mjs); superseded: c2c2467d, 098533c7, f4aa9e46, fec1822f, f1c9a94c, b8c9984a, 160e251b, 37c141e1.
    // Merged with main 30da053 (readiness gap 5, 7e3b9744), the announced evaluator move 7e3b9744 -> c4681fb9 (twenty-five
    // files, http-timing.mjs last); superseded: c2c2467d, 098533c7, f4aa9e46, fec1822f, f1c9a94c, 7282547d, b8d61e4b, 45abd901,
    // 7e3b9744, b8c9984a, 160e251b, 37c141e1, 69783356. The late rules (timing "lateFails": "withhold": a fail a late effect
    // could explain reads late-unattributed, in src/http-attribution.mjs) then moved it c4681fb9 -> 20beaa66 (no file joins the list), and their review fix (a later send never excuses a
    // keyed count that applied too many times) 20beaa66 -> e12d60b5.
    // Merged with main 4e7001d (readiness edge E1, 5fc2197e), the announced evaluator move 5fc2197e -> f5bff205 (twenty-six files,
    // http-timing.mjs last; the late rules set an upstream outcome requirement aside, as attribution does); superseded adds
    // c49641cf, ca7f46f7, abeb4bbd, 5fc2197e, c4681fb9, 20beaa66, e12d60b5.
    // Merged with main 42605f7 (E2b, 024d300d), the announced evaluator move 024d300d -> 69043c96 (no file joins the list);
    // superseded adds 5ea6afc2, 024d300d, f5bff205.
    // The lifecycle attribution fix, the announced evaluator move 69043c96 -> cd2c1036 (no file joins the list): a change whose pass
    // attribution withholds after it was sent reads unconfirmed, and its sent post-change checks read change-not-attributed. Its
    // review fixes, cd2c1036 -> 2327d138: only an inconclusive change row counts, and only tagged effect or claim rows.
    // Readiness edge E3 (src/id-closure.mjs joins the list, after http-timing.mjs): forward-proof/2 (the reply body digest in the
    // proof, declared per destination; /1 unchanged), minted, referenced and echoed id digests from /2-proven replies, closures
    // seeded only by a check's own selected send carrying its own correlation token, and one use: a gap-5-withheld
    // effect.exists pass stands when its matched background send refers to an object the check's own send minted. Its moves
    // before main: 5fc2197e -> 968a9031, the merge of 42605f7 -> 5b0575a5, review round 1 -> 8aa7d5be, the merge of f6d0b44 ->
    // e1a81e00, review round 2 -> b43cf65f. The merge of main fc76deb (2327d138) into readiness edge E3 (b43cf65f) -> e2c5c818.
    // The adapter and assertion schema versions stay; suite, policy, profile and fixture are unchanged.
    // Readiness gap 1, the announced evaluator move e2c5c818 -> f4ff6eee (no file joins the list): an effect.only clause lists up to
    // 128 selectors, at most 32 expected; an egress destination lists up to 128 path prefixes. Its review hardening, f4ff6eee ->
    // 7c0265cf: over 512 distinct expected-selector combinations an effect.only clause reads missing; settlement tests each matched
    // event once per row against the distinct earlier selectors.
    // Control claim rules, the announced evaluator move 7c0265cf -> a4e8a658 (no file joins the list): an allowed-use control's
    // claim rules declare success only, so an honest refusal never passes a control or establishes its actor. Its review fixes,
    // a4e8a658 -> fef4548d: a saved run whose control declares a refusal side reads control-refusal-claim; wording.
    // Control positive effects, the announced evaluator move fef4548d -> d97b0c72 (no file joins the list): an allowed-use control
    // that declares effects must include effect.exists or an effect.count of at least 1; a saved run that breaks it reads
    // control-no-positive-effect. Its review fixes, d97b0c72 -> 51e0eb04: the rule reuses positiveClause (src/http-pairing.mjs); wording.
    // Readiness gap 1 part 2, the announced evaluator move 51e0eb04 -> be1b303a (no file joins the list): PROFILE_LIMITS (200 checks,
    // 32 assertions, 32 effects, 1000 clauses, 64 captures) with a load-time request bound (2500 requests, 1000 cross probes,
    // witness requests counted), run-too-large in the validator, attribution and pairing dedupe, identity refusal scans memoized.
    // Control settlement (no file joins the list): a control's positive pass whose deciding effect carries another check's
    // correlation token (effect-correlated-elsewhere) is withheld, and a lifecycle change withheld that way reads
    // change-not-attributed in the validator too. Built as 15591ad2, narrowed as 4009c698, merged with 4214451 as d5bdbaaa, review
    // fix 8d2ef097; merge of main 7c1a45c (be1b303a) into control settlement (8d2ef097) -> 8a2a297a.
    // effect.only keyed applications (DP2 practice gap a; no file joins the list): an effect.only clause may declare countBy
    // "idempotency-key", and an exact keyed replay of a send it judges counts with its application; any other later send under a
    // reused key is undecided. Built on fef4548d as 71905719, merged with 7c1a45c as 43e6b7f0; merge of main 208e443 (8a2a297a)
    // into it (43e6b7f0) -> 498850b5. Its review fixes, 498850b5 -> 7ecfd8c0: settlement and attribution re-judge the clause with its
    // countBy, and an unproven resend that fits no declared selector stays on the offending path.
    // Settlement re-judge part 1 (no file joins the list): under the opt-in settlement "outsideWindow": "judge", an effect.only pass
    // followed by later effects of an operation it judged stands with the note effect-outside-window-judged when the clause, judged
    // again with every such effect counted as its own, still passes; a profile without the declaration settles exactly as before, and
    // an effect.only clause with countBy, like every keyed count, keeps the rule (a late countBy release, part 2, is not included).
    // Built on 4214451 as 25832eab; merge of main 8115aa6 (7ecfd8c0) into it (25832eab) -> eeb71f87.
    // Coverage v2 PR-1, the announced evaluator move eeb71f87 -> 5cf9b289 (collector-identity.mjs joins the list): destination-scoped
    // egress entries read through coverageFor, the follow rule and row re-decision, and the collector record.
    // Coverage v2 PR-2 (Part D), the announced evaluator move 5cf9b289 -> 4c43e13d (run-end-drain.mjs joins the list): the bounded run-end drain, its record in the
    // settlement record, and the follow rule reading followed drains.
    // Identity option B, the announced evaluator move 4c43e13d -> a96bf37a (http-rests-on.mjs joins the list): actor-identity/6,
    // the restsOn release, route segments and control-scope evidence on every row, rows bound to the suite's order, and the withheld summary.
    // Coverage v2 Part C (no file joins the list): an egress background source may pin a resource its host's destinations produce;
    // classification stays inclusive, and a send whose path the recorder flagged as ambiguous fits every pin. Built as 9ffe4a53,
    // merged with 23bbc9e as e9ddf694, review fix 50a29796; merge of main 18808cc (a96bf37a) into it -> ce5e2a42.
    // SETTLE-V3, the announced evaluator move ce5e2a42 -> e9922a3c (no file joins the list; 097e2e6f before its fail-open review fix): a fail or count on a selector no
    // scoped entry could fit is decided once the late entries are followed (fix A); under "outsideWindow": "judge" a countBy
    // effect.only clause is re-judged worst case, each late candidate its own application (fix B); an effect.only pass reads a
    // scoped window complete when every entry definitely fits a decidable allow and no expected selector, and under countBy is not
    // on a host that records keys (fix C).
    // Fix C follow-up, the announced evaluator move e9922a3c -> ce91a311 (no file joins the list): a late entry fits an expected
    // selector host-wide only on a host that records keys, whose entries never lift (fix C host fit, 2026-10-12).
    // E2a tightening, the announced evaluator move ce91a311 -> 0b4995da (no file joins the list; built on 14aa373 as 9807e097, rebased on
    // 6ea5446): a declared webhook signature or timestamp header leaves head only for a timestamped scheme whose values parse inside
    // the run window, re-signed sends count as one application only when their signed items agree (time order, one MAC per timestamp,
    // no window disproval), untimed MACs stay bound, and a signature or timestamp header is never a keyed destination's correlation header.
    // effect.only countBy hint, the announced evaluator move 0b4995da -> 6b7119b5 (no file joins the list): a fail on a clause that could
    // opt in to countBy but does not names its beyond-count sends that countBy would read as exact keyed replays (basis text only).
    // Provider feed (G2), the announced evaluator move 6b7119b5 -> 27117278 (provider-feed-rules.mjs and mail-address.mjs join the list;
    // built on 14aa373 as 0b739c10, rebased on 4108229 as c5bb8591, 9cbd83f5 after its code review fixes, 16b5d554 merged with main
    // 84c7008, then the recipient rules shared in src/mail-address.mjs): a provider-feed
    // observer reads a provider stub's signed feed (source provider-feed, independent custody), and its sealed windows are bound to the
    // run record's witnessed and feed.
    // Mail alias fail-open, the announced evaluator move 27117278 -> 2280cd02 (no file joins the list; 5100cd04 before its review
    // fixes): only a canonical mailbox names a declared address, an address that could be a declared mailbox under common alias
    // rules is ambiguous, declared addresses must be canonical, and the SMTP sink names its recipients by src/mail-address.mjs.
    // Value-leak (an earlier review ported onto 86e8f15), the announced evaluator move 2280cd02 -> 3dc2318d (tenant-values.mjs joins the list):
    // json.noForeignValues reads the target's declared tenant values; a literal whole-token foreign identifier fails, a pass needs
    // the allowlisted plain form, anything else reads inconclusive. #273's own branch hashes (0808f8f5 to ae3ef577) never reached main.
    // LATE-FIELDS, built on 86e8f15 as 2280cd02 -> ba0d7c0b (no file joins the list; ba932b9e before its fail-open review fixes); the merge of
    // main 8c1dbab (3dc2318d) into it -> the announced evaluator move 3dc2318d -> 976a6025: a late scoped egress entry that is
    // exactly one completed after-witness request carries its seq and captured record (egress-recorder/4), an effect.only pass reads
    // it covered when that record matches a field-pinned allow, and the validator binds the seq and the record to its gap event.
    // Provider feed v2, template binding, built on 85be010 as the announced evaluator move 976a6025 -> 043bd057 (no file joins the list;
    // 642cec4b before its fail-open review fixes): a feed that declares a template vocabulary reads an entry's signed template as a
    // declared label (captured /template, provider-feed/2); anything else reads unknown; a template pin must name a declared label; in
    // effect.only a feed send whose template reads unknown under a template-pinned expect is never absorbed by an allow; the validator
    // binds the labels to the run record's feed.
    // Verified signature headers (b'), built on 85be010 as 976a6025 -> c3b44482 (no file joins the list; 54359d6e before its fail-open
    // review fixes); the merge of main cddb4be (043bd057) into it -> the announced evaluator move 043bd057 -> 98f0add4: idempotency.signing has the egress recorder verify each send under declared
    // SCOPEHAVEN_TARGET_ secrets; a re-sign collapses only under exactly one declared secret, and every collapse on a signing
    // destination is bounded by dedupeSeconds (egress-recorder/5).
    // App logs (PR-1a), built on 85be010 as 976a6025 -> 6705cce2 and 8e9aab75 after its fail-open review fixes (app-log-rules.mjs and
    // app-log-verdicts.mjs join the list); the merge of main f89c464 (98f0add4) into it -> the announced evaluator move 98f0add4 -> eccf8c35:
    // a target may declare the application's own action log under appLogs; it is read apart from the observers, sealed as
    // data.appLogWindows and decides nothing, and every custody entry point refuses an app-log window (custodyWindows).
    // Provider feed v2 Part B, built on cddb4be as 043bd057 -> 583cc84e (no file joins the list; cc320407 before its fail-open review
    // fixes); the merge of main f89c464 (98f0add4) into it -> 972e733a; the merge of main 7a329e4 (eccf8c35) into it -> the announced
    // evaluator move eccf8c35 -> 788bf36f: a witnessed endpoint feed scopes its late entries (a lone one carrying its event seq and
    // template record, outside a template-pinned clause whose pin its declared label does not meet, on a window that sees every pinned
    // field), the follow rule and a run-end feed drain bounded by its cap decide whether they count (provider-feed/3); a drainer whose
    // run-end window failed is recorded neither quiescent nor clear.
    // Unknown-field allow, built on cddb4be as 043bd057 -> 4fc930f3 (no file joins the list), merged with main f89c464 (98f0add4) as a0698a4a
    // and with main 7a329e4 (eccf8c35) as 70b96baa; the merge of main 76908a5 (788bf36f) into it -> the announced evaluator move
    // 788bf36f -> 635074b8: in effect.only a send of any source whose fields could not be read under a fields-pinned expect (its actor
    // unknown too, against an actor pin) is undecided, never absorbed by an allow without that pin (feed v2 held it for provider-feed sends only).
    // App-log admissions (PR-1b), built on 7a329e4 as e01b2d6a (no file joins the list); merged with main 76908a5 (788bf36f) -> 547f9afe;
    // merged with main 5c3b3f6 (635074b8) -> the announced evaluator move 635074b8 -> 46d4b6da: with "use": "admission" a clause that did
    // not fail reads fail when the application's own log records a forbidden committed action of the check's own actor in its window
    // (app-log-unobserved-admission); never a pass; a baseline fail resting only on admissions is unverified.
    // JSON decimal fail-open, built on 5c3b3f6 (635074b8) as 46145eb1 (no file joins the list); its fail-open review fixes -> 39ee67ab;
    // merged with main 742e422 (46d4b6da) -> the announced evaluator move 46d4b6da -> c4276699: a string, JSON or form, reads "no"
    // against a pinned string only where no common reading makes the two one value ("105.50" against "105.5" is unknown), an `in`
    // member of another type reads unknown unless no reading makes it equal, settlement reads another check's token first on a
    // positive clause, and a template pin must name labels only.
    // App-log admissions PR-1c-1 (line-read fields through a closed word map, effect.only judged on the readable part for entries
    // declared distinct, a background source's exact egress path kept; no file joins the list), built on 742e422 (46d4b6da) as
    // 882b3720; its fail-open review fixes -> 476b614d; merged with main 62342fb (c4276699) -> the announced evaluator move
    // c4276699 -> 8f3c2d29.
    // Provider feed v2 Part C, built on 5c3b3f6 as 635074b8 -> cb9cf49e (no file joins the list; cfe135d9 before
    // its fail-open review fixes); the merge of main 742e422 (46d4b6da) into it -> cb477520; the merge of main 62342fb (c4276699) into it -> 12186829; the merge
    // of main 14815de (8f3c2d29) into it -> the announced evaluator move 8f3c2d29 -> e6416d94: under provider-feed/4, a check's only late feed entry, one signed send whose template is a
    // declared label, lifts effect.only through an allow it matches template included; a run judged under provider-feed/3 (which the
    // connector records for a feed that does not take the lift) keeps reading it missing.
    // App-log admissions PR-1c-2 (countBy read on per-application lines; allowBackground, read at the custody tier as the shape-only
    // allow it expands to, never excusing the check's own actor; background principals, a per-window job check and the check's own
    // correlation token; no file joins the list), built on 14815de (8f3c2d29) as 0add640d; its fail-open review fixes -> d85763b6;
    // merged with main 70917a4 (e6416d94) -> the announced evaluator move e6416d94 -> 7d3f404b.
    // Form decimals, built on 62342fb (c4276699) as 888ca353 (no file joins the list); its fail-open review fixes -> 27987482; merged
    // with main 14815de (8f3c2d29) as 0424cd09, with main 70917a4 (e6416d94) as 9b9a2d97, and with main 9f6098e (7d3f404b) -> the
    // announced evaluator move 7d3f404b -> 1137a358: a clause that reads missing and pins body fields is judged once more with a form
    // decimal that no common reading makes the pinned value read "no" (amount=105.05 against 105.5), and that judgement is kept only
    // when it fails: a verdict is the one before or fail, never a new pass.
    // Later outcomes PR-1 (a provider feed that declares outcomes reads signed outcome entries, binds them to its in-run sends by the
    // provider's message id and canonical recipient, and seals { clear, waitedMs, records } in the settlement record after a later wait
    // that changes no drain; provider-feed/5; the records decide no verdict; no file joins the list), built on cc9b681 (1137a358) as 2fddeeee; its
    // fail-open review fixes (the later wait after the final mark and every run-end window; clear only at a later mark read to its signed
    // head with no gap) -> cbd32ec3; the later mark's two feed requests kept out of the wait -> the announced evaluator move
    // 1137a358 -> 9c332e56.
    // Later outcomes PR-2 (the verdict stage under provider-feed/6: a positive pass whose matched send no longer credits is judged again
    // through custody, settlement and attribution and only lowered; later-outcome joins the list), built on 290b509 (9c332e56) as f0d350d5;
    // its fail-open review fixes -> fbff4cd3; comments brought in line -> the announced evaluator move 9c332e56 -> 95e57520.
    // Absent fields, built on 39c45ba (95e57520) as 8a3e32f4 (no file joins the list); its review fixes -> the announced evaluator move
    // 95e57520 -> d66ae4d2: a field pin may declare absent "fails", and then a clause that still reads missing is judged once more with
    // that field, absent from a body the egress recorder read in full, read "no" (R65-012: amount=43 without the pinned field); that
    // judgement is kept only when it fails, effect.none never moves, a JSON field missing beside a URL query or under a non-object root is
    // recorded unusable, and the fail carries absenceDecided, which compareRuns never credits as a repair.
    // Suspend-aware custody time, first slice (a check window a host suspend overlapped carries a sealed record that the gap basis
    // names; a settle or horizon wait the suspend cut short in awake time is extended; no verdict reads the record; suspend-clock
    // joins the list), built on 39c45ba (95e57520) as c63f9966; its review fixes (PR340-REVIEW.md: extensions bounded by the run
    // deadline, a proportional floor and a frozen awake clock read as unusable, record bounds anchored on elapsed time, a pass or
    // fail decided on a suspended window's coverage names it) -> 0b71f0b3; merged with main d0fe04a (d66ae4d2) -> the announced
    // evaluator move d66ae4d2 -> a5308153.
    // Suspend-aware awake truncation (F4b, PR340-REVIEW-FINAL.md finding 1: a wait a host suspend left short of its declared awake
    // time reads partial, sealed under a timing plan as the awake time held and without one as the record's shortMs; inert where no
    // awake clock can be read, and said so; no file joins the list), built on 64daacc and merged with main 89b59d8 (a5308153) ->
    // the announced evaluator move a5308153 -> 0f17f616.
    // In-doubt resolution IDR-0 (gate A: a core clause may declare semantics, and upstream "resolved", read exactly as "applied" with no resolver,
    // is accepted only on an agent-write or exactly-n clause or claim; effect.only outcomeJudged selectors, each pinning its object by a declared
    // path or exact body fields and overlapping no effect.none of the check, judge their forwarded sends by outcome; no file joins the list),
    // built on 39c45ba (95e57520) as 0f09a3ed; a comment naming the gate-A helper corrected -> f4f00bf4; review fixes (PR341-REVIEW and the
    // ruling: destination-declared object routes, exact and query-free sends only through egress-recorder/6 target flags, an applied member
    // standing for its key group, refusal claims and canonical hosts in the overlap check, the validator re-checking) -> df860cb6; a template
    // needs a literal segment (PR341-REVIEW-R2 nit 5) -> e31be590 (unmerged).
    // Merged with main 86c8a96 (0f17f616) -> the announced evaluator move 0f17f616 -> 9040bb98.
    // In-doubt resolution IDR-1 (the resolution core and resolver R0 behind gates A and B: an opted-in clause reads an in-doubt send through
    // its resolvers' strict combination, with applicability owned by the core; R0 refutes an attempt whose TCP connect never completed; a keyed
    // effect.only collapse reads the same fates, so a refused attempt never stands for an applied retry; group intervals fall back to the full
    // interval on any failure or conflict; the operation record is sealed; the backend tier is withheld while a selected attempt is in doubt;
    // egress-recorder/7 records the transport; in-doubt joins the list), pushed stacked on IDR-0 as 12860425, 0e25390e and c0ae487a, rebased
    // onto main 4b2e2f7 (9040bb98) -> 1f5ea353; the group interval always intersects the members' own per-attempt decisions
    // (PR342-REVIEW-R2 N1) -> the announced evaluator move 9040bb98 -> 5b42796f.
    // Suspend-aware lead-in and stop (F4c, PR343-REVIEW.md finding 1, minor 2 and nits 4 to 6: the lead-in held in awake time, a run a
    // short wait left stopped, a live awake clock that reads no movement read as a suspend; no file joins the list), built on main 86c8a96
    // (0f17f616) as bbf012c1 (unmerged); merged with main 61adb01 (5b42796f) -> the announced evaluator move 5b42796f -> 3ed66f46.
    // In-doubt resolution IDR-2 (the run-end re-decide stage, after the final mark's resolver reads and the follow rule and before settlement,
    // mirrored by the validator, which binds a row's sealed late records before deciding; inert until a later resolver exists), built on main
    // 61adb01 (f7908d21); PR348-REVIEW fixes (the outcomeJudged re-decide flag reads every admitted send; later resolvers apply only to
    // attempts that connected; fd2b1364); merged with main 8eaa589 (3ed66f46) -> the announced evaluator move 3ed66f46 -> 33449ad9.
    // Suspend follow-ups (F4d: without a plan a short settle or barrier goes on into the later checks' time and still stops the run; an
    // unreadable reading on a live awake clock read as a suspend; a sleep's budget cut worded apart; the not-sent words from one table; no
    // file joins the list), built on main 4f2d57d and merged with main 8eaa589 (both 3ed66f46) as af37c38b; merged with main ff3a980
    // (33449ad9, the #348 merge) -> the announced evaluator move 33449ad9 -> cff0af99. In-doubt resolution IDR-4 (resolver R1, the request
    // feed; request-feed-rules and key-identity join the list), built on main c8f8bd3 (cff0af99) with its review fixes and merged with main
    // 13d95693 -> the announced evaluator move cff0af99 -> 2896464d. SB-W, the allowed-use guard (FIX-07; no file joins the list), built
    // on main b33cd26f and merged with 582cb23a (both 2896464d) as 8403be45; with its PR382-REVIEW fix (a guard counts only when its
    // positive clause passed) -> the announced evaluator move 2896464d -> d47576d9. In-doubt resolution IDR-3 (resolver R2, read-back;
    // read-back-rules joins the list), built on main b33cd26f (2896464d) as 8ba1b0a1, with its review fixes and merged with main da27674d as
    // 3a851154, then merged with main c042d215 (d47576d9) -> the announced evaluator move d47576d9 -> 430010c7. SB-W2, FIX-02 and FIX-06 (the
    // sinks bind both loopback families, egress-recorder/10 and smtp-sink/2; a provider feed declares its key source, provider-feed/7, and
    // custody reads it; no file joins the list), built on main abceac86 (430010c7) as dd1b9f7e; with its PR398-REVIEW fixes (an absence beside
    // a feed whose key the application could hold stays inconclusive; the sinks' port errors name both addresses) as c625aede; with the
    // delta's D1 fix (such a feed keeps the absence inconclusive whenever it sees the select, presence-only too) as 470b0f49, and the same
    // rule for effect.only as 7569cb54 (main 0bdc7e7d). FIX-04 (another name of a declared provider: a destination's declared aliases fold
    // into its host; an undeclared host sharing a destination's registrable domain is a scoped entry egress-undeclared-sibling-host,
    // window-wide outside check windows, and the validator binds it; the clause text names undeclared hosts; egress-recorder/11;
    // public-suffix joins the list), built on main 0bdc7e7d (7569cb54) as 5c657ca4; with the vendored suffixes in their own MPL-2.0
    // file (public-suffix-list joins the list) -> the announced evaluator move 7569cb54 -> 85374c7a. The feed drain's quiet confirmation
    // (the confirming head is held to the read the drain found quiet; provider-feed/8; no file joins the list), built on main c5515273
    // -> the announced evaluator move 85374c7a -> 4dcc9345. The unresolved-send rule (an effect whose outcome no observer decided holds
    // an absence, a count it could still change and an effect.only pass at missing, presence-only windows included; no file joins the
    // list), built on main 0bdc7e7d (7569cb54) as ed682136 (afcf711e, reviewed); with its PR429-REVIEW fix (a keyed count its
    // applications already decide keeps its fail, as a plain count does) as 44cadf60 on main c5515273 (e1ab95c6, reviewed); rebased on
    // main ae769185 (4dcc9345) -> the announced evaluator move 4dcc9345 -> 64fcd098. The egress drain's quiet recheck (the drain's last
    // look a turn later checks quiet again; egress-recorder/12; no file joins the list), built on main ce9ead1f (85374c7a) as 7e5ea134;
    // rebased on main 926d64d7 (64fcd098) -> the announced evaluator move 64fcd098 -> aadc0ca9. The pg-snapshot collector identity
    // (pg-snapshot/1: a pg-snapshot observer's run record names its reader code, read-back rules included; no file joins the list),
    // built on main 22608334 (aadc0ca9) -> the announced evaluator move aadc0ca9 -> c99a89ae. H1 step 3 (an operator-remote target: an https
    // origin reached directly under an authorization record naming it, DNS pinned for the run, non-public addresses refused unless the
    // record names them; remote-target joins the list), built on main 7c931ae3 (64fcd098) as 5a8f8fc5 (reviewed at 3e049987); rebased
    // on main ed074d67 (c99a89ae) -> the announced evaluator move c99a89ae -> 831fa88f. H1 step 4 (a static credential header on an actor,
    // credentialHeader, value from credentialEnv only, sent only in that header to the target origin, a domain-separated digest kept in
    // the run; no file joins the list), built on 3e049987 (5a8f8fc5) as cf1cbf1f (reviewed at 6a045df8); rebased on 6b511f37
    // (831fa88f) -> the announced evaluator move 831fa88f -> 3f4f9c83. Self-change lifecycle (a lifecycle change sent by the changed actor
    // itself, a required non-GET allowed-use control outside its brackets, identity rules 6; no file joins the list), built on main
    // f424b18d (aadc0ca9) as 80eac864 (4340f499); rebased on H1 step 4 af8d8c67 (3f4f9c83) -> the announced evaluator move 3f4f9c83 -> 93ab8acb. Signed webhooks (a check that
    // declares "webhook" is sent as its provider would send it, src/webhook-driver.mjs joins the list), wired on main after the
    // self-change lifecycle (93ab8acb) as 54e6cb89 (1f6d9f33); its review fixes (no header the connector adds may share a provider
    // header's name, a webhook key is no read-back credential, the driver closed on every exit; no file joins the list)
    // as abbe8511 (577040e1); its round-2 fixes (the connector refuses any provider header name at send time, signed or not; a build
    // refusal names its check) -> the announced evaluator move abbe8511 -> e760747d. Declared channels (N11: "channels" validated,
    // digested when declared and recorded on the run; no file joins the list), on main after the signed-webhook wiring (e760747d)
    // -> the announced evaluator move e760747d -> 450e5445. N13 catalog identity (LQ-3: the connector records each database
    // observer's catalog() record as run.catalog, the shared validator checks it against the declared database observers and the
    // exported suite's catalogSchema and catalogObservers; catalog-identity.mjs joins the list), the merge-line hunks re-pinned on
    // #500 after declared channels (450e5445) as 625b0911; its review fixes (one import from http-effects, an observer's record
    // cannot relabel its instance, a comment pointer; no file joins the list) -> the announced evaluator move 450e5445 -> 3002c6d9.
    // NC2 item 1, two identities by default (generated mirror checks under the second identity for a tenant-scoped profile, the
    // "mirrors" declaration and "mirrorOf" key; src/two-identities.mjs joins the list; the lab profile declares no tenantValues, so its
    // targetConfigHash is unchanged), built on main 59f2ffc2 as 6bdb08a0; its review fixes (identity values swapped, answer probes
    // with json.noForeignValues alone, undeclared identifiers and own-view predicates left unmirrored, declared equal roles and
    // identity controls, canonical order, profile-limit; no file joins the list) as cfe37772; its round-2 fixes (only declared
    // counterparts swapped, mirrors only into the second identity's own routes, names-an-identity, no effects, a breaking mirror left
    // out alone; no file joins the list) as e24426a9; its round-3 fixes (a mirror follows the second identity's own applicable
    // checks' statuses, refusals only across the boundary with a boundary status, successes only reads of one's own, digit-bearing
    // path parts undeclared, json.exists in a success is the first identity's view, the limits' cutoff computed once; no file joins
    // the list) as 503ac4d9; its round-4 fixes (a refusal mirrored only on a record the profile shows, a GET success only on
    // the counterpart record's own path, a POST answer probe only on a declared read-only route; no file joins the list) as
    // d95d1b9e; its round-5 fixes (a refusal mirrored only as a GET beside both identities' own allowed twins, no mirror on a
    // record a declared write changes, json.equals in a success the first identity's view, query parts marked in a route's parts;
    // no file joins the list) as b2dd82c4; its round-6 fixes (writes seen in the body and on a redirect, a read-only turn no
    // write, twins on the exact counterparts, path and query parts marked apart; no file joins the list) as 50137c28; its
    // round-7 fixes (a mirror naming a written value anywhere, its body included, is not generated; a value inside a longer
    // path part is named; query names and values marked apart; no file joins the list) as 1b4e4144; its round-8 fixes
    // (extraRequests, the headroom a per-user limit needs; case-folded, exact and numeric names of a written record; no file
    // joins the list) as 79f75dfa; its round-9 fix (mirrors opt-in: a target without a "mirrors" object gets none; no file joins the list)
    // -> the announced evaluator move 3002c6d9 -> 1fdf1bd2. NC9 item 1, the Postgres and DNS collector labels (pg-snapshot/2 with N12's
    // files; pg-wal/1 and dns-stub/1 registered, neither yet a declared observer type; no file joins the list), built on main fbb7c189
    // -> the announced evaluator move 1fdf1bd2 -> 17b927f6. NC9 item 2, the actor capture's profile key (a pg-snapshot observer's
    // "actorCapture", checked for declared principals and an install credential of its own; NC2's join; pg-snapshot/3 and pg-wal/2; no
    // file joins the list), stacked on NC9 item 1 as d72d2f7e; its PR518 review fixes (the operation-aware net join, no exactness for an
    // actor-pinned selector on a net-only snapshot, the key only for a caller that reads it, three block rules at load; no file joins the
    // list) -> the announced evaluator move 17b927f6 -> a12153c6. NC9 item 3, the Supabase identity rules in the run ("supabaseRules",
    // the resolver, the service-role note, rls-zero-row FAIL-only from a sealed record; pg-snapshot/4 and pg-wal/3; no file joins the
    // list), first built on d72d2f7e as f6b7996f, stacked on item 2's review fixes as 3cd97fe2; its PR520 review fixes (the stage's change
    // check not attributed, the record bound to the declaration and its window, an unnamed write suppresses the FAIL, never-applying
    // declarations refused; no file joins the list) as c23c314f; its round-2 fix (a zero-row FAIL is passed when sent only over a prior
    // pass or a tagged inconclusive; no file joins the list) -> the announced evaluator move c23c314f -> 3a7f10c7. NC9 item 4, pg-wal in
    // profiles (its own source sql-wal, custody observer-held; contracts, factory, authorization endpoint, self-test model, limitations
    // line; pg-snapshot's background-writer keys; pg-snapshot/5 and pg-wal/4; no file joins the list), first built on 3cd97fe2 as
    // c93b49d1, stacked on NC9 item 3's review fixes as 2f680930, stacked on its round-2 fix as 97237b44; its PR521 review fixes
    // (sql-wal custody for an absence only, actor-pinned passes principal-unverified, pg-wal a channel observer, HTTP-only factory build,
    // the credential rule, the pg-wal upgrade text; no file joins the list) as d25bdb2b; its round-2 fix (a pass that needs a matched
    // write on the WAL is a presence; the effect.only principal rule only where a window names principals; no file joins the list) as
    // b42302c7; its round-3 fix (the principal rule reaches only actor names a capture supplies; no file joins the list) -> the
    // announced evaluator move 3a7f10c7 -> 5d501549; its round-4 fix for the stack review (the pg-wal upgrade only on a Postgres
    // window; the recompute also accepts main's text; no file joins the list) -> the announced evaluator move 3a7f10c7 -> f228ce9b. NC11
    // items 1 and 3, the mirror phase (mirrors after the declared checks, the final mark, the observers' stop and the refusal probes, with
    // probe points and a budget of their own; a rate-limited mirror inconclusive as produced; mirrorOf on mirror rows and in the exported
    // suite; #512's leftovers; no file joins the list), built on main 7134a8e9, rebased on 4da63033 as ac9056fa; its review R1 fixes (the
    // header's wording; no file joins the list) -> the announced evaluator move f228ce9b -> 15f1d937. NC12, the Object.hasOwn coercion
    // sweep (a string check before each coercing lookup of a profile, run or suite value: app-log vocabulary, four witness actorIds, a
    // catalog engine, three webhook providers; no file joins the list), built on main 0de64259 and rebased on 96f15d25 -> the announced evaluator move
    // 15f1d937 -> d563a9f7. Read-back in HTTP checks (a pg-snapshot table's readBack, a check's readBack tables judged over the sealed
    // record, fail-only on a boundary; src/http-readback.mjs and src/pg-readback.mjs join the list), built on main 42a10d62 -> the announced
    // evaluator move d563a9f7 -> 16732dae; its review fixes (the sealed view, the reader's error codes, mirrors skip read-back) -> the
    // announced evaluator move d563a9f7 -> 10051cf2; the review (profile and suite digests read a read-back declaration through its
    // view) -> the announced evaluator move d563a9f7 -> b1c4a90d. FIX-08 (another recorder's destination: each egress recorder reads the
    // run's other recorders' destinations, a window holding a send to one or its sibling sees it, settlement reads such a later window;
    // egress-recorder/13; no file joins the list), built on main efdcaa98 -> the announced evaluator move b1c4a90d -> aa3566f8. N6-E1
    // (predicate records: each JSON predicate keeps its field pointer and keyed digests, or values in value mode; no verdict changes;
    // no file joins the list), built on main 93d25fd4 -> the announced evaluator move aa3566f8 -> 717bb581. Security review F12 (the
    // digests keyed with a per-run secret no run or pack keeps, not a public salt; no file joins the list) -> 717bb581 -> 81c15901. pg_net on the wire (a pg-wal
    // observer's pgNetWire with its programRoles and requestRoles declaration and a tap image named by digest, validated in src/contracts.mjs;
    // lane O; reviewed as 15b571da and 974e4507, never on main) -> the announced evaluator move 81c15901 -> 015af8ab.
    // L8 fix 6b (exactFor: a quiescent pg-snapshot xmin window decides insert and delete absence; no file joins the list), merged
    // with main cb7e9efa -> the announced evaluator move 015af8ab -> a5bd8776.
    targetConfigHash: 'ee1ce21af89bd865c10dea0dd19c9eabbb7265fc197b780f5d1363118da39fcd', evaluatorHash: 'a5bd87760ff72371c8b6df855604515ba91597488943c07b20e17bd238840f0e' },
};
test('AC15: suite, policy and fixture identities are unchanged; HTTP uses reviewed G1 capture identity', async () => {
  // Suite 2.3.0 (TRUTH-03, TARGET-BIND-01 and the PROMISE stated-reason pairs) is one
  // announced identity change; 2.1.0 stays pinned under fix 5 and 2.2.0 under fix 7.
  // The fixture data is unchanged: 2.3.0's scenarios are new inputs and new app
  // behaviour over the same orders, subscriptions and records. The fixture VERSION
  // still moves to support-fixture/5, because the runner's family map is keyed on it
  // and support-fixture/4 has to keep claiming exactly 2.2.0's 34 scenarios.
  const preflight = { suiteHash: 'd8f385a80cf1206f709881eca7502432f05828d64dbb9738cfdf130059a442c2', policyHash: 'f450ae2c7fe3045e56281b2d37369467d9803b9a8b715f7b3a0deb91561582fa',
    fixtureHash: '5df3c877bcd8cb91f1ddafd9ef21a45b38e151ef395a10c439b1819204dbc1dc', fixtureVersion: 'support-fixture/5', profileHash: 'b80280ada6c0f5528e5fecf3090f1d63cac5b2749e41d190e49a9ac7ba8b92c1',
    adapterVersion: 'owned-loopback-http/1', assertionSchemaVersion: 'fixture-policy/1' };
  assert.equal(SUITE.version, '2.3.0'); assert.equal(SUITE.checks.length, 44); assert.equal(SUITE.checks.filter(c => c.severity === 'control').length, 18);
  assert.deepEqual([SUITE.hash, POLICY_HASH, FIXTURE_HASH], [preflight.suiteHash, preflight.policyHash, preflight.fixtureHash]);
  for (const [run, targetConfigHash] of [[vulnerable, '7d4375d68ee4fdb2dadb7484db89b7d41ca454ed5035121dbcb6cd969199eea7'], [repaired, 'aa4ff9133dd314b37f77a01bf96806cddbc8dca10251fbf34183e592ef36758b']]) {
    for (const key of Object.keys(preflight)) assert.equal(run[key], preflight[key], key);
    assert.equal(run.targetConfigHash, targetConfigHash); assert.equal(run.evaluatorHash, EVALUATOR_HASH);
  }
  const http = await runHttpAssessment(makeLabProfile('http://127.0.0.1:9'), { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'synthetic-token' },
    transport: async () => ({ status: 200, complete: true, jsonParsed: true, json: { role: 'member', record: { tenant: 'aster' }, accepted: true }, bytes: 10 }) });
  assert.equal(http.evaluatorHash, HTTP_EVALUATOR_HASH, 'the exported identity is the one a run records');
  const pair = `${http.adapterVersion}|${http.assertionSchemaVersion}`;
  assert(Object.hasOwn(HTTP_IDENTITY_PINS, pair), `HTTP connector identity is now ${pair}: review the change and record its hashes in HTTP_IDENTITY_PINS`);
  assert.deepEqual(pick(http, Object.keys(HTTP_IDENTITY_PINS[pair])), HTTP_IDENTITY_PINS[pair]);
});
