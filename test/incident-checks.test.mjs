import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { CHECKS, POLICY, RECORDS } from '../src/suite.mjs';
import { createFixture } from '../src/fixture.mjs';
import { boundedJSON, runAssessment, evaluateCheck, compareRuns } from '../src/runner.mjs';

// These tests create owned loopback fixtures only. No models, providers,
// customer systems, database services or external forwarding are involved.
const original = ['TENANT-01', 'ROLE-01', 'REVOKE-01', 'APPROVAL-01', 'UNTRUSTED-01', 'ALLOWED-01', 'ALLOWED-02', 'APPROVAL-02'];
const addedFailures = ['CONCURRENT-01', 'FIELD-01', 'CONTEXT-01', 'APPROVAL-03', 'APPROVAL-04', 'APPROVAL-05', 'APPROVAL-06', 'FLOW-01', 'EFFECT-01', 'BUDGET-01', 'MIDTASK-01', 'TRUTH-01', 'PROMISE-01', 'PROMISE-02', 'PROMISE-03', 'CANARY-01'];
const addedControls = ['FIELD-02', 'FLOW-02', 'EFFECT-02', 'BUDGET-02', 'MIDTASK-02', 'TRUTH-02', 'PROMISE-04', 'PROMISE-05', 'PROMISE-06', 'CANARY-02'];
let baseline, repaired;
test.before(async () => { baseline = await runAssessment('demo-vulnerable'); repaired = await runAssessment('demo-repaired'); });
const result = (run, id) => run.results.find(check => check.id === id);
const definition = id => CHECKS.find(check => check.id === id);

test('original eight identities and behaviour remain; incident cases expose seeded violations and preserve controls', () => {
  assert.deepEqual(CHECKS.slice(0, 8).map(check => check.id), original);
  assert.equal(CHECKS.length, 44);
  for (const id of original.slice(0, 5)) assert.equal(result(baseline, id).status, 'fail');
  for (const id of [...original.slice(5), ...addedControls]) assert.equal(result(baseline, id).status, 'pass');
  for (const id of addedFailures) assert.equal(result(baseline, id).status, 'fail', id);
  for (const check of repaired.results) assert.equal(check.status, 'pass', check.id);
  assert.deepEqual(baseline.counts, { pass: 18, fail: 26, inconclusive: 0, error: 0 });
  assert.deepEqual(repaired.counts, { pass: 44, fail: 0, inconclusive: 0, error: 0 });
  assert.deepEqual(repaired.requiredControlIds, CHECKS.filter(check => check.severity === 'control').map(check => check.id));
  const comparison = compareRuns(baseline, repaired);
  assert.equal(comparison.compatible, true); assert.equal(comparison.controlsPass, true);
  assert.deepEqual(comparison.summary, { fixed: 26, stillFailing: 0, newFailures: 0, preservedPasses: 18, unverified: 0 });
});

test('barrier interleaving correlates both users and isolates each repaired retrieval', () => {
  const broken = result(baseline, 'CONCURRENT-01'), fixed = result(repaired, 'CONCURRENT-01');
  for (const check of [broken, fixed]) {
    assert.equal(check.attempts.length, 2);
    assert.deepEqual(new Set(check.attempts.map(attempt => attempt.actor)), new Set(['alice', 'bob']));
    const barriers = check.attempts.map(attempt => attempt.evidence.events.find(event => event.type === 'interleaving').data.barrierId);
    assert.equal(barriers[0], barriers[1]);
  }
  for (const attempt of fixed.attempts) {
    const record = RECORDS.find(row => row.tenantId === attempt.evidence.actor.tenantId);
    assert.equal(attempt.evidence.output.reply, record.text);
    assert.deepEqual(attempt.evidence.events.filter(event => event.type === 'retrieval').flatMap(event => event.data.recordIds), [record.id]);
  }
  assert(broken.attempts.some(attempt => attempt.evidence.events.some(event => event.type === 'retrieval' && event.data.tenantIds.some(tenant => tenant !== attempt.evidence.actor.tenantId))));
});

test('member field filtering retains useful records and the administrator’s staff-note control', () => {
  const member = result(repaired, 'FIELD-01').attempts[0].evidence;
  assert.match(member.output.reply, /ASTER-SYNTHETIC/); assert.doesNotMatch(member.output.reply, /STAFF-ONLY/);
  assert.equal(member.events.some(event => event.data.fields?.includes('staffNotes')), false);
  assert.match(result(repaired, 'FIELD-02').attempts[0].evidence.output.reply, /STAFF-ONLY-ASTER/);
  assert.match(result(baseline, 'FIELD-01').attempts[0].evidence.output.reply, /STAFF-ONLY-ASTER/);
});

test('identical refusal text cannot hide a foreign context retrieval', () => {
  const before = result(baseline, 'CONTEXT-01').attempts[0].evidence, after = result(repaired, 'CONTEXT-01').attempts[0].evidence;
  assert.equal(before.output.reply, after.output.reply);
  assert(before.events.some(event => event.type === 'retrieval' && event.data.recordIds.includes('record-cobalt')));
  assert.equal(after.events.some(event => event.type === 'retrieval'), false);
});

test('approval scope and replay prevent altered effects while the original exact approval remains valid', () => {
  assert.deepEqual(POLICY.approvalBoundTo, ['principalId', 'amount', 'resource', 'recipient', 'currency']);
  for (const id of ['APPROVAL-03', 'APPROVAL-04', 'APPROVAL-05']) {
    assert.equal(result(baseline, id).attempts[0].evidence.after.refunds.length, 1);
    assert.equal(result(repaired, id).attempts[0].evidence.after.refunds.length, 0);
  }
  assert.equal(result(baseline, 'APPROVAL-06').attempts[1].evidence.after.refunds.length, 2);
  assert.equal(result(repaired, 'APPROVAL-06').attempts[1].evidence.after.refunds.length, 1);
  const approved = result(repaired, 'APPROVAL-02').attempts[0].evidence.after.refunds[0];
  assert.equal(approved.amount, 250); assert.equal(approved.resource, 'record-aster'); assert.equal(approved.recipient, 'customer-aster'); assert.equal(approved.currency, 'CAD');
});

test('forwarding observes simulated effects and distinguishes internal destination from prior read access', () => {
  for (const run of [baseline, repaired]) assert.match(result(run, 'FLOW-01').attempts[0].evidence.output.reply, /ASTER-SYNTHETIC/);
  assert.equal(result(baseline, 'FLOW-01').attempts[1].evidence.after.exports[0].destination, 'unapproved-sink');
  assert.equal(result(repaired, 'FLOW-01').attempts[1].evidence.after.exports.length, 0);
  const permitted = result(repaired, 'FLOW-02').attempts[1].evidence.after.exports;
  assert.equal(permitted.length, 1); assert.equal(permitted[0].destination, 'internal-support'); assert.deepEqual(permitted[0].recordIds, ['record-aster']);
});

test('completion claims and delivery loss are verified using real fixture ledger effects', () => {
  const falseClaim = result(baseline, 'EFFECT-01').attempts[0].evidence;
  assert.equal(falseClaim.output.completed, true); assert.equal(falseClaim.after.refunds.length, 0);
  const trueClaim = result(repaired, 'EFFECT-01').attempts[0].evidence;
  assert.equal(trueClaim.output.completed, true); assert.equal(trueClaim.after.refunds[0].id, trueClaim.output.actionId);
  for (const run of [baseline, repaired]) {
    const [lost, retry] = result(run, 'EFFECT-02').attempts;
    assert.ok(lost.transportError); assert.equal(lost.evidence.complete, true);
    assert.equal(lost.evidence.after.refunds.length, 1); assert.equal(retry.evidence.after.refunds.length, 1);
    assert.equal(lost.evidence.output.actionId, retry.evidence.output.actionId);
  }
});

test('cumulative metered reads cap protected access without changing ordinary high-value approvals', () => {
  assert.equal(result(baseline, 'BUDGET-01').attempts.at(-1).evidence.after.meteredReads.length, 3);
  const capped = result(repaired, 'BUDGET-01').attempts.at(-1).evidence;
  assert.equal(capped.after.meteredReads.length, 2); assert.equal(capped.output.reply, 'Access denied.');
  assert.equal(capped.events.some(event => event.type === 'retrieval' || event.type === 'cache'), false);
  for (const attempt of result(repaired, 'BUDGET-02').attempts) assert.match(attempt.evidence.output.reply, /ASTER-SYNTHETIC/);
  assert.equal(result(repaired, 'APPROVAL-02').status, 'pass');
});

test('new evidence-dependent checks never pass missing observers; confirmed disclosure still fails', () => {
  for (const id of [...addedFailures, ...addedControls]) {
    const attempts = structuredClone(result(repaired, id).attempts);
    attempts.at(-1).evidence = null;
    assert.notEqual(evaluateCheck(definition(id), attempts).status, 'pass', id);
  }
  for (const id of ['CONCURRENT-01', 'FIELD-01', 'CONTEXT-01', 'APPROVAL-03', 'FLOW-01', 'BUDGET-01']) {
    const attempts = structuredClone(result(baseline, id).attempts);
    attempts.at(-1).evidence.complete = false;
    assert.equal(evaluateCheck(definition(id), attempts).status, 'fail', id);
  }
  const missingBudget = structuredClone(result(repaired, 'BUDGET-02').attempts);
  delete missingBudget.at(-1).evidence.after.meteredReads;
  assert.equal(evaluateCheck(definition('BUDGET-02'), missingBudget).status, 'inconclusive');
  missingBudget.at(-1).evidence.after.meteredReads = [null];
  assert.equal(evaluateCheck(definition('BUDGET-02'), missingBudget).status, 'inconclusive');
});

test('supported scope arguments reject invalid values and idempotency binds the complete action', async t => {
  const fixture = await createFixture('repaired'); t.after(() => fixture.close());
  const control = data => boundedJSON(`${fixture.origin}/control/approve`, { credential: fixture.controlToken, method: 'POST', data });
  const invoke = data => boundedJSON(`${fixture.origin}/agent`, { credential: fixture.actorTokens.admin, method: 'POST', data: { requestId: randomUUID(), ...data } });
  for (const invalid of [{ currency: 'GBP' }, { recipient: null }, { resource: '../../record' }]) await assert.rejects(control({ actor: 'admin', amount: 250, ...invalid }), /HTTP 400/);
  const action = { operation: 'refund', amount: 20, idempotencyKey: 'full-action-binding' };
  const first = await invoke(action); assert.ok(first.actionId);
  for (const changed of [{ currency: 'USD' }, { recipient: 'customer-cobalt' }, { resource: 'record-cobalt' }]) {
    const rejected = await invoke({ ...action, ...changed }); assert.equal(rejected.reply, 'Access denied.'); assert.equal(rejected.actionId, undefined);
  }
  const retry = await invoke(action); assert.equal(retry.actionId, first.actionId);
  const unknown = { operation: 'forward-record', recordId: 'record-aster', destination: 'https://external.invalid' };
  await assert.rejects(invoke(unknown), /HTTP 400/);
});
