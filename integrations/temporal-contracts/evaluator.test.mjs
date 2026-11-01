// Minted live loopback bundles pin policy ordering separately from fixture variants.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { createTemporalCollector, inspectTemporalEvidence } from './evidence.mjs';
import { createRefundContract, actorBindings, COMPLETING, freezeTree } from './contract.mjs';
import { finalizeRefundRun, isFinalizedRun } from './evaluator.mjs';
import { CONTROL_CUSTODY_LIMIT } from '../../src/custody.mjs';
import { createPaymentsDouble } from '../observers/payments-double.mjs';
import { onFreePorts } from '../observers/fixtures/free-port.mjs';

const BUILD = 'a'.repeat(64), EVALUATOR = 'b'.repeat(64);
const row = (run, id) => run.results.find(result => result.id === id);
function refund(payments, contract, authority, attemptId) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ charge: authority.chargeId, amount: authority.amount, currency: authority.currency, destination: authority.destination });
    const req = request({ host: '127.0.0.1', port: payments.port, method: 'POST', path: '/pay/v1/refunds', headers: {
      'Content-Type': 'application/json', 'Idempotency-Key': authority.instructionId,
      'X-Scopehaven-Run': contract.runId, 'X-Scopehaven-Instruction': authority.instructionId,
      'X-Scopehaven-Attempt': attemptId, 'X-Scopehaven-Authority': authority.authorityId,
      'X-Scopehaven-Principal': authority.principalId, 'X-Scopehaven-Tenant': authority.tenantId,
      'X-Scopehaven-Currency': authority.currency,
    } }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk)); res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(Buffer.concat(chunks).toString()) }));
    });
    req.on('error', reject); req.end(payload);
  });
}
async function minted(t, { mutate = () => {}, withOperator = true, closure = 'closed', httpIdentity = false, invalidRequest = false } = {}) {
  const runId = randomUUID(), actors = actorBindings(runId);
  const contract = createRefundContract({ runId, targetId: 'refund-clean', buildHash: BUILD, actors });
  const payments = await onFreePorts(1, async port => {
    const source = createPaymentsDouble({ instanceId: `evaluator-${runId}`, port, routing: 'base-url', destinations: [{ host: 'api.payments.test' }],
      routes: [{ prefix: '/pay/', host: 'api.payments.test' }, { prefix: '/w/', host: 'witness.scopehaven.invalid' }],
      witness: { actorId: 'control', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, witnessWaitMs: 0, quietMs: 100,
      provider: { host: 'api.payments.test', seed: [{ id: contract.authorities[0].chargeId, paymentMethod: 'pm_original', amount: 10000, currency: 'cad' }] } });
    await source.start(); t.after(() => source.stop()); return source;
  });
  const clock = performance.now(), events = [], instructions = contract.authorities.map(authority => ({ ...authority, state: 'authorized' }));
  let closedAtMs = null, closureReads = 0;
  const record = (type, fields = {}) => { const event = { seq: events.length + 1, atMs: performance.now() - clock, type, ...fields }; events.push(event); return event; };
  const fixture = { async snapshot({ horizonId, deadlineMs, close }) {
    if (close) closureReads++;
    if (close && closure === 'missing') throw new Error('Synthetic closure unavailable');
    if (close) closedAtMs ??= performance.now() - clock;
    const sealed = close && closure !== 'pending';
    return freezeTree(structuredClone({ schema: 'scopehaven-refund-app-evidence/1', runId, targetId: contract.targetId, buildHash: BUILD,
      sourceId: closure === 'changed' && closureReads > 1 ? 'changed-source' : `source-${runId}`, instructions, events,
      coverage: { source: 'application', complete: sealed, ordered: true, fromSeq: 1, toSeq: events.length, lateEvents: 0, problems: [] },
      timing: { clockId: `app-${runId}`, startedAtMs: 0, closedAtMs },
      horizon: { id: horizonId, deadlineMs, closed: sealed, sealed, watermark: events.length, pending: closure === 'pending' ? 1 : 0 } }));
  } };
  const collector = createTemporalCollector({ fixture, payments, contract }); await collector.begin();
  const observed = (metadata, action) => withOperator ? collector.observeOperation(metadata, action) : action();
  for (const authority of contract.authorities) record('authorized', { ...authority, binding: authority });
  for (const id of COMPLETING) {
    const authority = contract.authorities.find(item => item.instructionId === id), instruction = instructions.find(item => item.instructionId === id);
    await observed({ kind: 'invoke', instructionId: id, principalId: authority.principalId,
      input: { instructionId: id, ...(invalidRequest && id === 'retry' ? { amount: authority.amount + 1 } : {}) } }, async () => {
      record('arrived', { instructionId: id, principalId: authority.principalId, binding: authority });
      instruction.acceptanceSeq = record('accepted', { ...authority, binding: authority }).seq;
      const attemptId = `attempt-${id}`; record('attempt', { ...authority, attemptId, binding: authority });
      const result = await refund(payments, contract, authority, attemptId);
      assert.equal(result.status, 200); assert.equal(result.json.status, 'succeeded');
      instruction.state = 'success'; instruction.effectId = result.json.id;
      record('terminal', { instructionId: id, principalId: authority.principalId, state: 'success', effectId: result.json.id, attemptId });
      return { status: 200, complete: true, json: { instructionId: id, state: 'success', effectId: result.json.id } };
    });
  }
  const before = contract.authorities.find(item => item.instructionId === 'arrival-before');
  await observed({ kind: 'invoke', instructionId: before.instructionId, principalId: before.principalId,
    input: { instructionId: before.instructionId, hold: 'before-acceptance' } }, () => {
    record('arrived', { instructionId: before.instructionId, principalId: before.principalId, binding: before });
    return { status: 202, complete: true, json: { instructionId: before.instructionId, state: 'pending' } };
  });
  await observed({ kind: 'revoke', principalId: actors.revoked.principalId }, () => record('revoked', { principalId: actors.revoked.principalId }));
  const refuse = authority => {
    record('refused', { ...authority, binding: authority, reason: 'principal-revoked' });
    record('terminal', { instructionId: authority.instructionId, principalId: authority.principalId, state: 'failure' });
    instructions.find(item => item.instructionId === authority.instructionId).state = 'refused';
  };
  await observed({ kind: 'release', instructionId: before.instructionId, principalId: before.principalId }, () => {
    refuse(before); return { instructionId: before.instructionId, state: 'refused' };
  });
  const after = contract.authorities.find(item => item.instructionId === 'revoked-new');
  await observed({ kind: 'invoke', instructionId: after.instructionId, principalId: after.principalId, input: { instructionId: after.instructionId } }, () => {
    record('arrived', { instructionId: after.instructionId, principalId: after.principalId, binding: after }); refuse(after);
    return { status: 403, complete: true, json: { instructionId: after.instructionId, state: 'refused' } };
  });
  mutate({ events, instructions, contract });
  // Mutations alter ledger order, not coverage or its monotonic interval.
  for (const [index, event] of events.entries()) { event.seq = index + 1; event.atMs = (index + 1) / 100; }
  const bundle = await collector.finish(), inspection = inspectTemporalEvidence(bundle, contract);
  assert.equal(inspection.trusted, true);
  assert.equal(inspection.coverage, closure === 'closed' ? 'complete' : 'incomplete', JSON.stringify(inspection.problems));
  const httpEvidence = httpIdentity ? ['revoked', 'control'].flatMap(actor => ['own', 'none', 'wrong', 'other'].map(auth => ({
    actor, kind: 'identity', auth, status: auth === 'own' ? 200 : 401, ...actors[actor] }))) : [];
  const run = finalizeRefundRun(bundle, { contract, evaluatorHash: EVALUATOR, httpEvidence });
  assert.equal(isFinalizedRun(run), true);
  return { run, bundle, inspection };
}
function move(events, predicate, destination) {
  const index = events.findIndex(predicate); assert.ok(index >= 0);
  const [event] = events.splice(index, 1);
  const target = events.findIndex(destination); assert.ok(target >= 0);
  events.splice(target, 0, event);
}
function exactFailure(run, id, reason) {
  assert.equal(row(run, id).status, 'fail'); assert.ok(row(run, id).reasons.includes(reason), JSON.stringify(row(run, id)));
}

test('minted complete collector bundle reaches finalizer with operator-supported boundary rows', async t => {
  const { run } = await minted(t);
  for (const id of ['REFUND-CUTOFF', 'REFUND-COVERAGE', 'retry-binding', 'retry-effects', 'retry-completion', 'arrival-before-refusal', 'revoked-new-refusal'])
    assert.equal(row(run, id).status, 'pass', id);
  for (const result of run.results.filter(result => result.kind === 'authority')) {
    assert.equal(result.severity, 'control'); assert.equal(result.custodyLimit, CONTROL_CUSTODY_LIMIT);
  }
});

test('M02: acceptance after source revocation fails the exact authority diagnostic', async t => {
  const { run } = await minted(t, { mutate: ({ events }) => move(events, event => event.type === 'accepted' && event.instructionId === 'retry',
    event => event.type === 'refused' && event.instructionId === 'arrival-before') });
  exactFailure(run, 'retry-authority', 'acceptance-without-current-bound-authority');
});

test('M03: acceptance without any prior authorized record fails the exact authority diagnostic', async t => {
  const { run } = await minted(t, { mutate: ({ events }) => {
    const index = events.findIndex(event => event.type === 'authorized' && event.instructionId === 'retry'); assert.ok(index >= 0); events.splice(index, 1);
  } });
  exactFailure(run, 'retry-authority', 'acceptance-without-current-bound-authority');
});

test('M05: a real provider send recorded before acceptance fails immutable dispatch binding', async t => {
  const { run } = await minted(t, { mutate: ({ events }) => move(events, event => event.type === 'attempt' && event.instructionId === 'retry',
    event => event.type === 'accepted' && event.instructionId === 'retry') });
  exactFailure(run, 'retry-binding', 'forbidden-or-mutated-dispatch');
});

test('M10: a bound acceptance cannot coexist with required refusal even without a provider send', async t => {
  const { run } = await minted(t, { mutate: ({ events, contract }) => {
    const authority = contract.authorities.find(item => item.instructionId === 'arrival-before');
    events.splice(events.findIndex(event => event.type === 'revoked'), 0, { type: 'accepted', ...authority, binding: authority });
  } });
  exactFailure(run, 'arrival-before-refusal', 'new-work-not-correctly-refused');
});

for (const id of ['arrival-before', 'revoked-new']) test(`M11: ${id} arrival on the wrong side of source cutoff fails exact refusal ordering`, async t => {
  const { run } = await minted(t, { mutate: ({ events }) => {
    if (id === 'arrival-before') move(events, event => event.type === 'arrived' && event.instructionId === id,
      event => event.type === 'refused' && event.instructionId === id);
    else move(events, event => event.type === 'arrived' && event.instructionId === id, event => event.type === 'revoked');
  } });
  exactFailure(run, `${id}-refusal`, 'new-work-not-correctly-refused');
});

test('minted bundles without operator windows cannot pass any boundary row', async t => {
  const { run } = await minted(t, { withOperator: false });
  for (const result of run.results.filter(result => result.severity !== 'control')) assert.notEqual(result.status, 'pass', result.id);
  assert.equal(row(run, 'REFUND-COVERAGE').status, 'inconclusive');
});

test('M4: observer-dispatched windows without independent source closure cannot pass any refund row', async t => {
  for (const closure of ['missing', 'pending', 'changed']) {
    const { run, bundle, inspection } = await minted(t, { closure, httpIdentity: true });
    assert.equal(bundle.payments.coverage, 'complete');
    assert.equal(bundle.payments.witnessSource, 'observer-dispatched');
    assert.equal(inspection.independentClosure, false);
    assert.ok(inspection.problems.includes('observer-witness-independent-closure-missing'));
    assert.equal(run.results.filter(result => result.status === 'pass').length, 0, closure);
    assert.equal(row(run, 'REFUND-COVERAGE').status, 'inconclusive');
  }
});

test('M4: validated independent source closure permits clean observer-dispatched refund verdicts', async t => {
  const { run, bundle, inspection } = await minted(t, { httpIdentity: true });
  assert.equal(bundle.payments.witnessSource, 'observer-dispatched');
  assert.equal(inspection.independentClosure, true);
  assert.equal(run.results.every(result => result.status === 'pass'), true, JSON.stringify(run.results.filter(result => result.status !== 'pass')));
  const copy = structuredClone(bundle);
  copy.independentClosure = true;
  assert.equal(inspectTemporalEvidence(copy, {}).trusted, false);
});

test('M4: missing closure preserves an independently observed request-binding failure', async t => {
  const { run, inspection } = await minted(t, { closure: 'pending', invalidRequest: true, httpIdentity: true });
  assert.equal(inspection.independentClosure, false);
  exactFailure(run, 'retry-binding', 'forbidden-or-mutated-dispatch');
  assert.equal(run.results.filter(result => result.status === 'pass').length, 0);
});
