// Owned synthetic loopback sources; no model, database or real provider calls.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { setTimeout as wait } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { createTemporalCollector, inspectTemporalEvidence } from './evidence.mjs';
import { bindingOf, sameBinding, bindTemporalFacts, freezeEvidence } from './binding.mjs';
import { createPaymentsDouble, evaluateRefundCount } from '../observers/payments-double.mjs';
import { onFreePorts } from '../observers/fixtures/free-port.mjs';

const PAY = 'api.payments.test', WITNESS = 'witness.scopehaven.invalid';
const BUILD = 'a'.repeat(64);
const instruction = (id = 'instruction-1', extra = {}) => ({ instructionId: id, authorityId: `authority-${id}`, principalId: 'member', tenantId: 'tenant-1',
  operation: 'refund', chargeId: 'ch_order_1', amount: 400, currency: 'cad', destination: 'pm_card_on_file', ...extra });
const headers = (runId, binding, attemptId) => ({ 'X-Scopehaven-Run': runId, 'X-Scopehaven-Instruction': binding.instructionId, 'X-Scopehaven-Attempt': attemptId,
  'X-Scopehaven-Authority': binding.authorityId, 'X-Scopehaven-Principal': binding.principalId, 'X-Scopehaven-Tenant': binding.tenantId, 'X-Scopehaven-Currency': binding.currency });
function send(payments, { body, key, metadata = {}, path = '/pay/v1/refunds', lose = false } = {}) {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: payments.port, method: body === undefined ? 'GET' : 'POST', path,
      headers: { 'Content-Type': 'application/json', ...metadata, ...(key ? { 'Idempotency-Key': key } : {}) } }, res => {
      if (lose) { res.destroy(); return resolve({ status: res.statusCode, body: null }); }
      const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString() || 'null') }));
    });
    req.on('error', reject); req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}
async function environment(t, { authorities = [instruction()], runId = 'run-1', deadlineMs = 5000, paymentOptions = {}, sourceOptions = {}, requiredChecks } = {}) {
  const payments = await onFreePorts(1, async port => {
    const o = createPaymentsDouble({ instanceId: 'temporal-payments', provider: { host: PAY, seed: [
      { id: 'ch_order_1', paymentMethod: 'pm_card_on_file', amount: 2000, currency: 'cad' },
      { id: 'ch_order_2', paymentMethod: 'pm_second_card', amount: 2000, currency: 'usd' } ] },
      port, routing: 'base-url', destinations: [{ host: PAY }], routes: [{ prefix: '/pay/', host: PAY }, { prefix: '/w/', host: WITNESS }],
      witness: { actorId: 'member', method: 'GET', path: '/ping', host: WITNESS }, quietMs: 100, witnessWaitMs: 0, ...paymentOptions });
    await o.start(); t.after(() => o.stop()); return o;
  });
  const contract = { schema: 'scopehaven-refund-contract/1', id: 'refund-contract', revision: 1, runId, targetId: 'refund-fixture', buildHash: BUILD,
    horizon: { id: 'horizon-1', deadlineMs }, authorities, requiredChecks: requiredChecks ?? [{ id: 'completion', kind: 'completion', instructionIds: authorities.map(row => row.instructionId) }] };
  let seq = 0, pending = 0, closedWatermark = null, closedAtMs = null;
  const clockStart = performance.now();
  const events = [], instructions = authorities.map(row => ({ ...row }));
  function record(type, fields = {}) { const row = { seq: ++seq, atMs: performance.now() - clockStart, type, ...fields }; events.push(row); return row; }
  for (const row of authorities) record('authorized', { instructionId: row.instructionId, binding: row });
  const fixture = { async snapshot({ horizonId, deadlineMs: requestedDeadline, close }) {
    if (close) { closedWatermark ??= seq; closedAtMs ??= performance.now() - clockStart; }
    const closed = close && pending === 0 && !sourceOptions.unclosed;
    return freezeEvidence(JSON.parse(JSON.stringify({ schema: 'scopehaven-refund-app-evidence/1', runId, targetId: 'refund-fixture', buildHash: BUILD,
      sourceId: `app-source-${runId}`, instructions, events,
      coverage: { source: 'application', complete: closed && seq === closedWatermark, ordered: true, fromSeq: 1, toSeq: seq,
        lateEvents: closedWatermark === null ? 0 : seq - closedWatermark, problems: [] },
      timing: { clockId: `clock-${runId}`, startedAtMs: 0, closedAtMs },
      horizon: { id: horizonId, deadlineMs: sourceOptions.changedDeadline ? requestedDeadline - 1 : requestedDeadline,
        sealed: closed, closed, watermark: closedWatermark ?? seq, pending } })));
  } };
  let serial = 0;
  async function dispatch(binding = authorities[0], { key = binding.instructionId, lose = false, accept = true, metadata, body } = {}) {
    const attemptId = `attempt-${++serial}`;
    if (accept && !events.some(row => row.type === 'accepted' && row.instructionId === binding.instructionId)) record('accepted', { instructionId: binding.instructionId, principalId: binding.principalId, authorityId: binding.authorityId, binding });
    record('attempt', { instructionId: binding.instructionId, attemptId, binding });
    const result = await send(payments, { body: body ?? { charge: binding.chargeId, amount: binding.amount, currency: binding.currency, destination: binding.destination },
      key, lose, metadata: metadata ?? headers(runId, binding, attemptId) });
    record('terminal', { instructionId: binding.instructionId, state: result.body?.object === 'refund' ? 'success' : lose ? 'pending' : 'failure', effectId: result.body?.object === 'refund' ? result.body.id : undefined });
    return result;
  }
  const collector = createTemporalCollector({ fixture, payments, contract });
  return { payments, fixture, contract, collector, events, instructions, record, dispatch, setPending(value) { pending = value; } };
}
async function collected(t, action, options) { const env = await environment(t, options); await env.collector.begin(); await action(env); const bundle = await env.collector.finish(); return { ...env, bundle, inspection: inspectTemporalEvidence(bundle, env.contract) }; }

test('canonical binding covers all immutable fields and two identical instructions remain distinct', () => {
  const original = instruction(); assert.equal(sameBinding(original, original), true);
  assert.equal(bindingOf(original).destinationDigest.length, 64);
  for (const [field, value] of Object.entries({ instructionId: 'other', authorityId: 'other', principalId: 'other', tenantId: 'other', chargeId: 'ch_other',
    amount: 401, currency: 'usd', destination: 'pm_other' })) assert.equal(sameBinding(original, { ...original, [field]: value }), false, field);
  assert.equal(sameBinding(original, { ...original, amount: 0 }), false);
  assert.equal(sameBinding(original, { ...original, destinationDigest: bindingOf(instruction('other', { destination: 'different' })).destinationDigest }), false);
  assert.equal(bindingOf({ instructionId: 'wrong-outer-id', binding: original }), null);
  assert.equal(sameBinding(original, instruction('instruction-2')), false);
});

test('adapter: lost response and same-key retry are two attempts, one creating effect and terminal success', async t => {
  const { bundle, inspection } = await collected(t, async env => { await env.dispatch(undefined, { lose: true }); await env.dispatch(); });
  assert.deepEqual([inspection.trusted, inspection.coverage, inspection.problems], [true, 'complete', []]);
  assert.deepEqual([inspection.facts.attempts.length, inspection.facts.effects.length], [2, 1]);
  assert.deepEqual(inspection.facts.attempts.map(row => [row.created, row.replayed]), [[true, false], [false, true]]);
  assert.equal(inspection.facts.terminals[0].state, 'pending');
  assert.deepEqual(inspection.facts.terminals.at(-1).effectBound, true);
  assert.equal(inspection.facts.effects[0].attemptId, 'attempt-1');
  assert.equal(inspection.facts.attempts[1].effectId, inspection.facts.effects[0].effectId);
  assert.equal(Object.isFrozen(bundle.payments.lineage[0].binding), true);
});

test('adapter: changed retry keys and absent keys preserve two distinct effects for one instruction', async t => {
  for (const keys of [['key-1', 'key-2'], [null, null]]) {
    const { inspection } = await collected(t, async env => { for (const key of keys) await env.dispatch(undefined, { key }); });
    assert.equal(inspection.coverage, 'complete');
    assert.equal(inspection.facts.effects.length, 2);
    assert.notEqual(inspection.facts.effects[0].effectId, inspection.facts.effects[1].effectId);
    assert.ok(inspection.facts.effects.every(row => row.instructionId === 'instruction-1' && row.bound));
  }
});

test('adapter: independently authorized identical instructions each bind their own effect', async t => {
  const authorities = [instruction(), instruction('instruction-2')];
  const { inspection } = await collected(t, async env => { for (const row of authorities) await env.dispatch(row); }, { authorities });
  assert.deepEqual([inspection.coverage, inspection.facts.effects.length], ['complete', 2]);
  assert.deepEqual(inspection.facts.effects.map(row => row.instructionId), authorities.map(row => row.instructionId));
  assert.ok(inspection.facts.terminals.every(row => row.effectBound));
});

test('adapter: shared idempotency/effect cannot complete the second instruction', async t => {
  const authorities = [instruction(), instruction('instruction-2')];
  const { inspection } = await collected(t, async env => { for (const row of authorities) await env.dispatch(row, { key: 'shared-key' }); }, { authorities });
  assert.equal(inspection.coverage, 'complete');
  assert.equal(inspection.facts.effects.length, 1);
  assert.equal(inspection.facts.effects[0].instructionId, 'instruction-1');
  assert.deepEqual(inspection.facts.terminals.map(row => row.effectBound), [true, false]);
});

test('pure binding: duplicate delivery counts one effect; conflicting delivery is explicit', async t => {
  const { bundle, contract } = await collected(t, env => env.dispatch());
  const payments = JSON.parse(JSON.stringify(bundle.payments)); payments.refunds.push({ ...payments.refunds[0] });
  let facts = bindTemporalFacts({ application: bundle.application, payments, contract });
  assert.equal(facts.effects.length, 1); assert.deepEqual(facts.problems, []);
  payments.refunds[1].amount += 1;
  facts = bindTemporalFacts({ application: bundle.application, payments, contract });
  assert.equal(facts.effects.length, 1); assert.match(facts.problems.join(), /refund-effect-conflicting-identity/);
});

test('adapter: accepted, pending and false-success records do not create a provider effect', async t => {
  const { inspection } = await collected(t, async env => {
    env.record('accepted', { instructionId: 'instruction-1', binding: instruction() });
    env.record('terminal', { instructionId: 'instruction-1', state: 'pending' });
    env.record('terminal', { instructionId: 'instruction-1', state: 'success', effectId: 're_test_fake' });
  });
  assert.equal(inspection.facts.effects.length, 0);
  assert.ok(inspection.facts.terminals.every(row => !row.effectBound));
});

test('adapter: pre-cutoff acceptance retains causal unchanged retry after revocation', async t => {
  const { inspection } = await collected(t, async env => {
    await env.dispatch(undefined, { lose: true }); env.record('revoked', { principalId: 'member' }); await env.dispatch();
  });
  assert.equal(inspection.coverage, 'complete');
  const accepted = inspection.facts.events.find(row => row.type === 'accepted');
  assert.ok(accepted.seq < inspection.facts.revocations[0].effectiveSeq);
  assert.ok(inspection.facts.attempts[1].applicationSeq > inspection.facts.revocations[0].effectiveSeq);
  assert.ok(inspection.facts.attempts.every(row => row.bindingValid && row.lineageValid));
});

test('adapter: arrival does not change post-cutoff acceptance order', async t => {
  const { inspection } = await collected(t, async env => {
    env.record('arrived', { instructionId: 'instruction-1' }); env.record('revoked', { principalId: 'member' }); await env.dispatch();
  });
  const { events, revocations } = inspection.facts;
  assert.ok(events.find(row => row.type === 'arrived').seq < revocations[0].effectiveSeq);
  assert.ok(events.find(row => row.type === 'accepted').seq > revocations[0].effectiveSeq);
});

test('adapter: correct refusal and non-revoked active control remain separate observed facts', async t => {
  const authorities = [instruction(), instruction('control', { principalId: 'active' })];
  const { inspection } = await collected(t, async env => {
    env.record('revoked', { principalId: 'member' }); env.record('refused', { instructionId: 'instruction-1', principalId: 'member', binding: instruction() }); await env.dispatch(authorities[1]);
  }, { authorities });
  assert.equal(inspection.coverage, 'complete'); assert.equal(inspection.facts.effects[0].instructionId, 'control');
  assert.equal(inspection.facts.events.filter(row => row.type === 'refused').length, 1);
});

test('adapter: changed principal, tenant, charge, amount, currency and destination cannot inherit authority', async t => {
  for (const [field, value] of Object.entries({ principalId: 'other', tenantId: 'other', chargeId: 'ch_order_2', amount: 401, currency: 'usd', destination: 'pm_new_destination' })) {
    const { inspection } = await collected(t, env => env.dispatch({ ...instruction(), [field]: value }));
    assert.equal(inspection.facts.attempts.length, 1, field);
    assert.equal(inspection.facts.attempts[0].bindingValid, false, field);
    assert.ok(inspection.facts.effects.every(row => !row.bindingValid), field);
  }
});

test('adapter: provider-refused forbidden dispatch remains visible with zero business effects', async t => {
  const { inspection } = await collected(t, env => env.dispatch({ ...instruction(), amount: 2500, destination: 'pm_new_destination' }));
  assert.equal(inspection.facts.attempts.length, 1); assert.equal(inspection.facts.effects.length, 0);
  assert.equal(inspection.facts.attempts[0].providerStatus, 400); assert.equal(inspection.facts.attempts[0].bindingValid, false);
});

test('adapter: changed-body key refusal retains its own immutable attempted payload', async t => {
  const { inspection } = await collected(t, async env => { await env.dispatch(); await env.dispatch({ ...instruction(), destination: 'pm_new_destination' }); });
  assert.equal(inspection.facts.effects.length, 1); assert.equal(inspection.facts.attempts[1].providerStatus, 400);
  assert.equal(inspection.facts.attempts[1].bindingValid, false); assert.notEqual(inspection.facts.attempts[0].binding.destinationDigest, inspection.facts.attempts[1].binding.destinationDigest);
});

test('adapter: unbound sends are retained as incomplete rather than matched by charge, key or timing', async t => {
  const { inspection } = await collected(t, env => send(env.payments, { body: { charge: 'ch_order_1', amount: 400 }, key: 'instruction-1' }));
  assert.equal(inspection.coverage, 'incomplete'); assert.equal(inspection.facts.attempts.length, 1);
  assert.equal(inspection.facts.attempts[0].lineageValid, false); assert.equal(inspection.facts.effects[0].bound, false);
  assert.match(inspection.problems.join(), /metadata/);
});

test('adapter: forged header instruction or run cannot establish source lineage', async t => {
  for (const extra of [{ 'X-Scopehaven-Instruction': 'instruction-other' }, { 'X-Scopehaven-Run': 'run-other' }, { 'X-Scopehaven-Currency': 'usd' }]) {
    const { inspection } = await collected(t, env => env.dispatch(undefined, { metadata: { ...headers('run-1', instruction(), 'attempt-1'), ...extra } }));
    assert.equal(inspection.coverage, 'incomplete'); assert.equal(inspection.facts.effects[0].bound, false);
  }
});

test('adapter: dispatch trace without provider observation and unknown writes cannot close coverage', async t => {
  let result = await collected(t, env => env.record('attempt', { instructionId: 'instruction-1', attemptId: 'missing-attempt', binding: instruction() }));
  assert.match(result.inspection.problems.join(), /without-provider-observation/);
  result = await collected(t, env => send(env.payments, { path: '/pay/v1/transfers', body: { amount: 400 } }));
  assert.equal(result.inspection.coverage, 'incomplete'); assert.equal(result.inspection.facts.attempts.length, 1);
});

test('adapter: copied or deserialized bundles and changed expected contracts stay untrusted', async t => {
  const { bundle, contract, inspection } = await collected(t, env => env.dispatch());
  assert.equal(inspection.trusted, true);
  for (const candidate of [{ ...bundle }, JSON.parse(JSON.stringify(bundle)), freezeEvidence(JSON.parse(JSON.stringify(bundle)))]) assert.equal(inspectTemporalEvidence(candidate, contract).trusted, false);
  assert.equal(evaluateRefundCount({ kind: 'payment.refund.count', charge: 'ch_order_1', expected: 1 }, JSON.parse(JSON.stringify(bundle.payments))).verdict, 'inconclusive');
  const altered = JSON.parse(JSON.stringify(contract)); altered.horizon.deadlineMs--;
  assert.equal(inspectTemporalEvidence(bundle, altered).trusted, false);
  assert.equal(inspectTemporalEvidence(bundle, { ...contract, runId: 'different' }).trusted, false);
});

test('adapter: quiet silence, pending work and changed deadline do not prove closure', async t => {
  for (const options of [{ sourceOptions: { unclosed: true } }, { sourceOptions: { changedDeadline: true } }]) {
    const { inspection } = await collected(t, async () => {}, options); assert.equal(inspection.coverage, 'incomplete');
  }
  const { inspection } = await collected(t, env => env.setPending(1));
  assert.match(inspection.problems.join(), /horizon-not-closed/);
});

test('M4: a self-witness and no application contact leave an unclosed source inconclusive', async t => {
  const { bundle, inspection } = await collected(t, async () => {}, { sourceOptions: { unclosed: true } });
  assert.equal(bundle.payments.coverage, 'complete');
  assert.equal(bundle.payments.refunds.length, 0);
  assert.equal(bundle.payments.witnessSource, 'observer-dispatched');
  assert.equal(inspection.independentClosure, false);
  assert.equal(inspection.coverage, 'incomplete');
  assert.ok(inspection.problems.includes('observer-witness-independent-closure-missing'));
});

test('adapter: late application evidence is detected after the first source closure', async t => {
  const env = await environment(t); await env.collector.begin();
  const witness = env.payments.dispatchWitness;
  env.payments.dispatchWitness = async from => { env.record('attempt', { instructionId: 'instruction-1', attemptId: 'late-attempt', binding: instruction() }); await witness(from); };
  const bundle = await env.collector.finish();
  assert.equal(inspectTemporalEvidence(bundle, env.contract).coverage, 'incomplete');
  assert.match(bundle.problems.join(), /evidence-after-closure/);
});

test('adapter: missing and repeated witness delivery retain incomplete provider coverage', async t => {
  for (const duplicated of [false, true]) {
    const env = await environment(t); await env.collector.begin();
    const witness = env.payments.dispatchWitness;
    env.payments.dispatchWitness = async from => {
      if (!duplicated) { env.payments.markWitnessRequest(from); return; }
      await witness(from); await witness(from);
    };
    const bundle = await env.collector.finish(); assert.equal(bundle.coverage, 'incomplete');
    assert.match(bundle.payments.reason, duplicated ? /duplicate-witness/ : /witness-not-received/);
  }
});

test('adapter witness race: an unregistered matching witness cannot pass', async t => {
  const env = await environment(t); await env.collector.begin();
  env.payments.dispatchWitness = from => send(env.payments, { path: `/w/?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}` });
  const bundle = await env.collector.finish(); assert.equal(bundle.coverage, 'incomplete');
  assert.match(bundle.payments.reason, /payments-witness-request-not-marked/);
});

test('adapter witness race: repeating registration cannot move the first cutoff past a late send', async t => {
  const env = await environment(t); await env.collector.begin();
  const witness = env.payments.dispatchWitness;
  env.payments.dispatchWitness = async from => {
    env.payments.markWitnessRequest(from);
    await send(env.payments, { body: { charge: 'ch_order_1', amount: 300 } });
    env.payments.markWitnessRequest(from); await witness(from);
  };
  const bundle = await env.collector.finish(); assert.equal(bundle.coverage, 'incomplete');
  assert.match(bundle.payments.reason, /request-after-witness-request/);
});

test('adapter cursor race: forged concurrent legacy collection cannot erase the cutoff', async t => {
  const env = await environment(t); await env.collector.begin();
  const collect = env.payments.collectPayments;
  env.payments.collectPayments = async (from, to) => {
    const active = collect(from, to);
    await send(env.payments, { body: { charge: 'ch_order_1', amount: 300 } });
    const forged = await env.payments.collect({ ...from, witnessNonce: 'foreign' }, { ...to });
    assert.equal(forged.coverage, 'failed'); return active;
  };
  const bundle = await env.collector.finish(); assert.equal(bundle.coverage, 'incomplete');
  assert.match(bundle.payments.reason, /request-after-witness-request/);
});

test('adapter cursor race: original concurrent legacy collection loses after marks are consumed', async t => {
  const env = await environment(t); await env.collector.begin();
  const collect = env.payments.collectPayments;
  env.payments.collectPayments = async (from, to) => {
    const active = collect(from, to);
    assert.equal((await env.payments.collect(from, to)).coverage, 'failed');
    await assert.rejects(() => collect(from, to), /original, ordered, unused/);
    return active;
  };
  const bundle = await env.collector.finish(); assert.equal(bundle.coverage, 'complete');
});

test('adapter: collector/source reuse, foreign/edited marks and serialized raw windows cannot mint trust', async t => {
  const env = await environment(t); await env.collector.begin();
  await assert.rejects(() => env.collector.begin(), /single-use/);
  const other = createTemporalCollector({ fixture: { ...env.fixture }, payments: { ...env.payments }, contract: env.contract });
  await assert.rejects(() => other.begin(), /already belongs/);
  const collect = env.payments.collectPayments;
  env.payments.collectPayments = (from, to) => collect({ ...from }, to);
  const bundle = await env.collector.finish(); assert.equal(bundle.coverage, 'incomplete');
  await assert.rejects(() => env.collector.finish(), /exactly once/);
});

test('adapter: a fabricated payment window returned by a wrapper is never trusted as complete', async t => {
  const env = await environment(t); await env.collector.begin();
  const collect = env.payments.collectPayments;
  env.payments.collectPayments = async (...args) => freezeEvidence(JSON.parse(JSON.stringify(await collect(...args))));
  const bundle = await env.collector.finish(); assert.equal(bundle.coverage, 'incomplete'); assert.match(bundle.problems.join(), /custody-untrusted/);
  assert.equal(inspectTemporalEvidence(bundle, env.contract).trusted, false);
});

test('adapter: source epoch qualifies identical refund IDs across independent runs', async t => {
  const first = await collected(t, env => env.dispatch(), { runId: 'run-first' });
  const second = await collected(t, env => env.dispatch(), { runId: 'run-second' });
  assert.equal(first.inspection.facts.effects[0].providerEffectId, second.inspection.facts.effects[0].providerEffectId);
  assert.notEqual(first.inspection.facts.effects[0].effectId, second.inspection.facts.effects[0].effectId);
  assert.equal(inspectTemporalEvidence(first.bundle, second.contract).trusted, false);
});

test('adapter: replay of an effect created before the observed window cannot satisfy new completion', async t => {
  const env = await environment(t);
  await send(env.payments, { body: { charge: 'ch_order_1', amount: 400, currency: 'cad', destination: 'pm_card_on_file' }, key: 'instruction-1', metadata: headers('run-1', instruction(), 'old-attempt') });
  await env.collector.begin(); await env.dispatch(); const bundle = await env.collector.finish();
  const result = inspectTemporalEvidence(bundle, env.contract);
  assert.equal(result.coverage, 'incomplete'); assert.equal(result.facts.effects.length, 0);
  assert.equal(result.facts.terminals.at(-1).effectBound, false); assert.match(result.problems.join(), /outside-window/);
});

test('adapter: evicted and presence-only provider evidence cannot close a claim', async t => {
  let result = await collected(t, env => env.dispatch(), { paymentOptions: { retainedRequests: 1 } });
  assert.equal(result.inspection.coverage, 'incomplete'); assert.match(result.bundle.payments.reason, /records-evicted/);
  result = await collected(t, env => env.dispatch(), { paymentOptions: { routing: undefined, routes: undefined, witness: undefined } });
  assert.equal(result.inspection.coverage, 'incomplete');
});

test('pure binding: conflicting repeated attempt IDs and application sequence gaps are explicit', async t => {
  const { bundle, contract } = await collected(t, env => env.dispatch());
  const payments = JSON.parse(JSON.stringify(bundle.payments)); payments.lineage.push({ ...payments.lineage[0], seq: 99 });
  assert.match(bindTemporalFacts({ application: bundle.application, payments, contract }).problems.join(), /attempt-id-reused/);
  const application = JSON.parse(JSON.stringify(bundle.application)); application.events[1].seq += 20;
  assert.match(bindTemporalFacts({ application, payments: bundle.payments, contract }).problems.join(), /sequence-gap/);
});

test('adapter: missing clock, terminal timing, interval and registration seal cannot pass', async t => {
  for (const mutation of [snapshot => delete snapshot.timing, snapshot => { delete snapshot.events.at(-1).atMs; },
    snapshot => { snapshot.events.at(-1).atMs = snapshot.timing.closedAtMs + 1; }, snapshot => { snapshot.horizon.sealed = false; },
    snapshot => { snapshot.coverage.ordered = false; }, snapshot => { snapshot.horizon.deadlineMs--; }]) {
    const env = await environment(t); await env.collector.begin(); await env.dispatch();
    const snapshot = env.fixture.snapshot;
    env.fixture.snapshot = async args => { const row = JSON.parse(JSON.stringify(await snapshot(args))); mutation(row); return row; };
    const bundle = await env.collector.finish(); assert.equal(inspectTemporalEvidence(bundle, env.contract).coverage, 'incomplete');
  }
});

test('adapter: complete measured late success stays observable for a deadline failure', async t => {
  const { inspection, contract } = await collected(t, async env => { await wait(10); await env.dispatch(); }, { deadlineMs: 1 });
  assert.equal(inspection.coverage, 'complete');
  assert.ok(inspection.facts.terminals.at(-1).atMs > inspection.facts.timing.startedAtMs + contract.horizon.deadlineMs);
  assert.ok(inspection.facts.terminals.at(-1).effectBound);
});

test('fresh process: JSON of raw temporal or payment evidence cannot recreate live custody', async t => {
  const { bundle, contract } = await collected(t, env => env.dispatch());
  const program = `import {inspectTemporalEvidence} from ${JSON.stringify(new URL('./evidence.mjs', import.meta.url).href)};
    import {evaluateRefundCount} from ${JSON.stringify(new URL('../observers/payments-double.mjs', import.meta.url).href)};
    const {bundle,contract}=JSON.parse(${JSON.stringify(JSON.stringify({ bundle, contract }))});
    process.stdout.write(JSON.stringify({trusted:inspectTemporalEvidence(bundle,contract).trusted,
      verdict:evaluateRefundCount({kind:'payment.refund.count',charge:'ch_order_1',expected:1},bundle.payments).verdict}));`;
  const { stdout } = await promisify(execFile)(process.execPath, ['--input-type=module', '-e', program]);
  assert.deepEqual(JSON.parse(stdout), { trusted: false, verdict: 'inconclusive' });
});

test('independent regression: extra instruction/effect outside expected authority cannot hide beside required controls', async t => {
  const { inspection } = await collected(t, async env => {
    await env.dispatch();
    const rogue = instruction('rogue'); env.instructions.push(rogue);
    env.record('authorized', { instructionId: rogue.instructionId, binding: rogue }); await env.dispatch(rogue);
  });
  assert.equal(inspection.coverage, 'incomplete');
  assert.equal(inspection.facts.effects.length, 2);
  assert.equal(inspection.facts.effects[1].bindingValid, false);
  assert.match(inspection.problems.join(), /without-expected-authority/);
});

test('independent regression: predicted success before its creating dispatch cannot satisfy completion', async t => {
  const { inspection } = await collected(t, async env => {
    await env.dispatch();
    const attempt = env.events.find(row => row.type === 'attempt'), terminal = env.events.find(row => row.type === 'terminal');
    const sequence = attempt.seq, atMs = attempt.atMs;
    attempt.seq = terminal.seq; attempt.atMs = terminal.atMs;
    terminal.seq = sequence; terminal.atMs = atMs;
    env.events.sort((a, b) => a.seq - b.seq);
  });
  assert.equal(inspection.coverage, 'incomplete'); assert.equal(inspection.facts.terminals[0].effectBound, false);
  assert.match(inspection.problems.join(), /success-before-creating-dispatch/);
});

test('independent regression: initial revocation prefix cannot be rewritten before final closure', async t => {
  const env = await environment(t); env.record('revoked', { principalId: 'member' }); await env.collector.begin();
  env.events.find(row => row.type === 'revoked').principalId = 'other';
  const bundle = await env.collector.finish();
  assert.equal(bundle.coverage, 'incomplete'); assert.match(bundle.problems.join(), /initial-event-prefix-changed/);
});

test('independent regression: initially captured business instruction payload cannot be rewritten', async t => {
  const env = await environment(t); await env.collector.begin(); env.instructions[0].amount++;
  const bundle = await env.collector.finish(); assert.equal(bundle.coverage, 'incomplete');
  assert.match(bundle.problems.join(), /initial-instruction-binding-changed/);
});

test('independent regression: missing/conflicting refusal binding cannot masquerade as required actor refusal', async t => {
  const requiredChecks = [{ id: 'refusal', kind: 'refusal', instructionIds: ['instruction-1'] }];
  for (const fields of [{ principalId: 'other', binding: instruction() }, { principalId: 'member' }, { principalId: 'other', binding: instruction(undefined, { principalId: 'other' }) }]) {
    const { inspection } = await collected(t, env => env.record('refused', { instructionId: 'instruction-1', authorityId: 'authority-instruction-1', ...fields }), { requiredChecks });
    assert.equal(inspection.coverage, 'incomplete'); assert.match(inspection.problems.join(), /required-refusal-binding-unestablished/);
  }
  const { inspection } = await collected(t, env => env.record('refused', { instructionId: 'instruction-1', principalId: 'member', authorityId: 'authority-instruction-1', binding: instruction() }), { requiredChecks });
  assert.equal(inspection.coverage, 'complete'); assert.equal(inspection.facts.events.at(-1).bindingValid, true);
});

test('adapter: proper refusal of an unregistered request stays observable without creating authority', async t => {
  const { inspection } = await collected(t, env => env.record('refused', { instructionId: 'unregistered-request', principalId: 'member', reason: 'instruction-not-authorized' }));
  assert.equal(inspection.coverage, 'complete'); assert.equal(inspection.facts.effects.length, 0);
});

test('v1.3 freshness: run-derived principal, tenant, charge and authority bind without old literals', async t => {
  const results = [];
  for (let i = 0; i < 2; i++) {
    const runId = randomUUID();
    const desired = instruction('instruction-1', { authorityId: `${runId}-instruction-1`, principalId: `principal-${runId}-control`,
      tenantId: `tenant-${runId}-control`, chargeId: `ch_${runId.replaceAll('-', '_')}`, amount: 100, destination: 'pm_original' });
    const result = await collected(t, env => env.dispatch(desired), { runId, authorities: [desired], paymentOptions: {
      provider: { host: PAY, seed: [{ id: desired.chargeId, paymentMethod: desired.destination, amount: 10000, currency: desired.currency }] } } });
    assert.equal(result.inspection.coverage, 'complete');
    assert.ok(sameBinding(result.inspection.facts.effects[0], desired));
    results.push(result);
  }
  assert.notEqual(results[0].inspection.facts.effects[0].binding.chargeId, results[1].inspection.facts.effects[0].binding.chargeId);
  assert.notEqual(results[0].inspection.facts.effects[0].binding.principalId, results[1].inspection.facts.effects[0].binding.principalId);
  assert.equal(inspectTemporalEvidence(results[0].bundle, results[1].contract).trusted, false);
});

test('adapter: a revocation missing its principal cannot establish an acceptance cutoff', async t => {
  const { inspection } = await collected(t, env => env.record('revoked'));
  assert.equal(inspection.coverage, 'incomplete'); assert.match(inspection.problems.join(), /revocation-principal-missing/);
});

test('M17: matching coverage and horizon watermarks cannot exceed the last application event', async t => {
  const env = await environment(t); await env.collector.begin(); await env.dispatch();
  const snapshot = env.fixture.snapshot;
  env.fixture.snapshot = async args => {
    const result = structuredClone(await snapshot(args));
    if (args.close) { result.horizon.watermark++; result.coverage.toSeq = result.horizon.watermark; }
    return result;
  };
  const bundle = await env.collector.finish();
  assert.equal(bundle.coverage, 'incomplete'); assert.ok(bundle.problems.includes('application-watermark-mismatch'), JSON.stringify(bundle.problems));
});

test('M18: decreasing application event times inside the declared interval are rejected', async t => {
  const env = await environment(t); await env.collector.begin(); await env.dispatch();
  assert.ok(env.events[0].atMs > 0);
  env.events.find(event => event.type === 'accepted').atMs = env.events[0].atMs / 2;
  const bundle = await env.collector.finish();
  assert.equal(bundle.coverage, 'incomplete'); assert.ok(bundle.problems.includes('application-event-timing-invalid'), JSON.stringify(bundle.problems));
});

test('M19: an acceptance in the initial source prefix predates the operator provider window', async t => {
  const env = await environment(t);
  env.record('accepted', { instructionId: 'instruction-1', principalId: 'member', authorityId: 'authority-instruction-1', binding: instruction() });
  await env.collector.begin(); const bundle = await env.collector.finish();
  assert.equal(bundle.coverage, 'incomplete'); assert.ok(bundle.problems.includes('application-work-before-provider-window'), JSON.stringify(bundle.problems));
});

test('M23: a real provider send with valid headers still requires its application dispatch record', async t => {
  const { bundle, inspection } = await collected(t, env => send(env.payments, {
    body: { charge: 'ch_order_1', amount: 400, currency: 'cad', destination: 'pm_card_on_file' }, key: 'provider-without-app-dispatch',
    metadata: headers('run-1', instruction(), 'provider-only-attempt'),
  }));
  assert.equal(inspection.facts.attempts.length, 1); assert.equal(inspection.facts.effects.length, 1);
  assert.equal(inspection.facts.attempts[0].lineageValid, false);
  assert.equal(bundle.coverage, 'incomplete');
  assert.ok(bundle.problems.includes(`provider-attempt-without-application-dispatch:${inspection.facts.attempts[0].providerSeq}`), JSON.stringify(bundle.problems));
});
