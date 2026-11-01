// Synthetic loopback evidence only; no provider or model calls.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { createPaymentsDouble, evaluateRefundCount, isAuthenticPaymentsWindow } from './payments-double.mjs';
import { onFreePorts } from './fixtures/free-port.mjs';

async function source(t) {
  return onFreePorts(1, async port => {
    const payments = createPaymentsDouble({ instanceId: 'closure-test', port, routing: 'base-url',
      destinations: [{ host: 'api.payments.test' }],
      routes: [{ prefix: '/pay/', host: 'api.payments.test' }, { prefix: '/w/', host: 'witness.scopehaven.invalid' }],
      witness: { actorId: 'control', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, witnessWaitMs: 0, quietMs: 100,
      provider: { host: 'api.payments.test', seed: [{ id: 'ch_closure', amount: 1000, currency: 'cad', paymentMethod: 'pm_original' }] } });
    await payments.start(); t.after(() => payments.stop()); return payments;
  });
}
const count = (bundle, expected) => evaluateRefundCount({ kind: 'payment.refund.count', charge: 'ch_closure', expected }, bundle);

test('M4: observer witness without application contact cannot prove zero refunds', async t => {
  const payments = await source(t), from = await payments.mark();
  await payments.dispatchWitness(from);
  const bundle = await payments.collectPayments(from, await payments.mark());
  assert.equal(isAuthenticPaymentsWindow(bundle), true);
  assert.equal(bundle.coverage, 'complete', 'transport capture can be complete without application closure');
  assert.equal(bundle.scope.evidence, 'authoritative');
  assert.equal(bundle.refunds.length, 0);
  assert.equal(count(bundle, 0).verdict, 'inconclusive');
  assert.equal(count(bundle, 1).verdict, 'inconclusive');
  assert.equal(bundle.witnessSource, 'observer-dispatched');
  assert.match(count(bundle, 0).basis, /independent closure/);
});

test('M4: a prior request marker cannot hide observer dispatch', async t => {
  const payments = await source(t), from = await payments.mark();
  payments.markWitnessRequest(from);
  await payments.dispatchWitness(from);
  payments.markWitnessRequest(from);
  const bundle = await payments.collectPayments(from, await payments.mark());
  assert.equal(bundle.witnessSource, 'observer-dispatched');
  assert.equal(count(bundle, 0).verdict, 'inconclusive');
  assert.throws(() => { bundle.witnessSource = 'external'; }, TypeError);
});

test('M4: a separately delivered witness keeps the existing refund-count behavior', async t => {
  const payments = await source(t), from = await payments.mark();
  payments.markWitnessRequest(from);
  await new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: payments.port, method: 'GET',
      path: `/w/?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}` }, res => {
      res.resume(); res.on('end', resolve); res.on('error', reject);
    });
    req.on('error', reject); req.end();
  });
  const bundle = await payments.collectPayments(from, await payments.mark());
  assert.equal(bundle.witnessSource, 'external');
  assert.equal(count(bundle, 0).verdict, 'pass');
  assert.equal(count(bundle, 1).verdict, 'fail');
});
