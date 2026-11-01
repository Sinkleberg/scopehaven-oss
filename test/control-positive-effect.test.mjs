// An allowed-use control that declares effects must prove one positively (effect.exists, or effect.count expecting at least 1).
// With only effect.none, effect.count 0 or effect.only (whose expect is a ceiling), it passed when nothing happened, so an app that
// answered 200 and did nothing established the actor and its refused boundary rows passed clean. Injected transport and sink: no socket.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateTargetFile, validateHttpRunEvidence } from '../src/contracts.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { digest } from '../src/domain.mjs';

const PAY = 'payments.example.test';
const refunds = { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/refunds' };
const only = { kind: 'effect.only', expect: [refunds], allow: [], operations: ['send'] };
const exists = { kind: 'effect.exists', select: refunds };
let seq = 0;
function fakeSink(plan) {
  return configs => configs.map(c => {
    const instanceId = `${c.type}-${c.id}`, windows = [...plan];
    let mark = 0;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope: { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
      async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect() { const n = windows.shift() ?? 0; return { events: Array.from({ length: n }, () => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: ++seq, operation: 'send', name: PAY, resource: 'POST /v1/refunds', outcome: 'committed', content: { b: 1 } })), coverage: 'complete', reason: null }; } };
  });
}
// C: refund your own order (the allowed use, a required control); B: refunding another customer's order is refused.
const profile = effects => ({ id: 'refunds', name: 'Refunds', applicationId: 'refunds', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic', actors: { u: { principalId: 'u-1' } },
  observers: [{ id: 'sink', type: 'egress-recorder', port: 40998, routing: 'proxy', destinations: [{ host: PAY }], witness: { actorId: 'u', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250, quietMs: 150 }],
  requiredControlIds: ['C'], checks: [
    { id: 'C', title: 'Refund own order', category: 'x', severity: 'control', actorId: 'u', method: 'POST', path: '/orders/1/refund', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], ...(effects ? { effects } : {}) },
    { id: 'B', title: 'Refund another customer order', category: 'x', severity: 'high', actorId: 'u', method: 'POST', path: '/orders/2/refund', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] }] });
const valid = effects => validateTargetFile({ schemaVersion: 1, targets: [profile(effects)] });
// A build that answers the allowed use with 200 and the boundary with 403; `sends` refunds go out during C.
const transport = async (origin, c) => ({ status: c.path === '/orders/2/refund' ? 403 : 200, complete: true, jsonParsed: true, json: {}, bytes: 2 });
const assess = async (effects, sends) => { const run = await runHttpAssessment(profile(effects), { env: {}, transport, observerFactory: fakeSink([sends, 0, 0]) }); validateHttpRunEvidence(run); return run; };
const row = (run, id) => run.results.find(r => r.id === id);

test('a control that declares effects needs a positive one; a response-only control is unchanged', () => {
  const refused = /allowed-use controls that declare effects need a positive one/;
  for (const effects of [[only], [{ kind: 'effect.none', select: refunds }], [{ kind: 'effect.count', select: refunds, expected: 0 }], [only, { kind: 'effect.none', select: { ...refunds, resource: 'POST /v1/payouts' } }]])
    assert.throws(() => valid(effects), refused, JSON.stringify(effects.map(e => e.kind)));
  for (const effects of [[exists], [{ kind: 'effect.count', select: refunds, expected: 1 }], [only, exists], [exists, { kind: 'effect.none', select: { ...refunds, resource: 'POST /v1/payouts' } }]])
    assert.doesNotThrow(() => valid(effects), JSON.stringify(effects.map(e => e.kind)));
  assert.doesNotThrow(() => valid(null), 'a response-only control rests on its response, as before');
});

test('an app that answers 200 and does nothing never establishes the actor through a control with effects', async () => {
  const idle = await assess([only, exists], 0);
  assert.deepEqual([row(idle, 'C').status, row(idle, 'B').status], ['fail', 'inconclusive']);
  assert.equal(row(idle, 'B').assertions.find(a => /^Actor identity/.test(a.name))?.status, 'inconclusive');
  const done = await assess([only, exists], 1);
  assert.deepEqual([row(done, 'C').status, row(done, 'B').status], ['pass', 'pass']);
});

test('a saved run whose control declares effects but no positive one is refused as such', async () => {
  const run = await assess([only, exists], 1);
  const x = row(run, 'C');
  x.trace[1].data.effects = x.trace[1].data.effects.filter(e => e.kind === 'effect.only');
  x.evidenceDigest = digest({ evidence: x.trace[0].data, effects: x.trace[1].data, assertions: x.assertions });
  assert.throws(() => validateHttpRunEvidence(run), e => e.code === 'invalid-run-evidence' && e.detail === 'control-no-positive-effect');
});
