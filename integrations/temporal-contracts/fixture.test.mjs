// Local synthetic HTTP only. Provider effects are read independently from its ledger.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { startRefundFixture, refundBuildHash } from './fixtures/refund-app.mjs';
import { createPaymentsDouble } from '../observers/payments-double.mjs';
import { onFreePorts } from '../observers/fixtures/free-port.mjs';

const CARD = 'pm_card_on_file_member';
async function fixture(t, variant = 'clean', options = {}) {
  const payments = await onFreePorts(1, async port => {
    const double = createPaymentsDouble({ instanceId: `payments-${randomUUID()}`, port,
      provider: { host: 'api.payments.test', seed: options.seed ?? [
        { id: 'ch_order_1', paymentMethod: CARD, amount: 100000, currency: 'cad' },
        { id: 'ch_order_2', paymentMethod: CARD, amount: 100000, currency: 'cad' },
      ] }, routing: 'base-url', destinations: [{ host: 'api.payments.test' }],
      routes: [{ prefix: '/pay/', host: 'api.payments.test' }, { prefix: '/w/', host: 'witness.scopehaven.invalid' }],
      witness: { actorId: 'member', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' },
      witnessWaitMs: 1500, quietMs: 150 });
    await double.start();
    return double;
  });
  const app = await startRefundFixture({ runId: options.runId ?? `run-${randomUUID()}`, payments, variant, identityContext: options.identityContext });
  t.after(async () => { await app.close(); await payments.stop(); });
  return { app, payments };
}
function authorize(app, actor = 'revoked', extra = {}) {
  return app.authorize({ instructionId: `instruction-${randomUUID()}`, authorityId: `authority-${randomUUID()}`,
    principalId: app.actors[actor].principalId, tenantId: app.actors[actor].tenantId,
    operation: 'refund', chargeId: 'ch_order_1', amount: 500, currency: 'cad', destination: CARD, ...extra });
}
function call(app, actor, path, data, headers = {}) {
  return new Promise((resolve, reject) => {
    const payload = data === undefined ? undefined : typeof data === 'string' ? data : JSON.stringify(data);
    const url = new URL(path, app.origin);
    const req = request({ hostname: '127.0.0.1', port: url.port, method: data === undefined ? 'GET' : 'POST', path: url.pathname,
      headers: { Authorization: `Bearer ${app.actors[actor]?.credential ?? actor}`, 'Content-Type': 'application/json', ...headers } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    });
    req.on('error', reject); req.setTimeout(5000, () => req.destroy(new Error('Local fixture test timeout.'))); req.end(payload);
  });
}
const refund = (app, instruction, extra = {}, actor = 'revoked') => call(app, actor, '/refund', { instructionId: instruction.instructionId, ...extra });
const capture = (app, close = true, horizonId = 'test-horizon', deadlineMs = 5000) => app.snapshot({ horizonId, deadlineMs, close });
const ofType = (snapshot, type) => snapshot.events.filter(event => event.type === type);

test('independent authority is immutable, unique and validated before requests', async t => {
  const { app, payments } = await fixture(t);
  const input = { instructionId: 'i1', authorityId: 'a1', principalId: app.actors.revoked.principalId,
    tenantId: app.actors.revoked.tenantId, operation: 'refund', chargeId: 'ch_order_1', amount: 500, currency: 'cad', destination: CARD };
  const instruction = app.authorize(input);
  input.amount = 900;
  assert.equal(instruction.amount, 500);
  assert(Object.isFrozen(instruction));
  assert.throws(() => { instruction.amount = 1000; }, TypeError);
  assert.throws(() => app.authorize({ ...input, amount: 500 }), /already registered/);
  assert.throws(() => app.authorize({ ...input, instructionId: 'i2' }), /already registered/);
  for (const change of [{ amount: 0 }, { amount: 1.1 }, { currency: 'CAD' }, { tenantId: 'foreign' }, { principalId: 'unknown' }, { authorityId: '' }, { instructionId: '../i' }, { operation: 'payout' }, { unknown: 'field' }]) {
    assert.throws(() => app.authorize({ ...input, instructionId: 'valid-new', authorityId: 'valid-new-authority', ...change }));
  }
  assert.equal(payments.providerLedger().refunds.length, 0);
  assert.equal((await refund(app, instruction)).status, 200);
  const snapshot = await capture(app);
  assert.equal(snapshot.instructions[0].amount, 500);
  assert.equal(ofType(snapshot, 'authorized').length, 1);
  assert.equal(ofType(snapshot, 'accepted').length, 1);
});

test('bearer identity, tenant/status isolation, loopback and bounded JSON boundaries are enforced', async t => {
  const { app, payments } = await fixture(t);
  const instruction = authorize(app);
  assert.deepEqual((await call(app, 'revoked', '/identity')).body, { principalId: app.actors.revoked.principalId, tenantId: app.actors.revoked.tenantId });
  assert.equal((await call(app, 'invalid-token', '/identity')).status, 401);
  assert.equal((await call(app, 'control', `/instructions/${instruction.instructionId}`)).status, 403);
  assert.equal((await call(app, 'revoked', '/control/revoke', {})).status, 404);
  for (const headers of [{ Host: 'evil.example' }, { Host: 'localhost' }, { Origin: app.origin }, { 'Sec-Fetch-Site': 'same-origin' }]) {
    assert.equal((await call(app, 'revoked', '/refund', { instructionId: instruction.instructionId }, headers)).status, 403);
  }
  for (const data of ['null', '[]', '{broken', JSON.stringify({ instructionId: instruction.instructionId, padding: 'x'.repeat(9000) })]) {
    const response = await call(app, 'revoked', '/refund', data);
    assert([400, 413].includes(response.status));
  }
  assert.equal((await call(app, 'revoked', '/refund', {}, { 'Content-Type': 'text/plain' })).status, 415);
  assert.equal(payments.providerLedger().refunds.length, 0);
  assert.equal((await refund(app, instruction)).body.state, 'success');
});

test('requests and transport keys cannot create missing instruction authority', async t => {
  const { app, payments } = await fixture(t);
  for (const key of [undefined, 'new-key']) {
    const response = await call(app, 'revoked', '/refund', { instructionId: 'not-issued', amount: 500, chargeId: 'ch_order_1', currency: 'cad', destination: CARD, ...(key ? { key } : {}) });
    assert.equal(response.status, 403);
    assert.equal(response.body.reason, 'instruction-not-authorized');
  }
  const snapshot = await capture(app);
  assert.equal(snapshot.instructions.length, 0);
  assert.equal(ofType(snapshot, 'accepted').length, 0);
  assert.equal(ofType(snapshot, 'attempt').length, 0);
  assert.equal(payments.providerLedger().refunds.length, 0);
});

test('lost response after commit stays pending; retry keys cannot multiply one instruction', async t => {
  const { app, payments } = await fixture(t);
  const instruction = authorize(app);
  const first = await refund(app, instruction, { key: 'first', loseResponse: true });
  assert.equal(first.status, 202);
  assert.equal(first.body.state, 'pending');
  assert.equal(first.body.effectId, undefined);
  assert.equal(payments.providerLedger().refunds.length, 1);
  assert.equal((await call(app, 'revoked', `/instructions/${instruction.instructionId}`)).body.state, 'pending');
  assert.equal((await refund(app, instruction, { key: 'first', loseResponse: true })).status, 202);
  const retry = await refund(app, instruction, { key: 'changed-key' });
  assert.equal(retry.status, 200);
  assert.equal(retry.body.state, 'success');
  assert.equal(payments.providerLedger().refunds.length, 1);
  assert.equal((await refund(app, instruction)).body.effectId, retry.body.effectId);
  const snapshot = await capture(app);
  assert.equal(ofType(snapshot, 'arrived').length, 4);
  assert.equal(ofType(snapshot, 'accepted').length, 1);
  assert.equal(ofType(snapshot, 'attempt').length, 3);
  assert.deepEqual(ofType(snapshot, 'terminal').map(event => event.state), ['pending', 'pending', 'success']);
  assert.equal(snapshot.coverage.complete, true);
});

test('identical independently authorized instructions have separate effects even with a shared caller key', async t => {
  const { app, payments } = await fixture(t);
  const one = authorize(app), two = authorize(app);
  const a = await refund(app, one, { key: 'same' }), b = await refund(app, two, { key: 'same' });
  assert.equal(a.body.state, 'success'); assert.equal(b.body.state, 'success');
  assert.notEqual(a.body.effectId, b.body.effectId);
  assert.equal(payments.providerLedger().refunds.length, 2);
  const snapshot = await capture(app);
  assert.equal(ofType(snapshot, 'authorized').length, 2);
  assert.equal(ofType(snapshot, 'accepted').length, 2);
  assert.equal(ofType(snapshot, 'attempt').length, 2);
});

test('request arrival before cutoff does not authorize acceptance after cutoff', async t => {
  const { app, payments } = await fixture(t);
  const instruction = authorize(app);
  assert.equal((await refund(app, instruction, { hold: 'before-acceptance' })).status, 202);
  const cutoff = app.revoke(app.actors.revoked.principalId);
  assert.strictEqual(app.revoke(app.actors.revoked.principalId), cutoff);
  assert.equal((await app.release(instruction.instructionId)).state, 'refused');
  const control = authorize(app, 'control');
  assert.equal((await refund(app, control, {}, 'control')).body.state, 'success');
  const snapshot = await capture(app);
  const arrival = ofType(snapshot, 'arrived').find(event => event.instructionId === instruction.instructionId);
  const refusal = ofType(snapshot, 'refused').find(event => event.instructionId === instruction.instructionId);
  assert(arrival.seq < cutoff.seq && cutoff.seq < refusal.seq);
  assert.equal(ofType(snapshot, 'accepted').some(event => event.instructionId === instruction.instructionId), false);
  assert.equal(payments.providerLedger().refunds.length, 1);
  assert.equal(snapshot.coverage.complete, true);
});

test('unchanged accepted work finishes and retries after revoke; new revoked work refuses and control succeeds', async t => {
  const { app, payments } = await fixture(t);
  const prior = authorize(app), later = authorize(app), control = authorize(app, 'control');
  assert.equal((await refund(app, prior, { hold: 'after-acceptance', loseResponse: true })).status, 202);
  const cutoff = app.revoke(app.actors.revoked.principalId);
  assert.equal((await app.release(prior.instructionId)).state, 'pending');
  assert.equal((await refund(app, prior, { key: 'post-cutoff-retry' })).body.state, 'success');
  assert.equal((await refund(app, later)).status, 403);
  assert.equal((await refund(app, control, {}, 'control')).body.state, 'success');
  const snapshot = await capture(app);
  const acceptance = ofType(snapshot, 'accepted').find(event => event.instructionId === prior.instructionId);
  assert(acceptance.seq < cutoff.seq);
  assert(ofType(snapshot, 'attempt').filter(event => event.instructionId === prior.instructionId).every(event => event.seq > cutoff.seq));
  assert.equal(payments.providerLedger().refunds.length, 2);
  assert.equal(snapshot.coverage.complete, true);
});

test('initial and repeated requests cannot change any immutable binding field or authenticated actor', async t => {
  const { app, payments } = await fixture(t);
  const instruction = authorize(app);
  const overrides = [{ authorityId: 'other-authority' }, { principalId: app.actors.control.principalId }, { tenantId: app.actors.control.tenantId },
    { operation: 'payout' }, { chargeId: 'ch_order_2' }, { amount: 600 }, { currency: 'usd' }, { destination: 'pm_card_new_4000' }];
  for (const override of overrides) assert.equal((await refund(app, instruction, override)).status, 409);
  assert.equal((await refund(app, instruction, {}, 'control')).status, 409);
  assert.equal(payments.providerLedger().refunds.length, 0);
  assert.equal((await refund(app, instruction)).body.state, 'success');
  app.revoke(app.actors.revoked.principalId);
  for (const override of overrides) assert.equal((await refund(app, instruction, override)).status, 409);
  assert.equal((await refund(app, instruction, {}, 'control')).status, 409);
  const snapshot = await capture(app);
  assert.equal(ofType(snapshot, 'attempt').length, 1);
  assert.equal(snapshot.instructions[0].amount, 500);
  assert.equal(snapshot.instructions[0].state, 'success');
  assert.equal(payments.providerLedger().refunds.length, 1);
});

test('concurrent invokes and concurrent releases cannot duplicate clean acceptance or effects', async t => {
  const { app, payments } = await fixture(t);
  const one = authorize(app);
  const replies = await Promise.all(Array.from({ length: 12 }, (_, i) => refund(app, one, { key: `key-${i}` })));
  assert(replies.every(response => [200, 202].includes(response.status)));
  const two = authorize(app);
  await refund(app, two, { hold: 'after-acceptance' });
  await Promise.all([app.release(two.instructionId), app.release(two.instructionId)]);
  const snapshot = await capture(app);
  assert.equal(ofType(snapshot, 'accepted').length, 2);
  assert.equal(ofType(snapshot, 'attempt').length, 2);
  assert.equal(payments.providerLedger().refunds.length, 2);
});

test('provider refusal has an outbound attempt and cannot become success', async t => {
  const { app, payments } = await fixture(t);
  const instruction = authorize(app, 'revoked', { amount: 100001 });
  const result = await refund(app, instruction);
  assert.equal(result.body.state, 'failure');
  const snapshot = await capture(app);
  assert.equal(ofType(snapshot, 'attempt').length, 1);
  assert.equal(ofType(snapshot, 'terminal').at(-1).state, 'failure');
  assert.equal(payments.providerLedger().refunds.length, 0);
  assert.equal(snapshot.coverage.complete, true);
});

test('provider transport failure remains retryable pending instead of claiming completion', async t => {
  const { app, payments } = await fixture(t);
  const instruction = authorize(app);
  await payments.stop();
  assert.equal((await refund(app, instruction)).status, 202);
  assert.equal((await call(app, 'revoked', `/instructions/${instruction.instructionId}`)).body.state, 'pending');
  await payments.start();
  assert.equal((await refund(app, instruction)).body.state, 'success');
  assert.equal(payments.providerLedger().refunds.length, 1);
  assert.equal(ofType(await capture(app), 'attempt').length, 2);
});

for (const variant of ['deny-all', 'no-op', 'never-completing', 'false-success']) {
  test(`degenerate ${variant} exposes lack of legitimate completed effect`, async t => {
    const { app, payments } = await fixture(t, variant);
    const instruction = authorize(app, 'control');
    const response = await refund(app, instruction, {}, 'control');
    const snapshot = await capture(app);
    assert.equal(payments.providerLedger().refunds.length, 0);
    assert.equal(ofType(snapshot, 'attempt').length, 0);
    if (variant === 'deny-all') assert.equal(response.status, 403);
    if (variant === 'no-op') assert.equal(response.body.state, 'failure');
    if (variant === 'never-completing') {
      assert.equal(response.status, 202); assert.equal(snapshot.horizon.closed, false);
      assert.equal(snapshot.horizon.pending, 1); assert.equal(snapshot.coverage.complete, false);
    }
    if (variant === 'false-success') {
      assert.equal(response.body.state, 'success');
      assert.match(response.body.effectId, /^fabricated-/);
    }
    assert.equal(JSON.stringify(snapshot).includes(variant), false);
  });
}

test('duplicate-effect fault exposes two effects from one accepted instruction', async t => {
  const { app, payments } = await fixture(t, 'duplicate-effect');
  const instruction = authorize(app);
  await refund(app, instruction, { key: 'first', loseResponse: true });
  await refund(app, instruction, { key: 'second' });
  const snapshot = await capture(app);
  assert.equal(payments.providerLedger().refunds.length, 2);
  assert.equal(ofType(snapshot, 'accepted').length, 1);
  assert.equal(ofType(snapshot, 'attempt').length, 2);
  assert.equal(JSON.stringify(snapshot).includes('duplicate-effect'), false);
});

test('shared-effect fault exposes one provider effect falsely used for two instructions', async t => {
  const { app, payments } = await fixture(t, 'shared-effect');
  const one = authorize(app, 'revoked', { instructionId: 'identical-a' }), two = authorize(app, 'revoked', { instructionId: 'identical-b' });
  const a = await refund(app, one, { key: 'distinct-a' }), b = await refund(app, two, { key: 'distinct-b' });
  assert.equal(a.body.effectId, b.body.effectId);
  assert.equal(payments.providerLedger().refunds.length, 1);
  const snapshot = await capture(app);
  assert.equal(ofType(snapshot, 'accepted').length, 2);
  assert.equal(ofType(snapshot, 'terminal').filter(event => event.state === 'success').length, 2);
  assert.equal(JSON.stringify(snapshot).includes('shared-effect'), false);
});

test('accept-after-revoke fault is visible even with an earlier arrival and a live control', async t => {
  const { app, payments } = await fixture(t, 'accept-after-revoke');
  const instruction = authorize(app);
  await refund(app, instruction, { hold: 'before-acceptance' });
  const cutoff = app.revoke(app.actors.revoked.principalId);
  assert.equal((await app.release(instruction.instructionId)).state, 'success');
  const control = authorize(app, 'control');
  assert.equal((await refund(app, control, {}, 'control')).body.state, 'success');
  const snapshot = await capture(app);
  assert(ofType(snapshot, 'accepted').find(event => event.instructionId === instruction.instructionId).seq > cutoff.seq);
  assert.equal(payments.providerLedger().refunds.length, 2);
  assert.equal(JSON.stringify(snapshot).includes('accept-after-revoke'), false);
});

test('changed-binding fault retains improper downstream attempts even when provider dedupe refuses', async t => {
  const { app, payments } = await fixture(t, 'changed-binding-dispatch');
  const instruction = authorize(app);
  await refund(app, instruction);
  const result = await refund(app, instruction, { amount: 600, chargeId: 'ch_order_2', currency: 'usd', destination: 'pm_card_new_4000' }, 'control');
  assert.equal(result.body.state, 'failure');
  assert.equal(payments.providerLedger().refunds.length, 1);
  const snapshot = await capture(app);
  const attempts = ofType(snapshot, 'attempt');
  assert.equal(attempts.length, 2);
  assert.equal(attempts[1].binding.principalId, app.actors.control.principalId);
  assert.equal(attempts[1].binding.tenantId, app.actors.control.tenantId);
  assert.equal(attempts[1].binding.amount, 600);
  assert.equal(attempts[1].binding.chargeId, 'ch_order_2');
  assert.equal(attempts[1].binding.currency, 'usd');
  assert.equal(attempts[1].binding.destination, 'pm_card_new_4000');
  assert.equal(snapshot.instructions[0].amount, 500);
  assert.equal(JSON.stringify(snapshot).includes('changed-binding-dispatch'), false);
});

test('closure cannot hide scheduled work or late events, and snapshots are deeply frozen', async t => {
  const { app } = await fixture(t);
  const instruction = authorize(app);
  await refund(app, instruction, { hold: 'after-acceptance' });
  const first = await capture(app);
  assert.equal(first.coverage.complete, false);
  assert.equal(first.horizon.closed, false);
  assert.equal(first.horizon.pending, 1);
  assert(Object.isFrozen(first.events[0].binding));
  assert.throws(() => { first.instructions[0].amount = 100; }, TypeError);
  await app.release(instruction.instructionId);
  const late = await capture(app);
  assert.equal(late.horizon.watermark, first.horizon.watermark);
  assert.equal(late.coverage.complete, false);
  assert(late.coverage.lateEvents > 0);
  assert(late.coverage.problems.includes('late-application-events'));
  await assert.rejects(() => capture(app, true, 'replacement-horizon'), /replace/);
  assert.throws(() => authorize(app), /registration is closed/);
});

test('fresh fixtures reset lifecycle and isolate old effects and credentials from a new run', async t => {
  const first = await fixture(t), second = await fixture(t);
  const old = authorize(first.app);
  await refund(first.app, old);
  const fresh = authorize(second.app, 'revoked', { instructionId: old.instructionId, authorityId: old.authorityId });
  assert.equal(second.payments.providerLedger().refunds.length, 0);
  assert.equal((await call(second.app, first.app.actors.revoked.credential, '/identity')).status, 401);
  await refund(second.app, fresh);
  const a = await capture(first.app), b = await capture(second.app);
  assert.notEqual(a.runId, b.runId); assert.notEqual(a.sourceId, b.sourceId);
  assert.notEqual(ofType(a, 'attempt')[0].attemptId, ofType(b, 'attempt')[0].attemptId);
  assert.equal(a.instructions[0].attemptIds.length, 1); assert.equal(b.instructions[0].attemptIds.length, 1);
});

test('a conflicting request cannot conceal legitimate queued work from closure', async t => {
  const { app, payments } = await fixture(t);
  const instruction = authorize(app);
  await refund(app, instruction, { hold: 'before-acceptance' });
  assert.equal((await refund(app, instruction, {}, 'control')).status, 409);
  assert.equal((await call(app, 'revoked', `/instructions/${instruction.instructionId}`)).body.state, 'pending');
  const snapshot = await capture(app);
  assert.equal(snapshot.horizon.pending, 1);
  assert.equal(snapshot.horizon.closed, false);
  assert.equal(snapshot.coverage.complete, false);
  await app.release(instruction.instructionId);
  assert.equal(payments.providerLedger().refunds.length, 1);
  assert.equal((await capture(app)).coverage.complete, false);
});

test('an unfinished authenticated request body is in-scope delivery at horizon closure', async t => {
  const { app, payments } = await fixture(t);
  const instruction = authorize(app);
  const url = new URL(app.origin), payload = JSON.stringify({ instructionId: instruction.instructionId });
  let req;
  const response = new Promise((resolve, reject) => {
    req = request({ hostname: '127.0.0.1', port: url.port, method: 'POST', path: '/refund',
      headers: { Authorization: `Bearer ${app.actors.revoked.credential}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))));
    });
    req.on('error', reject);
    req.write(payload.slice(0, -1));
  });
  // A completed request on the same app confirms the prior delivery reached its
  // parser; no arbitrary timing sleep controls the authorization interleaving.
  await call(app, 'revoked', '/identity');
  const snapshot = await capture(app);
  assert.equal(snapshot.horizon.closed, false);
  assert.equal(snapshot.horizon.pending, 1);
  assert.equal(snapshot.coverage.complete, false);
  req.end(payload.slice(-1));
  assert.equal((await response).state, 'success');
  assert.equal(payments.providerLedger().refunds.length, 1);
  const late = await capture(app);
  assert.equal(late.coverage.complete, false);
  assert(late.coverage.lateEvents > 0);
});

test('concurrent closure cannot substitute another caller horizon identity', async t => {
  const { app } = await fixture(t);
  const instruction = authorize(app);
  await refund(app, instruction);
  const results = await Promise.allSettled([capture(app, true, 'first-horizon'), capture(app, true, 'second-horizon')]);
  assert.equal(results[0].status, 'fulfilled');
  assert.equal(results[0].value.horizon.id, 'first-horizon');
  assert.equal(results[1].status, 'rejected');
  assert.match(results[1].reason.message, /replace/);
});

test('fixture build identity is deterministic before startup and independent of run context', async t => {
  const one = await fixture(t), two = await fixture(t);
  assert.equal(refundBuildHash('clean'), one.app.buildHash);
  assert.equal(one.app.buildHash, two.app.buildHash);
  assert.match(one.app.buildHash, /^[a-f0-9]{64}$/);
  const hashes = ['clean', 'deny-all', 'no-op', 'never-completing', 'duplicate-effect', 'shared-effect', 'false-success', 'accept-after-revoke', 'changed-binding-dispatch'].map(refundBuildHash);
  assert.equal(new Set(hashes).size, hashes.length);
  assert.throws(() => refundBuildHash('unknown'), /Unknown/);
  assert.notEqual(one.app.actors.revoked.principalId, two.app.actors.revoked.principalId);
  assert.notEqual(one.app.actors.control.tenantId, two.app.actors.control.tenantId);
});

test('trusted actor context is copied without credentials and fresh charges flow through normal authorization', async t => {
  const runId = `context-${randomUUID()}`, chargeId = `ch_${runId.replaceAll('-', '_')}`;
  const identityContext = Object.fromEntries(['revoked', 'control'].map(role => [role,
    { principalId: `principal-${runId}-${role}`, tenantId: `tenant-${runId}-${role}` }]));
  const expected = structuredClone(identityContext);
  const { app, payments } = await fixture(t, 'clean', { runId, identityContext,
    seed: [{ id: chargeId, paymentMethod: CARD, amount: 100000, currency: 'cad' }] });
  identityContext.revoked.principalId = 'mutated-operator-object';
  assert.equal(app.actors.revoked.principalId, expected.revoked.principalId);
  assert.equal(app.actors.control.tenantId, expected.control.tenantId);
  assert.equal((await call(app, 'revoked', '/identity')).body.principalId, expected.revoked.principalId);
  const instruction = authorize(app, 'revoked', { authorityId: `${runId}-fresh-instruction`, chargeId });
  assert.equal((await refund(app, instruction)).body.state, 'success');
  const snapshot = await capture(app);
  assert.equal(ofType(snapshot, 'attempt')[0].binding.chargeId, chargeId);
  assert.equal(payments.providerLedger().refunds[0].charge, chargeId);
  for (const invalid of [
    { ...expected, extra: {} },
    { ...expected, revoked: { ...expected.revoked, credential: 'supplied-token' } },
    { ...expected, control: { ...expected.control, principalId: expected.revoked.principalId } },
    { ...expected, control: { ...expected.control, tenantId: expected.revoked.tenantId } },
    { ...expected, revoked: { ...expected.revoked, principalId: '' } },
  ]) await assert.rejects(() => startRefundFixture({ runId, payments, identityContext: invalid }), /Invalid trusted actor context/);
});

test('fresh run contexts bind distinct principal, tenant, charge and authority across repeated instruction names', async t => {
  const runs = [`fresh-${randomUUID()}`, `fresh-${randomUUID()}`], captures = [];
  for (const runId of runs) {
    const chargeId = `ch_${runId.replaceAll('-', '_')}`;
    const { app, payments } = await fixture(t, 'clean', { runId,
      seed: [{ id: chargeId, paymentMethod: CARD, amount: 100000, currency: 'cad' }] });
    const instruction = authorize(app, 'revoked', { instructionId: 'same-alias', authorityId: `${runId}-same-alias`, chargeId });
    await refund(app, instruction);
    assert.equal(payments.providerLedger().refunds.length, 1);
    captures.push(await capture(app));
  }
  for (const field of ['principalId', 'tenantId', 'chargeId', 'authorityId']) assert.notEqual(captures[0].instructions[0][field], captures[1].instructions[0][field]);
  assert.notEqual(captures[0].timing.clockId, captures[1].timing.clockId);
  assert.equal(captures[0].buildHash, captures[1].buildHash);
});

test('measured source boundary orders every event and fixed close timing survives rereads', async t => {
  const { app } = await fixture(t);
  const begin = await capture(app, false);
  assert.equal(begin.timing.closedAtMs, null);
  assert(Number.isFinite(begin.timing.startedAtMs) && begin.timing.startedAtMs >= 0);
  assert.equal(begin.horizon.deadlineMs, 5000);
  assert.equal(begin.horizon.sealed, false);
  await delay(10);
  const instruction = authorize(app);
  await refund(app, instruction, { hold: 'after-acceptance' });
  const cutoff = app.revoke(app.actors.revoked.principalId);
  await app.release(instruction.instructionId);
  const closed = await capture(app);
  assert.equal(closed.horizon.sealed, true);
  assert.equal(closed.coverage.complete, true);
  assert.equal(closed.timing.startedAtMs, begin.timing.startedAtMs);
  assert(closed.timing.closedAtMs - closed.timing.startedAtMs >= 10);
  assert(closed.events.every(event => Number.isFinite(event.atMs) && event.atMs >= begin.timing.startedAtMs && event.atMs <= closed.timing.closedAtMs));
  assert(closed.events.every((event, i) => i === 0 || event.atMs >= closed.events[i - 1].atMs));
  const acceptance = ofType(closed, 'accepted')[0];
  assert(acceptance.seq < cutoff.seq && acceptance.atMs <= cutoff.atMs);
  await delay(10);
  const again = await capture(app);
  assert.deepEqual(again.timing, closed.timing);
  assert.deepEqual(again.horizon, closed.horizon);
});

test('requested deadline is mandatory, bounded and cannot be changed or shortened', async t => {
  const { app } = await fixture(t);
  for (const deadlineMs of [undefined, 0, -1, 5001, NaN, Infinity, 1.5, '5000']) {
    await assert.rejects(() => app.snapshot({ horizonId: 'fixed', deadlineMs, close: false }), /bounded completion deadline/);
  }
  const begin = await capture(app, false, 'fixed', 100);
  const again = await capture(app, false, 'fixed', 100);
  assert.deepEqual(again.timing, begin.timing);
  await assert.rejects(() => capture(app, true, 'fixed', 99), /replace/);
  await assert.rejects(() => capture(app, true, 'fixed', 101), /replace/);
  const closed = await capture(app, true, 'fixed', 100);
  assert.equal(closed.horizon.deadlineMs, 100);
  await assert.rejects(() => capture(app, true, 'fixed', 50), /replace/);
});

test('an actually late terminal success retains measured complete evidence for completion failure', async t => {
  const { app, payments } = await fixture(t);
  const begin = await capture(app, false, 'late-horizon', 1);
  await delay(20);
  const instruction = authorize(app);
  assert.equal((await refund(app, instruction)).body.state, 'success');
  const snapshot = await capture(app, true, 'late-horizon', 1);
  const success = ofType(snapshot, 'terminal').find(event => event.state === 'success');
  assert(success.atMs > begin.timing.startedAtMs + snapshot.horizon.deadlineMs);
  assert(success.atMs <= snapshot.timing.closedAtMs);
  assert.equal(snapshot.coverage.complete, true);
  assert.equal(payments.providerLedger().refunds.length, 1);
  // Evaluator owns the failing completion verdict; fixture reports actual timing.
});

test('starting a collector after prior source events cannot hide events outside its interval', async t => {
  const { app } = await fixture(t);
  authorize(app);
  await capture(app, false);
  const snapshot = await capture(app);
  assert.equal(snapshot.coverage.complete, false);
  assert(snapshot.coverage.problems.includes('application-event-outside-interval'));
});

test('close seals new registration synchronously while a preexisting provider operation drains', async t => {
  let arrived, finish;
  const onArrival = new Promise(resolve => { arrived = resolve; }), onFinish = new Promise(resolve => { finish = resolve; });
  const provider = createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    arrived(); await onFinish;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ id: 're_owned_drain', charge: input.charge, amount: input.amount, currency: input.currency, status: 'succeeded' }));
  });
  await new Promise(resolve => provider.listen(0, '127.0.0.1', resolve));
  const app = await startRefundFixture({ runId: `drain-${randomUUID()}`, payments: { port: provider.address().port } });
  t.after(async () => { finish(); await app.close(); await new Promise(resolve => { provider.close(resolve); provider.closeAllConnections(); }); });
  await capture(app, false);
  const one = authorize(app), later = authorize(app);
  const response = refund(app, one);
  await onArrival;
  const closing = capture(app);
  assert.throws(() => authorize(app), /registration is closed/);
  assert.throws(() => app.revoke(app.actors.control.principalId), /registration is closed/);
  assert.equal((await refund(app, later)).status, 409);
  finish();
  assert.equal((await response).body.state, 'success');
  const snapshot = await closing;
  assert.equal(snapshot.horizon.sealed, true);
  assert.equal(snapshot.horizon.pending, 0);
  assert.equal(snapshot.coverage.complete, true);
  assert.equal(ofType(snapshot, 'attempt').length, 1);
  assert.equal(ofType(snapshot, 'arrived').length, 1);
});

test('shared-effect fault is confined to identical pair and preserves the unrelated control', async t => {
  const { app, payments } = await fixture(t, 'shared-effect');
  const a = authorize(app, 'control', { instructionId: 'identical-a' }), b = authorize(app, 'control', { instructionId: 'identical-b' });
  const control = authorize(app, 'control', { instructionId: 'active-control' });
  const one = await refund(app, a, { key: 'a' }, 'control'), two = await refund(app, b, { key: 'b' }, 'control');
  const active = await refund(app, control, { key: 'a' }, 'control');
  assert.equal(one.body.effectId, two.body.effectId);
  assert.notEqual(active.body.effectId, one.body.effectId);
  assert.equal(active.body.state, 'success');
  assert.equal(payments.providerLedger().refunds.length, 2);
});
