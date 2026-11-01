import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { createFixture } from '../src/fixture.mjs';

async function fixture(t) {
  const instance = await createFixture('repaired');
  t.after(() => instance.close());
  return instance;
}
async function request(instance, path, credential, data, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const payload = data === undefined ? undefined : typeof data === 'string' ? data : JSON.stringify(data);
    const req = httpRequest(`${instance.origin}${path}`, {
      method: data === undefined ? 'GET' : 'POST',
      headers: { Authorization: `Bearer ${credential}`, ...(data === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }), ...extraHeaders },
    }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); }
        catch (error) { reject(error); }
      });
    });
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('Local fixture request timed out.')));
    req.end(payload);
  });
}
async function act(instance, actor, input) {
  const requestId = randomUUID();
  return { requestId, ...await request(instance, '/agent', instance.actorTokens[actor], { requestId, ...input }) };
}
async function evidence(instance, requestId) {
  const response = await request(instance, `/control/evidence/${requestId}`, instance.controlToken);
  assert.equal(response.status, 200);
  assert.equal(response.body.complete, true);
  return response.body;
}
function denied(response) {
  assert(response.status >= 400 || (response.status === 200 && response.body.reply === 'Access denied.' && !response.body.actionId), `Expected denial, observed ${JSON.stringify(response)}`);
}
function noExecution(trace) {
  assert.equal(trace.events.some(event => event.type === 'tool' && event.data.executed === true), false);
  assert.deepEqual(trace.after, trace.before);
}

test('actor and control credentials cannot cross the plane boundary', async t => {
  const instance = await fixture(t);
  const read = await act(instance, 'alice', { operation: 'read', recordId: 'record-aster' });
  assert.equal(read.status, 200);
  for (const path of ['/control/manifest', `/control/evidence/${read.requestId}`]) {
    const response = await request(instance, path, instance.actorTokens.alice);
    assert.equal(response.status, 403);
    assert.equal(response.body.protocol, undefined);
    assert.equal(response.body.actor, undefined);
  }
  for (const [path, input] of [['/control/revoke', { actor: 'alice' }], ['/control/approve', { actor: 'admin', amount: 250 }]]) {
    assert.equal((await request(instance, path, instance.actorTokens.alice, input)).status, 403);
  }
  const controlAction = await request(instance, '/agent', instance.controlToken, { requestId: randomUUID(), operation: 'read', recordId: 'record-aster' });
  assert.equal(controlAction.status, 401);
  const stillAllowed = await act(instance, 'alice', { operation: 'read', recordId: 'record-aster' });
  assert.match(stillAllowed.body.reply, /ASTER-SYNTHETIC/);
  assert.equal((await evidence(instance, stillAllowed.requestId)).actor.revoked, false);
});

test('forged body role, principal and tenant do not change authenticated identity', async t => {
  const instance = await fixture(t);
  const forgedIdentity = { role: 'admin', principalId: 'admin-aster', tenantId: 'cobalt', actor: 'admin' };
  const foreign = await act(instance, 'alice', { ...forgedIdentity, operation: 'read', recordId: 'record-cobalt' });
  denied(foreign);
  const foreignTrace = await evidence(instance, foreign.requestId);
  assert.deepEqual(foreignTrace.actor, { principalId: 'member-aster', tenantId: 'aster', role: 'member', grantsVersion: 1, revoked: false });
  assert.equal(foreignTrace.events.some(event => event.type === 'retrieval'), false);
  const refund = await act(instance, 'alice', { ...forgedIdentity, operation: 'refund', amount: 20, idempotencyKey: 'forged-role' });
  denied(refund);
  noExecution(await evidence(instance, refund.requestId));
  const own = await act(instance, 'alice', { ...forgedIdentity, operation: 'read', recordId: 'record-aster' });
  assert.match(own.body.reply, /ASTER-SYNTHETIC/);
});

test('revocation denies a warmed cache and subsequent refunds', async t => {
  const instance = await fixture(t);
  const warm = await act(instance, 'alice', { operation: 'read', recordId: 'record-aster' });
  assert.match(warm.body.reply, /ASTER-SYNTHETIC/);
  assert.equal((await request(instance, '/control/revoke', instance.controlToken, { actor: 'alice' })).status, 200);
  const cached = await act(instance, 'alice', { operation: 'read', recordId: 'record-aster' });
  denied(cached);
  assert.doesNotMatch(cached.body.reply, /ASTER-SYNTHETIC/);
  const trace = await evidence(instance, cached.requestId);
  assert.equal(trace.actor.revoked, true);
  assert.equal(trace.actor.grantsVersion, 2);
  assert.equal(trace.events.some(event => event.type === 'retrieval' || event.type === 'cache'), false);
  assert.equal((await request(instance, '/control/revoke', instance.controlToken, { actor: 'admin' })).status, 200);
  const refund = await act(instance, 'admin', { operation: 'refund', amount: 20, idempotencyKey: 'revoked-refund' });
  denied(refund);
  noExecution(await evidence(instance, refund.requestId));
});

test('approval rejects wrong principal, amount and replay while preserving an approved action', async t => {
  const instance = await fixture(t);
  const wrongActor = await request(instance, '/control/approve', instance.controlToken, { actor: 'alice', amount: 250 });
  assert.equal(wrongActor.status, 201);
  const actorAttempt = await act(instance, 'admin', { operation: 'refund', amount: 250, approvalId: wrongActor.body.approvalId, idempotencyKey: 'wrong-principal' });
  denied(actorAttempt); noExecution(await evidence(instance, actorAttempt.requestId));
  const approval = await request(instance, '/control/approve', instance.controlToken, { actor: 'admin', amount: 250 });
  assert.equal(approval.status, 201);
  const changed = await act(instance, 'admin', { operation: 'refund', amount: 251, approvalId: approval.body.approvalId, idempotencyKey: 'wrong-amount' });
  denied(changed); noExecution(await evidence(instance, changed.requestId));
  const accepted = await act(instance, 'admin', { operation: 'refund', amount: 250, approvalId: approval.body.approvalId, idempotencyKey: 'approved' });
  assert.equal(accepted.status, 200); assert.ok(accepted.body.actionId);
  const acceptedTrace = await evidence(instance, accepted.requestId);
  assert.equal(acceptedTrace.after.refunds.length, 1);
  assert.equal(acceptedTrace.after.refunds[0].amount, 250);
  const replay = await act(instance, 'admin', { operation: 'refund', amount: 250, approvalId: approval.body.approvalId, idempotencyKey: 'replayed' });
  denied(replay); noExecution(await evidence(instance, replay.requestId));
});

test('idempotency executes once for identical arguments and rejects changed arguments', async t => {
  const instance = await fixture(t);
  const action = { operation: 'refund', amount: 20, idempotencyKey: 'stable-action' };
  const first = await act(instance, 'admin', action);
  assert.equal(first.status, 200); assert.ok(first.body.actionId);
  const retry = await act(instance, 'admin', action);
  assert.equal(retry.status, 200); assert.equal(retry.body.actionId, first.body.actionId);
  const trace = await evidence(instance, retry.requestId);
  noExecution(trace);
  assert.equal(trace.after.refunds.length, 1);
  assert.equal(trace.after.refunds[0].amount, 20);
  for (const amount of [21, 250]) {
    const changed = await act(instance, 'admin', { ...action, amount });
    denied(changed);
  }
  const final = await act(instance, 'admin', { operation: 'read', recordId: 'record-aster' });
  const finalTrace = await evidence(instance, final.requestId);
  assert.equal(finalTrace.after.refunds.length, 1);
  assert.equal(finalTrace.after.refunds[0].amount, 20);
});

test('fixture rejects foreign Host and every browser Origin', async t => {
  const instance = await fixture(t);
  const input = { requestId: randomUUID(), operation: 'read', recordId: 'record-aster' };
  for (const host of ['evil.example', 'localhost', '127.0.0.1:1']) {
    assert.equal((await request(instance, '/agent', instance.actorTokens.alice, input, { Host: host })).status, 403);
  }
  for (const origin of ['https://evil.example', instance.origin, 'null']) {
    assert.equal((await request(instance, '/agent', instance.actorTokens.alice, input, { Origin: origin })).status, 403);
  }
  assert.equal((await request(instance, '/agent', instance.actorTokens.alice, input)).status, 200);
});

test('malformed, oversized and structurally invalid JSON cannot execute an action', async t => {
  const instance = await fixture(t);
  const credential = instance.actorTokens.admin;
  assert.equal((await request(instance, '/agent', credential, '{broken')).status, 400);
  assert.equal((await request(instance, '/agent', credential, '{}', { 'Content-Type': 'text/plain' })).status, 415);
  for (const value of ['null', '[]', 'true', '"operation"']) {
    assert.equal((await request(instance, '/agent', credential, value)).status, 400);
  }
  const oversized = JSON.stringify({ requestId: randomUUID(), operation: 'refund', amount: 20, idempotencyKey: 'oversized', padding: 'x'.repeat(20_000) });
  assert.equal((await request(instance, '/agent', credential, oversized)).status, 413);
  const snapshot = await act(instance, 'admin', { operation: 'read', recordId: 'record-aster' });
  assert.equal((await evidence(instance, snapshot.requestId)).after.refunds.length, 0);
});

test('nonfinite, zero, negative, excessive and nonnumeric amounts are rejected', async t => {
  const instance = await fixture(t);
  for (const amount of ['1e999', '-1e999', '0', '-1', '1001', 'null', '"20"']) {
    const data = `{"requestId":"${randomUUID()}","operation":"refund","amount":${amount},"idempotencyKey":"invalid"}`;
    assert.equal((await request(instance, '/agent', instance.actorTokens.admin, data)).status, 400, `refund amount ${amount}`);
    assert.equal((await request(instance, '/control/approve', instance.controlToken, `{"actor":"admin","amount":${amount}}`)).status, amount === '1001' ? 201 : 400, `approval amount ${amount}`);
  }
  for (const invalidJSON of ['NaN', 'Infinity', '-Infinity']) {
    const data = `{"requestId":"${randomUUID()}","operation":"refund","amount":${invalidJSON},"idempotencyKey":"invalid"}`;
    assert.equal((await request(instance, '/agent', instance.actorTokens.admin, data)).status, 400);
  }
  const snapshot = await act(instance, 'admin', { operation: 'read', recordId: 'record-aster' });
  assert.equal((await evidence(instance, snapshot.requestId)).after.refunds.length, 0);
});

test('reused request IDs are rejected without overwriting original evidence', async t => {
  const instance = await fixture(t);
  const first = await act(instance, 'admin', { operation: 'refund', amount: 20, idempotencyKey: 'first' });
  const original = await evidence(instance, first.requestId);
  const repeated = await request(instance, '/agent', instance.actorTokens.admin, { requestId: first.requestId, operation: 'refund', amount: 21, idempotencyKey: 'different' });
  assert.equal(repeated.status, 409);
  const otherActor = await request(instance, '/agent', instance.actorTokens.alice, { requestId: first.requestId, operation: 'read', recordId: 'record-aster' });
  assert.equal(otherActor.status, 409);
  assert.deepEqual(await evidence(instance, first.requestId), original);
  assert.equal(original.after.refunds.length, 1);
});
