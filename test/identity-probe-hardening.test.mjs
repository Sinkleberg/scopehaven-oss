// Identity hunt LOW-1 (IDENTITY-HUNT-2026-10-06.json): the invalid-credential probe
// used a fixed "scopehaven-invalid-" prefix, so a fail-open target that recognised it
// passed the identity proof. The probe is now a per-run random look-alike of each
// actor's own credential (same length and character class, no fixed marker).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { runHttpAssessment, lookalikeCredential } from '../src/http-connector.mjs';
import { compareRuns } from '../src/runner.mjs';
import { createRegistry } from '../src/registry.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';

const A = 'alice-session-token-7Hq2Lw', B = 'bob-session-token-9Kx4Pz';
const env = { SCOPEHAVEN_TARGET_ALICE: A, SCOPEHAVEN_TARGET_BOB: B };
const send = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
const cookie = req => /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];
async function serve(t, handler) {
  const server = createServer(handler);
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const actor = (id, envName) => ({ principalId: id, credentialEnv: envName, credentialCookie: 'sid', identityValue: `${id}@x.test` });
const whoami = (id, actorId) => ({ id, title: id, category: 'Access', severity: 'control', actorId, method: 'GET', path: '/whoami', evidenceRequirement: 'response',
  assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/email', expected: `${actorId}@x.test` }] });
const profile = (origin, actors, checks, requiredControlIds) => ({ id: 'probe', name: 'Probe', applicationId: 'probeapp', origin, buildLabel: 'b', contextId: 'ctx', actors, requiredControlIds, checks });
const suiteOf = p => createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
// A fail-open who-am-I that sniffs the old probe prefix: any other token is alice.
const sniffing = (req, res) => {
  const c = cookie(req);
  if (!c || c.startsWith('scopehaven-invalid-')) return send(res, 401, {});
  return send(res, 200, { email: c === B ? 'bob@x.test' : 'alice@x.test' });
};

test('the invalid credential is a per-run look-alike of the actor\'s own: same length and classes, no fixed marker', () => {
  const secret = randomBytes(32), jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.abc_DEF-123';
  for (const real of [A, jwt, 'x', '0000']) {
    const fake = lookalikeCredential(real, secret, 'alice');
    assert.notEqual(fake, real); assert.equal(fake.length, real.length);
    [...real].forEach((ch, i) => { const cls = c => /[a-z]/.test(c) ? 'l' : /[A-Z]/.test(c) ? 'u' : /[0-9]/.test(c) ? 'd' : c; assert.equal(cls(fake[i]), cls(ch)); });
    assert.ok(!fake.startsWith('scopehaven'));
  }
  assert.equal(lookalikeCredential(jwt, secret, 'alice').split('.').length, 3, 'a JWT keeps its shape');
  assert.notEqual(lookalikeCredential(A, randomBytes(32), 'alice'), lookalikeCredential(A, randomBytes(32), 'alice'), 'fresh each run');
  assert.notEqual(lookalikeCredential(A, secret, 'alice'), lookalikeCredential(A, secret, 'bob'), 'per actor');
});

test('identity hunt D: a fail-open target that recognises the old probe prefix no longer proves a login', async t => {
  const origin = await serve(t, (req, res) => req.url === '/whoami' ? sniffing(req, res) : send(res, 404, {}));
  const p = profile(origin, { alice: actor('alice', 'SCOPEHAVEN_TARGET_ALICE') }, [whoami('WA', 'alice')], ['WA']);
  const run = await runHttpAssessment(p, { env });
  const alice = run.identityEvidence.actors.find(a => a.actorId === 'alice');
  assert.equal(alice.invalid[0].httpStatus, 200, 'the look-alike was accepted by the fail-open target');
  assert.equal(alice.loginProven, false);
  const gate = summarizeGate({ candidate: run, expectedSuite: suiteOf(p) });
  assert.notEqual(gate.exitCode, 0); assert.ok(gate.reasons.includes('identity-not-established'), JSON.stringify(gate.reasons));
});

test('identity hunt K: with a second honest actor, the probe-sniffing target cannot show a fix as restored', async t => {
  // One target (same origin, same profile) whose leak is "fixed" between the runs.
  const state = { leak: true };
  const origin = await serve(t, (req, res) => {
    if (req.url === '/whoami') return sniffing(req, res);
    if (req.url === '/secret') return !cookie(req) ? send(res, 401, {}) : state.leak ? send(res, 200, { s: 'x' }) : send(res, 403, {});
    send(res, 404, {});
  });
  const checks = [whoami('WA', 'alice'), whoami('WB', 'bob'),
    { id: 'SECRET', title: 'SECRET', category: 'Access', severity: 'high', actorId: 'alice', method: 'GET', path: '/secret', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] }];
  const actors = { alice: actor('alice', 'SCOPEHAVEN_TARGET_ALICE'), bob: actor('bob', 'SCOPEHAVEN_TARGET_BOB') };
  const fixed = profile(origin, actors, checks, ['WA', 'WB']);
  const before = await runHttpAssessment(fixed, { env });
  state.leak = false;
  const after = await runHttpAssessment(fixed, { env });
  assert.deepEqual(after.identityEvidence.actors.map(a => [a.actorId, a.loginProven]), [['alice', false], ['bob', true]]);
  const compared = compareRuns(before, after);
  assert.notEqual(compared.rows.find(r => r.id === 'SECRET').transition, 'contract-restored', JSON.stringify(compared.rows));
  const gate = summarizeGate({ candidate: after, baseline: before, expectedSuite: suiteOf(fixed) });
  assert.notEqual(gate.exitCode, 0, JSON.stringify(gate.reasons));
  // An honest target that validates credentials still proves both logins.
  const honest = profile(await serve(t, (req, res) => { const c = cookie(req); return req.url === '/whoami' ? (c === A ? send(res, 200, { email: 'alice@x.test' }) : c === B ? send(res, 200, { email: 'bob@x.test' }) : send(res, 401, {})) : send(res, 404, {}); }),
    actors, [whoami('WA', 'alice'), whoami('WB', 'bob')], ['WA', 'WB']);
  const proven = await runHttpAssessment(honest, { env });
  assert.deepEqual(proven.identityEvidence.actors.map(a => a.loginProven), [true, true]);
  assert.equal(summarizeGate({ candidate: proven, expectedSuite: suiteOf(honest) }).exitCode, 0);
});
