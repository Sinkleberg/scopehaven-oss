import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const PROJECT = fileURLToPath(new URL('../', import.meta.url));
const ACTOR = 'SCOPEHAVEN_TARGET_READINESS_ACTOR';
const AUDIT = 'SCOPEHAVEN_TARGET_READINESS_AUDIT';
const actorToken = 'synthetic-actor-token';
const auditToken = 'synthetic-audit-token';
const observer = () => ({ id: 'audit', type: 'http-audit', origin: 'http://127.0.0.1:1', path: '/audit',
  credentialEnv: AUDIT, itemsPointer: '/items', pageLimit: 100, fields: { id: '/id', actor: '/actor', action: '/action' },
  actions: { read: 'update' }, principals: ['reader'] });
const profile = () => ({ id: 'audit-readiness', name: 'Synthetic audit readiness', applicationId: 'readiness-test',
  origin: 'http://127.0.0.1:1', buildLabel: 'synthetic', contextId: 'local-only',
  actors: { reader: { principalId: 'reader', credentialEnv: ACTOR } }, observers: [observer()],
  requiredControlIds: ['READ'], checks: [{ id: 'READ', title: 'Allowed read', category: 'Allowed use', severity: 'control',
    actorId: 'reader', method: 'GET', path: '/read', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }] });

// Run only the real CLI's offline readiness branch, with a fresh synthetic
// profile and an explicit environment: never inherit local credentials.
async function check(t, { target = profile(), env = { [ACTOR]: actorToken }, flag = '--check-config', setupError } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven audit readiness '));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const config = join(dir, 'targets.json');
  await writeFile(config, JSON.stringify({ schemaVersion: 1, targets: [target] }), { mode: 0o600 });
  const result = spawnSync(process.execPath, ['src/cli.mjs', flag, '--config', config], {
    cwd: PROJECT, env: { TMPDIR: tmpdir(), ...env }, encoding: 'utf8', timeout: 30000,
  });
  assert.ifError(result.error);
  for (const value of Object.values(env).filter(value => value.length > 8)) {
    for (const output of [result.stdout, result.stderr]) {
      assert.equal(output.includes(value), false, 'credential values must not be printed');
      assert.equal(output.includes(JSON.stringify(value).slice(1, -1)), false, 'encoded credential values must not be printed');
    }
  }
  if (setupError) {
    assert.equal(result.status, 2); assert.equal(result.stdout, ''); assert.match(result.stderr, setupError);
    return;
  }
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  const report = JSON.parse(result.stdout);
  assert.equal(report.configurationValid, true);
  assert.equal(report.connectionTested, false);
  const row = report.targets.find(row => row.id === target.id);
  assert.ok(row);
  return row;
}

function notReady(row, refs = [AUDIT]) {
  assert.equal(row.available, false);
  assert.equal(row.credentialsReady, false);
  assert.match(row.readinessReason, /audit observer credential.*missing or invalid/i);
  assert.deepEqual(row.missingCredentialRefs, refs);
}

test('check-config reports missing audit credentials as not ready', async t => {
  notReady(await check(t));
});

test('check-config keeps a correctly configured audit profile ready', async t => {
  const row = await check(t, { env: { [ACTOR]: actorToken, [AUDIT]: auditToken } });
  assert.equal(row.available, true);
  assert.equal(row.credentialsReady, true);
  assert.deepEqual(row.missingCredentialRefs, []);
  assert.equal(row.readinessReason, undefined);
});

test('check-config rejects unusable audit credential values', async t => {
  for (const [name, value] of [['empty', ''], ['space', 'synthetic token'], ['newline', 'synthetic\ntoken'],
    ['non-ASCII', 'synthetic-\u00e9'], ['too long', 'x'.repeat(8193)]]) {
    await t.test(name, async t => notReady(await check(t, { env: { [ACTOR]: actorToken, [AUDIT]: value } })));
  }
});

test('check-config applies audit cookie credential rules', async t => {
  const target = profile(); target.observers[0].credentialCookie = 'audit_session';
  await t.test('valid cookie', async t => {
    const row = await check(t, { target, env: { [ACTOR]: actorToken, [AUDIT]: auditToken } });
    assert.equal(row.available, true); assert.equal(row.credentialsReady, true); assert.deepEqual(row.missingCredentialRefs, []);
  });
  await t.test('cookie separator', async t => {
    notReady(await check(t, { target, env: { [ACTOR]: actorToken, [AUDIT]: 'synthetic;second=value' } }));
  });
  await t.test('invalid cookie name', async t => {
    const invalid = structuredClone(target); invalid.observers[0].credentialCookie = 'bad name';
    notReady(await check(t, { target: invalid, env: { [ACTOR]: actorToken, [AUDIT]: auditToken } }));
  });
});

test('check-config rejects invalid audit references but supports an anonymous audit endpoint', async t => {
  for (const ref of [null, '', 'OTHER_TOKEN']) await t.test(`invalid reference ${JSON.stringify(ref)}`, async t => {
    const target = profile(); target.observers[0].credentialEnv = ref;
    await check(t, { target, env: { [ACTOR]: actorToken, OTHER_TOKEN: auditToken }, setupError: /credential references must use the dedicated SCOPEHAVEN_TARGET_ namespace/ });
  });
  await t.test('anonymous audit endpoint', async t => {
    const target = profile(); delete target.observers[0].credentialEnv;
    const row = await check(t, { target });
    assert.equal(row.available, true); assert.equal(row.credentialsReady, true); assert.deepEqual(row.missingCredentialRefs, []);
  });
  await t.test('cookie without a reference', async t => {
    const target = profile(); delete target.observers[0].credentialEnv; target.observers[0].credentialCookie = 'audit_session';
    notReady(await check(t, { target }), []);
  });
});

test('check-config merges and deduplicates actor and audit credential references', async t => {
  const target = profile(); target.observers.push({ ...observer(), id: 'second-audit' });
  notReady(await check(t, { target, env: {} }), [ACTOR, AUDIT]);
});

test('check-config preserves missing actor readiness with a valid audit credential', async t => {
  const row = await check(t, { env: { [AUDIT]: auditToken } });
  assert.equal(row.available, false); assert.equal(row.credentialsReady, false); assert.deepEqual(row.missingCredentialRefs, [ACTOR]);
});

test('check-config keeps response-only profiles ready and list uses the same audit readiness', async t => {
  const target = profile(); delete target.observers;
  const row = await check(t, { target });
  assert.equal(row.available, true); assert.equal(row.credentialsReady, true); assert.deepEqual(row.missingCredentialRefs, []);
  notReady(await check(t, { flag: '--list' }));
});
