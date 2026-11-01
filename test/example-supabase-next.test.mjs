// The Supabase + Next.js example (examples/supabase-next/) and its guide (docs/guides/supabase-next-10-minutes.md) stay usable
// as templates: the profile validates with the product's own loader and declares what its README says; the authorization
// record is sealed and covers the profile's origin, its observer's endpoint and every credentialed actor; the pg-snapshot
// observer builds from the declaration without connecting; the policy importer reads the example migration with no gap;
// .env.example names every credential the profile reads and holds no value; and the guide names every file in the folder.
// Shape only: nothing here connects to anything or sends a request.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { validateTargetFile } from '../src/contracts.mjs';
import { validateAuthorization, checkAuthorization, contactedEndpoints, AUTHORIZATION_SCHEMA, AuthorizationError } from '../src/authorization.mjs';
import { readAuthorizationFile } from '../src/authorization-file.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';
import { IGNORE_PLATFORMS } from '../integrations/observers/ignore-lists/ignore-list.mjs';
import { importRls } from '../integrations/policy-import/rls.mjs';

const EXAMPLE = new URL('../examples/supabase-next/', import.meta.url);
const GUIDE = new URL('../docs/guides/supabase-next-10-minutes.md', import.meta.url);
const read = url => readFile(url, 'utf8');
// Every file under the example folder, as a path relative to it.
async function filesUnder(url, prefix = '') {
  const out = [];
  for (const entry of (await readdir(url, { withFileTypes: true })).sort((x, y) => x.name.localeCompare(y.name))) {
    if (entry.isDirectory()) out.push(...await filesUnder(new URL(`${entry.name}/`, url), `${prefix}${entry.name}/`));
    else out.push(`${prefix}${entry.name}`);
  }
  return out;
}
const target = validateTargetFile(JSON.parse(await read(new URL('profile.json', EXAMPLE))))[0];
const byId = Object.fromEntries(target.checks.map(check => [check.id, check]));
// The instant inside the template's placeholder window the checks below use.
const INSIDE = new Date('2026-11-01T12:00:00Z');
const credentialEnvs = [...Object.values(target.actors).map(actor => actor.credentialEnv), ...target.observers.map(o => o.credentialEnv)].filter(Boolean);

test('the profile validates and declares two tenants, an ended session, the controls and the three prohibitions the README names', () => {
  assert.equal(target.id, 'supabase-next');
  assert.equal(target.origin, 'http://127.0.0.1:54321', 'the Supabase API gateway of a default supabase start');
  assert.deepEqual([target.actors.a.tenantId, target.actors.a.role, target.actors.b.tenantId, target.actors.b.role], ['tenant-a', 'admin', 'tenant-b', 'member']);
  assert.equal(target.actors.revoked.credentialEnv, 'SCOPEHAVEN_TARGET_SUPABASE_NEXT_REVOKED');
  assert.equal(Object.hasOwn(target.actors.revoked, 'identityValue'), false, 'an ended session has no identity to establish');
  assert.deepEqual(target.actors.anonymous, { principalId: 'anonymous' });
  // The three prohibitions and what decides each.
  const crossTenant = byId['B-READS-A-NOTE'];
  assert.deepEqual([crossTenant.actorId, crossTenant.method, crossTenant.severity, crossTenant.evidenceRequirement], ['b', 'GET', 'high', 'response']);
  assert.deepEqual(crossTenant.assertions, [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/0', expected: false }], 'PostgREST refuses with 200 and no rows; the body is judged');
  assert.ok(crossTenant.path.includes('REPLACE_NOTE_A_ID') && byId['A-OWN-NOTE'].path === crossTenant.path, 'B asks for exactly the note A opens');
  const adminWrite = byId['B-MEMBER-ADMIN-WRITE'];
  assert.deepEqual([adminWrite.actorId, adminWrite.method, adminWrite.severity, adminWrite.evidenceRequirement], ['b', 'PATCH', 'high', 'backend']);
  assert.deepEqual(adminWrite.assertions, [{ kind: 'status.equals', expected: 204 }], 'a filtered UPDATE answers 204 like a real one: the status cannot decide');
  assert.deepEqual(adminWrite.effects, [{ kind: 'effect.none', select: { source: 'sql-snapshot', operation: 'update', name: 'workspaces' } }]);
  const revokedWrite = byId['REVOKED-WRITES-OWN-NOTE'];
  assert.deepEqual([revokedWrite.actorId, revokedWrite.method, revokedWrite.evidenceRequirement], ['revoked', 'PATCH', 'backend']);
  assert.deepEqual(revokedWrite.assertions, [{ kind: 'status.in', expected: [401, 403] }]);
  assert.deepEqual(revokedWrite.effects, [{ kind: 'effect.none', select: { source: 'sql-snapshot', operation: 'update', name: 'notes' } }]);
  assert.deepEqual(byId['REVOKED-WHOAMI'].assertions, [{ kind: 'status.in', expected: [401, 403] }]);
  // The allowed-use controls beside them: required, severity control, and the two writes show the observer sees each table.
  for (const id of ['A-OWN-NOTE', 'B-OWN-NOTE', 'A-OWN-WORKSPACE-UPDATE', 'B-OWN-NOTE-UPDATE']) {
    assert.ok(target.requiredControlIds.includes(id), `${id} is required`);
    assert.equal(byId[id].severity, 'control', id);
  }
  assert.deepEqual(byId['A-OWN-WORKSPACE-UPDATE'].effects[0], { kind: 'effect.exists', select: { source: 'sql-snapshot', operation: 'update', name: 'workspaces', resource: 'workspaces/REPLACE_WORKSPACE_A_ID' } });
  assert.deepEqual(byId['B-OWN-NOTE-UPDATE'].effects[0], { kind: 'effect.exists', select: { source: 'sql-snapshot', operation: 'update', name: 'notes', resource: 'notes/REPLACE_NOTE_B_ID' } });
  // Each prohibition's actor has a required allowed-use control (the ended session, by design, has none).
  for (const check of target.checks.filter(c => c.severity !== 'control' && c.actorId !== 'anonymous' && c.actorId !== 'revoked')) {
    assert.ok(target.requiredControlIds.some(id => byId[id].actorId === check.actorId && id !== check.id), `${check.id} has an allowed-use control beside it`);
  }
  // No prohibition is a required control.
  for (const id of target.requiredControlIds) assert.equal(byId[id].severity, 'control', `${id} is a control`);
  // Every check of a credentialed actor with an identity has that identity's who-am-I control required.
  for (const alias of ['a', 'b']) assert.ok(target.requiredControlIds.some(id => byId[id].actorId === alias && byId[id].assertions.some(a => a.kind === 'json.equals' && a.expected === target.actors[alias].identityValue)), `${alias} has an identity control`);
});

test('the pg-snapshot observer points at the local Supabase Postgres with the checked-in supabase ignore list, and builds without connecting', () => {
  assert.equal(target.observers.length, 1);
  const [observer] = target.observers;
  assert.deepEqual([observer.type, observer.host, observer.port, observer.database, observer.platform], ['pg-snapshot', '127.0.0.1', 54322, 'postgres', 'supabase']);
  assert.ok(IGNORE_PLATFORMS.postgres.includes(observer.platform), 'the platform names a checked-in Postgres ignore list (integrations/observers/ignore-lists/supabase.json)');
  assert.deepEqual(observer.tables.map(t => t.table).sort(), ['notes', 'workspaces']);
  // The factory builds from the declaration alone (it connects only at start, which is not called here).
  const built = buildObservers(target.observers, { env: { [observer.credentialEnv]: 'scopehaven_read:synthetic-password' } });
  assert.equal(built.length, 1);
  assert.equal(typeof built[0].start, 'function');
  assert.equal(built[0].postResponseSettleMs, 500);
  // Every effect selector names a declared table of the declared source.
  const names = new Set(observer.tables.map(t => t.table));
  for (const check of target.checks) for (const effect of check.effects ?? []) {
    assert.equal(effect.select.source, 'sql-snapshot', check.id);
    assert.ok(names.has(effect.select.name), `${check.id} names an observed table`);
  }
});

test('the authorization record is sealed, covers the profile, its observer endpoint and every credentialed actor, and its window is real', async () => {
  const record = await readAuthorizationFile(fileURLToPath(new URL('authorization.json', EXAMPLE)));
  const valid = validateAuthorization(record);
  assert.equal(valid.schema, AUTHORIZATION_SCHEMA);
  const stamp = checkAuthorization(record, target, { now: INSIDE });
  assert.deepEqual(stamp, { schema: AUTHORIZATION_SCHEMA, id: record.id, sha256: record.sha256 });
  const contacted = contactedEndpoints(target);
  assert.ok(contacted.includes('tcp://127.0.0.1:54322'), 'the observer endpoint is one the run contacts');
  for (const endpoint of contacted) assert.ok(record.origins.includes(endpoint), `${endpoint} is in the record`);
  const credentialed = Object.values(target.actors).filter(actor => actor.credentialEnv).map(actor => actor.principalId).sort();
  assert.deepEqual([...record.identities].sort(), credentialed, 'the record names exactly the credentialed test accounts');
  // A placeholder window is still a window: outside it the record refuses, so a copied template cannot run unedited next month.
  assert.throws(() => checkAuthorization(record, target, { now: new Date('2026-11-03T00:00:00Z') }), error => error instanceof AuthorizationError && error.code === 'authorization-window');
  // An edit without re-sealing shows.
  assert.throws(() => validateAuthorization({ ...record, identities: [...record.identities, 'another'] }), error => error.code === 'authorization-checksum');
});

test('.env.example names every credential the profile reads, and no value', async () => {
  const lines = (await read(new URL('.env.example', EXAMPLE))).split('\n');
  const assigned = Object.fromEntries(lines.filter(line => /^[A-Z0-9_]+=/.test(line)).map(line => line.split('=')));
  for (const name of credentialEnvs) assert.ok(Object.hasOwn(assigned, name), `${name} is listed`);
  for (const [name, value] of Object.entries(assigned)) {
    assert.ok(name.startsWith('SCOPEHAVEN_TARGET_SUPABASE_NEXT_'), name);
    assert.ok(value === '' || value.endsWith(':'), `${name} holds no value (a user: prefix at most)`);
  }
  assert.ok(lines.some(line => line.includes('SCOPEHAVEN_TARGET_SUPABASE_NEXT_DB_WAL')), 'the init --stack observer credential is named for the guide');
});

test('the policy importer reads the example migration: both tenant tables are under row-level security, with no gap', async () => {
  const dir = new URL('supabase/migrations/', EXAMPLE);
  const names = (await readdir(dir)).filter(name => name.endsWith('.sql')).sort();
  assert.ok(names.length >= 1);
  const files = await Promise.all(names.map(async name => ({ id: name, content: await read(new URL(name, dir)) })));
  const matrix = importRls(files, { application: 'supabase-next', roles: ['anon', 'authenticated'], bypassRoles: ['service_role'] });
  const cell = (role, resource, action) => matrix.cells.find(c => c.role === role && c.resource === resource && c.action === action);
  assert.equal(matrix.cells.filter(c => c.decision === 'unknown').length, 0, 'no statement the importer could not follow');
  assert.equal(matrix.gaps.length, 0);
  assert.equal(cell('anon', 'public.notes', 'SELECT').decision, 'deny', 'row-level security on, no policy for anon');
  assert.equal(cell('authenticated', 'public.notes', 'SELECT').decision, 'conditional', 'members of the workspace');
  assert.equal(cell('authenticated', 'public.notes', 'UPDATE').decision, 'conditional', 'the author only');
  assert.equal(cell('authenticated', 'public.workspaces', 'UPDATE').decision, 'conditional', 'admins only: what B-MEMBER-ADMIN-WRITE tests');
  assert.equal(cell('authenticated', 'public.workspaces', 'DELETE').decision, 'deny');
  assert.equal(cell('anon', 'public.workspaces', 'UPDATE').decision, 'deny');
});

test('the guide names every file in the example folder, the commands its steps run, and a time budget', async () => {
  const guide = await read(GUIDE);
  const files = await filesUnder(EXAMPLE);
  assert.ok(files.includes('profile.json') && files.includes('authorization.json') && files.includes('.env.example') && files.includes('README.md'));
  for (const file of files) assert.ok(guide.includes(file), `the guide names ${file}`);
  for (const text of ['examples/supabase-next/', 'init --stack supabase', 'policy import rls', 'assess --config', 'supabase start', 'npm run dev', 'roe/cli.mjs seal', 'check-config']) assert.ok(guide.includes(text), `the guide shows ${text}`);
  for (const word of ['FAIL', 'INCONCLUSIVE', 'subject-writable-custody']) assert.ok(guide.includes(word), `the guide explains ${word}`);
  // A time budget per step, and the total named.
  assert.ok((guide.match(/\(\d+(?:\.\d+)? min[);,]/g) ?? []).length >= 6, 'each step carries its minutes, as "(N min)", "(N min, ...)" or "(N min; ...)"');
  assert.match(guide, /ten minutes|10 minutes/);
  assert.match(guide, /unmeasured|not measured/, 'the guide says which minutes were not measured');
});

test('the example and the guide carry no home paths, internal references or claims the product does not make', async () => {
  const texts = [['docs/guides/supabase-next-10-minutes.md', await read(GUIDE)]];
  for (const file of await filesUnder(EXAMPLE)) texts.push([`examples/supabase-next/${file}`, await read(new URL(file, EXAMPLE))]);
  for (const [name, text] of texts) {
    // The markers are assembled so this file carries none of them itself (as test/build-release.test.mjs does).
    for (const banned of [`/${'Users'}/`, `/${'home'}/`, `outputs/${'scopehaven'}`]) assert.equal(text.includes(banned), false, `${name} holds ${banned}`);
    assert.doesNotMatch(text, /vulnerab|fixed the app|found a vulnerability|detection edge/i, name);
  }
});
