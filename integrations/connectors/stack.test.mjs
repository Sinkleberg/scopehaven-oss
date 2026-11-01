// Focused tests for init --stack (integrations/init/stack.mjs): the pure wiring rules, and the whole command against init's
// owned two-tenant app in its PostgREST mode, over loopback only. No Postgres is needed: the runs here wire no observer, or
// stop before the starter run (--no-run), so the wired profile is checked by the product's own loader. The deciding runs
// on local Supabase copies are recorded in connectors/README.md.
// Run unsandboxed: the starter assessment binds loopback and spawns the workbench CLI.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, readdir, chmod, rm, mkdir, symlink } from 'node:fs/promises';
import { createServer } from 'node:net';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { randomBytes, createHash } from 'node:crypto';
import { join } from 'node:path';
import { validateTargetFile } from '../../src/contracts.mjs';
import { readConnector } from './spec.mjs';
import { runStack, splitArgs, recordTarget, backendClauses, writeTwin, parseTwinWrite, wireBackend, observerEntry, unloggedTableFindings, declarationFiles, pgNetUse, cronJobsOf, livePgNet, liveCheckGuard, plannedTwin, twinActions, PG_NET_USE_SQL, PG_CRON_USE_SQL, TWIN_ID } from '../init/stack.mjs';
import { createTwoTenantApp } from '../init/test/fixtures/two-tenant-app.mjs';

const ROE = ['--client', 'Synthetic test owner', '--contact', 'Test operator, Owner of the local copy'];
const RECORDS = ['--record-a', '/rest/v1/notes?id=eq.note-a1', '--record-b', '/rest/v1/notes?id=eq.note-b1'];
async function workspace() {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven stack test '));
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}
async function envFile(dir, name, pairs, mode = 0o600) {
  const path = join(dir, name);
  await writeFile(path, `${Object.entries(pairs).map(([k, v]) => `${k}=${v}`).join('\n')}\n`, { mode });
  await chmod(path, mode);
  return path;
}
async function run(argv, env = process.env, io = {}) {
  let text = '';
  const code = await runStack(argv, { stdout: { write: chunk => { text += chunk; } }, env, stdin: { isTTY: false }, ...io });
  return { code, text };
}
async function filesUnder(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await filesUnder(path)); else out.push(path);
  }
  return out;
}

test('splitArgs keeps init\'s flags in order and refuses a stack flag without a value or given twice', () => {
  assert.deepEqual(splitArgs(['--stack', 'supabase', '--yes', '--id', 'x', '--observer-port', '5']), { stack: { '--stack': 'supabase', '--observer-port': '5' }, init: ['--yes', '--id', 'x'] });
  assert.throws(() => splitArgs(['--stack']), /--stack needs a value/);
  assert.throws(() => splitArgs(['--stack', '--yes']), /--stack needs a value/);
  assert.throws(() => splitArgs(['--stack', 'a', '--stack', 'b']), /given twice/);
});

test('recordTarget: a PostgREST path names its table, key and id; an app route needs --record-table', async () => {
  const c = await readConnector('supabase');
  assert.deepEqual(recordTarget(c, '/rest/v1/notes?id=eq.note-a1'), { table: 'notes', key: 'id', id: 'note-a1', from: 'the record path (a connector record template)' });
  // A template path names its own table, key and id: an override would make the twin write another column.
  assert.throws(() => recordTarget(c, '/rest/v1/notes?id=eq.note-a1', { recordTable: 'public.notes:owner_id' }), /leave out --record-table and --record-id/);
  assert.throws(() => recordTarget(c, '/rest/v1/notes?id=eq.note-a1', { recordId: 'note-b1' }), /leave out --record-table and --record-id/);
  assert.equal(recordTarget(c, '/api/notes/note-a1'), null);
  assert.deepEqual(recordTarget(c, '/api/notes/note%2Da1', { recordTable: 'app.notes:note_id' }), { schema: 'app', table: 'notes', key: 'note_id', id: 'note-a1', from: '--record-table, with the id from the record path\'s last segment' });
  assert.equal(recordTarget(c, '/api/notes/x', { recordTable: 'notes', recordId: '42' }).id, '42');
  assert.throws(() => recordTarget(c, '/api/notes/x', { recordTable: 'notes;drop' }), /plain identifier/);
  // Extra parts are refused, never dropped: a.b.c would otherwise watch a.b.
  for (const recordTable of ['a.b.c', 'notes:id:x']) assert.throws(() => recordTarget(c, '/api/notes/x', { recordTable }), /plain identifier/);
  assert.throws(() => recordTarget(c, '/api/notes/x', { recordTable: 'notes', recordId: '' }), /--record-id/);
});

test('backendClauses follow the pairing rules: the row pin only with a twin, the table on a refusal check', async () => {
  const c = await readConnector('supabase');
  const record = { table: 'notes', key: 'id', id: 'note-a1' };
  const row = { kind: 'effect.none', select: { source: 'sql-wal', name: 'notes', resource: 'notes/note-a1' } };
  const table = { kind: 'effect.none', select: { source: 'sql-wal', name: 'notes' } };
  assert.deepEqual(backendClauses(c, record, { twin: true, refusal: false }), [row], '200 [] with a twin: the row, no unpinned clause the allowed-use guard would hold back');
  assert.deepEqual(backendClauses(c, record, { twin: true, refusal: true }), [row, table]);
  assert.deepEqual(backendClauses(c, record, { twin: false, refusal: true }), [table], 'a refusal check judges the table and needs no twin');
  assert.deepEqual(backendClauses(c, record, { twin: false, refusal: false }), [table]);
  // Every clause names the table: an absence needs an exact name from the observer's vocabulary.
  for (const clauses of [backendClauses(c, record, { twin: true, refusal: true })]) assert.ok(clauses.every(e => e.select.name === 'notes'));
});

test('writeTwin: a no-op PATCH of the key on a PostgREST record, an operator-given write on an app route, none without an owner', async () => {
  const c = await readConnector('supabase');
  const record = { table: 'notes', key: 'id', id: 'note-a1' };
  const backend = { path: '/rest/v1/notes?id=eq.note-a1' };
  const twin = writeTwin(c, { record, backend, owner: 'a' });
  assert.equal(twin.id, TWIN_ID);
  assert.deepEqual([twin.method, twin.path, twin.body, twin.severity, twin.actorId], ['PATCH', backend.path, { id: 'note-a1' }, 'control', 'a']);
  assert.deepEqual(twin.assertions, [{ kind: 'status.equals', expected: 204 }]);
  assert.deepEqual(twin.effects, [{ kind: 'effect.exists', select: { source: 'sql-wal', name: 'notes', resource: 'notes/note-a1' } }]);
  assert.equal(writeTwin(c, { record, backend, owner: null }), null);
  assert.equal(writeTwin(c, { record, backend: { path: '/api/notes/note-a1' }, owner: 'a' }), null);
  const given = writeTwin(c, { record, backend: { path: '/api/notes/note-a1' }, owner: 'a', write: parseTwinWrite('PATCH:/api/notes/note-a1:200:{"title":"Ada synthetic note"}') });
  assert.deepEqual([given.method, given.path, given.body, given.assertions[0].expected], ['PATCH', '/api/notes/note-a1', { title: 'Ada synthetic note' }, 200]);
  assert.throws(() => parseTwinWrite('GET:/x:200:{}'), /METHOD:PATH:STATUS:JSON/);
  assert.throws(() => parseTwinWrite('PATCH:/x:404:{}'), /2xx/);
  assert.throws(() => parseTwinWrite('PATCH:/x:200:{nope}'), /not JSON/);
  assert.throws(() => parseTwinWrite('PATCH:/api/../admin:200:{}'), /absolute path on the app/);
  assert.throws(() => parseTwinWrite('PATCH:/api/notes/1?x#y:200:{}'), /absolute path on the app/);
  assert.match(parseTwinWrite('PATCH:/api/notes/1:200:{"title":"t"}').bodySha256, /^[0-9a-f]{64}$/);
  // A template twin that would write another record than the path names is refused.
  assert.throws(() => writeTwin(c, { record: { table: 'notes', key: 'owner_id', id: 'x' }, backend, owner: 'a' }), /differs from the one the record path names/);
});

test('unloggedTableFindings never ignores pg_net\'s queue: it reports what the migrations and the live catalog say, as the reason windows stay partial', async () => {
  const c = await readConnector('supabase');
  const wal = c.observers.find(o => o.type === 'pg-wal');
  // A scan as declarationFiles returns it: the files, what it left unread, and the paths it read.
  const scanned = (list, extra = {}) => Object.assign(list, { skipped: 0, readRoots: new Set(['supabase/migrations']), ...extra });
  const clean = scanned([{ id: '1.sql', content: Buffer.from('create table notes (id text primary key);') }]);
  const unused = { pg_net: pgNetUse(['1', '0', '0', '0', '0', '1']) };
  const [found] = unloggedTableFindings(wal, clean, unused, { checkedAt: new Date('2026-10-27T01:02:03.000Z') });
  // Every check says unused, and the queue is still watched: the finding is the reason, never an ignore entry.
  assert.deepEqual([found.entry, found.use], ['net.http_request_queue', 'unused']);
  assert.match(found.why, /^pg_net installed but unused per the migrations and the catalog, so the queue is left watched and windows read partial \(table-not-in-wal\) until its requests are observed on the wire/);
  assert.equal(Object.hasOwn(found, 'ignore'), false);
  assert.deepEqual([found.files.checked, found.files.skipped, found.live.used, found.checkedAt], [1, 0, false, '2026-10-27T01:02:03.000Z']);
  assert.match(found.files.scanDigest, /^[0-9a-f]{64}$/);
  // No live check ran: no check time is stamped.
  assert.equal(unloggedTableFindings(wal, clean, {}, { checkedAt: new Date('2026-10-27T01:02:03.000Z') })[0].checkedAt, null);
  const why = (files, live = unused) => unloggedTableFindings(wal, files, live)[0];
  // What keeps the finding at unknown: an unread migrations folder, a scan that skipped anything, no declarations, no live check.
  assert.deepEqual([why(scanned([...clean], { readRoots: new Set(['supabase/seed.sql']) })).use, why(scanned([...clean], { readRoots: new Set(['supabase/seed.sql']) })).why.split(',')[0]], ['unknown', 'supabase/migrations was not read in --app-dir']);
  assert.match(why(scanned([...clean], { skipped: 1 })).why, /left 1 entry unread/);
  assert.equal(why(scanned([...clean], { skipped: 1 })).use, 'unknown');
  assert.match(why(scanned([])).why, /no --app-dir/);
  assert.match(why(clean, {}).why, /its live check did not run/);
  // Every spelling a migration may use names it, and makes the finding "used".
  for (const sql of ["select net.http_post('http://127.0.0.1:9/x');", 'SELECT NET.HTTP_POST(1);', 'select "net"."http_post"(1);', 'select net . http_get(1);', 'create extension PG_NET;', 'perform supabase_functions.HTTP_REQUEST();', 'set search_path = net; select http_post (1);']) {
    const found2 = why(scanned([...clean, { id: 'sub/2.sql', content: Buffer.from(sql) }]));
    assert.deepEqual([found2.use, found2.files.named], ['used', ['sub/2.sql']], sql);
    assert.match(found2.why, /named in sub\/2\.sql, so the queue is left watched/);
  }
  // The live check's own results, each reported as it reads.
  for (const [row, use, said] of [[['1', '2', '0', '0', '0', '1'], 'used', /2 functions and 0 triggers that call pg_net/], [['1', '0', '1', '0', '0', '1'], 'used', /0 functions and 1 trigger that call pg_net/], [['1', '0', '0', '1', '0', '1'], 'unknown', /pg_cron is installed/], [['1', '0', '0', '0', '3', '1'], 'used', /3 other objects .* depend on a pg_net function/], [['1', '0', '0', '0'], 'unknown', /could not be read/], [null, 'unknown', /could not be read/]]) {
    const found3 = why(clean, { pg_net: pgNetUse(row) });
    assert.equal(found3.use, use, String(row));
    assert.match(found3.why, said);
  }
  // With no pg_net, the live check reads unknown (an install later would bring an unlogged queue back).
  assert.equal(pgNetUse(['0', '0', '0', '0', '0', '0']).used, null);
  assert.match(pgNetUse(['0', '0', '0', '0', '0', '0']).why, /pg_net is not installed/);
  // A queue that is not pg_net's unlogged table reads unknown too.
  assert.equal(pgNetUse(['1', '0', '0', '0', '0', '0']).used, null);
  assert.match(pgNetUse(['1', '0', '0', '0', '0', '0']).why, /not an unlogged table/);
  assert.match(PG_NET_USE_SQL, /relpersistence = 'u'/);
  // pg_cron's count is read with whether the role sees every row: row security off, or a superuser or BYPASSRLS role.
  assert.match(PG_CRON_USE_SQL, /not c\.relrowsecurity or r\.rolsuper or r\.rolbypassrls/);
  assert.match(PG_CRON_USE_SQL, /r\.rolname = current_user/);
  // pg_cron's jobs, when the observer role may read them: none calling pg_net clears it, one keeps the queue.
  assert.equal(pgNetUse(['1', '0', '0', '1', '0', '1'], 0).used, false);
  assert.match(pgNetUse(['1', '0', '0', '1', '0', '1'], 2).why, /2 pg_cron jobs that call pg_net/);
  assert.match(pgNetUse(['1', '0', '0', '1', '0', '1'], null).why, /grant it SELECT on cron\.job/);
  // cron.job has row-level security (each role sees its own jobs): a count is used only when the role saw every row.
  assert.equal(cronJobsOf(['0', 'f']), null, 'a filtered view of cron.job reads as unread, never as no jobs');
  assert.equal(cronJobsOf(['0', false]), null);
  assert.equal(cronJobsOf(['0', null]), null);
  assert.equal(cronJobsOf(['0', 't']), 0);
  assert.equal(cronJobsOf(['2', true]), 2);
  assert.equal(pgNetUse(['1', '0', '0', '1', '0', '1'], cronJobsOf(['0', 'f'])).used, null);
  assert.match(pgNetUse(['1', '0', '0', '1', '0', '1'], cronJobsOf(['0', 'f'])).why, /BYPASSRLS/);
  // The query reads function bodies, unqualified calls and pg_depend (a BEGIN ATOMIC body keeps its calls there).
  assert.match(PG_NET_USE_SQL, /pg_depend/);
  assert.match(PG_NET_USE_SQL, /\\mhttp_\(post\|get/);
  assert.match(PG_NET_USE_SQL, /grant_pg_net_access/);
  // The live query reads catalogs only and matches pg_net calls in any case, quoting or spacing.
  assert.doesNotMatch(PG_NET_USE_SQL, /\bfrom (?!pg_)[a-z_]+\./i);
  assert.match(PG_NET_USE_SQL, /~\*/);
});

test('plannedTwin and twinActions: the sealed actions name the exact write the run sends', async () => {
  const c = await readConnector('supabase');
  const path = '/rest/v1/notes?id=eq.note-a1';
  const planned = plannedTwin(c, { backendPath: path, twoIdentities: true });
  assert.deepEqual(planned, { method: 'PATCH', path, viaTemplate: true });
  const twin = writeTwin(c, { record: recordTarget(c, path), backend: { path }, owner: 'a' });
  assert.deepEqual([twin.method, twin.path], [planned.method, planned.path]);
  assert.match(twinActions(planned), /^read-only GET requests from the drafted profile, plus one allowed-use write: identity A's PATCH \/rest\/v1\/notes\?id=eq\.note-a1 of its own record/);
  assert.doesNotMatch(twinActions(planned), /; no writes$/);
  // The template twin is not called value-free: the table's UPDATE triggers run on it (an updated_at stamp, for example).
  assert.match(twinActions(planned), /the table's UPDATE triggers still run/);
  assert.doesNotMatch(twinActions(planned), /no value changes/);
  assert.equal(plannedTwin(c, { backendPath: path, twoIdentities: false }), null);
  assert.equal(plannedTwin(c, { backendPath: path, twoIdentities: true, noTwin: true }), null);
  assert.equal(plannedTwin(c, { backendPath: '/api/notes/note-a1', twoIdentities: true }), null);
  const given = parseTwinWrite('PATCH:/api/notes/note-a1:200:{"title":"t"}');
  const plannedGiven = plannedTwin(c, { backendPath: '/api/notes/note-a1', twoIdentities: true, write: given });
  assert.deepEqual(plannedGiven, { method: 'PATCH', path: '/api/notes/note-a1', viaTemplate: false, bodySha256: given.bodySha256 });
  assert.match(twinActions(plannedGiven), new RegExp(`the --twin-write body with sha256 ${given.bodySha256.slice(0, 16)}`), 'the sealed actions bind the body');
});

test('wireBackend: the wired profile validates, the twin is sent before every boundary check, and a bad wiring is refused', async () => {
  const c = await readConnector('supabase');
  const app = await createTwoTenantApp({ postgrest: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, 'ids.env', { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const { code, text } = await run(['--stack', 'supabase', '--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', ...RECORDS, ...ROE, '--confirm-authorization', '--out', join(dir, 'out'), '--no-run']);
    assert.equal(code, 0, text);
    const manifest = JSON.parse(await readFile(join(dir, 'out', 'targets.json'), 'utf8'));
    const record = recordTarget(c, '/rest/v1/notes?id=eq.note-a1');
    const backend = manifest.targets[0].checks.find(x => x.evidenceRequirement === 'backend');
    const twin = writeTwin(c, { record, backend, owner: 'a' });
    const observer = observerEntry(c, { targetId: 'notes', record, port: 55432 });
    assert.deepEqual(observer, { id: 'wal', type: 'pg-wal', host: '127.0.0.1', port: 55432, database: 'postgres', platform: 'supabase', settleMs: 500, barrierMs: 2000, credentialEnv: 'SCOPEHAVEN_TARGET_NOTES_DB_WAL', tables: [{ table: 'notes', key: 'id' }] });
    const { manifest: wired, wired: summary } = wireBackend(manifest, c, { record, observerConfig: observer, twin });
    assert.doesNotThrow(() => validateTargetFile(wired));
    assert.deepEqual(summary, { check: 'B-READS-A-RECORD-BACKEND', observer: 'wal', type: 'pg-wal', clauses: 1, twin: TWIN_ID });
    const ids = wired.targets[0].checks.map(x => x.id);
    const at = ids.indexOf(TWIN_ID);
    assert.ok(wired.targets[0].checks.slice(at + 1).every(x => x.severity !== 'control'), 'the twin follows every other control and precedes every boundary check');
    assert.ok(wired.targets[0].checks.slice(0, at).every(x => x.severity === 'control'));
    assert.equal(manifest.targets[0].observers, undefined, 'wireBackend does not change its input');
    // A wiring the loader refuses leaves targets.json alone (here: an observer with a remote host).
    assert.throws(() => wireBackend(manifest, c, { record, observerConfig: { ...observer, host: '10.0.0.1' }, twin }), /does not validate/);
    assert.throws(() => wireBackend({ ...manifest, targets: [{ ...manifest.targets[0], checks: manifest.targets[0].checks.filter(x => x.evidenceRequirement !== 'backend') }] }, c, { record, observerConfig: observer, twin }), /no backend check/);
  } finally { await app.close(); await cleanup(); }
});

test('init --stack supabase without an observer env: init runs, the backend row stays inconclusive, and the stack report says why', async () => {
  const app = await createTwoTenantApp({ postgrest: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, 'ids.env', { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const out = join(dir, 'out');
    const { code, text } = await run(['--stack', 'supabase', '--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', ...RECORDS, ...ROE, '--confirm-authorization', '--out', out]);
    assert.equal(code, 0, text);
    assert.match(text, /No --observer-env: the backend row is not wired \(pg-wal needs SCOPEHAVEN_TARGET_NOTES_DB_WAL\)/);
    assert.match(text, /Stopped after writing \(--no-run\)\./, 'init itself stops after writing; the stack runs the starter assessment');
    assert.match(text, /Backend row B-READS-A-RECORD-BACKEND: INCONCLUSIVE/);
    assert.match(text, /Gateway header apikey: declared, not sent/);
    const report = JSON.parse(await readFile(join(out, 'stack-report.json'), 'utf8'));
    assert.equal(report.schema, 'scopehaven-init-stack/1');
    assert.equal(report.connector.stack, 'supabase');
    assert.match(report.connector.sha256, /^[0-9a-f]{64}$/);
    assert.deepEqual(report.wired, []);
    assert.deepEqual(report.notWired.map(n => n.what), ['backend row', 'supabaseRules']);
    assert.equal(report.notWired[0].why, 'no --observer-env (needs SCOPEHAVEN_TARGET_NOTES_DB_WAL)');
    assert.deepEqual(report.refusals['B-READS-A-RECORD'], { judged: 'empty-list', declaredByStack: true });
    assert.deepEqual(report.gatewayHeaders.map(g => [g.header, g.env, g.sent]), [['apikey', 'SCOPEHAVEN_TARGET_NOTES_APIKEY', false]]);
    const record = JSON.parse(await readFile(join(out, 'authorization.json'), 'utf8'));
    assert.deepEqual(record.origins, [app.origin], 'no observer, so no observer endpoint is authorized');
    // The starter run sends its checks under the sealed record (src/cli.mjs --authorization: every request and observer call
    // window-checked): the saved run carries that record's stamp.
    const runs = (await readdir(join(out, 'evidence', 'runs'))).filter(f => f.endsWith('.json'));
    assert.equal(runs.length, 1);
    const saved = JSON.parse(await readFile(join(out, 'evidence', 'runs', runs[0]), 'utf8')).core;
    assert.deepEqual([saved.authorization?.id, saved.authorization?.sha256], [record.id, record.sha256], 'the starter run ran under the sealed record');
    // The onboarding clock (clocks.mjs) reads every stamp line, the stack's starter run among them.
    const { readStamps } = await import('../init/clocks.mjs');
    const stamps = await readStamps(out);
    assert.ok(stamps.some(st => st.stage === 'run-saved'), 'the stack\'s starter run is on the onboarding clock');
  } finally { await app.close(); await cleanup(); }
});

test('init --stack supabase with an observer env: the record covers the observer, the profile is wired, the credential never reaches disk', async () => {
  const app = await createTwoTenantApp({ postgrest: true });
  const { dir, cleanup } = await workspace();
  try {
    const marker = `wal-secret-${randomBytes(12).toString('hex')}`;
    const env = await envFile(dir, 'ids.env', { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const observers = await envFile(dir, 'observers.env', { SCOPEHAVEN_TARGET_NOTES_DB_WAL: `scopehaven_wal:${marker}` });
    const appDir = join(dir, 'app');
    await mkdir(join(appDir, 'supabase', 'migrations'), { recursive: true });
    await writeFile(join(appDir, 'supabase', 'migrations', '0001_notes.sql'), 'create table public.notes (id text primary key, owner uuid not null, title text);\nalter table public.notes enable row level security;\ncreate policy "own notes" on public.notes for select to authenticated using (owner = auth.uid());\n');
    const out = join(dir, 'out');
    // The live check's connection is refused (injected, so a Postgres listening on the port cannot change the result).
    const refused = async () => { throw Object.assign(new Error('connect refused'), { code: 'ECONNREFUSED' }); };
    let text = '';
    const code = await runStack(['--stack', 'supabase', '--observer-env', observers, '--observer-port', '55432', '--app-dir', appDir, '--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', ...RECORDS, ...ROE, '--confirm-authorization', '--out', out, '--no-run'],
      { stdout: { write: chunk => { text += chunk; } }, env: process.env, stdin: { isTTY: false }, liveConnect: refused });
    assert.equal(code, 0, text);
    assert.match(text, /Observer: pg-wal on tcp:\/\/127\.0\.0\.1:55432/);
    // The connection is refused, so the live pg_net check fails and the queue is kept: windows would read partial.
    assert.match(text, /net\.http_request_queue: the live check failed \([^)]*\), so the queue is left watched/);
    assert.match(text, /A-WRITES-OWN-RECORD: the allowed-use twin, sent first: PATCH \/rest\/v1\/notes\?id=eq\.note-a1, expecting 204/);
    assert.match(text, /Policy: rls matrix from 1 file, unconfirmed in policy-matrix\.json/);
    const record = JSON.parse(await readFile(join(out, 'authorization.json'), 'utf8'));
    assert.deepEqual(record.origins, [app.origin, 'tcp://127.0.0.1:55432'], 'the observer endpoint joined the record before it was sealed');
    // The record binds the rules file, and the rules file names the one write the run sends.
    const roe = await readFile(join(out, 'rules-of-engagement.md'), 'utf8');
    assert.equal(record.rulesOfEngagement.sha256, createHash('sha256').update(roe).digest('hex'));
    assert.match(roe, /- Permitted actions: read-only GET requests from the drafted profile, plus one allowed-use write: identity A's PATCH \/rest\/v1\/notes\?id=eq\.note-a1 of its own record/);
    assert.doesNotMatch(roe, /; no writes\n/);
    const target = JSON.parse(await readFile(join(out, 'targets.json'), 'utf8')).targets[0];
    assert.equal(target.observers[0].credentialEnv, 'SCOPEHAVEN_TARGET_NOTES_DB_WAL');
    assert.deepEqual(target.checks.find(x => x.id === 'B-READS-A-RECORD-BACKEND').effects, [{ kind: 'effect.none', select: { source: 'sql-wal', name: 'notes', resource: 'notes/note-a1' } }]);
    const report = JSON.parse(await readFile(join(out, 'stack-report.json'), 'utf8'));
    assert.equal(report.wired[0].twin, TWIN_ID);
    // What the wiring takes as given: the connector's timings and the template twin's key. The live check failed here, so
    // nothing is assumed about the functions it would not count, and no check time is stamped on a result it did not read.
    assert.deepEqual(report.assumptions.map(a => [a.what, a.value]), [['observer timings', { settleMs: 500, barrierMs: 2000 }], ['the write twin selects one row', 'notes.id']]);
    assert.equal(report.policy.skipped, 0);
    assert.deepEqual(report.watched.map(w => [w.entry, w.use, w.checkedAt]), [['net.http_request_queue', 'unknown', null]]);
    assert.equal(target.observers[0].ignore, undefined, 'no ignore entry from inference');
    assert.equal(report.policy.confirmed, false);
    const rules = JSON.parse(await readFile(join(out, 'stack-rules.draft.json'), 'utf8'));
    assert.deepEqual(rules.actorCapture.block.tables, [{ table: 'notes', key: 'id' }]);
    assert.deepEqual(Object.values(rules.actorCapture.block.principals), ['identity-a', 'identity-b']);
    assert.deepEqual(rules.supabaseRules.serviceRoles, ['service_role', 'postgres', 'supabase_admin']);
    assert.ok(report.notWired.some(n => n.what === 'supabaseRules'));
    const matrix = JSON.parse(await readFile(join(out, 'policy-matrix.json'), 'utf8'));
    assert.equal(matrix.schema, 'scopehaven-policy-matrix/2');
    // Neither the observer's credential nor an identity's token is written anywhere.
    for (const file of await filesUnder(dir)) {
      if (file === observers || file === env) continue;
      const body = await readFile(file, 'utf8');
      for (const secret of [marker, app.tokenA, app.tokenB]) assert.ok(!body.includes(secret), `${file} holds a credential value`);
    }
  } finally { await app.close(); await cleanup(); }
});

test('init --stack refuses before any request: an unknown stack, a non-http connector, an observer env holding other keys, a missing --env', async () => {
  const app = await createTwoTenantApp({ postgrest: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, 'ids.env', { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const base = ['--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', ...RECORDS, ...ROE, '--confirm-authorization', '--out', join(dir, 'out')];
    let r = await run(['--stack', 'firebase', ...base]);
    assert.equal(r.code, 2); assert.match(r.text, /"firebase" is not a shipped connector \(shipped: chat-completions, stripe, supabase\)/);
    r = await run(['--stack', 'stripe', ...base]);
    assert.equal(r.code, 2); assert.match(r.text, /is a payments connector/);
    const mixed = await envFile(dir, 'mixed.env', { SCOPEHAVEN_TARGET_NOTES_DB_WAL: 'u:p', SCOPEHAVEN_TARGET_NOTES_A: app.tokenA });
    r = await run(['--stack', 'supabase', '--observer-env', mixed, ...base]);
    assert.equal(r.code, 2); assert.match(r.text, /holds only SCOPEHAVEN_TARGET_NOTES_DB_WAL/);
    r = await run(['--stack', 'supabase', ...base.filter((v, i, a) => v !== '--env' && a[i - 1] !== '--env')]);
    assert.equal(r.code, 2); assert.match(r.text, /give --env FILE as a flag/);
    // The id names the folder init writes, which --stack reads after init: it is a flag, never a prompt answer.
    r = await run(['--stack', 'supabase', ...base.filter((v, i, a) => v !== '--id' && a[i - 1] !== '--id')]);
    assert.equal(r.code, 2); assert.match(r.text, /with --stack, give --id as a flag/);
    assert.equal(app.requests(), 0, 'nothing reached the app');
  } finally { await app.close(); await cleanup(); }
});

test('init --stack supabase on a leaky PostgREST app: the starter run decides FAIL and exits 1', async () => {
  const app = await createTwoTenantApp({ postgrest: true, leaky: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, 'ids.env', { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const { code, text } = await run(['--stack', 'supabase', '--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', ...RECORDS, ...ROE, '--confirm-authorization', '--out', join(dir, 'out')]);
    assert.equal(code, 1, text);
    assert.match(text, /First decided row: FAIL {2}B-READS-A-RECORD/);
    assert.match(text, /Exit 1: the starter run has \d FAIL rows?/);
  } finally { await app.close(); await cleanup(); }
});

test('init --stack: the write twin and --actions, --no-twin, an unwired record and the flags an observer needs', async () => {
  const app = await createTwoTenantApp({ postgrest: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, 'ids.env', { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const observers = await envFile(dir, 'observers.env', { SCOPEHAVEN_TARGET_NOTES_DB_WAL: 'scopehaven_wal:synthetic' });
    const base = id => ['--stack', 'supabase', '--observer-env', observers, '--observer-port', '55432', '--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', ...ROE, '--confirm-authorization', '--out', join(dir, id), '--no-run'];
    // An operator's own actions text cannot cover the twin it does not name.
    let r = await run([...base('a'), ...RECORDS, '--actions', 'read-only GET requests']);
    assert.equal(r.code, 2); assert.match(r.text, /names it in the authorization's actions itself; leave --actions out, or give --no-twin/);
    // --no-twin keeps init's read-only actions and wires no write.
    r = await run([...base('b'), ...RECORDS, '--no-twin']);
    assert.equal(r.code, 0, r.text);
    assert.match(await readFile(join(dir, 'b', 'rules-of-engagement.md'), 'utf8'), /- Permitted actions: read-only GET requests from the drafted profile; no writes/);
    const checks = JSON.parse(await readFile(join(dir, 'b', 'targets.json'), 'utf8')).targets[0].checks;
    assert.ok(checks.every(c => c.method === 'GET'), 'no write check without its named action');
    // The PostgREST backend check expects 200 [], not a refusal: without a twin its table clause reads inconclusive.
    assert.match(r.text, /No write twin: the check expects a 2xx answer, so it judges the whole table, and the allowed-use guard holds that clause back/);
    assert.doesNotMatch(r.text, /the check expects a refusal/);
    // An app route without --record-table: no observer is wired, so its endpoint is not authorized.
    r = await run([...base('c'), '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1']);
    assert.equal(r.code, 0, r.text);
    assert.match(r.text, /is not one of the connector's record templates and no --record-table was given, so no observer is wired or authorized/);
    assert.deepEqual(JSON.parse(await readFile(join(dir, 'c', 'authorization.json'), 'utf8')).origins, [app.origin]);
    // An app route with --record-table and --twin-write: the sealed actions bind the twin's body by its sha256, and the twin
    // sent is that body.
    const write = 'PATCH:/api/notes/note-a1:200:{"title":"same title"}';
    r = await run([...base('e'), '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', '--record-table', 'notes', '--twin-write', write]);
    assert.equal(r.code, 0, r.text);
    const sha = createHash('sha256').update(JSON.stringify({ title: 'same title' })).digest('hex');
    const roeE = await readFile(join(dir, 'e', 'rules-of-engagement.md'), 'utf8');
    assert.match(roeE, new RegExp(`plus one allowed-use write: identity A's PATCH /api/notes/note-a1 of its own record \\(the --twin-write body with sha256 ${sha.slice(0, 16)}\\); no other writes`));
    const record = JSON.parse(await readFile(join(dir, 'e', 'authorization.json'), 'utf8'));
    assert.equal(record.rulesOfEngagement.sha256, createHash('sha256').update(roeE).digest('hex'), 'the sealed record binds that rules file');
    const twinE = JSON.parse(await readFile(join(dir, 'e', 'targets.json'), 'utf8')).targets[0].checks.find(c => c.id === TWIN_ID);
    assert.deepEqual([twinE.method, twinE.path, twinE.body], ['PATCH', '/api/notes/note-a1', { title: 'same title' }]);
    // --record-table without :KEY or --record-id: the key and id it takes as given are reported.
    const reportE = JSON.parse(await readFile(join(dir, 'e', 'stack-report.json'), 'utf8'));
    assert.deepEqual(reportE.assumptions.filter(a => a.what.startsWith('the record ')).map(a => [a.what, a.value]), [['the record key column', 'id'], ['the record id', 'note-a1']]);
    // A --twin-write that is not sent is said, never dropped silently.
    r = await run([...base('f'), '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', '--twin-write', write]);
    assert.equal(r.code, 0, r.text);
    assert.match(r.text, /--twin-write not sent: no observer is wired/);
    assert.ok(JSON.parse(await readFile(join(dir, 'f', 'stack-report.json'), 'utf8')).notWired.some(n => n.what === '--twin-write'));
    r = await run([...base('i'), ...RECORDS, '--no-twin', '--twin-write', write]);
    assert.equal(r.code, 0, r.text);
    assert.match(r.text, /--twin-write not sent: --no-twin was given/);
    // One identity: the record has no declared owner, so no twin is planned and the given write is not sent.
    const envOne = await envFile(dir, 'one.env', { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA });
    r = await run(['--stack', 'supabase', '--observer-env', observers, '--observer-port', '55432', '--yes', '--base-url', app.origin, '--env', envOne, '--id', 'notes', ...ROE, '--confirm-authorization', '--out', join(dir, 'j'), '--no-run', ...RECORDS, '--twin-write', write]);
    assert.equal(r.code, 0, r.text);
    assert.match(r.text, /--twin-write not sent: one identity: the record has no declared owner/);
    // A partial scan is said in the policy section: a named pipe beside a migration is left unread.
    const refused = { liveConnect: async () => { throw Object.assign(new Error('connect refused'), { code: 'ECONNREFUSED' }); } };
    const partial = join(dir, 'partial-app');
    await mkdir(join(partial, 'supabase', 'migrations'), { recursive: true });
    await writeFile(join(partial, 'supabase', 'migrations', '0001_notes.sql'), 'create table public.notes (id text primary key);\n');
    execFileSync('mkfifo', [join(partial, 'supabase', 'migrations', '0002.sql')]);
    r = await run([...base('g'), ...RECORDS, '--app-dir', partial], process.env, refused);
    assert.equal(r.code, 0, r.text);
    assert.match(r.text, /Policy: rls matrix from 1 file \(1 entry left unread, so the matrix may be partial\)/);
    assert.equal(JSON.parse(await readFile(join(dir, 'g', 'stack-report.json'), 'utf8')).policy.skipped, 1);
    // A scan that read nothing because it refused a linked folder says so, rather than "no .sql files".
    const linked = join(dir, 'linked-app');
    await mkdir(linked, { recursive: true }); await symlink(join(partial, 'supabase'), join(linked, 'supabase'));
    r = await run([...base('h'), ...RECORDS, '--app-dir', linked], process.env, refused);
    assert.equal(r.code, 0, r.text);
    assert.match(r.text, /Policy: not imported \(no \.sql file was read under supabase\/migrations in --app-dir: the scan left 1 entry unread/);
    assert.ok(JSON.parse(await readFile(join(dir, 'h', 'stack-report.json'), 'utf8')).policy.skipped > 0);
    // With --observer-env the answers the observer depends on are flags.
    r = await run(base('d'));
    assert.equal(r.code, 2); assert.match(r.text, /with --observer-env, give --record-a, --record-b as flags/);
  } finally { await app.close(); await cleanup(); }
});

test('init --stack --help is init\'s help and writes nothing', async () => {
  const { dir, cleanup } = await workspace();
  try {
    const r = await run(['--stack', 'supabase', '--help', '--out', join(dir, 'out')]);
    assert.equal(r.code, 0);
    assert.match(r.text, /scopehaven init \(v0\)/);
    await assert.rejects(readdir(join(dir, 'out')), /ENOENT/);
  } finally { await cleanup(); }
});

test('init --stack with the starter run and an observer it cannot reach: the run is saved and decides nothing from it, and no credential reaches disk or the output', async () => {
  const app = await createTwoTenantApp({ postgrest: true });
  const { dir, cleanup } = await workspace();
  try {
    const marker = `wal-secret-${randomBytes(12).toString('hex')}`;
    const env = await envFile(dir, 'ids.env', { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const observers = await envFile(dir, 'observers.env', { SCOPEHAVEN_TARGET_NOTES_DB_WAL: `scopehaven_wal:${marker}` });
    const out = join(dir, 'out');
    // No Postgres listens on the observer's port, so every observer window fails to collect.
    const { code, text } = await run(['--stack', 'supabase', '--observer-env', observers, '--observer-port', '1', '--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', ...RECORDS, ...ROE, '--confirm-authorization', '--out', out]);
    // The fixture answers the twin's PATCH 200 (not PostgREST's 204) and the observer saw nothing, so the twin fails: a FAIL
    // row, exit 1, and the backend row stays inconclusive (never decided from an observer that collected nothing).
    assert.equal(code, 1, text);
    assert.match(text, /First decided row: FAIL {2}A-WRITES-OWN-RECORD/);
    assert.match(text, /Backend row B-READS-A-RECORD-BACKEND: INCONCLUSIVE \(backend evidence unavailable\)/);
    for (const file of await filesUnder(dir)) {
      if (file === observers || file === env) continue;
      const body = await readFile(file, 'utf8');
      for (const secret of [marker, app.tokenA, app.tokenB]) assert.ok(!body.includes(secret), `${file} holds a credential value`);
    }
    assert.ok(!text.includes(marker) && !text.includes(app.tokenA), 'the output holds no credential value');
  } finally { await app.close(); await cleanup(); }
});

test('init --stack: the live pg_net check runs only under the sealed record: the endpoint and the window are checked before the database is reached', async () => {
  const app = await createTwoTenantApp({ postgrest: true });
  const { dir, cleanup } = await workspace();
  const connections = [];
  const db = createServer(socket => { connections.push(Date.now()); socket.destroy(); });
  await new Promise(done => db.listen(0, '127.0.0.1', done));
  try {
    const env = await envFile(dir, 'ids.env', { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const observers = await envFile(dir, 'observers.env', { SCOPEHAVEN_TARGET_NOTES_DB_WAL: 'scopehaven_wal:synthetic' });
    const appDir = join(dir, 'app');
    await mkdir(join(appDir, 'supabase', 'migrations'), { recursive: true });
    await writeFile(join(appDir, 'supabase', 'migrations', '0001_notes.sql'), 'create table public.notes (id text primary key);\n');
    const out = join(dir, 'out'), port = db.address().port;
    const { code, text } = await run(['--stack', 'supabase', '--observer-env', observers, '--observer-port', String(port), '--app-dir', appDir, '--yes', '--base-url', app.origin,
      '--env', env, '--id', 'notes', ...RECORDS, ...ROE, '--confirm-authorization', '--out', out, '--no-run']);
    assert.equal(code, 0, text);
    assert.equal(connections.length, 1, 'inside the window, the live check reached the observer port once');
    const record = JSON.parse(await readFile(join(out, 'authorization.json'), 'utf8'));
    const target = JSON.parse(await readFile(join(out, 'targets.json'), 'utf8')).targets[0];
    const observer = target.observers.find(o => o.type === 'pg-wal');
    // After the window, the guard refuses before anything is sent, and the check it hands the live query refuses too.
    const after = () => new Date(Date.parse(record.validUntil) + 1);
    await assert.rejects(liveCheckGuard(join(out, 'authorization.json'), target, observer, { now: after }), err => err.name === 'AuthorizationError' && err.code === 'authorization-window');
    const ended = () => { throw Object.assign(new Error('window ended'), { name: 'AuthorizationError', code: 'authorization-window-ended' }); };
    await assert.rejects(livePgNet(observer, 'scopehaven_wal:synthetic', ended), err => err.code === 'authorization-window-ended');
    assert.equal(connections.length, 1, 'a window that has ended reaches no database');
    // The window is checked again before each query: one that ends after the connection sends no query.
    const queries = [];
    let calls = 0;
    const fakeDb = { query: async sql => { queries.push(sql); return [{ rows: [['1', '0', '0', '0', '0', '1']] }]; }, close: async () => {} };
    await assert.rejects(livePgNet(observer, 'scopehaven_wal:synthetic', () => { if (++calls > 1) ended(); }, { connect: async () => fakeDb }), err => err.code === 'authorization-window-ended');
    assert.deepEqual([calls, queries.length], [2, 0], 'checked before the connection and again before the query, which was never sent');
    // And before the pg_cron query: a window that ends after the catalog query sends no cron query.
    queries.length = 0; calls = 0;
    const cronDb = { query: async sql => { queries.push(sql); return [{ rows: [['1', '0', '0', '1', '0', '1']] }]; }, close: async () => {} };
    await assert.rejects(livePgNet(observer, 'scopehaven_wal:synthetic', () => { if (++calls > 2) ended(); }, { connect: async () => cronDb }), err => err.code === 'authorization-window-ended');
    assert.deepEqual([calls, queries.length], [3, 1], 'the cron query is never sent after the window ends');
    // End to end: a record whose window has ended by the live check stops the stack with exit 3, and no database is reached.
    let lateText = '';
    const lateCode = await runStack(['--stack', 'supabase', '--observer-env', observers, '--observer-port', String(port), '--app-dir', appDir, '--yes', '--base-url', app.origin,
      '--env', env, '--id', 'notes', ...RECORDS, ...ROE, '--confirm-authorization', '--out', join(dir, 'late2'), '--no-run'],
      { stdout: { write: chunk => { lateText += chunk; } }, env: process.env, stdin: { isTTY: false }, liveCheckNow: () => new Date(Date.now() + 400 * 24 * 3600000) });
    assert.equal(lateCode, 3, lateText);
    assert.match(lateText, /the sealed record does not cover the live pg_net check \(authorization-window\); nothing was sent to the database/);
    assert.equal(connections.length, 1, 'the late run reached no database');
    // The guard's own check reads the window again on each call: inside the window it passes, past validUntil it throws.
    let at = Date.parse(record.validUntil) - 60000;
    const moving = await liveCheckGuard(join(out, 'authorization.json'), target, observer, { now: () => new Date(at) });
    moving();
    at = Date.parse(record.validUntil) + 1;
    assert.throws(() => moving(), err => err.code === 'authorization-window-ended');
    // The platform ignore list the stack declares is named in the report with its bytes.
    const report = JSON.parse(await readFile(join(out, 'stack-report.json'), 'utf8'));
    assert.deepEqual([report.platformIgnoreList?.platform, report.platformIgnoreList?.file], ['supabase', 'integrations/observers/ignore-lists/supabase.json']);
    assert.match(report.platformIgnoreList.sha256, /^[0-9a-f]{64}$/);
    // An observer endpoint the record does not name is refused too.
    await assert.rejects(liveCheckGuard(join(out, 'authorization.json'), target, { ...observer, port: port + 1 }), err => err.code === 'authorization-origin');
  } finally { db.close(); await app.close(); await cleanup(); }
});

test('init --stack: a migration the file scan cannot read keeps pg_net\'s queue (a symbolic link, a file over 4 MiB)', async () => {
  const app = await createTwoTenantApp({ postgrest: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, 'ids.env', { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const observers = await envFile(dir, 'observers.env', { SCOPEHAVEN_TARGET_NOTES_DB_WAL: 'scopehaven_wal:synthetic' });
    for (const [name, make] of [['linked', async m => { await writeFile(join(dir, 'outside.sql'), 'select net.http_post(1);\n'); await symlink(join(dir, 'outside.sql'), join(m, '0002_linked.sql')); }],
      ['large', m => writeFile(join(m, '0002_large.sql'), `-- ${'x'.repeat(4 * 1024 * 1024)}\nselect net.http_post(1);\n`)]]) {
      const appDir = join(dir, `app-${name}`), migrations = join(appDir, 'supabase', 'migrations');
      await mkdir(migrations, { recursive: true });
      await writeFile(join(migrations, '0001_notes.sql'), 'create table public.notes (id text primary key);\n');
      await make(migrations);
      const { code, text } = await run(['--stack', 'supabase', '--observer-env', observers, '--observer-port', '55432', '--app-dir', appDir, '--yes', '--base-url', app.origin,
        '--env', env, '--id', 'notes', ...RECORDS, ...ROE, '--confirm-authorization', '--out', join(dir, `out-${name}`), '--no-run']);
      assert.equal(code, 0, text);
      assert.match(text, /net\.http_request_queue: the file scan left 1 entry unread .*, so the queue is left watched/, name);
      const target = JSON.parse(await readFile(join(dir, `out-${name}`, 'targets.json'), 'utf8')).targets[0];
      assert.equal(target.observers[0].ignore?.includes('net.http_request_queue') ?? false, false, name);
    }
  } finally { await app.close(); await cleanup(); }
});

test('declarationFiles counts what it could not read: an unreadable folder, a linked or missing scan path, a folder deeper than four, files past 2000', async () => {
  const c = await readConnector('supabase');
  const paths = ['supabase/migrations', 'supabase/seed.sql'];
  const { dir, cleanup } = await workspace();
  try {
    const app = name => join(dir, name);
    const migrations = name => join(app(name), 'supabase', 'migrations');
    const clean = 'create table public.notes (id text primary key);\n';
    // Clean: the folder is read, nothing skipped.
    await mkdir(migrations('ok'), { recursive: true }); await writeFile(join(migrations('ok'), '0001.sql'), clean);
    let files = await declarationFiles(c, app('ok'), paths);
    assert.deepEqual([files.length, files.skipped, files.readRoots.has('supabase/migrations')], [1, 0, true]);
    // An unreadable migrations folder is counted, and never read.
    await mkdir(migrations('closed'), { recursive: true }); await writeFile(join(migrations('closed'), '0001.sql'), 'select "http_post"(1);\n'); await chmod(migrations('closed'), 0o000);
    try { files = await declarationFiles(c, app('closed'), paths); } finally { await chmod(migrations('closed'), 0o700); }
    assert.deepEqual([files.skipped, files.readRoots.has('supabase/migrations')], [1, false]);
    // A missing migrations folder is not counted, but not read either.
    await mkdir(join(app('none'), 'supabase'), { recursive: true }); await writeFile(join(app('none'), 'supabase', 'seed.sql'), clean);
    files = await declarationFiles(c, app('none'), paths);
    assert.deepEqual([files.skipped, files.readRoots.has('supabase/migrations'), files.readRoots.has('supabase/seed.sql')], [0, false, true]);
    // The scan path itself as a link is counted and not followed.
    await mkdir(join(app('linked'), 'supabase'), { recursive: true }); await symlink(migrations('ok'), migrations('linked'));
    files = await declarationFiles(c, app('linked'), paths);
    assert.deepEqual([files.skipped, files.readRoots.has('supabase/migrations')], [1, false]);
    // A folder deeper than four is counted.
    const deep = join(migrations('deep'), 'a', 'b', 'c', 'd', 'e');
    await mkdir(deep, { recursive: true }); await writeFile(join(deep, '0001.sql'), clean); await writeFile(join(migrations('deep'), '0000.sql'), clean);
    files = await declarationFiles(c, app('deep'), paths);
    assert.equal(files.skipped, 1);
    // Files past the 2000th are counted.
    await mkdir(migrations('many'), { recursive: true });
    await Promise.all(Array.from({ length: 2001 }, (_, i) => writeFile(join(migrations('many'), `${String(i).padStart(4, '0')}.sql`), clean)));
    files = await declarationFiles(c, app('many'), paths);
    assert.deepEqual([files.length, files.skipped > 0], [2000, true]);
    // A migration's extension in upper case is read.
    await mkdir(migrations('upper'), { recursive: true }); await writeFile(join(migrations('upper'), '0003.SQL'), clean);
    files = await declarationFiles(c, app('upper'), paths);
    assert.deepEqual([files.length, files.skipped], [1, 0]);
    // An entry that is neither a file nor a folder (a named pipe) is counted.
    await mkdir(migrations('pipe'), { recursive: true }); await writeFile(join(migrations('pipe'), '0001.sql'), clean); execFileSync('mkfifo', [join(migrations('pipe'), '0002.sql')]);
    files = await declarationFiles(c, app('pipe'), paths);
    assert.deepEqual([files.length, files.skipped], [1, 1]);
    // A scan path that is itself neither a folder nor a .sql file (a named pipe at supabase/seed.sql) is counted too.
    execFileSync('mkfifo', [join(app('pipe'), 'supabase', 'seed.sql')]);
    files = await declarationFiles(c, app('pipe'), paths);
    assert.deepEqual([files.length, files.skipped], [1, 2]);
    // A linked folder above the scan path: its files are not the app's own, so they are counted and not read.
    await mkdir(app('parent'), { recursive: true }); await symlink(join(app('ok'), 'supabase'), join(app('parent'), 'supabase'));
    files = await declarationFiles(c, app('parent'), paths);
    assert.deepEqual([files.length, files.skipped > 0, files.readRoots.has('supabase/migrations')], [0, true, false]);
  } finally { await cleanup(); }
});

test('init --stack: no ignore entry from inference: with every check saying pg_net is unused, the queue stays watched and the report says why', async () => {
  const app = await createTwoTenantApp({ postgrest: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, 'ids.env', { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const observers = await envFile(dir, 'observers.env', { SCOPEHAVEN_TARGET_NOTES_DB_WAL: 'scopehaven_wal:synthetic' });
    const appDir = join(dir, 'app');
    await mkdir(join(appDir, 'supabase', 'migrations'), { recursive: true });
    await writeFile(join(appDir, 'supabase', 'migrations', '0001_notes.sql'), 'create table public.notes (id text primary key);\n');
    // The live check's database answers "pg_net installed, unlogged queue, nothing calls it".
    const unusedDb = { query: async () => [{ rows: [['1', '0', '0', '0', '0', '1']] }], close: async () => {} };
    let text = '';
    const out = join(dir, 'out');
    const code = await runStack(['--stack', 'supabase', '--observer-env', observers, '--observer-port', '55432', '--app-dir', appDir, '--yes', '--base-url', app.origin,
      '--env', env, '--id', 'notes', ...RECORDS, ...ROE, '--confirm-authorization', '--out', out, '--no-run'],
      { stdout: { write: chunk => { text += chunk; } }, env: process.env, stdin: { isTTY: false }, liveConnect: async () => unusedDb });
    assert.equal(code, 0, text);
    assert.match(text, /net\.http_request_queue: pg_net installed but unused per the migrations and the catalog, so the queue is left watched and windows read partial \(table-not-in-wal\) until its requests are observed on the wire/);
    const target = JSON.parse(await readFile(join(out, 'targets.json'), 'utf8')).targets[0];
    assert.equal(target.observers[0].ignore, undefined, 'no ignore entry from inference');
    const report = JSON.parse(await readFile(join(out, 'stack-report.json'), 'utf8'));
    assert.deepEqual(report.watched.map(w => [w.entry, w.use]), [['net.http_request_queue', 'unused']]);
    assert.match(report.watched[0].checkedAt, /^\d{4}-\d\d-\d\dT/);
    assert.deepEqual(report.assumptions.map(a => a.what), ['observer timings', 'functions the live pg_net check does not count', 'the write twin selects one row']);
  } finally { await app.close(); await cleanup(); }
});
