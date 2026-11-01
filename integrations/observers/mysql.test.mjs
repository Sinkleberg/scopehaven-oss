// MySQL snapshot observer and its wire client, against a scripted fake server
// (fixtures/fake-mysql.mjs) on loopback. No real MySQL is used here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { mysqlConnect, MysqlError } from './mysql-wire.mjs';
import { createMysqlSnapshotObserver } from './mysql-snapshot.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';
import { fakeMysql, scriptedMysql, COLUMNS, MYSQL_USER, MYSQL_PASSWORD, MYSQL_SERVER_KEY } from './fixtures/fake-mysql.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../../src/contracts.mjs';
import { createRegistry } from '../../src/registry.mjs';
import { digest } from '../../src/domain.mjs';

const login = (server, extra = {}) => mysqlConnect({ host: '127.0.0.1', port: server.port, database: 'app', user: MYSQL_USER, password: MYSQL_PASSWORD, ...extra });
const echo = sql => /SELECT 1/.test(sql) ? { rows: [['1', null, 'x']] } : /missing/.test(sql) ? { error: '42S02' } : { ok: true };

test('mysql wire: caching_sha2 (fast and full RSA), native and a switch to native authenticate; results keep NULL; errors keep only the SQLSTATE', async t => {
  for (const auth of ['caching-fast', 'caching-full', 'native', 'switch-native']) {
    const server = await fakeMysql(t, { onQuery: echo, auth });
    const client = await login(server, auth === 'caching-full' ? { serverPublicKey: MYSQL_SERVER_KEY() } : {});
    assert.deepEqual((await client.query('SELECT 1')).rows, [['1', null, 'x']], auth);
    await assert.rejects(client.query('SELECT * FROM missing'), e => e instanceof MysqlError && e.sqlState === '42S02' && !/fake error/.test(e.message));
    assert.ok(!Object.values(client).some(v => v === MYSQL_PASSWORD), 'the client keeps no password');
    client.close();
  }
});

test('mysql wire: refuses a wrong password, cleartext, a server without DEPRECATE_EOF, non-loopback hosts, empty passwords and multi-statements', async t => {
  await assert.rejects(login(await fakeMysql(t, { onQuery: echo }), { password: 'wrong' }), e => e.code === 'authentication-failed' && e.sqlState === '28000');
  await assert.rejects(login(await fakeMysql(t, { onQuery: echo, auth: 'clear' })), e => e.code === 'cleartext-password-refused');
  await assert.rejects(login(await fakeMysql(t, { onQuery: echo, auth: 'no-deprecate-eof' })), e => e.code === 'unsupported-protocol');
  await assert.rejects(mysqlConnect({ host: 'localhost', port: 3306, database: 'app', user: 'u', password: 'p' }), e => e.code === 'host-must-be-literal-loopback');
  await assert.rejects(mysqlConnect({ host: '127.0.0.1', port: 3306, database: 'app', user: 'u', password: '' }), e => e.code === 'empty-password-refused');
  const client = await login(await fakeMysql(t, { onQuery: echo }));
  await assert.rejects(client.query('SELECT 1; DROP TABLE t'), e => e.code === 'one-statement-only');
  client.close();
});

// The observer over a scripted database: two marks per window.
const NOW = '2026-10-06 12:00:00.000000', OLD = '2026-10-06 10:00:00.000000';
let dir;
test.before(() => { dir = mkdtempSync(join(tmpdir(), 'scopehaven-mysql-')); writeFileSync(join(dir, 'SOURCE-AUDIT.md'), 'synthetic: the app never writes updated_at explicitly\n'); });
test.after(() => rmSync(dir, { recursive: true, force: true }));
const env = { SCOPEHAVEN_TARGET_MYSQL: `${MYSQL_USER}:${MYSQL_PASSWORD}` };
const observerOn = (server, extra = {}) => createMysqlSnapshotObserver({ env, host: '127.0.0.1', port: server.port, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_MYSQL',
  tables: [{ table: 'notes', key: 'id', changeColumn: { column: 'updated_at', audit: join(dir, 'SOURCE-AUDIT.md') } }], maxCommitLagMs: 1000, watchedResources: ['notes/n1', 'notes/n2'], ...extra });
const at = (rows, extra = {}) => ({ now: NOW, tables: { notes: rows }, ...extra });
async function window(t, before, after, extra) {
  const log = [];
  const server = await scriptedMysql(t, [before, after], log);
  const o = observerOn(server, extra);
  const w = await collectWindow(o, await o.mark(), await o.mark());
  return Object.assign(w, { log });
}
const none = resource => ({ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'notes', operation: 'update', ...(resource ? { resource } : {}) } });
const rows = [['n1', OLD, 'h1'], ['n2', OLD, 'h2']];

test('mysql observer: an unchanged server-maintained column proves no committed update of a named row; a moved one is an update', async t => {
  const quiet = await window(t, at(rows), at(rows));
  assert.deepEqual([quiet.coverage, quiet.events.length, quiet.exact[0].violated], ['net-only', 0, false]);
  assert.equal(evaluateEffectAssertion(none('notes/n1'), [quiet]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(none(), [quiet]).verdict, 'missing', 'a table-wide selector also covers rows never seen');
  // Written and reverted inside the window: same content, a new stamp.
  const reverted = await window(t, at(rows), at([['n1', '2026-10-06 12:00:01.250000', 'h1'], rows[1]]));
  assert.deepEqual(reverted.events.map(e => [e.operation, e.resource]), [['update', 'notes/n1']], 'the moved column is an update even with the same content');
  assert.equal(evaluateEffectAssertion(none('notes/n1'), [reverted]).verdict, 'fail');
  const updated = await window(t, at(rows), at([['n1', '2026-10-06 12:00:01.250000', 'h9'], rows[1]]));
  assert.deepEqual(updated.events.map(e => [e.operation, e.resource]), [['update', 'notes/n1']]);
  assert.equal(evaluateEffectAssertion(none('notes/n1'), [updated]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion(none('notes/n2'), [updated]).verdict, 'pass');
});

test('mysql observer: content changed under an unchanged column voids the table and reports none of its changes; recent stamps and one-mark rows are ambiguous', async t => {
  const sneaky = await window(t, at(rows), at([['n1', OLD, 'h9'], rows[1]]));
  assert.equal(sneaky.exact[0].violated, true); assert.equal(sneaky.events.length, 0);
  assert.equal(evaluateEffectAssertion(none('notes/n2'), [sneaky]).verdict, 'missing');
  const recent = await window(t, at([['n1', '2026-10-06 11:59:59.500000', 'h1'], rows[1]]), at([['n1', '2026-10-06 11:59:59.500000', 'h1'], rows[1]]));
  assert.deepEqual(recent.exact[0].ambiguousResources, ['notes/n1'], 'within maxCommitLagMs of the start mark');
  assert.equal(evaluateEffectAssertion(none('notes/n1'), [recent]).verdict, 'missing');
  const churn = await window(t, at(rows), at([rows[0], ['n3', NOW, 'h3']]));
  assert.deepEqual(churn.events.map(e => e.operation).sort(), ['delete', 'insert']);
  assert.notEqual(evaluateEffectAssertion(none('notes/n2'), [churn]).verdict, 'pass', 'a deleted watched row is not exact');
});

test('L1: the guard spans one tick of the column precision; a NULL or zero-date stamp is ambiguous; more rows than rowsPerTable fail the mark', async t => {
  // A TIMESTAMP(0) stamp drops the fraction: a write at 12:00:01.9 reads 12:00:01, and with 1 s of commit lag it could
  // still be in flight at a start mark of 12:00:02.3. With microsecond ticks the same stamp would read settled.
  const seconds = { notes: { engine: 'InnoDB', type: 'BASE TABLE', created: '2026-10-01 00:00:00', columns: [COLUMNS[0], ['updated_at', 'DEFAULT_GENERATED on update CURRENT_TIMESTAMP', 'timestamp', '0', 'CURRENT_TIMESTAMP'], COLUMNS[2]] } };
  const coarse = [['n1', '2026-10-06 12:00:01.000000', 'h1'], ['n2', '2026-10-06 12:00:00.000000', 'h2']];
  const tick = await window(t, at(coarse, { now: '2026-10-06 12:00:02.300000', meta: seconds }), at(coarse, { now: '2026-10-06 12:00:09.000000', meta: seconds }));
  assert.deepEqual(tick.exact[0].ambiguousResources, ['notes/n1']);
  assert.equal(evaluateEffectAssertion(none('notes/n1'), [tick]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion(none('notes/n2'), [tick]).verdict, 'pass');
  for (const stamp of [null, '0000-00-00 00:00:00.000000', '2026-00-06 10:00:00.000000', '2026-10-00 10:00:00.000000']) {
    const odd = [['n1', stamp, 'h1'], rows[1]];
    const w = await window(t, at(odd), at(odd));
    assert.deepEqual(w.exact[0].ambiguousResources, ['notes/n1'], String(stamp));
    assert.equal(evaluateEffectAssertion(none('notes/n1'), [w]).verdict, 'missing', String(stamp));
  }
  const many = await window(t, at([...rows, ['n3', OLD, 'h3']]), at(rows), { rowsPerTable: 2 });
  assert.deepEqual([many.coverage, many.reason, many.events.length], ['failed', 'row-limit', 0]);
});

test('mysql observer: rows that cannot be identified across the marks fail the window with no events', async t => {
  const rebuilt = await window(t, at(rows), at(rows, { meta: { notes: { engine: 'InnoDB', type: 'BASE TABLE', created: '2026-10-06 12:00:00', columns: COLUMNS } } }));
  assert.deepEqual([rebuilt.coverage, rebuilt.reason, rebuilt.events.length], ['failed', 'relation-rewritten', 0]);
  const altered = await window(t, at(rows), at(rows, { meta: { notes: { engine: 'InnoDB', type: 'BASE TABLE', created: '2026-10-01 00:00:00', columns: [COLUMNS[0], COLUMNS[1], ['v', '', 'mediumtext', null, null]] } } }));
  assert.deepEqual([altered.coverage, altered.reason], ['failed', 'relation-rewritten']);
  // CREATE_TIME has whole seconds: a table created in the second the start mark reads it cannot be followed.
  const metaAt = created => ({ notes: { engine: 'InnoDB', type: 'BASE TABLE', created, columns: [COLUMNS[0], COLUMNS[1]] } });
  const fresh = await window(t, at(rows, { meta: metaAt('2026-10-06 12:00:00') }), at(rows, { meta: metaAt('2026-10-06 12:00:00') }));
  assert.deepEqual([fresh.coverage, fresh.reason, fresh.events.length], ['failed', 'relation-unverified', 0]);
  // L1: the same-second check reads the start mark; an end mark seconds later does not settle it.
  const later = await window(t, at(rows, { meta: metaAt('2026-10-06 12:00:00') }), at(rows, { meta: metaAt('2026-10-06 12:00:00'), now: '2026-10-06 12:00:05.000000' }));
  assert.deepEqual([later.coverage, later.reason], ['failed', 'relation-unverified']);
  const unknown = await window(t, at(rows, { meta: metaAt(null) }), at(rows, { meta: metaAt(null) }));
  assert.deepEqual([unknown.coverage, unknown.reason], ['failed', 'relation-unverified']);
  const settled = await window(t, at(rows, { meta: metaAt('2026-10-06 11:59:59') }), at(rows, { meta: metaAt('2026-10-06 11:59:59') }));
  assert.equal(settled.coverage, 'net-only', 'created in the second before the start mark');
  for (const dup of [[['n1', OLD, 'h1'], ['n1', OLD, 'h2']], [['n1', OLD, 'h1'], [null, OLD, 'h2']]]) {
    const w = await window(t, at(rows), at(dup));
    assert.deepEqual([w.coverage, w.reason], ['failed', 'duplicate-key']);
  }
});

test('M1: with tableIds an exchanged partition or a renamed twin (other InnoDB ids, the same CREATE_TIME) fails the window; ids it cannot read fail the mark', async t => {
  const ids = (tableId, space) => ({ ids: { notes: [tableId, space] } });
  const quiet = await window(t, at(rows, ids('1084', '18')), at(rows, ids('1084', '18')), { tableIds: true });
  assert.deepEqual([quiet.coverage, evaluateEffectAssertion(none('notes/n1'), [quiet]).verdict], ['net-only', 'pass']);
  assert.ok(quiet.log.includes("SELECT TABLE_ID, SPACE FROM information_schema.INNODB_TABLES WHERE BINARY NAME = 'app/notes'"));
  assert.match(quiet.exact[0].basis, /table identity: CREATE_TIME and InnoDB table and tablespace ids;/);
  for (const [label, after] of [['exchanged (both ids)', ids('1087', '21')], ['table id only', ids('1087', '18')], ['tablespace only', ids('1084', '21')]]) {
    const w = await window(t, at(rows, ids('1084', '18')), at(rows, after), { tableIds: true });
    assert.deepEqual([w.coverage, w.reason, w.events.length], ['failed', 'relation-rewritten', 0], label);
  }
  // Without tableIds the same swap is invisible: CREATE_TIME and the rows are unchanged (the stated limit).
  const blind = await window(t, at(rows, ids('1084', '18')), at(rows, ids('1087', '21')));
  assert.equal(evaluateEffectAssertion(none('notes/n1'), [blind]).verdict, 'pass');
  // M-L2: the run records which identity each table's exactness rested on.
  assert.match(blind.exact[0].basis, /table identity: CREATE_TIME only, so an exchanged partition or a same-second renamed twin is not seen;/);
  assert.match(evaluateEffectAssertion(none('notes/n1'), [blind]).basis, /table identity: CREATE_TIME only/);
  assert.ok(!blind.log.some(s => /INNODB_TABLES/.test(s)));
  // M-L3: two dictionary rows (names that differ only in case) are not one table's ids.
  for (const [label, state] of [['no row', at(rows)], ['not numeric', at(rows, ids('x', '18'))], ['two rows', at(rows, { ids: { notes: [['1084', '18'], ['1090', '25']] } })], ['no PROCESS', at(rows, { ids: { notes: { error: '42000' } } })]]) {
    const w = await window(t, state, at(rows, ids('1084', '18')), { tableIds: true });
    assert.deepEqual([w.coverage, w.reason], ['failed', label === 'no PROCESS' ? 'permission-denied' : 'table-ids-unreadable'], label);
  }
  assert.throws(() => observerOn({ port: 1 }, { tableIds: 'yes' }), /tableIds is true or false/);
});

test('mysql observer: only an InnoDB base table with a server-maintained change column; a replica is refused; windows move forward', async t => {
  const failsMark = async (state, reason) => { const w = await window(t, state, at(rows)); assert.deepEqual([w.coverage, w.reason], ['failed', reason], reason); };
  await failsMark(at(rows, { meta: { notes: { engine: 'MyISAM', type: 'BASE TABLE', created: 'x', columns: [] } } }), 'relation-not-innodb-table');
  await failsMark(at(rows, { meta: { notes: { engine: null, type: 'VIEW', created: 'x', columns: [] } } }), 'relation-not-innodb-table');
  const withStamp = column => at(rows, { meta: { notes: { engine: 'InnoDB', type: 'BASE TABLE', created: '2026-10-01 00:00:00', columns: [COLUMNS[0], column] } } });
  await failsMark(withStamp(['updated_at', 'DEFAULT_GENERATED', 'timestamp', '6', 'CURRENT_TIMESTAMP(6)']), 'change-column-not-server-maintained');
  // H1: a DATETIME stamp is written in the writer's session time zone, so a fresh one can look hours old (any precision).
  await failsMark(withStamp(['updated_at', 'DEFAULT_GENERATED on update CURRENT_TIMESTAMP(6)', 'datetime', '6', 'CURRENT_TIMESTAMP(6)']), 'change-column-not-server-maintained');
  await failsMark(withStamp(['updated_at', 'DEFAULT_GENERATED on update CURRENT_TIMESTAMP', 'datetime', '0', 'CURRENT_TIMESTAMP']), 'change-column-not-server-maintained');
  // H2: a constant default lets a delete-and-reinsert or REPLACE land the old stamp; the default and its marker each count.
  await failsMark(withStamp(['updated_at', 'on update CURRENT_TIMESTAMP(6)', 'timestamp', '6', '2020-01-01 00:00:00.000000']), 'change-column-not-server-maintained');
  await failsMark(withStamp(['updated_at', 'DEFAULT_GENERATED on update CURRENT_TIMESTAMP(6)', 'timestamp', '6', '2020-01-01 00:00:00.000000']), 'change-column-not-server-maintained');
  await failsMark(withStamp(['updated_at', 'on update CURRENT_TIMESTAMP(6)', 'timestamp', '6', 'CURRENT_TIMESTAMP(6)']), 'change-column-not-server-maintained');
  // M1: a partition can be exchanged with no table-level change.
  await failsMark(at(rows, { meta: { notes: { engine: 'InnoDB', type: 'BASE TABLE', created: '2026-10-01 00:00:00', options: 'partitioned', columns: COLUMNS } } }), 'relation-partitioned-refused');
  await failsMark(at(rows, { readOnly: '1' }), 'read-only-server-refused');
  await failsMark(at(rows, { meta: { notes: 'missing' } }), 'table-missing');
  await failsMark({ now: NOW, tables: { notes: { error: '42000' } } }, 'permission-denied');
  const server = await scriptedMysql(t, [at(rows), at(rows)]);
  const o = observerOn(server); const a = await o.mark(), b = await o.mark();
  assert.deepEqual((({ coverage, reason }) => [coverage, reason])(await collectWindow(o, b, a)), ['failed', 'window-not-forward']);
});

test('mysql observer: each mark is one consistent read-only snapshot in UTC, one statement per query, hashing every column in the server', async t => {
  const w = await window(t, at(rows), at(rows));
  // L3: the server clock is read before the snapshot starts; sql_mode is pinned to MySQL 8.4's default.
  assert.deepEqual(w.log.slice(0, 6), ['SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ', "SET SESSION time_zone = '+00:00'",
    "SET SESSION sql_mode = 'ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'", 'SET SESSION max_execution_time = 10000',
    "SELECT DATE_FORMAT(NOW(6), '%Y-%m-%d %H:%i:%s.%f'), @@global.read_only", 'START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY']);
  assert.ok(w.log.some(s => /MD5\(JSON_ARRAY\(`id`, `updated_at`, `v`\)\) FROM `app`\.`notes`/.test(s)));
  assert.ok(w.log.every(s => !s.includes(';')));
  assert.equal(w.log.filter(s => s === 'COMMIT').length, 2);
});

test('mysql observer: a table without a change column reports net changes but never claims absence', async t => {
  const server = await scriptedMysql(t, [at(rows), at([['n1', null, 'h9'], rows[1]])]);
  const o = observerOn(server, { tables: [{ table: 'notes', key: 'id' }], maxCommitLagMs: undefined });
  const w = await collectWindow(o, await o.mark(), await o.mark());
  assert.equal(w.exact, undefined);
  assert.equal(evaluateEffectAssertion(none('notes/n1'), [w]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion(none('notes/n2'), [w]).verdict, 'missing');
});

// End to end through the connector and the shared validator.
async function app(t) {
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    if (req.headers.authorization !== 'Bearer synthetic-bob-token') return reply(401, {});
    if (req.url === '/me') return reply(200, { user: 'bob' });
    reply(403, { error: 'forbidden' });
  }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const profile = (origin, port) => ({ id: 'notes-app', name: 'Notes app', applicationId: 'notes-app', origin, buildLabel: 'b1', contextId: 'synthetic-notes',
  actors: { bob: { principalId: 'bob', credentialEnv: 'SCOPEHAVEN_TARGET_BOB', identityValue: 'bob' } }, requiredControlIds: ['WHOAMI'],
  observers: [{ id: 'db', type: 'mysql-snapshot', host: '127.0.0.1', port, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_MYSQL', settleMs: 250, maxCommitLagMs: 1000,
    tables: [{ table: 'notes', key: 'id', changeColumn: { column: 'updated_at', audit: join(dir, 'SOURCE-AUDIT.md') } }] }],
  checks: [
    { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'bob', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'bob' }] },
    { id: 'BOB-NO-EDIT', title: "Bob cannot edit alice's note", category: 'object-access', severity: 'high', actorId: 'bob', method: 'GET', path: '/notes/n1/edit', evidenceRequirement: 'backend',
      assertions: [{ kind: 'status.equals', expected: 403 }], effects: [{ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'notes', operation: 'update', resource: 'notes/n1' } }] },
  ] });

test('mysql in a profile: an unchanged server-maintained column proves the refused edit changed nothing (backend observed, suite-valid); a relabelled method is refused', async t => {
  // Five marks: start(), the settlement mark before the first check (src/http-settlement.mjs), the check's two marks and the final mark.
  const origin = await app(t), server = await scriptedMysql(t, [at(rows), at(rows), at(rows), at(rows), at(rows)]);
  const p = profile(origin, server.port), envs = { ...env, SCOPEHAVEN_TARGET_BOB: 'synthetic-bob-token' };
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  const run = await runHttpAssessment(p, { env: envs });
  const r = run.results.find(x => x.id === 'BOB-NO-EDIT'), w = r.trace[1].data.windows[0];
  // Custody (src/custody.mjs): the snapshot reads the app's own store, so the decided absence reads inconclusive in a boundary check.
  assert.deepEqual([r.status, r.backendEvidence, w.lineage.observer, w.exact[0].presentResources, r.trace[1].data.effects[0].custodyReason], ['inconclusive', 'observed', 'mysql-snapshot-diff', ['notes/n1'], 'subject-writable-custody'], JSON.stringify(r.assertions));
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env: envs }).exportSuite(p.id) });
  assert.ok(run.limitations.some(l => l.startsWith('MySQL snapshot observers (db)')));
  // M-L4: the stated limits, pinned: every writer the source check must cover, and the swaps only tableIds sees.
  const mysqlLimit = run.limitations.find(l => l.startsWith('MySQL snapshot observers (db)'));
  for (const phrase of ['no writer sets it: the app, SQL the agent can run, SET timestamp, triggers or foreign-key cascades', 'Unless the observer declares tableIds (its reader then needs PROCESS), rows swapped in by EXCHANGE PARTITION, or a twin created in the same second and renamed into place, read as the same table',
    'a TRUNCATE reads as deletes (with tableIds it fails the window)', 'partitioned tables are refused']) assert.ok(mysqlLimit.includes(phrase), phrase);
  assert.match(w.exact[0].basis, /source-checked that no writer sets it \(app code, agent SQL, SET timestamp, triggers, cascades\)/);
  // tableIds reaches the observer from a profile: each mark then reads InnoDB's ids.
  const log = [], withIds = { ...at(rows), ids: { notes: ['1084', '18'] } }, idServer = await scriptedMysql(t, [withIds, withIds, withIds, withIds, withIds], log);
  const pi = profile(origin, idServer.port); pi.observers[0].tableIds = true;
  validateTargetFile({ schemaVersion: 1, targets: [pi] });
  const idRun = await runHttpAssessment(pi, { env: envs });
  assert.deepEqual([idRun.results.find(x => x.id === 'BOB-NO-EDIT').status, idRun.results.find(x => x.id === 'BOB-NO-EDIT').backendEvidence], ['inconclusive', 'observed']);
  assert.ok(log.some(s => /INNODB_TABLES/.test(s)));
  // A change-column entry relabelled as Postgres row versions is refused: the method is bound to the observer type.
  const forged = structuredClone(run), fr = forged.results.find(x => x.id === 'BOB-NO-EDIT'), fw = fr.trace[1].data.windows[0];
  Object.assign(fw.exact[0], { method: 'xmin', auditSha256: null, marks: { startXmax: '800', endXmax: '800', inProgress: 0 } });
  fr.evidenceDigest = digest({ evidence: fr.trace[0].data, effects: fr.trace[1].data, assertions: fr.assertions });
  assert.throws(() => validateHttpRunEvidence(forged), /invalid-run-evidence/);
});

test('mysql profiles: loopback, plain identifiers, the credential only through credentialEnv, a change column with its audit and commit lag', () => {
  const reject = (edit, pattern) => { const p = profile('http://127.0.0.1:4000', 3306); edit(p.observers[0]); assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [p] }), pattern); };
  reject(o => { o.password = 'x'; }, /its credential comes only from credentialEnv/);
  reject(o => { o.host = 'localhost'; }, /"host" must be the literal loopback/);
  reject(o => { o.database = 'app db'; }, /plain identifier/);
  reject(o => { o.tables = [{ table: 'notes; DROP', key: 'id' }]; }, /plain identifiers/);
  reject(o => { delete o.maxCommitLagMs; }, /"maxCommitLagMs" is declared exactly when/);
  reject(o => { o.tables[0].changeColumn = { column: 'updated_at' }; }, /changeColumn/);
  reject(o => { o.credentialEnv = 'MYSQL_PWD'; }, /SCOPEHAVEN_TARGET_/);
  reject(o => { o.tableIds = 'yes'; }, /"tableIds" is true or false/);
});

// 2026-10-16 security scan F3: the server is not authenticated, so the password is encrypted only to a pinned key.
test('SEC-F3: full caching_sha2 authentication encrypts only to the pinned key; without one, or to a key the server pushes, no password byte is sent', async t => {
  const unpinned = [];
  await assert.rejects(login(await fakeMysql(t, { onQuery: echo, auth: 'caching-full', received: unpinned })), e => e.code === 'server-key-not-pinned');
  assert.deepEqual(unpinned, [], 'nothing follows the full-authentication request without a pinned key');
  for (const extra of [{}, { serverPublicKey: MYSQL_SERVER_KEY() }]) {
    const pushed = [];
    await assert.rejects(login(await fakeMysql(t, { onQuery: echo, auth: 'offer-key', received: pushed }), extra), e => e.code === 'protocol-error');
    assert.deepEqual(pushed, [], 'a key the server offers is never used, pinned key or not');
  }
  const other = generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } }).publicKey;
  const elsewhere = [];
  await assert.rejects(login(await fakeMysql(t, { onQuery: echo, auth: 'caching-full', received: elsewhere }), { serverPublicKey: other }), e => e.code === 'authentication-failed');
  assert.equal(elsewhere.length, 1, 'one ciphertext, to the pinned key, which this server cannot read');
  const ec = generateKeyPairSync('ec', { namedCurve: 'P-256', publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } }).publicKey;
  for (const serverPublicKey of ['not a key', ec]) await assert.rejects(login(await fakeMysql(t, { onQuery: echo }), { serverPublicKey }), e => e.code === 'invalid-server-key');
  // The observer reads the pin beside its credential (<credentialEnv>_RSA_PUBLIC_KEY).
  const read = async observerEnv => { const server = await scriptedMysql(t, [at(rows), at(rows)], [], { auth: 'caching-full' }); const o = observerOn(server, { env: observerEnv }); return collectWindow(o, await o.mark(), await o.mark()); };
  const refused = await read(env);
  assert.deepEqual([refused.coverage, refused.reason], ['failed', 'authentication-refused']);
  assert.notEqual((await read({ ...env, SCOPEHAVEN_TARGET_MYSQL_RSA_PUBLIC_KEY: MYSQL_SERVER_KEY() })).coverage, 'failed');
});
