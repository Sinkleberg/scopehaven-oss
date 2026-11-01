// PostgreSQL snapshot observer (pg-snapshot): what the application's own
// Postgres database committed between two marks. Read-only and dependency-free
// (./pg-wire.mjs). Each mark is one REPEATABLE READ READ ONLY transaction with
// search_path = pg_catalog (every name is schema-qualified), row_security = off
// and a statement_timeout, in two round trips:
//   1. the server and the tables: pg_current_snapshot(), in-progress writers
//      (pg_locks), pg_is_in_recovery(), and each declared table's oid, relkind,
//      access method and persistence. A standby, or a table that is not an
//      ordinary or partitioned heap table (a view, a foreign table, another
//      access method), fails the mark before any table is read; so does an
//      unlogged table ('unlogged-table'), which crash recovery empties.
//   2. per declared table, every row's key, xmin and md5(row::text) (computed
//      in the database, so no values leave it), then the writers again, the
//      column layout and the key column's output function. A key whose text is
//      not fixed by its stored bytes fails the mark ('key-type-refused'): its type's
//      output function is not immutable (an enum, a reg* type, aclitem, an array,
//      range or composite, or a domain over one) and does not depend only on a
//      pinned setting, or it is a virtual generated column or not a column.
//
// Why updates are exact. Every committed UPDATE writes a new row version with a
// new xmin: a no-op update, a HOT update and a write reverted within the window
// (two updates) all change it. Row locks (SELECT ... FOR UPDATE/SHARE) set xmax,
// not xmin. So an existing row whose xmin is unchanged between the two marks had
// no committed update; no operator assertion is needed. A row is ambiguous, never
// exact, when:
//   - its xmin reads as the frozen id (2) at one mark only (freezing is not an update);
//   - its unchanged 32-bit xmin equals, mod 2^32, the id of a transaction that was not
//     committed at the start mark (in progress then, or assigned during the window):
//     the 32-bit wraparound coincidence;
//   - it was inserted or deleted in the window (inserts and deletes are net-only);
//   - a selected resource (a row a check names) is absent at either mark: absence is
//     claimed only about rows the observer saw at both marks (presentResources).
// A table-wide or prefix selector is exact only on a quiescent window: start xmax
// equals end xmax (no transaction with an id completed anywhere in the cluster)
// and no writer was seen at either mark, so nothing at all was committed.
// Partitions and inheritance children are read with their parent; every
// descendant must itself be a heap (or partitioned) table that the parent scan
// reads: another session's temporary child and a partition being detached
// concurrently (PostgreSQL 14+) are skipped by the scan, so either fails the mark
// ('descendant-not-scanned'). More than 10000 descendants fail it too.
// Row identity. The window fails, with no events at all, when a table's rows cannot
// be identified across the marks: its oid changed (replaced or renamed in), its set
// of descendants changed, a row came from an unverified relation ('relation-unverified'),
// a key is NULL or duplicated ('duplicate-key'), a row's xmin is 0 or 1, not a heap
// row version ('invalid-row-version'), or the end snapshot's xmax is below the
// start's ('xmax-regressed'), or a key whose row version is new to it carries an id
// already committed at the start mark ('key-without-new-version'). A table whose content changed under an unchanged xmin
// is violated: never exact, and none of its changes is reported as an event.
// A window whose end mark is not after its start mark fails ('window-not-forward').
//
// Row-level security. With row_security = off, a role that a policy would filter
// gets an error (42501) instead of a silently partial table: the mark fails as
// permission-denied, never a complete, short or empty window.
//
// In-flight transactions. A write transaction still in progress at the end mark
// could commit after it, so the window is partial ('transaction-in-flight-at-window-end').
// pg_current_snapshot()'s xip lists only in-progress ids below xmax (one past the
// latest completed transaction), so every transaction holding a 'transactionid'
// lock in pg_locks is also read, at the start of the mark and after the table
// reads; any writer seen there or in xip makes the window partial. A writer in
// progress when the snapshot is taken that commits before the first lock read
// (the same statement, microseconds later) is not seen: it reads as a commit
// after the end mark, which the post-response settle disclosure covers. Any
// writer in the cluster counts, so a long-running unrelated write transaction
// keeps windows partial (never a pass).
//
// Read-back (src/pg-readback.mjs): a table may declare readBack, the value columns to read and what they should hold.
// Round trip 1 then also reads that table's columns and types (under the same snapshot and lock); round trip 2 reads
// exactly the declared columns, as text (no cast that can raise an error), beside a sha256 of the row's other columns
// and one of the whole row, in the same scan. A missing column, a virtual one or a type the reader cannot canonicalise
// leaves that table's read-back unusable and its scan as it is without read-back, so the window itself never changes;
// so does a descendant holding a column the parent lacks, found after the scan. Values are canonicalised as each mark is
// read, and a sensitive column's values are sealed there under a salt held only by this observer. collect() returns the
// read-back record beside the window (collectWindow keeps only the window); judgeReadBack decides it. The scan returns
// every declared value of every row, each cut at 4097 characters, and pg-wire holds the whole result: the read-back
// budget (otherValueChars) bounds what a mark keeps, not what it reads. A large table with wide declared columns can
// reach the statement timeout or the process memory, which fails the mark and the window (never a pass).
//
// Credentials: credentialEnv names a SCOPEHAVEN_TARGET_ variable holding
// "user:password" for a role with SELECT only (SCRAM-SHA-256; trust and md5 are
// refused). Host: literal 127.0.0.1. Table names are unique within an observer
// (events are named by table).
//
// Background writers (N12), each opt-in, so a profile that declares none reads exactly as before:
//   - platform / ignore (./ignore-lists/ignore-list.mjs): declaring either makes the in-flight rule attribute writers. A
//     writer in progress at the end mark then stops counting when, at each lock read of that mark where it holds a
//     transaction id, it holds or awaits at least one write lock (RowExclusive or stronger) and every one is on a table
//     the platform's checked-in list names (an index, a TOAST table or an owned sequence reads as its table; never a
//     declared table or queue, nor their partitions and children, read by oid) or in another database (a session cannot
//     write this one's tables; a shared catalog, database 0, is not another database). Only the platform's list counts:
//     those writers are the platform's own services, whose transactions write only their bookkeeping. A profile's own
//     ignore entries do not: they are the application's workers, and a worker that has written only its heartbeat can
//     still write an application table before it commits. A writer with no write lock, or one on any other table,
//     still counts: a table nobody declared is never ignored. What it rests on: a write made after the end mark is a late
//     effect, read in a later window as any write after a mark is. Quiescence is not attributed and cannot be: a
//     transaction that wrote an ignored table can also have inserted and deleted a declared row, which no snapshot
//     shows, so a table-wide or prefix absence still needs a quiescent cluster (use pg-wal on a platform with
//     background writers).
//   - queues (./end-barrier.mjs): each mark first polls the queues' pending counts on its connection until they read
//     zero or drainTimeoutMs passes, then reads them again inside its own snapshot, beside the rows. An end mark with
//     pending work reads queue-not-drained (partial). An enqueuer still in progress at the mark is an in-flight writer.
//     The role then needs SELECT on the queue tables.
//   - runLease (./run-lease.mjs): start() opens a session that holds the run lease until stop(), and refuses while
//     another run holds one on this database; each mark reads the other runs' leases and its own, and takes its own
//     again (never refusing) when its session has gone. A window either of whose marks saw another run's reads partial
//     with shared-database, and one whose end mark found its own lease gone reads lease-lost (a run that started and
//     ended in the gap was never seen); the events stay either way.
//
// Catalog fingerprint (N13, ./catalog.mjs), always on: each mark also reads the database's catalog fingerprint on a
// second, short session, before and after the mark's transaction (printing a view or policy locks what it names, so it is
// never read inside the mark's transaction), and start() keeps the latest as the run's baseline, tried again a few times
// and refusing the start without one (an observer marked without start() keeps its first mark's). A window whose marks' definitions differ from the baseline, or whose catalog changed
// between its marks or while one was read, reads schema-drift; one without a readable fingerprint (a lock not granted
// within a second included) reads catalog-unreadable. Both are partial and keep the events. catalog() returns the record a
// run keeps (counts and sha256 digests only). The catalog is readable by every role, so the observer's role needs nothing
// more; each mark opens one more connection.
import { randomBytes } from 'node:crypto';
import { pgConnect, PgError, PG_LIMITS } from './pg-wire.mjs';
import { digest } from '../../src/domain.mjs';
import { validateReadBack, kindOfColumn, keyKindOfColumn, canonicalValue, sealWith, buildReadBackRecord, PG_READBACK_LIMITS } from '../../src/pg-readback.mjs';
import { makeEffect, credentialFrom } from './events.mjs';
import { resolveIgnoreList } from './ignore-lists/ignore-list.mjs';
import { validateQueues, validateDrain, pgQueueCountSql, drainWait, pendingOf } from './end-barrier.mjs';
import { RUN_KEY, pgLeaseSql, pgOtherRunsSql, pgOwnLeaseSql } from './run-lease.mjs';
import { catalogExclusions, pgCatalogSql, openPgCatalogSession, bracketCatalog, readPgCatalogBaseline, catalogReasons, catalogRecord, SCHEMA_DRIFT, BASELINE_REFUSED } from './catalog.mjs';
import { validateActorCapture, verifySql as actorVerifySql, verifyRecord as actorVerifyRecord, ledgerSql, parseLedger, attributeNetChange, windowLedger, ledgerOp, resolveActor, PG_ACTOR_SCHEMA, PG_ACTOR_LIMITS } from './pg-actor.mjs';
import { zeroRowFacts } from './supabase-rules.mjs';

const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const quote = name => { if (!IDENT.test(name)) throw new Error(`Unsupported SQL identifier "${String(name).slice(0, 64)}".`); return `"${name}"`; };
const literal = name => { if (!IDENT.test(name)) throw new Error(`Unsupported SQL identifier "${String(name).slice(0, 64)}".`); return `'${name}'`; };
// A column name read from the catalog (the remainder's columns): quoted, or null for one with a control character.
const quoteName = name => (typeof name === 'string' && /^[^\u0000-\u001f\u007f]{1,63}$/.test(name) ? `"${name.replace(/"/g, '""')}"` : null);
// A read-back value as text, cut one past the value limit. json is parsed by the reader, never cast to jsonb here: jsonb
// refuses some json an application can store ("\u0000"), and an error in the scan would fail the whole mark.
const valueSql = column => `pg_catalog.left((r.${column})::pg_catalog.text, ${PG_READBACK_LIMITS.valueChars + 1})`;
// A sha256 of a text's bytes, computed in the database (textsend: no encoding conversion that could fail).
const sha256Sql = text => `pg_catalog.encode(pg_catalog.sha256(pg_catalog.textsend(${text})), 'hex')`;
// A read-back table's plan from its columns (round trip 1): each declared column's kind, the key column's kind (an
// exact-key range compares keys as it reads them), and the remainder's columns.
function readBackPlan(t, attributes) {
  const byName = new Map(attributes.map(([, name, typid, generated, typtype, basetype]) => [name, { typid, generated, typtype, basetype }]));
  const rb = t.readBack, columns = rb.columns.map(name => ({ name, kind: byName.has(name) ? kindOfColumn(byName.get(name)) : null, sealed: rb.sensitive.includes(name) && !rb.reveal.includes(name) }));
  const others = attributes.map(([, name]) => name).filter(name => name !== t.key && !rb.columns.includes(name)).map(quoteName);
  const status = rb.columns.some(c => !byName.has(c)) ? 'column-missing' : rb.columns.some(c => byName.get(c).generated === 'v') ? 'column-virtual'
    : columns.some(c => !c.kind) ? 'type-refused' : others.includes(null) ? 'column-name-refused' : 'ok';
  return { status, columns, keyKind: byName.has(t.key) ? keyKindOfColumn(byName.get(t.key)) : null, others };
}
// Explicit bounds, so a large table cannot stall a mark or the run budget: a server-side
// statement_timeout per mark (the client also gives up shortly after it), a row cap per
// table and the client's total row cap per mark.
export const PG_SNAPSHOT_LIMITS = Object.freeze({ rowsPerTable: 200000, tables: 32, statementTimeoutMs: 10000, statementTimeoutBounds: [500, 60000], rowsPerTableBounds: [1, 200000],
  rowsPerMark: PG_LIMITS.rows, retainedMarks: 128, presentResources: 1000, descendants: 10000 });
const MAX_DESCENDANTS = PG_SNAPSHOT_LIMITS.descendants;
const FROZEN = '2', INVALID_XMIN = new Set(['0', '1']), MOD32 = 1n << 32n;
// Output functions that are not immutable only because they read a setting each mark pins (DateStyle, TimeZone,
// IntervalStyle, lc_monetary). byteaout and float8out read bytea_output and extra_float_digits but are immutable.
const PINNED_OUTPUTS = new Set(['pg_catalog.date_out', 'pg_catalog.timestamp_out', 'pg_catalog.timestamptz_out', 'pg_catalog.interval_out', 'pg_catalog.cash_out']);
const parseSnapshot = text => {
  const m = /^(\d+):(\d+):([\d,]*)$/.exec(String(text ?? ''));
  if (!m) throw new PgError('snapshot-unreadable');
  return { xmin: m[1], xmax: m[2], xip: m[3] ? m[3].split(',') : [] };
};
const lockIds = text => {
  if (text === null || text === undefined || text === '') return [];
  if (!/^\{[\d,]*\}$/.test(text)) throw new PgError('locks-unreadable');
  return text.slice(1, -1).split(',').filter(Boolean);
};
// Ids that were not committed at the start mark: in progress then, or assigned before the end mark.
function uncommittedAtStart(before, after) {
  // From the start snapshot's xmin (the oldest id in progress; its subtransactions are not
  // all listed in xip) to the end snapshot's xmax.
  const lo = BigInt(before.snapshot.xmin), hi = BigInt(after.snapshot.xmax), span = hi > lo ? hi - lo : 0n;
  const inProgress = new Set([...before.snapshot.xip, ...before.snapshot.writers].map(x => (BigInt(x) % MOD32).toString()));
  return xmin32 => {
    const x = BigInt(xmin32);
    if (inProgress.has(x.toString())) return true;
    if (span >= MOD32) return true;
    return ((x - lo % MOD32) % MOD32 + MOD32) % MOD32 < span;
  };
}

// Was a 32-bit xmin's transaction already completed when the start snapshot was taken? Its full id is taken
// as the latest id with those low 32 bits before the end snapshot's xmax; below the start xmin, or below the
// start xmax and not in progress then (xip or a transactionid lock), it was completed. A frozen xmin was
// completed long ago. A window spanning 2^32 ids or more cannot be decided: treated as completed.
function completedAtStart(before, after) {
  const lo = BigInt(before.snapshot.xmin), startXmax = BigInt(before.snapshot.xmax), hi = BigInt(after.snapshot.xmax);
  const inProgress = new Set(before.snapshot.xip.map(x => BigInt(x)));
  const writers = new Set(before.snapshot.writers.map(x => (BigInt(x) % MOD32).toString()));
  return xmin32 => {
    if (xmin32 === FROZEN || !/^\d+$/.test(xmin32) || hi - lo >= MOD32) return true;
    const top = hi - 1n, full = top - (((top - BigInt(xmin32)) % MOD32) + MOD32) % MOD32;
    if (full < lo) return true;
    return full < startXmax && !inProgress.has(full) && !writers.has(xmin32);
  };
}

// tables: [{ table, key, schema? ('public'), resourcePrefix? }]
// watchedResources: the resources the profile's effect selectors name ("Chat/<key>"); supplied by the connector.
// platform, ignore, queues (with drainTimeoutMs, pollMs) and runLease: the background-writer options above (runKey is a
// test seam, never from a configuration).
export function createPgSnapshotObserver({ instanceId = 'pg-snapshot-1', env = process.env, host, port, database, credentialEnv, tables, rowsPerTable = PG_SNAPSHOT_LIMITS.rowsPerTable,
  statementTimeoutMs = PG_SNAPSHOT_LIMITS.statementTimeoutMs, watchedResources = [], platform, ignore, queues: queueDecl, drainTimeoutMs, pollMs, runLease = false, runKey = RUN_KEY, connect = pgConnect, actorCapture = null }) {
  const within = (v, [min, max]) => Number.isInteger(v) && v >= min && v <= max;
  if (!within(rowsPerTable, PG_SNAPSHOT_LIMITS.rowsPerTableBounds)) throw new Error('rowsPerTable must be an integer from 1 to 200000.');
  if (!within(statementTimeoutMs, PG_SNAPSHOT_LIMITS.statementTimeoutBounds)) throw new Error('statementTimeoutMs must be an integer from 500 to 60000.');
  if (host !== '127.0.0.1') throw new Error('The Postgres host must be the literal loopback address 127.0.0.1.');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Declare the Postgres port.');
  if (typeof database !== 'string' || !IDENT.test(database)) throw new Error('Declare the Postgres database name.');
  if (!Array.isArray(tables) || !tables.length || tables.length > PG_SNAPSHOT_LIMITS.tables) throw new Error('Declare 1 to 32 tables.');
  const declared = tables.map(t => ({ table: t.table, key: t.key, schema: t.schema ?? 'public', prefix: t.resourcePrefix ?? t.table,
    readBack: t.readBack === undefined ? null : validateReadBack(t.readBack, { key: t.key, where: `${t.table} readBack` }) }));
  for (const t of declared) { quote(t.table); quote(t.key); quote(t.schema); }
  // The read-back tables, by their index among the declared ones; the salt that seals sensitive values (never leaves the observer).
  const readBackAt = declared.flatMap((t, i) => (t.readBack ? [i] : []));
  const seal = readBackAt.length ? sealWith(randomBytes(32)) : null;
  // Events and exact entries are named by table, so a table name appears once per observer.
  if (new Set(declared.map(t => t.table)).size !== declared.length) throw new Error('Each table name is declared once per observer (events are named by table; use a second observer for another schema).');
  if (!Array.isArray(watchedResources) || !watchedResources.every(r => typeof r === 'string' && r.length <= 200)) throw new Error('watchedResources lists resource strings.');
  credentialFrom(env, credentialEnv, 'pg-snapshot credential'); // validates the namespace now; the value is read at each mark
  const queues = validateQueues(queueDecl, { engine: 'postgres' }), drain = validateDrain({ drainTimeoutMs, pollMs });
  if (typeof runLease !== 'boolean') throw new Error('runLease is true or false.');
  // Attribution is on once a profile declares an ignore list (even platform "none" with no entries).
  const attribute = platform !== undefined || ignore !== undefined;
  const ignoreList = resolveIgnoreList({ engine: 'postgres', platform: platform ?? 'none', ignore: ignore ?? [], declared: declared.map(t => ({ schema: t.schema, table: t.table })), queues });
  // The catalog fingerprint leaves out the platform's own objects only (never a declared table or queue).
  const catalogExcluded = catalogExclusions(ignoreList, { declared: declared.map(t => ({ schema: t.schema, table: t.table })), queues }), catalogSql = pgCatalogSql(catalogExcluded);
  // Actor capture (./pg-actor.mjs, NC2 item 2), opt-in: { block, installedSha256, resolve? }, the installed capture, the
  // digest its installation recorded, and the resolver (./supabase-rules.mjs supabaseResolver, else the capture's own).
  // Each mark then also reads the capture's definitions and its ledger, through the reader function (this observer's role
  // needs EXECUTE on it: installActorCapture's readers), under the mark's own snapshot, after the rows. A ledger that does
  // not read leaves that mark's capture unreadable; it never fails the mark.
  if (actorCapture !== null && (typeof actorCapture !== 'object' || typeof actorCapture.installedSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(actorCapture.installedSha256) || (actorCapture.resolve !== undefined && typeof actorCapture.resolve !== 'function')))
    throw new Error('actorCapture is { block, installedSha256, resolve? }: the installed capture and its installation digest.');
  const actors = actorCapture === null ? null : { block: validateActorCapture(actorCapture.block), installed: actorCapture.installedSha256, resolve: actorCapture.resolve ?? resolveActor };
  const observer = { kind: 'postgres-snapshot-diff', instanceId };
  const snapshots = new Map();
  // baseline: start()'s catalog fingerprint; latest: the last readable mark's; drifted: a mark or window differed from it.
  let seq = 0, nextIndex = 0, leaseClient = null, baseline = null, latest = null, drifted = false;

  const login = () => {
    const secret = credentialFrom(env, credentialEnv, 'pg-snapshot credential');
    const split = typeof secret === 'string' ? secret.indexOf(':') : -1;
    if (split < 1) throw new PgError('credential-missing');
    return { host, port, database, user: secret.slice(0, split), password: secret.slice(split + 1), connectTimeoutMs: Math.min(5000, statementTimeoutMs) };
  };
  // The transaction ids whose every write lock (held or awaited) is on an ignored table or in another database: never on a
  // declared table or queue, nor any partition or child of one (by oid). Read at each of a mark's two lock reads.
  const textValues = pairs => (pairs.length ? `VALUES ${pairs.map(([s, t]) => `('${s}'::pg_catalog.text, ${t === null ? 'NULL' : `'${t}'`}::pg_catalog.text)`).join(', ')}` : 'SELECT NULL::pg_catalog.text, NULL::pg_catalog.text WHERE false');
  const quietSql = `(WITH RECURSIVE decl(nsp, rel) AS (${textValues([...declared, ...queues].map(t => [t.schema, t.table]))}),
      tree(oid) AS (SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace JOIN decl d ON d.nsp = n.nspname::pg_catalog.text AND d.rel = c.relname::pg_catalog.text
        UNION SELECT h.inhrelid FROM tree t JOIN pg_catalog.pg_inherits h ON h.inhparent = t.oid),
      ign(nsp, rel) AS (${textValues(ignoreList.platformEntries.map(e => [e.schema, e.table]))}),
      -- Each locked relation as the table it belongs to: an index, a TOAST table or an owned sequence (a write locks all three).
      locked AS (SELECT DISTINCT l.relation AS oid FROM pg_catalog.pg_locks l WHERE l.locktype = 'relation' AND l.relation IS NOT NULL),
      byindex AS (SELECT k.oid, COALESCE((SELECT x.indrelid FROM pg_catalog.pg_index x WHERE x.indexrelid = k.oid), k.oid) AS tab FROM locked k),
      bytoast AS (SELECT b.oid, COALESCE((SELECT c.oid FROM pg_catalog.pg_class c WHERE c.reltoastrelid = b.tab AND b.tab <> 0), b.tab) AS tab FROM byindex b),
      owner AS (SELECT b.oid, COALESCE((SELECT d.refobjid FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_class q ON q.oid = d.objid AND q.relkind = 'S'
          WHERE d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass AND d.objid = b.tab AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass AND d.deptype IN ('a', 'i') LIMIT 1), b.tab) AS tab FROM bytoast b),
      wl AS (SELECT l.pid, ((l.database <> 0 AND l.database IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database())) OR (NOT EXISTS (SELECT 1 FROM tree JOIN owner o ON o.tab = tree.oid WHERE o.oid = l.relation)
          AND EXISTS (SELECT 1 FROM owner o JOIN pg_catalog.pg_class c ON c.oid = o.tab JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace JOIN ign i ON i.nsp = n.nspname::pg_catalog.text AND (i.rel IS NULL OR i.rel = c.relname::pg_catalog.text) WHERE o.oid = l.relation))) AS ok
        FROM pg_catalog.pg_locks l WHERE l.locktype = 'relation' AND l.mode IN ('RowExclusiveLock', 'ShareRowExclusiveLock', 'ExclusiveLock', 'AccessExclusiveLock') AND l.pid IS NOT NULL)
      SELECT pg_catalog.array_agg(l.transactionid::text) FROM pg_catalog.pg_locks l WHERE l.locktype = 'transactionid' AND l.mode = 'ExclusiveLock' AND l.granted
        AND l.pid IN (SELECT pid FROM wl GROUP BY pid HAVING pg_catalog.bool_and(ok)))::text`;
  const queueCount = queues.length ? `/* sh:queuecount */ ${pgQueueCountSql(queues)}` : null;
  const countsOf = row => { const counts = (row ?? []).map(Number); if (counts.length !== queues.length || !counts.every(Number.isInteger)) throw new PgError('unexpected-result'); return counts; };

  // A mark: its rows in one transaction (read), bracketed by two reads of the catalog on the catalog's own session
  // (./catalog.mjs openPgCatalogSession), which never holds a lock while the mark's transaction is open.
  const take = async () => {
    const options = login(), catalogSession = await openPgCatalogSession(connect, options, catalogSql, { statementTimeoutMs });
    try {
      // A first read that did not read (a lock held past the wait) is not tried again: the mark has no fingerprint either way.
      const first = await catalogSession.read(), mark = await read(options), second = first.ok ? await catalogSession.read() : first;
      return { ...mark, catalog: bracketCatalog(first, second), catalogLatest: second };
    } finally { catalogSession.close(); }
  };
  const read = async options => {
    const client = await connect(options);
    const queryTimeoutMs = statementTimeoutMs + 1000, writers = "(SELECT pg_catalog.array_agg(transactionid::text) FROM pg_catalog.pg_locks WHERE locktype = 'transactionid')::text";
    try {
      // Round trip 1: the server and the tables, before any row is read.
      const settings = ['BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY', 'SET LOCAL search_path = pg_catalog', 'SET LOCAL row_security = off', `SET LOCAL statement_timeout = ${statementTimeoutMs}`, `SET LOCAL lock_timeout = ${statementTimeoutMs}`,
        // row::text, which is hashed, depends on these: a session default never changes a row's hash.
        "SET LOCAL DateStyle = 'ISO, MDY'", "SET LOCAL TimeZone = 'UTC'", "SET LOCAL IntervalStyle = 'postgres'", 'SET LOCAL extra_float_digits = 1', "SET LOCAL bytea_output = 'hex'", "SET LOCAL lc_monetary = 'C'"];
      // Each table, and through it every descendant, is locked before the snapshot is taken (LOCK takes no
      // snapshot): DDL that changes what a scan reads (DETACH, DROP, TRUNCATE, NO INHERIT, a rewriting ALTER)
      // cannot commit between this mark's snapshot and its scan.
      const locks = declared.map(t => `LOCK TABLE ${quote(t.schema)}.${quote(t.table)} IN ACCESS SHARE MODE`);
      const at = settings.length + locks.length; // the snapshot statement
      // The end barrier's wait, before the transaction: the counts this mark keeps are read again under its snapshot.
      let drained = null;
      if (queues.length) {
        await client.query(`SET search_path = pg_catalog; SET row_security = off; SET statement_timeout = ${statementTimeoutMs}`, { queryTimeoutMs });
        drained = await drainWait(async () => ({ clean: countsOf((await client.query(queueCount, { queryTimeoutMs }))[0]?.rows[0]).every(n => n === 0) }), drain);
      }
      const head = [...settings, ...locks,
        // With attribution, the quiet writers (above) in the same statement; with the run lease, the other runs' leases.
        `SELECT pg_catalog.pg_current_snapshot()::text, ${writers}, pg_catalog.pg_is_in_recovery()::text, pg_catalog.pg_postmaster_start_time()::text${attribute ? `, ${quietSql}` : ''}${runLease ? `, (${pgOtherRunsSql(runKey)}), (${pgOwnLeaseSql(runKey)})` : ''}`,
        ...declared.map(t => `SELECT c.oid::text, c.relkind::text, COALESCE(am.amname::text, ''), c.relfilenode::text, c.relpersistence::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace LEFT JOIN pg_catalog.pg_am am ON am.oid = c.relam WHERE n.nspname = ${literal(t.schema)} AND c.relname = ${literal(t.table)}`),
        // Every partition and inheritance child, at any depth, with its persistence and (PostgreSQL 14+,
        // read through to_jsonb so older servers answer too) whether a concurrent detach is pending.
        ...declared.map(t => `WITH RECURSIVE d(oid, pending) AS (SELECT i.inhrelid, COALESCE(pg_catalog.to_jsonb(i) ->> 'inhdetachpending', 'false') FROM pg_catalog.pg_inherits i WHERE i.inhparent = (SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = ${literal(t.schema)} AND c.relname = ${literal(t.table)}) UNION SELECT i.inhrelid, COALESCE(pg_catalog.to_jsonb(i) ->> 'inhdetachpending', 'false') FROM pg_catalog.pg_inherits i JOIN d ON i.inhparent = d.oid) SELECT c.oid::text, c.relkind::text, COALESCE(am.amname::text, ''), c.relpersistence::text, d.pending, c.relfilenode::text FROM d JOIN pg_catalog.pg_class c ON c.oid = d.oid LEFT JOIN pg_catalog.pg_am am ON am.oid = c.relam ORDER BY 1 LIMIT ${MAX_DESCENDANTS + 1}`),
        // The relations this backend holds a lock on now: LOCK lists the tree once and then waits, so a child that
        // joined during that wait is listed by the snapshot but was never locked.
        "SELECT pg_catalog.array_agg(relation::text)::text FROM pg_catalog.pg_locks WHERE pid = pg_catalog.pg_backend_pid() AND locktype = 'relation' AND granted",
        // Each read-back table's columns and their types (a domain with its base type), under the snapshot and the lock.
        ...readBackAt.map(i => `SELECT a.attnum::text, a.attname::text, a.atttypid::text, COALESCE(pg_catalog.to_jsonb(a) ->> 'attgenerated', ''), t.typtype::text, t.typbasetype::text FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_type t ON t.oid = a.atttypid WHERE a.attrelid = (SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = ${literal(declared[i].schema)} AND c.relname = ${literal(declared[i].table)}) AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum`)];
      // Fixed rows, one per relation, up to MAX_DESCENDANTS + 1 descendants each, and up to 1600 columns per read-back table.
      const first = await client.query(head.join('; '), { maxRows: 8 + declared.length * (MAX_DESCENDANTS + 2) + readBackAt.length * 1601, queryTimeoutMs });
      if (first.length !== head.length) throw new PgError('unexpected-result');
      const [snapshotText, startWriters, inRecovery, serverStart, ...extra] = first[at].rows[0] ?? [];
      const startQuiet = attribute ? extra[0] : null, otherRuns = runLease ? Number(extra[attribute ? 1 : 0] ?? NaN) : 0, ownLease = runLease ? Number(extra[attribute ? 2 : 1] ?? NaN) : 1;
      if (!Number.isInteger(otherRuns) || !Number.isInteger(ownLease)) throw new PgError('unexpected-result');
      const locked = new Set(lockIds(first[at + 1 + 2 * declared.length].rows[0]?.[0]));
      if (inRecovery !== 'false') throw new PgError('standby-refused');
      // A partitioned table has no storage; PostgreSQL 17 may record heap as its access method.
      const heapOrPartitioned = (relkind, am) => (relkind === 'r' && am === 'heap') || (relkind === 'p' && (am === '' || am === 'heap'));
      const relations = declared.map((_, i) => {
        const row = first[at + 1 + i].rows[0];
        if (!row) throw new PgError('table-missing');
        const [oid, relkind, am, filenode, persistence] = row;
        if (!heapOrPartitioned(relkind, am)) throw new PgError('relation-not-heap-table');
        // Crash recovery empties an unlogged table without a new file node, and with restart_after_crash (the
        // default) the postmaster start time does not change: its rows cannot be followed across marks.
        if (persistence !== 'p') throw new PgError(persistence === 'u' ? 'unlogged-table' : 'temporary-table');
        const descendants = first[at + 1 + declared.length + i].rows;
        if (descendants.length > MAX_DESCENDANTS) throw new PgError('too-many-descendants');
        if (!descendants.every(([, k, a]) => heapOrPartitioned(k, a))) throw new PgError('relation-not-heap-table');
        // The parent scan skips another session's temporary child and a partition being detached concurrently.
        if (descendants.some(([, , , persistence, pending]) => !['p', 'u'].includes(persistence) || pending !== 'false')) throw new PgError('descendant-not-scanned');
        if (descendants.some(([, , , persistence]) => persistence === 'u')) throw new PgError('unlogged-table');
        // The relations a row may come from: the parent if it stores rows, and every heap descendant.
        const sources = new Set([...(relkind === 'r' ? [oid] : []), ...descendants.filter(([, k]) => k === 'r').map(([o]) => o)]);
        // Storage: each relation's file node. A rewrite (TRUNCATE, VACUUM FULL, CLUSTER, ALTER COLUMN TYPE) gives a new one.
        const storage = [[oid, filenode], ...descendants.map(([o, , , , , f]) => [o, f])];
        if (!storage.every(([o]) => locked.has(o))) throw new PgError('descendant-not-locked');
        return { oid, sources, storage, signature: digest(descendants.map(([o]) => o)) };
      });
      const plans = declared.map((t, i) => (t.readBack ? readBackPlan(t, first[at + 2 + 2 * declared.length + readBackAt.indexOf(i)].rows) : null));
      // Round trip 2: the rows, then the writers again, then each relation's current file node, then commit.
      const storage = relations.flatMap(r => r.storage);
      if (!storage.every(([o]) => /^[1-9]\d{0,9}$/.test(o))) throw new PgError('unexpected-result'); // oids are placed in the next statement
      // A usable read-back table's scan also reads its declared columns, a sha256 of its other columns (an expected row's
      // remainder) and a sha256 of the whole row (any other row's).
      const readBackSql = plan => (plan?.status === 'ok' ? `${plan.columns.map(c => `, ${valueSql(quote(c.name))}`).join('')}, ${sha256Sql(`ROW(${plan.others.map(o => `r.${o}`).join(', ')})::pg_catalog.text`)}, ${sha256Sql('r::pg_catalog.text')}` : '');
      const body = [...declared.map((t, i) => `SELECT (r.${quote(t.key)})::text, r.xmin::text, pg_catalog.md5(r::text), r.tableoid::text${readBackSql(plans[i])} FROM ${quote(t.schema)}.${quote(t.table)} AS r ORDER BY 1, r.tableoid, r.ctid LIMIT ${rowsPerTable + 1}`), `SELECT ${writers}${attribute ? `, ${quietSql}` : ''}`,
        `SELECT o::text, COALESCE(pg_catalog.pg_relation_filenode(o)::text, '0') FROM pg_catalog.unnest(ARRAY[${storage.map(([o]) => `'${o}'`).join(', ')}]::pg_catalog.oid[]) AS o`,
        // The column layout, under the snapshot: a rename or retype changes what a key reads without writing a row.
        `SELECT attrelid::text, attnum::text, attname::text, atttypid::text, attisdropped::text FROM pg_catalog.pg_attribute WHERE attrelid = ANY (ARRAY[${storage.map(([o]) => `'${o}'`).join(', ')}]::pg_catalog.oid[]) AND attnum > 0 ORDER BY 1, 2`,
        // Each relation's key column, under the snapshot: whether it is virtual (PostgreSQL 18; read through to_jsonb so
        // older servers answer too) and its type's output function (a domain's is its base type's).
        ...relations.map((r, i) => `SELECT a.attrelid::text, COALESCE(pg_catalog.to_jsonb(a) ->> 'attgenerated', ''), p.provolatile::text, n.nspname::text || '.' || p.proname::text FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_type ty ON ty.oid = a.atttypid JOIN pg_catalog.pg_proc p ON p.oid = ty.typoutput JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE a.attrelid = ANY (ARRAY[${r.storage.map(([o]) => `'${o}'`).join(', ')}]::pg_catalog.oid[]) AND a.attname = ${literal(declared[i].key)} AND a.attnum > 0 AND NOT a.attisdropped ORDER BY 1`),
        // The end barrier's counts, under this mark's snapshot.
        ...(queueCount ? [queueCount] : []),
        // With actor capture the transaction stays open for round trip 3 (below); the statement keeps the indexes and returns
        // no row, so the mark's row budget is the same as without it (PR518 review NIT 6).
        actors ? 'SELECT WHERE false' : 'COMMIT'];
      const rest = await client.query(body.join('; '), { maxRows: Math.min(PG_SNAPSHOT_LIMITS.rowsPerMark, declared.length * (rowsPerTable + 1) + 1 + storage.length * 1602), queryTimeoutMs });
      if (rest.length !== body.length) throw new PgError('unexpected-result');
      // A relation rewritten after this mark's snapshot (a descendant attached after the lock) was scanned from new storage.
      const now = new Map(rest[declared.length + 1].rows);
      if (storage.some(([o, f]) => now.get(o) !== f)) throw new PgError('relation-rewritten');
      const attributes = rest[declared.length + 2].rows;
      // A read-back table's descendants may hold only columns its parent holds: the parent scan cannot see the others.
      const names = oid => new Set(attributes.filter(([o, , , , dropped]) => o === oid && dropped === 'false').map(([, , name]) => name));
      plans.forEach((plan, i) => {
        if (plan?.status !== 'ok') return;
        const parent = names(relations[i].oid);
        if (relations[i].storage.some(([o]) => o !== relations[i].oid && [...names(o)].some(n => !parent.has(n)))) plans[i] = { ...plan, status: 'descendant-columns' };
      });
      // The key must read stored bytes: exactly one column of that name in every relation (a name that is not a column
      // is a function of the row), not virtual, and of a type whose output function is immutable or depends only on a
      // setting this mark pins. A stable output reads the catalog or another type's output: an enum label, a reg* or
      // aclitem name can be renamed, and a virtual column's expression replaced, without writing a row; arrays, ranges
      // and composites can hold such values.
      relations.forEach((r, i) => {
        const rows = rest[declared.length + 3 + i].rows;
        const fixed = rel => { const own = rows.filter(([o]) => o === rel); return own.length === 1 && own[0][1] !== 'v' && (own[0][2] === 'i' || PINNED_OUTPUTS.has(own[0][3])); };
        if (!r.storage.every(([o]) => fixed(o))) throw new PgError('key-type-refused');
      });
      const endWriters = rest[declared.length].rows[0] ?? [];
      const snapshot = { ...parseSnapshot(snapshotText), serverStart, writers: [...new Set([...lockIds(startWriters), ...lockIds(endWriters[0])])],
        // Per lock read, the transaction ids holding one and those of them that were quiet (attribution only).
        ...(attribute ? { reads: [{ holders: lockIds(startWriters), quiet: lockIds(startQuiet) }, { holders: lockIds(endWriters[0]), quiet: lockIds(endWriters[1]) }] } : {}) };
      const queueState = queueCount ? (counts => ({ clean: counts.every(n => n === 0), waitedMs: drained.waitedMs, pending: pendingOf(queues, counts) }))(countsOf(rest[body.length - 2].rows[0])) : null;
      const byTable = new Map();
      declared.forEach((t, i) => {
        const rows = rest[i].rows;
        if (rows.length > rowsPerTable) throw new PgError('row-limit');
        const map = new Map(rows.map(([key, xmin, hash]) => [key, { xmin, hash }]));
        map.oid = relations[i].oid; map.descendants = relations[i].signature; map.storage = digest(relations[i].storage);
        const own = new Set(relations[i].storage.map(([o]) => o));
        map.columns = digest(attributes.filter(([o]) => own.has(o)));
        map.duplicateKeys = map.size !== rows.length || rows.some(([key]) => key === null);
        map.invalidVersions = rows.some(([, xmin]) => INVALID_XMIN.has(xmin));
        map.unverifiedSource = rows.some(([, , , tableoid]) => !relations[i].sources.has(tableoid));
        if (plans[i]) map.readBack = readBackRows(t, plans[i], rows);
        byTable.set(`${t.schema}.${t.table}`, map);
      });
      // Round trip 3 (actor capture): the capture's definitions, then its ledger, under the same snapshot as the rows.
      // Neither read can fail the mark: one that does not read leaves the capture unreadable (an error there aborts only
      // this read-only transaction, whose rows were already read).
      let actor = null;
      if (actors) {
        let verified = null, ledger = null;
        try { verified = actorVerifyRecord(await client.query(actorVerifySql(actors.block), { queryTimeoutMs }), actors.block, actors.installed); } catch {}
        if (verified) try { ledger = parseLedger((await client.query(ledgerSql(actors.block), { maxRows: PG_ACTOR_LIMITS.ledgerRows + 1, queryTimeoutMs }))[0]?.rows); } catch {}
        const status = !verified ? 'unreadable' : verified.status === 'intact' && !ledger ? 'unreadable' : verified.status;
        actor = { status, sha256: verified?.sha256 ?? null, ledger: status === 'intact' ? ledger : null };
        try { await client.query('ROLLBACK', { queryTimeoutMs }); } catch {}
      }
      return { snapshot, tables: byTable, otherRuns, ownLease, queues: queueState, ...(actors ? { actor } : {}) };
    } finally { client.close(); }
  };
  // A mark's read-back rows: each row's whole-row sha256; each expected row's declared values canonicalised (a sensitive
  // one sealed) with its remainder sha256; the other rows' values only within the budget, so a large table keeps no more
  // than its hashes (the scan has already read them all; see the header).
  const readBackRows = (t, plan, rows) => {
    if (plan.status !== 'ok') return { status: plan.status, columns: plan.columns, keyKind: plan.keyKind, rows: new Map(), shas: new Map(), othersKept: false };
    const width = 6 + plan.columns.length;
    if (rows.some(row => row.length !== width)) throw new PgError('unexpected-result');
    const valuesOf = row => Object.fromEntries(plan.columns.map((c, j) => {
      const v = canonicalValue(c.kind, row[4 + j]);
      return [c.name, v.error ? { error: v.error } : c.sealed ? seal(c.kind, v.value) : v.value];
    }));
    const expected = new Set(t.readBack.expect.map(e => e.key)), kept = new Map();
    let budget = PG_READBACK_LIMITS.otherValueChars, othersKept = true;
    for (const row of rows) {
      if (expected.has(row[0])) { kept.set(row[0], { values: valuesOf(row), rest: row[width - 2] }); continue; }
      if (!othersKept) continue;
      budget -= plan.columns.reduce((n, c, j) => n + 8 + (row[4 + j]?.length ?? 0), 0);
      if (budget >= 0) { kept.set(row[0], { values: valuesOf(row), rest: null }); continue; }
      othersKept = false;
      for (const key of [...kept.keys()]) if (!expected.has(key)) kept.delete(key);
    }
    return { status: 'ok', columns: plan.columns, keyKind: plan.keyKind, rows: kept, shas: new Map(rows.map(row => [row[0], row[width - 1]])), othersKept };
  };
  const reasonOf = error => !(error instanceof PgError) ? 'read-failed'
    : error.sqlState === '42501' ? 'permission-denied' : error.sqlState === '57014' ? 'statement-timeout' : error.sqlState === '55P03' ? 'lock-timeout'
    : error.sqlState === '42P01' ? 'table-missing' : error.sqlState === '42809' ? 'relation-not-heap-table'
    : ['row-limit', 'credential-missing', 'standby-refused', 'relation-not-heap-table', 'table-missing', 'too-many-descendants', 'descendant-not-scanned', 'descendant-not-locked', 'relation-rewritten', 'unlogged-table', 'temporary-table', 'key-type-refused'].includes(error.code) ? error.code
    : ['connection-closed', 'connect-failed'].includes(error.code) ? 'read-timeout-or-closed'
    : ['authentication-not-challenged', 'md5-authentication-refused', 'cleartext-password-refused', 'server-signature-mismatch', 'authentication-failed'].includes(error.code) ? 'authentication-refused' : 'read-failed';

  // The end mark's writers that could still commit a write this window misses. Without attribution: any transaction id in
  // the snapshot or at either lock read (as before). With it: each one except those quiet at every lock read that saw it
  // holding its id, read 1 first (an id in the snapshot that read 1 did not see stays counted).
  const norm = x => (BigInt(x) % MOD32).toString();
  const inFlight = after => {
    const s = after.snapshot;
    if (!attribute) return { counted: s.xip.length + s.writers.length, ignored: 0 };
    const all = [...new Set([...s.xip, ...s.writers].map(norm))], xip = new Set(s.xip.map(norm));
    const [r1, r2] = s.reads.map(r => ({ holders: new Set(r.holders.map(norm)), quiet: new Set(r.quiet.map(norm)) }));
    const quiet = x => (r1.holders.has(x) ? r1.quiet.has(x) && (!r2.holders.has(x) || r2.quiet.has(x)) : !xip.has(x) && r2.holders.has(x) && r2.quiet.has(x));
    const ignored = all.filter(quiet).length;
    return { counted: all.length - ignored, ignored };
  };
  // The run lease's session (runLease): opened by start(), held until stop().
  // refuse: start() refuses while another run holds a lease; taking it again after a loss never refuses (the window reads it).
  const holdLease = async ({ refuse = true } = {}) => {
    const client = await connect(login());
    try {
      const [lease, others] = await client.query(`${pgLeaseSql(runKey)}; ${pgOtherRunsSql(runKey)}`, { queryTimeoutMs: statementTimeoutMs + 1000 });
      if (lease?.rows[0]?.[0] !== 'true' || !/^\d+$/.test(others?.rows[0]?.[0] ?? '')) throw new PgError('unexpected-result');
      if (refuse && Number(others.rows[0][0]) > 0) throw new Error('shared-database: another ScopeHaven run holds a lease on this database; runs that reseed one database never share it.');
      leaseClient = client;
    } catch (error) { client.close(); throw error; }
  };

  const api = {
    kind: observer.kind, instanceId, source: 'sql-snapshot',
    scope: Object.freeze({ operations: ['insert', 'update', 'delete'], names: declared.map(t => t.table), actorAttribution: actors ? 'principal' : 'none', evidence: 'authoritative' }),
    // The baseline is the bracket's second read (the catalog just before the first mark), tried again a few times when it
    // does not read; a start without one is refused, and the lease goes with it.
    async start() {
      if (runLease && !leaseClient) await holdLease();
      try {
        const taken = await take();
        if (taken.catalogLatest.ok) baseline = taken.catalogLatest;
        else {
          const session = await openPgCatalogSession(connect, login(), catalogSql, { statementTimeoutMs });
          try { baseline = await readPgCatalogBaseline(session); } finally { session.close(); }
        }
        if (!baseline.ok) throw new Error(BASELINE_REFUSED);
      } catch (error) { leaseClient?.close(); leaseClient = null; throw error; }
    },
    async mark() {
      const index = nextIndex++;
      try { snapshots.set(index, { ok: true, at: new Date().toISOString(), ...(await take()) }); }
      catch (error) { snapshots.set(index, { ok: false, at: new Date().toISOString(), reason: reasonOf(error) }); }
      // The lease session has gone (its lock is no longer held): take the lease again, so a run that starts later sees it.
      if (runLease && snapshots.get(index).ok && snapshots.get(index).ownLease === 0) { leaseClient?.close(); leaseClient = null; try { await holdLease({ refuse: false }); } catch {} }
      // An observer marked without start() takes its first mark's fingerprint as the baseline.
      const taken = snapshots.get(index);
      if (taken.ok) baseline ??= taken.catalogLatest;
      if (taken.ok && taken.catalog.ok) { latest = taken.catalog; drifted ||= Boolean(baseline?.ok) && taken.catalog.sha256 !== baseline.sha256; }
      snapshots.delete(index - PG_SNAPSHOT_LIMITS.retainedMarks); // bounded memory: older marks are dropped
      return { index };
    },
    async collect(from, to) {
      const before = snapshots.get(from?.index), after = snapshots.get(to?.index);
      if (!before?.ok || !after?.ok) return { events: [], coverage: 'failed', reason: (!before?.ok ? before : after)?.reason || 'missing-snapshot' };
      if (!(to.index > from.index)) return { events: [], coverage: 'failed', reason: 'window-not-forward' };
      // Row identity first: rows that cannot be matched across the marks decide nothing.
      const identity = new Set();
      if (BigInt(after.snapshot.xmax) < BigInt(before.snapshot.xmax)) identity.add('xmax-regressed');
      // A restart separates the marks (a backstop: unlogged tables, which crash recovery empties, are refused).
      if (before.snapshot.serverStart !== after.snapshot.serverStart) identity.add('server-restarted');
      const completed = completedAtStart(before, after);
      for (const t of declared) {
        const a = before.tables.get(`${t.schema}.${t.table}`), b = after.tables.get(`${t.schema}.${t.table}`);
        // The relation itself first: a replaced, re-parented or rewritten table is reported alone.
        if (a.oid !== b.oid || a.descendants !== b.descendants || a.unverifiedSource || b.unverifiedSource) { identity.add('relation-unverified'); continue; }
        // Rewritten between the marks: every row gets a new version without a change of its own.
        if (a.storage !== b.storage) { identity.add('relation-rewritten'); continue; }
        // A renamed, retyped or dropped column changes what a key reads without writing a row.
        if (a.columns !== b.columns) { identity.add('columns-changed'); continue; }
        if (a.duplicateKeys || b.duplicateKeys) identity.add('duplicate-key');
        if (a.invalidVersions || b.invalidVersions) identity.add('invalid-row-version');
        if (a.duplicateKeys || b.duplicateKeys || a.invalidVersions || b.invalidVersions) continue;
        // A key whose row version is new to it must carry an id not yet committed at the start mark. One already
        // committed was not written in the window: its key text changed without a write (a new key, or labels
        // swapped between rows) or its rows were out of reach. Freezing is handled below (ambiguous, never an event).
        // The id arithmetic needs xmax to move forward.
        if (!identity.has('xmax-regressed')) for (const [key, row] of b) {
          const was = a.get(key);
          if (was && (was.xmin === row.xmin || was.xmin === FROZEN || row.xmin === FROZEN)) continue;
          if (completed(row.xmin)) { identity.add('key-without-new-version'); break; }
        }
      }
      if (identity.size) return { events: [], coverage: 'failed', reason: [...identity].sort().join(',') };
      const coincides = uncommittedAtStart(before, after);
      // Quiescent: no transaction with an id completed or was in progress anywhere during the window.
      const marks = { startXmax: before.snapshot.xmax, endXmax: after.snapshot.xmax,
        inProgress: before.snapshot.xip.length + before.snapshot.writers.length + after.snapshot.xip.length + after.snapshot.writers.length };
      const quiescent = marks.startXmax === marks.endXmax && marks.inProgress === 0;
      const events = [], exact = [];
      // Actor capture: the window's ledger is what the end mark's snapshot sees that the start mark's did not; the capture is
      // intact only when both marks verified it intact against the installation's digest. A row is attributed by the net
      // join (pg-actor attributeNetChange): every write to it in the window must resolve to one actor.
      const capture = actors ? (() => {
        // Intact only when both marks read it so; a mark without a record reads unreadable.
        const status = [before.actor, after.actor].every(m => m?.status === 'intact') ? 'intact' : [before.actor, after.actor].find(m => m && m.status !== 'intact')?.status ?? 'unreadable';
        if (status !== 'intact') return { status, entries: [] };
        return { status, entries: windowLedger(before.actor.ledger, after.actor.ledger) };
      })() : null;
      const tally = { attributed: 0, unattributed: 0, ambiguous: 0 };
      const actorOf = (t, operation, key, row) => {
        if (!actors) return null;
        const r = attributeNetChange({ xid: operation === 'delete' ? null : row.xmin, table: `${t.schema}.${t.table}`, key, op: ledgerOp(operation) }, capture.entries, actors.block, { capture: capture.status, resolve: actors.resolve });
        tally[r.actor !== null ? 'attributed' : r.reason === 'actor-ambiguous' ? 'ambiguous' : 'unattributed'] += 1;
        return r.actor;
      };
      for (const t of declared) {
        const a = before.tables.get(`${t.schema}.${t.table}`), b = after.tables.get(`${t.schema}.${t.table}`), resourceOf = key => `${t.prefix}/${key}`;
        const found = [];
        const emit = (operation, key, row) => found.push(makeEffect({ source: 'sql-snapshot', observer, seq: ++seq, observedAt: after.at, actor: actorOf(t, operation, key, row),
          operation, name: t.table, resource: resourceOf(key).slice(0, 200), outcome: 'committed', content: digest({ xmin: row.xmin, hash: row.hash }) }));
        const ambiguous = new Set();
        let violated = false;
        for (const [key, row] of b) {
          if (!a.has(key)) { emit('insert', key, row); ambiguous.add(resourceOf(key)); continue; } // inserted in the window
          const was = a.get(key);
          if (was.xmin !== row.xmin) {
            // Freezing is not an update: a change to or from the frozen id is ambiguous, never an event.
            if (was.xmin === FROZEN || row.xmin === FROZEN) { ambiguous.add(resourceOf(key)); continue; }
            emit('update', key, row);
          } else {
            if (was.hash !== row.hash) violated = true; // content changed without a new row version: never expected
            if (/^\d+$/.test(row.xmin) && row.xmin !== FROZEN && coincides(row.xmin)) ambiguous.add(resourceOf(key)); // 32-bit wraparound coincidence
          }
        }
        for (const [key, row] of a) if (!b.has(key)) { emit('delete', key, row); ambiguous.add(resourceOf(key)); }
        // Absence is claimed only about selected rows seen at both marks.
        const present = [];
        for (const resource of new Set(watchedResources)) {
          if (!resource.startsWith(`${t.prefix}/`)) continue;
          const key = resource.slice(t.prefix.length + 1);
          if (a.has(key) && b.has(key)) present.push(resource); // a selected row missing at either mark is simply not exact
        }
        const list = [...ambiguous];
        violated ||= list.length > 10000 || present.length > PG_SNAPSHOT_LIMITS.presentResources;
        // A violated table's changes are never reported: its rows decide no check.
        if (!violated) events.push(...found);
        exact.push({ name: t.table, method: 'xmin', auditSha256: null, ambiguousResources: list.slice(0, 10000), presentResources: present.slice(0, PG_SNAPSHOT_LIMITS.presentResources), marks, ...(quiescent && !list.length ? { quiescent: true } : {}),
          violated,
          basis: `row versions (xmin) of ${t.schema}.${t.table}: every committed update writes a new xmin; ${list.length} ambiguous row${list.length === 1 ? '' : 's'}`.slice(0, 512) });
      }
      // A write transaction still in progress at the end mark could commit after it; with attribution, one quiet at the
      // lock reads that saw it does not count. And the end barrier: pending work in the end mark's own snapshot.
      // And another run on this database at either mark (the run lease): no absence passes on this window, and its
      // events stay, so a fail stays a fail.
      const writers = inFlight(after), reasons = [...(writers.counted ? ['transaction-in-flight-at-window-end'] : []), ...(after.queues && !after.queues.clean ? ['queue-not-drained'] : []),
        ...(before.otherRuns > 0 || after.otherRuns > 0 ? ['shared-database'] : []),
        // The end mark found this run's own lease gone: a run that started and ended in that gap was never seen.
        ...(after.ownLease === 0 ? ['lease-lost'] : []),
        // The catalog against the run's baseline, and between the window's own marks (./catalog.mjs).
        ...catalogReasons(baseline, before.catalog, after.catalog)].sort();
      drifted ||= reasons.includes(SCHEMA_DRIFT);
      const background = attribute || queues.length || runLease ? { background: { ...(attribute ? { ignore: ignoreList.record, ignoredWriters: writers.ignored } : {}),
        ...(queues.length ? { queues: { start: before.queues, end: after.queues } } : {}), ...(runLease ? { otherRuns: Math.max(before.otherRuns, after.otherRuns) } : {}) } } : {};
      // The capture's record beside the window (collectWindow keeps only the window): counts and statuses, no captured value.
      const actorRecord = actors ? { actors: { schema: PG_ACTOR_SCHEMA, capture: { start: before.actor.status, end: after.actor.status }, ...tally } } : {};
      if (reasons.length) return { events, coverage: 'partial', reason: reasons.join(','), ...background, ...actorRecord };
      return { events, coverage: 'net-only', reason: 'net-change-between-snapshots', exact, ...background, ...actorRecord };
    },
    // The zero-row facts of a window (./supabase-rules.mjs zeroRowFacts, NC9 item 3), from the same two marks' capture reads as
    // collect(); null without actor capture.
    zeroRowFacts(from, to) {
      if (!actors) return null;
      const before = snapshots.get(from?.index), after = snapshots.get(to?.index);
      const status = [before?.actor, after?.actor].every(m => m?.status === 'intact') ? 'intact' : [before?.actor, after?.actor].find(m => m && m.status !== 'intact')?.status ?? 'unreadable';
      return zeroRowFacts({ entries: status === 'intact' ? windowLedger(before.actor.ledger, after.actor.ledger) : null, block: actors.block, capture: status, resolve: actors.resolve });
    },
    // The catalog record a run keeps for this observer (./catalog.mjs catalogRecord).
    catalog() { return catalogRecord({ engine: 'postgres', baseline, latest, drifted, excluded: catalogExcluded }); },
    async stop() { leaseClient?.close(); leaseClient = null; },
  };
  if (!readBackAt.length) return api;
  // With read-back, collect() returns the same window plus the read-back record, decided only on a window the observer
  // could follow (net-only), never on a partial or failed one.
  const windowOf = api.collect;
  return { ...api, async collect(from, to) {
    const window = await windowOf(from, to), before = snapshots.get(from?.index), after = snapshots.get(to?.index), status = window.coverage === 'net-only' ? 'ok' : window.reason;
    const violated = new Set((window.exact ?? []).filter(e => e.violated).map(e => e.name));
    return { ...window, readBack: buildReadBackRecord({ status, seal, tables: readBackAt.map(i => { const t = declared[i], name = `${t.schema}.${t.table}`;
      return { name: t.table, schema: t.schema, decl: t.readBack, violated: violated.has(t.table), before: status === 'ok' ? before.tables.get(name) : null, after: status === 'ok' ? after.tables.get(name) : null }; }) }) };
  } };
}
