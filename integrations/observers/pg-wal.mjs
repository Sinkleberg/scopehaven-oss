// Postgres logical-decoding observer (pg-wal): every row change the server committed to the declared tables between two
// marks, read from the write-ahead log through a temporary test_decoding slot. Dependency-free (./pg-wire.mjs).
//
// What it adds over pg-snapshot. It is a Postgres completeness upgrade, not the answer to the bypass corpus (19 of the 20
// SURPASS-BYPASS-01 false passes were egress-route bypasses, which confinement and a declared-channel rule address, and
// pg-snapshot already reads Postgres directly). It adds three things on the observed tables: writes made and undone
// between the marks (an insert then a delete of the same row, an update and its revert, each decoded), exact inserts and
// deletes (pg-snapshot is net-only), and absence without a quiescent cluster (a committed write elsewhere in the cluster,
// a platform's background job included, never touches an observed table's stream). Two cluster-wide conditions remain.
// The end barrier below: an open transaction that has written anywhere, uncommitted, can hold the server's flush below the
// end mark until some commit flushes it (observed live), and the window then reads wal-barrier, never a pass. And creating
// the slot (at start, or after a loss) waits for every transaction then writing anywhere in the cluster to end, at most
// the statement timeout: start() then fails, or the mark that reopens fails, never a window that reads complete.
//
// How it reads. start() opens one session, pins the output settings (DateStyle, TimeZone, IntervalStyle,
// extra_float_digits, bytea_output, lc_monetary) and creates a TEMPORARY logical slot with test_decoding. The server
// drops a temporary slot when its session ends for any reason, and while the session lives no other session can read,
// advance or drop it (55006, observed live): the application cannot consume its changes. test_decoding is read over SQL,
// never through a pgoutput publication: a publication covering UPDATE and DELETE makes those statements fail on tables
// without a replica identity, which would change the target's behaviour. Streaming of in-progress transactions is off,
// so a transaction is decoded only once it commits: a write rolled back (a whole transaction or to a savepoint) is never
// decoded, and neither is an UPDATE that row-level security filtered to zero rows. Both are invisible by design.
//
// Each mark, in order: the catalog of every declared table and descendant, the write locks held or requested on them, the
// WAL insert position, the slot's state, the locks again and the catalog again. collect(from, to) reads the slot with
// pg_logical_slot_peek_changes, never get_changes (which consumes before the read is kept), one stretch between
// consecutive marks at a time: each stretch is read up to its end mark's position and parsed against that mark's catalog
// (test_decoding prints each change under the relation name and columns it had when it was written), each decoded
// transaction is kept in this observer's own ledger, deduplicated by its commit LSN and tagged with that catalog, and only
// then is the slot advanced (pg_replication_slot_advance).
// A transaction is in the window when its commit record ends after the start mark's position and at or before the end
// mark's. The server projects every change it decodes before it leaves the server: a change to a declared table comes
// back whole (at most 1 MiB), a change to any other table only as its name, a logical message and anything else as a kind.
// Of a declared table's columns, the declared value columns are kept as values (a column whose name reads as a secret or
// personal data must be declared sensitive and is then sealed); every other column is kept only as an HMAC-SHA256 under
// a salt this observer holds, computed as the change is parsed: no undeclared value leaves the observer's process.
//
// Custody (src/custody.mjs, NC9 item 4). The WAL is written by the server, not by the application, and the slot is held
// by this observer's session. So an absence decided from it on the observed tables does not rest on anything the
// application chose to route through a recorder, and the application cannot remove a committed change from it: dropping
// or consuming the slot needs this session to end, a lost WAL segment shows as wal_status lost, and making a table
// unlogged, renaming it or its schema, or changing its replica identity (directly or through its indexes), columns,
// policies, triggers or constraints changes the catalog fingerprint. Each of those reads inconclusive with its reason, never "no change". Every window carries a source of its
// own, sql-wal (PG_WAL_SOURCE): lineage database-log, custody observer-held for an absence only. A presence it shows is a write
// the application chose to make, so a presence pass reads subject-writable, and an actor its capture names is the application's
// own claim (principal-unverified). What it cannot see: reads (cross-tenant reads included), Redis and
// in-process caches, files, direct external API calls, queues and jobs that finish after the end mark (unless declared as
// queues, below), LISTEN/NOTIFY, large objects, sequences, DDL, unlogged and temporary tables, other databases on the
// server, and a superuser who ends this session or disables decoding (that reads inconclusive). An absence check may pass
// only on the observed tables, never as "nothing else changed".
//
// Every other table (N12). The WAL names every logged table a committed transaction changed, so each one is accounted
// for: a declared table (decoded), a declared queue, a table on the ignore list (./ignore-lists/ignore-list.mjs: the
// platform's checked-in list, such as Supabase's auth audit entries or pg_cron's run details, plus the profile's own
// background tables), or unlisted. An unlisted change keeps the window from passing an absence (unlisted-table-changed):
// the effect the absence is about could have been written there instead, and a table nobody declared is never ignored.
// So does a logical decoding message (logical-message), which other decoders read as an outbox. An ignored change only
// counts. Writes the WAL never carries cannot be seen this way: an unlogged table's and a foreign table's. So each mark
// also lists the database's unlogged and foreign tables, and one that is neither declared, a queue nor ignored, at either
// mark, keeps the window from passing an absence too (table-not-in-wal). Large objects stay unseen (below).
// The end barrier (N12, ./end-barrier.mjs): with queues declared, each mark first waits, on a second session, for them to
// drain, reading in order the WAL insert position P0, the write locks on the queue tables and the pending counts, and then
// takes the mark at P. A window whose end mark was not drained, or whose WAL holds a queue change committed in (P0, P],
// reads queue-not-drained; a drain read that failed reads queue-unreadable. A queue that is unlogged, temporary, a view
// or a foreign table is refused (queue-not-in-wal): its changes are not in the WAL, so the (P0, P] check could not see them. The drain session
// reads at READ COMMITTED, so each of its statements takes its own snapshot in that order. The role then needs SELECT on
// the queue tables (only those). A queue's write locks also count as in-flight writers at the end mark.
// The shared-database rule (N12, ./run-lease.mjs): this observer's session holds the run lease; start() refuses while
// another run holds one on this database, and a window either of whose marks saw one reads partial with shared-database
// (its events stay, so a fail stays a fail).
// The catalog fingerprint (N13, ./catalog.mjs). The declared tables' own catalog above is this observer's within-window
// instrument (it carries oids and row versions, so a TRUNCATE moves it too, and it is never compared across runs). Each
// mark also reads the database's catalog fingerprint before and after its own reads, on a second short session (printing a
// view or policy locks what it names, and an error in this observer's session would end its slot), and start() reads one
// there as the run's baseline: a window whose marks' definitions differ from the baseline, or whose catalog changed
// between its marks or while one was read, reads schema-drift; one without a readable fingerprint, catalog-unreadable
// (a baseline that still does not read after a few tries refuses the start). catalog() returns the record a run keeps
// (counts and sha256 digests only).
//
// What makes a window inconclusive (coverage partial, the reasons comma-joined; the changes it did read stay events, so a
// forbidden write it saw still fails a check):
//   slot-created-after-baseline       the slot that reads the end mark did not exist at the start mark (a reconnect)
//   connection-lost                   the session (and with it the temporary slot) ended between the marks
//   wal-status-lost, slot-lost        the server removed WAL the slot needed, or the slot is gone. Any ERROR raised in
//                                     this session ends its slot too: the server drops a backend's temporary slots on
//                                     ERROR (observed live), so the generation ends and the next mark opens a new slot
//   wal-barrier                       the flushed WAL did not reach the end mark's position within barrierMs (an
//                                     uncommitted write anywhere in the cluster can hold it back until a commit)
//   schema-drift                      a declared table's catalog fingerprint (the relation, its descendants, columns,
//                                     replica identity, persistence, policies, triggers, indexes, constraints, and each
//                                     catalog row's xmin, so a change made and reverted between the marks is seen) differs
//                                     between the marks, changed while a mark was read, or differs from the catalog a
//                                     transaction in the window was parsed under
//   transaction-in-flight-at-window-end  another session or a prepared transaction holds or requests a write lock on an
//                                     observed relation at the end mark: its write could commit after it. Locks elsewhere
//                                     do not count.
//   table-truncated                   a TRUNCATE of an observed table (its rows are not listed one by one)
//   key-not-in-replica-identity       an UPDATE or DELETE whose old key the WAL does not carry (the declared key is not in
//                                     the table's replica identity); inserts on such a table stay exact, and the UPDATE's
//                                     new key stays an event
//   key-unreadable, key-too-long      a change whose key is NULL, an unchanged TOAST value or over the resource limit
//   decode-unparsed, change-too-large, decode-limit, decode-failed, statement-timeout, slot-unusable, event-limit
//                                     the stream could not be read in full
//   unlisted-table-changed            a table neither declared, a declared queue nor on the ignore list changed (above)
//   logical-message                   a logical decoding message was written in the window
//   table-not-in-wal                  an unlisted unlogged or foreign table exists at either mark (above); pg_net's queue is
//                                     the exception when a wire observer's window is complete and observer-held (wire, below)
//   queue-not-drained, queue-unreadable, queue-not-in-wal  the end barrier did not hold at the end mark (above)
//   shared-database                   another run's lease at either mark (above)
//   schema-drift, catalog-unreadable  the database's catalog fingerprint (N13, ./catalog.mjs; below)
// wire (opt-in, or attachWire before start): a pg_net wire observer (./pg-net-wire.mjs) marked with each of this observer's marks. When its window is
// complete, pg_net sent nothing in the window but its witnesses, so the table it covers (net.http_request_queue) is observed
// on the wire; when the window is also observer-held (its declared programRoles, ./pg-net-wire.mjs), the table does not count
// as table-not-in-wal. Any other wire window leaves the table counted; either way the wire window's custody and sealed record
// are kept in others.wire. Without wire the record is exactly as before.
// A mark that cannot be read fails its windows (coverage failed). A declared table that is unlogged, temporary, a system
// catalog, not a heap table, or has a temporary or unlogged descendant is refused at the mark: its writes are not decoded.
// A relation in two declared trees (a table and its own partition, both declared) reports each change under both names.
//
// TOAST. An UPDATE that leaves a large out-of-line value unchanged carries a marker, not the value. A value check on such
// a column reads an earlier change in the same window, or is inconclusive (toast-unchanged): the observer never reads
// the table itself.
//
// Requirements: PostgreSQL 13 or later (run live on 15 and 17) with wal_level = logical, and a role with the REPLICATION
// attribute (it needs no SELECT on any table). Host: literal 127.0.0.1 (pg-wire). The role can decode every table's changes in the database;
// the projection above is what keeps the other tables' values in the server.
import { createHmac, randomBytes } from 'node:crypto';
import { pgConnect, PgError } from './pg-wire.mjs';
import { digest } from '../../src/domain.mjs';
import { looksSensitive, sealWith } from '../../src/pg-readback.mjs';
import { makeEffect, credentialFrom, EFFECT_LIMITS } from './events.mjs';
import { resolveIgnoreList } from './ignore-lists/ignore-list.mjs';
import { validateQueues, validateDrain, pgQueueCountSql, pgQueueTreeSql, drainWait, pendingOf } from './end-barrier.mjs';
import { RUN_KEY, pgLeaseSql, pgOtherRunsSql } from './run-lease.mjs';
import { catalogExclusions, pgCatalogSql, openPgCatalogSession, bracketCatalog, readPgCatalogBaseline, catalogReasons, catalogRecord, SCHEMA_DRIFT, BASELINE_REFUSED } from './catalog.mjs';
import { validateActorCapture, verifySql as actorVerifySql, verifyRecord as actorVerifyRecord, ledgerSql, parseLedger, attributeChange, ledgerOp, resolveActor, schemaOf, PG_ACTOR_SCHEMA, PG_ACTOR_LIMITS } from './pg-actor.mjs';

export const PG_WAL_SCHEMA = 'scopehaven-pg-wal/1';
// The effect source every window carries (NC9 item 4): its own, sql-wal, whose lineage is database-log and whose custody is
// observer-held (src/effect-lineage.mjs, src/custody.mjs). Before the wiring it carried sql-snapshot.
export const PG_WAL_SOURCE = 'sql-wal';
export const PG_WAL_LIMITS = Object.freeze({ tables: 32, valueColumns: 16, descendants: 1000, statementTimeoutMs: 20000, statementTimeoutBounds: [500, 60000],
  barrierMs: 3000, barrierBounds: [100, 30000], lineBytes: 1024 * 1024, valueChars: 4096, rowsPerRead: 200000, ledgerChanges: 200000,
  retainedMarks: 128, changesPerTable: 1000, otherNames: 32 });

const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const literal = name => { if (!IDENT.test(name)) throw new Error(`Unsupported SQL identifier "${String(name).slice(0, 64)}".`); return `'${name}'`; };
const LSN = /^[0-9A-F]{1,8}\/[0-9A-F]{1,8}$/;
export const lsnValue = text => {
  if (typeof text !== 'string' || !LSN.test(text)) throw new PgError('lsn-unreadable');
  const [hi, lo] = text.split('/');
  return (BigInt(`0x${hi}`) << 32n) | BigInt(`0x${lo}`);
};
const lsnText = value => `${(value >> 32n).toString(16).toUpperCase()}/${(value & 0xffffffffn).toString(16).toUpperCase()}`;
// Output functions that are not immutable only because they read a setting the session pins (as pg-snapshot).
const PINNED_OUTPUTS = ['pg_catalog.date_out', 'pg_catalog.timestamp_out', 'pg_catalog.timestamptz_out', 'pg_catalog.interval_out', 'pg_catalog.cash_out'];
const WRITE_LOCKS = ['RowExclusiveLock', 'ShareRowExclusiveLock', 'ExclusiveLock', 'AccessExclusiveLock'];
const TOAST = Object.freeze({ toast: 'unchanged' });
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// One value as test_decoding prints it: 'quoted' text with '' doubled, B'bits', an unquoted number or boolean (only the
// built-in numeric types and boolean print unquoted), null, or the unchanged-TOAST marker. Returns { value, end } or null.
function readValue(line, pos) {
  if (line.startsWith("'", pos)) {
    let out = '', at = pos + 1;
    for (;;) {
      const q = line.indexOf("'", at);
      if (q < 0) return null;
      out += line.slice(at, q);
      if (line[q + 1] === "'") { out += "'"; at = q + 2; continue; }
      return { value: { text: out }, end: q + 1 };
    }
  }
  if (line.startsWith("B'", pos)) {
    const q = line.indexOf("'", pos + 2);
    return q < 0 || !/^[01]*$/.test(line.slice(pos + 2, q)) ? null : { value: { text: line.slice(pos + 2, q) }, end: q + 1 };
  }
  const space = line.indexOf(' ', pos), end = space < 0 ? line.length : space, token = line.slice(pos, end);
  if (token === 'null') return { value: null, end };
  if (token === 'unchanged-toast-datum') return { value: TOAST, end };
  return /^(?:-?(?:\d+(?:\.\d+)?(?:e[+-]?\d+)?|Infinity)|NaN|true|false)$/i.test(token) ? { value: { text: token }, end } : null;
}
// A tuple: " label:value" for each column, labels exactly as the mark's catalog prints them (quote_ident(name)[type]) and
// in attnum order. A new tuple holds every column; an old key holds a subset (test_decoding skips its nulls). stop ends it.
function readTuple(line, pos, columns, { subset = false, stop = null } = {}) {
  const values = new Map();
  let next = 0;
  while (pos < line.length) {
    if (stop !== null && line.startsWith(stop, pos)) break;
    if (line[pos] !== ' ') return null;
    pos += 1;
    let j = next;
    if (subset) while (j < columns.length && !line.startsWith(`${columns[j].label}:`, pos)) j += 1;
    if (j >= columns.length || !line.startsWith(`${columns[j].label}:`, pos)) return null;
    pos += columns[j].label.length + 1;
    const v = readValue(line, pos);
    if (!v) return null;
    values.set(columns[j].name, v.value);
    pos = v.end; next = j + 1;
  }
  if (!subset && next !== columns.length) return null;
  return { values, end: pos };
}
// One test_decoding change line of a declared relation ({ qualified, columns: [{ name, label }] }): { op, tuple, oldTuple }
// with Maps of column name to { text }, null or the TOAST marker; or { op: 'truncate' }; or { error: 'decode-unparsed' }.
export function parseChangeLine(line, relation) {
  const head = `table ${relation.qualified}: `, unparsed = { error: 'decode-unparsed' };
  if (typeof line !== 'string' || !line.startsWith(head)) return unparsed;
  const pos = head.length, op = ['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE'].find(o => line.startsWith(`${o}:`, pos));
  if (!op) return unparsed;
  if (op === 'TRUNCATE') return { op: 'truncate' };
  const at = pos + op.length + 1, none = ' (no-tuple-data)';
  if (line.slice(at) === none) return op === 'INSERT' ? unparsed : { op: op.toLowerCase(), tuple: null, oldTuple: null };
  if (op === 'INSERT') { const t = readTuple(line, at, relation.columns); return t && t.end === line.length ? { op: 'insert', tuple: t.values, oldTuple: null } : unparsed; }
  if (op === 'DELETE') { const t = readTuple(line, at, relation.columns, { subset: true }); return t && t.end === line.length && t.values.size ? { op: 'delete', tuple: null, oldTuple: t.values } : unparsed; }
  let oldTuple = null, from = at;
  if (line.startsWith(' old-key:', at)) {
    const old = readTuple(line, at + ' old-key:'.length, relation.columns, { subset: true, stop: ' new-tuple:' });
    if (!old || !line.startsWith(' new-tuple:', old.end) || !old.values.size) return unparsed;
    oldTuple = old.values; from = old.end + ' new-tuple:'.length;
  }
  const t = readTuple(line, from, relation.columns);
  return t && t.end === line.length ? { op: 'update', tuple: t.values, oldTuple } : unparsed;
}
// The relations a TRUNCATE line names ('table a.b, "C".d: TRUNCATE: ...'), as quoted qualified names, or null.
function truncatedNames(line) {
  const tail = /: TRUNCATE:(?: \(no-flags\)| restart_seqs| cascade| restart_seqs cascade)$/.exec(line);
  if (!line.startsWith('table ') || !tail) return null;
  const list = line.slice('table '.length, tail.index), names = [];
  const ident = /"(?:[^"]|"")+"|[^",. ]+/y;
  for (let pos = 0; pos < list.length;) {
    const parts = [];
    for (let k = 0; k < 2; k++) {
      ident.lastIndex = pos;
      const m = ident.exec(list);
      if (!m) return null;
      parts.push(m[0]); pos = ident.lastIndex;
      if (k === 0) { if (list[pos] !== '.') return null; pos += 1; }
    }
    names.push(parts.join('.'));
    if (pos < list.length) { if (!list.startsWith(', ', pos)) return null; pos += 2; }
  }
  return names;
}
// A quoted qualified name's schema and table, unquoted.
const unquote = part => (part.startsWith('"') ? part.slice(1, -1).replace(/""/g, '"') : part);
function splitQualified(text) {
  const m = /^("(?:[^"]|"")+"|[^".]+)\.("(?:[^"]|"")+"|[^".]+)$/.exec(String(text ?? ''));
  return m ? { schema: unquote(m[1]), table: unquote(m[2]) } : null;
}

// tables: [{ table, key, schema? ('public'), resourcePrefix?, values? ([column]), sensitive? ([column]), reveal? ([column]) }]
// platform: a built-in ignore list ('none', 'supabase'); ignore: the profile's own 'schema' or 'schema.table' entries.
// queues: the end barrier's queue or job tables (./end-barrier.mjs), with drainTimeoutMs and pollMs. runLease: hold and
// check the run lease (./run-lease.mjs; runKey is a test seam, never from a configuration).
export function createPgWalObserver({ instanceId = 'pg-wal-1', env = process.env, host, port, database, credentialEnv, tables, platform = 'none', ignore = [],
  queues: queueDecl, drainTimeoutMs, pollMs, runLease = true, runKey = RUN_KEY,
  statementTimeoutMs = PG_WAL_LIMITS.statementTimeoutMs, barrierMs = PG_WAL_LIMITS.barrierMs, connect = pgConnect, actorCapture = null, wire = null }) {
  const within = (v, [min, max]) => Number.isInteger(v) && v >= min && v <= max;
  if (!within(statementTimeoutMs, PG_WAL_LIMITS.statementTimeoutBounds)) throw new Error('statementTimeoutMs must be an integer from 500 to 60000.');
  if (!within(barrierMs, PG_WAL_LIMITS.barrierBounds)) throw new Error('barrierMs must be an integer from 100 to 30000.');
  if (host !== '127.0.0.1') throw new Error('The Postgres host must be the literal loopback address 127.0.0.1.');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Declare the Postgres port.');
  if (typeof database !== 'string' || !IDENT.test(database)) throw new Error('Declare the Postgres database name.');
  if (!Array.isArray(tables) || !tables.length || tables.length > PG_WAL_LIMITS.tables) throw new Error('Declare 1 to 32 tables.');
  const list = (t, field) => {
    const v = t[field] ?? [];
    if (!Array.isArray(v) || v.length > PG_WAL_LIMITS.valueColumns || !v.every(c => typeof c === 'string' && IDENT.test(c)) || new Set(v).size !== v.length) throw new Error(`${t.table} ${field} lists up to ${PG_WAL_LIMITS.valueColumns} distinct column names.`);
    return v;
  };
  const declared = tables.map(t => {
    if (t === null || typeof t !== 'object' || Object.keys(t).some(k => !['table', 'key', 'schema', 'resourcePrefix', 'values', 'sensitive', 'reveal'].includes(k))) throw new Error('A pg-wal table is { table, key, schema?, resourcePrefix?, values?, sensitive?, reveal? }.');
    const d = { table: t.table, key: t.key, schema: t.schema ?? 'public', prefix: t.resourcePrefix ?? t.table, values: list(t, 'values'), sensitive: list(t, 'sensitive'), reveal: list(t, 'reveal') };
    literal(d.table); literal(d.key); literal(d.schema);
    if (typeof d.prefix !== 'string' || !d.prefix || d.prefix.length > 64) throw new Error('resourcePrefix is 1 to 64 characters.');
    if (d.values.includes(d.key)) throw new Error(`${d.table}: the key is never a value column.`);
    if (!d.sensitive.every(c => d.values.includes(c)) || !d.reveal.every(c => d.sensitive.includes(c))) throw new Error(`${d.table}: sensitive lists value columns, and reveal lists sensitive ones.`);
    const undeclared = d.values.find(c => looksSensitive(c) && !d.sensitive.includes(c));
    if (undeclared !== undefined) throw new Error(`${d.table}: the value column ${undeclared} reads as a secret or personal data; declare it sensitive.`);
    return Object.freeze(d);
  });
  // Events are named by table, as pg-snapshot's are.
  if (new Set(declared.map(t => t.table)).size !== declared.length) throw new Error('Each table name is declared once per observer.');
  const queues = validateQueues(queueDecl, { engine: 'postgres' }), drain = validateDrain({ drainTimeoutMs, pollMs });
  // Actor capture (./pg-actor.mjs, NC2 item 2), opt-in: { block, installedSha256, resolve? }, as for pg-snapshot. Each mark
  // reads the capture's definitions on a short session of its own (an error there never reaches the slot's session), and
  // each window reads the capture's ledger the same way, through the reader function (this observer's role needs EXECUTE
  // on it). Every decoded change is joined on its own transaction id (pg-actor attributeChange): the WAL lists each write,
  // so the join is per write, not per row. The audit table's own changes are the capture's, counted apart (others.capture),
  // never on the profile's ignore list: they are written only in the transactions of the captured writes.
  if (actorCapture !== null && (typeof actorCapture !== 'object' || typeof actorCapture.installedSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(actorCapture.installedSha256) || (actorCapture.resolve !== undefined && typeof actorCapture.resolve !== 'function')))
    throw new Error('actorCapture is { block, installedSha256, resolve? }: the installed capture and its installation digest.');
  const wireShape = w => w !== null && typeof w === 'object' && ['start', 'mark', 'collect', 'stop'].every(f => typeof w[f] === 'function') && Array.isArray(w.covers);
  if (wire !== null && !wireShape(wire)) throw new Error('wire is a pg_net wire observer (./pg-net-wire.mjs).');
  let begun = false;
  const actors = actorCapture === null ? null : { block: validateActorCapture(actorCapture.block), installed: actorCapture.installedSha256, resolve: actorCapture.resolve ?? resolveActor };
  // The one ignore-list reader (./ignore-lists/ignore-list.mjs): a declared table or queue is never ignored.
  const ignoreList = resolveIgnoreList({ engine: 'postgres', platform, ignore, declared: declared.map(t => ({ schema: t.schema, table: t.table })), queues });
  // Declared tables that are also queues (their changes are decoded as declared ones).
  const queueTables = new Set(declared.flatMap((t, i) => (queues.some(q => q.schema === t.schema && q.table === t.table) ? [i] : [])));
  credentialFrom(env, credentialEnv, 'pg-wal credential'); // validates the namespace now; the value is read when a session opens

  const salt = randomBytes(32), sealer = sealWith(salt);
  const columnDigest = (column, value) => createHmac('sha256', salt).update(`${PG_WAL_SCHEMA} column\n${column}\n${value}`).digest('hex');
  const observer = { kind: 'postgres-wal-decode', instanceId };
  const queryTimeoutMs = statementTimeoutMs + 2000;
  const marks = new Map(), generations = new Map(), ledgers = new Map();
  // The database's catalog fingerprint leaves out the platform's own objects only (never a declared table or queue).
  const dbExcluded = catalogExclusions(ignoreList, { declared: declared.map(t => ({ schema: t.schema, table: t.table })), queues }), dbCatalogSql = pgCatalogSql(dbExcluded);
  // baseline: start()'s fingerprint; latest: the last readable mark's; drifted: a mark or window differed from it.
  let session = null, generation = 0, seq = 0, nextIndex = 0, chain = Promise.resolve(), baseline = null, latest = null, drifted = false;
  const serial = fn => { const run = chain.then(fn, fn); chain = run.catch(() => {}); return run; };
  const lost = error => error instanceof PgError && ['connection-closed', 'connection-error', 'connect-failed'].includes(error.code);
  const reasonOf = error => !(error instanceof PgError) ? 'read-failed' : lost(error) ? 'connection-lost'
    : error.sqlState === '42501' ? 'permission-denied' : error.sqlState === '57014' ? 'statement-timeout' : error.sqlState === '42704' ? 'slot-lost'
    : error.sqlState === '55006' ? 'slot-not-held' : error.sqlState === '55000' ? 'slot-unusable'
    : ['credential-missing', 'wal-level-not-logical', 'server-too-old', 'standby-refused', 'table-missing', 'too-many-descendants', 'relation-not-heap-table', 'unlogged-table',
      'temporary-table', 'descendant-not-decoded', 'system-catalog-refused', 'key-type-refused', 'lsn-unreadable', 'catalog-unreadable', 'row-limit', 'slot-lost', 'wal-status-lost', 'slot-not-held'].includes(error.code) ? error.code
    : ['authentication-not-challenged', 'md5-authentication-refused', 'cleartext-password-refused', 'server-signature-mismatch', 'authentication-failed'].includes(error.code) ? 'authentication-refused' : 'read-failed';
  // Ends a session's generation. The server drops a backend's temporary slots when any statement of it raises an ERROR
  // (PostgresMain's error recovery, observed live), and a lost connection ends the session itself: either way the slot is
  // gone, so the generation ends with that reason and the next mark opens a new one.
  const retire = (s, reason) => {
    if (!s) return;
    if (session === s) session = null;
    const g = generations.get(s.generation);
    if (g && !g.lost) g.lost = reason;
    s.client.close();
  };
  const q = async (sql, maxRows = 10000) => {
    const s = session;
    try { return await s.client.query(sql, { queryTimeoutMs, maxRows }); }
    catch (error) {
      // A client-side limit (row-limit) reads the rest of the reply and leaves the server, and the slot, as they were.
      if (lost(error) || (error instanceof PgError && error.sqlState)) retire(s, lost(error) ? 'connection-lost' : 'slot-lost');
      throw error;
    }
  };

  // The ScopeHaven credential as { user, password } (read when a session opens, never kept).
  const login = () => {
    const secret = credentialFrom(env, credentialEnv, 'pg-wal credential');
    const split = typeof secret === 'string' ? secret.indexOf(':') : -1;
    if (split < 1) throw new PgError('credential-missing');
    return { host, port, database, user: secret.slice(0, split), password: secret.slice(split + 1), connectTimeoutMs: Math.min(5000, statementTimeoutMs) };
  };
  // A new session and a new temporary slot: one generation. The slot's consistent point is its first readable position.
  // Returns the number of other runs holding a lease on this database (0 with the lease off).
  const open = async () => {
    const client = await connect(login());
    const slot = `scopehaven_wal_${randomBytes(8).toString('hex')}`;
    try {
      // Session settings: test_decoding prints values with this session's output settings, so they are pinned here.
      const results = await client.query(['/* sh:session */ SET search_path = pg_catalog', 'SET standard_conforming_strings = on', "SET DateStyle = 'ISO, MDY'", "SET TimeZone = 'UTC'",
        "SET IntervalStyle = 'postgres'", 'SET extra_float_digits = 1', "SET bytea_output = 'hex'", "SET lc_monetary = 'C'", `SET statement_timeout = ${statementTimeoutMs}`, `SET lock_timeout = ${statementTimeoutMs}`,
        "/* sh:server */ SELECT pg_catalog.current_setting('wal_level'), pg_catalog.current_setting('server_version_num'), pg_catalog.pg_is_in_recovery()::text, pg_catalog.current_setting('wal_block_size'), (SELECT setting FROM pg_catalog.pg_settings WHERE name = 'wal_segment_size')",
        ...(runLease ? [pgLeaseSql(runKey), pgOtherRunsSql(runKey)] : [])].join(';\n'), { queryTimeoutMs });
      const [walLevel, version, recovery, blockSize, segmentSize] = results.at(runLease ? -3 : -1)?.rows[0] ?? [];
      if (runLease && results.at(-2)?.rows[0]?.[0] !== 'true') throw new PgError('lease-unavailable');
      const otherRuns = runLease ? Number(results.at(-1)?.rows[0]?.[0] ?? NaN) : 0;
      if (!Number.isInteger(otherRuns)) throw new PgError('catalog-unreadable');
      if (recovery !== 'false') throw new PgError('standby-refused');
      if (!(Number(version) >= 130000)) throw new PgError('server-too-old');
      if (walLevel !== 'logical') throw new PgError('wal-level-not-logical');
      if (!/^[1-9]\d{2,5}$/.test(blockSize ?? '') || !/^[1-9]\d{5,10}$/.test(segmentSize ?? '')) throw new PgError('catalog-unreadable');
      // Waits for transactions already writing to finish (the slot's consistent point), at most the statement timeout.
      const [created] = await client.query(`/* sh:create */ SELECT lsn::text FROM pg_catalog.pg_create_logical_replication_slot('${slot}', 'test_decoding', true)`, { queryTimeoutMs });
      const consistent = lsnValue(created?.rows[0]?.[0]);
      generation += 1;
      session = { client, slot, generation, streamOption: Number(version) >= 140000, blockSize: BigInt(blockSize), segmentSize: BigInt(segmentSize) };
      generations.set(generation, { slot, consistent });
      ledgers.set(generation, { readThrough: consistent, txns: [], ends: new Set(), changes: 0 });
      return otherRuns;
    } catch (error) { client.close(); throw error; }
  };
  // The end barrier's drain read, on its own short session (an ERROR there never touches the slot): the WAL insert
  // position P0, then the write locks other sessions hold or await on the queue tables, then the pending counts, each a
  // statement of its own so each reads after the one before. Clean when no lock and no pending row. names: every queue
  // table and descendant as test_decoding prints it, for the (P0, P] check at collect.
  const queueNamesSql = `/* sh:queuenames */ SELECT pg_catalog.quote_ident(n.nspname) || '.' || pg_catalog.quote_ident(c.relname), c.relpersistence::text || c.relkind::text FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid IN ${queues.length ? pgQueueTreeSql(queues) : '(SELECT NULL::pg_catalog.oid)'} ORDER BY 1`;
  const queueLocksSql = `/* sh:queuelocks */ SELECT pg_catalog.count(*)::text FROM pg_catalog.pg_locks l WHERE l.locktype = 'relation'
      AND l.database = (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database()) AND l.relation IN ${queues.length ? pgQueueTreeSql(queues) : '(SELECT NULL::pg_catalog.oid)'}
      AND l.mode IN (${WRITE_LOCKS.map(m => `'${m}'`).join(', ')}) AND l.pid IS DISTINCT FROM pg_catalog.pg_backend_pid()`;
  const drainRead = async () => {
    let client;
    try {
      client = await connect(login());
      await client.query(`/* sh:drainsession */ SET search_path = pg_catalog;\nSET row_security = off;\nSET default_transaction_isolation = 'read committed';\nSET statement_timeout = ${statementTimeoutMs}`, { queryTimeoutMs });
      return await drainWait(async () => {
        const [p0, locks, counts, names] = await client.query(['/* sh:drainlsn */ SELECT pg_catalog.pg_current_wal_insert_lsn()::text', queueLocksSql, `/* sh:queuecount */ ${pgQueueCountSql(queues)}`, queueNamesSql].join(';\n'), { queryTimeoutMs, maxRows: 10000 });
        const pending = (counts?.rows[0] ?? []).map(Number), held = Number(locks?.rows[0]?.[0] ?? NaN);
        if (pending.length !== queues.length || !pending.every(Number.isInteger) || !Number.isInteger(held)) throw new PgError('catalog-unreadable');
        // A queue the WAL does not carry (unlogged, temporary, a view, a foreign table): the (P0, P] check would be blind to it.
        if ((names?.rows ?? []).some(r => !['pr', 'pp'].includes(r[1]))) throw new PgError('queue-not-in-wal');
        return { clean: held === 0 && pending.every(n => n === 0), p0: lsnValue(p0?.rows[0]?.[0]), locks: held, pending: pendingOf(queues, pending), names: new Set((names?.rows ?? []).map(r => r[0])) };
      }, drain);
    } catch (error) {
      return { clean: false, error: error instanceof PgError && error.sqlState === '42501' ? 'permission-denied' : error instanceof PgError && error.code === 'queue-not-in-wal' ? 'queue-not-in-wal' : 'queue-unreadable',
        p0: null, locks: null, pending: [], names: new Set(), waitedMs: null };
    } finally { client?.close(); }
  };
  const drop = async () => {
    const s = session; session = null;
    if (!s) return;
    try { await s.client.query(`/* sh:drop */ SELECT pg_catalog.pg_drop_replication_slot('${s.slot}')`, { queryTimeoutMs }); } catch {} finally { s.client.close(); }
  };

  // The catalog of every declared table and descendant, one row per relation: the relation, its columns, the key column's
  // output function, whether the key is in the replica identity, its policies, triggers, indexes and constraints, and its
  // schema. A policy's expressions are read as their stored trees, never printed: printing one with a subquery locks the
  // relations it names, so an application holding one of them could stall this session past its timeout and end the slot.
  // The trees carry oids, which is fine here: this fingerprint is compared within a run only. Every catalog row's xmin is part of it, so a change made and reverted between two marks still changes the
  // fingerprint: a replica identity moved through its indexes (a primary key dropped and added again), and a table or its
  // schema renamed away and back (test_decoding prints a change made meanwhile under the other name).
  const catalogSql = () => `/* sh:catalog */ WITH RECURSIVE declared(i, nsp, rel, key) AS (VALUES ${declared.map((t, i) => `(${i}, ${literal(t.schema)}, ${literal(t.table)}, ${literal(t.key)})`).join(', ')}),
    roots AS (SELECT d.i, c.oid FROM declared d JOIN pg_catalog.pg_namespace n ON n.nspname = d.nsp JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relname = d.rel),
    tree(i, oid) AS (SELECT i, oid FROM roots UNION SELECT t.i, h.inhrelid FROM tree t JOIN pg_catalog.pg_inherits h ON h.inhparent = t.oid)
    SELECT t.i::text, c.oid::text, c.xmin::text, pg_catalog.quote_ident(n.nspname) || '.' || pg_catalog.quote_ident(c.relname), c.relkind::text, COALESCE(am.amname::text, ''), c.relpersistence::text,
      c.relreplident::text, c.relrowsecurity::text, c.relforcerowsecurity::text, EXISTS (SELECT 1 FROM roots r WHERE r.i = t.i AND r.oid = c.oid)::text,
      COALESCE((SELECT pg_catalog.json_agg(pg_catalog.json_build_array(a.attnum, pg_catalog.quote_ident(a.attname) || '[' || pg_catalog.format_type(a.atttypid, NULL) || ']', a.attname, a.attgenerated, a.xmin::text) ORDER BY a.attnum)
        FROM pg_catalog.pg_attribute a WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped)::text, '[]'),
      (SELECT pg_catalog.json_build_array(pg_catalog.count(*), pg_catalog.bool_and(p.provolatile = 'i' OR (pn.nspname || '.' || p.proname) = ANY (ARRAY[${PINNED_OUTPUTS.map(o => `'${o}'`).join(', ')}])),
        pg_catalog.bool_or(a.attgenerated = 'v'), pg_catalog.max(pn.nspname || '.' || p.proname))
        FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_type ty ON ty.oid = a.atttypid JOIN pg_catalog.pg_proc p ON p.oid = ty.typoutput JOIN pg_catalog.pg_namespace pn ON pn.oid = p.pronamespace
        WHERE a.attrelid = c.oid AND a.attname = d.key AND a.attnum > 0 AND NOT a.attisdropped)::text,
      (CASE c.relreplident WHEN 'f' THEN true WHEN 'n' THEN false ELSE EXISTS (SELECT 1 FROM pg_catalog.pg_index x JOIN pg_catalog.pg_attribute ka ON ka.attrelid = x.indrelid AND ka.attname = d.key AND ka.attnum > 0 AND NOT ka.attisdropped
        WHERE x.indrelid = c.oid AND (CASE c.relreplident WHEN 'd' THEN x.indisprimary ELSE x.indisreplident END) AND ka.attnum = ANY (x.indkey::pg_catalog.int2[])) END)::text,
      COALESCE((SELECT pg_catalog.json_agg(pg_catalog.json_build_array(po.polname, po.polcmd, po.polpermissive, po.polroles::text, po.polqual::text, po.polwithcheck::text, po.xmin::text) ORDER BY po.polname)
        FROM pg_catalog.pg_policy po WHERE po.polrelid = c.oid)::text, '[]'),
      COALESCE((SELECT pg_catalog.json_agg(pg_catalog.json_build_array(tg.tgname, tg.tgfoid::text, tg.tgtype, tg.tgenabled, tg.tgisinternal, tg.xmin::text) ORDER BY tg.tgname)
        FROM pg_catalog.pg_trigger tg WHERE tg.tgrelid = c.oid)::text, '[]'),
      COALESCE((SELECT pg_catalog.json_agg(pg_catalog.json_build_array(x.indexrelid::text, x.indisprimary, x.indisreplident, x.indisunique, x.indisvalid, x.indkey::text, x.xmin::text) ORDER BY x.indexrelid)
        FROM pg_catalog.pg_index x WHERE x.indrelid = c.oid)::text, '[]'),
      COALESCE((SELECT pg_catalog.json_agg(pg_catalog.json_build_array(co.conname, co.contype, co.conindid::text, co.xmin::text) ORDER BY co.conname, co.oid)
        FROM pg_catalog.pg_constraint co WHERE co.conrelid = c.oid)::text, '[]'),
      n.oid::text, n.xmin::text
    FROM tree t JOIN declared d ON d.i = t.i JOIN pg_catalog.pg_class c ON c.oid = t.oid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace LEFT JOIN pg_catalog.pg_am am ON am.oid = c.relam
    ORDER BY 1, 2 LIMIT ${declared.length * (PG_WAL_LIMITS.descendants + 1) + 1}`;
  // The relations to decode, by quoted qualified name: each declared table and every descendant, with its column labels.
  // A relation in two declared trees (a table and its own partition, both declared) is listed once per tree, so its
  // changes are events under both names, as pg-snapshot reports them.
  const relationsOf = result => {
    const rows = result?.rows ?? [];
    if (!rows.every(r => r.length === 20 && /^\d+$/.test(r[0]) && /^[1-9]\d{0,9}$/.test(r[1]))) throw new PgError('catalog-unreadable');
    const relations = [];
    declared.forEach((_, i) => {
      const own = rows.filter(r => r[0] === String(i));
      if (own.filter(r => r[10] === 'true').length !== 1) throw new PgError('table-missing');
      if (own.length > PG_WAL_LIMITS.descendants + 1) throw new PgError('too-many-descendants');
      for (const [, oid, , qualified, relkind, am, persistence, replident, , , root, columnsJson, keyJson, covered] of own) {
        // A partitioned table stores no rows (PostgreSQL 17 may record heap as its access method); every other one is a heap table.
        if (!((relkind === 'r' && am === 'heap') || (relkind === 'p' && (am === '' || am === 'heap')))) throw new PgError('relation-not-heap-table');
        // Unlogged and temporary relations are not in the WAL: refused for the declared table and every descendant.
        if (persistence !== 'p') throw new PgError(root === 'true' ? (persistence === 'u' ? 'unlogged-table' : 'temporary-table') : 'descendant-not-decoded');
        // System catalogs (below FirstNormalObjectId) are never decoded as row changes.
        if (Number(oid) < 16384) throw new PgError('system-catalog-refused');
        let columns, key;
        try { columns = JSON.parse(columnsJson); key = JSON.parse(keyJson); } catch { throw new PgError('catalog-unreadable'); }
        // The key reads stored bytes: exactly one column of that name, not virtual, with an immutable (or pinned-setting) output.
        if (!Array.isArray(key) || key[0] !== 1 || key[1] !== true || key[2] === true) throw new PgError('key-type-refused');
        if (relkind === 'p') continue; // its rows are decoded under its partitions' names
        // A blank-padded char key (or a domain over one) reads without its padding, as pg-snapshot's ::text reads it.
        relations.push({ index: i, oid, qualified, replident, keyCovered: covered === 'true', keyChar: key[3] === 'pg_catalog.bpcharout',
          columns: columns.map(([, label, name]) => ({ label, name })) });
      }
    });
    return relations;
  };
  const slotSql = () => `/* sh:slot */ SELECT s.wal_status::text, (s.active_pid = pg_catalog.pg_backend_pid())::text FROM pg_catalog.pg_replication_slots s WHERE s.slot_name = '${session.slot}'`;
  const slotProblem = result => { const row = result?.rows[0]; return !row ? 'slot-lost' : row[0] === 'lost' ? 'wal-status-lost' : row[1] !== 'true' ? 'slot-not-held' : null; };

  // The capture's definitions (at a mark) and its ledger (for a window), each on a short session of its own.
  const shortQuery = async (sql, maxRows) => { const s = await connect(login()); try { return await s.query(sql, { queryTimeoutMs, maxRows }); } finally { s.close(); } };
  const actorMark = async () => { try { return actorVerifyRecord(await shortQuery(actorVerifySql(actors.block), 10000), actors.block, actors.installed); } catch { return { status: 'unreadable', sha256: null, reason: 'capture-unreadable' }; } };
  const actorLedger = async () => { try { return parseLedger((await shortQuery(ledgerSql(actors.block), PG_ACTOR_LIMITS.ledgerRows + 1))[0]?.rows); } catch { return null; } };
  // A mark (readMark), bracketed by two reads of the database's catalog on the catalog's own short session (./catalog.mjs),
  // so neither its locks nor an error in it ever reach this observer's session or its slot.
  const take = async () => {
    const catalogSession = await openPgCatalogSession(connect, login(), dbCatalogSql, { statementTimeoutMs });
    try {
      const first = await catalogSession.read(), mark = await readMark(), second = first.ok ? await catalogSession.read() : first;
      return { ...mark, dbCatalog: bracketCatalog(first, second), dbCatalogLatest: second, ...(actors ? { actor: await actorMark() } : {}) };
    } finally { catalogSession.close(); }
  };
  const readMark = async () => {
    // The end barrier first: the drain read (and its P0) comes before this mark's position.
    const drained = queues.length ? await drainRead() : null;
    if (!session) await open();
    const first = await q(catalogSql(), declared.length * (PG_WAL_LIMITS.descendants + 1) + 1);
    const relations = relationsOf(first[0]), allOids = [...new Set((first[0]?.rows ?? []).map(r => r[1]))];
    // The write locks (held or requested) on the observed relations and the declared queues, read before and again after
    // the position. A writer that commits between the first read and the position is in the window; one that takes its
    // lock in between and is still open at the position is seen by the second read. A writer that commits in the instant
    // between the position and the second read is not seen there: its commit is after the end mark (the post-response
    // settle covers it).
    const writersSql = `/* sh:writers */ SELECT pg_catalog.count(*)::text FROM pg_catalog.pg_locks l WHERE l.locktype = 'relation'
        AND l.database = (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database()) AND (l.relation = ANY (ARRAY[${allOids.map(o => `'${o}'`).join(', ')}]::pg_catalog.oid[])${queues.length ? ` OR l.relation IN ${pgQueueTreeSql(queues)}` : ''})
        AND l.mode IN (${WRITE_LOCKS.map(m => `'${m}'`).join(', ')}) AND l.pid IS DISTINCT FROM pg_catalog.pg_backend_pid()`;
    // The tables whose writes the WAL never carries (unlogged and foreign), by the name test_decoding would print.
    const notInWalSql = `/* sh:notinwal */ SELECT pg_catalog.quote_ident(n.nspname) || '.' || pg_catalog.quote_ident(c.relname) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE (c.relkind IN ('r', 'p') AND c.relpersistence = 'u') OR c.relkind = 'f' ORDER BY 1 LIMIT ${PG_WAL_LIMITS.otherNames * 32 + 1}`;
    const rest = await q([writersSql, '/* sh:position */ SELECT pg_catalog.pg_current_wal_insert_lsn()::text, pg_catalog.pg_is_in_recovery()::text', slotSql(), writersSql, catalogSql(), notInWalSql,
      ...(runLease ? [pgOtherRunsSql(runKey)] : [])].join(';\n'), declared.length * (PG_WAL_LIMITS.descendants + 1) + PG_WAL_LIMITS.otherNames * 32 + 7);
    if (rest.length !== (runLease ? 7 : 6)) throw new PgError('catalog-unreadable');
    const [held, position, slot, heldAfter, again, unlogged, others] = rest;
    if (position.rows[0]?.[1] !== 'false') throw new PgError('standby-refused');
    const problem = slotProblem(slot);
    if (problem) { retire(session, problem); throw new PgError(problem); }
    const otherRuns = runLease ? Number(others.rows[0]?.[0] ?? NaN) : 0;
    if (!Number.isInteger(otherRuns)) throw new PgError('catalog-unreadable');
    // The fingerprint read before the locks and after the position: a catalog change while the mark was read shows as drift.
    const fingerprint = digest(first[0].rows);
    return { gen: session.generation, lsn: lsnValue(position.rows[0]?.[0]), writers: Number(held.rows[0]?.[0] ?? 0) + Number(heldAfter.rows[0]?.[0] ?? 0), relations,
      catalog: { digest: fingerprint, stable: digest(again.rows) === fingerprint }, otherRuns, drained,
      // Past the read's limit an unread name stands in, never ignored.
      notInWal: [...(unlogged?.rows ?? []).slice(0, PG_WAL_LIMITS.otherNames * 32).map(r => r[0]), ...((unlogged?.rows ?? []).length > PG_WAL_LIMITS.otherNames * 32 ? ['?'] : [])] };
  };

  // The end barrier: the flushed WAL has reached a mark's insert position. An insert position at the start of a WAL page
  // reads past the page header (24 bytes, or 40 at the start of a segment), which no record occupies, so a flush at that
  // page's start has reached it too; any other gap has not.
  const reaches = (flush, lsn) => flush >= lsn || (flush % session.blockSize === 0n && lsn - flush === (flush % session.segmentSize === 0n ? 40n : 24n));
  // Reads the slot of the current generation up to an end mark's position into the ledger: the barrier first, then the
  // slot's state, then each stretch between consecutive marks in turn (peek, parse, and only then advance). A stretch is
  // read with its own end mark's catalog: test_decoding prints each change under the relation name and columns it had
  // when it was written, which a later rename or key change would otherwise misread. Returns the reasons the read leaves.
  const readTo = async (mark) => {
    const ledger = ledgers.get(mark.gen), ended = () => generations.get(mark.gen)?.lost ?? 'connection-lost';
    if (ledger && ledger.readThrough >= mark.lsn) return { reasons: [], barrier: { reached: true, waitedMs: 0, flushLsn: null } };
    if (!session || session.generation !== mark.gen) return { reasons: [ended()], barrier: null };
    try {
      const started = performance.now();
      let flush;
      for (;;) {
        flush = lsnValue((await q("/* sh:flush */ SELECT pg_catalog.pg_current_wal_flush_lsn()::text"))[0]?.rows[0]?.[0]);
        if (reaches(flush, mark.lsn) || performance.now() - started >= barrierMs) break;
        await sleep(25);
      }
      const barrier = { reached: reaches(flush, mark.lsn), waitedMs: Math.round(performance.now() - started), flushLsn: lsnText(flush) };
      if (!barrier.reached) return { reasons: ['wal-barrier'], barrier };
      const problem = slotProblem((await q(slotSql()))[0]);
      if (problem) { retire(session, problem); return { reasons: [problem], barrier }; }
      const options = ["'include-xids', '1'", "'skip-empty-xacts', '1'", "'include-timestamp', '0'", "'include-rewrites', '0'", ...(session.streamOption ? ["'stream-changes', '0'"] : [])];
      const stretch = [...marks.values()].filter(m => m.ok && m.gen === mark.gen && m.lsn > ledger.readThrough && m.lsn <= mark.lsn).sort((x, y) => (x.lsn < y.lsn ? -1 : x.lsn > y.lsn ? 1 : 0));
      for (const end of stretch) {
        if (end.lsn <= ledger.readThrough) continue; // two marks at one position
        // The projection: what leaves the server for each decoded row. A declared relation's change whole (its prefix is the
        // stretch's end mark's own name for it, sent as a literal); a TRUNCATE line (it names relations and flags only);
        // another table's change only as its name (the header, which a value cannot reach: the first ': INSERT:' style
        // marker ends the quoted name); anything else only as its kind. A TRUNCATE line ends in its flags, which no INSERT,
        // UPDATE or DELETE line can (a quoted value ends in a quote, an unquoted one is a number, a boolean or null).
        // Bracket expressions keep these patterns free of backslashes; the prefixes are E'' literals (backslashes and quotes
        // doubled), so they read the same whatever standard_conforming_strings is.
        const prefixes = [...new Set(end.relations.map(r => `table ${r.qualified}: `))];
        const peek = `/* sh:peek */ WITH declared(prefix) AS (VALUES ${prefixes.length ? prefixes.map(x => `(E'${x.replace(/\\/g, '\\\\').replace(/'/g, "''")}')`).join(', ') : "(NULL::pg_catalog.text)"})
          SELECT ch.lsn::text, ch.xid::text, k.kind, CASE WHEN k.kind IN ('tx', 'declared', 'truncate') THEN ch.data
              WHEN k.kind = 'other' THEN pg_catalog.substring(ch.data, '^table (.+?): (?:INSERT|UPDATE|DELETE):') END
          FROM pg_catalog.pg_logical_slot_peek_changes('${session.slot}', '${lsnText(end.lsn)}'::pg_catalog.pg_lsn, NULL, ${options.join(', ')}) WITH ORDINALITY AS ch(lsn, xid, data, n)
          CROSS JOIN LATERAL (SELECT CASE WHEN ch.data ~ '^(BEGIN|COMMIT) [0-9]+$' THEN 'tx'
              WHEN EXISTS (SELECT 1 FROM declared d WHERE pg_catalog.starts_with(ch.data, d.prefix))
                THEN CASE WHEN pg_catalog.octet_length(ch.data) > ${PG_WAL_LIMITS.lineBytes} THEN 'oversize' ELSE 'declared' END
              WHEN ch.data ~ '^table .*: TRUNCATE:( [(]no-flags[)]| restart_seqs| cascade| restart_seqs cascade)$' THEN 'truncate'
              WHEN ch.data ~ '^table .+?: (INSERT|UPDATE|DELETE):' THEN 'other' WHEN ch.data LIKE 'message: %' THEN 'message' ELSE 'unknown' END AS kind) AS k
          ORDER BY ch.n`;
        const [result] = await q(peek, PG_WAL_LIMITS.rowsPerRead);
        if (ingest(ledger, result?.rows ?? [], end) === null) return { reasons: ['decode-unparsed'], barrier };
        // Kept in the ledger: now the slot may move past it.
        await q(`/* sh:advance */ SELECT end_lsn::text FROM pg_catalog.pg_replication_slot_advance('${session.slot}', '${lsnText(end.lsn)}'::pg_catalog.pg_lsn)`);
        ledger.readThrough = end.lsn;
      }
      return { reasons: [], barrier };
    } catch (error) {
      // A server error or a lost connection has ended the generation (retire): the window names why, and the slot loss.
      const reason = error instanceof PgError && error.code === 'row-limit' ? 'decode-limit' : reasonOf(error) === 'read-failed' ? 'decode-failed' : reasonOf(error);
      return { reasons: [...new Set([reason, ...(session?.generation === mark.gen ? [] : [ended()])])], barrier: null };
    }
  };
  // Decoded rows into transactions, each parsed against the stretch's end mark's relations and digested now, and tagged
  // with that mark's catalog fingerprint. A transaction whose commit ends after the mark's position is left for the next
  // read; one already in the ledger (by its commit LSN) is skipped. Past the ledger's change budget a transaction keeps no
  // changes and reads decode-limit. A logical message outside its own transaction (a non-transactional one, decoded where it was written, and on
  // PostgreSQL 15 a transaction holding only a message, which test_decoding does not frame) is an entry of its own, placed
  // by its LSN; its content is never read. Returns the number added, or null when the framing (BEGIN, changes, COMMIT)
  // does not hold.
  const ingest = (ledger, rows, mark) => {
    let open = null, added = 0;
    for (const [lsn, xid, kind, data] of rows) {
      if (kind === 'tx') {
        const [word, id] = data.split(' ');
        if (word === 'BEGIN') { if (open) return null; open = { xid: id, catalog: mark.catalog.digest, changes: [], flags: new Set(), others: new Map(), messages: 0 }; continue; }
        if (!open || open.xid !== id || xid !== id) return null;
        const end = lsnValue(lsn), txn = open; open = null;
        if (end > mark.lsn || ledger.ends.has(lsn)) continue;
        txn.commitLsn = lsn; txn.commitEnd = end; txn.key = lsn;
        if (ledger.changes + txn.changes.length > PG_WAL_LIMITS.ledgerChanges) { txn.changes = []; txn.flags.add('decode-limit'); }
        ledger.txns.push(txn); ledger.ends.add(lsn); ledger.changes += txn.changes.length; added += 1;
        continue;
      }
      if (kind === 'message' && open?.xid !== xid) {
        const end = lsnValue(lsn), key = `message ${lsn}`;
        if (end > mark.lsn || ledger.ends.has(key)) continue;
        ledger.txns.push({ xid, catalog: mark.catalog.digest, commitLsn: lsn, commitEnd: end, key, changes: [], flags: new Set(), others: new Map(), messages: 1 }); ledger.ends.add(key); added += 1;
        continue;
      }
      if (!open || open.xid !== xid) return null;
      if (kind === 'declared') {
        const trees = mark.relations.filter(r => data.startsWith(`table ${r.qualified}: `));
        const parsed = trees.length ? parseChangeLine(data, trees[0]) : { error: 'decode-unparsed' };
        if (parsed.error) open.flags.add(parsed.error);
        else if (parsed.op === 'truncate') open.flags.add('table-truncated');
        else for (const relation of trees) { const change = changeOf(relation, parsed, lsn); if (change.flag) open.flags.add(change.flag); if (change.ops) open.changes.push(change); }
      } else if (kind === 'truncate') {
        const names = truncatedNames(data);
        if (names === null) open.flags.add('decode-unparsed');
        else for (const name of names) {
          if (mark.relations.some(r => r.qualified === name)) open.flags.add('table-truncated');
          else open.others.set(name, (open.others.get(name) ?? 0) + 1);
        }
      } else if (kind === 'other') open.others.set(data ?? '?', (open.others.get(data ?? '?') ?? 0) + 1);
      else if (kind === 'message') open.messages += 1;
      else if (kind === 'oversize') open.flags.add('change-too-large');
      else open.flags.add('decode-unparsed');
    }
    return open ? null : added;
  };
  // One parsed change: its operations by key (an UPDATE that moved the key is an update of both keys), the declared values
  // (sealed when sensitive) and every other column's digest. The raw line is not kept.
  const changeOf = (relation, parsed, lsn) => {
    const t = declared[relation.index];
    const keyOf = tuple => {
      if (!tuple?.has(t.key)) return { missing: true };
      const v = tuple.get(t.key);
      if (v === null || v === TOAST) return { flag: 'key-unreadable' };
      const key = relation.keyChar ? v.text.replace(/ +$/, '') : v.text;
      return `${t.prefix}/${key}`.length > EFFECT_LIMITS.resource ? { flag: 'key-too-long' } : { key };
    };
    const tuple = parsed.tuple ?? parsed.oldTuple;
    const values = {}, digests = {};
    for (const [column, v] of tuple ?? []) {
      if (column === t.key) continue;
      if (t.values.includes(column)) {
        values[column] = v === null || v === TOAST ? v : v.text.length > PG_WAL_LIMITS.valueChars ? { error: 'value-too-long' }
          : t.sensitive.includes(column) && !t.reveal.includes(column) ? sealer('text', v.text) : v.text;
      } else digests[column] = v === null ? null : v === TOAST ? 'toast-unchanged' : columnDigest(column, v.text);
    }
    const base = { table: relation.index, lsn, values, digests };
    if (parsed.op === 'insert') { const k = keyOf(parsed.tuple); return k.key !== undefined ? { ...base, op: 'insert', key: k.key, ops: [['insert', k.key]] } : { flag: k.flag ?? 'key-unreadable' }; }
    if (parsed.op === 'delete') {
      const k = keyOf(parsed.oldTuple);
      return k.key !== undefined ? { ...base, op: 'delete', key: k.key, ops: [['delete', k.key]] } : { flag: k.flag ?? 'key-not-in-replica-identity' };
    }
    const next = keyOf(parsed.tuple);
    if (next.key === undefined) return { flag: next.flag ?? 'key-unreadable' };
    // No old key: the replica identity did not change, which tells the key did not only when the key is part of it.
    // Otherwise the update of the new key is certain and the old key unknown: the event stays and the window is partial.
    if (!parsed.oldTuple) return { ...base, op: 'update', key: next.key, ops: [['update', next.key]], ...(relation.keyCovered ? {} : { flag: 'key-not-in-replica-identity' }) };
    const old = keyOf(parsed.oldTuple);
    if (old.key === undefined) return { flag: old.flag ?? 'key-not-in-replica-identity' };
    return { ...base, op: 'update', key: next.key, ...(old.key !== next.key ? { oldKey: old.key } : {}), ops: old.key === next.key ? [['update', next.key]] : [['update', old.key], ['update', next.key]] };
  };
  // Drops ledger transactions no retained mark can still start a window before, and generations no mark refers to.
  const trim = () => {
    const live = new Set([...marks.values()].filter(m => m.ok).map(m => m.gen));
    for (const gen of [...ledgers.keys()]) if (!live.has(gen) && gen !== session?.generation) ledgers.delete(gen);
    for (const gen of [...generations.keys()]) if (!live.has(gen) && gen !== session?.generation) generations.delete(gen);
    for (const [gen, ledger] of ledgers) {
      const lows = [...marks.values()].filter(m => m.ok && m.gen === gen).map(m => m.lsn);
      if (!lows.length) continue;
      const low = lows.reduce((a, b) => (a < b ? a : b));
      const keep = ledger.txns.filter(x => x.commitEnd > low);
      for (const x of ledger.txns) if (x.commitEnd <= low) ledger.ends.delete(x.key);
      ledger.changes = keep.reduce((n, x) => n + x.changes.length, 0); ledger.txns = keep;
    }
  };

  const windowOf = async (from, to) => {
    const a = marks.get(from?.index), b = marks.get(to?.index);
    if (!a?.ok || !b?.ok) return { events: [], coverage: 'failed', reason: (!a?.ok ? a : b)?.reason || 'missing-mark', wal: null };
    if (!(to.index > from.index) || b.lsn < a.lsn) return { events: [], coverage: 'failed', reason: 'window-not-forward', wal: null };
    const reasons = new Set();
    // Another run on this database at either mark: no absence passes on this window, and the events it read stay.
    if (a.otherRuns > 0 || b.otherRuns > 0) reasons.add('shared-database');
    // The end barrier: the end mark's drain read held pending work, a queue write lock, a queue the WAL does not carry, or failed.
    if (b.drained && !b.drained.clean) reasons.add(b.drained.error === 'queue-not-in-wal' ? 'queue-not-in-wal' : b.drained.error ? 'queue-unreadable' : 'queue-not-drained');
    // The start mark's slot ended before the end mark's was created: the changes between are not in either.
    if (a.gen !== b.gen) reasons.add('slot-created-after-baseline').add(generations.get(a.gen)?.lost ?? 'connection-lost');
    const slot = generations.get(b.gen);
    if (a.lsn < slot.consistent) reasons.add('slot-created-after-baseline');
    if (a.catalog.digest !== b.catalog.digest || !a.catalog.stable || !b.catalog.stable) reasons.add('schema-drift');
    // The database's catalog against the run's baseline, and between the window's own marks (./catalog.mjs).
    for (const r of catalogReasons(baseline, a.dbCatalog, b.dbCatalog)) reasons.add(r);
    drifted ||= reasons.has(SCHEMA_DRIFT);
    if (b.writers > 0) reasons.add('transaction-in-flight-at-window-end');
    const read = await readTo(b);
    for (const r of read.reasons) reasons.add(r);
    const ledger = ledgers.get(b.gen);
    const low = a.gen === b.gen ? a.lsn : slot.consistent, high = ledger ? (ledger.readThrough < b.lsn ? ledger.readThrough : b.lsn) : low;
    const txns = (ledger?.txns ?? []).filter(x => x.commitEnd > low && x.commitEnd <= high).sort((x, y) => (x.commitEnd < y.commitEnd ? -1 : 1));
    const events = [], perTable = declared.map(t => ({ name: t.table, schema: t.schema, inserted: [], updated: [], deleted: [], counts: { insert: 0, update: 0, delete: 0 }, changes: [], changesOmitted: 0 }));
    // Actor capture: intact only when both marks verified it against the installation's digest and the ledger read.
    let capture = null;
    if (actors) {
      // Intact only when both marks read it so; a mark without a record reads unreadable.
      const marked = [a.actor, b.actor].every(m => m?.status === 'intact') ? 'intact' : [a.actor, b.actor].find(m => m && m.status !== 'intact')?.status ?? 'unreadable', entries = marked === 'intact' ? await actorLedger() : [];
      capture = { status: entries === null ? 'unreadable' : marked, entries: entries ?? [] };
    }
    const tally = { attributed: 0, unattributed: 0, ambiguous: 0 };
    const actorOf = (txn, change) => {
      if (!actors) return null;
      const d = declared[change.table], r = attributeChange({ xid: txn.xid, table: `${d.schema}.${d.table}`, key: change.key, op: ledgerOp(change.op) }, capture.entries, actors.block, { capture: capture.status, resolve: actors.resolve });
      tally[r.actor !== null ? 'attributed' : r.reason === 'actor-ambiguous' ? 'ambiguous' : 'unattributed'] += 1;
      return r.actor;
    };
    const others = new Map();
    let messages = 0;
    for (const txn of txns) {
      if (txn.catalog !== a.catalog.digest && txn.catalog !== b.catalog.digest) reasons.add('schema-drift');
      for (const f of txn.flags) reasons.add(f);
      for (const [name, n] of txn.others) others.set(name, (others.get(name) ?? 0) + n);
      messages += txn.messages;
      for (const change of txn.changes) {
        const table = perTable[change.table];
        for (const [op, key] of change.ops) {
          table.counts[op] += 1;
          table[{ insert: 'inserted', update: 'updated', delete: 'deleted' }[op]].push(key);
          if (events.length < EFFECT_LIMITS.eventsPerWindow) events.push(makeEffect({ source: PG_WAL_SOURCE, observer, seq: ++seq, observedAt: b.at, actor: actorOf(txn, change), operation: op, name: declared[change.table].table,
            resource: `${declared[change.table].prefix}/${key}`, outcome: 'committed', content: { xid: txn.xid, commitLsn: txn.commitLsn, lsn: change.lsn, op, values: change.values, digests: change.digests } }));
          else reasons.add('event-limit');
        }
        if (table.changes.length < PG_WAL_LIMITS.changesPerTable) table.changes.push({ op: change.op, key: change.key, ...(change.oldKey ? { oldKey: change.oldKey } : {}), xid: txn.xid, commitLsn: txn.commitLsn, lsn: change.lsn, values: change.values, digests: change.digests });
        else table.changesOmitted += 1;
      }
    }
    // Every other table is a declared queue (or one of its partitions, by the drain read's names), ignored, or unlisted.
    const isQueue = (name, parts) => (parts && queues.some(qd => qd.schema === parts.schema && qd.table === parts.table)) || (b.drained?.names.has(name) ?? false);
    let ignoredChanges = 0, queueChanges = 0, captureChanges = 0;
    const unlisted = [];
    const captureOwn = parts => actors !== null && parts?.schema === schemaOf(actors.block) && parts.table === 'audit';
    for (const [name, n] of [...others].sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0))) {
      const parts = splitQualified(name);
      if (isQueue(name, parts)) queueChanges += n;
      else if (captureOwn(parts)) captureChanges += n;
      else if (parts && ignoreList.ignores(parts.schema, parts.table)) ignoredChanges += n;
      else unlisted.push({ name, changes: n });
    }
    if (unlisted.length) reasons.add('unlisted-table-changed');
    if (messages) reasons.add('logical-message');
    // Unlogged and foreign tables at either mark that are neither declared, a queue nor ignored: their writes are not in the WAL.
    // A wire window covers its tables only when it is complete (./pg-net-wire.mjs); a mark the wire could not take fails it.
    const wired = wire === null ? null : a.wire && b.wire ? await wire.collect(a.wire, b.wire).catch(() => ({ coverage: 'failed', reason: 'pg-net-collect-failed', covers: [], wire: null }))
      : { coverage: 'failed', reason: 'pg-net-mark-failed', covers: [], wire: null };
    const covered = new Set(wired?.coverage === 'complete' && wired.custody === 'observer-held' ? wired.covers : []);
    const notInWal = [...new Set([...a.notInWal, ...b.notInWal])].filter(name => { const parts = splitQualified(name); return !isQueue(name, parts) && !(parts && ignoreList.ignores(parts.schema, parts.table)) && !covered.has(name); }).sort();
    if (notInWal.length) reasons.add('table-not-in-wal');
    // The end barrier's (P0, P] check: a queue change committed after the drain read and at or before this mark.
    if (b.drained?.clean && txns.some(x => x.commitEnd > b.drained.p0 && ([...x.others.keys()].some(name => isQueue(name, splitQualified(name))) || x.changes.some(c => queueTables.has(c.table)))))
      reasons.add('queue-not-drained');
    const coverage = reasons.size ? 'partial' : 'complete', reason = reasons.size ? [...reasons].sort().join(',') : null;
    const drainOf = m => (m.drained ? { clean: m.drained.clean, ...(m.drained.error ? { error: m.drained.error } : {}), waitedMs: m.drained.waitedMs, locks: m.drained.locks, pending: m.drained.pending, p0: m.drained.p0 === null ? null : lsnText(m.drained.p0) } : null);
    const wal = { schema: PG_WAL_SCHEMA, coverage, reasons: [...reasons].sort(), startLsn: lsnText(a.lsn), endLsn: lsnText(b.lsn), readThrough: ledger ? lsnText(ledger.readThrough) : null,
      slot: { name: slot.slot, generation: b.gen, consistentLsn: lsnText(slot.consistent) }, barrier: read.barrier, catalog: { start: a.catalog.digest, end: b.catalog.digest },
      tables: perTable, others: { platform, ignore: ignoreList.record, ignored: ignoredChanges, queue: queueChanges, ...(actors ? { capture: captureChanges } : {}), unlisted: unlisted.slice(0, PG_WAL_LIMITS.otherNames), unlistedOmitted: Math.max(0, unlisted.length - PG_WAL_LIMITS.otherNames), messages,
        notInWal: notInWal.slice(0, PG_WAL_LIMITS.otherNames), notInWalOmitted: Math.max(0, notInWal.length - PG_WAL_LIMITS.otherNames),
        ...(wired ? { wire: { coverage: wired.coverage, reason: wired.reason, custody: wired.custody ?? null, declaration: wired.declaration ?? null, covered: [...covered], record: wired.wire } } : {}) },
      ...(queues.length ? { queues: { start: drainOf(a), end: drainOf(b) } } : {}) };
    // The capture's record beside the window (collectWindow keeps only the window): counts and statuses, no captured value.
    // With a wire, the declaration it rests on goes beside the window, word for word (src/effect-events.mjs collectWindow keeps it).
    return { events, coverage, reason, ...(wire !== null ? { declaration: wired?.declaration ?? null } : {}), wal: { ...wal, digest: digest(wal) }, ...(actors ? { actors: { schema: PG_ACTOR_SCHEMA, capture: { start: a.actor.status, end: b.actor.status, window: capture.status }, ...tally } } : {}) };
  };

  return {
    kind: observer.kind, instanceId, source: PG_WAL_SOURCE,
    scope: Object.freeze({ operations: ['insert', 'update', 'delete'], names: declared.map(t => t.table), actorAttribution: actors ? 'principal' : 'none', evidence: 'authoritative' }),
    // Refuses while another run holds a lease on this database (the shared-database rule), before any mark.
    // The wire given after construction (a profile's pgNetWire, attached by src/http-connector.mjs): once, and before the first start.
    attachWire(w) {
      if (wire !== null || begun) throw new Error('pg-wal: a wire attaches once, before the observer starts.');
      if (!wireShape(w)) throw new Error('wire is a pg_net wire observer (./pg-net-wire.mjs).');
      wire = w;
    },
    async start() {
      begun = true;
      await serial(async () => {
        if (session) return;
        if (await open() > 0) { await drop(); throw new Error('shared-database: another ScopeHaven run holds a lease on this database; runs that reseed one database never share it.'); }
        // The run's catalog baseline, on the catalog's own session (an error there never touches the slot), tried again a few
        // times when it does not read; a start without one is refused, and the slot goes with it.
        const catalogSession = await openPgCatalogSession(connect, login(), dbCatalogSql, { statementTimeoutMs });
        try { baseline = await readPgCatalogBaseline(catalogSession); } finally { catalogSession.close(); }
        if (!baseline.ok) { await drop(); throw new Error(BASELINE_REFUSED); }
        if (wire) { try { await wire.start(); } catch (error) { await drop(); throw error; } }
      });
    },
    async mark() {
      return serial(async () => {
        const index = nextIndex++, at = new Date().toISOString();
        try { marks.set(index, { ok: true, at, ...(await take()), ...(wire ? { wire: await wire.mark().catch(() => null) } : {}) }); }
        catch (error) {
          // A server error or a lost connection has already ended the generation (retire); the next mark opens a new one.
          marks.set(index, { ok: false, at, reason: reasonOf(error) });
        }
        // An observer marked without start() takes its first mark's fingerprint as the baseline.
        const taken = marks.get(index);
        if (taken.ok) baseline ??= taken.dbCatalogLatest;
        if (taken.ok && taken.dbCatalog.ok) { latest = taken.dbCatalog; drifted ||= Boolean(baseline?.ok) && taken.dbCatalog.sha256 !== baseline.sha256; }
        marks.delete(index - PG_WAL_LIMITS.retainedMarks); // bounded memory: older marks are dropped
        return { index };
      });
    },
    // { events, coverage, reason } for collectWindow, plus wal: the sealed per-table record (null when a mark failed).
    async collect(from, to) { return serial(async () => { const out = await windowOf(from, to); trim(); return out; }); },
    // A value check on a declared column, judged by this observer (it holds the salt sensitive values are sealed under).
    judgeValue(record, expectation) { return judgeWalValue(record, expectation, { sealer, declared }); },
    // The catalog record a run keeps for this observer (./catalog.mjs catalogRecord).
    catalog() { return catalogRecord({ engine: 'postgres', baseline, latest, drifted, excluded: dbExcluded }); },
    async stop() { await serial(async () => { await drop(); await wire?.stop(); }); },
  };
}

// A value check over one window's record: { table, key, column, equals } where equals is the text Postgres prints for the
// value (with the pinned output settings) or null for SQL NULL. Reads the last change of that key in the window: a delete
// fails it; a value the change carried passes or fails it; an unchanged TOAST value reads an earlier change of the same
// window, or is inconclusive (toast-unchanged). A key the window did not write, a column not declared, and a record that
// is not complete are inconclusive: the observer reads changes, never the table.
export function judgeWalValue(record, expectation, { sealer = null, declared = null } = {}) {
  const verdict = (v, reason) => ({ verdict: v, reason });
  if (record?.schema !== PG_WAL_SCHEMA) return verdict('inconclusive', 'record-unreadable');
  if (record.coverage !== 'complete') return verdict('inconclusive', record.reasons.join(',') || 'window-partial');
  const { table, key, column, equals } = expectation ?? {};
  const t = record.tables.find(x => x.name === table), d = declared?.find(x => x.table === table);
  if (!t) return verdict('inconclusive', 'table-not-observed');
  if (d && !d.values.includes(column)) return verdict('inconclusive', 'column-not-declared');
  if (t.changesOmitted) return verdict('inconclusive', 'changes-omitted');
  const changes = t.changes.filter(c => c.key === key || c.oldKey === key);
  if (!changes.length) return verdict('inconclusive', 'row-not-written-in-window');
  const last = changes.at(-1);
  if (last.op === 'delete') return verdict('fail', 'row-deleted');
  if (last.oldKey === key && last.key !== key) return verdict('fail', 'key-moved');
  const carried = [...changes].reverse().find(c => c.key === key && Object.hasOwn(c.values, column) && c.values[column]?.toast !== 'unchanged');
  if (!carried) return verdict('inconclusive', changes.some(c => c.values[column]?.toast === 'unchanged') ? 'toast-unchanged' : 'column-not-carried');
  const value = carried.values[column];
  if (value !== null && typeof value === 'object' && value.error) return verdict('inconclusive', value.error);
  if (value !== null && typeof value === 'object' && typeof value.sealed === 'string') {
    if (!sealer || typeof equals !== 'string') return verdict('inconclusive', 'sealed');
    return value.sealed === sealer('text', equals).sealed ? verdict('pass', null) : verdict('fail', 'value-mismatch');
  }
  if (!(equals === null || typeof equals === 'string')) return verdict('inconclusive', 'expectation-not-text');
  return value === equals ? verdict('pass', null) : verdict('fail', 'value-mismatch');
}
