// The end barrier (N12, lead-queue item 2): a window closes only once the declared queues or job tables hold no pending
// work, so an effect a background worker performs after the response is inside the window instead of after it. Each
// database observer (pg-snapshot, pg-wal, sqlite-snapshot) waits at every mark, before it reads, for its declared queues
// to drain, up to drainTimeoutMs, polling every pollMs, and then reads the queues again as part of the mark itself. A
// window whose end mark still saw pending work reads inconclusive with queue-not-drained, never a pass. A start mark's
// queue state is recorded but decides nothing: a job left from before the window can still write inside it.
//
// A queue: { table, schema? ("public"; Postgres only), pending? }. Pending work is every row by default (a queue whose
// worker deletes each job when it is done: graphile-worker, pgmq, solid_queue's ready and claimed executions), or the rows
// whose state column holds one of the listed values ({ column, in: [...] }: pg-boss, Oban, a jobs table's status), or
// whose column is NULL ({ column, isNull: true }: a finished_at stamp). A job scheduled for later is pending: it may still
// make the effect, so a run that schedules past the timeout reads queue-not-drained. A permanently failed job that stays
// in the table is pending too unless the state predicate leaves it out. A queue is never on the ignore list
// (./ignore-lists/ignore-list.mjs), and its own rows are never an unlisted change.
//
// How exact the cut is, by observer (each header has the detail):
//   pg-snapshot      the count is read inside the mark's own REPEATABLE READ snapshot, the one its rows are read under, and
//                    an enqueuer still in progress at the mark is an in-flight writer: exact.
//   sqlite-snapshot  the count is read from the same consistent private copy as the mark's tables: exact.
//   pg-wal           the count is read on a second session at READ COMMITTED, after the WAL position P0 and after the write
//                    locks on the queue tables, then the mark's position P is read; any queue change committed in (P0, P]
//                    (decoded from the WAL) makes the window queue-not-drained too. With the write locks read before the
//                    count, an enqueue committed before P0 is either counted or still holds its lock: exact for a logged
//                    queue table. An unlogged or temporary one is refused (queue-not-in-wal): its changes are not in the WAL.
// Pure helpers apart from the poll's clock.
import { setTimeout as sleep } from 'node:timers/promises';

export const BARRIER_LIMITS = Object.freeze({ queues: 8, states: 16, drainTimeoutMs: 10000, drainBounds: [0, 120000], pollMs: 100, pollBounds: [20, 5000], countCap: 10000 });
const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const STATE = /^[A-Za-z0-9_.:-]{1,64}$/;
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);

// The declared queues, checked: [{ schema, table, pending: null | { column, in } | { column, isNull: true } }].
export function validateQueues(queues, { engine }) {
  if (queues === undefined) return Object.freeze([]);
  if (!Array.isArray(queues) || queues.length > BARRIER_LIMITS.queues) throw new Error(`queues lists up to ${BARRIER_LIMITS.queues} queue or job tables.`);
  const out = queues.map((q, i) => {
    const keys = engine === 'postgres' ? ['table', 'schema', 'pending'] : ['table', 'pending'];
    if (!plain(q) || Object.keys(q).some(k => !keys.includes(k))) throw new Error(`Queue ${i + 1} is { ${keys.join(', ')} } (pending optional).`);
    const schema = engine === 'postgres' ? q.schema ?? 'public' : 'main';
    if (!IDENT.test(q.table ?? '') || !IDENT.test(schema)) throw new Error(`Queue ${i + 1} names an unsupported identifier.`);
    let pending = null;
    if (q.pending !== undefined) {
      const p = q.pending;
      if (!plain(p) || !IDENT.test(p.column ?? '')) throw new Error(`Queue ${i + 1}: pending names a column.`);
      if (Object.hasOwn(p, 'in') && Object.keys(p).length === 2 && Array.isArray(p.in) && p.in.length >= 1 && p.in.length <= BARRIER_LIMITS.states && p.in.every(v => typeof v === 'string' && STATE.test(v)) && new Set(p.in).size === p.in.length)
        pending = Object.freeze({ column: p.column, in: Object.freeze([...p.in]) });
      else if (p.isNull === true && Object.keys(p).length === 2) pending = Object.freeze({ column: p.column, isNull: true });
      else throw new Error(`Queue ${i + 1}: pending is { column, in: [1 to ${BARRIER_LIMITS.states} state values] } or { column, isNull: true }.`);
    }
    return Object.freeze({ schema, table: q.table, pending });
  });
  if (new Set(out.map(q => `${q.schema}.${q.table}`)).size !== out.length) throw new Error('Each queue is declared once.');
  return Object.freeze(out);
}

// The drain wait's bounds: drainTimeoutMs 0 reads once and never waits.
export function validateDrain({ drainTimeoutMs = BARRIER_LIMITS.drainTimeoutMs, pollMs = BARRIER_LIMITS.pollMs } = {}) {
  const within = (v, [min, max]) => Number.isInteger(v) && v >= min && v <= max;
  if (!within(drainTimeoutMs, BARRIER_LIMITS.drainBounds)) throw new Error('drainTimeoutMs must be an integer from 0 to 120000.');
  if (!within(pollMs, BARRIER_LIMITS.pollBounds)) throw new Error('pollMs must be an integer from 20 to 5000.');
  return Object.freeze({ drainTimeoutMs, pollMs });
}

// One queue's pending rows as SQL, bounded: at most countCap + 1 are counted (more reads as countCap + 1).
const pendingWhere = (q, quote, asText) => (q.pending === null ? 'TRUE' : q.pending.isNull ? `${quote(q.pending.column)} IS NULL`
  : `${asText(quote(q.pending.column))} IN (${q.pending.in.map(v => `'${v}'`).join(', ')})`);
const pgQuote = name => { if (!IDENT.test(name)) throw new Error('Unsupported SQL identifier.'); return `"${name}"`; };
export const pgQueueCountSql = queues => `SELECT ${queues.map(q => `(SELECT pg_catalog.count(*) FROM (SELECT 1 FROM ${pgQuote(q.schema)}.${pgQuote(q.table)} WHERE ${pendingWhere(q, pgQuote, c => `(${c})::pg_catalog.text`)} LIMIT ${BARRIER_LIMITS.countCap + 1}) AS p)::text`).join(', ')}`;
// Every queue table and its partitions and inheritance children, by oid, for a lock or WAL read (a subquery).
export const pgQueueTreeSql = queues => `(WITH RECURSIVE q(oid) AS (SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE (n.nspname, c.relname) IN (VALUES ${queues.map(q => `('${q.schema}', '${q.table}')`).join(', ')}) UNION SELECT h.inhrelid FROM q JOIN pg_catalog.pg_inherits h ON h.inhparent = q.oid) SELECT oid FROM q)`;
// SQLite: the pending counts from an open (private) copy.
export function sqliteQueueCounts(db, queues) {
  const quote = name => { if (!IDENT.test(name)) throw new Error('Unsupported SQL identifier.'); return `"${name}"`; };
  return queues.map(q => Number(db.prepare(`SELECT count(*) AS n FROM (SELECT 1 FROM ${quote(q.table)} WHERE ${pendingWhere(q, quote, c => `CAST(${c} AS TEXT)`)} LIMIT ${BARRIER_LIMITS.countCap + 1})`).get().n));
}
// The pending counts by queue, as a record entry.
export const pendingOf = (queues, counts) => queues.map((q, i) => ({ queue: q.schema === 'main' ? q.table : `${q.schema}.${q.table}`, pending: counts[i] }));

// Polls read() (resolving { clean, ... }) until it reads clean or the timeout passes; returns the last reading with
// waitedMs. A read that throws ends the wait with that error (the caller decides what it means).
export async function drainWait(read, { drainTimeoutMs, pollMs }, { now = () => performance.now(), wait = sleep } = {}) {
  const started = now();
  for (;;) {
    const reading = await read();
    const waitedMs = Math.round(now() - started);
    if (reading.clean || waitedMs >= drainTimeoutMs) return { ...reading, waitedMs };
    await wait(Math.min(pollMs, Math.max(1, drainTimeoutMs - waitedMs)));
  }
}
