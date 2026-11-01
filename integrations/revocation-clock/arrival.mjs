// Arrival poller: the sink side of the revocation clock. It reads an app's audit table
// read-only every few milliseconds and stamps each read with one clock. A row first seen
// by read k was committed after read k-1 began (or that read would have seen it) and
// before read k ended, so its commit time is bracketed by two stamps from one clock:
// (start of read k-1, end of read k]. No WAL, trigger or app timestamp is used.
import { DatabaseSync } from 'node:sqlite';

export const ARRIVAL_LIMITS = Object.freeze({ polls: 200000, rows: 10000, pollMs: [1, 50] });
export const hostClock = () => process.hrtime.bigint();
const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

// path: the SQLite file; table/idColumn/columns: what to read; clock: () => bigint ns.
// The first read (before start returns) sets the baseline: rows already there are not arrivals.
// limits: { polls, rows } below ARRIVAL_LIMITS (a test can make an overflow cheap to reach).
export function createArrivalPoller({ path, table, idColumn = 'id', columns = [], pollMs = 2, clock = hostClock, limits = ARRIVAL_LIMITS }) {
  for (const name of [table, idColumn, ...columns]) if (!IDENT.test(name)) throw new Error('Arrival poller: table and column names must be plain identifiers.');
  if (!Number.isInteger(pollMs) || pollMs < ARRIVAL_LIMITS.pollMs[0] || pollMs > ARRIVAL_LIMITS.pollMs[1]) throw new Error('Arrival poller: pollMs must be 1 to 50.');
  let db = null, timer = null, lastId = 0, running = false, overflow = false, error = null;
  const polls = [], rows = [];
  const select = () => db.prepare(`SELECT ${[idColumn, ...columns].map(c => `"${c}"`).join(', ')} FROM "${table}" WHERE "${idColumn}" > ? ORDER BY "${idColumn}"`);
  const read = () => {
    if (polls.length >= Math.min(limits.polls, ARRIVAL_LIMITS.polls)) { overflow = true; return; }
    try {
      const start = clock(), found = select().all(lastId), end = clock();
      const seq = polls.length + 1;
      polls.push({ seq, start: String(start), end: String(end), maxId: found.length ? Number(found.at(-1)[idColumn]) : lastId });
      for (const row of found) {
        if (rows.length >= Math.min(limits.rows, ARRIVAL_LIMITS.rows)) { overflow = true; break; }
        rows.push({ ...Object.fromEntries(columns.map(c => [c, row[c] === null ? null : String(row[c])])), id: Number(row[idColumn]), poll: seq });
      }
      if (found.length) lastId = Number(found.at(-1)[idColumn]);
    } catch (e) { error = e?.code ?? 'read-failed'; }
  };
  const loop = () => { if (!running) return; read(); timer = setTimeout(loop, pollMs); };
  return {
    pollMs,
    async start() { db = new DatabaseSync(path, { readOnly: true }); read(); running = true; timer = setTimeout(loop, pollMs); },
    // A read on demand: the clock takes one just before and just after the access change,
    // so an effect committed right before the change is never bracketed across it.
    readNow() { if (db) read(); },
    // A last read after the run, so an arrival during the final interval is bracketed.
    async stop() { running = false; clearTimeout(timer); read(); db?.close(); db = null; return { polls: polls.map(p => ({ ...p })), rows: rows.map(r => ({ ...r })), overflow, error }; },
  };
}

// The commit bracket of every row first seen after the baseline read: [after, before]
// in the poller's clock (ns, BigInt). A row seen in the baseline read has no bracket.
export function arrivalBrackets({ polls, rows }) {
  const byPoll = new Map(polls.map(p => [p.seq, p]));
  return rows.filter(r => r.poll > 1).map(r => {
    const prev = byPoll.get(r.poll - 1), seen = byPoll.get(r.poll);
    if (!prev || !seen) return { ...r, after: null, before: null };
    return { ...r, after: BigInt(prev.start), before: BigInt(seen.end) };
  });
}
