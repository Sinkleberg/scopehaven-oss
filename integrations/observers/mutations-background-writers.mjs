#!/usr/bin/env node
// Mutation sweep for the background-writer rules (N12): the ignore-list reader and its lists, pg-wal's other tables, end
// barrier and lease, pg-snapshot's attribution, barrier and lease, sqlite-snapshot's, and the shared helpers. One mutation
// per property; each must make a test fail. A survivor is a test gap.
//   node integrations/observers/mutations-background-writers.mjs [--out FILE] [--only ID,ID...]
// As mutations-pg-readback.mjs: a temporary copy (in a folder whose name has spaces) of the modules the tests load, never
// the checkout; the tests run once unmutated (they must pass), then once per mutation. Each edit must match once. A
// mutation runs the unit tests first; one marked live that survives them runs the live tests too when SCOPEHAVEN_PG_LIVE
// names a disposable server (else it reads needs-live). Tests run in-process (--test-isolation=none), one file at a time.
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const UNIT = ['integrations/observers/background-writers.test.mjs', 'integrations/observers/pg-wal.test.mjs'];
const LIVE = ['integrations/observers/background-writers.live.test.mjs', 'integrations/observers/pg-wal.live.test.mjs'];
const m = (id, property, file, edits, { live = false } = {}) => ({ id, property, file, edits, live });
const IL = 'integrations/observers/ignore-lists/ignore-list.mjs', SB = 'integrations/observers/ignore-lists/supabase.json';
const W = 'integrations/observers/pg-wal.mjs', S = 'integrations/observers/pg-snapshot.mjs', Q = 'integrations/observers/sqlite.mjs';
const L = 'integrations/observers/run-lease.mjs', B = 'integrations/observers/end-barrier.mjs';
export const MUTATIONS = [
  // The one reader and its lists.
  m('I1', 'a profile entry that names a declared table or queue is refused', IL, [['    const hit = watchedHere(schema, table);', '    const hit = table === null ? watchedHere(schema, table) : undefined;']]),
  m('I2', 'a schema-wide profile entry over a schema holding a declared table is refused', IL, [['    const hit = watchedHere(schema, table);', '    const hit = table === null ? undefined : watchedHere(schema, table);']]),
  m('I3', 'a platform entry never applies to a declared table or queue', IL, [['const ignores = (schema, table) => !watchedHere(schema, table) && entries.some(', 'const ignores = (schema, table) => entries.some(']]),
  m('I4', 'a table entry ignores its own table only', IL, [['entries.some(e => e.schema === schema && (e.table === null || same(e.table, table)));', 'entries.some(e => e.schema === schema);']]),
  m('I5', 'a checked-in entry names its writer and why', IL, [[' || !text(e.writer) || !text(e.why)) fail(', ') fail(']]),
  m('I6', 'a checked-in entry is listed once', IL, [['    if (seen.has(name)) fail(', '    if (false) fail(']]),
  m('I7', 'a table entry under a schema-wide entry is refused', IL, [['  if (entries.some(e => e.table !== null && seen.has(e.schema))) fail(', '  if (false) fail(']]),
  m('I8', 'tables that carry an effect stay off the Supabase list', SB, [['    { "schema": "auth", "table": "schema_migrations",', '    { "schema": "auth", "table": "users", "writer": "x", "why": "y" },\n    { "schema": "auth", "table": "schema_migrations",']]),
  m('I9', 'an overridden platform entry is recorded', IL, [['const overridden = Object.freeze(watched.filter(', 'const overridden = Object.freeze([].filter(']]),
  m('I10', 'a profile entry is listed once', IL, [["  if (new Set(names.map(n => (engine === 'sqlite' ? fold(n) : n))).size !== names.length) throw", '  if (false) throw']]),
  m('I11', 'SQLite names compare without case', IL, [["const same = engine === 'sqlite' ? (a, b) => fold(a) === fold(b) : (a, b) => a === b;", 'const same = (a, b) => a === b;']]),
  m('I12', 'a system schema is never on a profile\'s list', IL, [["if (engine === 'postgres' && (/^pg_/i.test(schema) || schema.toLowerCase() === 'information_schema')) throw", 'if (false) throw']]),
  // pg-wal: every other table, the end barrier, the lease.
  m('W1', 'pg-wal: an unlisted change makes the window partial', W, [["    if (unlisted.length) reasons.add('unlisted-table-changed');\n", '']]),
  m('W2', 'pg-wal: a logical message makes the window partial', W, [["    if (messages) reasons.add('logical-message');\n", '']]),
  m('W3', 'pg-wal: an ignored change is counted, not unlisted', W, [['else if (parts && ignoreList.ignores(parts.schema, parts.table)) ignoredChanges += n;', 'else if (false) ignoredChanges += n;']]),
  m('W4', 'pg-wal: a declared queue\'s changes are the queue\'s', W, [['if (isQueue(name, parts)) queueChanges += n;', 'if (false) queueChanges += n;']]),
  m('W5', 'pg-wal: queue partitions named by the drain read are the queue\'s', W, [[' || (b.drained?.names.has(name) ?? false)', '']]),
  m('W6', 'pg-wal: an end mark not drained reads queue-not-drained', W, [['    if (b.drained && !b.drained.clean) reasons.add(', '    if (false) reasons.add(']]),
  m('W7', 'pg-wal: a failed drain read is never drained', W, [['      return { clean: false, error:', '      return { clean: true, error:']]),
  m('W8', 'pg-wal: a queue change committed between the drain read and the mark reads queue-not-drained', W, [['    if (b.drained?.clean && txns.some(x => x.commitEnd > b.drained.p0', '    if (false && txns.some(x => x.commitEnd > b.drained.p0']]),
  m('W9', 'pg-wal: the drain read comes before the mark\'s position', W, [['    const drained = queues.length ? await drainRead() : null;\n', '    let drained = null;\n'],
    ['    const otherRuns = runLease ? Number(others.rows[0]?.[0] ?? NaN) : 0;', '    drained = queues.length ? await drainRead() : null;\n    const otherRuns = runLease ? Number(others.rows[0]?.[0] ?? NaN) : 0;']]),
  m('W10', 'pg-wal: the drain read takes the queue locks before the counts', W, [["const [p0, locks, counts, names] = await client.query(['/* sh:drainlsn */ SELECT pg_catalog.pg_current_wal_insert_lsn()::text', queueLocksSql, `/* sh:queuecount */ ${pgQueueCountSql(queues)}`, queueNamesSql]",
    "const [p0, counts, locks, names] = await client.query(['/* sh:drainlsn */ SELECT pg_catalog.pg_current_wal_insert_lsn()::text', `/* sh:queuecount */ ${pgQueueCountSql(queues)}`, queueLocksSql, queueNamesSql]"]]),
  m('W11', 'pg-wal: a write lock on a queue keeps it from reading drained', W, [['clean: held === 0 && pending.every(n => n === 0)', 'clean: pending.every(n => n === 0)']]),
  m('W12', 'pg-wal: queue write locks count as in-flight writers at the end mark', W, [['${queues.length ? ` OR l.relation IN ${pgQueueTreeSql(queues)}` : \'\'}', "${''}"]]),
  m('W13', 'pg-wal: start refuses while another run holds a lease', W, [['if (await open() > 0) { await drop(); throw', 'if (await open() > 1e9) { await drop(); throw']]),
  m('W14', 'pg-wal: another run\'s lease at a mark holds absence back', W, [["    if (a.otherRuns > 0 || b.otherRuns > 0) reasons.add('shared-database');\n", '']]),
  m('W14b', 'pg-wal: another run\'s lease keeps the window\'s events (a fail stays a fail)', W, [["    if (a.otherRuns > 0 || b.otherRuns > 0) reasons.add('shared-database');", "    if (a.otherRuns > 0 || b.otherRuns > 0) return { events: [], coverage: 'failed', reason: 'shared-database', wal: null };"]]),
  m('W15', 'pg-wal: its session holds the run lease', W, [['...(runLease ? [pgLeaseSql(runKey), pgOtherRunsSql(runKey)] : [])', '...(runLease ? [pgOtherRunsSql(runKey), pgOtherRunsSql(runKey)] : [])'],
    ["      if (runLease && results.at(-2)?.rows[0]?.[0] !== 'true') throw new PgError('lease-unavailable');\n", '']], { live: true }),
  m('W17', 'pg-wal: an unlisted unlogged or foreign table holds absence back', W, [["    if (notInWal.length) reasons.add('table-not-in-wal');\n", '']]),
  m('W18', 'pg-wal: an ignored unlogged table is accounted for', W, [['!(parts && ignoreList.ignores(parts.schema, parts.table)); }).sort();', 'true; }).sort();']]),
  m('W19', 'pg-wal: tables the WAL never carries are read at both marks', W, [['[...new Set([...a.notInWal, ...b.notInWal])]', '[...new Set([...b.notInWal])]']]),
  m('W20', 'pg-wal: an unlogged or temporary queue is refused', W, [["if ((names?.rows ?? []).some(r => !['pr', 'pp'].includes(r[1]))) throw new PgError('queue-not-in-wal');", "if (false) throw new PgError('queue-not-in-wal');"]]),
  m('W22', 'pg-wal: a view or foreign table declared as a queue is refused', W, [["!['pr', 'pp'].includes(r[1])", "r[1][0] !== 'p'"]]),
  m('W21', 'pg-wal: the drain session reads at READ COMMITTED', W, [["SET default_transaction_isolation = 'read committed';\\n", '']]),
  m('W16', 'pg-wal: the ignore list is resolved with the declared tables', W, [['declared: declared.map(t => ({ schema: t.schema, table: t.table })), queues });\n  // Declared tables that are also queues', 'declared: [], queues });\n  // Declared tables that are also queues']]),
  // pg-snapshot: attribution, the end barrier, the lease.
  m('S1', 'pg-snapshot: without a list every end-mark writer counts', S, [['if (!attribute) return { counted: s.xip.length + s.writers.length, ignored: 0 };', 'if (!attribute) return { counted: 0, ignored: 0 };']]),
  m('S2', 'pg-snapshot: attribution is on only when a list is declared', S, [['const attribute = platform !== undefined || ignore !== undefined;', 'const attribute = true;']]),
  m('S3', 'pg-snapshot: a writer quiet at read 1 must still be quiet at read 2 if it is there', S, [['r1.quiet.has(x) && (!r2.holders.has(x) || r2.quiet.has(x))', 'r1.quiet.has(x)']]),
  m('S4', 'pg-snapshot: an id in the snapshot that read 1 did not see stays counted', S, [[': !xip.has(x) && r2.holders.has(x) && r2.quiet.has(x));', ': r2.holders.has(x) && r2.quiet.has(x));']]),
  m('S5', 'pg-snapshot: a writer first seen at read 2 must be quiet there', S, [[': !xip.has(x) && r2.holders.has(x) && r2.quiet.has(x));', ': !xip.has(x));']]),
  m('S6', 'pg-snapshot: ids are compared at 32 bits', S, [['const norm = x => (BigInt(x) % MOD32).toString();', 'const norm = x => String(x);']]),
  m('S7', 'pg-snapshot: a declared table or queue, its partitions and children are never ignored', S, [['NOT EXISTS (SELECT 1 FROM tree JOIN owner o ON o.tab = tree.oid WHERE o.oid = l.relation)', 'TRUE']], { live: true }),
  m('S8', 'pg-snapshot: a writer in another database cannot write this one', S, [['((l.database <> 0 AND l.database IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database())) OR (NOT EXISTS', '(FALSE OR (NOT EXISTS']], { live: true }),
  m('S18', 'pg-snapshot: a shared catalog (database 0) is not another database', S, [['((l.database <> 0 AND l.database IS DISTINCT FROM', '((l.database IS DISTINCT FROM']], { live: true }),
  m('S17', 'pg-snapshot: only the platform\'s list makes a writer quiet', S, [['textValues(ignoreList.platformEntries.map(', 'textValues(ignoreList.entries.map(']], { live: true }),
  m('S9', 'pg-snapshot: an index reads as its table', S, [['byindex AS (SELECT k.oid, COALESCE((SELECT x.indrelid FROM pg_catalog.pg_index x WHERE x.indexrelid = k.oid), k.oid) AS tab FROM locked k)', 'byindex AS (SELECT k.oid, k.oid AS tab FROM locked k)']], { live: true }),
  m('S10', 'pg-snapshot: an owned sequence reads as its table', S, [["d.deptype IN ('a', 'i') LIMIT 1), b.tab) AS tab FROM bytoast b)", "d.deptype IN ('a', 'i') LIMIT 0), b.tab) AS tab FROM bytoast b)"]], { live: true }),
  m('S11', 'pg-snapshot: pending work at the end mark reads queue-not-drained', S, [["...(after.queues && !after.queues.clean ? ['queue-not-drained'] : [])", '...([])']]),
  m('S12', 'pg-snapshot: the count that decides is read under the mark\'s snapshot', S, [['clean: counts.every(n => n === 0), waitedMs: drained.waitedMs', 'clean: drained.clean, waitedMs: drained.waitedMs']]),
  m('S13', 'pg-snapshot: the mark waits for its queues before its transaction', S, [['drained = await drainWait(async () => ({ clean: countsOf(', 'drained = await drainWait(async () => ({ clean: true || countsOf(']]),
  m('S14', 'pg-snapshot: start refuses while another run holds a lease', S, [["if (refuse && Number(others.rows[0][0]) > 0) throw new Error('shared-database", "if (false) throw new Error('shared-database"]]),
  m('S15', 'pg-snapshot: another run\'s lease at a mark holds absence back', S, [["...(before.otherRuns > 0 || after.otherRuns > 0 ? ['shared-database'] : []),\n        // The end mark found", "...([]),\n        // The end mark found"]]),
  m('S16', 'pg-snapshot: a lost lease is taken again at the next mark', S, [['snapshots.get(index).ownLease === 0) {', 'snapshots.get(index).ownLease === -1) {']], { live: true }),
  m('S20', 'pg-snapshot: a window ending at a mark that found its own lease gone reads lease-lost', S, [["...(after.ownLease === 0 ? ['lease-lost'] : [])].sort();", '...([])].sort();']]),
  m('S21', 'pg-snapshot: the lease is taken again without refusing', S, [['try { await holdLease({ refuse: false }); }', 'try { await holdLease(); }']]),
  // sqlite-snapshot.
  m('Q1', 'sqlite: with a list, an unlisted table that changed holds absence back', Q, [["const reasons = [...(changed.length ? ['unlisted-table-changed'] : [])", 'const reasons = [...([])']]),
  m('Q2', 'sqlite: ignored tables are not watched', Q, [["if (accounted.has(fold(name)) || (IDENT.test(name) && ignoreList.ignores('main', name))) continue;", 'if (accounted.has(fold(name))) continue;']]),
  m('Q16', 'sqlite: names fold ASCII only, as SQLite does', Q, [['  const fold = n => n.replace(/[A-Z]/g, c => c.toLowerCase());\n  const accounted', '  const fold = n => n.toLowerCase();\n  const accounted']]),
  m('Q3', 'sqlite: SQLite\'s own tables are never watched', Q, [[" AND name NOT LIKE 'sqlite\\\\_%' ESCAPE '\\\\'", '']]),
  m('Q4', 'sqlite: a table that appeared or vanished counts as changed', Q, [['return !x || !y || x.unreadable || y.unreadable || x.digest !== y.digest;', 'return Boolean(x && y && (x.unreadable || y.unreadable || x.digest !== y.digest));']]),
  m('Q5', 'sqlite: without a list other tables are not read', Q, [['const watchOthers = platform !== undefined || ignore !== undefined;', 'const watchOthers = true;']]),
  m('Q6', 'sqlite: pending work at the end mark reads queue-not-drained', Q, [["...(after.queues && !after.queues.clean ? ['queue-not-drained'] : [])", '...([])']]),
  m('Q7', 'sqlite: drained is read from the same copy as the mark\'s tables', Q, [['return { clean: r.pending.every(n => n === 0), r }; }, drain);', 'return { clean: true, r }; }, drain);']]),
  m('Q8', 'sqlite: a mark is retaken until its queue drains', Q, [['return { clean: r.pending.every(n => n === 0), r }; }, drain);', 'return { clean: r.pending.every(n => n === 0), r }; }, { ...drain, drainTimeoutMs: 0 });']]),
  m('Q9', 'sqlite: start refuses while another run holds a lease', Q, [['if (lease.others() > 0) { lease.release(); throw', 'if (false) { lease.release(); throw']]),
  m('Q10', 'sqlite: another run\'s lease at a mark holds absence back', Q, [["...(before.otherRuns > 0 || after.otherRuns > 0 ? ['shared-database'] : [])].sort();", '...([])].sort();']]),
  m('Q12', 'sqlite: an integer past 2^53 reads exactly in the other-table scan', Q, [['      read.setReadBigInts(true); // an integer past 2^53 reads exactly instead of throwing\n', '']]),
  m('Q13', 'sqlite: a virtual table is not read (its shadow tables are)', Q, [[" AND (sql IS NULL OR sql NOT LIKE 'CREATE VIRTUAL TABLE%')", '']]),
  m('Q14', 'sqlite: a declared table matches its stored name without case', Q, [['].map(fold));', ']);']]),
  m('Q15', 'sqlite: a start whose read fails releases the lease', Q, [['      try { await read(); } catch (error) { lease?.release(); throw error; }', '      await read();']]),
  m('Q11', 'sqlite: stop releases the lease', Q, [['    async stop() { lease?.release(); },', '    async stop() {},']]),
  // The shared helpers.
  m('L1', 'lease: a run never counts itself', L, [['Number(m[2]) !== runKey && ', '']]),
  m('L2', 'lease: a dead process holds no lease', L, [[' && alive(Number(m[1]))', '']]),
  m('L3', 'lease: the file stays while another observer of the run holds it', L, [['if (count <= 0) {', 'if (true) {']]),
  m('L4', 'lease: other runs are counted in this database only', L, [['l.objid <> ${runKeyOf(runKey)}::pg_catalog.oid AND l.granted\n    AND l.database = (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database())', 'l.objid <> ${runKeyOf(runKey)}::pg_catalog.oid AND l.granted']], { live: true }),
  m('L5', 'lease: another run is another key', L, [['l.objid <> ${runKeyOf(runKey)}::pg_catalog.oid AND l.granted', 'l.granted']], { live: true }),
  m('B1', 'barrier: a count stops at the cap', B, [['LIMIT ${BARRIER_LIMITS.countCap + 1}) AS p)', ') AS p)']]),
  m('B2', 'barrier: the wait ends on a clean reading', B, [['if (reading.clean || waitedMs >= drainTimeoutMs) return', 'if (waitedMs >= drainTimeoutMs) return']]),
  m('B3', 'barrier: the wait ends at its timeout', B, [['if (reading.clean || waitedMs >= drainTimeoutMs) return', 'if (reading.clean || waitedMs >= drainTimeoutMs * 1000) return']]),
  m('B4', 'barrier: a state value is a plain token', B, [['const STATE = /^[A-Za-z0-9_.:-]{1,64}$/;', 'const STATE = /^.{1,64}$/;']]),
  m('B5', 'barrier: a queue is declared once', B, [["  if (new Set(out.map(q => `${q.schema}.${q.table}`)).size !== out.length) throw", '  if (false) throw']]),
  m('B6', 'barrier: pending rows are those in the listed states', B, [["`${asText(quote(q.pending.column))} IN (", "`${asText(quote(q.pending.column))} NOT IN ("]]),
];

function runFiles(root, files) {
  const failed = [];
  for (const file of files) {
    const out = spawnSync(process.execPath, ['--test', '--test-isolation=none', file], { cwd: root, encoding: 'utf8', timeout: 600000, env: process.env });
    const lines = (out.stdout ?? '').split('\n');
    if (out.status !== 0) failed.push(...new Set(lines.filter(l => /^✖ /.test(l)).map(l => `${file.split('/').pop()}: ${l.slice(2).replace(/ \([\d.]+ms\)$/, '')}`)), ...(out.status === null ? [`${file}: timeout`] : []));
  }
  return failed;
}

async function main() {
  const arg = flag => (process.argv.includes(flag) ? process.argv[process.argv.indexOf(flag) + 1] : null);
  const outFile = arg('--out'), only = arg('--only')?.split(',') ?? null, live = Boolean(process.env.SCOPEHAVEN_PG_LIVE);
  const tmp = mkdtempSync(join(tmpdir(), 'scopehaven bg writers mutations '));
  try {
    for (const dir of ['src', 'integrations', 'test']) cpSync(join(ROOT, dir), join(tmp, dir), { recursive: true });
    cpSync(join(ROOT, 'package.json'), join(tmp, 'package.json'));
    const base = runFiles(tmp, [...UNIT, ...(live ? LIVE : [])]);
    if (base.length) throw new Error(`Unmutated tests fail: ${base.join('; ')}`);
    const results = [];
    for (const mu of MUTATIONS.filter(x => !only || only.includes(x.id))) {
      const path = join(tmp, mu.file), original = readFileSync(path, 'utf8');
      const counts = mu.edits.map(([find]) => original.split(find).length - 1);
      if (counts.some(c => c !== 1)) { results.push({ id: mu.id, property: mu.property, status: 'not-applied', reason: `finds matched ${counts.join(', ')} times` }); process.stderr.write(`${mu.id} not-applied\n`); continue; }
      writeFileSync(path, mu.edits.reduce((text, [find, replace]) => text.replace(find, () => replace), original));
      try {
        let failed = runFiles(tmp, UNIT), by = 'unit';
        if (!failed.length && mu.live) { if (live) { failed = runFiles(tmp, LIVE); by = 'live'; } else by = 'needs-live'; }
        results.push({ id: mu.id, property: mu.property, file: mu.file, status: failed.length ? 'killed' : by === 'needs-live' ? 'needs-live' : 'SURVIVED', by, killedBy: failed.slice(0, 3) });
      } finally { writeFileSync(path, original); }
      process.stderr.write(`${mu.id} ${results.at(-1).status} ${results.at(-1).by ?? ''}\n`);
    }
    const summary = { schema: 'scopehaven-background-writers-mutations/1', at: new Date().toISOString(), node: process.version, live, unit: UNIT, liveTests: LIVE, total: results.length, killed: results.filter(r => r.status === 'killed').length, results };
    if (outFile) writeFileSync(outFile, `${JSON.stringify(summary, null, 1)}\n`);
    process.stdout.write(`${JSON.stringify({ total: summary.total, killed: summary.killed, survivors: results.filter(r => r.status !== 'killed').map(r => `${r.id} ${r.status}`) })}\n`);
    if (summary.killed !== summary.total) process.exitCode = 1;
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
