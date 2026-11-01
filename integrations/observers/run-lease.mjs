// The shared-database rule (N12, lead-queue item 2): reseeded runs never share one database. Two runs observing one
// database at once see each other's writes (a reseed, the other run's checks) inside their own windows, which can fail a
// check on noise or hide an effect, so each database observer holds a run lease and looks for another run's.
//   - Postgres: a session-level shared advisory lock (classid LEASE_CLASS, objid this process's RUN_KEY) held by a session
//     the observer keeps open for the run. Shared locks never block anyone, the app included; another run's lease is the
//     same lock class under a different RUN_KEY in this database, visible in pg_locks to every role. Advisory locks write no
//     WAL and change no catalog.
//   - SQLite: a lease file in a folder per database (the folder named by a sha256 of the database's resolved path) under
//     this machine's temporary directory, the file named by process id and RUN_KEY; another run's is a file under a
//     different RUN_KEY whose process is alive. The observer never writes beside the application's database.
// One process is one run: every observer in it shares RUN_KEY, so a pg-snapshot and a pg-wal of the same run on one
// database never see each other. An observer refuses to start when another run already holds a lease on its database,
// and a window either of whose marks saw another run's lease reads partial with shared-database: no absence passes on
// it, and the events it read stay, so a fail stays a fail (anything can take a lock of this class, the application
// under test included, and it must not erase its own fails that way; a fail in such a window can be the other run's
// write, so re-run it alone). A pg-snapshot whose lease session ended takes the lease again at its next mark. What it cannot see: a run that holds no lease (an older version, an observer
// with the lease off, a reseed script started before the observers), and on SQLite a run under another user or another
// temporary directory. Start the observers before reseeding, so a second run is refused before it writes anything.
import { randomInt, createHash } from 'node:crypto';
import { mkdirSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// "SHLS" as a 32-bit integer: the advisory lock class every ScopeHaven run lease uses.
export const LEASE_CLASS = 0x53484c53;
export const RUN_KEY = randomInt(1, 2 ** 31 - 1);
const runKeyOf = key => { if (!Number.isInteger(key) || key < 1 || key >= 2 ** 31) throw new Error('runKey is an integer from 1 to 2^31 - 1.'); return key; };

export const pgLeaseSql = (runKey = RUN_KEY) => `/* sh:lease */ SELECT pg_catalog.pg_try_advisory_lock_shared(${LEASE_CLASS}, ${runKeyOf(runKey)})::text`;
// Other runs holding a lease in this database (distinct RUN_KEYs).
export const pgOtherRunsSql = (runKey = RUN_KEY) => `/* sh:shared */ SELECT pg_catalog.count(DISTINCT l.objid)::text FROM pg_catalog.pg_locks l WHERE l.locktype = 'advisory'
    AND l.classid = ${LEASE_CLASS}::pg_catalog.oid AND l.objsubid = 2 AND l.objid <> ${runKeyOf(runKey)}::pg_catalog.oid AND l.granted
    AND l.database = (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database())`;

// This run's own lease in this database (0 when the session that held it is gone).
export const pgOwnLeaseSql = (runKey = RUN_KEY) => `/* sh:ownlease */ SELECT pg_catalog.count(*)::text FROM pg_catalog.pg_locks l WHERE l.locktype = 'advisory'
    AND l.classid = ${LEASE_CLASS}::pg_catalog.oid AND l.objsubid = 2 AND l.objid = ${runKeyOf(runKey)}::pg_catalog.oid AND l.granted
    AND l.database = (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database())`;

// SQLite: one lease file per process and database, shared by the process's observers (counted), removed with the last.
const held = new Map();
const alive = pid => { try { process.kill(pid, 0); return true; } catch (error) { return error.code === 'EPERM'; } };
export function fileLease(path, { runKey = RUN_KEY, root = join(tmpdir(), 'scopehaven-run-leases') } = {}) {
  runKeyOf(runKey);
  const folder = () => join(root, createHash('sha256').update(realpathSync(path)).digest('hex').slice(0, 32));
  const entry = `${process.pid}-${runKey}`;
  let mine = null;
  return {
    // Other runs' live leases on this database.
    others() {
      let names;
      try { names = readdirSync(mine ?? folder()); } catch (error) { if (error.code === 'ENOENT') return 0; throw error; }
      return new Set(names.map(n => /^(\d+)-(\d+)$/.exec(n)).filter(m => m && Number(m[2]) !== runKey && alive(Number(m[1]))).map(m => m[2])).size;
    },
    acquire() {
      if (mine) return;
      mine = folder();
      const key = join(mine, entry), count = held.get(key) ?? 0;
      if (!count) { mkdirSync(mine, { recursive: true }); writeFileSync(key, new Date().toISOString()); }
      held.set(key, count + 1);
    },
    release() {
      if (!mine) return;
      const key = join(mine, entry), count = (held.get(key) ?? 1) - 1;
      if (count <= 0) { held.delete(key); rmSync(key, { force: true }); } else held.set(key, count);
      mine = null;
    },
  };
}
