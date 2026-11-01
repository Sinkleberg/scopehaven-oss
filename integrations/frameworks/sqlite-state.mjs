// SQLite state snapshot for the turn runner: ScopeHaven's own process reads the
// operator-named database file between turns. The agent and the app never
// produce these rows, so the snapshot is ScopeHaven-taken (state.mjs).
//
// The live file is never opened by SQLite (opening it, even read-only, can
// create -wal/-shm files and take locks the app's writers would wait on). It
// is copied byte for byte (an APFS clone where the file system allows) and the
// copy is accepted only when no commit landed during the copy, by the same
// tests integrations/observers/sqlite.mjs uses: for a rollback-journal file,
// no hot journal, the same header change counter (bytes 24-27) before, after
// and in the copy, and the file itself (inode, size, mtime) unchanged, which
// also catches commits under exclusive locking, where the counter stays put; for a WAL file, the database file and the WAL header
// (checkpoint sequence and salts) unchanged across copying both. Otherwise the
// copy is retried and then the snapshot fails ('no-consistent-copy'). Queries
// run on the private copy only.
import { DatabaseSync } from 'node:sqlite';
import { closeSync, constants, copyFileSync, mkdtempSync, openSync, readSync, rmSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonical, STATE_DIFF_LIMITS } from '../collateral/state-diff.mjs';
import { IDENT, REMAINDER_KEY, projectRow, StateSpecError } from './state.mjs';

export const SQLITE_COPY_ATTEMPTS = 5;
const quote = name => { if (!IDENT.test(name)) throw new StateSpecError('identifier'); return `"${name}"`; };
function header(path) {
  const fd = openSync(path, 'r'), buf = Buffer.alloc(100);
  try { if (readSync(fd, buf, 0, 100, 0) < 100 || buf.toString('latin1', 0, 15) !== 'SQLite format 3') throw new StateSpecError('not-sqlite'); } finally { closeSync(fd); }
  return { wal: buf[18] === 2, counter: buf.readUInt32BE(24) };
}
const hotJournal = path => { try { return statSync(`${path}-journal`).size > 0; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } };
function walState(path) {
  let fd;
  try { fd = openSync(`${path}-wal`, 'r'); } catch (error) { if (error.code === 'ENOENT') return 'none'; throw error; }
  try { const buf = Buffer.alloc(32); return readSync(fd, buf, 0, 32, 0) < 32 ? 'empty' : buf.toString('hex', 12, 24); } finally { closeSync(fd); }
}
const fileState = path => { const st = statSync(path, { bigint: true }); return `${st.ino}:${st.size}:${st.mtimeNs}`; };
export const cloneFile = (from, to) => copyFileSync(from, to, constants.COPYFILE_FICLONE);

// A private copy that no commit touched, or an error. Returns the copy's path.
// `clone` copies one file; tests pass one that lands a commit mid-copy.
async function consistentCopy(path, dir, clone) {
  const copy = join(dir, 'snapshot.db');
  for (let attempt = 0; attempt < SQLITE_COPY_ATTEMPTS; attempt++) {
    if (attempt) await new Promise(resolve => setTimeout(resolve, 25 * attempt));
    rmSync(copy, { force: true }); rmSync(`${copy}-wal`, { force: true }); rmSync(`${copy}-shm`, { force: true });
    const first = header(path);
    if (first.wal) {
      const wal = walState(path), file = fileState(path);
      clone(path, copy);
      if (wal !== 'none') try { clone(`${path}-wal`, `${copy}-wal`); } catch (error) { if (error.code !== 'ENOENT') throw error; continue; }
      if (walState(path) === wal && fileState(path) === file && header(path).counter === first.counter && header(copy).wal) return { copy, wal: true };
      continue;
    }
    if (hotJournal(path)) continue;
    // The file itself must not change either: under exclusive locking the change counter does not move.
    const file = fileState(path);
    clone(path, copy);
    if (!hotJournal(path) && fileState(path) === file && header(path).counter === first.counter && header(copy).counter === first.counter && !header(copy).wal) return { copy, wal: false };
  }
  throw new StateSpecError('no-consistent-copy');
}

function whereClause(where) {
  if (where === undefined) return { sql: '1', params: [] };
  const parts = [], params = [];
  for (const [column, value] of Object.entries(where)) {
    const values = Array.isArray(value) ? value : [value];
    parts.push(`${quote(column)} IN (${values.map(() => '?').join(', ')})`);
    params.push(...values);
  }
  return { sql: parts.join(' AND '), params };
}
const plainRow = row => Object.fromEntries(Object.entries(row));

// Read every sqlite-file projection from one consistent copy.
function readProjections(db, projections) {
  const state = {};
  for (const p of projections) {
    const keySql = p.key === 'rowid' ? 'rowid AS "rowid", ' : '';
    const { sql, params } = whereClause(p.where);
    const rows = db.prepare(`SELECT ${keySql}* FROM ${quote(p.table)} WHERE ${sql} ORDER BY ${quote(p.key)} LIMIT ${STATE_DIFF_LIMITS.rowsPerCollection + 1}`).all(...params);
    if (rows.length > STATE_DIFF_LIMITS.rowsPerCollection) throw new StateSpecError('row-limit');
    const projected = rows.map(r => projectRow(plainRow(r), p));
    if (p.remainder) {
      // Every row the watch leaves out, in key order, folded into one digest. A
      // NULL in a watched column counts as outside the watch, so no row is in neither.
      const hash = createHash('sha256');
      let count = 0;
      for (const r of db.prepare(`SELECT ${keySql}* FROM ${quote(p.table)} WHERE NOT coalesce((${sql}), 0) ORDER BY ${quote(p.key)}`).iterate(...params)) {
        hash.update(canonical(Object.fromEntries(Object.entries(r).map(([f, v]) => [f, v instanceof Uint8Array ? `bytes:${Buffer.from(v).toString('hex')}` : v]))));
        hash.update('\n');
        count++;
      }
      projected.push({ [p.key]: REMAINDER_KEY, rows: count, digest: `#${hash.digest('hex')}` });
    }
    state[p.collection] = projected;
  }
  return state;
}

// One snapshot: { ok, at, takenBy: 'scopehaven', source, state } or { ok: false, reason }.
export async function snapshotSqlite(path, projections, { clone = cloneFile } = {}) {
  const at = new Date().toISOString();
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-frameworks-'));
  try {
    const { copy, wal } = await consistentCopy(path, dir, clone);
    // A WAL copy is recovered by SQLite from its copied log, so it is opened writable; it is private.
    const db = new DatabaseSync(copy, wal ? {} : { readOnly: true });
    try { return { ok: true, at, takenBy: 'scopehaven', source: 'sqlite-file', state: readProjections(db, projections) }; }
    finally { db.close(); }
  } catch (error) {
    const reason = error instanceof StateSpecError ? error.code : error.code === 'ENOENT' ? 'file-missing' : 'read-failed';
    return { ok: false, at, takenBy: 'scopehaven', source: 'sqlite-file', reason };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
