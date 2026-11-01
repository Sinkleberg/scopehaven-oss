// L8 fix 1b: the sqlite-snapshot reader's compact state. Rows live in sealed chunks shared between marks, keys outside the JS
// heap and a typed-array index, with windows as the reader gave before. Local temp databases only; the memory test runs in a child process.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { createSqliteSnapshotObserver } from './sqlite.mjs';

const opsOf = window => window.events.map(e => `${e.operation} ${e.resource}`);
const database = (t, ddl) => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven sqlite memory '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'app.db'), db = new DatabaseSync(path);
  db.exec(ddl);
  t.after(() => db.close());
  return { dir, path, db };
};
const fill = (db, rows, sql, row) => { const s = db.prepare(sql); db.exec('BEGIN'); for (let i = 1; i <= rows; i++) s.run(...row(i)); db.exec('COMMIT'); };

test('L8 fix 1b: across chunk boundaries a window reports each insert, update and delete, inserts and updates in key order, then deletes', async t => {
  const { path, db } = database(t, 'CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
  fill(db, 9000, 'INSERT INTO t VALUES (?, ?)', i => [i * 2, `v${i}`]);
  const o = createSqliteSnapshotObserver({ path, tables: [{ table: 't', key: 'id' }] });
  await o.start();
  const m0 = await o.mark();
  // A row in the second chunk, the last row of the first chunk and a row past both chunks' ends.
  db.exec("UPDATE t SET v = 'changed' WHERE id IN (10000, 8192, 18000)");
  // A delete in the first chunk moves every later row one place, so their chunks no longer line up with the earlier mark.
  db.exec('DELETE FROM t WHERE id = 200');
  const m1 = await o.mark();
  // An insert between existing keys moves them the other way, and one past the end.
  db.exec("INSERT INTO t VALUES (9, 'new'), (100001, 'new')");
  db.exec('DELETE FROM t WHERE id = 18000');
  const m2 = await o.mark();
  const quiet = await o.mark();
  assert.deepEqual(opsOf(await o.collect(m0, m1)), ['update t/8192', 'update t/10000', 'update t/18000', 'delete t/200']);
  assert.deepEqual(opsOf(await o.collect(m1, m2)), ['insert t/9', 'insert t/100001', 'delete t/18000']);
  assert.deepEqual(opsOf(await o.collect(m0, m2)), ['insert t/9', 'update t/8192', 'update t/10000', 'insert t/100001', 'delete t/200', 'delete t/18000']);
  assert.deepEqual(opsOf(await o.collect(m2, quiet)), []);
  // Each event carries its own row digest.
  const window = await o.collect(m0, m1);
  assert.equal(new Set(window.events.map(e => e.contentDigest)).size, 4);
  await o.stop();
});

test('L8 fix 1b: keys of any stored type match across marks by their text, and a key whose text repeats anywhere in a table decides nothing', async t => {
  const { path, db } = database(t, 'CREATE TABLE t (k, v TEXT); CREATE TABLE d (k, v TEXT); CREATE TABLE n (k TEXT COLLATE NOCASE, v TEXT)');
  const keys = [7, 'text', 1.5, Buffer.from([1, 2]), 'é-ü', '', '日本'];
  fill(db, keys.length, 'INSERT INTO t VALUES (?, ?)', i => [keys[i - 1], `v${i}`]);
  const o = createSqliteSnapshotObserver({ path, tables: [{ table: 't', key: 'k' }] });
  await o.start();
  const a = await o.mark();
  db.exec("UPDATE t SET v = 'x' WHERE k = 'é-ü'; UPDATE t SET v = 'x' WHERE k = ''; DELETE FROM t WHERE k = '日本'; INSERT INTO t VALUES ('日本語', 'new')");
  const b = await o.mark();
  assert.deepEqual(opsOf(await o.collect(a, b)).sort(), ['delete t/日本', 'insert t/日本語', 'update t/', 'update t/é-ü']);
  await o.stop();
  // 1 and '1' sort apart, with other rows between them, and read as one key: every window on the table fails, as a Set of keys would have it.
  db.exec("INSERT INTO d VALUES (1, 'a'), (2, 'b'), (3, 'c'), ('x', 'd'), ('1', 'e')");
  const dup = createSqliteSnapshotObserver({ path, tables: [{ table: 'd', key: 'k' }] });
  await dup.start();
  const [c, e] = [await dup.mark(), await dup.mark()];
  assert.deepEqual([(await dup.collect(c, e)).coverage, (await dup.collect(c, e)).reason], ['failed', 'duplicate-key']);
  await dup.stop();
  // 'a' and 'A' are equal under NOCASE and different text: both are distinct keys, and both are seen.
  db.exec("INSERT INTO n VALUES ('a', '1'), ('A', '2'), ('b', '3')");
  const nocase = createSqliteSnapshotObserver({ path, tables: [{ table: 'n', key: 'k' }] });
  await nocase.start();
  const f = await nocase.mark();
  db.prepare('UPDATE n SET v = ? WHERE k = ? AND v = ?').run('9', 'A', '2');
  const g = await nocase.mark();
  assert.deepEqual(opsOf(await nocase.collect(f, g)), ['update n/A']);
  await nocase.stop();
});

test('L8 fix 1b: a change-column table still decides exactness row by row, with the watched rows found by key', async t => {
  const { dir, path, db } = database(t, 'CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT, stamp INTEGER)');
  const old = Math.floor(Date.now() / 1000) - 100000;
  fill(db, 5000, 'INSERT INTO t VALUES (?, ?, ?)', i => [i, `v${i}`, old]);
  const audit = join(dir, 'audit.txt');
  writeFileSync(audit, 'source');
  const o = createSqliteSnapshotObserver({ path, tables: [{ table: 't', key: 'id', changeColumn: { column: 'stamp', unit: 'seconds', audit } }], changeColumnSkewMs: 1000, maxCommitLagMs: 0, watchedResources: ['t/1', 't/4500', 't/4999', 't/77777', 'other/1'] });
  await o.start();
  const a = await o.mark();
  db.exec(`UPDATE t SET v = 'moved', stamp = ${old + 1} WHERE id = 4500; DELETE FROM t WHERE id = 4999; INSERT INTO t VALUES (6000, 'new', ${old})`);
  const b = await o.mark();
  const window = await o.collect(a, b), [exact] = window.exact;
  assert.deepEqual(opsOf(window), ['update t/4500', 'insert t/6000', 'delete t/4999']);
  assert.deepEqual([exact.violated, exact.ambiguousResources, exact.presentResources], [false, ['t/4999', 't/6000'], ['t/1', 't/4500']]);
  // Content changed under an unchanged stamp: the assertion does not hold, and the table reports nothing.
  db.exec("UPDATE t SET v = 'silent' WHERE id = 2");
  const c = await o.mark(), broken = await o.collect(b, c);
  assert.deepEqual([broken.exact[0].violated, broken.events.length], [true, 0]);
  await o.stop();
});

// One child, garbage collected before each reading: what the marks retain, in the JS heap and outside it.
const CHILD = `
import { DatabaseSync } from 'node:sqlite';
const [modulePath, path, marksArg] = process.argv.slice(1), marks = Number(marksArg);
const { createSqliteSnapshotObserver } = await import(modulePath);
const held = () => { globalThis.gc(); const m = process.memoryUsage(); return m.heapUsed + m.arrayBuffers; };
const writer = new DatabaseSync(path), o = createSqliteSnapshotObserver({ path, tables: [{ table: 't', key: 'id' }] });
const before = held();
await o.start();
const cursors = [await o.mark()], one = held() - before;
for (let k = 1; k < marks; k++) { writer.prepare('UPDATE t SET v = ? WHERE id = ?').run('w' + k, 1 + k * 7919 % 100000); cursors.push(await o.mark()); }
const all = held() - before;
const window = await o.collect(cursors[0], cursors.at(-1));
console.log(JSON.stringify({ one, all, events: window.events.length, marks: cursors.length }));
await o.stop(); writer.close();
`;
test('L8 fix 1b: twelve marks of a table with small writes retain about one state, under 80 bytes a row', async t => {
  const { path, db } = database(t, 'CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
  const rows = 100000;
  fill(db, rows, 'INSERT INTO t VALUES (?, ?)', i => [i, `value ${i}`]);
  const moduleUrl = new URL('./sqlite.mjs', import.meta.url).href;
  const child = spawnSync(process.execPath, ['--expose-gc', '--no-warnings', '--input-type=module', '-e', CHILD, moduleUrl, path, '12'], { encoding: 'utf8', timeout: 120000, cwd: fileURLToPath(new URL('.', import.meta.url)) });
  assert.equal(child.status, 0, child.stderr);
  const { one, all, events, marks } = JSON.parse(child.stdout.trim().split('\n').at(-1));
  assert.deepEqual([marks, events], [12, 11]);
  assert.ok(all / rows < 80, `retained ${Math.round(all / rows)} bytes a row`);
  assert.ok(all < one * 1.5, `twelve marks retained ${Math.round(all / 1048576)} MiB, one mark ${Math.round(one / 1048576)} MiB`);
});
