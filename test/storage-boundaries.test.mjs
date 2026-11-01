import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, lstat, realpath, chmod, chown, symlink, unlink, utimes, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { digest } from '../src/domain.mjs';
import { createStore } from '../src/store.mjs';

// Filesystem-only tests: every created or modified path is inside a temporary
// test directory, removed by its test cleanup. No production evidence is used.
async function directory(t) {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-storage-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}
const core = (id = randomUUID()) => ({ schemaVersion: 1, id, createdAt: '2026-10-03T00:00:00.000Z', targetId: 'owned-demo', counts: { pass: 1, fail: 0, inconclusive: 0, error: 0 }, results: [{ id: 'check', status: 'pass' }], limitations: [] });
const encoded = run => JSON.stringify({ core: run, sha256: digest(run) }, null, 2);
const mode = stat => stat.mode & 0o7777;
const published = dir => readdir(join(dir, 'runs'));

test('ready creates private real directories and atomic writes use private leaves without leftover temporaries', async t => {
  const parent = await directory(t), dir = join(parent, 'new-store'), store = createStore(dir);
  assert(store.ready instanceof Promise); await store.ready;
  for (const path of [dir, join(dir, 'runs'), join(dir, 'notes')]) {
    const stat = await lstat(path); assert.equal(stat.isDirectory(), true); assert.equal(stat.isSymbolicLink(), false); assert.equal(stat.uid, process.getuid()); assert.equal(mode(stat), 0o700);
  }
  const run = core(); await store.save(run); await store.note(run.id, 'check', 'Human note');
  assert.equal(mode(await lstat(join(dir, 'runs', `${run.id}.json`))), 0o600);
  assert.equal(mode(await lstat(join(dir, 'notes', `${run.id}.json`))), 0o600);
  assert.equal((await published(dir)).some(name => name.endsWith('.tmp')), false);
  assert.equal((await readdir(join(dir, 'notes'))).some(name => name.endsWith('.tmp')), false);
});

test('unsafe roots and subdirectories are rejected rather than chmodded or followed', async t => {
  const base = await directory(t), privateDir = join(base, 'private'); await mkdir(privateDir, { mode: 0o700 });
  const rootLink = join(base, 'root-link'); await symlink(privateDir, rootLink);
  await assert.rejects(createStore(rootLink).ready, /real, owner-controlled/);
  const unsafe = join(base, 'unsafe'); await mkdir(unsafe, { mode: 0o700 }); await chmod(unsafe, 0o777);
  await assert.rejects(createStore(unsafe).ready, /mode 0700/); assert.equal(mode(await lstat(unsafe)), 0o777);
  for (const component of ['runs', 'notes']) {
    const root = join(base, `symlink-${component}`); await mkdir(root, { mode: 0o700 }); await symlink(privateDir, join(root, component));
    await assert.rejects(createStore(root).ready, /real, owner-controlled/);
    const wideRoot = join(base, `wide-${component}`); await mkdir(wideRoot, { mode: 0o700 }); await mkdir(join(wideRoot, component), { mode: 0o700 }); await chmod(join(wideRoot, component), 0o755);
    await assert.rejects(createStore(wideRoot).ready, /mode 0700/); assert.equal(mode(await lstat(join(wideRoot, component))), 0o755);
  }
});

test('directory privacy is revalidated before later reads or writes', async t => {
  const dir = await directory(t), store = createStore(dir), run = core(); await store.save(run);
  for (const path of [dir, join(dir, 'runs'), join(dir, 'notes')]) {
    await chmod(path, 0o755);
    await assert.rejects(store.get(run.id), /mode 0700/); await assert.rejects(store.save(core()), /mode 0700/);
    await chmod(path, 0o700);
  }
  assert.equal((await store.get(run.id)).id, run.id);
});

test('no-follow leaf reads reject run and note symlinks, nonregular leaves and broad modes', async t => {
  const dir = await directory(t), store = createStore(dir); await store.ready;
  const outside = join(dir, 'outside-private.json'); await writeFile(outside, '{"secret":"never-expose-file-contents"}', { mode: 0o600 });
  const id = randomUUID(), leaf = join(dir, 'runs', `${id}.json`); await symlink(outside, leaf);
  await assert.rejects(store.get(id), error => /safely/.test(error.message) && !error.message.includes('never-expose'));
  await assert.rejects(store.list(), /safely/); await unlink(leaf);
  await mkdir(leaf, { mode: 0o700 }); await assert.rejects(store.get(id), /regular file/); await rm(leaf, { recursive: true });
  const run = core(); await store.save(run); const real = join(dir, 'runs', `${run.id}.json`);
  await chmod(real, 0o644); await assert.rejects(store.get(run.id), /private/); await chmod(real, 0o600);
  const noteLeaf = join(dir, 'notes', `${run.id}.json`); await symlink(outside, noteLeaf);
  await assert.rejects(store.get(run.id), /safely/); await assert.rejects(store.note(run.id, 'check', 'replacement'), /safely/);
  assert.equal(await readFile(outside, 'utf8'), '{"secret":"never-expose-file-contents"}');
});

test('non-owner leaves are rejected when the test process can create them', async t => {
  if (process.getuid() !== 0) { t.skip('Changing ownership to another UID requires root; no privilege escalation is attempted.'); return; }
  const dir = await directory(t), store = createStore(dir), run = core(); await store.save(run);
  const leaf = join(dir, 'runs', `${run.id}.json`); await chown(leaf, 1, 1);
  await assert.rejects(store.get(run.id), /owner-controlled/);
});

test('run count, retained byte and file quotas reject before publication and preserve earlier evidence', async t => {
  const countDir = await directory(t), counted = createStore(countDir, { maxRuns: 1 }), first = core(); await counted.save(first);
  await assert.rejects(counted.save(core()), error => error.status === 507);
  assert.deepEqual(await published(countDir), [`${first.id}.json`]); assert.equal((await counted.get(first.id)).results[0].status, 'pass');
  const byteDir = await directory(t), run = core(), bytes = Buffer.byteLength(encoded(run));
  const limited = createStore(byteDir, { maxTotalBytes: bytes + 20 }); await limited.save(run);
  await assert.rejects(limited.save(core()), error => error.status === 507);
  await assert.rejects(limited.note(run.id, 'check', 'note'), error => error.status === 507);
  assert.deepEqual(await published(byteDir), [`${run.id}.json`]); assert.deepEqual(await readdir(join(byteDir, 'notes')), []);
  const fileDir = await directory(t), fileLimited = createStore(fileDir, { maxFileBytes: bytes - 1 });
  await assert.rejects(fileLimited.save(run), error => error.status === 413); assert.deepEqual(await published(fileDir), []);
});

test('notes quota checks preserve prior notes and hashes; replacement never mutates computed verdicts', async t => {
  const dir = await directory(t), run = core(), store = createStore(dir, { maxTotalBytes: Buffer.byteLength(encoded(run)) + 300 });
  const saved = await store.save(run); await store.note(run.id, 'check', 'earlier note');
  const noteFile = join(dir, 'notes', `${run.id}.json`), previous = await readFile(noteFile, 'utf8');
  await assert.rejects(store.note(run.id, 'check', 'x'.repeat(1000)), error => error.status === 507);
  assert.equal(await readFile(noteFile, 'utf8'), previous);
  await store.note(run.id, 'check', 'short'); const loaded = await store.get(run.id);
  assert.equal(loaded.notes.check.note, 'short'); assert.equal(loaded.integrity.sha256, saved.integrity.sha256); assert.equal(loaded.results[0].status, 'pass');
  await assert.rejects(store.note(run.id, 'unknown', 'note'), error => error.status === 400);
  await assert.rejects(store.note(run.id, 'check', 'x'.repeat(5001)), error => error.status === 400);
});

test('exclusive immutable publication rejects duplicates and canonical-root store instances share quotas', async t => {
  const dir = await directory(t), first = createStore(dir, { maxRuns: 1 }), second = createStore(await realpath(dir), { maxRuns: 1 });
  const a = core(), b = core(), results = await Promise.allSettled([first.save(a), second.save(b)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.find(result => result.status === 'rejected').reason.status, 507);
  const existing = results.find(result => result.status === 'fulfilled').value;
  await assert.rejects(second.save({ ...existing, notes: undefined, integrity: undefined }), error => error.status === 409);
  assert.equal((await first.list()).length, 1); assert.equal((await published(dir)).length, 1);
});

test('pagination uses stable mtime-plus-ID cursors without dropping duplicate timestamps', async t => {
  const dir = await directory(t), store = createStore(dir); await store.ready;
  const ids = Array.from({ length: 7 }, () => randomUUID()), time = new Date('2026-10-03T00:00:00Z');
  for (const id of ids) { const file = join(dir, 'runs', `${id}.json`); await writeFile(file, encoded(core(id)), { mode: 0o600 }); await utimes(file, time, time); }
  const seen = []; let before;
  do {
    const page = await store.historyPage({ limit: 2, ...(before ? { before } : {}) });
    assert.equal(page.total, 7); assert(page.runs.length <= 2); seen.push(...page.runs.map(run => run.id)); before = page.nextCursor;
  } while (before);
  assert.equal(new Set(seen).size, 7); assert.deepEqual(seen, ids.sort((a, b) => b.localeCompare(a)));
  for (const limit of [0, 101, 1.5, '2']) await assert.rejects(store.list({ limit }), error => error.status === 400);
  for (const cursor of ['', 'not-json', '../path', 'a'.repeat(257), Buffer.from(JSON.stringify({ v: 1, id: randomUUID(), mtimeNs: '1', extra: true })).toString('base64url')]) await assert.rejects(store.historyPage({ before: cursor }), error => error.status === 400);
});

test('default latest page is bounded and older malformed JSON is not parsed outside the selected page', async t => {
  const dir = await directory(t), store = createStore(dir); await store.ready;
  const old = randomUUID(), oldFile = join(dir, 'runs', `${old}.json`); await writeFile(oldFile, '{private-invalid-json-content', { mode: 0o600 }); await utimes(oldFile, new Date(0), new Date(0));
  for (let i = 0; i < 55; i++) { const run = core(); await writeFile(join(dir, 'runs', `${run.id}.json`), encoded(run), { mode: 0o600 }); }
  assert.equal((await store.list()).length, 50);
  const latest = await store.historyPage({ limit: 55 }); assert.equal(latest.runs.length, 55); assert.equal(latest.total, 56);
  await assert.rejects(store.historyPage({ limit: 1, before: latest.nextCursor }), error => /invalid JSON/.test(error.message) && !error.message.includes('private-invalid'));
});

test('metadata scans are bounded and interrupted temporary files are ignored without deletion', async t => {
  const dir = await directory(t), store = createStore(dir, { maxRuns: 1 }), run = core(); await store.save(run);
  const temporary = join(dir, 'runs', '.interrupted.tmp'); await writeFile(temporary, '{incomplete', { mode: 0o600 });
  assert.deepEqual((await store.list()).map(item => item.id), [run.id]); assert.equal(await readFile(temporary, 'utf8'), '{incomplete');
  await Promise.all(Array.from({ length: 1001 }, (_, i) => writeFile(join(dir, 'runs', `.interrupted-${i}.tmp`), '', { mode: 0o600 })));
  await assert.rejects(store.historyPage(), /metadata scan exceeds/);
  assert.equal((await store.get(run.id)).id, run.id);
});

test('file and identifier guards reject unsafe reads without exposing contents', async t => {
  const dir = await directory(t), store = createStore(dir, { maxFileBytes: 512 }); await store.ready;
  for (const id of ['../outside', '__proto__', `${randomUUID()}/other`, '']) await assert.rejects(store.get(id), error => error.status === 400);
  const id = randomUUID(); await writeFile(join(dir, 'runs', `${id}.json`), 'secret-file-marker'.repeat(100), { mode: 0o600 });
  await assert.rejects(store.get(id), error => /bounded/.test(error.message) && !error.message.includes('secret-file-marker'));
  await assert.rejects(store.get(randomUUID()), error => error.status === 404);
});
