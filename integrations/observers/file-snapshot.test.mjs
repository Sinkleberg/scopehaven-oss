import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, symlinkSync, unlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateFileSnapshotConfig, takeFileSnapshot, fileReport, FILE_SNAPSHOT_SCHEMA } from './file-snapshot.mjs';

const sha = text => createHash('sha256').update(text).digest('hex');

test('L8 fix 5: files.json is refused unless every root is a plain absolute directory and every bound holds', t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven files '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, 'a')); mkdirSync(join(dir, 'a', 'inner')); mkdirSync(join(dir, 'b')); writeFileSync(join(dir, 'plain.txt'), 'x');
  symlinkSync(join(dir, 'b'), join(dir, 'link-to-b'));
  const ok = validateFileSnapshotConfig({ roots: [{ alias: 'a', path: join(dir, 'a') }, { alias: 'b', path: join(dir, 'b') }] });
  assert.deepEqual([ok.roots.map(r => r.alias), ok.maxFiles, ok.maxFileBytes], [['a', 'b'], 20000, 64 * 1024 * 1024]);
  for (const [config, pattern] of [
    [[], /must be an object/], [{ roots: [] }, /1 to 16/], [{ roots: [{ alias: 'a', path: join(dir, 'a') }], extra: 1 }, /unknown key/],
    [{ roots: [{ alias: 'a', path: 'relative/dir' }] }, /absolute path/],
    [{ roots: [{ alias: 'a', path: join(dir, 'missing') }] }, /not a readable directory/],
    [{ roots: [{ alias: 'a', path: join(dir, 'plain.txt') }] }, /directory, not a symlink/],
    [{ roots: [{ alias: 'l', path: join(dir, 'link-to-b') }] }, /directory, not a symlink/],
    [{ roots: [{ alias: 'a', path: join(dir, 'a') }, { alias: 'i', path: join(dir, 'a', 'inner') }] }, /overlaps/],
    [{ roots: [{ alias: 'a', path: join(dir, 'a') }, { alias: 'a', path: join(dir, 'b') }] }, /distinct identifier/],
    [{ roots: [{ alias: '../x', path: join(dir, 'a') }] }, /distinct identifier/],
    [{ roots: [{ alias: 'a', path: join(dir, 'a'), extra: 1 }] }, /exactly/],
    [{ roots: [{ alias: 'a', path: join(dir, 'a') }], exclude: ['/etc/*'] }, /relative patterns/],
    [{ roots: [{ alias: 'a', path: join(dir, 'a') }], maxFiles: 0 }, /maxFiles/],
    [{ roots: [{ alias: 'a', path: join(dir, 'a') }], maxFileBytes: 2 ** 31 }, /maxFileBytes/]])
    assert.throws(() => validateFileSnapshotConfig(config), pattern, JSON.stringify(config));
});

test('L8 fix 5: two snapshots report added, changed and removed files by digest only; links are never followed and a FIFO is never opened', t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven files '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const root = join(dir, 'exports'), outside = join(dir, 'outside-secret.txt');
  mkdirSync(join(root, 'sub'), { recursive: true }); mkdirSync(join(root, 'cache'));
  writeFileSync(outside, 'secret outside the root');
  writeFileSync(join(root, 'a.txt'), 'first export');
  writeFileSync(join(root, 'sub', 'b.bin'), 'to be removed');
  writeFileSync(join(root, 'cache', 'x.tmp'), 'cache 1');
  symlinkSync(outside, join(root, 'link'));
  const fifo = spawnSync('mkfifo', [join(root, 'pipe')]).status === 0;
  const config = validateFileSnapshotConfig({ roots: [{ alias: 'exports', path: root }], exclude: ['cache/**'] });
  const start = takeFileSnapshot(config);
  assert.equal(start.ok, true);
  // The link is listed by a digest of its text, never by the content it points at; the FIFO is present, never read.
  assert.deepEqual(start.entries.get('exports/link'), { type: 'symlink', sha256: sha(outside) });
  if (fifo) assert.deepEqual(start.entries.get('exports/pipe'), { type: 'special', sha256: null });
  assert.ok(![...start.entries.keys()].some(k => k.startsWith('exports/cache/')), 'excluded paths are never read');
  writeFileSync(join(root, 'a.txt'), 'second export');
  writeFileSync(join(root, 'sub', 'c.txt'), 'refund batch 7');
  unlinkSync(join(root, 'sub', 'b.bin'));
  unlinkSync(join(root, 'link')); symlinkSync(join(dir, 'elsewhere'), join(root, 'link'));
  writeFileSync(join(root, 'cache', 'x.tmp'), 'cache 2');
  const end = takeFileSnapshot(config);
  const report = fileReport(config, start, end, { sequenceId: 'SEQ', runFile: 'SEQ-1.json' });
  assert.equal(report.schema, FILE_SNAPSHOT_SCHEMA); assert.equal(report.reportOnly, true); assert.equal(report.coverage, 'net-only');
  assert.deepEqual(report.changes.map(c => `${c.operation} ${c.resource}`), ['update exports/a.txt', 'update exports/link', 'insert exports/sub/c.txt', 'delete exports/sub/b.bin']);
  assert.deepEqual(report.changes.find(c => c.resource === 'exports/sub/c.txt'), { operation: 'insert', resource: 'exports/sub/c.txt', type: 'file', size: 14, sha256: sha('refund batch 7') });
  const text = JSON.stringify(report);
  for (const content of ['second export', 'refund batch 7', 'secret outside the root', 'cache 2']) assert.ok(!text.includes(content), content);
  // Not a window and not a verdict: no events, coverage window fields or evidence kinds.
  for (const key of ['events', 'instanceId', 'scope', 'verdict', 'evidence']) assert.ok(!Object.hasOwn(report, key), key);
});

test('L8 fix 5: a snapshot past a bound fails with its reason, and the report then compares nothing', t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven files '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const name of ['one', 'two', 'three']) writeFileSync(join(dir, name), '0123456789');
  const many = validateFileSnapshotConfig({ roots: [{ alias: 'd', path: dir }], maxFiles: 2 });
  assert.deepEqual(takeFileSnapshot(many).reason, 'file-limit');
  const big = validateFileSnapshotConfig({ roots: [{ alias: 'd', path: dir }], maxFileBytes: 5 });
  const failed = takeFileSnapshot(big);
  assert.deepEqual([failed.ok, failed.reason], [false, 'file-too-large']);
  const fine = validateFileSnapshotConfig({ roots: [{ alias: 'd', path: dir }] });
  const report = fileReport(fine, takeFileSnapshot(fine), failed);
  assert.deepEqual([report.coverage, report.changes, report.end], ['failed', [], { at: failed.at, ok: false, reason: 'file-too-large' }]);
  let deep = dir;
  for (let i = 0; i < 66; i++) { deep = join(deep, 'd'); mkdirSync(deep); }
  assert.equal(takeFileSnapshot(fine).reason, 'too-deep');
});
