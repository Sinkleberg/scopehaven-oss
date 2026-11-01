import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createSqliteSnapshotObserver } from '../observers/sqlite.mjs';
import { evaluateEffectAssertion } from '../../src/effect-events.mjs';
import { custodyOf, subjectIntegrityVerdict } from './custody.mjs';

// Why sql-snapshot is subject-writable, against a real observer rather than a
// stub. The observer computes the delta itself, so the subject cannot present a
// selective view, but it still controls the state's content. Owned synthetic
// SQLite files in a temp directory: no network, no model, nothing saved as
// evidence.

const collect = async (observer, from, to) => {
  const out = await observer.collect(from, to);
  return { kind: observer.kind, instanceId: observer.instanceId, source: observer.source, scope: observer.scope, ...out };
};

const setup = async t => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-evid-subject-snap-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'app.db');
  const db = new DatabaseSync(path);
  db.exec(`PRAGMA journal_mode=WAL;
    CREATE TABLE refunds (id INTEGER PRIMARY KEY, status TEXT, updated_at INTEGER);
    INSERT INTO refunds VALUES (1, 'pending', 1000);`);
  return { dir, path, db };
};

const SELECT = Object.freeze({ source: 'sql-snapshot', operation: 'update', name: 'refunds' });

test('write-then-revert: the state changed, the snapshot shows nothing', async t => {
  const { path, db } = await setup(t);
  const snap = createSqliteSnapshotObserver({ path, tables: [{ table: 'refunds', key: 'id' }] });
  await snap.start();
  const s0 = await snap.mark();

  // The prohibited effect happens and is undone before the second mark, with the
  // change column reset so it does not betray the write.
  db.exec(`UPDATE refunds SET status = 'approved', updated_at = 2000 WHERE id = 1;`);
  db.exec(`UPDATE refunds SET status = 'pending', updated_at = 1000 WHERE id = 1;`);

  const window = await collect(snap, s0, await snap.mark());
  assert.deepEqual(window.events, [], 'a reverted write leaves no net change');

  // The effect rules alone reach a pass here: nothing was observed.
  const decision = evaluateEffectAssertion({ kind: 'effect.none', select: SELECT }, [window]);
  assert.ok(['pass', 'unobservable', 'missing'].includes(decision.verdict), decision.verdict);

  // Custody is what stops that pass from standing, because the subject owns the
  // table the snapshot reads.
  assert.equal(custodyOf(window), 'subject-writable');
  const decided = subjectIntegrityVerdict({ proposed: decision.verdict === 'pass' ? 'pass' : 'inconclusive',
    select: SELECT, support: [window] });
  assert.notEqual(decided.verdict, 'pass');
  assert.ok(decided.reasons.includes('subject-writable-custody'));
});

test('file swap: the observer reads the path, and the inode is never compared', async t => {
  const { dir, path, db } = await setup(t);
  const snap = createSqliteSnapshotObserver({ path, tables: [{ table: 'refunds', key: 'id' }] });
  await snap.start();
  const s0 = await snap.mark();

  db.exec(`UPDATE refunds SET status = 'approved', updated_at = 2000 WHERE id = 1;`);
  db.close();

  // A decoy database with the original state, swapped in under the same path.
  const decoyPath = join(dir, 'decoy.db');
  const decoy = new DatabaseSync(decoyPath);
  decoy.exec(`PRAGMA journal_mode=WAL;
    CREATE TABLE refunds (id INTEGER PRIMARY KEY, status TEXT, updated_at INTEGER);
    INSERT INTO refunds VALUES (1, 'pending', 1000);`);
  decoy.close();
  await copyFile(decoyPath, path);

  const window = await collect(snap, s0, await snap.mark());
  // Whatever the observer reports, it must not be the basis of a pass: the file
  // it read is one the subject can replace.
  assert.equal(custodyOf(window), 'subject-writable');
  const decided = subjectIntegrityVerdict({ proposed: 'pass', select: SELECT, support: [window] });
  assert.notEqual(decided.verdict, 'pass');
  assert.ok(decided.reasons.includes('subject-writable-custody'));
});

test('a snapshot window cannot be declared independent', () => {
  const window = { source: 'sql-snapshot', coverage: 'complete', events: [],
    scope: { operations: ['update'], names: ['refunds'], actorAttribution: 'none', evidence: 'authoritative' } };
  assert.equal(custodyOf(window, { declared: 'independent' }), 'subject-writable');
  assert.equal(custodyOf(window, { declared: 'observer-held' }), 'subject-writable');
  const decided = subjectIntegrityVerdict({ proposed: 'pass', select: SELECT,
    support: [{ ...window, declaredCustody: 'independent' }] });
  assert.equal(decided.verdict, 'inconclusive');
  assert.ok(decided.reasons.includes('subject-writable-custody'));
});
