// Release Permission Diff on real lab runs (owned synthetic HTTP lab, loopback).
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHttpLab, makeLabProfile } from '../../examples/http-lab.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { permissionDiff, classifyDiff, buildReport } from './summary.mjs';

let lab, runs = {};
before(async () => {
  lab = await createHttpLab({ build: 'repaired' });
  const env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken };
  runs.repaired = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-repaired'), { env });
  lab.setBuild('baseline');
  runs.baseline = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-baseline'), { env });
  const other = makeLabProfile(lab.origin, 'lab-baseline');
  const dropped = other.checks.find(c => c.severity !== 'control' && !other.requiredControlIds.includes(c.id));
  other.checks = other.checks.filter(c => c !== dropped); // a different suite
  runs.otherSuite = await runHttpAssessment(other, { env });
});
after(async () => { await lab.close(); });

test('a release that breaks a boundary shows DENY -> ALLOW flips; the reverse shows restored', () => {
  const regressed = permissionDiff(runs.repaired, runs.baseline);
  assert.equal(regressed.comparable, true);
  assert.ok(regressed.flips.length >= 1, 'flips');
  for (const f of regressed.flips) { assert.equal(f.before, 'pass'); assert.equal(f.after, 'fail'); assert.notEqual(f.severity, 'control'); }
  assert.equal(regressed.brokenControls.length, 0);
  // The lab's backend-required check is inconclusive on the repaired build and fails on the regressed one.
  assert.deepEqual(regressed.newFailures.map(r => r.id), ['BACKEND-UNVERIFIED']);
  const fixed = permissionDiff(runs.baseline, runs.repaired);
  assert.equal(fixed.flips.length, 0);
  assert.deepEqual(fixed.restored.map(r => r.id).sort(), regressed.flips.map(r => r.id).sort());
});

test('runs with different identities are not comparable and show no per-check cells', () => {
  const diff = permissionDiff(runs.baseline, runs.otherSuite);
  assert.equal(diff.comparable, false);
  assert.ok(diff.reasons.length > 0);
  assert.equal(diff.flips, undefined);
  // A tampered run fails the shared evidence validator, so it is not comparable either.
  const tampered = structuredClone(runs.baseline); tampered.results.find(r => r.status === 'fail').status = 'pass';
  assert.equal(permissionDiff(runs.repaired, tampered).comparable, false);
});

test('classification: broken controls, newly inconclusive and restored are separated', () => {
  const comparison = { rows: [
    { id: 'CTL', title: 'control', before: 'pass', after: 'fail', transition: 'regression' },
    { id: 'B1', title: 'boundary', before: 'pass', after: 'fail', transition: 'regression' },
    { id: 'B2', title: 'boundary', before: 'fail', after: 'inconclusive', transition: 'unverified' },
    { id: 'B3', title: 'boundary', before: 'fail', after: 'pass', transition: 'contract-restored' },
    { id: 'CTL2', title: 'control', before: 'pass', after: 'inconclusive', transition: 'unverified' },
    { id: 'B4', title: 'boundary', before: 'inconclusive', after: 'fail', transition: 'unverified' },
    { id: 'B5', title: 'boundary', before: 'not_applicable', after: 'fail', transition: 'unverified' },
    { id: 'CTL3', title: 'control', before: 'inconclusive', after: 'fail', transition: 'unverified' },
    { id: 'CTL4', title: 'control', before: 'error', after: 'inconclusive', transition: 'unverified' } ] };
  const results = [{ id: 'CTL', severity: 'control' }, { id: 'B1', severity: 'high' }, { id: 'B2', severity: 'high' }, { id: 'B3', severity: 'critical' }, { id: 'CTL2', severity: 'control' }, { id: 'B4', severity: 'critical' }, { id: 'B5', severity: 'high' }, { id: 'CTL3', severity: 'control' }, { id: 'CTL4', severity: 'control' }];
  const d = classifyDiff(comparison, results);
  // CTL3 was undecided and now fails (over-blocking); CTL4 stays undecided, so it is not a broken control.
  assert.deepEqual(d.brokenControls.map(r => [r.id, r.before]), [['CTL', 'pass'], ['CTL2', 'pass'], ['CTL3', 'inconclusive']]);
  assert.deepEqual(d.flips.map(r => r.id), ['B1']);
  assert.deepEqual(d.newFailures.map(r => r.id), ['B4', 'B5']);
  assert.deepEqual(d.newlyInconclusive.map(r => r.id), ['B2', 'CTL2']);
  assert.deepEqual(d.restored.map(r => [r.id, r.label]), [['B3', 'contract-restored']]);
});

test('the job summary renders the diff, escapes cells and never leaks the lab token', () => {
  const report = buildReport({ runInput: runs.baseline, baselineInput: runs.repaired, baselineState: 'ok', env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken } });
  assert.match(report.markdown, /### Release permission diff/);
  assert.match(report.markdown, /\*\*DENY → ALLOW flips\*\* \(\d+\)/);
  assert.match(report.markdown, /\*\*New failures \(previously undecided\)\*\* \(1\)/);
  assert.ok(!report.markdown.includes(lab.memberToken));
  const none = buildReport({ runInput: runs.baseline, env: {} });
  assert.match(none.markdown, /### Release permission diff\n\nNot requested/);
  const incompatible = buildReport({ runInput: runs.otherSuite, baselineInput: runs.baseline, baselineState: 'ok', env: {} });
  assert.match(incompatible.markdown, /\*\*Not comparable\*\*/);
  assert.doesNotMatch(incompatible.markdown, /DENY → ALLOW/);
});
