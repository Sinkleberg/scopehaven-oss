import test from 'node:test';
import assert from 'node:assert/strict';
import { runAssessment, compareRuns } from '../src/runner.mjs';
import { comparisonDocument, renderComparisonReport } from '../src/report.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { normalizeGate } from '../integrations/github-action/summary.mjs';

// Owned synthetic fixture over loopback HTTP only. No model, provider or network dependency.
const baseline = await runAssessment('demo-vulnerable');
const repaired = await runAssessment('demo-repaired');
const copy = value => structuredClone(value);

// The candidate passes every repaired check but one required allowed-use control fails, so no
// restored row can verify a repair: the pair is still comparable, and must not carry a repair label.
function controlFailed() {
  const candidate = copy(repaired);
  const id = candidate.requiredControlIds[0], row = candidate.results.find(r => r.id === id);
  row.status = 'fail'; row.assertions[0].status = 'fail'; candidate.counts.pass--; candidate.counts.fail++;
  return candidate;
}

test('a comparable pair whose required controls passed keeps its repair label', () => {
  const comparison = compareRuns(baseline, repaired);
  assert.equal(comparison.compatible, true); assert.equal(comparison.controlsPass, true);
  assert.equal(comparison.restorationLabel, 'Fixed');
  assert.ok(comparison.summary.fixed > 0);
});

test('a failed required control withholds the repair label in the comparison, the gate and the export', () => {
  const candidate = controlFailed();
  const comparison = compareRuns(baseline, candidate);
  assert.equal(comparison.compatible, true); assert.equal(comparison.controlsPass, false);
  assert.equal(comparison.summary.fixed, 0);
  assert.ok(comparison.rows.some(row => row.transition === 'blocked-by-controls'));
  assert.equal(comparison.restorationLabel, 'Unverified changes');

  const gate = summarizeGate({ candidate, baseline });
  assert.notEqual(gate.exitCode, 0);
  assert.equal(gate.comparison.restorationLabel, 'Unverified changes');
  // The GitHub Action's PR summary prints the gate's label, so it no longer says "Fixed" either.
  assert.equal(normalizeGate(gate).comparison.restorationLabel, 'Unverified changes');

  const doc = comparisonDocument(baseline, candidate, comparison);
  assert.equal(doc.comparison.restorationLabel, 'Unverified changes');
  assert.doesNotMatch(renderComparisonReport(doc), />Fixed</);
});

test('a pair in which every candidate row errored carries no repair label', () => {
  const candidate = copy(repaired);
  for (const row of candidate.results) { row.status = 'error'; for (const a of row.assertions ?? []) a.status = 'error'; }
  const comparison = compareRuns(baseline, candidate);
  assert.equal(comparison.controlsPass, false); assert.equal(comparison.summary.fixed, 0);
  assert.equal(comparison.restorationLabel, 'Unverified changes');
});
