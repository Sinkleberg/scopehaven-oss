import test from 'node:test';
import assert from 'node:assert/strict';
import { runAssessment, compareRuns, NO_VERIFIED_REPAIR } from '../src/runner.mjs';
import { comparisonDocument, renderComparisonReport } from '../src/report.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { normalizeGate } from '../integrations/github-action/summary.mjs';

// Owned synthetic fixture over loopback HTTP only. No model, provider or network dependency.
const vulnerable = await runAssessment('demo-vulnerable');
const repaired = await runAssessment('demo-repaired');
const copy = value => structuredClone(value);

// A comparable pair, controls passed, carries its repair label only when it restored a row and
// introduced no new failure. Every surface that prints the label must agree.
function assertNoRepairLabel(baseline, candidate) {
  const comparison = compareRuns(baseline, candidate);
  assert.equal(comparison.compatible, true); assert.equal(comparison.controlsPass, true);
  assert.equal(comparison.restorationLabel, NO_VERIFIED_REPAIR);
  const gate = summarizeGate({ candidate, baseline });
  assert.notEqual(gate.exitCode, 0);
  assert.equal(gate.comparison.restorationLabel, NO_VERIFIED_REPAIR);
  assert.equal(normalizeGate(gate).comparison.restorationLabel, NO_VERIFIED_REPAIR);
  const doc = comparisonDocument(baseline, candidate, comparison);
  assert.equal(doc.comparison.restorationLabel, NO_VERIFIED_REPAIR);
  const html = renderComparisonReport(doc);
  assert.doesNotMatch(html, /\bFixed\b/); assert.match(html, /No verified repair: this pair restored nothing, introduced a new failure, or left rows unverified or not applicable\./);
  return comparison;
}

test('a repair keeps its label: vulnerable to repaired reads Fixed', () => {
  const comparison = compareRuns(vulnerable, repaired);
  assert.equal(comparison.restorationLabel, 'Fixed');
  assert.equal(comparison.summary.fixed, 26); assert.equal(comparison.summary.newFailures, 0);
  assert.equal(summarizeGate({ candidate: repaired, baseline: vulnerable }).comparison.restorationLabel, 'Fixed');
});

test('a regression carries no repair label: repaired to vulnerable reads No verified repair everywhere', () => {
  const comparison = assertNoRepairLabel(repaired, vulnerable);
  assert.equal(comparison.summary.fixed, 0); assert.equal(comparison.summary.newFailures, 26);
});

test('a pair that restored nothing carries no repair label: vulnerable to vulnerable', () => {
  const comparison = assertNoRepairLabel(vulnerable, copy(vulnerable));
  assert.equal(comparison.summary.fixed, 0); assert.equal(comparison.summary.stillFailing, 26);
});

test('a pair that restored rows but introduced a new failure carries no repair label', () => {
  // One boundary check passes in the baseline and fails in the candidate; the other 25 failures are restored.
  const id = vulnerable.results.find(r => r.status === 'fail' && r.severity !== 'control').id;
  const baseline = copy(vulnerable), candidate = copy(repaired);
  const before = baseline.results.find(r => r.id === id), after = candidate.results.find(r => r.id === id);
  before.status = 'pass'; for (const a of before.assertions ?? []) a.status = 'pass'; baseline.counts.fail--; baseline.counts.pass++;
  after.status = 'fail'; after.assertions[0].status = 'fail'; candidate.counts.pass--; candidate.counts.fail++;
  const comparison = compareRuns(baseline, candidate);
  assert.equal(comparison.summary.fixed, 25); assert.equal(comparison.summary.newFailures, 1);
  assert.equal(comparison.restorationLabel, NO_VERIFIED_REPAIR);
  assert.doesNotMatch(renderComparisonReport(comparisonDocument(baseline, candidate, comparison)), /\bFixed\b/);
});

test('a repair with a not-applicable or unverified row is incomplete and carries no repair label, as the gate requires', () => {
  // Every candidate row restored but one, which is not applicable (or unverified) in both runs: the gate
  // reports comparison-incomplete, so the core label must not claim the repair either.
  const id = vulnerable.results.find(r => r.status === 'fail' && r.severity !== 'control').id;
  for (const status of ['not_applicable', 'inconclusive']) {
    const baseline = copy(vulnerable), candidate = copy(repaired);
    for (const run of [baseline, candidate]) {
      const row = run.results.find(r => r.id === id), was = row.status;
      row.status = status; for (const a of row.assertions ?? []) a.status = status === 'not_applicable' ? 'not_applicable' : 'inconclusive';
      run.counts[was]--; run.counts[status] = (run.counts[status] ?? 0) + 1;
    }
    const comparison = compareRuns(baseline, candidate);
    assert.equal(comparison.compatible, true); assert.equal(comparison.controlsPass, true);
    assert.equal(comparison.summary.fixed, 25); assert.equal(comparison.summary.newFailures, 0);
    assert.ok(comparison.summary.unverified || comparison.summary.notApplicable, status);
    assert.equal(comparison.restorationLabel, NO_VERIFIED_REPAIR, status);
    assert.ok(summarizeGate({ candidate, baseline }).reasons.includes('comparison-incomplete'), status);
  }
});
