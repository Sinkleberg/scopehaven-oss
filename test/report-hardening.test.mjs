// Exported HTML reports are opened from disk, where no server CSP applies. Every
// run field is escaped (including counts) and the document carries its own CSP.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runAssessment, compareRuns } from '../src/runner.mjs';
import { renderReport, comparisonDocument, renderComparisonReport } from '../src/report.mjs';

const CSP = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">';

test('the run report escapes counts and carries a script-free CSP of its own', async () => {
  const run = await runAssessment('demo-vulnerable');
  const html = renderReport({ ...run, counts: { ...run.counts, pass: '<img src=x onerror=alert(1)>' } });
  assert(!html.includes('<img src=x'));
  assert(html.includes('&lt;img src=x onerror=alert(1)&gt; passed'));
  assert(html.includes(CSP));
});

test('the comparison report carries the same CSP', async () => {
  const [baseline, candidate] = [await runAssessment('demo-vulnerable'), await runAssessment('demo-repaired')];
  assert(renderComparisonReport(comparisonDocument(baseline, candidate, compareRuns(baseline, candidate))).includes(CSP));
});
