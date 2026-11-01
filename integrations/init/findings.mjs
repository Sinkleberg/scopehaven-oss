// Reading the starter run for the operator. Verdict words are FAIL, INCONCLUSIVE and "not exercised" only: a row that
// met its contract is not listed or counted here (the run file has every row), because one clean starter run says
// nothing about what the profile does not test.
import { IDENTITY_REASONS } from '../../src/contracts.mjs';

export const VERDICT = Object.freeze({ fail: 'FAIL', inconclusive: 'INCONCLUSIVE', error: 'not exercised', not_applicable: 'not exercised' });

// The assertions that decided the row: failing ones for a FAIL, inconclusive ones for an INCONCLUSIVE.
// The workbench's own reason texts (src/contracts.mjs IDENTITY_REASONS) sometimes say a control "did not pass"; only
// those exact texts are reworded ("did not hold", the same meaning). Any other text, which can hold the app's own
// values, is shown as it is.
const REWORDED = new Map(Object.values(IDENTITY_REASONS).map(text => [text, text.replace(/\bdid not pass\b/g, 'did not hold')]));
export const neutral = text => (typeof text === 'string' && REWORDED.has(text) ? REWORDED.get(text) : text);
export function firedAssertions(row) {
  const want = row.status === 'fail' ? 'fail' : 'inconclusive';
  return (row.assertions ?? []).filter(a => a.status === want).map(a => ({ name: a.name, expected: neutral(a.expected), actual: neutral(a.actual) }));
}

export function summarizeRun(core) {
  const rows = Array.isArray(core?.results) ? core.results : [];
  const fail = rows.filter(r => r.status === 'fail'), inconclusive = rows.filter(r => r.status === 'inconclusive');
  const notExercised = rows.filter(r => r.status === 'error' || r.status === 'not_applicable');
  const first = fail[0] ?? inconclusive[0] ?? null;
  return {
    counts: { FAIL: fail.length, INCONCLUSIVE: inconclusive.length, 'not exercised': notExercised.length },
    first: first && { verdict: VERDICT[first.status], id: first.id, title: first.title, severity: first.severity, decision: first.decision ?? first.status,
      summary: first.summary, fired: firedAssertions(first) },
    notExercised: notExercised.map(r => r.id),
    failIds: fail.map(r => r.id),
  };
}

export function formatFirstRow(first) {
  if (!first) return ['No row was decided FAIL or INCONCLUSIVE in this starter run. The run file lists every row; add checks (docs/ONBOARDING.md) before reading anything into it.'];
  const lines = [`First decided row: ${first.verdict}  ${first.id}  (${first.severity})  ${first.title}`];
  if (first.decision === 'prohibition-observed-identity-unproven') lines.push('  decision: prohibition observed, identity or allowed use not established');
  for (const a of first.fired) lines.push(`  fired check: ${a.name}: expected ${a.expected}; got ${a.actual}`);
  // A row summary that uses pass wording ("never a pass") is left out; the fired check above carries the reason.
  if (first.summary && !/\bpass(ed|es|ing)?\b/i.test(first.summary)) lines.push(`  why: ${first.summary}`);
  return lines;
}
