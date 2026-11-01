// Dispatcher and recomputation for scopehaven-observation/1 views. Library only:
// nothing here is persisted or routed. v1 results stay authoritative; the
// recomputed answers sit beside them with an explicit agreement flag.
import { compareRuns } from './runner.mjs';
import { stable } from './domain.mjs';
import { CONTRACT_VERSION, ContractError, validateView, isExternalAttributed, unsupported } from './evidence-contract.mjs';
import { projectSyntheticInternal } from './contract-synthetic.mjs';
import { projectHttpInternal } from './contract-http.mjs';

const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const originOf = run => isRecord(run) && typeof run.evidenceOrigin === 'string' && run.evidenceOrigin.length <= 200 ? run.evidenceOrigin : null;
const PROJECTORS = Object.freeze({ 'synthetic-local-http': projectSyntheticInternal, 'local-http-response': projectHttpInternal });

// Never throws: a validation or projector failure becomes unsupported('invalid-view').
function project(run) {
  try {
    if (!isRecord(run)) return { view: unsupported('not-native-run', null), shadowRows: null };
    if (isExternalAttributed(run)) return { view: unsupported('external-attributed', originOf(run)), shadowRows: null };
    if (run.schemaVersion !== 1 || !Array.isArray(run.results)) return { view: unsupported('not-native-run', originOf(run)), shadowRows: null };
    const origin = originOf(run);
    if (!Object.hasOwn(PROJECTORS, origin)) return { view: unsupported('adapter-not-migrated', origin), shadowRows: null };
    const projected = PROJECTORS[origin](run);
    validateView(projected.view);
    return projected;
  } catch (error) {
    return { view: unsupported('invalid-view', originOf(run), error instanceof ContractError ? error.code : 'projector-error'), shadowRows: null };
  }
}

export function contractView(run) { return project(run).view; }

// A copy of the run whose row statuses are the contract statuses. Attempts,
// evidence digests and identity are untouched; counts use the stored key set.
function shadowOf(run, projected) {
  const shadow = structuredClone(run);
  for (const row of shadow.results) {
    const recomputed = projected.shadowRows.get(row.id);
    row.status = recomputed.status;
    if (recomputed.assertions) row.assertions = structuredClone(recomputed.assertions);
  }
  const keys = isRecord(run.counts) ? Object.keys(run.counts) : ['pass', 'fail', 'inconclusive', 'error'];
  shadow.counts = Object.fromEntries(keys.map(key => [key, 0]));
  for (const row of shadow.results) shadow.counts[row.status] = (shadow.counts[row.status] || 0) + 1;
  return shadow;
}
export function shadowRun(run) {
  const projected = project(run);
  return projected.view.supported ? shadowOf(run, projected) : null;
}

const unsupportedPair = (baseline, candidate) => ({ contractVersion: CONTRACT_VERSION, supported: false, reason: 'unsupported-input',
  baseline: baseline && !baseline.view.supported ? baseline.view.reason : null, candidate: candidate && !candidate.view.supported ? candidate.view.reason : null });
const comparable = value => ({ compatible: value.compatible, controlsPass: value.controlsPass, summary: value.summary,
  rows: value.rows.map(({ id, before, after, transition }) => ({ id, before, after, transition })) });
const verdictOf = check => check ? { verdict: check.verdict, basis: check.basis } : { verdict: 'missing', basis: 'candidate-row-absent' };

export function compareContracts(baseline, candidate) {
  const before = project(baseline), after = project(candidate);
  if (!before.view.supported || !after.view.supported) return unsupportedPair(before, after);
  try {
    const v1 = compareRuns(baseline, candidate), recomputed = compareRuns(shadowOf(baseline, before), shadowOf(candidate, after));
    const rows = v1.rows.map(row => {
      const shadowRow = recomputed.rows.find(r => r.id === row.id);
      const b = verdictOf(before.view.checks.find(c => c.checkId === row.id)), a = verdictOf(after.view.checks.find(c => c.checkId === row.id));
      const refinedTransition = a.basis === 'candidate-row-absent' ? 'candidate-row-absent'
        : ['unverified', 'not-applicable'].includes(shadowRow.transition) ? `${b.verdict}->${a.verdict}` : shadowRow.transition;
      return { id: row.id, v1Transition: row.transition, recomputedTransition: shadowRow.transition, before: b, after: a, refinedTransition };
    });
    const count = verdict => after.view.checks.filter(c => c.verdict === verdict).length;
    return { contractVersion: CONTRACT_VERSION, supported: true, v1, recomputed, agreement: stable(comparable(v1)) === stable(comparable(recomputed)), rows,
      evidenceSummary: { regressionsToIncomplete: rows.filter(r => r.before.verdict === 'pass' && !['pass', 'fail'].includes(r.after.verdict)).length,
        candidateMissing: count('missing'), candidateConflicting: count('conflicting'), candidateObserverFailure: count('observer-failure'),
        candidateNotExercised: count('not-exercised'), candidateUnobservable: count('unobservable') } };
  } catch {
    return { contractVersion: CONTRACT_VERSION, supported: false, reason: 'comparison-not-recomputable', baseline: null, candidate: null };
  }
}

const gateComparable = summary => ({ outcome: summary.outcome, exitCode: summary.exitCode, reasons: summary.reasons, counts: summary.current?.counts ?? null, comparison: summary.comparison });
// summarizeGate is injected (integrations/regression-gate/gate.mjs) so src/ gains no integrations import.
export function gateContracts({ candidate, baseline = null, expectedSuite } = {}, { summarizeGate } = {}) {
  if (typeof summarizeGate !== 'function') return { contractVersion: CONTRACT_VERSION, supported: false, reason: 'summarize-gate-not-injected', baseline: null, candidate: null };
  const current = project(candidate), before = baseline === null || baseline === undefined ? null : project(baseline);
  if (!current.view.supported || (before && !before.view.supported)) return unsupportedPair(before, current);
  try {
    const v1 = summarizeGate({ candidate, baseline: baseline ?? null, expectedSuite });
    const recomputed = summarizeGate({ candidate: shadowOf(candidate, current), baseline: before ? shadowOf(baseline, before) : null, expectedSuite });
    const views = [current.view, ...(before ? [before.view] : [])];
    const contractReasons = [...new Set([
      ...views.flatMap(view => view.checks.filter(check => check.verdict === 'conflicting').map(check => check.basis)),
      ...(views.some(view => view.pins.reset.violations.length) ? ['reset-unverified'] : []),
      ...([current, before].some(p => p?.runEvidence?.valid === false) ? ['run-evidence-invalid'] : []),
    ])].sort();
    return { contractVersion: CONTRACT_VERSION, supported: true, v1, recomputed, agreement: stable(gateComparable(v1)) === stable(gateComparable(recomputed)), contractReasons, verdictCounts: { ...current.view.verdictCounts } };
  } catch {
    return { contractVersion: CONTRACT_VERSION, supported: false, reason: 'gate-not-recomputable', baseline: null, candidate: null };
  }
}
