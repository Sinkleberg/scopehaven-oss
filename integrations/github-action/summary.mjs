#!/usr/bin/env node
// Scopehaven GitHub Action summary. Zero dependencies, local files only.
// Reads one saved run (store record {core, sha256} or `export --format json`
// output), an optional regression-gate summary and an optional policy-matrix
// diff (`scopehaven policy diff --out`). It prints only identifiers,
// titles, statuses, severities, counts and hashes: never credentials, profile
// bodies, assertion values, traces or response content. Any value of a
// SCOPEHAVEN_TARGET_* environment variable is redacted from the output.
import { lstatSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { compareRuns } from '../../src/runner.mjs';
import { strictModelIdentity } from '../../src/http-model-identity.mjs';
import { GATED_KINDS, canonical, diffMatrices } from '../policy-import/matrix.mjs';
import { validDate } from '../regression-gate/report-only.mjs';
import { READINGS, TRIALS_MAX, TRIALS_MIN, TRIALS_SCHEMA } from '../regression-gate/trials.mjs';

export const STATUSES = Object.freeze(['pass', 'fail', 'inconclusive', 'error', 'not_applicable']);
export const FAIL_ON = Object.freeze(['fail', 'inconclusive', 'never']);
// Gate reasons that mean failed, untrustworthy or non-comparable evidence.
// Unknown future reasons are treated as hard (fail-safe).
export const SOFT_GATE_REASONS = Object.freeze(['inconclusive-evidence', 'not-applicable-is-not-pass', 'comparison-incomplete', 'model-identity-malformed', 'model-identity-not-recorded']);
// Model attribution values the summary prints (integrations/model-identity); anything else reads unrecognized.
const FLIP_CAUSES = ['app', 'model', 'confounded', 'unexplained', 'model-unverified'];
const ROW_ATTRIBUTIONS = [...FLIP_CAUSES, 'held-across-model-change', 'failed-across-model-change', 'no-change', 'incompatible'];
const REPAIR_LABELS = ['fixed', 'contract-restored', 'local-control-restored'];
const GATE_OUTCOMES = ['clean', 'assessment-failed', 'config-or-runtime-error'];
const ATTENTION = ['fail', 'error', 'inconclusive'];
const MAX_ROWS = 100;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const IDENT = /^[A-Za-z0-9_.:-]{1,120}$/;
const HEX64 = /^[a-f0-9]{64}$/;
const CERTIFICATION = 'These are observed checks, not a safety certification.';
const SCOPES = Object.freeze({
  'local-http-response': 'Response-level evidence: HTTP response contracts only. Backend access and action effects are not independently verified by this run.',
  'synthetic-local-http': 'Owned synthetic backend evidence on the built-in fixture; no production or model security certification.',
});
// HTTP v3 runs can carry authoritative backend observation for some rows.
const HTTP_V3_SCOPE = 'Response contracts plus authoritative backend observation for rows marked observed; other backend effects remain unverified.';
const UNKNOWN_SCOPE = 'Response-level evidence unless backend observers are configured; this run does not declare a recognized evidence origin.';

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

export function secretValues(env = process.env) {
  return Object.entries(env)
    .filter(([key, value]) => /^SCOPEHAVEN_TARGET_/.test(key) && typeof value === 'string' && value.length >= 4)
    .map(([, value]) => value).sort((a, b) => b.length - a.length);
}
export function redact(text, secrets) {
  let out = String(text);
  for (const secret of secrets) out = out.split(secret).join('REDACTED');
  return out;
}

/** One GitHub-flavoured markdown table cell: single line, bounded, inert. */
export function escapeCell(value, { secrets = [], max = 200 } = {}) {
  let text = redact(String(value ?? ''), secrets).replace(/[\u0000-\u001f\u007f\u0085\u2028\u2029]+/g, ' ').trim();
  if (text.length > max) text = `${text.slice(0, max - 3)}...`;
  return text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/[\\`*_~[\]()#!|]/g, character => `\\${character}`);
}
const code = value => `\`${value}\``; // only for values already matched against a strict pattern
const safeId = value => typeof value === 'string' && IDENT.test(value) ? value : null;
const safeUuid = value => typeof value === 'string' && UUID.test(value) ? value.toLowerCase() : null;
const safeHash = value => typeof value === 'string' && HEX64.test(value) ? value : null;

function readJson(path) {
  if (!path) return { state: 'absent' };
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) return { state: 'invalid' };
    return { state: 'ok', value: JSON.parse(readFileSync(path, 'utf8')) };
  } catch (error) { return { state: error?.code === 'ENOENT' ? 'missing' : 'invalid' }; }
}

/** Accept a store record ({core, sha256}) or an exported run; return a minimal view. */
export function normalizeRun(input) {
  const core = object(input) && object(input.core) && Array.isArray(input.core.results) ? input.core : input;
  if (!object(core) || !Array.isArray(core.results)) return null;
  const sha256 = safeHash(object(input) && object(input.core) ? input.sha256 : core.integrity?.sha256);
  const counts = Object.fromEntries(STATUSES.map(status => [status, 0]));
  let unrecognized = 0;
  for (const row of core.results) {
    if (object(row) && STATUSES.includes(row.status)) counts[row.status] += 1; else unrecognized += 1;
  }
  return {
    id: safeUuid(core.id), targetId: core.targetId, targetName: core.targetName, applicationId: core.applicationId, build: core.build,
    evidenceOrigin: typeof core.evidenceOrigin === 'string' ? core.evidenceOrigin : null,
    httpV3: core.evidenceOrigin === 'local-http-response' && core.adapterVersion === 'loopback-response-contract/3',
    httpObserved: core.evidenceOrigin === 'local-http-response' && core.adapterVersion === 'loopback-response-contract/3' && Array.isArray(core.observers) && core.observers.length > 0,
    targetContext: ['operator-forwarded', 'operator-remote'].includes(core.targetContext) ? core.targetContext : 'local-app', targetLabel: typeof core.targetLabel === 'string' ? core.targetLabel : null,
    hashes: { evidenceIntegrity: sha256, suiteHash: safeHash(core.suiteHash), policyHash: safeHash(core.policyHash), profileHash: safeHash(core.profileHash) },
    checksTotal: core.results.length, counts, unrecognized,
    attention: core.results.filter(row => object(row) && ATTENTION.includes(row.status))
      .map(row => ({ id: row.id, title: row.title, severity: row.severity, status: row.status })),
    // The gate's hard reasons, computed from the run itself so a run without a
    // baseline cannot go green where the gate would fail.
    // Fails closed: no required controls, no results, or a required id that is
    // not a passing control row all count as not passed.
    requiredControlsPassed: Array.isArray(core.requiredControlIds) && core.requiredControlIds.length > 0 && core.results.length > 0
      && core.requiredControlIds.every(id => core.results.some(row => object(row) && row.id === id && row.severity === 'control' && row.status === 'pass')),
    unprovenActors: object(core.identityEvidence) && Array.isArray(core.identityEvidence.actors) ? core.identityEvidence.actors.filter(a => !object(a) || a.established !== true).length : 0,
  };
}

// Allowlisted projection of the gate's model attribution: fixed codes only, never free text.
function modelAttributionOf(value) {
  if (!object(value)) return null;
  if (value.state === 'recorded') return { state: 'recorded', flipCause: value.flipCause === null ? null : FLIP_CAUSES.includes(value.flipCause) ? value.flipCause : 'unrecognized',
    relation: safeId(value.relation) || 'unrecognized', strength: safeId(value.strength) || 'unrecognized', repairCreditedToApp: value.repairCreditedToApp === true };
  if (value.state === 'not-recorded') return { state: 'not-recorded', malformed: Array.isArray(value.malformed) ? value.malformed.map(entry => safeId(entry) || 'unrecognized') : [] };
  return { state: 'unrecognized' };
}
// Allowlisted projection of the gate's trials block (gate --trials): counts, codes and run ids only, never the scope text.
// Anything malformed reads as no block, so a requested trials count without a readable block fails the job.
const count = value => Number.isSafeInteger(value) && value >= 0;
function trialsOf(value) {
  if (!object(value) || value.schema !== TRIALS_SCHEMA || !(Number.isSafeInteger(value.trials) && value.trials >= TRIALS_MIN && value.trials <= TRIALS_MAX)) return null;
  if (!(Number.isSafeInteger(value.k) && value.k >= 1 && value.k <= value.trials) || typeof value.floor !== 'string' || !/^(1|[1-9][0-9]{0,6}\/[1-9][0-9]{0,6})$/.test(value.floor)) return null;
  if (!object(value.readings) || !READINGS.every(reading => count(value.readings[reading])) || !Array.isArray(value.checks) || !Array.isArray(value.perTrial) || value.perTrial.length !== value.trials) return null;
  return { trials: value.trials, k: value.k, floor: value.floor, readings: Object.fromEntries(READINGS.map(reading => [reading, value.readings[reading]])),
    checks: value.checks.filter(object).map(check => ({ id: safeId(check.id) || 'unrecognized', reading: READINGS.includes(check.reading) ? check.reading : 'unrecognized',
      passed: count(check.passed) ? check.passed : null, trials: count(check.trials) ? check.trials : null,
      passK: typeof check.exact === 'string' && /^[0-9]{1,30}(\/[0-9]{1,30})?$/.test(check.exact) ? check.exact : null, unpaired: check.unpaired === true })),
    perTrial: value.perTrial.map(trial => ({ runId: safeUuid(trial?.runId), exitCode: [0, 1, 2].includes(trial?.exitCode) ? trial.exitCode : null,
      reasons: Array.isArray(trial?.reasons) ? trial.reasons.map(reason => safeId(reason) || 'unrecognized-reason') : [] })) };
}
/** Allowlisted projection of a regression-gate summary. */
export function normalizeGate(input) {
  if (!object(input) || !GATE_OUTCOMES.includes(input.outcome) || ![0, 1, 2].includes(input.exitCode) || !Array.isArray(input.reasons)) return null;
  const comparison = object(input.comparison) && input.comparison.requested === true ? {
    baselineRunId: safeUuid(input.comparison.baselineRunId),
    compatibility: input.comparison.compatibility === 'compatible' ? 'compatible' : 'incompatible',
    restorationLabel: typeof input.comparison.restorationLabel === 'string' ? input.comparison.restorationLabel : null,
    labels: object(input.comparison.labels) ? Object.fromEntries(Object.entries(input.comparison.labels)
      .filter(([label, count]) => safeId(label) && Number.isSafeInteger(count) && count > 0)) : {},
    modelAttribution: modelAttributionOf(input.comparison.modelAttribution),
  } : null;
  return { outcome: input.outcome, exitCode: input.exitCode, reasons: input.reasons.map(reason => safeId(reason) || 'unrecognized-reason'),
    runId: safeUuid(input.current?.runId), comparison, trials: trialsOf(input.trials),
    // gate --report-only: the window the gate itself applied (the verdict above is the real one either way).
    reportOnly: object(input.reportOnly) ? { state: ['applied', 'ended'].includes(input.reportOnly.state) ? input.reportOnly.state : 'unrecognized' } : null };
}

/** Pass/fail decision for the action step. Setup errors fail regardless of fail-on.
 * CI follows the assessment and the gate: unless fail-on is "never", the job
 * fails whenever `scopehaven assess` or the regression gate would exit non-zero,
 * and on the same conditions recomputed from the saved run. "inconclusive" is
 * kept as an alias of "fail" for existing workflows. With trials (the trials
 * input), a gate that did not stop on a setup error must report a trials block
 * for exactly that count, whatever fail-on says. */
export function decide({ run, gate, gateRequested = false, failOn = 'fail', assessExit = null, trials = null } = {}) {
  if (!FAIL_ON.includes(failOn)) return { decision: 'fail', reason: 'invalid-fail-on' };
  if (assessExit === 2) return { decision: 'fail', reason: 'assessment-setup-error' };
  if (gateRequested && !gate) return { decision: 'fail', reason: 'gate-unavailable' };
  if (gateRequested && trials !== null && gate.exitCode !== 2 && gate.trials?.trials !== trials) return { decision: 'fail', reason: 'gate-trials-unavailable' };
  if (!run || !run.id) return { decision: 'fail', reason: gateRequested && gate?.reasons?.length ? 'gate-setup-error' : 'evidence-unavailable' };
  if (failOn === 'never') return { decision: 'pass', reason: 'fail-on-never' };
  if (run.counts.error || run.unrecognized) return { decision: 'fail', reason: 'checks-errored' };
  if (run.counts.fail) return { decision: 'fail', reason: 'checks-failed' };
  if (!run.requiredControlsPassed) return { decision: 'fail', reason: 'required-controls-not-passed' };
  if (run.unprovenActors) return { decision: 'fail', reason: 'identity-not-established' };
  if (gate && (gate.exitCode !== 0 || gate.reasons.length)) {
    const hard = gate.reasons.filter(reason => !SOFT_GATE_REASONS.includes(reason));
    return { decision: 'fail', reason: `gate-${hard[0] ?? gate.reasons[0] ?? 'not-clean'}` };
  }
  if (assessExit !== null && assessExit !== 0) return { decision: 'fail', reason: 'assessment-not-clean' };
  if (run.counts.inconclusive) return { decision: 'fail', reason: 'checks-inconclusive' };
  return { decision: 'pass', reason: 'clean' };
}

// Report-only (the report-only input): while the window is open the job does not fail on what the checks found.
// It never relaxes a setup error, an errored check (as the gate never relaxes exit 2), the strict model identity policy
// or the opted-in policy diff, and only an assessment-failed verdict: a gate that ran must have exited 1 and assess 0
// or 1, so a gate exit 2 or a crashed assess is never relaxed whatever the run-level reason. It applies only when the
// prepare step found the window open, the gate (when one ran) applied it too, and the export step marked every report
// and SARIF file REPORT-ONLY (marked true), so a green job never ships an unmarked report. wouldFail is the decision
// report-only relaxed.
export const REPORT_ONLY = Object.freeze(['off', 'applied', 'ended']);
const RELAXED = ['checks-failed', 'required-controls-not-passed', 'identity-not-established', 'assessment-not-clean', 'checks-inconclusive'];
export function decideReportOnly(base, { reportOnly = 'off', marked = 'false', gate = null, gateRequested = false, assessExit = null } = {}) {
  if (!REPORT_ONLY.includes(reportOnly)) return { decision: 'fail', reason: 'invalid-report-only', state: 'invalid' };
  if (reportOnly !== 'applied') return { ...base, state: reportOnly };
  if (marked !== 'true' || (gateRequested && gate?.reportOnly?.state !== 'applied')) return { ...base, state: 'not-applied' };
  const findings = (!gateRequested || gate?.exitCode === 1) && [null, 0, 1].includes(assessExit);
  const relaxed = findings && base.decision === 'fail' && (RELAXED.includes(base.reason)
    || (base.reason.startsWith('gate-') && !['gate-unavailable', 'gate-setup-error', 'gate-trials-unavailable'].includes(base.reason)));
  return relaxed ? { decision: 'pass', reason: 'report-only', wouldFail: base.reason, state: 'applied' } : { ...base, state: 'applied' };
}
function reportOnlyLines({ state, wouldFail }, until, gateRequested, cell) {
  const through = validDate(until) ? until : 'an unreadable date';
  if (state === 'off') return [];
  if (state === 'invalid') return ['> **Report-only: invalid value**; the job fails.', ''];
  if (state === 'ended') return [`> **Report-only window ended** (\`report-only-until\` ${cell(through)}): this job follows \`fail-on\` again.`, ''];
  if (state === 'not-applied') return [`> **Report-only not applied**: requested through ${cell(through)}, but ${gateRequested ? 'the gate did not apply it or ' : ''}not every report and SARIF file was marked REPORT-ONLY, so this job follows \`fail-on\`.`, ''];
  return [`> **REPORT-ONLY RUN** through ${cell(through)} (UTC). Until then this job does not fail on what the checks find, so a green job is not a pass: the statuses, verdict and reasons below are the real results.${wouldFail ? ` Without report-only this job would fail (${code(safeId(wouldFail) || 'unrecognized')}).` : ''} Setup errors, errored checks, \`require-model-identity\` and \`fail-on-policy-diff\` still fail it. \`report.html\`, \`comparison.html\` and the SARIF file are marked REPORT-ONLY too; \`run.json\` is the recorded run, unchanged.`, ''];
}

// Release Permission Diff: what changed in access decisions between a baseline
// run and this run, check by check. It is computed only when the core's
// compareRuns says the two runs are compatible (same application, suite,
// policy, profile, evaluator, evidence versions and actors); otherwise it says
// "not comparable" and lists why, with no per-check cells.
//   flips              - a boundary check that held (pass) now fails: access denied before, allowed now
//   brokenControls     - an allowed-use control that passed no longer passes, or that was
//                        undecided and now fails (Before shows which)
//   newlyInconclusive  - a decided check (pass or fail) is now inconclusive or errored
//   newFailures        - a boundary check that was undecided (inconclusive, error or not
//                        applicable) now fails: never shown passing, but failing now
//   restored           - a failing check now passes (labelled by the core's evidence scope)
export function classifyDiff(comparison, currentResults) {
  const byId = new Map((currentResults || []).filter(object).map(row => [row.id, row]));
  const out = { flips: [], newFailures: [], brokenControls: [], newlyInconclusive: [], restored: [] };
  for (const row of comparison.rows || []) {
    const current = byId.get(row.id), severity = current?.severity;
    const entry = { id: row.id, title: row.title, severity, before: row.before, after: row.after, ...(typeof row.attribution === 'string' ? { attribution: ROW_ATTRIBUTIONS.includes(row.attribution) ? row.attribution : 'unrecognized' } : {}) };
    // A control that passed and no longer does, or that was undecided and now fails (over-blocking).
    if (severity === 'control') { if ((row.before === 'pass' && row.after !== 'pass') || (['inconclusive', 'error', 'not_applicable'].includes(row.before) && row.after === 'fail')) out.brokenControls.push(entry); }
    else if (row.before === 'pass' && row.after === 'fail') out.flips.push(entry);
    else if (['inconclusive', 'error', 'not_applicable'].includes(row.before) && row.after === 'fail') out.newFailures.push(entry);
    if (['pass', 'fail'].includes(row.before) && ['inconclusive', 'error'].includes(row.after)) out.newlyInconclusive.push(entry);
    if (row.before === 'fail' && row.after === 'pass') out.restored.push({ ...entry, label: row.transition });
  }
  return out;
}
export function permissionDiff(baselineInput, currentInput) {
  const core = value => object(value) && object(value.core) && Array.isArray(value.core.results) ? value.core : value;
  const baseline = core(baselineInput), current = core(currentInput);
  if (!object(baseline) || !object(current) || !Array.isArray(baseline.results) || !Array.isArray(current.results)) return { comparable: false, reasons: ['A run is missing or unreadable.'] };
  let comparison;
  try { comparison = compareRuns(structuredClone(baseline), structuredClone(current)); } catch { return { comparable: false, reasons: ['The runs could not be compared.'] }; }
  if (!comparison.compatible) return { comparable: false, reasons: comparison.reasons.slice(0, 20) };
  const ma = comparison.modelAttribution;
  return { comparable: true, baselineId: comparison.baselineId, currentId: comparison.candidateId, notes: comparison.reasons.slice(0, 20),
    ...(ma ? { modelAttribution: ma.state === 'recorded' ? { state: 'recorded', flipCause: ma.flipCause, repairCreditedToApp: ma.repairCreditedToApp === true }
      : { state: 'not-recorded', ...(Array.isArray(ma.malformed) && ma.malformed.length ? { malformed: ma.malformed.map(entry => safeId(entry) || 'unrecognized') } : {}) } } : {}),
    ...classifyDiff(comparison, current.results) };
}
function diffSection(diff, cell, policyUnmet = false) {
  const lines = ['### Release permission diff', ''];
  if (!diff) return [...lines, 'Not requested (no `baseline-run`).', ''];
  if (!diff.comparable) return [...lines, '**Not comparable**: no per-check diff is shown for runs with different identities.', '', ...diff.reasons.map(reason => `- ${cell(reason)}`), ''];
  lines.push(`Baseline ${safeUuid(diff.baselineId) ? code(safeUuid(diff.baselineId)) : 'unidentified'} → this run ${safeUuid(diff.currentId) ? code(safeUuid(diff.currentId)) : 'unidentified'}.`, '');
  // With model attribution recorded, each row says who its change is credited to.
  const attributed = diff.modelAttribution?.state === 'recorded', unreadable = diff.modelAttribution?.malformed?.length > 0;
  // A restored row is not the application's repair when attribution does not credit it or an identity could not be read (an earlier review, M1).
  const uncredited = policyUnmet || unreadable || (attributed && !diff.modelAttribution.repairCreditedToApp);
  if (policyUnmet) lines.push('Model identity policy not met: no change below is credited to the application.', '');
  if (attributed) lines.push(`Model identity recorded on both runs; repairs credited to the application: **${diff.modelAttribution.repairCreditedToApp && !policyUnmet ? 'yes' : 'no'}**.`, '');
  else if (unreadable) lines.push(`Model identity present but unreadable (${diff.modelAttribution.malformed.map(code).join(', ')}): no change below is credited to the application.`, '');
  else if (diff.modelAttribution) lines.push('Model identity not recorded for one or both runs: a change below may come from the model.', '');
  const table = (title, rows, empty) => rows.length
    ? [`**${title}** (${rows.length})`, '', `| Check | Title | Severity | Before | After |${attributed ? ' Attribution |' : ''}`, `| --- | --- | --- | --- | --- |${attributed ? ' --- |' : ''}`,
      ...rows.slice(0, MAX_ROWS).map(r => `| ${cell(r.id)} | ${cell(r.title)} | ${cell(r.severity)} | ${cell(r.before)} | ${cell(r.after)} |${attributed ? ` ${cell(r.attribution ?? 'none')} |` : ''}`), '']
    : [`**${title}**: ${empty}`, ''];
  lines.push(...table('DENY → ALLOW flips', diff.flips, 'none'), ...table('New failures (previously undecided)', diff.newFailures, 'none'), ...table('Broken allowed-use controls', diff.brokenControls, 'none'),
    ...table('Newly inconclusive', diff.newlyInconclusive, 'none'), ...table(uncredited ? 'Restored (not credited to the application)' : 'Restored', diff.restored, 'none'));
  if (diff.notes.length) lines.push('Notes:', '', ...diff.notes.map(note => `- ${cell(note)}`), '');
  return lines;
}

// Policy matrix diff: the cells of one layer's declared permissions that changed
// between the previous and the current matrix, and the gaps (what the importer
// could not read) the current matrix added. The action's step runs
// `scopehaven policy diff --out`; the summary recomputes the same diff from the
// two matrices and accepts that file only when it is exactly this diff and the
// step's exit code matches it (0 nothing gated, 1 a gated cell or gap, 2 not comparable).
// Gated kinds (more access, a declaration that became unknown or undeclared, a new
// gap, or any gap when the gaps can't be compared by identity) are listed one by
// one; every kind is counted.
export function expectedPolicyDiff(before, after) {
  try { return JSON.parse(JSON.stringify(diffMatrices(before, after))); } catch { return null; }
}
export function normalizePolicyDiff(input, exitCode, expected) {
  if (!object(input) || !object(expected) || canonical(input) !== canonical(expected)) return { state: 'unavailable' };
  if (expected.comparable !== true) return exitCode === 2 ? { state: 'not-comparable', reason: safeId(expected.reason) || 'unrecognized-reason' } : { state: 'unavailable' };
  const gated = expected.changes.filter(change => GATED_KINDS.includes(change.kind));
  // A new gap gates whatever its cells read: where they were already unknown, nothing else shows the change.
  const gatedGaps = expected.gapChanges.filter(change => GATED_KINDS.includes(change.kind));
  const any = gated.length > 0 || gatedGaps.length > 0;
  if (exitCode !== (any ? 1 : 0)) return { state: 'unavailable' };
  return { state: any ? 'gated' : 'clean', application: expected.application, layer: expected.layer,
    beforeMatrixId: safeHash(expected.beforeMatrixId), afterMatrixId: safeHash(expected.afterMatrixId), counts: expected.counts, gapCounts: expected.gapCounts,
    gapComparison: safeId(expected.gapComparison) || 'unrecognized',
    gated: gated.map(change => ({ kind: change.kind, role: change.role, resource: change.resource, action: change.action,
      // A cell that stayed unknown but gained a reason is marked; the reason codes stay in policy-diff.json.
      before: side(change.from, change.fromComputed), after: `${side(change.to, change.toComputed)}${Array.isArray(change.addedReasons) && change.addedReasons.length ? ' (new reason)' : ''}` })),
    gatedGaps: gatedGaps.map(change => ({ kind: change.kind, scope: change.scope, source: change.source, id: safeHash(change.id) })) };
}
const GAP_COMPARISON = Object.freeze({
  identity: 'Gaps compared by identity: a gap of the current matrix that the previous one does not have is gated, whatever its cells read.',
  'before-unidentified': 'Gaps not compared by identity: the previous matrix has gaps without identities (an older `scopehaven-policy-matrix/1`), so every gap of the current matrix is gated. Re-import the previous matrix from its sources to compare gaps.',
  'after-unidentified': 'Gaps not compared by identity: the current matrix has gaps without identities (an older `scopehaven-policy-matrix/1`), so every one of its gaps is gated. Re-import it from its sources to compare gaps.',
});
const side = (decision, computed) => decision === undefined ? 'absent' : computed !== undefined ? `${decision} (computed ${computed ?? 'unknown'})` : decision;
function policySection(policy, failOnPolicyDiff, cell) {
  const lines = ['### Policy matrix diff', ''];
  if (!policy) return [...lines, 'Not requested (no `policy-baseline-matrix` and `policy-matrix`).', ''];
  const flag = ['true', 'false'].includes(failOnPolicyDiff) ? failOnPolicyDiff : 'invalid';
  const mode = `fail-on-policy-diff ${code(flag)}: ${flag === 'true' ? 'a gated cell or gap, or an unavailable diff, fails the job.' : flag === 'false' ? 'reported only.' : 'invalid value; the job fails.'}`;
  if (policy.state === 'unavailable') return [...lines, '**unavailable**: the policy diff produced no result that matches the two matrices. See the step log.', '', mode, ''];
  if (policy.state === 'not-comparable') return [...lines, `**Not comparable** (${code(policy.reason)}): no per-cell diff is shown.`, '', mode, ''];
  lines.push(`Application ${cell(policy.application)}, layer ${cell(policy.layer)}: matrix ${policy.beforeMatrixId ? code(policy.beforeMatrixId) : 'unidentified'} → ${policy.afterMatrixId ? code(policy.afterMatrixId) : 'unidentified'}.`, '');
  const counted = Object.entries(policy.counts);
  if (counted.length) lines.push('| Change | Cells |', '| --- | ---: |', ...counted.map(([kind, count]) => `| ${cell(kind)} | ${Number(count)} |`), '');
  else lines.push('No cells changed.', '');
  if (policy.gated.length) {
    lines.push(`**Gated cells** (${policy.gated.length}): more access, or a declaration that became unknown or undeclared.`, '',
      '| Change | Role | Resource | Action | Before | After |', '| --- | --- | --- | --- | --- | --- |',
      ...policy.gated.slice(0, MAX_ROWS).map(r => `| ${r.kind} | ${cell(r.role)} | ${cell(r.resource)} | ${cell(r.action)} | ${cell(r.before)} | ${cell(r.after)} |`), '');
    if (policy.gated.length > MAX_ROWS) lines.push(`${policy.gated.length - MAX_ROWS} more gated cells are in policy-diff.json in the evidence artifact.`, '');
  } else lines.push('**Gated cells**: none (no widened, added-open, became-unknown or became-undeclared cell).', '');
  const gapCounted = Object.entries(policy.gapCounts);
  if (gapCounted.length) lines.push('| Gap change | Gaps |', '| --- | ---: |', ...gapCounted.map(([kind, count]) => `| ${cell(kind)} | ${Number(count)} |`), '');
  lines.push(GAP_COMPARISON[policy.gapComparison] ?? 'Gaps compared: unrecognized.', '');
  if (policy.gatedGaps.length) {
    lines.push(`**Gated gaps** (${policy.gatedGaps.length}): statements or rows the importer could not read, so the cells they affect read unknown.`, '',
      '| Change | Scope | Source | Gap id |', '| --- | --- | --- | --- |',
      ...policy.gatedGaps.slice(0, MAX_ROWS).map(g => `| ${g.kind} | ${cell(g.scope)} | ${cell(g.source)} | ${g.id ? code(g.id.slice(0, 16)) : 'none'} |`), '');
    if (policy.gatedGaps.length > MAX_ROWS) lines.push(`${policy.gatedGaps.length - MAX_ROWS} more gated gaps are in policy-diff.json in the evidence artifact.`, '');
  } else lines.push('**Gated gaps**: none (no gap the previous matrix does not have).', '');
  lines.push('Matrices are readings of declared policy, not observed behaviour. Every change is in policy-diff.json in the evidence artifact.', '', mode, '');
  return lines;
}
/** The policy diff fails the job only when the operator opted in (fail-on-policy-diff: true).
 * It is independent of fail-on and never turns a failing decision into a passing one. */
export function decidePolicy(base, { policy, failOnPolicyDiff = 'false' } = {}) {
  if (!['true', 'false'].includes(failOnPolicyDiff)) return { decision: 'fail', reason: 'invalid-fail-on-policy-diff' };
  if (base.decision !== 'pass' || failOnPolicyDiff !== 'true') return base;
  if (!policy) return { decision: 'fail', reason: 'policy-diff-not-requested' };
  if (policy.state === 'gated') return { decision: 'fail', reason: 'policy-diff-gated' };
  if (policy.state === 'not-comparable') return { decision: 'fail', reason: 'policy-diff-not-comparable' };
  if (policy.state !== 'clean') return { decision: 'fail', reason: 'policy-diff-unavailable' };
  return base;
}

// Strict identity is independent of report-only mode. Recompute from saved runs;
// a missing or edited gate summary cannot turn unknown identity into a pass.
// causes: why the policy was not met, as { side, reason } fixed codes (printed in the summary).
export function decideModelIdentity(base, { runInput, baselineInput, baselineState = 'absent', requireModelIdentity = 'false' } = {}) {
  if (!['true', 'false'].includes(requireModelIdentity)) return { decision: 'fail', reason: 'invalid-require-model-identity' };
  if (requireModelIdentity !== 'true') return base;
  if (baselineState !== 'ok') return { decision: 'fail', reason: 'model-identity-baseline-required' };
  const core = value => object(value) && object(value.core) ? value.core : value;
  let comparison;
  try { comparison = compareRuns(core(baselineInput), core(runInput)); } catch { return { decision: 'fail', reason: 'model-identity-unavailable' }; }
  let strict;
  try { strict = strictModelIdentity(comparison, core(baselineInput), core(runInput)); } catch { return { decision: 'fail', reason: 'model-identity-unavailable' }; }
  return strict.reasons.length ? { decision: 'fail', reason: strict.reasons[0], causes: strict.causes, policyUnmet: true } : base;
}
const SIDES = ['baseline', 'candidate', 'pair'];
function modelIdentityPolicyLines(requireModelIdentity, causes) {
  const flag = ['true', 'false'].includes(requireModelIdentity) ? requireModelIdentity : 'invalid';
  const lines = [flag !== 'true' ? `Model identity policy: ${code(flag)} (${flag === 'false' ? 'not required' : 'invalid value; the job fails'}).` : `Model identity policy: ${code(flag)}. Both HTTP runs need a comparable model identity observed by a model tap Scopehaven held in its own process (custody \`tap-memory\`). A tap log file another process wrote (custody \`tap-file\`) can be rewritten by any process running as its user, so it reads unverified (\`subject-writable-custody\`). Every model reading, a weights digest included, is what the model upstream reported to the tap; an upstream the application controls can report any model, so a reading is not attested weights. The stored runs are read as their files record them: the run digest is a checksum, not a signature, so keep \`baseline-run\` where the application and its authors cannot write it. The tap sees only calls sent to its port, so the policy holds only where routing outside the application leaves that port its only way to the model server.`, ''];
  if (Array.isArray(causes) && causes.length) lines.push(`Model identity policy not met: ${causes.slice(0, 20).map(c => `${SIDES.includes(c?.side) ? c.side : 'unrecognized'} ${code(safeId(c?.reason) || 'unrecognized')}`).join(', ')}.`, '');
  return lines;
}

// The trials section: the counts, the gate's readings, the trials and the checks that did not read PASS (bounded).
function trialsLines(gate, trials, cell) {
  if (trials === null) return [];
  const lines = ['### Repeated trials', ''];
  const t = gate?.trials;
  if (!gate || gate.exitCode === 2 || t?.trials !== trials) {
    lines.push(`**unavailable**: ${trials > 0 ? `${trials} trials were requested` : 'trials were requested with an invalid count'}, but the gate summary has no trials block for them${gate?.exitCode === 2 ? ' (the gate stopped with exit 2)' : ''}.`, '');
    return lines;
  }
  lines.push(`${t.trials} trials, k = ${t.k}, floor ${code(t.floor)}. Readings: ${READINGS.map(reading => `${reading} ${t.readings[reading]}`).join(', ')}.`, '',
    '| Trial | Run | Exit | Reasons |', '| ---: | --- | ---: | --- |',
    ...t.perTrial.map((trial, i) => `| ${i + 1} | ${trial.runId ? code(trial.runId) : 'unidentified'} | ${trial.exitCode ?? 'unrecognized'} | ${trial.reasons.length ? `${trial.reasons.slice(0, 20).map(code).join(', ')}${trial.reasons.length > 20 ? ` and ${trial.reasons.length - 20} more` : ''}` : 'none'} |`), '');
  const notPass = t.checks.filter(check => check.reading !== 'PASS');
  if (!notPass.length) lines.push(t.checks.length ? 'Every check passed every trial.' : 'No checks were read across the trials.', '');
  else {
    lines.push('| Check | Reading | Passed | pass^k |', '| --- | --- | ---: | --- |',
      ...notPass.slice(0, MAX_ROWS).map(check => `| ${cell(check.id)} | ${check.reading}${check.unpaired ? ' (a pass had no passing same-route control)' : ''} | ${check.passed ?? '?'} of ${check.trials ?? '?'} | ${check.passK ? code(check.passK) : 'insufficient trials'} |`));
    if (notPass.length > MAX_ROWS) lines.push('', `${notPass.length - MAX_ROWS} more checks are in trials.html in the evidence artifact.`);
    lines.push('');
  }
  lines.push('The status counts, checks and comparison above are the first trial\'s; the readings cover every trial. Trials are fresh runs made one after another, only as independent as the application and its state between runs, so correlated trials overstate pass^k. trials.html and trials.sarif in the evidence artifact have every check\'s reading.', '');
  return lines;
}

// The check packs section (pack-updates): an allowlisted projection of the prepare step's pack status and pull records, names,
// versions and states only. It never changes the decision: a pin that no longer loads already stops the assessment.
const PACK_NAME = /^[a-z][a-z0-9-]{1,47}$/, PACK_VERSION = /^\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const PACK_STATES = Object.freeze({ current: 'current', pull: 'behind, same major', major: 'behind by a major version', older: 'newer than this action ships', local: 'the operator\'s own pack', missing: 'no longer ships' });
const packName = v => typeof v === 'string' && PACK_NAME.test(v) ? v : null, packVersion = v => typeof v === 'string' && PACK_VERSION.test(v) ? v : null;
function packsLines(status, pull) {
  if (!object(status) || status.schema !== 'scopehaven-pack-status/1' || !Array.isArray(status.packs)) return [];
  const rows = status.packs.filter(p => object(p) && packName(p.name) && Object.hasOwn(PACK_STATES, p.state)).slice(0, MAX_ROWS);
  const pulled = object(pull) && pull.schema === 'scopehaven-pack-pull/1' && Array.isArray(pull.pulled) ? pull.pulled.filter(p => object(p) && packName(p.name) && packVersion(p.from) && packVersion(p.to)) : [];
  const lines = ['### Check packs', '', '| Target | Instance | Pack | Pinned | Shipped | State |', '| --- | --- | --- | --- | --- | --- |',
    ...rows.map(p => `| ${safeId(p.target) ? code(p.target) : 'unidentified'} | ${safeId(p.as) ? code(p.as) : '?'} | ${code(p.name)} | ${packVersion(p.pinned) ? code(p.pinned) : '?'} | ${packVersion(p.shipped) ? code(p.shipped) : 'none'} | ${PACK_STATES[p.state]}${pulled.some(x => x.as === p.as && x.target === p.target) ? ', pulled for this run' : ''} |`), ''];
  if (pulled.length) lines.push(`Pulled for this run (pack-updates: pull): ${pulled.map(p => `${code(p.name)} ${code(p.from)} to ${code(p.to)}`).join(', ')}. The assessment used a locked copy of the profile in the runner's work directory; the committed profile and \`scopehaven.lock\` are unchanged, so set the version and run \`scopehaven pack lock --update\` to keep it.`, '');
  // pack-updates: pull refuses a profile with an operator's own pack (pack-pull-local), so it is suggested only without one.
  else if (rows.some(p => p.state === 'pull')) lines.push(rows.some(p => p.state === 'local')
    ? 'A pin behind the shipped version no longer loads. Set its version and run `scopehaven pack lock --update` (`pack-updates: pull` does not apply: the profile reads an operator\'s own pack).'
    : 'A pin behind the shipped version no longer loads. Set its version and run `scopehaven pack lock --update`, or set `pack-updates: pull` to assess a locked copy that takes it.', '');
  const unused = Array.isArray(status.unused) ? status.unused.filter(u => object(u) && packName(u.name) && packVersion(u.version)).slice(0, MAX_ROWS) : [];
  if (unused.length) lines.push(`Shipped packs this profile does not use: ${unused.map(u => code(`${u.name}@${u.version}`)).join(', ')}. A pack is added by hand, with its parameters (\`scopehaven pack show NAME\`).`, '');
  return lines;
}

export function buildReport({ runInput, runState = 'ok', gateInput, gateState = 'absent', baselineInput, baselineState = 'absent', failOn = 'fail', assessExit = null,
  sarifPath = '', uploadSarif = 'false', policyBeforeInput, policyAfterInput, policyDiffInput, policyDiffState = 'absent', policyDiffExit = null, failOnPolicyDiff = 'false', requireModelIdentity = 'false',
  reportOnly = 'off', reportOnlyUntil = '', reportOnlyMarked = 'false', trials = null, packStatusInput = null, packPullInput = null, env = process.env } = {}) {
  const secrets = secretValues(env);
  const cell = value => escapeCell(value, { secrets });
  const run = runState === 'ok' ? normalizeRun(runInput) : null;
  const gateRequested = gateState !== 'absent';
  const gate = gateState === 'ok' ? normalizeGate(gateInput) : null;
  const verdict = gateRequested ? (gate ? gate.outcome : 'unavailable') : 'not-requested';
  const policy = policyDiffState === 'absent' ? null : policyDiffState === 'ok' ? normalizePolicyDiff(policyDiffInput, policyDiffExit, expectedPolicyDiff(policyBeforeInput, policyAfterInput)) : { state: 'unavailable' };
  const relaxed = decideReportOnly(decide({ run, gate, gateRequested, failOn, assessExit, trials: gateRequested ? trials : null }), { reportOnly, marked: reportOnlyMarked, gate, gateRequested, assessExit });
  const { decision, reason, causes, policyUnmet } = decideModelIdentity(decidePolicy({ decision: relaxed.decision, reason: relaxed.reason }, { policy, failOnPolicyDiff }), { runInput, baselineInput, baselineState, requireModelIdentity });
  const lines = ['## Scopehaven assessment', '', ...reportOnlyLines(relaxed, reportOnlyUntil, gateRequested, cell)];
  const forwarded = run?.httpV3 && run.targetContext === 'operator-forwarded' ? `${cell(`operator-forwarded target: ${run.targetLabel ?? 'unlabelled'}.`)} `
    : run?.httpV3 && run.targetContext === 'operator-remote' ? `${cell(`remote target over HTTPS: ${run.targetLabel ?? 'unlabelled'}.`)} ` : '';
  lines.push(`> **Scope:** ${forwarded}${cell(run ? (run.httpObserved ? HTTP_V3_SCOPE : SCOPES[run.evidenceOrigin] || UNKNOWN_SCOPE) : SCOPES['local-http-response'])} ${CERTIFICATION}`, '');
  if (!run) {
    lines.push(`No saved run is available (${runState === 'absent' ? 'the assessment did not produce one' : `run file ${runState}`}). See the step log for the setup error.`, '');
  } else {
    lines.push('| Field | Value |', '| --- | --- |',
      `| Run | ${run.id ? code(run.id) : 'invalid identifier'} |`,
      `| Target | ${cell(run.targetId)} (${cell(run.targetName)}) |`,
      `| Application | ${cell(run.applicationId)} |`,
      `| Build | ${cell(run.build)} |`,
      `| Evidence origin | ${cell(run.evidenceOrigin)} |`,
      `| Checks | ${run.checksTotal} |`);
    for (const [label, key] of [['Evidence integrity SHA-256', 'evidenceIntegrity'], ['Profile hash', 'profileHash'], ['Suite hash', 'suiteHash'], ['Policy hash', 'policyHash']])
      if (run.hashes[key]) lines.push(`| ${label} | ${code(run.hashes[key])} |`);
    lines.push('', '### Status counts', '', '| Status | Count |', '| --- | ---: |', ...STATUSES.map(status => `| ${status} | ${run.counts[status]} |`));
    if (run.unrecognized) lines.push(`| unrecognized | ${run.unrecognized} |`);
    lines.push('');
  }
  lines.push('### Regression gate', '');
  if (!gateRequested) lines.push('Not requested (no `baseline-run`).', '');
  else if (!gate) lines.push('**unavailable**: the gate produced no readable summary.', '');
  else {
    lines.push(`Verdict: **${gate.outcome}** (exit ${gate.exitCode})`, '',
      `Reasons: ${gate.reasons.length ? gate.reasons.map(code).join(', ') : 'none'}`, '');
    if (gate.comparison) {
      lines.push(`Baseline ${gate.comparison.baselineRunId ? code(gate.comparison.baselineRunId) : 'unidentified'}: ${gate.comparison.compatibility}` +
        (gate.comparison.restorationLabel ? `; restoration label "${cell(gate.comparison.restorationLabel)}"` : ''), '');
      const ma = gate.comparison.modelAttribution;
      if (ma?.state === 'recorded') lines.push(`Model attribution: verdict changes credited to ${code(ma.flipCause ?? 'none (not comparable)')}; model ${code(ma.relation)} at ${code(ma.strength)}, as the model upstream reported it to the tap; repairs credited to the application: **${ma.repairCreditedToApp ? 'yes' : 'no'}**`, '');
      else if (ma?.state === 'not-recorded') lines.push(`Model attribution: not recorded for one or both runs, so a verdict change may come from the model${ma.malformed.length ? ` (identity present but unreadable: ${ma.malformed.map(code).join(', ')})` : ''}.`, '');
      else if (ma) lines.push('Model attribution: unrecognized.', '');
      const labels = Object.entries(gate.comparison.labels);
      // A repair the attribution does not credit to the application (or whose identity could not be read) is marked as such.
      const uncredited = (ma?.state === 'recorded' && !ma.repairCreditedToApp) || ma?.malformed?.length > 0;
      if (labels.length) lines.push('| Transition | Checks |', '| --- | ---: |', ...labels.map(([label, count]) => `| ${label}${uncredited && REPAIR_LABELS.includes(label) ? ' (not credited to the application)' : ''} | ${count} |`), '');
    }
  }
  if (gateRequested) lines.push(...trialsLines(gate, trials, cell));
  lines.push(...diffSection(baselineState === 'absent' ? null : baselineState === 'ok' && runState === 'ok' ? permissionDiff(baselineInput, runInput) : { comparable: false, reasons: [`The baseline or current run is ${baselineState === 'ok' ? runState : baselineState}.`] }, cell, policyUnmet === true));
  if (run) {
    lines.push('### Checks needing attention', '');
    if (!run.attention.length) lines.push('No failed, errored or inconclusive checks.', '');
    else {
      lines.push('| Check | Title | Severity | Status |', '| --- | --- | --- | --- |',
        ...run.attention.slice(0, MAX_ROWS).map(row => `| ${cell(row.id)} | ${cell(row.title)} | ${cell(row.severity)} | ${cell(row.status)} |`));
      if (run.attention.length > MAX_ROWS) lines.push('', `${run.attention.length - MAX_ROWS} more rows are in the uploaded report.`);
      lines.push('');
    }
  }
  lines.push(...packsLines(packStatusInput, packPullInput));
  lines.push(...policySection(policy, failOnPolicyDiff, cell));
  lines.push(...modelIdentityPolicyLines(requireModelIdentity, causes));
  lines.push('### Action decision', '', `fail-on ${code(FAIL_ON.includes(failOn) ? failOn : 'invalid')}${policy || failOnPolicyDiff !== 'false' ? `, fail-on-policy-diff ${code(['true', 'false'].includes(failOnPolicyDiff) ? failOnPolicyDiff : 'invalid')}` : ''}${relaxed.state !== 'off' ? `, report-only ${code(relaxed.state)}` : ''}: **${decision}** (${code(reason)}${reason === 'report-only' && relaxed.wouldFail ? `; would fail: ${code(safeId(relaxed.wouldFail) || 'unrecognized')}` : ''})`, '');
  lines.push('### SARIF', '', sarifPath ? `Exported to ${cell(sarifPath)}.` : 'No SARIF file was exported.');
  if (uploadSarif === 'true') lines.push('', 'Code scanning upload requested. It runs with `continue-on-error`; private repositories need paid GitHub Code Security, and the job needs `security-events: write`.');
  else lines.push('', 'Code scanning upload not requested (`upload-sarif: false`). The SARIF file is in the evidence artifact.');
  const markdown = redact(`${lines.join('\n')}\n`, secrets);
  const counts = run ? JSON.stringify(run.counts) : '{}';
  const single = value => String(value ?? '').replace(/[\r\n]/g, '');
  const outputs = redact([`run-id=${run?.id || ''}`, `status-counts=${counts}`, `gate-verdict=${verdict}`, `sarif-path=${single(sarifPath)}`,
    `decision=${decision}`, `decision-reason=${reason}`, `policy-diff=${policy ? policy.state : 'not-requested'}`,
    `report-only=${relaxed.state}`, `would-fail=${reason === 'report-only' ? safeId(relaxed.wouldFail) || '' : ''}`].join('\n') + '\n', secrets);
  return { markdown, outputs, decision, reason, verdict, policyDiff: policy ? policy.state : 'not-requested', reportOnly: relaxed.state };
}

export function parseArgs(args) {
  const names = { '--run': 'run', '--gate': 'gate', '--baseline': 'baseline', '--fail-on': 'failOn', '--assess-exit': 'assessExit', '--sarif-path': 'sarifPath', '--upload-sarif': 'uploadSarif', '--format': 'format',
    '--policy-before': 'policyBefore', '--policy-after': 'policyAfter', '--policy-diff': 'policyDiff', '--policy-diff-exit': 'policyDiffExit', '--fail-on-policy-diff': 'failOnPolicyDiff', '--require-model-identity': 'requireModelIdentity',
    '--report-only': 'reportOnly', '--report-only-until': 'reportOnlyUntil', '--report-only-marked': 'reportOnlyMarked', '--trials': 'trials', '--pack-status': 'packStatus', '--pack-pull': 'packPull' };
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = names[args[i]];
    if (!key || Object.hasOwn(options, key) || i + 1 >= args.length) throw new Error('usage');
    options[key] = args[i + 1];
  }
  if (!['markdown', 'outputs', undefined].includes(options.format)) throw new Error('usage');
  return options;
}

export function main(args, env = process.env) {
  const options = parseArgs(args);
  const runFile = readJson(options.run ? resolve(options.run) : '');
  const gateFile = readJson(options.gate ? resolve(options.gate) : '');
  const baselineFile = readJson(options.baseline ? resolve(options.baseline) : '');
  const policyFile = readJson(options.policyDiff ? resolve(options.policyDiff) : '');
  const packStatusFile = readJson(options.packStatus ? resolve(options.packStatus) : ''), packPullFile = readJson(options.packPull ? resolve(options.packPull) : '');
  const policyBefore = readJson(options.policyBefore ? resolve(options.policyBefore) : ''), policyAfter = readJson(options.policyAfter ? resolve(options.policyAfter) : '');
  const assessExit = /^[0-9]{1,3}$/.test(options.assessExit || '') ? Number(options.assessExit) : null;
  const policyDiffExit = /^[0-9]{1,3}$/.test(options.policyDiffExit || '') ? Number(options.policyDiffExit) : null;
  // A requested diff whose file was never written (the diff failed before --out) is unavailable, not absent.
  const policyDiffState = options.policyDiff === undefined ? 'absent' : options.policyDiff === '' || policyFile.state === 'absent' ? 'missing' : policyFile.state;
  const report = buildReport({ runInput: runFile.value, runState: runFile.state, gateInput: gateFile.value, gateState: gateFile.state, baselineInput: baselineFile.value, baselineState: baselineFile.state,
    failOn: options.failOn || 'fail', assessExit, sarifPath: options.sarifPath || '', uploadSarif: options.uploadSarif || 'false',
    policyBeforeInput: policyBefore.value, policyAfterInput: policyAfter.value, policyDiffInput: policyFile.value, policyDiffState, policyDiffExit, failOnPolicyDiff: options.failOnPolicyDiff ?? 'false', requireModelIdentity: options.requireModelIdentity ?? 'false',
    // The prepare step writes no state when it stopped before the window check: that is off, not invalid.
    reportOnly: options.reportOnly || 'off', reportOnlyUntil: options.reportOnlyUntil ?? '', reportOnlyMarked: options.reportOnlyMarked ?? 'false',
    // A malformed count is still a request (0 matches no trials block), so the job fails rather than reading as no trials.
    trials: options.trials === undefined ? null : /^[1-9][0-9]{0,2}$/.test(options.trials) ? Number(options.trials) : 0,
    packStatusInput: packStatusFile.state === 'ok' ? packStatusFile.value : null, packPullInput: packPullFile.state === 'ok' ? packPullFile.value : null, env });
  return options.format === 'outputs' ? report.outputs : report.markdown;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try { process.stdout.write(main(process.argv.slice(2))); }
  catch {
    console.error('Usage: summary.mjs [--format markdown|outputs] [--run RUN.json] [--gate GATE-SUMMARY.json] [--baseline BASELINE-RUN.json] [--fail-on fail|inconclusive|never] [--assess-exit N] [--sarif-path PATH] [--upload-sarif true|false] [--policy-before MATRIX --policy-after MATRIX --policy-diff POLICY-DIFF.json --policy-diff-exit N] [--fail-on-policy-diff true|false] [--require-model-identity true|false] [--report-only off|applied|ended --report-only-until YYYY-MM-DD --report-only-marked true|false] [--trials N] [--pack-status PACK-STATUS.json] [--pack-pull PACK-PULL.json]');
    process.exitCode = 2;
  }
}
