import { isFinalizedRun } from '../temporal-contracts/evaluator.mjs';
import { createResultSigner, writeFinalizedRun, readFinalizedRun, readTrustedPublicKey, isVerifiedRun } from '../temporal-contracts/persistence.mjs';
import { strictModelIdentity, ownedTapConfig } from '../../src/http-model-identity.mjs';
import { constants } from 'node:fs';
import { mkdir, lstat, readdir, realpath, open, unlink } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRegistry, loadProfiles } from '../../src/registry.mjs';
import { createStore } from '../../src/store.mjs';
import { compareRuns, evaluateCheck } from '../../src/runner.mjs';
import { CHECKS, digest, stable } from '../../src/suite.mjs';
import { assertRuntime } from '../../src/runtime.mjs';
import { validateHttpRunEvidence, HttpEvidenceError } from '../../src/contracts.mjs';
// The stated scope of absence passes an egress recorder or SMTP sink decided (presentation only; never a gate reason).
import { absenceScopeRows, absenceScopeRule, routingScopeOf } from '../../src/absence-scope.mjs';
import { routingTierOf } from '../../src/confinement-record.mjs';
import { validateConversationRun, ConversationEvidenceError } from '../../src/conversation-native.mjs';
import { needsAuthorization, isAuthorizationStamp, WINDOW_ENDED } from '../../src/authorization.mjs';
import { unpairedForwardedPasses, unpairedReasonOf } from '../../src/forwarded-pairing.mjs';
import { channelGateReasons } from '../../src/channels.mjs';
import { authorizeConfigured } from '../../src/authorization-file.mjs';
// Sequence evidence (integrations/sequences/native.mjs) loads when that folder is present. Without it, a sequence
// run is refused (sequence-evidence-unavailable) and every other origin is judged as before.
const sequenceNative = await import('../sequences/native.mjs').catch(error => { if (error?.code === 'ERR_MODULE_NOT_FOUND') return null; throw error; });

export const EXIT = Object.freeze({ clean: 0, assessmentFailed: 1, error: 2 });
const statuses = ['pass', 'fail', 'inconclusive', 'error', 'not_applicable'];
const transitions = ['fixed', 'contract-restored', 'local-control-restored', 'regression', 'still-failing', 'preserved', 'unverified', 'incompatible', 'blocked-by-controls', 'not-applicable'];
const hashKeys = ['suiteHash', 'policyHash', 'fixtureHash', 'evaluatorHash', 'profileHash', 'targetConfigHash'];
const identityKeys = ['suiteId', 'applicationId', 'fixtureVersion', 'adapterVersion', 'runtimeMode', 'assertionSchemaVersion', 'contextId', 'build'];
const scopes = {
  'owned-refund-loopback-http': { evidenceScope:'owned-refund-closed-workflow', restorationLabel:'Refund contract restored', interpretation:'Owned synthetic HTTP workflow with operator-window effects, operator revoke ordering and completion timing. Acceptance timing is an application ledger control only. No real provider/model/customer evidence or OS isolation.' },
  'synthetic-local-http': { evidenceScope: 'owned-synthetic-backend', restorationLabel: 'Fixed', interpretation: 'Owned synthetic backend evidence; no production or model security certification.' },
  'local-http-response': { evidenceScope: 'response-only', restorationLabel: 'Response contracts restored', interpretation: 'HTTP response contracts only; backend effects remain unverified.' },
  'local-conversation': { evidenceScope: 'conversation-reply-and-surfaces', restorationLabel: 'Conversation checks restored', interpretation: 'Loopback conversation evidence: reply predicates, customer-visible state and declared surfaces only; fetched-but-unsaid data and tool arguments are not observed.' },
  'local-sequence': { evidenceScope: 'sequence-observed-effects-and-response-status', restorationLabel: 'Sequence checks restored', interpretation: 'Loopback timed sequence: effect rows are decided from the declared observers, where a boundary pass needs a deciding observer held outside the application (hold gate, egress recorder or SMTP sink); response-status rows are the status codes the application answered. Reply text and application state no observer sees are not assessed.' },
};
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(value);
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const countsOf = results => Object.fromEntries(statuses.map(status => [status, results.filter(row => row.status === status).length]));
const same = (a, b) => stable(a) === stable(b);
const sorted = values => [...values].sort();
class GateError extends Error { constructor(code, detail) { super(code); this.code = code; if (typeof detail === 'string') this.detail = detail; } }
const requireShape = (ok, code = 'invalid-run-evidence') => { if (!ok) throw new GateError(code); };

/** Validate shape and internal consistency, not the truth of an untrusted target. */
export function validateRun(run, expectedSuite) {
  requireShape(object(run) && run.schemaVersion === 1 && identifier(run.id) && identifier(run.targetId));
  // The authorization stamp (CMP-ROE-01), when present, is exactly { schema, id, sha256 }: the summary copies only that.
  requireShape(run.authorization === undefined || isAuthorizationStamp(run.authorization));
  // A string first: Object.hasOwn coerces its key, so an array or object naming a known origin would skip every origin rule below.
  requireShape(typeof run.evidenceOrigin === 'string' && Object.hasOwn(scopes, run.evidenceOrigin));
  requireShape(identityKeys.every(key => typeof run[key] === 'string' && run[key].length > 0 && run[key].length <= 200));
  requireShape(hashKeys.every(key => hash(run[key])));
  requireShape(run.targetBuildHash === null || hash(run.targetBuildHash));
  requireShape(Array.isArray(run.results) && run.results.length > 0 && run.results.length <= 1000 && run.checksTotal === run.results.length);
  requireShape(new Set(run.results.map(row => row?.id)).size === run.results.length);
  if (run.evidenceOrigin === 'owned-refund-loopback-http') {
    requireShape(isFinalizedRun(run) || isVerifiedRun(run), 'refund-trusted-finalization-required');
    requireShape(expectedSuite?.sourceReady===true && expectedSuite.targetId===run.targetId && expectedSuite.buildHash===run.targetBuildHash && expectedSuite.evaluatorHash===run.evaluatorHash, 'refund-source-or-target-changed');
  } else requireShape(!Object.hasOwn(run,'refundAdjudication'));
  // An expected suite names its evidence origin (HTTP suites do); a run from another origin never matches it.
  if (expectedSuite?.evidenceOrigin !== undefined) requireShape(expectedSuite.evidenceOrigin === run.evidenceOrigin, 'unexpected-suite-evidence');
  // HTTP evidence uses the one shared validator (src/contracts.mjs), the same rules compareRuns applies.
  let http = { unprovenActors: [], loginUnprovenActors: [] };
  if (run.evidenceOrigin === 'local-http-response') {
    try { http = validateHttpRunEvidence(run, { expectedSuite }); }
    catch (error) { if (error instanceof HttpEvidenceError) throw new GateError(error.code, error.detail); throw error; }
  }
  // Conversation evidence: the native validator recomputes every verdict and binds the run to the expected suite.
  if (run.evidenceOrigin === 'local-conversation') {
    try { http = validateConversationRun(run, { expectedSuite }); }
    catch (error) { if (error instanceof ConversationEvidenceError) throw new GateError(error.code); throw new GateError('invalid-conversation-evidence'); }
  } else requireShape(!Object.hasOwn(run, 'conversationEvidence'));
  // Sequence evidence: the native run is rebuilt from its sealed sequence run, every verdict recomputed, and bound to the expected suite.
  if (run.evidenceOrigin === 'local-sequence') {
    requireShape(sequenceNative !== null, 'sequence-evidence-unavailable');
    try { http = sequenceNative.validateSequenceNativeRun(run, { expectedSuite }); }
    catch (error) { throw error instanceof sequenceNative.SequenceNativeError ? new GateError(error.code, error.detail) : new GateError('invalid-sequence-evidence'); }
  } else requireShape(!Object.hasOwn(run, 'sequenceEvidence'));
  for (const row of run.results) {
    requireShape(object(row) && identifier(row.id) && statuses.includes(row.status) && ['critical', 'high', 'medium', 'low', 'control'].includes(row.severity) && hash(row.evidenceDigest));
    requireShape(Array.isArray(row.assertions) && row.assertions.length <= 100 && row.assertions.every(a => object(a) && statuses.includes(a.status)));
    if (row.status === 'pass') requireShape(row.assertions.length > 0 && row.assertions.every(a => a.status === 'pass'));
    if (row.status === 'fail') requireShape(row.assertions.some(a => a.status === 'fail'));
    if (row.status === 'not_applicable') requireShape(row.assertions.length > 0 && row.assertions.every(a => a.status === 'not_applicable'));
    if (run.evidenceOrigin === 'synthetic-local-http') {
      requireShape(Array.isArray(row.attempts) && digest(row.attempts) === row.evidenceDigest);
      if (row.status === 'pass') {
        // Reuse the core evaluator for request/actor identity, terminal evidence
        // and observed effects instead of accepting a bare "complete" flag.
        let verified = false;
        try {
          const definition = CHECKS.find(check => check.id === row.id);
          verified = Boolean(definition) && row.attempts.length > 0 && evaluateCheck(definition, row.attempts).status === 'pass';
        } catch {}
        requireShape(verified);
      }
    }
  }
  const counts = countsOf(run.results);
  requireShape(object(run.counts) && Object.keys(run.counts).every(key => statuses.includes(key)));
  requireShape(statuses.every(key => (key === 'not_applicable' && !Object.hasOwn(run.counts, key) ? 0 : run.counts[key]) === counts[key]));
  requireShape(Array.isArray(run.requiredControlIds) && run.requiredControlIds.length > 0 && run.requiredControlIds.every(identifier) && new Set(run.requiredControlIds).size === run.requiredControlIds.length);
  if (expectedSuite) {
    requireShape(Array.isArray(expectedSuite.checks) && same(sorted(expectedSuite.checks.map(c => c.id)), sorted(run.results.map(c => c.id))), 'unexpected-suite-evidence');
    const expectedControls = expectedSuite.requiredControlIds || expectedSuite.checks.filter(c => c.severity === 'control').map(c => c.id);
    // Registry HTTP suite exports expose the profile hash, not the suite hash.
    const expectedHash = run.evidenceOrigin === 'local-http-response' ? run.profileHash : run.suiteHash;
    requireShape(same(sorted(expectedControls), sorted(run.requiredControlIds)) && expectedSuite.hash === expectedHash, 'unexpected-suite-evidence');
    requireShape(expectedSuite.checks.every(c => run.results.find(r => r.id === c.id)?.severity === c.severity), 'unexpected-suite-evidence');
  }
  const controls = run.requiredControlIds.map(id => run.results.find(row => row.id === id));
  return { counts, unprovenActors: http.unprovenActors, loginUnprovenActors: http.loginUnprovenActors, rateFailures: http.rateFailures ?? [], controls: { required: controls.length, passed: controls.filter(row => row?.severity === 'control' && row.status === 'pass').length,
    status: controls.every(row => row?.severity === 'control' && row.status === 'pass') ? 'pass' : 'not-passed' } };
}

// A pair with a sequence run on either side is compared by the sequence comparator; every other pair by the core.
const comparePair = (baseline, candidate) => sequenceNative !== null && [baseline, candidate].some(run => run?.evidenceOrigin === 'local-sequence')
  ? sequenceNative.compareSequenceRuns(baseline, candidate) : compareRuns(baseline, candidate);

/** Reject an edited/truncated comparison; retain the core's exact transition labels. */
export function validateComparison(comparison, baseline, candidate) {
  validateRun(baseline); validateRun(candidate);
  requireShape(object(comparison) && typeof comparison.compatible === 'boolean' && typeof comparison.controlsPass === 'boolean', 'invalid-comparison-evidence');
  requireShape(Array.isArray(comparison.rows) && comparison.rows.every(row => object(row) && identifier(row.id) && statuses.includes(row.before) && statuses.includes(row.after) && transitions.includes(row.transition)), 'invalid-comparison-evidence');
  const projection = value => ({ compatible: value.compatible, controlsPass: value.controlsPass, baselineId: value.baselineId, candidateId: value.candidateId,
    reasons: value.reasons, summary: value.summary, evidenceScope: value.evidenceScope, restorationLabel: value.restorationLabel, modelAttribution: value.modelAttribution ?? null,
    rows: value.rows.map(({ id, before, after, transition }) => ({ id, before, after, transition })).sort((a, b) => a.id.localeCompare(b.id)) });
  const fresh = comparePair(baseline, candidate);
  // A comparison saved before model attribution existed has no modelAttribution; it matches a fresh
  // comparison only where that one reads not-recorded. Removing a recorded attribution is refused.
  const supplied = comparison.modelAttribution === undefined && fresh.modelAttribution?.state === 'not-recorded' ? { ...comparison, modelAttribution: fresh.modelAttribution } : comparison;
  requireShape(same(projection(supplied), projection(fresh)), 'invalid-comparison-evidence');
  return supplied;
}

// detail: why the evidence was refused, when the code alone does not say (for example effect-window-exact).
const failureSummary = (code, detail) => ({ schemaVersion: 1, outcome: 'config-or-runtime-error', exitCode: EXIT.error,
  reasons: [code], ...(typeof detail === 'string' ? { detail } : {}), current: null, comparison: null });

// An HTTP baseline taken with the same profile as the expected suite is held to
// that suite too, so an edited baseline cannot shed an actor's identity binding.
// A baseline from another profile or schema is left to the comparison, which
// reports it incompatible (exit 1), not as invalid evidence.
const baselineSuite = (baseline, expectedSuite) => expectedSuite?.evidenceOrigin === 'local-http-response' && baseline?.evidenceOrigin === 'local-http-response'
  && baseline.assertionSchemaVersion === expectedSuite.version && baseline.profileHash === expectedSuite.hash ? expectedSuite : undefined;

const POLICY_NOT_MET_LABEL = 'Not attributable to the application: the model identity policy was not met';
/** Deterministic for the same evidence. No titles, bodies, traces, paths or error text. */
export function summarizeGate({ candidate, baseline = null, comparison, expectedSuite, requireModelIdentity = false, selfTest = null } = {}) {
  try {
    const current = validateRun(candidate, expectedSuite), before = baseline ? validateRun(baseline, baselineSuite(baseline, expectedSuite)) : null;
    requireShape(baseline || comparison === undefined || comparison === null, 'invalid-comparison-evidence');
    const compared = baseline ? validateComparison(comparison ?? comparePair(baseline, candidate), baseline, candidate) : null;
    const reasons = [];
    if (current.counts.error || before?.counts.error) reasons.push('runner-error');
    if (current.counts.fail) reasons.push('checks-failed');
    // A conversation row under a rate policy failed on its failure rate (promises), not on a single confirmed leak.
    if (current.rateFailures.length) reasons.push('conversation-rate-above-limit');
    if (current.counts.inconclusive) reasons.push('inconclusive-evidence');
    // actor-identity/5: a boundary row that observed the expected refusal while its actor's identity or allowed use was not
    // established for it is a distinct state, reported as such; it is never a pass and no repair is credited on it (it is counted inconclusive).
    if (candidate.results.some(row => row?.decision === 'prohibition-observed-identity-unproven')) reasons.push('prohibition-observed-identity-unproven');
    if (current.counts.not_applicable) reasons.push('not-applicable-is-not-pass');
    if (current.controls.status !== 'pass') reasons.push('required-controls-not-passed');
    if (current.unprovenActors.length) reasons.push('identity-not-established');
    // Operator-forwarded (H1 step 2) and remote (step 3): a boundary pass with no passing required control on the same route
    // could be the forwarder, or a gateway in front of the remote target, answering that route itself (src/forwarded-pairing.mjs).
    if (unpairedForwardedPasses(candidate).length) reasons.push(unpairedReasonOf(candidate.targetContext));
    // Declared channels (N11, src/channels.mjs): an absence pass whose declared channels were not all observed in its window, carried an
    // effect its clauses do not bound, or whose run's confinement did not show no undeclared way out, is not clean
    // (channel-unobserved:<channel>, channel-unaccounted:<channel>, channels-undeclared).
    for (const reason of channelGateReasons(candidate)) if (!reasons.includes(reason)) reasons.push(reason);
    // A baseline taken while a login was not proven cannot show a fix for that actor.
    if (before?.loginUnprovenActors.length) reasons.push('baseline-identity-not-established');
    if (compared && !compared.compatible) reasons.push('incompatible-baseline');
    if (compared && (compared.summary.unverified || compared.summary.notApplicable)) reasons.push('comparison-incomplete');
    // Model identity recorded on both runs: a repair the application is not credited with (the model
    // changed, both changed, or the model was not observed comparably) never passes the gate as a fix.
    if (compared?.modelAttribution?.state === 'recorded' && compared.summary.fixed > 0 && compared.modelAttribution.repairCreditedToApp !== true) reasons.push('repair-not-attributable');
    // A model identity a run carries but that cannot be read (or that failed attribution) is reported,
    // never read as "no identity". With --require-model-identity, a model-served comparison must carry
    // a recorded identity on both runs: deleting the field no longer lets a model swap pass as a repair.
    if (compared?.modelAttribution?.malformed?.length) reasons.push('model-identity-malformed');
    // The strict policy also needs custody held by Scopehaven (tap-memory) and a comparable relation.
    const strict = requireModelIdentity === true && compared ? strictModelIdentity(compared, baseline, candidate) : null;
    for (const reason of strict?.reasons ?? []) if (!reasons.includes(reason)) reasons.push(reason);
    // Policy not met: the summary credits no repair and withholds the repair label where one could stand.
    const policyUnmet = Boolean(strict?.reasons.length && compared.modelAttribution);
    // --self-test (src/self-test.mjs, reasons given by runGate): a check that cannot fail or always fails is never counted
    // toward a clean exit, whatever the run read; the report is carried beside the summary.
    for (const reason of selfTest?.reasons ?? []) if (!reasons.includes(reason)) reasons.push(reason);
    const exitCode = reasons.includes('runner-error') ? EXIT.error : reasons.length ? EXIT.assessmentFailed : EXIT.clean;
    // HTTP v3 (observers, target context): the scope names authoritative backend observation and,
    // for a forwarded target, its name. Earlier versions keep their summaries unchanged.
    const v3 = candidate.evidenceOrigin === 'local-http-response' && candidate.adapterVersion === 'loopback-response-contract/3';
    const forwarded = v3 && candidate.targetContext === 'operator-forwarded', remoteRun = v3 && candidate.targetContext === 'operator-remote';
    const observed = v3 && Array.isArray(candidate.observers) && candidate.observers.length > 0;
    const base = observed ? { evidenceScope: 'response-plus-observed-backend', restorationLabel: 'Response contracts restored; backend observed where marked',
      interpretation: 'HTTP response contracts plus authoritative backend observation for rows marked observed; other backend effects remain unverified.' } : scopes[candidate.evidenceOrigin];
    const scope = forwarded ? { ...base, interpretation: `operator-forwarded target: ${candidate.targetLabel ?? 'unlabelled'}. ${base.interpretation}` }
      : remoteRun ? { ...base, interpretation: `remote target over HTTPS: ${candidate.targetLabel ?? 'unlabelled'}. ${base.interpretation}` } : base;
    // Routing declared, not shown exclusive, and bounded by the final mark: stated beside the counts, never read for the outcome.
    const absenceScope = v3 ? absenceScopeRows(candidate) : [];
    return { schemaVersion: 1, outcome: exitCode === 0 ? 'clean' : exitCode === 1 ? 'assessment-failed' : 'config-or-runtime-error', exitCode, reasons,
      current: { runId: candidate.id, targetId: candidate.targetId, checksTotal: candidate.checksTotal, counts: current.counts, ...(candidate.authorization ? { authorization: candidate.authorization } : {}),
        evidenceOrigin: candidate.evidenceOrigin, ...(v3 ? { targetContext: forwarded ? 'operator-forwarded' : remoteRun ? 'operator-remote' : 'local-app', targetLabel: forwarded || remoteRun ? candidate.targetLabel ?? null : null } : {}), ...scope, allowedControls: current.controls,
        ...(absenceScope.length ? { absenceScope: { tier: routingTierOf(candidate), routing: routingScopeOf(candidate), checks: absenceScope.map(row => row.id), note: absenceScopeRule(candidate) } } : {}) },
      comparison: compared ? { requested: true, baselineRunId: baseline.id, compatibility: compared.compatible ? 'compatible' : 'incompatible',
        allowedControlsPass: compared.controlsPass, summary: { ...compared.summary }, evidenceScope: compared.evidenceScope,
        restorationLabel: policyUnmet && compared.compatible && compared.controlsPass ? POLICY_NOT_MET_LABEL : compared.restorationLabel, labels: Object.fromEntries(transitions.map(label => [label, compared.rows.filter(row => row.transition === label).length])),
        ...(compared.modelAttribution ? { modelAttribution: compared.modelAttribution.state === 'recorded'
          ? { state: 'recorded', flipCause: compared.modelAttribution.flipCause, relation: compared.modelAttribution.relation, strength: compared.modelAttribution.strength, repairCreditedToApp: policyUnmet ? false : compared.modelAttribution.repairCreditedToApp, ...(policyUnmet ? { policy: 'not-met' } : {}) }
          : { state: compared.modelAttribution.state, ...(compared.modelAttribution.malformed?.length ? { malformed: [...compared.modelAttribution.malformed] } : {}), ...(policyUnmet ? { policy: 'not-met' } : {}) } } : {}),
        // Only with --require-model-identity on a model-served comparison: whether the policy was met, and why not.
        ...(strict && compared.modelAttribution ? { modelIdentityPolicy: { required: true, met: strict.reasons.length === 0, causes: strict.causes } } : {}) }
        : { requested: false, compatibility: 'not-requested' }, ...(selfTest ? { selfTest: selfTest.report } : {}) };
  } catch (error) { return error instanceof GateError ? failureSummary(error.code, error.detail) : failureSummary('invalid-evidence'); }
}

// The switches: they take no value.
const SWITCHES = Object.freeze({ '--require-model-identity': 'requireModelIdentity', '--report-only': 'reportOnly', '--self-test': 'selfTest' });
export function parseArgs(args) {
  const options = {}, names = { '--target': 'targetId', '--config': 'configFile', '--out': 'outputDirectory', '--baseline': 'baselineRunId', '--saved-refund':'savedRefund', '--refund-public-key':'refundPublicKey', '--refund-key-fingerprint':'refundKeyFingerprint', '--expected-run':'expectedRunId', '--refund-trust-out':'refundTrustOutput', '--authorization': 'authorizationFile', '--report-only-until': 'reportOnlyUntil', '--report-only-runs': 'reportOnlyRuns', '--trials': 'trials', '--pass-k': 'passK', '--pass-k-floor': 'passKFloor' };
  for (let i = 0; i < args.length; i++) {
    if (Object.hasOwn(SWITCHES, args[i])) { requireShape(!Object.hasOwn(options, SWITCHES[args[i]]), 'invalid-options'); options[SWITCHES[args[i]]] = true; continue; }
    const key = names[args[i]], value = args[++i];
    requireShape(key && !Object.hasOwn(options, key) && typeof value === 'string' && value.length > 0 && !value.startsWith('--'), 'invalid-options');
    options[key] = value;
  }
  if (options.reportOnlyRuns !== undefined) options.reportOnlyRuns = /^[1-9][0-9]{0,2}$/.test(options.reportOnlyRuns) ? Number(options.reportOnlyRuns) : -1;
  for (const key of ['trials', 'passK']) if (options[key] !== undefined) options[key] = /^[1-9][0-9]{0,2}$/.test(options[key]) ? Number(options[key]) : -1;
  validateOptions(options); return options;
}
function validateOptions(options) {
  requireShape(object(options) && Object.keys(options).every(key => ['targetId', 'configFile', 'outputDirectory', 'baselineRunId', 'requireModelIdentity', 'savedRefund', 'refundPublicKey', 'refundKeyFingerprint', 'expectedRunId', 'refundTrustOutput', 'authorizationFile', 'reportOnly', 'reportOnlyUntil', 'reportOnlyRuns', 'selfTest', 'trials', 'passK', 'passKFloor'].includes(key)), 'invalid-options');
  // A saved refund result is read, not run: there is no profile to self-test.
  if (options.selfTest !== undefined) requireShape(typeof options.selfTest === 'boolean' && options.savedRefund === undefined, 'invalid-options');
  if (options.requireModelIdentity !== undefined) requireShape(typeof options.requireModelIdentity === 'boolean', 'invalid-options');
  // A run without a baseline makes no repair claim, so the switch would decide nothing: refused, as the Action refuses it.
  if (options.requireModelIdentity === true) requireShape(options.baselineRunId !== undefined, 'invalid-options');
  requireShape(identifier(options.targetId) && (options.savedRefund || (typeof options.outputDirectory === 'string' && isAbsolute(options.outputDirectory))), 'invalid-options');
  for (const key of ['savedRefund','refundPublicKey','refundTrustOutput']) if(options[key]!==undefined) requireShape(typeof options[key]==='string'&&isAbsolute(options[key]),'invalid-options');
  if(options.savedRefund!==undefined) requireShape(options.refundPublicKey&&hash(options.refundKeyFingerprint)&&identifier(options.expectedRunId)&&!options.baselineRunId&&!options.refundTrustOutput&&!options.outputDirectory,'invalid-options');
  else requireShape(options.refundPublicKey===undefined&&options.refundKeyFingerprint===undefined&&options.expectedRunId===undefined,'invalid-options');
  if (options.configFile !== undefined) requireShape(typeof options.configFile === 'string' && isAbsolute(options.configFile), 'invalid-options');
  if (options.baselineRunId !== undefined) requireShape(identifier(options.baselineRunId), 'invalid-options');
  if (options.authorizationFile !== undefined) requireShape(typeof options.authorizationFile === 'string' && isAbsolute(options.authorizationFile) && options.savedRefund === undefined, 'invalid-options');
  // Report-only needs a bounded window: a last UTC date, a number of runs, or both. A saved refund result records no new run, so it has none.
  if (options.reportOnly === true) requireShape(options.savedRefund === undefined && (options.reportOnlyUntil !== undefined || options.reportOnlyRuns !== undefined), 'invalid-options');
  else requireShape((options.reportOnly === undefined || options.reportOnly === false) && options.reportOnlyUntil === undefined && options.reportOnlyRuns === undefined, 'invalid-options');
  // Shape only here; the calendar date and the run cap are checked by report-only.mjs before anything is read or sent.
  if (options.reportOnlyUntil !== undefined) requireShape(typeof options.reportOnlyUntil === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(options.reportOnlyUntil), 'invalid-options');
  if (options.reportOnlyRuns !== undefined) requireShape(Number.isSafeInteger(options.reportOnlyRuns) && options.reportOnlyRuns >= 1, 'invalid-options');
  // --trials N, with --pass-k and --pass-k-floor only beside it. Shape only here; the count, k and floor are checked by
  // trials.mjs before anything is read or sent. A saved refund result records no new run, so it has no trials.
  if (options.trials !== undefined) requireShape(Number.isSafeInteger(options.trials) && options.trials >= 1 && options.savedRefund === undefined, 'invalid-options');
  else requireShape(options.passK === undefined && options.passKFloor === undefined, 'invalid-options');
  if (options.passK !== undefined) requireShape(Number.isSafeInteger(options.passK) && options.passK >= 1, 'invalid-options');
  if (options.passKFloor !== undefined) requireShape(typeof options.passKFloor === 'string' && /^[0-9/]{1,15}$/.test(options.passKFloor), 'invalid-options');
}

const marker = '.scopehaven-regression-gate';
const markerText = 'scopehaven-regression-gate/1\n';
const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
async function writePrivate(path, content) {
  const handle = await open(path, flags, 0o600);
  try { await handle.writeFile(content); await handle.sync(); } finally { await handle.close(); }
}
async function privateDirectory(path) {
  const stat = await lstat(path);
  requireShape(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === process.getuid() && (stat.mode & 0o7777) === 0o700, 'output-directory-not-private');
}
async function prepareOutput(path) {
  const requested = resolve(path), parent = await realpath(resolve(requested, '..'));
  // Require an existing parent: no recursive creation in an accidental location.
  const directory = join(parent, basename(requested));
  const project = await realpath(fileURLToPath(new URL('../../', import.meta.url)));
  const data = join(project, 'data');
  const fromData = relative(data, directory);
  requireShape(directory !== project && (fromData === '..' || fromData.startsWith(`..${sep}`) || isAbsolute(fromData)), 'output-directory-is-project-data');
  try { await mkdir(directory, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  await privateDirectory(directory);
  const entries = await readdir(directory);
  if (!entries.includes(marker)) {
    requireShape(entries.length === 0, 'output-directory-not-dedicated');
    await writePrivate(join(directory, marker), markerText);
  }
  const handle = await open(join(directory, marker), constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    requireShape(stat.isFile() && stat.uid === process.getuid() && (stat.mode & 0o7777) === 0o600 && stat.size === markerText.length, 'invalid-output-marker');
    requireShape(await handle.readFile('utf8') === markerText, 'invalid-output-marker');
  } finally { await handle.close(); }
  requireShape(entries.every(name => [marker, 'runs', 'notes', 'gate-summaries', '.gate-lock', 'signed-results'].includes(name)), 'output-directory-not-dedicated');
  return directory;
}

/** One run, one immutable summary, no retries or scheduler. Errors are allowlisted. */
export async function runGate(options, { env = {}, now = new Date() } = {}) {
  let lock, stage = 'runtime-error';
  try {
    assertRuntime(); stage = 'invalid-options'; validateOptions(options);
    // Report-only: the window is checked against the run date before anything is read or sent. report-only.mjs (and the
    // report and SARIF renderers it loads) is imported only then, so the gate's import closure is unchanged without it.
    stage = 'report-only-unavailable';
    const ro = options.reportOnly === true ? await import('./report-only.mjs') : null;
    const reportOnly = ro ? ro.checkWindow({ until: options.reportOnlyUntil ?? null, runs: options.reportOnlyRuns ?? null }, now) : null;
    // --trials (trials.mjs, imported only then): the count, k and floor are checked before anything is read or sent.
    stage = 'trials-unavailable';
    const tr = options.trials !== undefined ? await import('./trials.mjs') : null;
    const trials = tr ? tr.checkTrials({ trials: options.trials, k: options.passK ?? null, floor: options.passKFloor ?? null }) : null;
    stage = 'configuration-error';
    const profiles = await loadProfiles(options.configFile);
    const registry = createRegistry({ profiles, env });
    requireShape(registry.has(options.targetId), 'unknown-target');
    const target = registry.list().find(row => row.id === options.targetId);
    requireShape(target?.available === true, target?.kind === 'http-contract' ? 'target-credentials-unavailable' : 'target-unavailable');
    // Repeated trials are fresh runs of an HTTP contract target. Scripted targets give the same run each time, and a
    // conversation target carries its own trials inside one run, so any other target is refused, never run once as if repeated.
    if (trials) requireShape(target.kind === 'http-contract', 'trials-unsupported-target');
    // --self-test (src/self-test.mjs): the profile's planted violations through the pure evaluators, before the record is
    // checked, the output directory is touched or anything is sent. Only an HTTP contract target is planted; any other is
    // refused (self-test-unsupported-target), never gated as if it had been tested.
    let selfTest = null;
    if (options.selfTest === true) {
      stage = 'self-test-error';
      const { selfTestFor, selfTestReasons, SelfTestError } = await import('../../src/self-test.mjs');
      try { const report = selfTestFor(target, profiles.find(p => p.id === options.targetId)); selfTest = { report, reasons: selfTestReasons(report) }; }
      catch (error) { if (error instanceof SelfTestError) throw new GateError(error.code); throw error; }
      stage = 'configuration-error';
    }
    const expectedSuite = registry.currentSuite ? await registry.currentSuite(options.targetId) : registry.exportSuite(options.targetId);
    if(options.savedRefund) {
      requireShape(target.kind==='owned-refund-contract','refund-saved-target-required');
      stage='refund-trust-key-error';
      const publicKey=await readTrustedPublicKey(options.refundPublicKey,{resultFile:options.savedRefund,expectedPublicKeyFingerprint:options.refundKeyFingerprint});
      stage='refund-saved-result-invalid';
      const candidate=await readFinalizedRun(options.savedRefund,{publicKey,expectedPublicKeyFingerprint:options.refundKeyFingerprint,expectedSuite,expectedRunId:options.expectedRunId});
      return summarizeGate({candidate,expectedSuite});
    }
    if(target.kind==='owned-refund-contract')requireShape(!options.baselineRunId,'refund-fresh-baseline-required');
    // A configured target runs only under an authorization record that covers it now (CMP-ROE-01): checked before
    // the output directory is touched or any request is sent. The refusal's code is the gate's reason. The owned model
    // tap's upstream, which this process forwards the application's model calls to, must be covered too. The window is
    // checked again before every request the run sends and every observer call it makes, and once more immediately
    // before the run is stamped and saved; once it ends, nothing more is sent and the gate reports
    // authorization-window-ended (exit 2), saving and stamping nothing.
    let authorization = null, granted = null;
    if (needsAuthorization(target)) {
      try { granted = await authorizeConfigured(profiles.find(p => p.id === options.targetId), options.authorizationFile, { alsoContacts: [ownedTapConfig(env)?.upstream].filter(upstream => upstream !== undefined) }); authorization = granted.stamp; }
      catch (error) { throw new GateError(error?.name === 'AuthorizationError' ? error.code : 'authorization-invalid'); }
    }
    stage = 'output-directory-error';
    const directory = await prepareOutput(options.outputDirectory);
    const lockPath = join(directory, '.gate-lock');
    try { await writePrivate(lockPath, 'one-shot gate in progress\n'); lock = lockPath; }
    catch { throw new GateError('output-directory-busy'); }
    const store = createStore(directory); await store.ready;
    const summaries = join(directory, 'gate-summaries');
    try { await mkdir(summaries, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    await privateDirectory(summaries);
    // The window's runs are counted in this output directory, under the lock, before this run.
    const used = reportOnly ? await ro.runsUsed(summaries) : 0;
    stage = 'baseline-read-error';
    const baseline = options.baselineRunId ? await store.get(options.baselineRunId) : null;
    if (baseline) validateRun(baseline);
    stage = 'runner-error';
    const runOnce = async () => {
      let candidate;
      try { candidate = await registry.run(options.targetId, granted ? { beforeRequest: granted.window.check, remote: granted.remote } : undefined); }
      catch (error) { if (granted?.window.ended()) throw new GateError(WINDOW_ENDED); throw error; }
      if (granted?.window.ended()) throw new GateError(WINDOW_ENDED);
      requireShape(candidate.targetId === options.targetId, 'unexpected-target-evidence');
      validateRun(candidate, expectedSuite);
      const currentSuite = registry.currentSuite ? await registry.currentSuite(options.targetId) : expectedSuite;
      validateRun(candidate, currentSuite);
      return { candidate, currentSuite };
    };
    let { candidate, currentSuite } = await runOnce();
    // --trials: the other trials run the same way, one after another under the same lock and window, and every one is
    // validated before any of them is stamped or saved.
    let others = [];
    for (let trial = 1; trial < (trials?.trials ?? 1); trial++) others.push((await runOnce()).candidate);
    // The pass^k column over the trials, before any is stamped or saved: trials of another identity are refused with nothing kept.
    stage = 'trials-error';
    const read = trials ? tr.trialColumn([candidate, ...others], { ...trials, expectedSuite: currentSuite }) : null;
    stage = 'runner-error';
    // The window once more, immediately before the run is stamped and saved: a run that ended at or after validUntil is refused.
    if (granted) { try { granted.window.check(); } catch { throw new GateError(WINDOW_ENDED); } }
    // The stamp is added after validation, so it never changes a verdict; the store's checksum then covers it like the rest of the run.
    if (authorization) { candidate = { ...candidate, authorization }; others = others.map(run => ({ ...run, authorization })); }
    stage = 'evidence-storage-error';
    if(candidate.evidenceOrigin==='owned-refund-loopback-http') {
      const signer=createResultSigner();
      const envelope=signer.signRun(candidate);
      const signedPath=join(directory,'signed-results',`${candidate.id}.json`);
      await writeFinalizedRun(signedPath,envelope);
      if(options.refundTrustOutput) {
        const trustedDestination=join(await realpath(dirname(options.refundTrustOutput)),basename(options.refundTrustOutput));
        const outside=relative(directory,trustedDestination);
        requireShape(outside==='..'||outside.startsWith(`..${sep}`)||isAbsolute(outside),'refund-trust-key-must-be-external');
        await writePrivate(trustedDestination,signer.publicKey);
      }
      candidate=await readFinalizedRun(signedPath,{publicKey:signer.publicKey,expectedPublicKeyFingerprint:signer.publicKeyFingerprint,expectedSuite:currentSuite,expectedRunId:candidate.id});
    }
    const saved = await store.save(candidate);
    const savedOthers = [];
    for (const run of others) savedOthers.push(await store.save(run));
    let summary = summarizeGate({ candidate: candidate.evidenceOrigin==='owned-refund-loopback-http'?candidate:saved, baseline, expectedSuite: currentSuite, requireModelIdentity: options.requireModelIdentity === true, selfTest });
    // Each check's reading against the floor beside the first trial's verdict, with every other trial's own reasons.
    if (trials) summary = tr.applyTrials(summary, savedOthers.map(run => summarizeGate({ candidate: run, expectedSuite: currentSuite })), trials, read);
    const window = reportOnly ? ro.windowState(reportOnly, { used, now }) : null;
    const recorded = window ? ro.applyReportOnly(summary, window) : summary;
    await privateDirectory(summaries);
    // While the window applies, the report and SARIF marked REPORT-ONLY are written before the summary that records the run,
    // so a run whose marked files could not be written is not counted and exits 2.
    if (window?.state === 'applied') {
      stage = 'report-only-output-error';
      const stored = await store.get(saved.id);
      await writePrivate(join(summaries, `${saved.id}.report-only.html`), ro.markedReport(stored, window));
      await writePrivate(join(summaries, `${saved.id}.report-only.sarif`), ro.markedSarif(stored, window));
      stage = 'evidence-storage-error';
    }
    // The trials' report and SARIF (pass^k, k, floor and reading per check), marked REPORT-ONLY too while that window
    // applies; written before the summary, so a run whose trial files could not be written is not counted and exits 2.
    if (read && recorded.trials) {
      stage = 'trials-output-error';
      const stored = await store.get(saved.id);
      const html = tr.trialsReport(stored, recorded), sarif = tr.trialsSarif(stored, recorded, read.column);
      await writePrivate(join(summaries, `${saved.id}.trials.html`), window?.state === 'applied' ? ro.stampHtml(html, window) : html);
      await writePrivate(join(summaries, `${saved.id}.trials.sarif`), window?.state === 'applied' ? ro.stampSarif(sarif, window) : sarif);
      stage = 'evidence-storage-error';
    }
    await writePrivate(join(summaries, `${saved.id}.json`), `${JSON.stringify(recorded, null, 2)}\n`);
    return recorded;
  // A remote target the connector refused before or during its run (src/remote-target.mjs) reports the refusal's code.
  } catch (error) { return failureSummary(error instanceof GateError || error?.name==='TemporalPersistenceError' || error?.name === 'RemoteTargetError' || error?.name === 'ReportOnlyError' || error?.name === 'TrialsError' ? error.code : stage); }
  finally { if (lock) await unlink(lock).catch(() => {}); }
}
