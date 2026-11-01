// Read-side projector: saved local HTTP response-contract runs -> scopehaven-observation/1.
// Response-only scope: backend stages stay unobservable. Raw responses are discarded by
// design, so JSON predicate values cannot be re-evaluated. Every assertion that can be
// recomputed from the retained evidence fields is recomputed (recomputeHttpRow), and a
// stored label that disagrees is conflicting, never trusted.
import { compareRuns } from './runner.mjs';
import { validateHttpRunEvidence } from './contracts.mjs';
import { digest } from './domain.mjs';
import { CONTRACT_VERSION, CHECK_VERDICTS, ContractError, LIMITS, unsupported, viewDigest } from './evidence-contract.mjs';
import { CONTRACT_EVALUATOR_HASH } from './contract-synthetic.mjs';

// Supported (adapterVersion, assertionSchemaVersion) pairs and the stored row reader for
// each. Unknown pairs are unsupported('http-version').
export const HTTP_V1_PAIR = 'loopback-response-contract/1|http-contract/2';
export const HTTP_V2_PAIR = 'loopback-response-contract/2|http-contract/3';
// Connector v3 (declared observers, sealed effect windows) waits for the same reviewed reader.
export const HTTP_V3_PAIR = 'loopback-response-contract/3|http-contract/4';
// Connector v2 is not merged. Its runs stay unsupported('http-version-pending') until a
// reviewed v2 reader exists. That reader is more than a table change: it must check
// identityEvidence (actor-identity/3) and never pass rows of an actor whose login is unproven.
export const HTTP_CONNECTOR_V2_PENDING = Object.freeze({ pending: 'http-version-pending' });
export const HTTP_VERSION_TABLE = Object.freeze({
  [HTTP_V1_PAIR]: Object.freeze({ reader: 'response-metadata/1', ruleVersion: 'http-stage-rules/2' }),
  [HTTP_V2_PAIR]: HTTP_CONNECTOR_V2_PENDING,
  [HTTP_V3_PAIR]: HTTP_CONNECTOR_V2_PENDING,
});
const STATUS_ASSERTION = 'HTTP status matches contract';
const BACKEND_ASSERTION = 'Trusted backend observation available';
const JSON_KINDS = ['json.equals', 'json.exists', 'json.notContains'];
const TERMINAL = ['complete', 'invalid-json'];
const TRANSPORT_FAILURES = ['timeout', 'network', 'too-large'];
const PROBLEM_ORDER = ['transport-facts-inconsistent', 'assertion-set-invalid', 'stored-assertion-disagrees'];
const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(value);
const sha256Hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const str = value => typeof value === 'string' ? value : null;
const observedStage = value => ({ state: 'observed', value });
const otherStage = (state, basis) => ({ state, basis });

export function httpVersionOf(run) {
  // Both versions as strings first: the template coerces, so ["loopback-response-contract/1"] would select a known reader (D-01's shape).
  if (typeof run?.adapterVersion !== 'string' || typeof run?.assertionSchemaVersion !== 'string') return null;
  const key = `${run.adapterVersion}|${run.assertionSchemaVersion}`;
  return Object.hasOwn(HTTP_VERSION_TABLE, key) ? HTTP_VERSION_TABLE[key] : null;
}
// A v1 label on evidence that carries v2-only fields is a downgrade, as the v2 gate rules it.
const downgraded = run => Object.hasOwn(run, 'identityEvidence') ||
  run.results.some(row => isRecord(row?.trace?.[0]?.data) && ['credentialMode', 'requestTimeoutMs'].some(key => Object.hasOwn(row.trace[0].data, key)));

// Recomputes one stored v1 row from its retained evidence fields. Mirrors the consistency
// rules of validateHttpObservation (integrations/regression-gate/gate.mjs at 4444dc7) and
// returns problems instead of throwing. This is the single swap point for the shared
// contracts.mjs evidence validator planned with connector v2.
export function recomputeHttpRow(row) {
  const problems = [], flag = (basis, detail) => problems.push({ basis, detail });
  const assertions = Array.isArray(row.assertions) ? row.assertions : [];
  if (row.status === 'not_applicable') {
    if (!assertions.length || !assertions.every(a => isRecord(a) && a.status === 'not_applicable')) flag('assertion-set-invalid', 'not-applicable-assertions');
    if (!isRecord(row.observed) || row.observed.requestAttempted !== false) flag('transport-facts-inconsistent', 'not-applicable-request');
    return { notApplicable: true, problems, recomputedAssertions: assertions.filter(isRecord).map(a => a.status), recomputedStatus: 'not_applicable', requestAttempted: false, transportOutcome: null, httpStatus: null, terminal: false, jsonPredicates: 0 };
  }
  const evidence = row.trace?.[0]?.data, observed = row.observed;
  if (!isRecord(evidence) || !isRecord(observed)) {
    flag('transport-facts-inconsistent', 'evidence-shape');
    return { notApplicable: false, problems, recomputedAssertions: [], recomputedStatus: 'inconclusive', requestAttempted: false, transportOutcome: null, httpStatus: null, terminal: false, jsonPredicates: 0 };
  }
  const outcome = evidence.transportOutcome, terminal = TERMINAL.includes(outcome);
  const knownStatus = Number.isInteger(evidence.httpStatus) && evidence.httpStatus >= 100 && evidence.httpStatus <= 599;
  if (!['response', 'backend'].includes(row.evidenceRequirement) || row.backendEvidence !== 'unavailable' || evidence.backendEvidence !== 'unavailable') flag('transport-facts-inconsistent', 'backend-evidence');
  if (!identifier(evidence.requestId) || !identifier(evidence.actorId) || !['GET', 'POST'].includes(evidence.method) || !sha256Hex(evidence.requestPathHash)) flag('transport-facts-inconsistent', 'request-identity');
  if (!knownStatus && evidence.httpStatus !== null) flag('transport-facts-inconsistent', 'http-status');
  if (!Number.isSafeInteger(evidence.responseBytes) || evidence.responseBytes < 0) flag('transport-facts-inconsistent', 'response-bytes');
  if (!['responseComplete', 'jsonParsed', 'requestAttempted'].every(key => typeof evidence[key] === 'boolean')) flag('transport-facts-inconsistent', 'flags');
  if (![...TERMINAL, ...TRANSPORT_FAILURES].includes(outcome)) flag('transport-facts-inconsistent', 'transport-outcome');
  if (observed.evidenceScope !== 'response-only' || observed.complete !== evidence.responseComplete || observed.jsonParsed !== evidence.jsonParsed || observed.httpStatus !== evidence.httpStatus) flag('transport-facts-inconsistent', 'observed-mirror');
  if (evidence.responseComplete !== terminal || evidence.jsonParsed !== (outcome === 'complete')) flag('transport-facts-inconsistent', 'terminal-flags');
  if (terminal && !(evidence.requestAttempted === true && knownStatus)) flag('transport-facts-inconsistent', 'terminal-without-response');
  if (evidence.requestAttempted !== true && !(outcome === 'timeout' && evidence.httpStatus === null && evidence.responseBytes === 0)) flag('transport-facts-inconsistent', 'unattempted-request');
  const predicates = Array.isArray(observed.predicates) && observed.predicates.length <= 10 ? observed.predicates : null;
  if (!predicates) flag('assertion-set-invalid', 'predicates');
  const completeJSON = terminal && evidence.jsonParsed === true;
  const recomputedAssertions = [];
  let statusAssertions = 0, backendAssertions = 0, predicateIndex = 0;
  for (const assertion of assertions) {
    if (!isRecord(assertion)) { flag('assertion-set-invalid', 'assertion-shape'); recomputedAssertions.push(null); continue; }
    if (assertion.name === STATUS_ASSERTION) {
      statusAssertions++;
      const expected = typeof assertion.expected === 'string' ? /^HTTP ([1-5][0-9]{2})$/.exec(assertion.expected) : null;
      if (!expected) { flag('assertion-set-invalid', 'status-expected'); recomputedAssertions.push(null); continue; }
      const status = !knownStatus ? 'inconclusive' : evidence.httpStatus === Number(expected[1]) ? 'pass' : 'fail';
      recomputedAssertions.push(status);
      if (assertion.status !== status || assertion.actual !== (knownStatus ? `HTTP ${evidence.httpStatus}` : 'HTTP status unavailable')) flag('stored-assertion-disagrees', STATUS_ASSERTION);
    } else if (assertion.name === BACKEND_ASSERTION) {
      // The connector never holds backend evidence, so this assertion is always inconclusive.
      backendAssertions++; recomputedAssertions.push('inconclusive');
      if (assertion.status !== 'inconclusive') flag('stored-assertion-disagrees', BACKEND_ASSERTION);
    } else {
      const predicate = predicates?.[predicateIndex++];
      if (!isRecord(predicate) || !JSON_KINDS.includes(predicate.kind) || !['pass', 'fail', 'inconclusive'].includes(predicate.outcome) || assertion.name !== `${predicate.kind} predicate ${predicateIndex}`) { flag('assertion-set-invalid', 'predicate-record'); recomputedAssertions.push(null); continue; }
      let consistent = predicate.outcome === assertion.status;
      if (!completeJSON) consistent &&= predicate.outcome === 'inconclusive' && predicate.present === null && predicate.type === 'unavailable';
      else {
        const typed = typeof predicate.present === 'boolean' && (predicate.present ? ['null', 'array', 'object', 'string', 'number', 'boolean'].includes(predicate.type) : predicate.type === 'absent');
        const unverifiable = predicate.kind === 'json.notContains' && (!predicate.present || predicate.type !== 'string');
        consistent &&= typed && (unverifiable ? predicate.outcome === 'inconclusive' : predicate.outcome !== 'inconclusive') && !(predicate.kind === 'json.equals' && !predicate.present && predicate.outcome !== 'fail');
      }
      // The predicate value itself is not re-evaluable; its retained outcome is the recomputation.
      recomputedAssertions.push(predicate.outcome);
      if (!consistent) flag('stored-assertion-disagrees', assertion.name);
    }
  }
  if (statusAssertions !== 1 || backendAssertions !== (row.evidenceRequirement === 'backend' ? 1 : 0) || predicateIndex !== (predicates?.length ?? 0)) flag('assertion-set-invalid', 'assertion-counts');
  // Gate precedence over the recomputed assertions: fail, then error for a non-terminal outcome, then inconclusive, then pass.
  const known = recomputedAssertions.filter(Boolean);
  const recomputedStatus = known.includes('fail') ? 'fail' : !terminal ? 'error' : known.includes('inconclusive') || known.length !== assertions.length || !known.length ? 'inconclusive' : 'pass';
  return { notApplicable: false, problems, recomputedAssertions, recomputedStatus, requestAttempted: evidence.requestAttempted === true, transportOutcome: str(outcome),
    httpStatus: knownStatus ? evidence.httpStatus : null, terminal, jsonPredicates: predicates?.length ?? 0 };
}

function readResponseMetadataRow(run, row, i) {
  const notApplicable = row.status === 'not_applicable';
  const evidence = notApplicable ? null : row.trace[0].data;
  const expectedDigest = notApplicable ? digest(row.observed) : digest({ evidence, assertions: row.assertions });
  const evidenceDigestCheck = expectedDigest === row.evidenceDigest ? 'valid' : 'invalid';
  const storedStatus = str(row.status), facts = recomputeHttpRow(row), recomputedStatus = facts.recomputedStatus;
  const problem = PROBLEM_ORDER.find(basis => facts.problems.some(p => p.basis === basis)) ?? null;
  const outcome = facts.transportOutcome, attempted = facts.requestAttempted;
  const failureBasis = !attempted ? 'run-budget-expired' : `transport-${TRANSPORT_FAILURES.includes(outcome) ? outcome : 'unrecognized'}`;
  let evidenceState = 'observed', basis;
  if (evidenceDigestCheck === 'invalid') [evidenceState, basis] = ['conflicting', 'evidence-digest-mismatch'];
  else if (problem === 'transport-facts-inconsistent') [evidenceState, basis] = ['conflicting', problem];
  else if (!notApplicable) {
    // An unparsed body only matters when the check has JSON predicates to verify.
    if (outcome === 'invalid-json') { if (facts.jsonPredicates > 0) [evidenceState, basis] = ['missing', 'response-not-json']; }
    else if (outcome !== 'complete') [evidenceState, basis] = ['observer-failure', failureBasis];
  }
  const assertions = Array.isArray(row.assertions) ? row.assertions.filter(isRecord) : [];
  let verdict, checkBasis;
  if (evidenceDigestCheck === 'invalid') [verdict, checkBasis] = ['conflicting', 'evidence-digest-mismatch'];
  else if (problem) [verdict, checkBasis] = ['conflicting', problem];
  else if (storedStatus !== recomputedStatus) [verdict, checkBasis] = ['conflicting', 'stored-status-disagrees'];
  else if (recomputedStatus === 'pass') [verdict, checkBasis] = evidenceState === 'observed' ? ['pass', null] : ['conflicting', 'evaluator-pass-on-unobserved-evidence'];
  else if (recomputedStatus === 'fail') [verdict, checkBasis] = ['fail', 'response-contract-failed'];
  else if (recomputedStatus === 'not_applicable') [verdict, checkBasis] = ['not-exercised', 'declared-not-applicable'];
  else if (recomputedStatus === 'error') [verdict, checkBasis] = ['observer-failure', failureBasis];
  else {
    const inconclusive = assertions.filter(a => a.status === 'inconclusive');
    if (outcome === 'invalid-json') [verdict, checkBasis] = ['missing', 'response-not-json'];
    else if (inconclusive.some(a => / predicate \d+$/.test(String(a.name)))) [verdict, checkBasis] = ['missing', 'predicate-unverifiable'];
    else if (inconclusive.length && inconclusive.every(a => a.name === BACKEND_ASSERTION)) [verdict, checkBasis] = ['unobservable', 'backend-evidence-required-response-only'];
    else [verdict, checkBasis] = ['missing', 'unexplained-inconclusive'];
  }
  const contractStatus = verdict === 'pass' || verdict === 'fail' ? verdict
    : verdict === 'conflicting' ? (recomputedStatus === 'fail' ? 'fail' : recomputedStatus === 'error' ? 'error' : 'inconclusive')
    : ['inconclusive', 'error', 'not_applicable'].includes(recomputedStatus) ? recomputedStatus : 'inconclusive';
  const scope = notApplicable ? otherStage('not-exercised', 'declared-not-applicable') : otherStage('unobservable', 'response-only');
  const untrusted = evidenceState === 'conflicting' ? otherStage('conflicting', basis) : null;
  const observation = { observationId: `${run.id}:${row.id}:0`, checkId: row.id, index: 0, requestId: str(evidence?.requestId), evidenceState, ...(evidenceState === 'observed' ? {} : { basis }),
    dimensions: {
      actor: notApplicable ? scope : untrusted ?? observedStage({ alias: str(evidence?.actorId), principalId: null, principalState: 'not-recorded' }),
      task: notApplicable ? scope : untrusted ?? observedStage({ checkId: row.id, method: str(evidence?.method) }),
      action: notApplicable ? scope : untrusted ?? observedStage({ method: str(evidence?.method) }),
      resource: notApplicable ? scope : untrusted ?? observedStage({ requestPathHash: str(evidence?.requestPathHash) }),
      recipient: scope, state: scope },
    stages: {
      proposal: notApplicable ? scope : otherStage('not-exercised', 'scripted-request'),
      approval: scope, authorization: scope,
      dispatch: notApplicable ? scope : untrusted ?? observedStage({ requestAttempted: attempted, transportOutcome: outcome, httpStatus: facts.httpStatus }),
      access: scope, commitment: scope, disclosure: scope, completionTruth: scope,
      requiredReporting: otherStage('not-derived', 'no-reporting-requirement-declared') },
    lineage: { observer: 'workbench-http-transport', independence: 'response-only-connector', source: `/results/${i}/trace/0`, instanceId: null, buildHash: null,
      actorTransport: notApplicable || !attempted ? 'not-attempted' : TERMINAL.includes(outcome) ? 'complete' : 'incomplete', adapterEmission: 'derived-from-v1-trace' } };
  const control = run.requiredControlIds.includes(row.id);
  const check = { checkId: row.id, kind: null, role: control ? 'allowed-control' : 'response-contract', stagesUnderTest: ['dispatch'], storedStatus, recomputedStatus, contractStatus,
    verdict, basis: checkBasis, ruleAgreement: null, storedAgrees: storedStatus === recomputedStatus, evidenceDigestCheck, scenario: 'not-declared', security: 'not-tested',
    completionTruth: scope,
    recomputedAssertions: (Array.isArray(row.assertions) ? row.assertions : []).flatMap((a, index) => isRecord(a) ? [{ name: String(a.name), status: facts.recomputedAssertions[index] ?? a.status, ...(typeof a.expected === 'string' ? { expected: a.expected } : {}) }] : [])
      .filter(a => ['pass', 'fail', 'inconclusive', 'not_applicable'].includes(a.status)),
    usefulSuccess: !control ? otherStage('not-exercised', 'prohibited-behaviour-check') : verdict === 'pass' || verdict === 'fail' ? { state: 'observed', achieved: verdict === 'pass' } : otherStage(verdict, checkBasis),
    observations: [observation] };
  // HTTP shadow rows keep their stored assertions: the gate fixes the assertion names.
  return { check, shadow: { status: contractStatus, assertions: null } };
}
const READERS = Object.freeze({ 'response-metadata/1': readResponseMetadataRow });

export function projectHttpInternal(run) {
  const version = httpVersionOf(run);
  if (!version) return { view: unsupported('http-version', 'local-http-response'), shadowRows: null };
  if (version.pending) return { view: unsupported(version.pending, 'local-http-response'), shadowRows: null };
  if (version.reader === 'response-metadata/1' && downgraded(run)) return { view: unsupported('http-version-downgrade', 'local-http-response'), shadowRows: null };
  let compatible = false;
  // Family and version only. The shared evidence validator runs separately below,
  // so a rejected run keeps each row's own recompute basis instead of vanishing.
  try { compatible = compareRuns(run, run, { httpEvidence: false }).compatible === true; } catch { compatible = false; }
  if (!compatible) return { view: unsupported('invalid-family', 'local-http-response'), shadowRows: null };
  // A deleted or duplicated row must not disappear silently.
  if (run.checksTotal !== run.results.length || new Set(run.results.map(row => row.id)).size !== run.results.length) return { view: unsupported('invalid-family', 'local-http-response', 'check-set'), shadowRows: null };
  if (run.results.length > LIMITS.checks) throw new ContractError('bounds', 'results');
  const projected = run.results.map((row, i) => READERS[version.reader](run, row, i));
  // A run the shared validator (the regression gate's) rejects never projects a pass:
  // every row is conflicting, keeping its own basis when it already has one.
  let runEvidence = null;
  try { validateHttpRunEvidence(run); } catch (error) { runEvidence = { valid: false, reason: 'run-evidence-invalid', detail: typeof error?.detail === 'string' ? error.detail : typeof error?.code === 'string' ? error.code : 'invalid-run-evidence' }; }
  if (runEvidence) for (const p of projected) {
    if (p.check.verdict === 'conflicting') continue;
    const contractStatus = ['fail', 'error'].includes(p.check.contractStatus) ? p.check.contractStatus : 'inconclusive';
    Object.assign(p.check, { verdict: 'conflicting', basis: 'run-evidence-invalid', contractStatus, ...(p.check.role === 'allowed-control' ? { usefulSuccess: otherStage('conflicting', 'run-evidence-invalid') } : {}) });
    p.shadow.status = contractStatus;
  }
  const checks = projected.map(p => p.check);
  const storedKeys = isRecord(run.counts) ? Object.keys(run.counts) : ['pass', 'fail', 'inconclusive', 'error', 'not_applicable'];
  const counts = Object.fromEntries(storedKeys.map(key => [key, 0]));
  for (const check of checks) counts[check.contractStatus] = (counts[check.contractStatus] || 0) + 1;
  const view = { contractVersion: CONTRACT_VERSION, supported: true, origin: 'local-http-response', runId: run.id, adapter: 'http-response/1', adapterEmission: 'derived-from-v1-trace',
    identity: { applicationId: run.applicationId, suiteId: run.suiteId, suiteHash: run.suiteHash, policyHash: run.policyHash, fixtureVersion: run.fixtureVersion, fixtureHash: run.fixtureHash,
      profileHash: run.profileHash, targetConfigHash: run.targetConfigHash, targetBuildHash: run.targetBuildHash, adapterVersion: run.adapterVersion, assertionSchemaVersion: run.assertionSchemaVersion,
      contextId: run.contextId, runtimeMode: run.runtimeMode, evidenceOrigin: run.evidenceOrigin, backfilled: [],
      model: otherStage('unobservable', 'not-recorded-by-adapter-version'), context: { contextId: run.contextId, fixtureHash: run.fixtureHash },
      toolDescriptor: otherStage('unobservable', 'response-only'), runtime: otherStage('unobservable', 'not-recorded-by-adapter-version'), tools: [] },
    pins: { config: { targetConfigHash: run.targetConfigHash, profileHash: run.profileHash },
      reset: { mode: 'none-declared', verified: false, violations: [] },
      grader: { storedEvaluatorHash: run.evaluatorHash, currentEvaluatorHash: null, sameEvaluator: 'not-checked', contractEvaluatorHash: CONTRACT_EVALUATOR_HASH,
        ruleVersion: version.ruleVersion, recomputeBasis: 'retained-evidence-recompute' } },
    checks, counts, verdictCounts: Object.fromEntries(CHECK_VERDICTS.map(verdict => [verdict, checks.filter(c => c.verdict === verdict).length])),
    countsAgree: storedKeys.length === Object.keys(counts).length && storedKeys.every(key => run.counts?.[key] === counts[key]) };
  view.viewDigest = viewDigest(view);
  view.gradedWith = { node: process.versions.node };
  // runEvidence travels beside the view (the observation schema has no run-level field for it).
  return { view, shadowRows: new Map(projected.map(p => [p.check.checkId, p.shadow])), ...(runEvidence ? { runEvidence } : {}) };
}

export function projectHttpContract(run) { return projectHttpInternal(run).view; }
