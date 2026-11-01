// Frozen copy of scopehaven/src/http-connector.mjs at ff3a980 (main after the suspend-aware lead-in and stop, F4c, and in-doubt
// resolution IDR-2, before the suspend follow-ups, F4d; imports re-pointed: the frozen suspend-clock-ff3a980.mjs beside it, everything
// else the live src/ and integrations/; its evaluator identity is a fixed marker, never a run identity). For test/suspend-f4d.test.mjs,
// main's side of the differential only. Not in any identity list.
import { request } from 'node:http';
import { randomUUID, randomBytes } from 'node:crypto';
import { lookalikeCredential } from '../../src/lookalike.mjs';
import { readFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { digest } from '../../src/domain.mjs';
import { validateTargetFile, evaluateHttpCheck, contractDigest, targetScopePrefix, targetConfigDigest, ASSERTION_SCHEMA_VERSION, COOKIE_NAME_PATTERN, IDENTITY_ASSERTION, IDENTITY_EVIDENCE_SCHEMA, IDENTITY_REASONS, LOGIN_PROVEN_REASONS, HTTP_EVIDENCE_VERSIONS, HTTP_CHECK_METHODS, HTTP_WRITE_METHODS, MUTATION_EFFECTS, identityControlPlan, identityPlanShape, identityIndexOf, identityReason, rowIdentityReason,
  routeReason, coveringPoints, rowDecision, loginLevel, IDENTITY_UNPROVEN_DECISION, IDENTITY_UNPROVEN_SUMMARY, PRECONDITION_ASSERTION, PRECONDITION_EXPECTED, PRECONDITION_REASONS, readPointer, passedAtSend, recordIdentityProven, IDENTITY_EXPECTED, withheldSummary, statusCodes } from '../../src/contracts.mjs';
// Identity option B (src/http-rests-on.mjs, actor-identity/6): route segments and control-scope evidence on every row, and the release, shared with the validator.
import { routeSegments, captureTypes, controlScopeEvidence, recordClasses, restsOnView, restsOnReleases, failureAdmitted } from '../../src/http-rests-on.mjs';
import { assertRuntime } from '../../src/runtime.mjs';
import { decideEffects, effectAssertionRows, backendObserved, effectTrace, applySettle, settleDeclared, declaredObserverRecord, roleOfSeverity, BACKEND_ASSERTION, EFFECT_ASSERTION_PATTERN, CLAIM_ASSERTION_PATTERN, sealWindows, applyLater, redecideResolved } from '../../src/http-effects.mjs';
// Claim rules (src/http-claims.mjs): read from the response before it is discarded; the records decide them.
import { readClaims } from '../../src/http-claims.mjs';
// Typed captures, the lifecycle phase and run settlement (each a pure module in the evaluator identity below).
import { captureUsesOf, captureOutcome, captureValueDigest, fillCaptures } from '../../src/http-captures.mjs';
import { postChangeIndex, postChangeChecks } from '../../src/http-lifecycle.mjs';
import { settlementFindings, applySettlement, settlementTokens, correlationDeclared, SETTLEMENT_SCHEMA, SETTLEMENT_SCHEMA_CORRELATED } from '../../src/http-settlement.mjs';
// Background attribution (readiness gap 5): declared background sources never decide a clause; applied after settlement.
import { attributionFindings, applyAttribution, attributionRecord, backgroundUnseen } from '../../src/http-attribution.mjs';
// Correlation (run settlement): the header every sent check request carries, and the pairs that record it.
import { correlationHeaderValid, correlationHeaderValue, correlationRecorded } from '../../src/egress-rules.mjs';
// A declared effect horizon and run budget (src/http-timing.mjs): lead-in, horizon, gate, reserve and truncation.
import { TIMING_SCHEMA, RUN_BUDGET_EXHAUSTED, LATE_FAILS, applyHorizon, identityProbeBound, probeBudgetMs, witnessCloseMs } from '../../src/http-timing.mjs';
// Positive-match pairing of absence selectors (src/http-pairing.mjs), applied after settlement.
import { selectorPairs, pairingFindings, applyPairing } from '../../src/http-pairing.mjs';
// Forbidden-value leak detection (src/tenant-values.mjs): compiled once per run; each json.noForeignValues check gets a matcher.
import { FOREIGN_VALUES_KIND, compileTenantValues, matcherFor, tenantValueCounts, numberSourceReviver } from '../../src/tenant-values.mjs';
// The raw body's key tokens (src/body-fields.mjs), so a repeated member name JSON.parse dropped is still counted.
import { countKeyTokens } from '../../src/body-fields.mjs';
// Wording only (outside the evaluator hash): the scope line and limitations.
import { httpScopeText, httpLimitations, AUDIT_FILE_QUIET_DEFAULT_MS, EGRESS_QUIET_DEFAULT_MS } from '../../src/http-scope-text.mjs';
import { collectWindow, unfollowedLate, markUnfollowed } from '../../src/effect-events.mjs';
import { appLogRecords, admissionsFor, applyAdmissions, admissionRows } from '../../src/app-log-verdicts.mjs';
import { followedDrains, drainsDeclared, drainsFeed, drainCapOf } from '../../src/run-end-drain.mjs';
import { signingSecretValueClash, signingRunOf } from '../../src/idempotency.mjs';
import { COLLECTOR_RECORDS, TEMPLATE_LIFT_LABELS, OUTCOME_COLLECTOR_LABELS, LATER_STAGE_LABELS, IN_DOUBT_LABELS } from '../../src/collector-identity.mjs';
import { admitInDoubt } from '../../src/in-doubt.mjs';
import { laterFindings, laterReadings } from '../../src/later-outcome.mjs';
import { laterFeedsOf, PROVIDER_FEED_REQUEST_MS } from '../../src/provider-feed-rules.mjs';
import { beginModelIdentityCapture, finishModelIdentityCapture, releaseModelIdentityCapture, ownedTapConfig } from '../../src/http-model-identity.mjs';
// Suspend-aware custody time (src/suspend-clock.mjs): a check window a host suspend overlapped carries its record, a settle
// wait or lead-in the suspend cut short in awake time is extended, and a run a suspend left short stops (SUSPEND_STOPPED).
import { createSuspendDetector, platformClocks, suspendRecord, applySuspendShort, SUSPEND_STOPPED } from './suspend-clock-ff3a980.mjs';

// v3 adds declared observers and sealed effect windows (http-contract/4).
export const HTTP_ADAPTER_VERSION = 'loopback-response-contract/3';
// Saved HTTP evidence versions (defined with the shared validator in contracts.mjs).
export { HTTP_EVIDENCE_VERSIONS, IDENTITY_EVIDENCE_SCHEMA, IDENTITY_REASONS };
const evaluatorHash = digest('frozen copy of src/http-connector.mjs at ff3a980: a test differential only, never a run identity');
// The HTTP evaluator identity every run records, for consumers that refuse runs from another evaluator (the assessor-pack exporter).
export const HTTP_EVALUATOR_HASH = evaluatorHash;
export const HTTP_LIMITS = Object.freeze({ requestBytes: 8192, responseBytes: 65536, requestTimeoutMs: 3000, runTimeoutMs: 60000 });
// Bearer credentials allow any visible ASCII. A cookie value must also avoid
// the separators that would let it smuggle a second cookie (RFC 6265 cookie-octet).
const BEARER_VALUE = /^[\x21-\x7e]{1,8192}$/, COOKIE_VALUE = /^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]{1,8192}$/;
const credentialFormatValid = (value, cookieName) => typeof value === 'string' && (cookieName === undefined ? BEARER_VALUE : COOKIE_VALUE).test(value);

// Node's HTTP client connects directly to a literal loopback address. No
// redirects, DNS resolution, proxy environment routing or automatic retries.
// correlationHeader: { name, value }, the run's per-request correlation token (src/egress-rules.mjs), on sent checks only.
export function observeHttp(origin, check, { credential, credentialCookie, timeoutMs = HTTP_LIMITS.requestTimeoutMs, maxResponseBytes = HTTP_LIMITS.responseBytes, correlationHeader } = {}) {
  const literal = typeof origin === 'string' && /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/?$/.exec(origin);
  if (!literal || Number(literal[1]) > 65535) throw new Error('Target connection is outside the configured local origin.');
  const base = new URL(origin), url = new URL(check.path, origin);
  if (url.origin !== base.origin || url.username || url.password || url.hash) throw new Error('Target connection is outside the configured local origin.');
  if (!HTTP_CHECK_METHODS.includes(check.method)) throw new Error('Unsupported request method.');
  if (credentialCookie !== undefined && (typeof credentialCookie !== 'string' || !COOKIE_NAME_PATTERN.test(credentialCookie) || credential === undefined)) throw new Error('Credential cookie is missing or has an unsupported name.');
  if (credential !== undefined && !credentialFormatValid(credential, credentialCookie)) throw new Error('Credential is missing or has an unsupported format.');
  if (correlationHeader !== undefined && !(correlationHeaderValid(correlationHeader?.name) && typeof correlationHeader.value === 'string' && /^[0-9a-f-]{32,55}$/.test(correlationHeader.value))) throw new Error('Correlation header is unsupported.');
  const payload = check.body === undefined ? null : JSON.stringify(check.body);
  if (payload && Buffer.byteLength(payload) > HTTP_LIMITS.requestBytes) throw new Error('Request exceeds the local connector limit.');
  return new Promise(resolve => {
    let done = false, status = null, bytes = 0, timer;
    const chunks = [];
    const finish = result => {
      if (done) return; done = true; clearTimeout(timer);
      resolve({ status, complete: false, jsonParsed: false, json: undefined, bytes, ...result });
    };
    const req = request(url, { method: check.method, agent: false, maxHeaderSize: 8192, headers: {
      Accept: 'application/json', Connection: 'close',
      ...(credential === undefined ? {} : credentialCookie === undefined ? { Authorization: `Bearer ${credential}` } : { Cookie: `${credentialCookie}=${credential}` }),
      ...(payload === null ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }),
      ...(correlationHeader === undefined ? {} : { [correlationHeader.name]: correlationHeader.value }),
    } }, res => {
      status = res.statusCode;
      // A redirect is itself a response. Never follow its Location header.
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > maxResponseBytes) { finish({ error: 'too-large' }); res.destroy(); req.destroy(); return; }
        chunks.push(chunk);
      });
      res.on('end', () => {
        if (!res.complete) return finish({ error: 'network' });
        let value, text;
        try { text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)); value = JSON.parse(text); }
        catch { return finish({ complete: true, error: 'invalid-json' }); }
        // repeatedKeys: JSON.parse keeps only the last of a repeated member name, so the raw body's key tokens beyond the
        // parsed tree's keys are the repeats (json.noForeignValues reads a body with any repeat inconclusive). jsonSource: the
        // same tree with each number's source text kept, so json.noForeignValues reads numbers as the body writes them.
        // The reviver recurses, so nesting the plain parse accepts can overflow it: then no source tree (body-unchecked).
        let jsonSource;
        try { jsonSource = JSON.parse(text, numberSourceReviver); } catch { jsonSource = undefined; }
        finish({ complete: true, jsonParsed: true, json: value, jsonSource, repeatedKeys: countKeyTokens(text) - parsedKeyCount(value) });
      });
      res.on('aborted', () => finish({ error: 'network' }));
      res.on('error', () => finish({ error: 'network' }));
    });
    req.on('error', () => finish({ error: 'network' }));
    timer = setTimeout(() => { finish({ error: 'timeout' }); req.destroy(); }, timeoutMs);
    req.end(payload);
  });
}

// The keys of a parsed JSON tree at any depth, without recursion.
function parsedKeyCount(root) {
  let keys = 0;
  const stack = [root];
  while (stack.length) {
    const value = stack.pop();
    if (value === null || typeof value !== 'object') continue;
    const children = Array.isArray(value) ? value : Object.values(value);
    if (!Array.isArray(value)) keys += children.length;
    for (const child of children) stack.push(child);
  }
  return keys;
}

// Actors the run sends requests as: those of applicable checks, and every observer's
// witness actor (audit file, egress recorder, SMTP sink), so a witness is never sent
// anonymously by accident, also when its actor has no check of its own.
const usedActorIds = profile => new Set([...profile.checks.filter(c => c.applicability?.applies !== false).map(c => c.actorId),
  ...(profile.observers ?? []).filter(o => typeof o.witness?.actorId === 'string').map(o => o.witness.actorId)]);
export function credentialReadiness(profile, env = process.env) {
  const usedActors = usedActorIds(profile);
  const used = Object.entries(profile.actors).filter(([alias, actor]) => usedActors.has(alias) && actor.credentialEnv);
  const missing = [...new Set(used.filter(([, actor]) => !credentialFormatValid(env[actor.credentialEnv], actor.credentialCookie)).map(([, actor]) => actor.credentialEnv))];
  return { ready: missing.length === 0, missingCredentialRefs: missing };
}
function resolveCredentials(profile, env) {
  if (!credentialReadiness(profile, env).ready) throw Object.assign(new Error('One or more configured actor credentials are missing or invalid. Check the local profile setup.'), { status: 400 });
  const used = usedActorIds(profile);
  return Object.fromEntries(Object.entries(profile.actors).filter(([alias]) => used.has(alias)).map(([alias, actor]) => [alias, actor.credentialEnv ? env[actor.credentialEnv] : undefined]));
}
// Proving a credentialed actor's login (identity evidence, actor-identity/3).
// Every credentialed actor with an applicable check is judged. Its login is
// proven only by positive evidence: an identity control, meaning a required GET
// control with a 2xx status and a json.equals on the actor's declared
// identityValue. The login is proven when every identity control
//   - passed in the run,
//   - passed again immediately before the actor's first other check and after its
//     last (bracketing all of its other checks, required controls included), and
//   - was refused when sent without a credential, with a random credential of
//     valid format, and with each other judged actor's credential in this
//     actor's slot. A refusal is 401, 403, the declared sign-in redirect, or a
//     complete 2xx JSON response that does not name the actor.
// The actor is established when its login is proven and all of its other
// required controls passed. Only identity controls (GETs) are re-sent; every
// other check, including any POST, PUT, PATCH or DELETE, runs once. Probes share the run budget.
// Statuses and predicate outcomes are recorded, never content or credentials.
// Identity is proven per check (actor-identity/5): the identity and surface controls are re-sent at a
// probe point before the actor's first bracketed check and after each of them, so each check is covered
// by the point before it and the point after it. A point that does not pass withholds only the checks
// it covers, except a probe refused there with the actor's own credential (a surface probe answering 401, 403
// or the declared sign-in redirect, or an identity probe refused as above: one of those statuses, or a complete
// 2xx naming another principal or none), which withholds every check of the actor (contracts.mjs
// rowIdentityReason, shared with the validator). A "who am I" route that does not validate the credential
// the way protected routes do is caught only through a surface control.
// Lifecycle: a changed actor's post-change checks are outside its brackets, so the bracket closes before the change.
// The plan's shape (bracketed checks, controls) comes from contracts.mjs identityPlanShape, which the load-time request bound
// (requestPlan) counts, so the bound and the run plan cannot drift apart.
function planIdentity(profile) {
  const plans = new Map();
  for (const shape of identityPlanShape(profile)) {
    const { others } = shape;
    plans.set(shape.actorId, { ...shape, first: others.length ? others[0] : -1, last: others.length ? others.at(-1) : -1,
      before: [], between: [], after: [], anonymous: [], invalid: [], cross: [] });
  }
  return plans;
}
// A traceparent parent id: 16 random hex characters, never all zero (W3C Trace Context).
const spanId = () => { const hex = randomBytes(8).toString('hex'); return /^0+$/.test(hex) ? '0000000000000001' : hex; };
// The invalid credential's look-alike lives in ./lookalike.mjs (in both the HTTP and conversation identity sets).
export { lookalikeCredential };
function identityProbe(profile, { credentials, transport, limits, deadline, requestBudget, clock, contextFor }) {
  // The invalid credential: a per-run random look-alike of each actor's own credential,
  // never a real one and with no fixed marker a target could recognise.
  const lookalikes = new Map(), secret = randomBytes(32);
  const invalidCredentialFor = actorId => {
    if (!lookalikes.has(actorId)) lookalikes.set(actorId, lookalikeCredential(credentials[actorId] ?? '', secret, actorId));
    return lookalikes.get(actorId);
  };
  return async (plan, check, kind, crossActorId) => {
    const identity = identityIndexOf(check, plan.actor.identityValue);
    const kinds = check.assertions.filter(a => a.kind.startsWith('json.')).map(a => a.kind);
    const base = { controlId: check.id, kind, ...(kind === 'cross' ? { crossActorId } : {}) };
    const remaining = deadline - clock.now();
    if (remaining <= 0) return { ...base, requestAttempted: false, requestTimeoutMs: 0, httpStatus: null, transportOutcome: 'timeout', statusOutcome: 'inconclusive', predicates: kinds.map((k, i) => ({ kind: k, outcome: 'inconclusive', identity: i === identity })), outcome: 'error' };
    const appliedTimeoutMs = Math.max(1, Math.round(Math.min(requestBudget(check), remaining)));
    const credential = kind === 'anonymous' ? undefined : kind === 'invalid' ? invalidCredentialFor(plan.actorId) : kind === 'cross' ? credentials[crossActorId] : credentials[plan.actorId];
    let observation;
    try { observation = await transport(profile.origin, check, { credential, credentialCookie: credential === undefined ? undefined : plan.actor.credentialCookie, timeoutMs: appliedTimeoutMs, maxResponseBytes: limits.responseBytes }); }
    catch { observation = { status: null, complete: false, jsonParsed: false, json: undefined, bytes: 0, error: 'network' }; }
    const evaluated = evaluateHttpCheck(check, observation, contextFor(check, check)), known = Number.isInteger(observation.status) && observation.status >= 100 && observation.status <= 599;
    return { ...base, requestAttempted: true, requestTimeoutMs: appliedTimeoutMs, httpStatus: known ? observation.status : null, transportOutcome: observation.error || 'complete',
      statusOutcome: evaluated.assertions.find(a => a.name === 'HTTP status matches contract').status,
      predicates: evaluated.observed.predicates.map((predicate, i) => ({ kind: predicate.kind, outcome: predicate.outcome, identity: i === identity })), outcome: evaluated.status };
  };
}
// The inputs of an actor's identity reason, read from its plan and the rows as they stand.
const identityInputs = (plan, results) => {
  const status = id => results.find(row => row.id === id)?.status;
  return { ...plan, between: plan.between.flatMap(point => point.probes), identityControlsPassed: plan.identityControls.every(id => status(id) === 'pass'), requiredPassed: plan.required.every(id => status(id) === 'pass') };
};
// lifecycle: actorId -> { changeCheckId, after, changeConfirmed, changerLoginProven, postChangeCheckIds } for changed actors.
function identityEvidenceOf(plans, results, lifecycle = new Map()) {
  return { schema: IDENTITY_EVIDENCE_SCHEMA, actors: [...plans.values()].map(plan => {
    const reason = identityReason(identityInputs(plan, results));
    return { actorId: plan.actorId, credentialMode: plan.actor.credentialCookie ? 'cookie' : 'bearer', requiredControlIds: plan.required, identityControlIds: plan.identityControls,
      surfaceControlIds: plan.surfaceControls, refusesWith401: plan.refusesWith401, refusalStatuses: plan.refusalStatuses, before: plan.before, between: plan.between, after: plan.after, anonymous: plan.anonymous, invalid: plan.invalid, cross: plan.cross,
      reason, loginProven: LOGIN_PROVEN_REASONS.includes(reason), established: reason === 'established', ...(lifecycle.has(plan.actorId) ? { lifecycle: lifecycle.get(plan.actorId) } : {}) };
  }) };
}
// The per-check identity judge (actor-identity/6, rule in contracts.mjs rowIdentityReason): a row's reason, from its
// actor's route proof, the two probe points that cover it, for a post-change row the attribution of its change, and for a
// check that declares restsOn the release of identity option B (src/http-rests-on.mjs), read from the rows as they stand
// (before the identity assertion), as the validator reads them. windowsById: each observed row's own check windows, as its
// decisions read them. judge.failedControlsOf(actorId) names the actor's required controls that did not pass.
function identityJudge(profile, results, identity, plans, postChange = new Map(), windowsById = new Map()) {
  const byId = new Map(profile.checks.map(check => [check.id, check]));
  const controlFailed = new Set(profile.requiredControlIds.filter(id => results.find(row => row.id === id)?.status !== 'pass').map(id => byId.get(id).actorId));
  const entries = new Map(identity.actors.map(entry => [entry.actorId, entry]));
  const routes = new Map([...plans.values()].map(plan => [plan.actorId, routeReason(identityInputs(plan, results))]));
  const bracketedIds = new Map([...plans.values()].map(plan => [plan.actorId, plan.others.map(index => profile.checks[index].id)]));
  const argsOf = (row, released) => {
    const check = byId.get(row.id), entry = entries.get(check.actorId);
    return { credentialed: Boolean(profile.actors[check.actorId].credentialEnv), required: profile.requiredControlIds.includes(check.id), control: check.severity === 'control',
      entry, httpStatus: row.trace[0].data.httpStatus, controlFailed: controlFailed.has(check.actorId), postChange: postChange.has(check.id), rules: 6,
      route: routes.get(check.actorId) ?? null, points: entry ? coveringPoints(entry, bracketedIds.get(check.actorId), row.id) : null, changerUnproven: postChange.has(check.id) && entry?.lifecycle?.changerLoginProven === false, released };
  };
  const principals = Object.fromEntries(Object.entries(profile.actors).map(([alias, actor]) => [alias, actor.principalId]));
  const released = restsOnReleases(restsOnView(results, { required: profile.requiredControlIds, failed: row => row.status !== 'pass', identityProven: row => recordIdentityProven(argsOf(row, false)),
    refusalStatusesOf: actor => entries.get(actor)?.refusalStatuses ?? [401, 403], codesOf: label => statusCodes(label, true), principals, credentialed: actor => Boolean(profile.actors[actor]?.credentialEnv),
    admitted: row => failureAdmitted(row, windowsById.get(row.id) ?? null, principals[row.trace[0].data.actorId]) }));
  const judge = row => rowIdentityReason(argsOf(row, released.has(row.id)));
  // Read once, before establishActorIdentity turns any row inconclusive, as the validator reads them (before the identity assertion).
  const failedControls = profile.requiredControlIds.filter(id => results.find(row => row.id === id)?.status !== 'pass');
  judge.failedControlsOf = actorId => failedControls.filter(id => byId.get(id).actorId === actorId);
  return judge;
}
// Rows whose identity was not proven for them carry an inconclusive identity assertion, so a refusal seen while the
// login did not work can never pass. A boundary row whose own predicates and effects passed becomes the distinct
// state "prohibition observed, identity or allowed use not established" (its decision); every other row's decision is its status.
// Failures stay failures, errors stay errors, not-applicable rows are untouched.
function establishActorIdentity(results, judge) {
  for (const row of results) {
    if (row.status === 'not_applicable') continue;
    const reason = judge(row), third = rowDecision(row, reason) === IDENTITY_UNPROVEN_DECISION;
    if (!reason) { row.decision = row.status; continue; }
    row.assertions.push({ name: IDENTITY_ASSERTION, status: 'inconclusive', expected: IDENTITY_EXPECTED, actual: IDENTITY_REASONS[reason] });
    // The summary names the reason that fired (for control-not-passed, the controls), never a lost login for another reason.
    if (row.status === 'pass') { row.status = 'inconclusive'; row.summary = withheldSummary(reason, judge.failedControlsOf?.(row.trace[0].data.actorId) ?? [], third); }
    row.decision = third ? IDENTITY_UNPROVEN_DECISION : row.status;
    row.evidenceDigest = sealDigest(row);
  }
}
// A row's evidence digest covers its response evidence, its sealed effect windows (if any) and its assertions.
const sealDigest = row => digest(row.trace.length === 2 ? { evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions } : { evidence: row.trace[0].data, assertions: row.assertions });
const EFFECT_SUMMARIES = Object.freeze({ fail: 'A response predicate or an observed effect failed.', error: 'The response observation could not be completed.', inconclusive: 'A response predicate or an observed effect could not be decided.', pass: 'Response predicates and observed effects passed.' });
const precondition = reason => ({ name: PRECONDITION_ASSERTION, status: 'inconclusive', expected: PRECONDITION_EXPECTED, actual: PRECONDITION_REASONS[reason] });
// actor-identity/6 (src/http-rests-on.mjs): a row's route segments (keyed digests, with the profile's capture types), its
// controlScope (read before the body is discarded) and, for a check that declares restsOn, the ids.
const routeEvidence = (check, observation, sentPath, { routeKey, routeTypes, recordRanks }) => ({ routeSegments: routeSegments(check.path, routeKey, routeTypes),
  controlScope: controlScopeEvidence(check, observation, sentPath, routeKey, recordRanks), ...(check.restsOn ? { restsOn: check.restsOn } : {}) });
// A check whose precondition did not hold is not sent (src/http-captures.mjs, src/http-lifecycle.mjs): no request,
// no effect window, and an inconclusive row naming why. Its captures, if it declares any, are unavailable.
function notSentRow(profile, check, { requestId, reason, uses, routeKey, routeTypes, recordRanks }) {
  const actor = profile.actors[check.actorId];
  const evaluated = evaluateHttpCheck(check, { status: null, complete: false, jsonParsed: false, json: undefined, bytes: 0, error: 'not-sent' });
  const assertions = [...evaluated.assertions, precondition(reason)];
  const evidence = { requestId, actorId: check.actorId, method: check.method, requestPathHash: digest(check.path), ...routeEvidence(check, null, null, { routeKey, routeTypes, recordRanks }),
    credentialMode: !actor.credentialEnv ? 'none' : actor.credentialCookie ? 'cookie' : 'bearer', requestTimeoutMs: 0,
    httpStatus: null, responseComplete: false, responseBytes: 0, jsonParsed: false, transportOutcome: 'not-sent', backendEvidence: 'unavailable',
    requestAttempted: false, mutationEffects: HTTP_WRITE_METHODS.includes(check.method) ? MUTATION_EFFECTS.write : MUTATION_EFFECTS.read, notSent: reason, ...(uses.length ? { captureUses: uses } : {}),
    ...(check.capture ? { captures: Object.entries(check.capture).map(([name, spec]) => ({ name, type: spec.type, createdBy: check.actorId, outcome: 'response-unavailable', valueDigest: null })) } : {}) };
  // A declared run budget that could not hold the check (src/http-timing.mjs), or a run a host suspend stopped (src/suspend-clock.mjs),
  // is named apart from a precondition.
  const budget = reason === RUN_BUDGET_EXHAUSTED, stopped = reason === SUSPEND_STOPPED;
  return { id: check.id, title: check.title, category: check.category, severity: check.severity, status: 'inconclusive',
    summary: budget ? 'Not sent: the declared run budget could not hold this check, so it was not decided.' : stopped ? 'Not sent: a host sleep left an earlier check\'s wait short of its declared awake time, so the run stopped and this check was not decided.' : 'Not sent: a declared precondition did not hold, so this check was not decided.',
    assertions, observed: evaluated.observed, evidenceRequirement: check.evidenceRequirement, expected: 'A request sent once its declared preconditions hold.', backendEvidence: 'unavailable',
    trace: [{ type: 'http-observation', label: budget ? 'No request sent: the declared run budget could not hold this check' : stopped ? 'No request sent: the run stopped after a host sleep' : 'No request sent: a declared precondition did not hold', data: evidence }],
    remediation: budget ? { title: 'Review the declared run budget', why: 'A check that was not sent decides nothing.', steps: ['Raise "timing.runBudgetMs", or lower the effect horizon or the number of checks in one run.', 'Retest the unchanged contract.'], codePointers: ['Local target profile', `Check ${check.id}`] }
      : stopped ? { title: 'Rerun on a host that stays awake', why: 'A check that was not sent decides nothing.', steps: ['Keep the host awake for the whole run, or declare a timing plan whose budget leaves room to extend a wait a sleep cut short.', 'Retest the unchanged contract.'], codePointers: ['Local target profile', `Check ${check.id}`] }
      : { title: 'Review the declared precondition', why: 'A check that was not sent decides nothing.', steps: ['Check that the creating check returns the captured value, or that the declared account change passes.', 'Retest the unchanged contract.'], codePointers: ['Local target profile', `Check ${check.id}`] },
    durationMs: 0, evidenceDigest: digest({ evidence, assertions }) };
}
// Settlement, attribution and pairing findings change a row's effect clauses (src/http-settlement.mjs,
// src/http-attribution.mjs, src/http-pairing.mjs): reseal its assertions, trace, status and digest.
// admission: the row's app-log admissions (src/app-log-verdicts.mjs), applied last; an admitted clause is not authoritative, so
// the backend row is decided again then.
// later: the row's later-outcome findings (src/later-outcome.mjs), applied after admissions (only to a clause that still passes), and the
// backend row decided again when any applies (a clause judged again carries its own authoritative reading).
function resealEffects({ row, decisions, windows, role, appLogWindows = null, backendRow = null }, { settlement, attribution, pairing, admission = null, later = null }, observerMeta) {
  const paired = applyPairing(applyAttribution(applySettlement(decisions, settlement, role), attribution, role), pairing, role);
  const settled = applyLater(applyAdmissions(paired, admission), later), rows = effectAssertionRows(settled);
  let n = 0;
  row.assertions = row.assertions.map(a => EFFECT_ASSERTION_PATTERN.test(a.name) || CLAIM_ASSERTION_PATTERN.test(a.name) ? rows[n++] : a);
  if (admission?.some(a => a !== null) || later?.some(f => f !== null)) {
    const backend = backendObserved(settled);
    row.backendEvidence = backend ? 'observed' : 'unavailable';
    row.assertions = row.assertions.map(a => a.name === BACKEND_ASSERTION && backendRow ? (backend ? { ...backendRow, status: 'pass', actual: 'Authoritative observers decided every declared effect' } : backendRow) : a);
  }
  row.trace[1] = effectTrace(settled, windows, observerMeta, appLogWindows);
  const terminal = ['complete', 'invalid-json'].includes(row.trace[0].data.transportOutcome);
  row.status = row.assertions.some(a => a.status === 'fail') ? 'fail' : !terminal ? 'error' : row.assertions.some(a => a.status === 'inconclusive') ? 'inconclusive' : 'pass';
  row.summary = EFFECT_SUMMARIES[row.status];
  row.evidenceDigest = sealDigest(row);
}
// Observers are started once per run. A failing observer never stops the run:
// its windows read failed, which can never support a pass.
async function startObservers(configs, env, factory, watchedResources = []) {
  let built;
  try { built = factory(configs, { env, watchedResources }); } catch (error) { throw Object.assign(new Error(`Declared observers could not be created: ${error.message}`), { status: 400 }); }
  return Promise.all(built.map(async o => {
    let started = true;
    try { await o.start(); } catch { started = false; }
    return { kind: o.kind, instanceId: o.instanceId, source: o.source, scope: o.scope, started, stop: () => o.stop(), witnessRequest: o.witnessRequest ?? null,
      // Feed v2, Part C: a provider feed whose lone late entries may lift a template-pinned allow: the feed says so and this build's feed
      // collector reads a lift label (provider-feed/4). The run record's label is written from this one flag (runHttpAssessment).
      templateLift: o.source === 'provider-feed' && o.templateLift === true && TEMPLATE_LIFT_LABELS.includes(COLLECTOR_RECORDS['provider-feed']?.label),
      // Later outcomes (provider-feed/5): a provider feed whose code reads outcome entries, on a build whose feed collector says so. The run
      // record's label is written from this flag too, so a feed that cannot read them is never recorded as one that did.
      laterOutcomes: o.source === 'provider-feed' && o.laterOutcomes === true && OUTCOME_COLLECTOR_LABELS.includes(COLLECTOR_RECORDS['provider-feed']?.label),
      laterWait: async capMs => { if (!started || typeof o.laterWait !== 'function') return 0; try { return (await o.laterWait({ capMs }))?.waitedMs ?? 0; } catch { return 0; } },
      laterRecords: mark => { if (!started || mark === null || typeof o.laterRecords !== 'function') return null; try { return o.laterRecords(mark); } catch { return null; } },
      // In-doubt resolution, the run-end stage (IDR-2): a later resolver's records for this observer's sends, read at the final mark, as
      // { seq, records } items. No observer in this build has a later resolver (IDR-3 read-back and IDR-4 request feed add theirs), and
      // src/in-doubt.mjs binds no record without one; a read that fails or returns anything else reads no record.
      resolutionRecords: async mark => {
        if (!started || mark === null || typeof o.resolutionRecords !== 'function') return [];
        try { const list = await o.resolutionRecords(mark); return Array.isArray(list) ? list : []; } catch { return []; }
      },
      // Awaited before the witness request is sent, and said so ({ headSplit: true }): a provider feed reads its signed head
      // here to split the window without a clock (the sinks' is synchronous and ignores the option).
      markWitnessRequest: async from => { try { await o.markWitnessRequest?.(from, { headSplit: true }); } catch {} },
      mark: async () => { if (!started) return null; try { return await o.mark(); } catch { return null; } },
      collect: async (from, to, options) => { if (!from || !to) throw new Error('observer-not-marked'); return o.collect.call(o, from, to, options); },
      // Coverage v2 Part D (egress recorders only): the run-end drain, its own cap, and the final mark's clear state.
      ...(typeof o.drain === 'function' ? { drain: async capMs => { if (!started) return null; try { return await o.drain({ capMs }); } catch { return null; } },
        drainCapMs: () => { try { return o.drainCapMs(); } catch { return 0; } }, markClear: mark => { try { return mark !== null && o.markClear(mark) === true; } catch { return false; } },
        closedAfterCollect: () => { try { return o.closedAfterCollect() !== false; } catch { return true; } } } : {}),
      // Verified signature headers (egress recorders only): which declared secret slots were usable, booleans only.
      signingRecord: () => { try { return typeof o.signingRecord === 'function' ? o.signingRecord() : null; } catch { return null; } } };
  }));
}
// clock: the run's own time (now, and sleep for every wait); tests inject a virtual one.
const SYSTEM_CLOCK = Object.freeze({ now: () => performance.now(), sleep: ms => new Promise(resolve => setTimeout(resolve, ms)) });
// suspendClock: the host suspend detector (src/suspend-clock.mjs) over this platform's clocks. A run on an injected clock (virtual
// time) waits on no host timer, so no host suspend applies to it: its default detector reads no clock. Tests inject one over fake clocks.
export async function runHttpAssessment(input, { env = process.env, transport = observeHttp, limits = HTTP_LIMITS, observerFactory, modelTap, modelTapLog = env.SCOPEHAVEN_MODEL_TAP_LOG, modelTapOwned = ownedTapConfig(env), clock = SYSTEM_CLOCK,
  suspendClock = createSuspendDetector(clock === SYSTEM_CLOCK ? platformClocks() : { awake: null, elapsed: null }) } = {}) {
  assertRuntime();
  const profile = validateTargetFile({ schemaVersion: 1, targets: [input] })[0];
  const modelCapture = await beginModelIdentityCapture({ path: modelTapLog, tap: modelTap, owned: modelTapOwned });
  try { // An owned model tap never outlives the run, including a run that throws.
  const credentials = resolveCredentials(profile, env); // Fail before any request; never silently become anonymous.
  // A declared per-check timeout (model-turn endpoints) extends the run budget
  // by exactly its extra time, so ordinary checks keep the default limits.
  const requestBudget = check => check.timeoutMs ?? limits.requestTimeoutMs;
  // A check is observed when it declares effects or claim rules.
  const observed = check => Boolean(check.effects || check.claims);
  // Per-check settlement (src/http-settlement.mjs) adds one drain barrier, the largest declared settle, after each observed check.
  const correlation = profile.correlation ?? null, perCheck = profile.settlement?.mode === 'per-check';
  // Judged late effects (src/http-settlement.mjs): the declaration relaxes the effect.only settlement rule, and only for it.
  const judgeLate = profile.settlement?.outsideWindow === 'judge';
  const barrierMs = perCheck ? Math.max(0, ...(profile.observers ?? []).map(o => settleDeclared(o.settleMs) ? o.settleMs : 0)) : 0;
  // A declared run budget (src/http-timing.mjs) replaces the computed one: its plan already counts the extra timeouts and barriers.
  const timing = profile.timing ?? null;
  const runBudgetMs = timing ? timing.runBudgetMs : limits.runTimeoutMs + profile.checks.filter(c => c.applicability?.applies !== false).reduce((extra, c) => extra + Math.max(0, requestBudget(c) - limits.requestTimeoutMs) + (observed(c) ? barrierMs : 0), 0);
  const started = clock.now(), results = [], deadline = started + runBudgetMs;
  // The suspend detector's first sample: its first pair then spans the run's start, so an awake clock that moves there is known to be
  // alive before any wait (src/suspend-clock.mjs, a pair a live clock read no movement over).
  suspendClock.sample();
  // Under timing every request the run sends (checks, probes, witnesses) records when it ended, on the run clock and as a suspend
  // detector mark (the lead-in, held in awake time), and every identity probe is counted against its bound (the probe reserve).
  let lastRequestEnd = -Infinity, lastRequestMark = null, probesSent = 0;
  if (timing) { const send = transport; transport = async (...args) => { try { return await send(...args); } finally { lastRequestEnd = clock.now(); lastRequestMark = suspendClock.mark(); } }; }
  // json.noForeignValues: the check actor's tenant and the request actually sent (its own values are echoes, not leaks).
  const tenantValues = Object.hasOwn(profile, 'tenantValues') ? compileTenantValues(profile.tenantValues) : null;
  const contextFor = (check, sent) => tenantValues && check.assertions.some(a => a.kind === FOREIGN_VALUES_KIND) ? { foreignValues: matcherFor(tenantValues, profile.actors[check.actorId].tenantId, sent) } : {};
  const plans = planIdentity(profile), sendProbe = identityProbe(profile, { credentials, transport, limits, deadline, requestBudget, clock, contextFor });
  const probe = timing ? (...args) => { probesSent++; return sendProbe(...args); } : sendProbe;
  const control = id => profile.checks.find(c => c.id === id);
  // Lifecycle (src/http-lifecycle.mjs): the post-change checks, and the change checks before which every probe
  // that carries a changed actor's credential, or tests its slot, completes. Each probe runs once.
  const postChange = postChangeIndex(profile), changeAt = new Map(), changeConfirmed = new Map();
  for (const entry of profile.lifecycle ?? []) changeAt.set(entry.changeCheckId, [...(changeAt.get(entry.changeCheckId) ?? []), entry]);
  const probes = new Map(), judged = [...plans.keys()].sort();
  const probeOnce = async (plan, id, kind, other) => { const key = `${plan.actorId}|${id}|${kind}|${other ?? ''}`; if (!probes.has(key)) probes.set(key, await probe(plan, control(id), kind, other)); return probes.get(key); };
  const proveBeforeChange = async actorId => {
    for (const plan of plans.values()) for (const id of plan.identityControls) {
      if (plan.actorId === actorId) { await probeOnce(plan, id, 'anonymous'); await probeOnce(plan, id, 'invalid'); for (const other of judged.filter(a => a !== actorId)) await probeOnce(plan, id, 'cross', other); }
      else if (plans.has(actorId)) await probeOnce(plan, id, 'cross', actorId);
    }
  };
  // Typed captures (src/http-captures.mjs): values by name for this run only; their digests use a key the run does not keep.
  const captured = new Map(), captureKey = randomBytes(32).toString('hex');
  // Route segments and control-scope evidence (src/http-rests-on.mjs): digests keyed with a secret the run does not keep.
  const routing = { routeKey: randomBytes(32).toString('hex'), routeTypes: captureTypes(profile), recordRanks: recordClasses(profile) };
  const recordCaptures = (check, entries) => { for (const e of entries) captured.set(e.name, { type: e.type, createdBy: e.createdBy, captureCheckId: check.id, outcome: e.outcome, valueDigest: e.valueDigest, value: e.value }); };
  // The observer modules load only when a profile declares observers.
  // The rows checks name (resource selectors): snapshot observers claim absence only about rows they saw at both marks.
  const watchedResources = [...new Set(profile.checks.flatMap(c => [...(c.effects ?? []), ...(c.claims ?? [])]).map(e => e.select?.resource).filter(r => typeof r === 'string'))];
  // A signing secret that is also a forward proof secret, under any two names and in any recorder (src/idempotency.mjs): refused
  // before any observer starts. The values are compared and dropped; nothing is kept.
  const signingClash = Object.hasOwn(profile, 'observers') ? signingSecretValueClash(profile.observers, env) : null;
  if (signingClash) throw Object.assign(new Error(`Declared observers could not be created: ${signingClash}`), { status: 400 });
  const observers = Object.hasOwn(profile, 'observers') ? await startObservers(profile.observers, env, observerFactory ?? (await import('../../integrations/observers/factory.mjs')).buildObservers, watchedResources) : [];
  // Each built observer keeps its declared settle (observers are built in profile order).
  const declared = Object.hasOwn(profile, 'observers') ? declaredObserverRecord(profile.observers) : [];
  // Feed v2, Part C: one source for the template lift. A provider feed that did not take it (an injected one, or a build without it)
  // is recorded under provider-feed/3, the semantics the validator then applies, so the connector and the validator cannot disagree.
  declared.forEach((d, i) => { if (d.type === 'provider-feed' && d.collector && observers[i]?.templateLift !== true) d.collector = { ...d.collector, label: 'provider-feed/3' }; });
  // Later outcomes: one source for the label as well. A lift-capable feed that cannot read outcome entries is recorded under provider-feed/4.
  declared.forEach((d, i) => { if (d.type === 'provider-feed' && OUTCOME_COLLECTOR_LABELS.includes(d.collector?.label) && observers[i]?.laterOutcomes !== true) d.collector = { ...d.collector, label: 'provider-feed/4' }; });
  // Verified signature headers: per declared signing destination, which secret slots the recorder could use (src/idempotency.mjs).
  const signingRun = signingRunOf(declared, observers.map(o => o.signingRecord?.() ?? null));
  // App logs (src/app-log-rules.mjs): the application's own action log, read apart from the observers. Their marks are small
  // local file reads taken after the custody start marks and before any witness request, and they are read after every custody
  // collect, so they add no request or wait to any custody window; their windows are sealed as data.appLogWindows, and with
  // "use": "admission" they are read against the application after every custody rule (src/app-log-verdicts.mjs): fails only.
  const appLogs = Object.hasOwn(profile, 'appLogs') ? await (await import('../../integrations/observers/app-log.mjs')).startAppLogs(profile) : null;
  const observerMeta = new Map(observers.map((o, i) => [o.instanceId, { kind: o.kind, settleMs: declared[i].settleMs }]));
  const settleMs = Math.max(0, ...declared.map(o => o.settleMs ?? 0));
  // The witness: the test's own request, logged by the app after the check's effects. Its outcome is
  // not evidence; a witness that fails or is not logged leaves the window partial.
  const sendWitness = async (w, nonce) => {
    if (typeof nonce !== 'string') return;
    const remaining = runBudgetMs - (clock.now() - started);
    if (remaining <= 0) return;
    const path = `${w.path}${w.path.includes('?') ? '&' : '?'}scopehaven_witness=${encodeURIComponent(nonce)}`;
    try { await transport(profile.origin, { method: 'GET', path }, { credential: credentials[w.actorId], credentialCookie: credentials[w.actorId] === undefined ? undefined : profile.actors[w.actorId].credentialCookie, timeoutMs: Math.max(1, Math.round(Math.min(limits.requestTimeoutMs, remaining))), maxResponseBytes: limits.responseBytes }); } catch {}
  };
  // Settlement (src/http-settlement.mjs): with checks that declare effects, every observer is marked before the first
  // check; gap windows run from each effect window to the next and, after the final mark, the tail.
  const settling = profile.checks.some(c => observed(c) && c.applicability?.applies !== false);
  const gapMarks = [], effectRows = [], barrierMarks = [];
  let lastEnd = null, settlement = null;
  // Timing (src/http-timing.mjs). Every wait ends by the wait deadline, which keeps the final settle and the identity
  // probes still to send (each at most the longest probe budget) inside the run budget.
  const H = timing?.effectHorizonMs ?? 0, closeMs = timing ? witnessCloseMs(profile.observers ?? [], profile.actors, limits.requestTimeoutMs) : 0;
  const probeSends = timing ? identityProbeBound(profile, identityControlPlan(profile)) : 0, probeMs = timing ? probeBudgetMs(profile, identityControlPlan(profile), limits.requestTimeoutMs) : 0;
  const probeReserve = () => Math.max(0, probeSends - probesSent) * probeMs;
  const waitUntil = () => deadline - (settling ? settleMs : 0) - probeReserve();
  const leadIn = () => Math.max(0, Math.ceil(lastRequestEnd + H - clock.now()));
  // A wait never ends early (a timer that fires early sleeps again) and never past `until`; it returns the time it was allowed.
  const waitClipped = async (ms, until) => {
    // A wait that cannot be computed never reads as held: the run stops instead.
    if (!Number.isFinite(ms) || !Number.isFinite(until)) throw new Error('The declared run budget could not be applied to a wait.');
    const allowed = Math.max(0, Math.min(ms, Math.floor(until - clock.now()))), end = clock.now() + allowed;
    while (clock.now() < end) await clock.sleep(end - clock.now());
    return allowed;
  };
  // The time the end-of-run identity probes still to send need (under timing they were sent before the final settle): kept in hand by
  // every run-end wait, and by every settle extension.
  const endProbeReserveMs = () => (timing ? 0 : [...plans.values()].reduce((n, plan) => n + plan.identityControls.reduce((m, id) => m + [['anonymous'], ['invalid'], ...judged.filter(a => a !== plan.actorId).map(a => ['cross', a])]
    .filter(([kind, other]) => !probes.has(`${plan.actorId}|${id}|${kind}|${other ?? ''}`)).length, 0), 0)) * probeBudgetMs(profile, identityControlPlan(profile), limits.requestTimeoutMs);
  // Without a declared timing plan, a settle or barrier extension after the check at `index` never runs past the run deadline, and it
  // keeps in hand the final settle, the end-of-run identity probes, and each later applicable check's request budget and, for an
  // observed check, its settle and barrier. It does not reserve the witness round trips, the bracket and lifecycle identity probes, the
  // run-end drain or the later-outcome wait: one of those squeezed reads as it does when the budget runs short (a witness not sent
  // leaves its window partial, a probe not sent reads error, a drain with no time follows nothing), never as a pass. So without a
  // plan an extension uses only spare budget (docs/KNOWN-LIMITS.md).
  const laterNeedMs = index => profile.checks.slice(index + 1).filter(c => c.applicability?.applies !== false).reduce((n, c) => n + requestBudget(c) + (observed(c) ? settleMs + barrierMs : 0), 0);
  const extensionUntil = index => waitUntil() - endProbeReserveMs() - laterNeedMs(index);
  // Suspend-aware settle (src/suspend-clock.mjs). Where the run's timers count sleep (macOS: libuv reads mach_continuous_time), a
  // settle wait a host suspend overlapped ends with less awake time than it asked for, so the application had less time to act. The
  // wait (begun at mark `since`) is extended by the awake time it lost: at most its own length more, and never past `until` (under a
  // declared timing plan the bound the wait itself had; otherwise extensionUntil, or for the final settle the run deadline less the
  // end-of-run identity probes). It only ever waits longer, and without a suspend it returns at once. Returns the awake time the wait
  // is still owed when the extension runs out of room (0 when it was restored): its shortfall, from the extension's own count, so a
  // shortfall is never an artefact of the awake clock's resolution. A wait with a shortfall did not hold its declared awake time, and
  // its windows read partial (sealed as the awake time held under a timing plan, as the record's shortMs without one).
  const extendAwake = async (since, ms, until) => holdOwed(Math.min(ms, suspendClock.lostSince(since)), until);
  // Hold `owedMs` more awake time, never past `until`, in steps on the run clock. A step a suspend overlapped held less awake time
  // than it waited, so what that suspend took from it (at most the step) is owed again: a second sleep inside the extension can
  // never leave a wait short unseen. Returns what is still owed when the room runs out (0 once held).
  const holdOwed = async (owedMs, until) => {
    let owed = owedMs;
    while (true) {
      const step = Math.min(Math.ceil(owed), Math.floor(until - clock.now()));
      if (!(step >= 1)) return owed > 0 ? Math.ceil(owed) : 0;
      const at = suspendClock.mark(), end = clock.now() + step;
      while (clock.now() < end) await clock.sleep(end - clock.now());
      owed -= step - Math.min(step, suspendClock.lostSince(at));
    }
  };
  // The lead-in in awake time (PR343-REVIEW finding 1a): H must have passed since the end of the last request in the application's
  // own time, which a host sleep stops, not only on the run clock, which counts it. What it is still owed once the run clock has
  // waited it out: the time suspended since that request ended, less what the run clock waited past H; at most H, and 0 when no
  // suspend was seen (an inert detector waits exactly as before).
  const leadInOwed = () => {
    if (lastRequestMark === null) return 0;
    const lost = suspendClock.lostSince(lastRequestMark);
    return lost > 0 ? Math.min(H, Math.max(0, Math.ceil(lost - Math.max(0, clock.now() - lastRequestEnd - H)))) : 0;
  };
  // The gate: a check is sent only when its request and, if observed, its lead-in, horizon, witness close and barrier fit
  // before the wait deadline; an observed check then waits out its lead-in. A lead-in a host suspend left short is extended by the
  // awake time it is owed, keeping the check's own request, horizon, witness close and barrier before the wait deadline; one still
  // short is clipped as a lead-in the budget clipped (not admitted: the check and every later one are cut), never merely marked
  // partial, because an earlier request's send could then land in this check's window and decide it.
  const admit = async check => {
    if (clock.now() + requestBudget(check) + (observed(check) ? leadIn() + H + closeMs + barrierMs : 0) > waitUntil()) return false;
    if (!observed(check)) return true;
    const lead = leadIn();
    if (await waitClipped(lead, waitUntil()) !== lead) return false;
    return await holdOwed(leadInOwed(), waitUntil() - requestBudget(check) - H - closeMs - barrierMs) === 0;
  };
  // exhausted: a check was cut or a wait truncated, so every later applicable check is cut. stopped (no timing plan): a check's
  // settle or barrier a host suspend left short, so every later applicable check is not sent (SUSPEND_STOPPED).
  let exhausted = false, stopped = false, tailWaitedMs = null;
  const timingRows = [];
  // Background attribution (src/http-attribution.mjs): the declared sources, or null.
  const attribution = profile.attribution ?? null;
  // Coverage v2 Part D: the run-end drain runs only when attribution or a forwarded destination is declared.
  const drainDeclared = drainsDeclared(profile);
  try {
  // A background source no started observer can see would attribute nothing: refused before the first mark and request.
  if (attribution) {
    const unseen = backgroundUnseen(attribution.background, observers.filter(o => o.started));
    if (unseen.length) throw Object.assign(new Error(`attribution-background-unobservable: no started observer can see background source ${unseen.join(', ')}.`), { status: 400 });
  }
  if (settling) lastEnd = await Promise.all(observers.map(o => o.mark()));
  const bracket = async (index, side) => {
    // Probe points re-send the identity controls and the surface controls, all GETs: before the actor's first bracketed
    // check, after each bracketed check (between), and after its last one (actor-identity/5).
    for (const plan of plans.values()) {
      const controls = plan.identityControls.length ? [...plan.identityControls, ...plan.surfaceControls] : [];
      if (side === 'before') { if (plan.first === index) for (const id of controls) plan.before.push(await probe(plan, control(id), 'before')); continue; }
      if (!plan.others.includes(index)) continue;
      if (plan.last === index) { for (const id of controls) plan.after.push(await probe(plan, control(id), 'after')); continue; }
      const point = { afterCheckId: profile.checks[index].id, probes: [] };
      for (const id of controls) point.probes.push(await probe(plan, control(id), 'between'));
      plan.between.push(point);
    }
  };
  for (const [index, check] of profile.checks.entries()) {
    await bracket(index, 'before');
    for (const entry of changeAt.get(check.id) ?? []) await proveBeforeChange(entry.actorId);
    const checkStart = clock.now(), requestId = randomUUID();
    if (check.applicability?.applies === false) {
      const declared = { reason: check.applicability.reason, requestAttempted: false };
      results.push({ id: check.id, title: check.title, category: check.category, severity: check.severity, status: 'not_applicable', summary: 'Excluded by the versioned applicability declaration.',
        evidenceRequirement: check.evidenceRequirement, expected: 'A documented scope decision; no request is sent.', observed: declared,
        assertions: [{ name: 'Declared applicability', status: 'not_applicable', expected: 'Documented scope', actual: check.applicability.reason }],
        backendEvidence: 'not-assessed', trace: [{ type: 'scope', label: 'No test request sent', data: declared }],
        remediation: { title: 'Review scope when capabilities change', why: 'Not applicable is not a passing security test.', steps: ['Confirm the capability is genuinely absent.', 'Re-enable the check when the application scope changes.'], codePointers: ['Local target profile'] }, durationMs: 0, evidenceDigest: digest(declared) });
      continue;
    }
    // Preconditions: a post-change check whose change did not pass when it was sent, or a check using a value
    // that was not captured, is not sent and reads inconclusive.
    const uses = captureUsesOf(check), entry = postChange.get(check.id);
    const useRecords = uses.map(name => { const c = captured.get(name); return { name, type: c.type, createdBy: c.createdBy, captureCheckId: c.captureCheckId, valueDigest: c.valueDigest }; });
    let notSent = entry && changeConfirmed.get(entry.changeCheckId) !== true ? 'change-not-confirmed' : uses.some(name => captured.get(name).outcome !== 'captured') ? 'capture-unavailable' : null;
    // Timing: a check the declared budget cannot hold, and every later one, is not sent (run-budget-exhausted).
    if (timing && (exhausted || (!notSent && !(await admit(check))))) { exhausted = true; notSent = RUN_BUDGET_EXHAUSTED; }
    // No timing plan: after a check whose settle or barrier a host suspend left short, no applicable check is sent (SUSPEND_STOPPED).
    if (stopped) notSent = SUSPEND_STOPPED;
    if (notSent) {
      const row = notSentRow(profile, check, { requestId, reason: notSent, uses: useRecords, ...routing });
      if (check.capture) recordCaptures(check, row.trace[0].data.captures);
      if (changeAt.has(check.id)) changeConfirmed.set(check.id, false);
      results.push(row); await bracket(index, 'after'); continue;
    }
    const sent = uses.length ? fillCaptures(check, new Map(uses.map(name => [name, captured.get(name).value]))) : check;
    const remaining = runBudgetMs - (clock.now() - started);
    const appliedTimeoutMs = remaining > 0 ? Math.max(1, Math.round(Math.min(requestBudget(check), remaining))) : 0;
    let observation;
    // Effects: mark every declared observer just before the request and just after the response.
    // Suspend-aware custody time: the detector is marked before the start marks, so a suspend from here to the last collect is this check's.
    const suspendFrom = observed(check) ? suspendClock.mark() : null;
    const effectMarks = observed(check) ? await Promise.all(observers.map(o => o.mark())) : null;
    if (effectMarks && settling) gapMarks.push({ from: lastEnd, to: effectMarks, before: check.id });
    const appLogStarts = effectMarks && appLogs ? appLogs.mark() : null;
    if (remaining <= 0) observation = { status: null, complete: false, jsonParsed: false, json: undefined, bytes: 0, error: 'timeout' };
    else {
      // With correlation declared, the request carries this check's token (its requestId); probes and witnesses carry none.
      const correlationHeader = correlation ? { correlationHeader: { name: correlation.header, value: correlationHeaderValue(correlation.header, requestId, spanId()) } } : {};
      try { observation = await transport(profile.origin, sent, { credential: credentials[check.actorId], credentialCookie: credentials[check.actorId] === undefined ? undefined : profile.actors[check.actorId].credentialCookie, timeoutMs: appliedTimeoutMs, maxResponseBytes: limits.responseBytes, ...correlationHeader }); }
      catch { observation = { status: null, complete: false, jsonParsed: false, json: undefined, bytes: 0, error: 'network' }; }
    }
    let evaluated = evaluateHttpCheck(check, observation, contextFor(check, sent));
    // Captures read the response before it is discarded; the creator is this check's actor.
    const captures = check.capture ? Object.entries(check.capture).map(([name, spec]) => {
      const found = captureOutcome({ observation, statusPassed: evaluated.assertions.find(a => a.name === 'HTTP status matches contract')?.status === 'pass', pointer: spec.pointer, type: spec.type, lookup: readPointer });
      return { name, type: spec.type, createdBy: check.actorId, outcome: found.outcome, valueDigest: found.outcome === 'captured' ? captureValueDigest(captureKey, name, found.value) : null, value: found.value };
    }) : null;
    if (captures) recordCaptures(check, captures);
    // Claim readings: only the reading (and the declared phrase or value index) is kept, never the reply text.
    const readings = check.claims ? readClaims(check.claims, observation) : [];
    let effectEntry = null, backend = false, effectInfo = null, checkEndMarks = null;
    if (observed(check)) {
      // Post-response settle: an effect the app commits shortly after answering still
      // lands in this window. The next check's start mark comes after this end mark.
      // Under timing the window is held for the declared horizon instead, clipped at the wait deadline.
      let waitedMs = null;
      // The horizon also leaves room for the witnesses' close and the barrier that follow it before the wait deadline.
      // A host suspend during the wait extends it in awake time (extendAwake); a horizon already cut short is not extended. Under a
      // timing plan the horizon held is sealed as the awake time it held: a shortfall the extension could not restore truncates it
      // (applyHorizon below, and every later check is cut), exactly as a horizon the budget clipped. Without a plan the settle's
      // shortfall goes in the windows' suspend record (shortMs), and those windows read partial (applySuspendShort below).
      const settleSince = suspendClock.mark();
      let settleShortMs = 0;
      if (timing) {
        const holdUntil = waitUntil() - closeMs - barrierMs;
        waitedMs = await waitClipped(H, holdUntil);
        if (waitedMs === H) waitedMs = H - Math.min(H, await extendAwake(settleSince, H, holdUntil));
        if (waitedMs < H) exhausted = true;
      } else if (settleMs) { await clock.sleep(settleMs); settleShortMs = await extendAwake(settleSince, settleMs, extensionUntil(index)); }
      // Every other observer is end-marked first. Then each audit-log file observer gets its
      // witness request (tagged with its start mark's nonce) and its own end mark, so the
      // witness's side effects fall outside every window.
      // Each audit-log file window is collected right after its own end mark, before the next
      // witness is sent, so one observer's witness round trip never shortens another's quiet period.
      const endMarks = await Promise.all(observers.map(o => o.witnessRequest ? null : o.mark()));
      const appLogCuts = appLogStarts ? appLogs.mark() : null;
      const collected = new Array(observers.length);
      for (const [i, o] of observers.entries()) if (o.witnessRequest) {
        // Lines the app logs from here on can be the witness's own doing: never attributed to the check.
        if (effectMarks[i]) await o.markWitnessRequest(effectMarks[i]);
        await sendWitness(o.witnessRequest, effectMarks[i]?.witnessNonce);
        endMarks[i] = await o.mark();
        collected[i] = await collectWindow(o, effectMarks[i], endMarks[i], { scoped: true });
      }
      // A horizon cut short (src/http-timing.mjs): every authoritative window it held open reads partial, before any decision.
      // Check windows are collected scoped (coverage v2): an egress recorder may scope its problem units to their destination.
      const heldWindows = (await Promise.all(observers.map((o, i) => collected[i] ?? collectWindow(o, effectMarks[i], endMarks[i], { scoped: true })))).map((w, i) => applySettle(w, declared[i].settleMs))
        .map(w => timing && waitedMs < H ? applyHorizon(w) : w);
      // A host suspend between this check's start marks and its last collect: every window carries its record (src/suspend-clock.mjs),
      // set on the collected objects themselves so a scoped window stays admitted; with a settle shortfall (no timing plan) the record
      // holds it, and every authoritative window reads partial. Where no suspend could be checked (the timers count sleep but no
      // awake clock could be read), the windows say so (suspendUnchecked), and the verdicts are exactly as they were before.
      const checkedTo = suspendClock.mark();
      const suspended = suspendRecord(suspendClock.between(suspendFrom, checkedTo), { shortMs: settleShortMs });
      const unchecked = suspendClock.uncheckedSince(suspendFrom) > 0;
      const windows = heldWindows.map(w => {
        if (suspended !== null) w.suspend = { ...suspended };
        if (unchecked) w.suspendUnchecked = true;
        return applySuspendShort(w);
      });
      // Without a timing plan, a check whose windows hold a settle shortfall is the last one sent, as a horizon held short ends a timed
      // run (PR343-REVIEW finding 1b): a send the sleep displaced past its end marks cannot land in a later check's window. The
      // validator derives the stop from the same sealed windows (src/contracts.mjs capturePreconditions).
      if (!timing && windows.some(w => w.suspend?.shortMs > 0)) stopped = true;
      const appLogWindows = appLogStarts ? appLogs.collect(appLogStarts, appLogCuts) : null;
      if (timing && settling) timingRows.push({ id: check.id, waitedMs, barrierWaitedMs: null });
      // In-doubt resolution, gate B (src/in-doubt.mjs): this build's egress windows carry transport records, so the backend tier reads them.
      if (IN_DOUBT_LABELS.includes(COLLECTOR_RECORDS['egress-recorder']?.label)) for (const w of windows) admitInDoubt(w);
      // The check's role decides whether custody can degrade a pass (src/custody.mjs).
      const decisions = decideEffects(check.effects ?? [], windows, { role: roleOfSeverity(check.severity), claims: check.claims ?? [], readings });
      // What the follow rule needs to decide this row again at run end (coverage v2): its declared clauses, readings and backend row.
      if (settling) { lastEnd = endMarks; checkEndMarks = endMarks; effectInfo = { decisions, windows, appLogWindows, role: roleOfSeverity(check.severity), effects: check.effects ?? [], claims: check.claims ?? [], readings, backendRow: evaluated.assertions.find(a => a.name === BACKEND_ASSERTION) ?? null }; }
      backend = backendObserved(decisions);
      effectEntry = effectTrace(decisions, windows, observerMeta, appLogWindows);
      const assertions = [...evaluated.assertions.map(a => a.name === BACKEND_ASSERTION && backend ? { ...a, status: 'pass', actual: 'Authoritative observers decided every declared effect' } : a), ...effectAssertionRows(decisions)];
      const transportError = observation.complete !== true || ['timeout', 'network', 'too-large'].includes(observation.error);
      const status = assertions.some(a => a.status === 'fail') ? 'fail' : transportError ? 'error' : assertions.some(a => a.status === 'inconclusive') ? 'inconclusive' : 'pass';
      const summaries = { fail: 'A response predicate or an observed effect failed.', error: 'The response observation could not be completed.', inconclusive: 'A response predicate or an observed effect could not be decided.', pass: 'Response predicates and observed effects passed.' };
      evaluated = { ...evaluated, assertions, status, summary: summaries[status], observed: { ...evaluated.observed, evidenceScope: 'response-and-observers' } };
    }
    // The raw response exists only for evaluation. Keep a strict allowlist of
    // non-content observations, including when a target echoes a credential.
    const actor = profile.actors[check.actorId];
    const evidence = { requestId, actorId: check.actorId, method: check.method, requestPathHash: digest(check.path), ...routeEvidence(check, observation, sent.path, routing),
      credentialMode: !actor.credentialEnv ? 'none' : actor.credentialCookie ? 'cookie' : 'bearer', requestTimeoutMs: appliedTimeoutMs,
      httpStatus: observation.status, responseComplete: observation.complete, responseBytes: observation.bytes,
      jsonParsed: observation.jsonParsed, transportOutcome: observation.error || 'complete', backendEvidence: 'unavailable',
      requestAttempted: remaining > 0, mutationEffects: HTTP_WRITE_METHODS.includes(check.method) ? MUTATION_EFFECTS.write : MUTATION_EFFECTS.read,
      ...(captures ? { captures: captures.map(({ value, ...kept }) => kept) } : {}), ...(uses.length ? { captureUses: useRecords } : {}) };
    observation = null;
    const row = { id: check.id, title: check.title, category: check.category, severity: check.severity, ...evaluated,
      evidenceRequirement: check.evidenceRequirement, expected: check.evidenceRequirement === 'backend' ? 'Configured response predicates and independent backend evidence.' : effectEntry ? 'Configured HTTP response predicates and observed effects.' : 'Configured HTTP response predicates only.',
      backendEvidence: backend ? 'observed' : 'unavailable', trace: [{ type: 'http-observation', label: 'Retained response metadata; response content is not stored', data: evidence }, ...(effectEntry ? [effectEntry] : [])],
      remediation: { title: 'Review this application contract', why: 'A response predicate is evidence about the response, not proof of a backend effect.', steps: ['Review the original private profile and the target implementation.', 'Apply any repair in the authorized test application.', 'Retest the unchanged contract and required permitted-use controls.'], codePointers: ['Local target profile', `Check ${check.id}`] },
      durationMs: Math.round(clock.now() - checkStart), evidenceDigest: digest(effectEntry ? { evidence, effects: effectEntry.data, assertions: evaluated.assertions } : { evidence, assertions: evaluated.assertions }) };
    results.push(row);
    if (effectInfo) effectRows.push({ row, ...effectInfo });
    if (changeAt.has(check.id)) changeConfirmed.set(check.id, row.status === 'pass');
    // Per-check settlement: the drain barrier. Wait the largest settle, mark every observer, and start the next gap
    // there; no request of the run is sent between this check's end marks and its barrier marks.
    if (effectInfo && perCheck) {
      // Under timing the barrier is clipped at the wait deadline; a clipped barrier's windows read partial (below).
      // A host suspend during the barrier: under a timing plan the barrier is sealed as the awake time it held (a shortfall clips it);
      // without one its windows carry the suspend record, with the shortfall (applySuspendShort when they are collected).
      let clipped = false, barrierShortMs = 0;
      const barrierSince = suspendClock.mark();
      if (timing) {
        let waited = await waitClipped(barrierMs, waitUntil());
        if (waited === barrierMs) waited -= Math.min(waited, await extendAwake(barrierSince, barrierMs, waitUntil()));
        timingRows.at(-1).barrierWaitedMs = waited; clipped = waited < barrierMs; if (clipped) exhausted = true;
      } else if (barrierMs) { await clock.sleep(barrierMs); barrierShortMs = await extendAwake(barrierSince, barrierMs, extensionUntil(index)); }
      const barrierSuspend = suspendRecord(suspendClock.between(barrierSince, suspendClock.mark()), { shortMs: barrierShortMs });
      // A barrier held short (no timing plan) ends the run's checks too: its windows carry the shortfall when they are collected.
      if (!timing && barrierSuspend?.shortMs > 0) stopped = true;
      const marks = await Promise.all(observers.map(o => o.mark()));
      barrierMarks.push({ from: checkEndMarks, to: marks, after: check.id, clipped, suspend: barrierSuspend });
      lastEnd = marks;
    }
    await bracket(index, 'after');
  }
  // Timing: the end-of-run probes are sent now, before the final settle, so no wait can starve them (the loop after the
  // observers stop then reads them from the same cache and sends nothing).
  if (timing) for (const plan of plans.values()) for (const id of plan.identityControls) {
    await probeOnce(plan, id, 'anonymous'); await probeOnce(plan, id, 'invalid');
    for (const other of judged.filter(a => a !== plan.actorId)) await probeOnce(plan, id, 'cross', other);
  }
  // Settlement: wait the largest settle after the last check, take the final mark, collect every gap window
  // (sinks and audit files from where the previous window stopped attributing), then settle each clause.
  if (effectRows.length) {
    // Under timing every end-of-run probe was sent above, so the final settle may use the budget up to its end.
    const tailSince = suspendClock.mark();
    // A host suspend during the final settle: sealed under a timing plan as the awake time it held (a shortfall clips the tail, so
    // the run-end window reads partial); without one the run-end windows carry the record with the shortfall.
    let tailShortMs = 0;
    if (timing) { tailWaitedMs = await waitClipped(settleMs, deadline); if (tailWaitedMs === settleMs) tailWaitedMs -= Math.min(tailWaitedMs, await extendAwake(tailSince, settleMs, deadline)); }
    else if (settleMs) { await clock.sleep(settleMs); tailShortMs = await extendAwake(tailSince, settleMs, deadline - endProbeReserveMs()); }
    // Coverage v2 Part D, the bounded run-end drain (only with attribution or a forward declared, the lead's decision of
    // 2026-10-11): before the final mark every egress recorder waits, all at once under one shared cap, until no request is
    // arriving, no record is pending and its quiet period has passed since the latest arrival, forward settle or reply. The
    // cap is the largest recorder's own and never runs past the run deadline less the end-of-run identity probes still to
    // send (under timing they were sent above). A drain that does not end quiescent follows nothing.
    // One record per declared egress recorder, in declaration order; a recorder that cannot drain (an injected one) never follows.
    // Feed v2, Part B (lead decision at GO): every witnessed endpoint provider feed drains too, whatever the egress gate: it reads to
    // a fresh signed head until nothing accepted is unread and the feed has been quiet for quietMs (src/run-end-drain.mjs).
    const drainers = observers.filter((o, i) => (drainDeclared && profile.observers[i]?.type === 'egress-recorder') || drainsFeed(profile.observers[i]));
    let drained = [];
    if (drainers.length) {
      const reserve = endProbeReserveMs();
      const capMs = drainCapOf(drainers.map(o => o.drainCapMs?.() ?? 0), deadline - clock.now() - reserve);
      drained = await Promise.all(drainers.map(o => capMs > 0 && o.drain ? o.drain(capMs) : null));
    }
    const tailSuspend = suspendRecord(suspendClock.between(tailSince, suspendClock.mark()), { shortMs: tailShortMs });
    gapMarks.push({ from: lastEnd, to: await Promise.all(observers.map(o => o.mark())), before: null, clipped: timing !== null && tailWaitedMs < settleMs, suspend: tailSuspend });
    // Each drain's record: it follows only when quiescent, with a clear final mark and no pending record's connection closed after its collect.
    const drains = drainers.length ? drainers.map((o, k) => { const d = drained[k] ?? { quiescent: false, waitedMs: 0, closedAfterCollect: true };
      return { instanceId: o.instanceId, quiescent: d.quiescent === true, waitedMs: Math.max(0, Math.round(d.waitedMs ?? 0)), markClear: o.markClear?.(gapMarks.at(-1).to[observers.indexOf(o)]) === true, closedAfterCollect: d.closedAfterCollect !== false || o.closedAfterCollect?.() !== false }; }) : null;
    // With attribution declared, the run-end window (the last gap) is collected in final mode: nothing follows it, so a
    // send still arriving leaves it partial instead of complete (egress recorders and the payments double).
    const runEnd = gapMarks.at(-1);
    for (const gap of [...gapMarks, ...barrierMarks]) gap.windows = (await Promise.all(observers.map((o, i) => collectWindow({ source: o.source, instanceId: o.instanceId, scope: o.scope, collect: (from, to) => o.collect(from, to, { gap: true, ...(attribution && gap === runEnd ? { final: true } : {}) }) }, gap.from[i], gap.to[i])))).map((w, i) => applySettle(w, declared[i].settleMs));
    // Timing: a clipped barrier or final settle reads partial in every authoritative window it held open.
    if (timing) for (const gap of [...gapMarks, ...barrierMarks]) if (gap.clipped) gap.windows = gap.windows.map(applyHorizon);
    // A barrier or final settle a host suspend overlapped: its windows carry the record, and with a shortfall (no timing plan) every
    // authoritative one reads partial, so settlement withholds what it would have read through them (src/suspend-clock.mjs).
    for (const gap of [...gapMarks, ...barrierMarks]) if (gap.suspend) gap.windows = gap.windows.map(w => applySuspendShort(Object.assign(w, { suspend: { ...gap.suspend } })));
    // A drainer whose run-end window failed (its final mark could not be taken, the listener went down, the feed faulted) follows
    // nothing: its drain record reads neither quiescent nor clear, as the run validator requires of such a window.
    if (drains) for (const d of drains) if (runEnd.windows.some(w => w.instanceId === d.instanceId && w.coverage === 'failed')) { d.quiescent = false; d.markClear = false; }
    // Later outcomes (ADDENDUM-R1 M3, placed after the final mark by the PR-1 fail-open review): the later wait runs once, after every
    // drain, the final mark and the collect of every run-end and barrier window, so no window, drain record or verdict can depend on it.
    // Each feed that reads later outcomes waits up to its own declared waitMs (never past the run deadline less the end-of-run identity
    // probes still to send, and two feed requests kept for the later mark), then takes a later mark: a fresh signed head that its records
    // are cut at and that its clear flag reads.
    const laterFeeds = laterFeedsOf(declared, OUTCOME_COLLECTOR_LABELS).map(d => ({ d, o: observers[declared.indexOf(d)] }));
    const laterRead = new Map();
    if (laterFeeds.length) {
      const msLeft = Math.floor(deadline - clock.now() - endProbeReserveMs() - 2 * PROVIDER_FEED_REQUEST_MS);
      const read = await Promise.all(laterFeeds.map(async ({ d, o }) => {
        const capMs = Math.max(0, Math.min(d.feed.outcomes.waitMs, msLeft)), waited = capMs > 0 ? await o.laterWait(capMs) : 0;
        return { waitedMs: Math.max(0, Math.min(Math.round(waited ?? 0), d.feed.outcomes.waitMs)), mark: await o.mark() };
      }));
      laterFeeds.forEach(({ d }, k) => laterRead.set(d, read[k]));
    }
    // Per feed that reads them, its records up to the later mark's signed head, kept only for sends the run sealed as committed events of
    // that feed (a send in a failed window, past an event cap, or after the final mark has none), with the clear flag and the time the later
    // wait took. Sealed in the settlement record below; under provider-feed/6 the later-outcome stage reads them (src/later-outcome.mjs).
    const sealedNow = [...effectRows.flatMap(r => r.windows), ...gapMarks.flatMap(g => g.windows), ...barrierMarks.flatMap(b => b.windows)];
    const laterList = laterFeeds.map(({ d, o }) => {
      const instanceId = o.instanceId, events = new Set(sealedNow.filter(w => w.instanceId === instanceId).flatMap(w => w.events).filter(e => e.outcome === 'committed').map(e => e.seq));
      const { waitedMs, mark } = laterRead.get(d), read = o.laterRecords(mark);
      return { instanceId, clear: read?.clear === true, waitedMs, records: Array.isArray(read?.records) ? read.records.filter(r => events.has(r.of)) : [] };
    });
    // Correlation (src/http-settlement.mjs): the sent rows' tokens and the declared pairs that record them.
    const recorded = correlation ? correlationRecorded(profile.observers) : null;
    const correlated = correlation ? { mode: perCheck ? 'per-check' : 'run', ...(perCheck ? { barriers: barrierMarks.map(b => b.windows) } : {}), tokens: settlementTokens(results, effectRows.map(r => r.row)), declared: correlationDeclared(recorded) } : undefined;
    // The follow rule (coverage v2): a check window whose late entries (after the witness request, a pending forward) no later
    // collected check window of the same recorder follows is read window-wide, and its row is decided again, for every role,
    // before settlement. It can only move a verdict decided through a late entry to missing: a pass, a fail (SETTLE-V3 fix A) or an
    // effect.only pass (fix C).
    const unfollowed = unfollowedLate(effectRows.map(r => r.windows), { followed: followedDrains(drains) });
    // A row decided again before settlement (the follow rule, the run-end re-decide stage): its decisions, backend reading and seal.
    const decidedAgain = (r, decisions) => {
      r.decisions = decisions;
      const backend = backendObserved(r.decisions);
      r.row.backendEvidence = backend ? 'observed' : 'unavailable';
      r.row.assertions = r.row.assertions.map(a => a.name === BACKEND_ASSERTION && r.backendRow ? (backend ? { ...r.backendRow, status: 'pass', actual: 'Authoritative observers decided every declared effect' } : r.backendRow) : a);
      resealEffects(r, { settlement: r.decisions.map(() => null), attribution: r.decisions.map(() => null), pairing: r.decisions.map(() => null) }, observerMeta);
    };
    effectRows.forEach((r, k) => {
      if (!unfollowed[k].size) return;
      for (const w of r.windows) if (unfollowed[k].has(w.instanceId)) markUnfollowed(w);
      decidedAgain(r, decideEffects(r.effects, r.windows, { role: r.role, claims: r.claims, readings: r.readings }));
    });
    // In-doubt resolution, the run-end re-decide stage (IDR-2; IN-DOUBT-DESIGN-ADDENDUM-R1 1.6, ADDENDUM-R2 m7): after the final mark's
    // resolver reads and the follow rule (markUnfollowed only marks a window, so the records bound on its events stay), before settlement.
    // A later resolver's records are bound onto the attempts they name, and every row with an opted-in clause that reads a changed attempt
    // is decided again with decideEffects and resealed with the records (src/http-effects.mjs redecideResolved), so settlement, attribution,
    // pairing, later outcomes and admissions all read resolved fates; the validator binds the sealed records before it decides. No later
    // resolver exists in this build, so nothing binds and no row changes.
    const resolverReads = (await Promise.all(observers.map((o, i) => o.resolutionRecords(runEnd.to[i])))).flatMap((list, i) => list.filter(x => x !== null && typeof x === 'object').map(x => ({ observer: observers[i].instanceId, seq: x.seq, records: x.records })));
    redecideResolved(effectRows, resolverReads).forEach((decisions, k) => { if (decisions) decidedAgain(effectRows[k], decisions); });
    // Judged late effects (src/http-settlement.mjs): only a target that declares settlement "outsideWindow": "judge".
    const findings = settlementFindings(effectRows.map(r => ({ effects: r.decisions, windows: r.windows })), gapMarks.map(g => g.windows), correlated, { judge: judgeLate });
    // Pairing (src/http-pairing.mjs): each settled absence clause that pins an actor, a resource or a trace id needs an
    // allowed-use control with the same selector that matched in a deciding observer's window.
    const settled = effectRows.map((r, k) => applySettlement(r.decisions, findings[k], r.role));
    // Attribution: only with the declaration; it reads the settled clauses and every window (barriers in per-check mode).
    // Late fails (timing "lateFails": "withhold", src/http-timing.mjs) add the late rules, with or without background sources.
    const lateFails = timing?.lateFails === LATE_FAILS;
    const attributed = attribution || lateFails ? attributionFindings(effectRows.map((r, k) => ({ effects: settled[k], windows: r.windows })), gapMarks.map(g => g.windows), perCheck ? barrierMarks.map(b => b.windows) : undefined, { background: attribution?.background ?? [], lateFails, tokens: correlated?.tokens }) : effectRows.map(r => r.decisions.map(() => null));
    const owned = effectRows.map((r, k) => applyAttribution(settled[k], attributed[k], r.role));
    const pairing = pairingFindings(effectRows.map((r, k) => ({ id: r.row.id, actorId: r.row.trace[0].data.actorId, role: r.role, effects: owned[k], windows: r.windows })), selectorPairs(profile));
    // Later outcomes (provider-feed/6, src/later-outcome.mjs): read after pairing, a positive pass a matched send no longer credits (its
    // provider later failed it, or the feed's later horizon is not clear) is judged again without that send, and only lowered; the findings
    // apply after admissions, only to a clause that still passes (resealEffects).
    const stage = laterFeedsOf(declared, LATER_STAGE_LABELS).length > 0;
    const later = stage ? laterFindings({ rows: effectRows.map((r, k) => ({ raw: r.decisions, settled: settled[k], paired: applyPairing(owned[k], pairing[k], r.role), windows: r.windows, role: r.role })),
      gaps: gapMarks.map(g => g.windows), barriers: perCheck ? barrierMarks.map(b => b.windows) : undefined, correlation: correlated, judge: judgeLate,
      attribution: attribution || lateFails ? { background: attribution?.background ?? [], lateFails, tokens: correlated?.tokens } : null, readingOf: laterReadings(laterList, declared) })
      : effectRows.map(r => r.decisions.map(() => null));
    // App-log admissions (src/app-log-verdicts.mjs, "use": "admission"): last, after pairing; they only ever make a clause fail.
    const records = appLogs ? appLogRecords(profile.appLogs) : null;
    const contexts = records ? admissionRows(effectRows.map(r => ({ id: r.row.id, principal: profile.actors[r.row.trace[0].data.actorId]?.principalId, requestId: r.row.trace[0].data.requestId,
      decisions: r.decisions, windows: r.windows, appLogWindows: r.appLogWindows })), { background: attribution?.background ?? [] }) : [];
    const admitted = effectRows.map((r, k) => !records || !r.appLogWindows ? r.decisions.map(() => null) : admissionsFor(r.decisions, { windows: r.windows, appLogWindows: r.appLogWindows, records, ...contexts[k] }));
    effectRows.forEach((r, k) => { if ([findings[k], attributed[k], pairing[k], admitted[k], later[k]].some(list => list.some(f => f !== null))) resealEffects(r, { settlement: findings[k], attribution: attributed[k], pairing: pairing[k], admission: admitted[k], later: later[k] }, observerMeta); });
    const gaps = gapMarks.map((g, k) => ({ after: k ? effectRows[k - 1].row.id : null, before: g.before, windows: sealWindows(g.windows, observerMeta) }));
    settlement = correlation ? { schema: SETTLEMENT_SCHEMA_CORRELATED, settleMs, mode: correlated.mode, correlation: { header: correlation.header, recorded }, gaps,
      ...(perCheck ? { barriers: barrierMarks.map(b => ({ after: b.after, windows: sealWindows(b.windows, observerMeta) })) } : {}), ...(judgeLate ? { outsideWindow: 'judge' } : {}) }
      : { schema: SETTLEMENT_SCHEMA, settleMs, gaps, ...(judgeLate ? { outsideWindow: 'judge' } : {}) };
    if (drains) settlement.drains = drains;
    if (laterFeeds.length) settlement.later = laterList;
  }
  } finally { await Promise.allSettled([...observers.map(o => o.stop()), appLogs?.stop()]); }
  for (const plan of plans.values()) for (const id of plan.identityControls) {
    plan.anonymous.push(await probeOnce(plan, id, 'anonymous'));
    plan.invalid.push(await probeOnce(plan, id, 'invalid'));
    for (const other of judged.filter(a => a !== plan.actorId)) plan.cross.push(await probeOnce(plan, id, 'cross', other));
  }
  // Lifecycle entries (the changer's attribution is filled in below), then the per-check identity judge.
  const lifecycle = new Map((profile.lifecycle ?? []).filter(e => plans.has(e.actorId)).map(e => [e.actorId, { changeCheckId: e.changeCheckId, after: e.after, changeConfirmed: changeConfirmed.get(e.changeCheckId) === true, changerLoginProven: false, postChangeCheckIds: postChangeChecks(profile.checks, e).map(c => c.id) }]));
  const rowOf = id => results.find(r => r.id === id);
  // A change confirmed when it was sent whose own pass the run's attribution (src/http-attribution.mjs) or correlation settlement
  // (src/http-settlement.mjs, effect-correlated-elsewhere) then withheld is not
  // attributed to its check: the record reads it unconfirmed, as the validator does from the final row, and every post-change
  // check already sent carries change-not-attributed and never passes (a credential that still works still fails).
  for (const life of lifecycle.values()) {
    if (!life.changeConfirmed || passedAtSend(rowOf(life.changeCheckId))) continue;
    life.changeConfirmed = false;
    for (const row of life.postChangeCheckIds.map(rowOf)) {
      if (row.trace[0].data.transportOutcome === 'not-sent') continue;
      row.assertions.push(precondition('change-not-attributed'));
      if (row.status === 'pass') { row.status = 'inconclusive'; row.summary = 'Response predicates passed, but the account change this check rests on was not attributed to its change check.'; }
      row.evidenceDigest = sealDigest(row);
    }
  }
  const windowsById = new Map(effectRows.map(r => [r.row.id, r.windows]));
  let judge = identityJudge(profile, results, identityEvidenceOf(plans, results, lifecycle), plans, postChange, windowsById);
  // A sent row using a value whose creator's login was not proven at the capturing check: who created it is not established
  // (a row that already reads change-not-attributed keeps that one precondition).
  for (const row of results) {
    const uses = row.trace?.[0]?.data?.captureUses;
    if (!uses || row.trace[0].data.transportOutcome === 'not-sent' || row.assertions.some(a => a.name === PRECONDITION_ASSERTION) || !uses.some(u => plans.has(u.createdBy) && loginLevel(judge(rowOf(u.captureCheckId))))) continue;
    row.assertions.push(precondition('creator-login-unproven'));
    if (row.status === 'pass') { row.status = 'inconclusive'; row.summary = 'Response predicates passed, but who created a value this check used is not established.'; }
    row.evidenceDigest = sealDigest(row);
  }
  // A change is attributed only when the changer's login was proven for the change check (its own identity reason is null).
  for (const life of lifecycle.values()) life.changerLoginProven = judge(rowOf(life.changeCheckId)) === null;
  const identityEvidence = identityEvidenceOf(plans, results, lifecycle);
  judge = identityJudge(profile, results, identityEvidence, plans, postChange, windowsById);
  establishActorIdentity(results, judge);
  const capturedModelIdentity = await finishModelIdentityCapture(modelCapture);
  const counts = { pass: 0, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }; for (const r of results) counts[r.status]++;
  const profileHash = contractDigest(profile), suiteHash = digest({ checks: profile.checks, requiredControlIds: profile.requiredControlIds, schema: ASSERTION_SCHEMA_VERSION });
  return { schemaVersion: 1, id: randomUUID(), createdAt: new Date().toISOString(), targetId: profile.id, targetName: profile.name, build: profile.buildLabel,
    applicationId: profile.applicationId, suiteId: `${profile.id}-contracts`, suiteHash, policyHash: suiteHash,
    profileHash, contextId: profile.contextId, fixtureVersion: 'operator-declared-context/1', fixtureHash: digest(profile.contextId),
    adapterVersion: HTTP_ADAPTER_VERSION, assertionSchemaVersion: ASSERTION_SCHEMA_VERSION, evaluatorHash, requiredControlIds: [...profile.requiredControlIds],
    evidenceOrigin: 'local-http-response', runtimeMode: 'configured-local-application', targetBuildHash: null,
    targetConfigHash: targetConfigDigest({ profileHash, build: profile.buildLabel, targetContext: profile.targetContext, targetLabel: profile.targetLabel ?? null }), buildIdentity: 'Declared in configuration; not independently attested.',
    targetContext: profile.targetContext, targetLabel: profile.targetLabel ?? null,
    scopeLabel: targetScopePrefix({ targetContext: profile.targetContext, targetLabel: profile.targetLabel ?? null }) + httpScopeText({ observed: observers.length > 0, declared, judge: judgeLate }),
    ...(Object.hasOwn(profile, 'observers') ? { observers: declared } : {}), ...(signingRun ? { signing: signingRun } : {}), ...(settlement ? { settlement } : {}), ...(attribution ? { attribution: attributionRecord(attribution) } : {}),
    ...(appLogs ? { appLogs: appLogRecords(profile.appLogs) } : {}),
    // The declared horizon and budget, and how long each effect row's window, barrier and the tail were actually held.
    ...(timing ? { timing: { schema: TIMING_SCHEMA, effectHorizonMs: H, runBudgetMs, lateFails: timing.lateFails ?? null, rows: timingRows, tailWaitedMs: effectRows.length ? tailWaitedMs : null } } : {}),
    durationMs: Math.round(clock.now() - started), checksTotal: results.length, counts, results, identityEvidence,
    // The declared principals (alias -> principalId) the absence selectors are paired against (src/http-pairing.mjs).
    principals: Object.fromEntries(Object.entries(profile.actors).map(([alias, actor]) => [alias, actor.principalId])),
    // json.noForeignValues: the value-free tenant declaration (counts, policy, actor tenant positions) its predicates are validated against.
    ...(tenantValues ? { tenantValueCounts: tenantValueCounts(profile) } : {}),
    ...(capturedModelIdentity === undefined ? {} : { modelIdentity: capturedModelIdentity }),
    limitations: httpLimitations({ forwarded: profile.targetContext === 'operator-forwarded', observersDeclared: Object.hasOwn(profile, 'observers'), declared, signing: signingRun, judge: judgeLate, restsOn: profile.checks.some(c => Array.isArray(c.restsOn)),
      auditFiles: (profile.observers ?? []).filter(o => o.type === 'audit-file').map(o => ({ id: o.id, quietMs: o.quietMs ?? AUDIT_FILE_QUIET_DEFAULT_MS })),
      pgSnapshots: (profile.observers ?? []).filter(o => o.type === 'pg-snapshot').map(o => o.id),
      egressRecorders: (profile.observers ?? []).filter(o => o.type === 'egress-recorder').map(o => ({ id: o.id, routing: o.routing ?? null, quietMs: o.quietMs ?? EGRESS_QUIET_DEFAULT_MS })),
      mysqlSnapshots: (profile.observers ?? []).filter(o => o.type === 'mysql-snapshot').map(o => o.id),
      smtpSinks: (profile.observers ?? []).filter(o => o.type === 'smtp-sink').map(o => ({ id: o.id, routing: o.routing ?? null, quietMs: o.quietMs ?? EGRESS_QUIET_DEFAULT_MS })),
      providerFeeds: (profile.observers ?? []).filter(o => o.type === 'provider-feed').map(o => ({ id: o.id, route: o.feed?.endpoint ? 'endpoint' : 'file', witnessed: o.witness !== undefined, quietMs: o.quietMs ?? EGRESS_QUIET_DEFAULT_MS, templates: o.templates !== undefined, ...(laterFeedsOf(declared, OUTCOME_COLLECTOR_LABELS).some(d => d.id === o.id) ? { outcomesWaitMs: o.outcomes.waitMs ?? 0 } : {}) })),
      appLogs: (profile.appLogs ?? []).map(o => ({ id: o.id, use: o.use })),
      lifecycle: (profile.lifecycle ?? []).length > 0, captures: profile.checks.some(c => c.capture),
      bodyCapture: (profile.observers ?? []).some(o => o.type === 'egress-recorder' && (o.destinations ?? []).some(d => d.capture)), claims: profile.checks.some(c => c.claims), tenantValues: tenantValues !== null,
      correlation: correlation ? { header: correlation.header, mode: perCheck ? 'per-check' : 'run' } : null, attribution: attribution ? { sources: attribution.background.map(s => s.id) } : null,
      timing: timing ? { effectHorizonMs: H, runBudgetMs, lateFails: timing.lateFails === LATE_FAILS, truncated: timingRows.filter(r => r.waitedMs < H || (perCheck && r.barrierWaitedMs < barrierMs)).map(r => r.id),
        exhausted: results.filter(r => r.trace?.[0]?.data?.notSent === RUN_BUDGET_EXHAUSTED).map(r => r.id), tailClipped: effectRows.length > 0 && tailWaitedMs < settleMs } : null }) };
  } finally { await releaseModelIdentityCapture(modelCapture); }
}
