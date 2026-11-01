import { digest, stable } from './domain.mjs';
import { validateWebhookDeclaration, webhookEnvClash, webhookHeaderClash, webhookEvidenceProblem } from './webhook-driver.mjs';
// The run's catalog identity (N13): its shape and digest, and the observer types that read one.
import { validCatalogIdentity, CATALOG_IDENTITY_SCHEMA, CATALOG_OBSERVER_TYPES } from './catalog-identity.mjs';
import { CREDENTIAL_ENV, unfollowedLate, consistentScopedCaptures } from './effect-events.mjs';
import { validCollector, DRAIN_COLLECTOR_LABELS, TEMPLATE_COLLECTOR_LABELS, SIGNING_COLLECTOR_LABELS, OUTCOME_COLLECTOR_LABELS, LATER_STAGE_LABELS, TARGET_LABELS, REQUEST_FEED_LABELS, READ_BACK_LABELS, KEY_SOURCE_LABELS, SIBLING_LABELS, CROSS_LABELS } from './collector-identity.mjs';
// In-doubt resolution R1 (IDR-4): the request feed's port clash, its run record and the run-wide consistency of its sealed reads.
import { requestFeedClash, validRequestFeedRecord, consistentRequestFeedRun } from './request-feed-rules.mjs';
import { readBackClash, validReadBackRecord, consistentReadBackRun } from './read-back-rules.mjs';
import { laterFindings, laterReadings } from './later-outcome.mjs';
import { laterFeedsOf } from './provider-feed-rules.mjs';
import { validateAuditFileConfig } from './audit-file-rules.mjs';
import { validateEgressConfig, correlationHeaderValid, CORRELATION_HEADER_RULE, validObjectRecord, validAliasRecord, validCrossRecord } from './egress-rules.mjs';
import { validateSmtpConfig } from './smtp-rules.mjs';
import { validateProviderFeedConfig, providerFeedClash, providerFeedTemplatePins, validProviderFeedRecord, validProviderFeedCapture } from './provider-feed-rules.mjs';
// App logs (src/app-log-rules.mjs): the application's own action log, declared apart from the observers and recorded only.
import { validateAppLogs, backgroundAllowSelect } from './app-log-rules.mjs';
import { validAppLogRecords, admissionContexts } from './app-log-verdicts.mjs';
import { zeroRowClause, responseContractSucceeded } from './http-effects.mjs';
import { MAX_EFFECTS, OBSERVER_TYPES, OBSERVER_ID, EFFECT_ASSERTION_PATTERN, BACKEND_ASSERTION, SETTLE_BOUNDS, settleDeclared, recomputeEffectTrace, roleOfSeverity, validateDeclaredEffect, validateCheckEffects, outcomeJudgedProfileProblem, forbiddenSelectors, bindSealedWindows, declaredEffect,
  validateDeclaredClaims, declaredClaim, decideSealed, sealedClaims, bindSealedResolutions, CLAIM_ASSERTION_PATTERN, observerInstanceId } from './http-effects.mjs';
import { validCaptureMap, validCaptureForm } from './body-fields.mjs';
import { validIdempotencyMap, consistentIdempotencyRun, consistentSigningRun, validSigningRun, signingSecretClash, SIGNING_BOUNDS } from './idempotency.mjs';
import { forwardPortClash, forwardSecretClash, validForwardRecord } from './effect-outcome.mjs';
// Positive-match pairing of absence selectors (src/http-pairing.mjs): recomputed across the run like settlement.
import { selectorPairs, pairingFindings, positiveClause, applyPairing, allowedUseGuards } from './http-pairing.mjs';
// Typed captures, the lifecycle phase and run settlement: each in its own pure module.
import { validateCaptureDeclarations, CAPTURE_LIMITS, CAPTURE_TYPES, CAPTURE_OUTCOMES, CAPTURE_NAME } from './http-captures.mjs';
import { validateLifecycle, LIFECYCLE_POLICIES, postChangeIndex, selfChangeIds } from './http-lifecycle.mjs';
import { validateSettlementRecord, settlementFindings, applySettlement, settlementTokens, correlationDeclared, SETTLEMENT_MODES, SETTLEMENT_OUTSIDE_WINDOW } from './http-settlement.mjs';
// Coverage v2 Part D: the run-end drain's record and rules (src/run-end-drain.mjs).
import { drainersOf, validDrains, followedDrains } from './run-end-drain.mjs';
// Identity option B (actor-identity/6, src/http-rests-on.mjs): a boundary check's declared restsOn, its load rule and its release.
import { restsOnProblem, restsOnView, restsOnReleases, failureAdmitted, recordedRouteShape, controlScopeShape, declaredPartners, relatedByRoute, RESTS_ON_LIMITS } from './http-rests-on.mjs';
// A declared effect horizon and run budget (src/http-timing.mjs): load-time plan, run record and truncated windows.
import { validateTiming, validateTimingRecord, timingDeclarationOf, maxDeclaredSettle, carriesHorizon, RUN_BUDGET_EXHAUSTED, LATE_FAILS } from './http-timing.mjs';
// A run a host suspend stopped without a timing plan (src/suspend-clock.mjs): derived here from the sealed windows' shortfall.
import { SUSPEND_STOPPED, stopsRun } from './suspend-clock.mjs';
// A remote target's origin (H1 step 3): the one form the connector dials directly.
import { remoteOriginOf } from './remote-target.mjs';
// The declared-channel rule (N11): its declaration is checked here; the rule itself reads the saved run (src/channels.mjs).
import { channelDeclarationProblem } from './channels.mjs';
// Background attribution (readiness gap 5): recomputed across the run after settlement, like pairing.
import { attributionDeclarationProblem, validateAttributionRecord, attributionFindings, applyAttribution, backgroundUnseen } from './http-attribution.mjs';
// Per-check settlement adds one barrier (the largest settle) per applicable check with effects or claim rules; this bounds the total.
export const PER_CHECK_BARRIER_LIMIT_MS = 600000;
// Forbidden-value leak detection (json.noForeignValues): the declared tenant values and the whole-token scan, in their own pure module.
import { FOREIGN_VALUES_KIND, FOREIGN_VALUES_EXPECTED, validateTenantValues, foreignValuesPredicate, foreignValuesActual, validForeignValuesPredicate, validTenantValueCounts } from './tenant-values.mjs';
// Two identities by default (NC2 item 1, src/two-identities.mjs): the "mirrors" declaration and the generated mirror of each boundary check.
import { validateMirrorDeclaration, mirrorChecks, MIRROR_SUFFIX, validMirrorLimitStatuses } from './two-identities.mjs';
// Postgres read-back in HTTP checks (ROADMAP v2 item 2): a pg-snapshot table's readBack, a check's readBack member, and the sealed record.
import { validateReadBack } from './pg-readback.mjs';
import { readBackProblem, readBackDeclarations, readBackSuiteView, recomputeReadBack, readBackDigestOf, READBACK_ASSERTION_PATTERN } from './http-readback.mjs';

// http-contract/4 adds declared observers and per-check effects (observed backend effects).
export const ASSERTION_SCHEMA_VERSION = 'http-contract/4';
// A check may declare its own request budget, for endpoints that run a model
// turn. The default stays HTTP_LIMITS.requestTimeoutMs in the connector.
export const CHECK_TIMEOUT_BOUNDS = Object.freeze({ minimumMs: 1000, maximumMs: 120000, profileTotalMs: 600000 });
// RFC 6265 cookie-name token. Values are checked by the connector at send time.
export const COOKIE_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/;
// Added to a non-control row whose actor has a required control that did not pass.
export const IDENTITY_ASSERTION = 'Actor identity established by required controls';
// Check methods. Every method but GET is a write: only a write may carry a JSON
// body, and its evidence says a timeout does not undo it. Identity controls, the
// only checks that are re-sent, stay GET only (identityControlPlan).
export const HTTP_WRITE_METHODS = Object.freeze(['POST', 'PUT', 'PATCH', 'DELETE']);
export const HTTP_CHECK_METHODS = Object.freeze(['GET', ...HTTP_WRITE_METHODS]);
// Connector v1 and v2 sent only GET and POST, so a row labelled v1 or v2 with another method is refused.
const LEGACY_EVIDENCE_METHODS = Object.freeze(['GET', 'POST']);
// The evidence text the connector writes for each kind of method; a saved row must carry the one its method implies.
export const MUTATION_EFFECTS = Object.freeze({ write: 'Not independently observed; a timeout does not undo an action.', read: 'Not independently observed.' });
const STATUS_KINDS = ['status.equals', 'status.in'], JSON_KINDS = ['json.equals', 'json.exists', 'json.notContains', FOREIGN_VALUES_KIND];
const UNSAFE_KEYS = ['__proto__', 'prototype', 'constructor'];
class ContractValidationError extends Error { constructor(reason) { super(reason); this.reason = reason; this.where = []; } }
const fail = reason => { throw new ContractValidationError(reason); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(value);
// Errors name where the problem is, using only validated identifiers or
// positions and our own field names, never configured values.
const named = (noun, id, index) => identifier(id) && !UNSAFE_KEYS.includes(id) ? `${noun} "${id}"` : `${noun} ${index + 1}`;
const fieldName = key => typeof key === 'string' && /^[A-Za-z][A-Za-z0-9_]{0,31}$/.test(key) ? `"${key}"` : 'an unnamed field';
function within(label, run) {
  try { return run(); } catch (error) { if (error instanceof ContractValidationError) error.where.unshift(label); throw error; }
}
function text(value, maximum, reason) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) fail(reason);
}
// operator-remote (H1 step 3, src/remote-target.mjs): an https origin reached directly, only under an authorization record naming it.
export const TARGET_CONTEXTS = Object.freeze(['local-app', 'operator-forwarded', 'operator-remote']);
// The contexts a label may name: a forwarded or a remote target.
const LABELLED_CONTEXTS = Object.freeze(['operator-forwarded', 'operator-remote']);
// A label is a name ("Acme staging"), never a URL, host:port or user@host.
const validTargetLabel = label => typeof label === 'string' && /^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,79}$/.test(label);
// The scope-line prefix every export shows for an operator-forwarded target.
// A forwarded run's limitations must name the forwarder: the stable phrase every wording keeps (src/http-scope-text.mjs).
export const FORWARDER_MARKER = 'operator-run forwarder';
// A remote run's limitations must say it was reached directly: the stable phrase of REMOTE_LIMITATION (src/http-scope-text.mjs).
export const REMOTE_MARKER = 'reached directly over HTTPS';
// The run's target configuration digest binds the build label and target context to the profile hash.
export const targetConfigDigest = ({ profileHash, build, targetContext, targetLabel }) => digest({ profileHash, buildLabel: build, targetContext, targetLabel });
export const targetScopePrefix = run => run?.targetContext === 'operator-forwarded' ? `operator-forwarded target: ${run.targetLabel ?? 'unlabelled'}. `
  : run?.targetContext === 'operator-remote' ? `remote target over HTTPS: ${run.targetLabel ?? 'unlabelled'}. ` : '';
function shape(value, required, optional = []) {
  if (!object(value)) fail('unsupported or missing fields (expected a JSON object)');
  const unsupported = Reflect.ownKeys(value).find(key => typeof key !== 'string' || ![...required, ...optional].includes(key));
  if (unsupported !== undefined) fail(`unsupported or missing fields (unsupported field ${fieldName(unsupported)})`);
  const missing = required.find(key => !Object.hasOwn(value, key));
  if (missing !== undefined) fail(`unsupported or missing fields (missing field "${missing}")`);
}
function jsonValue(value, depth = 0, budget = { nodes: 0 }) {
  if (++budget.nodes > 1000 || depth > 12) fail('JSON complexity exceeds bounds');
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'number' && Number.isFinite(value)) return;
  if (typeof value === 'string' && value.length <= 8192) return;
  if (Array.isArray(value)) { for (const item of value) jsonValue(item, depth + 1, budget); return; }
  if (object(value)) {
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string' || key.length > 512 || ['__proto__', 'prototype', 'constructor'].includes(key)) fail('invalid JSON property');
      jsonValue(value[key], depth + 1, budget);
    }
    return;
  }
  fail('invalid JSON value');
}
function pointerTokens(pointer) {
  if (typeof pointer !== 'string' || pointer.length > 512 || (pointer !== '' && !pointer.startsWith('/')) || /~(?![01])/.test(pointer)) fail('invalid JSON pointer');
  const tokens = pointer === '' ? [] : pointer.slice(1).split('/').map(token => token.replaceAll('~1', '/').replaceAll('~0', '~'));
  if (tokens.some(token => ['__proto__', 'prototype', 'constructor'].includes(token))) fail('unsafe JSON pointer');
  return tokens;
}
function validPath(path) {
  text(path, 2048, 'invalid request path');
  if (!path.startsWith('/') || path.includes('#')) fail('invalid request path');
  try { decodeURIComponent(path); } catch { fail('invalid request path encoding'); }
  let decoded = path;
  for (let count = 0; count < 5; count++) {
    if (decoded.includes('\\') || decoded.includes('//') || /[\u0000-\u0020\u007f]/.test(decoded) || decoded.split('?')[0].split('/').some(part => part === '.' || part === '..')) fail('unsafe request path');
    if (!/%[0-9a-f]{2}/i.test(decoded)) return;
    try { decoded = decodeURIComponent(decoded); } catch { fail('invalid request path encoding'); }
  }
  fail('excessive request path encoding');
}
function validAssertion(assertion) {
  if (!object(assertion)) fail('unsupported or missing fields (expected a JSON object)');
  if (![...STATUS_KINDS, ...JSON_KINDS].includes(assertion.kind)) fail('unsupported assertion kind');
  if (assertion.kind === 'status.equals') {
    shape(assertion, ['kind', 'expected']);
    if (!Number.isInteger(assertion.expected) || assertion.expected < 100 || assertion.expected > 599) fail('invalid expected HTTP status');
  } else if (assertion.kind === 'status.in') {
    shape(assertion, ['kind', 'expected']);
    const codes = assertion.expected;
    if (!Array.isArray(codes) || codes.length < 2 || codes.length > 5 || new Set(codes).size !== codes.length || !codes.every(code => Number.isInteger(code) && code >= 300 && code <= 599)) fail('status.in needs 2 to 5 distinct refusal or redirect statuses from 300 to 599');
  } else if (assertion.kind === FOREIGN_VALUES_KIND) {
    // No expected value: the values are the target's declared "tenantValues", however many there are.
    shape(assertion, ['kind', 'pointer']); pointerTokens(assertion.pointer);
  } else {
    if (assertion.kind === 'json.exists' && !Object.hasOwn(assertion, 'expected')) fail('unsupported or missing fields (missing field "expected"; json.exists needs "expected": true or false)');
    shape(assertion, ['kind', 'pointer', 'expected']); pointerTokens(assertion.pointer);
    if (assertion.kind === 'json.exists') { if (typeof assertion.expected !== 'boolean') fail('invalid existence predicate'); }
    else if (assertion.kind === 'json.equals') {
      if (!(assertion.expected === null || typeof assertion.expected === 'boolean' || (typeof assertion.expected === 'number' && Number.isFinite(assertion.expected)) || (typeof assertion.expected === 'string' && assertion.expected.length <= 8192))) fail('invalid equality predicate');
    } else if (typeof assertion.expected !== 'string' || assertion.expected.length < 1 || assertion.expected.length > 200) fail('invalid containment predicate');
  }
}

// Header API keys (H1 step 4): an actor's credential sent in a named request header (x-api-key, apikey) instead of
// Authorization: Bearer or a cookie. The name is an RFC 9110 token of at most 64 characters, compared case-insensitively
// against the names the connector, HTTP framing or a proxy owns: those are refused, so a key can never replace the Host,
// smuggle a cookie or an Authorization value, or alter how the request is framed or routed.
const HEADER_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/;
// Also refused: the trace-context names tracing propagates and exports (traceparent, tracestate, baggage), the method and
// URL override names a gateway or framework honours, and cookie setters.
export const RESERVED_CREDENTIAL_HEADERS = Object.freeze(['host', 'cookie', 'cookie2', 'set-cookie', 'set-cookie2', 'authorization', 'proxy-authorization', 'www-authenticate', 'transfer-encoding',
  'connection', 'keep-alive', 'upgrade', 'te', 'trailer', 'expect', 'accept', 'accept-encoding', 'origin', 'referer', 'forwarded', 'via', 'max-forwards', 'range', 'if-range',
  'traceparent', 'tracestate', 'baggage', 'x-http-method-override', 'x-http-method', 'x-method-override', 'x-original-url', 'x-rewrite-url', 'x-original-method']);
const RESERVED_CREDENTIAL_PREFIXES = Object.freeze(['proxy-', 'sec-', 'content-', 'x-forwarded-', 'x-real-ip', 'x-scopehaven-']);
// What a run keeps of its header API keys: for each actor some row of which sent its key in a header, the header name
// (lower case) and a domain-separated SHA-256 of the value, so a reader can tell which key a run used without the run
// holding it. A guessable key could be confirmed against it: use generated test keys.
export const CREDENTIAL_HEADER_DIGEST = 'scopehaven-credential-header/1';
const headerActorsOf = results => [...new Set(results.filter(r => r?.trace?.[0]?.data?.credentialMode === 'header').map(r => r.trace[0].data.actorId))];
export const credentialHeadersOf = (profile, results, credentials) => headerActorsOf(results).filter(alias => typeof profile.actors?.[alias]?.credentialHeader === 'string' && typeof credentials[alias] === 'string')
  .map(alias => { const header = profile.actors[alias].credentialHeader.toLowerCase(); return { actorId: alias, header, valueDigest: digest({ schema: CREDENTIAL_HEADER_DIGEST, header, value: credentials[alias] }) }; });
const validCredentialHeaders = run => {
  const actors = headerActorsOf(run.results);
  if (!Object.hasOwn(run, 'credentialHeaders')) return actors.length === 0;
  const keys = run.credentialHeaders;
  return Array.isArray(keys) && keys.length === actors.length && new Set(keys.map(k => k?.actorId)).size === keys.length && keys.every(k => record(k) && Object.keys(k).length === 3 && actors.includes(k.actorId)
    && typeof k.header === 'string' && k.header === k.header.toLowerCase() && credentialHeaderProblem(k.header) === null && typeof k.valueDigest === 'string' && /^[a-f0-9]{64}$/.test(k.valueDigest));
};
// null when the name can carry a credential, else why not. Never echoes the name.
export function credentialHeaderProblem(name) {
  if (typeof name !== 'string' || !HEADER_TOKEN.test(name)) return 'must be a header name: 1-64 letters, digits or !#$%&\'*+.^_`|~-';
  const lower = name.toLowerCase();
  if (RESERVED_CREDENTIAL_HEADERS.includes(lower) || RESERVED_CREDENTIAL_PREFIXES.some(prefix => lower.startsWith(prefix))) return 'names a header the connector, HTTP framing or a proxy owns (Host, Cookie, Authorization and the like); use a name such as x-api-key';
  return null;
}
// Every variable name a config refers to: the string (or each string of a list) under a key ending in "Env", at any depth.
function envReferences(config) {
  const names = [];
  for (const stack = [config]; stack.length;) {
    const value = stack.pop();
    if (value === null || typeof value !== 'object') continue;
    for (const [key, child] of Object.entries(value)) {
      if (/Env$/.test(key)) for (const name of Array.isArray(child) ? child : [child]) if (typeof name === 'string') names.push(name);
      if (child !== null && typeof child === 'object') stack.push(child);
    }
  }
  return names;
}
function validActor(alias, actor) {
  if (!identifier(alias) || UNSAFE_KEYS.includes(alias)) fail('invalid actor identity');
  shape(actor, ['principalId'], ['credentialEnv', 'credentialCookie', 'credentialHeader', 'identityValue', 'signInRedirectStatus', 'tenantId', 'role', 'refusesWith401']);
  if (!identifier(actor.principalId)) fail('invalid actor principal');
  if (Object.hasOwn(actor, 'credentialEnv') && (typeof actor.credentialEnv !== 'string' || !/^SCOPEHAVEN_TARGET_[A-Z0-9_]{1,110}$/.test(actor.credentialEnv))) fail('credential references must use the dedicated SCOPEHAVEN_TARGET_ namespace');
  if (Object.hasOwn(actor, 'credentialCookie')) {
    if (!Object.hasOwn(actor, 'credentialEnv')) fail('"credentialCookie" needs a "credentialEnv" reference for its value');
    if (typeof actor.credentialCookie !== 'string' || !COOKIE_NAME_PATTERN.test(actor.credentialCookie)) fail('"credentialCookie" must be a cookie name (RFC 6265 token, up to 128 characters)');
  }
  // The value comes only from credentialEnv (a SCOPEHAVEN_TARGET_ variable), never from the profile.
  if (Object.hasOwn(actor, 'credentialHeader')) {
    if (!Object.hasOwn(actor, 'credentialEnv')) fail('"credentialHeader" needs a "credentialEnv" reference for its value');
    if (Object.hasOwn(actor, 'credentialCookie')) fail('an actor sends its credential as a cookie or in a header, not both');
    const problem = credentialHeaderProblem(actor.credentialHeader);
    if (problem) fail(`"credentialHeader" ${problem}`);
  }
  // identityValue: the value a "who am I" control must return for this login
  // (for example the user's email), checked with json.equals. It is the only
  // way a credentialed actor's login can be established.
  if (Object.hasOwn(actor, 'identityValue')) {
    if (!Object.hasOwn(actor, 'credentialEnv')) fail('"identityValue" needs a "credentialEnv" reference');
    text(actor.identityValue, 200, '"identityValue" must be a nonempty string up to 200 characters');
  }
  // A redirect status the target uses to send signed-out requests to sign-in.
  if (Object.hasOwn(actor, 'signInRedirectStatus')) {
    if (!Object.hasOwn(actor, 'credentialEnv')) fail('"signInRedirectStatus" needs a "credentialEnv" reference');
    if (![301, 302, 303, 307, 308].includes(actor.signInRedirectStatus)) fail('"signInRedirectStatus" must be 301, 302, 303, 307 or 308');
  }
  // refusesWith401: the application answers this actor's authorization denials with 401 (Open WebUI does), so a 401
  // counts as a refusal, but only while a surface control brackets the actor's checks (actor-identity/4).
  if (Object.hasOwn(actor, 'refusesWith401') && (actor.refusesWith401 !== true || !Object.hasOwn(actor, 'credentialEnv'))) fail('"refusesWith401" is true on an actor with a "credentialEnv", or absent');
  if (Object.hasOwn(actor, 'tenantId') && !identifier(actor.tenantId)) fail('invalid actor tenant');
  if (Object.hasOwn(actor, 'role')) text(actor.role, 80, 'invalid actor role');
}
// Does a claim rule (already shape-checked by validateDeclaredClaims) declare any refusal sentence or value?
const declaresRefusal = claim => (Object.values(claim.trigger)[0].refusal ?? []).length > 0;
function validCheck(check, target, checkIds) {
  shape(check, ['id', 'title', 'category', 'severity', 'actorId', 'method', 'path', 'evidenceRequirement', 'assertions'], ['body', 'applicability', 'timeoutMs', 'effects', 'claims', 'capture', 'precondition', 'restsOn', 'webhook', 'mirrorOf', 'readBack']);
  // Effects: what the declared observers must (not) see while this check runs.
  if (Object.hasOwn(check, 'effects')) within('"effects"', () => {
    if (!Object.hasOwn(target, 'observers')) fail('effects need the target to declare "observers" (an empty list is allowed and reads unobservable)');
    if (!Array.isArray(check.effects) || check.effects.length < 1 || check.effects.length > MAX_EFFECTS) fail(`effects must list 1 to ${MAX_EFFECTS} effect assertions`);
    // effect.none / effect.exists / effect.count, or effect.only (integrations/collateral/only.mjs): its codes name a
    // name-free selector (selector-name), a count below 1 (expect-count) and an unknown key (field, expect, selector).
    check.effects.forEach((effect, index) => within(`effect ${index + 1}`, () => { jsonValue(effect); try { validateDeclaredEffect(effect); } catch (error) { fail(`invalid effect assertion (${error.code || 'shape'})`); } }));
    // In-doubt resolution, gate A: no effect.only outcome-judged selector overlaps an absence of this check: an effect.none, or a refusal
    // claim read as an attempt (src/http-effects.mjs).
    try { validateCheckEffects(check.effects, Array.isArray(check.claims) ? check.claims : []); } catch (error) { fail(`invalid effect assertion (${error.code || 'shape'})`); }
    // An allowed-use control that declares effects must prove one positively (positiveClause: effect.exists, or effect.count expecting
    // at least one). effect.none, effect.count 0 and effect.only (whose expect is a ceiling) pass when nothing happened, so with only
    // those an app that answered and did nothing established the actor and released its boundary rows. A control with no effect
    // clauses rests on its response, as before.
    if (check.severity === 'control' && !check.effects.some(positiveClause)) fail('allowed-use controls that declare effects need a positive one (effect.exists, or effect.count expecting at least 1): effect.none, effect.count 0 and effect.only pass when nothing happened');
  });
  // Claim rules (src/http-claims.mjs): the response's claim selects which records requirement applies; the observers decide it.
  // Read-back (src/http-readback.mjs): the pg-snapshot tables whose declared read-back judges this check (fail-only on a boundary).
  if (Object.hasOwn(check, 'readBack')) within('"readBack"', () => {
    if (!Object.hasOwn(target, 'observers')) fail('readBack needs the target to declare "observers"');
    const problem = readBackProblem(target, check); if (problem) fail(problem);
  });
  if (Object.hasOwn(check, 'claims')) within('"claims"', () => {
    if (!Object.hasOwn(target, 'observers')) fail('claims need the target to declare "observers" (the records decide every claim)');
    jsonValue(check.claims);
    try { validateDeclaredClaims(check.claims); } catch (error) { fail(error.message); }
    // An allowed-use control proves its use works, so its claim rules declare success only. A declared refusal would pass the
    // control on an honest refusal (no effect, as claimed) and let an app that refuses everything establish the actor.
    // Undeclared, a refusal reply reads ambiguous (text), unreadable (a field value not declared) or untriggered (field pointer
    // absent), each inconclusive; a field claim declared "no-requirement" adds nothing then, and the control rests on its own assertions.
    if (check.severity === 'control' && check.claims.some(declaresRefusal)) fail('allowed-use controls declare claim rules with success only (a refusal never passes a control)');
  });
  if (Object.hasOwn(check, 'applicability')) within('"applicability"', () => {
    shape(check.applicability, ['applies', 'reason']);
    if (typeof check.applicability.applies !== 'boolean') fail('invalid applicability declaration');
    text(check.applicability.reason, 300, 'applicability needs a bounded reason');
  });
  if (!identifier(check.id) || checkIds.has(check.id)) fail('invalid or duplicate check identity'); checkIds.add(check.id);
  text(check.title, 200, 'invalid check title'); text(check.category, 80, 'invalid check category');
  if (!['critical', 'high', 'medium', 'low', 'control'].includes(check.severity)) fail('invalid check configuration ("severity" must be critical, high, medium, low or control)');
  if (!identifier(check.actorId) || !Object.hasOwn(target.actors, check.actorId)) fail('invalid check configuration ("actorId" must name a declared actor)');
  if (!HTTP_CHECK_METHODS.includes(check.method)) fail('invalid check configuration ("method" must be GET, POST, PUT, PATCH or DELETE)');
  if (!['response', 'backend'].includes(check.evidenceRequirement)) fail('invalid check configuration ("evidenceRequirement" must be response or backend)');
  within('"path"', () => validPath(check.path));
  if (Object.hasOwn(check, 'timeoutMs') && !(Number.isInteger(check.timeoutMs) && check.timeoutMs >= CHECK_TIMEOUT_BOUNDS.minimumMs && check.timeoutMs <= CHECK_TIMEOUT_BOUNDS.maximumMs)) fail(`"timeoutMs" must be an integer from ${CHECK_TIMEOUT_BOUNDS.minimumMs} to ${CHECK_TIMEOUT_BOUNDS.maximumMs}`);
  if (Object.hasOwn(check, 'body')) within('"body"', () => {
    if (!HTTP_WRITE_METHODS.includes(check.method) || !object(check.body)) fail('body requires POST, PUT, PATCH or DELETE and a JSON object');
    jsonValue(check.body);
    if (Buffer.byteLength(JSON.stringify(check.body)) > 8192) fail('request body exceeds bounds');
  });
  // A signed provider webhook (src/webhook-driver.mjs): its rules, and its body encoded once to check its bounds.
  if (Object.hasOwn(check, 'webhook')) within('"webhook"', () => { try { validateWebhookDeclaration(check.webhook, check); } catch (error) { fail(error.message); } });
  if (!Array.isArray(check.assertions) || check.assertions.length < 1 || check.assertions.length > PROFILE_LIMITS.assertions) fail('invalid assertion set');
  check.assertions.forEach((assertion, index) => within(`assertion ${index + 1}${[...STATUS_KINDS, ...JSON_KINDS].includes(assertion?.kind) ? ` (${assertion.kind})` : ''}`, () => validAssertion(assertion)));
  if (check.assertions.filter(assertion => STATUS_KINDS.includes(assertion.kind)).length !== 1) fail('one expected HTTP status is required (status.equals or status.in)');
  if (check.severity === 'control' && check.assertions.some(assertion => assertion.kind === 'status.in')) fail('allowed-use controls need one exact status (status.equals), not status.in');
  // json.noForeignValues reads the target's declared tenant values for the check actor's tenant (src/tenant-values.mjs).
  const foreign = check.assertions.filter(assertion => assertion.kind === FOREIGN_VALUES_KIND);
  if (foreign.length) {
    if (!Object.hasOwn(target, 'tenantValues')) fail('"json.noForeignValues" needs the target to declare "tenantValues"');
    const tenantId = target.actors[check.actorId].tenantId;
    if (tenantId === undefined) fail('"json.noForeignValues" needs the check\'s actor to declare "tenantId"');
    if (!Object.hasOwn(target.tenantValues.tenants, tenantId)) fail('"json.noForeignValues" needs the check\'s actor "tenantId" to be one of the tenants in "tenantValues"');
    if (new Set(foreign.map(assertion => assertion.pointer)).size !== foreign.length) fail('at most one "json.noForeignValues" per pointer in a check');
  }
  // A credentialed actor's controls prove its login worked, so they must expect success.
  if (check.severity === 'control' && target.actors[check.actorId].credentialEnv && !check.assertions.some(assertion => assertion.kind === 'status.equals' && assertion.expected >= 200 && assertion.expected <= 299)) fail('allowed-use controls of a credentialed actor need a 2xx status.equals');
}
// Typed captures and the lifecycle phase (src/http-captures.mjs, src/http-lifecycle.mjs), checked once
// every check and required control is valid. Both modules throw plain errors; the message names the rule.
function validateCapturesAndLifecycle(target) {
  const plan = identityControlPlan(target);
  const identityIds = new Set([...plan.values()].flatMap(p => p.identityControls)), surfaceIds = new Set([...plan.values()].flatMap(p => p.surfaceControls));
  try { validateCaptureDeclarations(target, identityIds, (check, index, run) => within(named('check', check?.id, index), () => { try { run(); } catch (error) { if (error instanceof ContractValidationError) throw error; fail(error.message); } }), pointerTokens, surfaceIds); }
  catch (error) { if (error instanceof ContractValidationError) throw error; fail(error.message); }
  if (Object.hasOwn(target, 'lifecycle')) within('"lifecycle"', () => {
    try { validateLifecycle(target, actorId => plan.get(actorId)?.identityControls ?? [], (entry, index, run) => within(`entry ${index + 1}`, () => { try { run(); } catch (error) { if (error instanceof ContractValidationError) throw error; fail(error.message); } }), actorId => plan.get(actorId)?.surfaceControls ?? []); }
    catch (error) { if (error instanceof ContractValidationError) throw error; fail(error.message); }
  });
}
// Correlation and the settlement mode (src/http-settlement.mjs, src/egress-rules.mjs), checked once observers and checks are valid.
//   correlation: { header }   the header the connector sets on every sent check request (traceparent or x-<name>);
//                             at least one egress-recorder destination records it, and every destination
//                             correlation names it
//   settlement: { mode, outsideWindow? }
//                             mode: "run" (the default) or "per-check", which needs correlation and adds one barrier
//                             (the largest declared settle) per applicable check with effects or claim rules, at most
//                             600000 ms in all. outsideWindow: "judge" only (settlement-outside-window), judged late
//                             effects for effect.only, countBy included (src/http-settlement.mjs); refused when no applicable
//                             check declares an effect.only clause (settlement-judge-unused), since it would change nothing
// Every selector one effect clause names: its select, or an effect.only clause's expected and allowed selectors.
const clauseSelectors = e => !object(e) ? [] : e.kind === 'effect.only'
  ? [...(Array.isArray(e.expect) ? e.expect : []).map(item => object(item) && Object.hasOwn(item, 'select') ? item.select : item), ...(Array.isArray(e.allow) ? e.allow : [])]
  : [e.select];
// Keyed retries (src/idempotency.mjs): a countBy clause names an exact host every egress-recorder destination of which declares
// "idempotency" (an effect.only countBy clause needs one such destination, and reads keys only where they are recorded), and no key
// header is the target's correlation header (the application writes that one per request).
function validateIdempotency(target) {
  const destinations = (target.observers ?? []).filter(o => o?.type === 'egress-recorder').flatMap(o => Array.isArray(o.destinations) ? o.destinations : []);
  within('"idempotency"', () => {
    if (destinations.some(d => object(d?.idempotency) && typeof d.idempotency.header === 'string' && d.idempotency.header === target.correlation?.header)) fail('idempotency-key-header-is-correlation: a key header cannot be the target\'s correlation header');
    // Verified signature headers (src/idempotency.mjs): no signing header is the target's correlation header (the application writes
    // that one per request), and one recorder declares at most SIGNING_BOUNDS.secretsPerRecorder secrets.
    const correlation = typeof target.correlation?.header === 'string' ? target.correlation.header.toLowerCase() : null;
    if (correlation !== null && destinations.some(d => object(d?.idempotency?.signing) && [d.idempotency.signing.signature, d.idempotency.signing.timestamp, d.idempotency.signing.id].includes(correlation))) fail('idempotency-signing-header-is-correlation: a signature, timestamp or id header cannot be the target\'s correlation header');
    for (const o of (target.observers ?? []).filter(x => x?.type === 'egress-recorder' && Array.isArray(x.destinations))) {
      const secrets = o.destinations.reduce((n, d) => n + (Array.isArray(d?.idempotency?.signing?.secretEnv) ? d.idempotency.signing.secretEnv.length : 0), 0);
      if (secrets > SIGNING_BOUNDS.secretsPerRecorder) fail(`idempotency-signing-secrets: an egress recorder declares at most ${SIGNING_BOUNDS.secretsPerRecorder} signing secrets`);
    }
  });
  (target.checks ?? []).forEach((check, index) => within(named('check', check?.id, index), () => {
    for (const e of Array.isArray(check?.effects) ? check.effects : []) {
      if (!object(e) || e.countBy === undefined) continue;
      if (e.kind === 'effect.only') { if (!destinations.some(d => d?.idempotency !== undefined)) fail('effect-only-count-by-unrecorded: an effect.only "countBy" clause needs an egress-recorder destination that declares "idempotency"'); continue; }
      const same = destinations.filter(d => d?.host === e.select?.name);
      if (!same.length || !same.every(d => d.idempotency !== undefined)) fail('effect-count-by-unrecorded: a "countBy" clause names an egress-recorder destination host that declares "idempotency"');
    }
  }));
}
// In-doubt resolution, gate A (integrations/collateral/only.mjs outcomeJudgedProfileProblem; IN-DOUBT-LEAD-RULING-IDR0 R-1 and R-3): every
// effect.only outcome-judged selector names a forwarded egress-recorder host whose destinations declare its route as an object route
// (src/egress-rules.mjs objectPaths, objectFields) and binds every declared identifier, and no selector overlaps an absence of the check
// on its host or on a host forwarded to the same upstream.
function validateOutcomeJudged(target) {
  const destinations = (target.observers ?? []).filter(o => o?.type === 'egress-recorder').flatMap(o => { try { return validateEgressConfig(o, target.actors).destinations; } catch { return []; } });
  (target.checks ?? []).forEach((check, index) => within(named('check', check?.id, index), () => {
    const forbidden = forbiddenSelectors(Array.isArray(check?.effects) ? check.effects : [], Array.isArray(check?.claims) ? check.claims : []);
    for (const e of Array.isArray(check?.effects) ? check.effects : []) if (object(e) && e.outcomeJudged !== undefined) { const problem = outcomeJudgedProfileProblem(e, destinations, forbidden); if (problem) fail(problem); }
  }));
}
function validateCorrelation(target) {
  if (Object.hasOwn(target, 'correlation')) within('"correlation"', () => {
    if (!object(target.correlation) || Object.keys(target.correlation).length !== 1 || !correlationHeaderValid(target.correlation.header)) fail(`correlation is { header }: ${CORRELATION_HEADER_RULE}`);
  });
  const destinations = (target.observers ?? []).filter(o => o.type === 'egress-recorder').flatMap(o => o.destinations.filter(d => d.correlation !== undefined));
  within('"correlation"', () => {
    if (Object.hasOwn(target, 'correlation') && !destinations.length) fail('a correlation header needs at least one egress-recorder destination that records it ("correlation": { "header" } on the destination)');
    if (!Object.hasOwn(target, 'correlation') && destinations.length) fail('a destination "correlation" needs the target\'s own "correlation" header');
    if (destinations.some(d => d.correlation.header !== target.correlation.header)) fail('every destination "correlation" names the target\'s correlation header');
  });
  // The recorded token is the application's own value, kept in a key no selector reads (src/effect-events.mjs). A traceId
  // selector that an egress recorder could see would read as if it selected that token, and select nothing instead,
  // so a correlated target refuses it: correlation-token-not-selectable. A claim rule's selector (src/http-claims.mjs) is
  // read as an effect clause's, so it is refused the same way.
  if (Object.hasOwn(target, 'correlation')) (target.checks ?? []).forEach((check, index) => within(named('check', check?.id, index), () => {
    for (const select of [...(Array.isArray(check?.effects) ? check.effects : []).flatMap(clauseSelectors), ...(Array.isArray(check?.claims) ? check.claims : []).map(c => object(c) ? c.select : undefined)]) {
      if (object(select) && Object.hasOwn(select, 'traceId') && (select.source === undefined || select.source === 'http-egress')) fail('correlation-token-not-selectable: a correlated target refuses a "traceId" selector an egress recorder could see (give a source other than http-egress); the recorded token is never selectable');
    }
  }));
  if (Object.hasOwn(target, 'settlement')) within('"settlement"', () => {
    shape(target.settlement, ['mode'], ['outsideWindow']);
    if (!SETTLEMENT_MODES.includes(target.settlement.mode)) fail(`"mode" must be one of ${SETTLEMENT_MODES.join(', ')}`);
    if (Object.hasOwn(target.settlement, 'outsideWindow')) {
      if (!SETTLEMENT_OUTSIDE_WINDOW.includes(target.settlement.outsideWindow)) fail(`settlement-outside-window: "outsideWindow" must be ${SETTLEMENT_OUTSIDE_WINDOW.map(v => `"${v}"`).join(' or ')}`);
      if (!target.checks.some(c => c.applicability?.applies !== false && Array.isArray(c.effects) && c.effects.some(e => object(e) && e.kind === 'effect.only'))) fail('settlement-judge-unused: "outsideWindow": "judge" re-judges effect.only clauses only, and no applicable check declares one');
    }
    if (target.settlement.mode !== 'per-check') return;
    if (!Object.hasOwn(target, 'correlation')) fail('settlement-per-check-needs-correlation: per-check settlement needs a declared "correlation" header');
    const settle = Math.max(0, ...(target.observers ?? []).map(o => settleDeclared(o.settleMs) ? o.settleMs : 0));
    if (settle * target.checks.filter(c => (c.effects || c.claims) && c.applicability?.applies !== false).length > PER_CHECK_BARRIER_LIMIT_MS) fail(`per-check barriers (the largest settleMs times the checks with effects or claim rules) exceed ${PER_CHECK_BARRIER_LIMIT_MS} ms`);
  });
}
// effect.only "allowBackground": ["<background source id>"] (APP-LOG-1C-DESIGN.md item d). At the custody tier it reads exactly as
// the shape-only allow an operator writes today: each named source is appended to the clause's allow as its select without the
// actor pin (src/app-log-rules.mjs backgroundAllowSelect), and the key itself is removed, so every custody path (decide, settle,
// attribute, pair) and only.mjs see plain allow entries. When the target declares an app log, the appended entries are recorded on
// it (appLogs[0].backgroundAllows: { check, effect, allow, source }) so admissions never let one excuse the check's own actor.
// A target without the key is returned as is; one already normalized has none, so validating it again changes nothing.
function normalizeAllowBackground(target) {
  const has = e => e !== null && typeof e === 'object' && !Array.isArray(e) && Object.hasOwn(e, 'allowBackground');
  if (!object(target) || !Array.isArray(target.checks) || !target.checks.some(c => Array.isArray(c?.effects) && c.effects.some(has))) return target;
  const t = structuredClone(target);
  const sources = Array.isArray(t.attribution?.background) ? t.attribution.background : [];
  const marks = [];
  t.checks.forEach((check, ci) => (Array.isArray(check?.effects) ? check.effects : []).forEach((e, ei) => {
    if (!has(e)) return;
    within(named('check', check?.id, ci), () => within('"effects"', () => within(`effect ${ei + 1}`, () => {
      const ids = e.allowBackground;
      if (e.kind !== 'effect.only' || !Array.isArray(ids) || ids.length < 1 || ids.length > 8 || new Set(ids).size !== ids.length || !ids.every(id => typeof id === 'string' && sources.some(s => s?.id === id && object(s.select))))
        fail('"allowBackground" (effect.only only) lists 1 to 8 distinct ids of declared background sources ("attribution": { "background" })');
      const { allowBackground, ...clause } = e;
      const base = Array.isArray(clause.allow) ? clause.allow : [];
      clause.allow = [...base, ...ids.map(id => backgroundAllowSelect(sources.find(s => s.id === id)))];
      check.effects[ei] = clause;
      ids.forEach((id, j) => marks.push({ check: check.id, effect: ei, allow: base.length + j, source: id }));
    })));
  }));
  if (Array.isArray(t.appLogs) && object(t.appLogs[0])) t.appLogs[0] = { ...t.appLogs[0], backgroundAllows: [...(Array.isArray(t.appLogs[0].backgroundAllows) ? t.appLogs[0].backgroundAllows : []), ...marks] };
  return t;
}

// Background attribution (src/http-attribution.mjs): { background: [{ id, select }] }, checked once observers and checks are
// valid. Protection that would silently be off is refused: no observers, no applicable check with effects or claim rules,
// or an applicable write check without them (its effects would have no window and no selector, so a later check's clause
// could rest on them: attribution-unobserved-write).
function validateAttribution(target) {
  if (!Object.hasOwn(target, 'attribution')) return;
  within('"attribution"', () => {
    const problem = attributionDeclarationProblem(target.attribution);
    if (problem) fail(problem);
    // Coverage v2 Part C: an egress resource pin names a resource every egress-recorder destination for that exact host can
    // produce: "<METHOD> <one of its declared paths>", or "<METHOD> *" (a path outside them; the only resource of a destination
    // that declares no paths).
    const destinations = (target.observers ?? []).filter(o => o?.type === 'egress-recorder').flatMap(o => Array.isArray(o.destinations) ? o.destinations : []);
    target.attribution.background.forEach((source, i) => {
      if (!Object.hasOwn(source.select, 'resource')) return;
      const same = destinations.filter(d => d?.host === source.select.name), path = source.select.resource.slice(source.select.resource.indexOf(' ') + 1);
      if (!same.length || !same.every(d => path === '*' || (Array.isArray(d.paths) && d.paths.includes(path))))
        fail(`attribution-resource-unproducible: background source ${i + 1}'s resource is not one its host's egress-recorder destinations produce ("<METHOD> <declared path>" or "<METHOD> *")`);
    });
    if (!Array.isArray(target.observers) || !target.observers.length) fail('attribution-needs-observers: background attribution needs declared observers');
    if (!target.checks.some(c => (c.effects || c.claims) && c.applicability?.applies !== false)) fail('attribution-needs-observed-check: background attribution needs an applicable check with effects or claim rules');
  });
  target.checks.forEach((check, index) => within(named('check', check?.id, index), () => {
    if (check.applicability?.applies !== false && HTTP_WRITE_METHODS.includes(check.method) && !check.effects && !check.claims) fail('attribution-unobserved-write: with background attribution declared, an applicable write check declares effects or claim rules');
  }));
}
// The database observers' background-writer options (N12; integrations/observers/{ignore-lists/ignore-list.mjs,end-barrier.mjs,
// run-lease.mjs}), as a pg-snapshot or pg-wal observer declares them (NC9 item 4): platform names a checked-in ignore list, ignore adds
// "schema" or "schema.table" entries, queues are job tables the end barrier waits on, and runLease holds one run per database. The
// forms are checked here; the observer refuses an ignore entry that names an observed table or a queue, and a queue of the wrong
// kind, when it is built.
const PG_BACKGROUND_KEYS = Object.freeze(['platform', 'ignore', 'queues', 'drainTimeoutMs', 'pollMs', 'runLease']);
function pgBackgroundProblem(o) {
  const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
  if (o.platform !== undefined && !(typeof o.platform === 'string' && ['none', 'supabase'].includes(o.platform))) return '"platform" is "none" or "supabase" (a checked-in Postgres ignore list)';
  if (o.ignore !== undefined && !(Array.isArray(o.ignore) && o.ignore.length <= 64 && o.ignore.every(e => typeof e === 'string' && e.split('.').length <= 2 && e.split('.').every(part => IDENT.test(part))))) return '"ignore" lists at most 64 "schema" or "schema.table" entries';
  if (o.queues !== undefined && !(Array.isArray(o.queues) && o.queues.length >= 1 && o.queues.length <= 8 && o.queues.every(object))) return '"queues" lists 1 to 8 job tables { table, schema?, pending? }';
  if (o.drainTimeoutMs !== undefined && !(Number.isInteger(o.drainTimeoutMs) && o.drainTimeoutMs >= 0 && o.drainTimeoutMs <= 120000)) return '"drainTimeoutMs" must be an integer from 0 to 120000';
  if (o.pollMs !== undefined && !(Number.isInteger(o.pollMs) && o.pollMs >= 20 && o.pollMs <= 5000)) return '"pollMs" must be an integer from 20 to 5000';
  if ((o.drainTimeoutMs !== undefined || o.pollMs !== undefined) && o.queues === undefined) return '"drainTimeoutMs" and "pollMs" are the end barrier\'s: declare "queues"';
  if (o.runLease !== undefined && typeof o.runLease !== 'boolean') return '"runLease" is true or false';
  return null;
}
// Supabase identity rules (integrations/observers/supabase-rules.mjs, NC2 item 3; wired in NC9 item 3): { tool, serviceRoles?,
// passThrough?, allowedWrites? }, read over a declared actor capture. tool names the server-side identity whose service-role writes
// are never an end user's; serviceRoles (default service_role, postgres, supabase_admin) and passThrough are the resolver's. allowedWrites
// maps an allowed-use control that writes to the write it should make ({ "table": "schema.table", "op": "UPDATE" | "DELETE" }): a table
// exactly one observer's capture declares and that observer reads, judged on the control's own positive clause on that write
// (src/http-effects.mjs zeroRowClause), FAIL-only (rls-zero-row).
const SUPABASE_RULE_KEYS = Object.freeze(['tool', 'serviceRoles', 'passThrough', 'allowedWrites']);
// The zero-row declaration of one check (rls-zero-row; src/http-effects.mjs): { table, op, instanceId } for an allowed-use control in
// supabaseRules.allowedWrites, the capturing pg-snapshot observer's instance named, else null. The connector seals the record on
// exactly these rows, the exported suite carries it (src/registry.mjs), and the validator requires the record where it is declared.
export function zeroRowDeclaration(target, check) {
  const writes = target?.supabaseRules?.allowedWrites;
  if (!object(writes) || !Object.hasOwn(writes, check?.id)) return null;
  const expect = writes[check.id];
  const owner = (Array.isArray(target.observers) ? target.observers : []).find(o => o?.type === 'pg-snapshot' && Array.isArray(o.actorCapture?.block?.tables) && o.actorCapture.block.tables.some(t => `${t.schema ?? 'public'}.${t.table}` === expect.table));
  return owner ? { table: expect.table, op: expect.op, instanceId: observerInstanceId(owner.type, owner.id) } : null;
}
function supabaseRulesProblem(target) {
  const r = target.supabaseRules, IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
  if (!object(r) || Object.keys(r).some(key => !SUPABASE_RULE_KEYS.includes(key))) return 'is { tool, serviceRoles?, passThrough?, allowedWrites? }';
  if (typeof r.tool !== 'string' || !/^[A-Za-z0-9_-]{1,80}$/.test(r.tool)) return '"tool" names the server-side identity: 1-80 letters, digits, "_" or "-"';
  if (r.serviceRoles !== undefined && !(Array.isArray(r.serviceRoles) && r.serviceRoles.length >= 1 && r.serviceRoles.length <= 8 && r.serviceRoles.every(role => typeof role === 'string' && IDENT.test(role)) && new Set(r.serviceRoles).size === r.serviceRoles.length)) return '"serviceRoles" lists 1 to 8 distinct role names';
  const captures = (Array.isArray(target.observers) ? target.observers : []).filter(o => object(o) && ['pg-snapshot', 'pg-wal'].includes(o.type) && object(o.actorCapture) && object(o.actorCapture.block) && Array.isArray(o.actorCapture.block.tables));
  if (!captures.length) return 'the rules read the actor capture: declare "actorCapture" on a pg-snapshot or pg-wal observer';
  const captured = captures.flatMap(o => o.actorCapture.block.tables.filter(object).map(t => ({ o, t, name: `${t.schema ?? 'public'}.${t.table}` })));
  if (r.passThrough !== undefined) {
    if (!object(r.passThrough) || Object.keys(r.passThrough).length !== 1 || !['jwt-claims', 'column'].includes(r.passThrough.from)) return '"passThrough" is { "from": "jwt-claims" } or { "from": "column" }';
    if (r.passThrough.from === 'column' && captured.some(c => c.t.actorColumn === undefined)) return '"passThrough" from "column" needs every captured table\'s "actorColumn"';
  }
  if (r.allowedWrites === undefined) return null;
  if (!object(r.allowedWrites) || Object.keys(r.allowedWrites).length > 64) return '"allowedWrites" maps up to 64 control ids to { table, op }';
  const checks = Array.isArray(target.checks) ? target.checks : [];
  for (const [id, w] of Object.entries(r.allowedWrites)) {
    const check = checks.find(c => object(c) && c.id === id);
    if (!check || check.severity !== 'control' || !HTTP_WRITE_METHODS.includes(check.method)) return 'an "allowedWrites" key names an allowed-use control that writes (severity "control", POST, PUT, PATCH or DELETE)';
    if (!object(w) || Object.keys(w).length !== 2 || typeof w.table !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,62}\.[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(w.table) || !['UPDATE', 'DELETE'].includes(w.op)) return 'an "allowedWrites" entry is { "table": "schema.table", "op": "UPDATE" | "DELETE" }';
    // rls-zero-row reads a pg-snapshot capture's window (pg-snapshot zeroRowFacts); a pg-wal capture names actors only.
    const owners = captured.filter(c => c.name === w.table && c.o.type === 'pg-snapshot');
    if (owners.length !== 1) return 'an "allowedWrites" table is captured by exactly one pg-snapshot observer\'s actor capture';
    const [schema, table] = w.table.split('.');
    if (!(Array.isArray(owners[0].o.tables) && owners[0].o.tables.some(t => object(t) && t.table === table && (t.schema ?? 'public') === schema))) return 'an "allowedWrites" table is one its capturing observer reads';
    // The rule can fire only where the capture names a zero-row statement's actor as the control's principal (PR520 review MINOR 2): the
    // claims or the session's role, not an app column (a statement that changed no row records none), the control's actor credentialed
    // (a request without a credential carries no claims), and its principal one the capture maps.
    const block = owners[0].o.actorCapture.block, actor = object(target.actors) ? target.actors[check.actorId] : undefined;
    if (!object(block.actor) || !['jwt-claims', 'current-user'].includes(block.actor.from)) return 'an "allowedWrites" capture names its actors from "jwt-claims" or "current-user" (a statement that changed no row records no app column)';
    if (!object(actor) || typeof actor.credentialEnv !== 'string') return 'an "allowedWrites" control\'s actor is credentialed (a request without a credential carries no claims)';
    if (!object(block.principals) || !Object.values(block.principals).includes(actor.principalId)) return 'an "allowedWrites" control\'s principal is one its capture maps ("principals")';
    if (!(Array.isArray(check.effects) && check.effects.some(e => zeroRowClause(e, table, w.op)))) return 'an "allowedWrites" control declares a positive clause on its write: effect.exists, or effect.count of at least 1, selecting source "sql-snapshot", the table\'s name and the operation';
  }
  return null;
}
// Actor capture on a Postgres observer (integrations/observers/pg-actor.mjs, NC2 item 2), opt-in: { block, installedSha256 }, the
// capture an operator installed on the test copy (pg-actor installActorCapture, with the block's superuser credential) and the digest
// that installation recorded. Each mark verifies the installed definitions against that digest, and only an intact capture names
// anyone. The block's own rules (its tables, actor source and schema) are its module's, checked when the observer is built; the parts
// a verdict reads are checked here: every principal it names is a declared actor's, and the install credential is a SCOPEHAVEN_TARGET_
// variable that is neither the observer's own nor an actor's (it installs and removes, never observes or acts).
// The platform schemas a capture never takes (integrations/observers/pg-actor.mjs PLATFORM_SCHEMAS, kept equal by a test).
export const ACTOR_PLATFORM_SCHEMAS = Object.freeze(['public', 'auth', 'storage', 'extensions', 'realtime', '_realtime', 'graphql', 'graphql_public', 'vault', 'net', 'cron', 'pgbouncer', 'pgsodium', 'pgsodium_masks', 'supabase_functions', 'supabase_migrations', 'information_schema']);
function actorCaptureProblem(capture, actors, observerCredentialEnv) {
  if (!object(capture) || Object.keys(capture).some(key => !['block', 'installedSha256'].includes(key)) || !object(capture.block)) return '"actorCapture" is { block, installedSha256 }: the installed capture\'s profile block and the digest its installation recorded';
  if (typeof capture.installedSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(capture.installedSha256)) return '"actorCapture" "installedSha256" is the 64 lowercase hex digest its installation recorded';
  // Three of the capture's own block rules, mirrored so check-config refuses what assess would (PR518 review NIT 2): a disposable copy,
  // a schema of its own, and an actor column on every table when the column names the actor.
  if (capture.block.testCopy !== true) return '"actorCapture" "testCopy": true is required: the installation changes the database\'s schema, so it runs on a disposable copy only';
  if (capture.block.schema !== undefined && !(typeof capture.block.schema === 'string' && /^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(capture.block.schema) && !/^pg_/i.test(capture.block.schema) && !ACTOR_PLATFORM_SCHEMAS.includes(capture.block.schema.toLowerCase()))) return '"actorCapture" "schema" is a plain identifier of a schema of its own (not pg_* or a platform schema)';
  if (object(capture.block.actor) && capture.block.actor.from === 'column' && !(Array.isArray(capture.block.tables) && capture.block.tables.every(t => object(t) && t.actorColumn !== undefined))) return '"actorCapture" "actor" from "column" needs every table\'s "actorColumn"';
  const declared = new Set(Object.values(object(actors) ? actors : {}).map(a => a?.principalId));
  if (!object(capture.block.principals) || Object.keys(capture.block.principals).length < 1 || Object.values(capture.block.principals).some(principal => typeof principal !== 'string' || !declared.has(principal))) return '"actorCapture" "principals" maps each value its source reads to the principalId of a declared actor';
  const install = capture.block.installCredentialEnv;
  if (typeof install !== 'string' || !CREDENTIAL_ENV.test(install)) return '"actorCapture" "installCredentialEnv" names a SCOPEHAVEN_TARGET_ variable (a superuser of the test copy)';
  if (install === observerCredentialEnv || Object.values(object(actors) ? actors : {}).some(a => a?.credentialEnv === install)) return '"actorCapture" "installCredentialEnv" is the install role\'s own, never the observer\'s or an actor\'s credential';
  return null;
}
export function validateTargetFile(input) {
  try {
    shape(input, ['schemaVersion', 'targets']);
    if (input.schemaVersion !== 1 || !Array.isArray(input.targets) || input.targets.length < 1 || input.targets.length > 20) fail('invalid target manifest');
    const targetIds = new Set();
    // One target's rules. A target with generated mirrors (src/two-identities.mjs) is checked again with them, as one profile.
    const validTarget = (declaredTarget, targetIds) => {
      // effect.only "allowBackground" becomes plain allow entries before any clause is read (normalizeAllowBackground).
      const target = normalizeAllowBackground(declaredTarget);
      shape(target, ['id', 'name', 'applicationId', 'origin', 'buildLabel', 'contextId', 'actors', 'requiredControlIds', 'checks'], ['observers', 'targetContext', 'targetLabel', 'lifecycle', 'correlation', 'settlement', 'attribution', 'timing', 'tenantValues', 'appLogs', 'channels', 'mirrors', 'supabaseRules']);
      // Target context: a local app, staging reached through an operator-run forwarder listening on the loopback
      // origin (the connector still dials only 127.0.0.1), or an https origin reached directly (operator-remote, H1
      // step 3: only under an authorization record naming it, DNS pinned, src/remote-target.mjs).
      within('"targetContext"', () => { if (Object.hasOwn(target, 'targetContext') && !TARGET_CONTEXTS.includes(target.targetContext)) fail(`must be one of ${TARGET_CONTEXTS.join(', ')}`); });
      if (Object.hasOwn(target, 'targetLabel')) within('"targetLabel"', () => {
        if (!LABELLED_CONTEXTS.includes(target.targetContext)) fail('a label names an operator-forwarded or operator-remote target only');
        if (!validTargetLabel(target.targetLabel)) fail('must be a short name of 1-80 letters, digits, spaces and . _ ( ) -, never a URL or address');
      });
      // Declared observers (built by integrations/observers/factory.mjs at run time).
      if (Object.hasOwn(target, 'observers')) within('"observers"', () => {
        if (!Array.isArray(target.observers) || target.observers.length > 16) fail('observers must be a list of at most 16 observers');
        const ids = new Set();
        target.observers.forEach((o, index) => within(named('observer', o?.id, index), () => {
          if (!object(o) || typeof o.id !== 'string' || !OBSERVER_ID.test(o.id) || ids.has(o.id)) fail('each observer needs a unique "id" (1-48 letters, digits, "_" or "-")'); ids.add(o.id);
          if (!OBSERVER_TYPES.includes(o.type)) fail(`observer "type" must be one of ${OBSERVER_TYPES.join(', ')}`);
          // lockFallback opens the application's live database: operator code only, never a profile.
          if (['env', 'transport', 'instanceId', 'lockFallback'].some(key => Object.hasOwn(o, key))) fail('observers cannot set env, transport, instanceId or lockFallback');
          if (Object.hasOwn(o, 'settleMs') && !settleDeclared(o.settleMs)) fail(`"settleMs" must be an integer from ${SETTLE_BOUNDS.minMs} to ${SETTLE_BOUNDS.maxMs}`);
          // An audit-log file observer: its rules, quiet period and witness (a logged GET) are checked here, before any request.
          if (o.type === 'audit-file') try { validateAuditFileConfig(o, target.actors); } catch (error) { fail(error.message); }
          // An egress sink: loopback only, declared destinations, and authoritative only with routing and a witness.
          if (o.type === 'egress-recorder') try { validateEgressConfig(o, target.actors); } catch (error) { fail(error.message); }
          // An SMTP sink: loopback only, declared recipient domains, and authoritative only with routing and a witness.
          if (o.type === 'smtp-sink') try { validateSmtpConfig(o, target.actors); } catch (error) { fail(error.message); }
          // A provider feed: a signed feed on 127.0.0.1 or in a bound file, declared recipient domains, authoritative only with a witness.
          if (o.type === 'provider-feed') try { validateProviderFeedConfig(o, target.actors); } catch (error) { fail(error.message); }
          // A Postgres snapshot observer: loopback only, plain identifiers, and the credential only through credentialEnv.
          if (o.type === 'pg-snapshot') {
            const PG_IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
            if (Object.keys(o).some(key => !['id', 'type', 'host', 'port', 'database', 'credentialEnv', 'tables', 'settleMs', 'rowsPerTable', 'statementTimeoutMs', 'actorCapture', ...PG_BACKGROUND_KEYS].includes(key))) fail('a pg-snapshot observer is { id, type, host, port, database, credentialEnv, tables, settleMs?, rowsPerTable?, statementTimeoutMs?, actorCapture?, platform?, ignore?, queues?, drainTimeoutMs?, pollMs?, runLease? }; its credential comes only from credentialEnv');
            { const problem = pgBackgroundProblem(o); if (problem) fail(problem); }
            if (Object.hasOwn(o, 'actorCapture')) { const problem = actorCaptureProblem(o.actorCapture, target.actors, o.credentialEnv); if (problem) fail(problem); }
            if (o.rowsPerTable !== undefined && !(Number.isInteger(o.rowsPerTable) && o.rowsPerTable >= 1 && o.rowsPerTable <= 200000)) fail('"rowsPerTable" must be an integer from 1 to 200000');
            if (o.statementTimeoutMs !== undefined && !(Number.isInteger(o.statementTimeoutMs) && o.statementTimeoutMs >= 500 && o.statementTimeoutMs <= 60000)) fail('"statementTimeoutMs" must be an integer from 500 to 60000');
            if (o.host !== '127.0.0.1') fail('"host" must be the literal loopback address 127.0.0.1');
            if (!Number.isInteger(o.port) || o.port < 1 || o.port > 65535) fail('"port" must be a TCP port');
            if (typeof o.database !== 'string' || !PG_IDENT.test(o.database)) fail('"database" must be a plain identifier');
            if (typeof o.credentialEnv !== 'string') fail('declare "credentialEnv" (a SCOPEHAVEN_TARGET_ variable holding user:password for a read-only role)');
            if (!Array.isArray(o.tables) || o.tables.length < 1 || o.tables.length > 32 || !o.tables.every(t => object(t) && Object.keys(t).every(key => ['table', 'key', 'schema', 'resourcePrefix', 'readBack'].includes(key))
              && PG_IDENT.test(t.table ?? '') && PG_IDENT.test(t.key ?? '') && (t.schema === undefined || PG_IDENT.test(t.schema)) && (t.resourcePrefix === undefined || /^[A-Za-z0-9_.-]{1,80}$/.test(t.resourcePrefix)))) fail('"tables" lists 1 to 32 { table, key, schema?, resourcePrefix?, readBack? } with plain identifiers');
            if (new Set(o.tables.map(t => t.table)).size !== o.tables.length) fail('each table name is declared once per pg-snapshot observer (events are named by table; use a second observer for another schema)');
            // Read-back (src/pg-readback.mjs): the value columns to read back and what must hold, refused here exactly as the observer refuses it.
            for (const t of o.tables.filter(t => Object.hasOwn(t, 'readBack'))) { try { jsonValue(t.readBack); validateReadBack(t.readBack, { key: t.key, where: `${t.table} readBack` }); } catch (error) { fail(`invalid readBack on ${t.table} (${error?.code ?? 'shape'})`); } }
          }
          // A Postgres WAL observer (NC9 item 4; integrations/observers/pg-wal.mjs, docs/PG-WAL.md): loopback only, plain identifiers, the
          // credential only through credentialEnv (a REPLICATION role's), declared value columns per table, the background-writer
          // options and the actor capture as pg-snapshot takes them. The observer's own rules (sensitive names, the key never a value,
          // the ignore list never naming an observed table, queue kinds) run when it is built, before any request.
          if (o.type === 'pg-wal') {
            const PG_IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
            if (Object.keys(o).some(key => !['id', 'type', 'host', 'port', 'database', 'credentialEnv', 'tables', 'settleMs', 'statementTimeoutMs', 'barrierMs', 'actorCapture', 'pgNetWire', ...PG_BACKGROUND_KEYS].includes(key))) fail('a pg-wal observer is { id, type, host, port, database, credentialEnv, tables, settleMs?, statementTimeoutMs?, barrierMs?, actorCapture?, pgNetWire?, platform?, ignore?, queues?, drainTimeoutMs?, pollMs?, runLease? }; its credential comes only from credentialEnv');
            if (o.host !== '127.0.0.1') fail('"host" must be the literal loopback address 127.0.0.1');
            if (!Number.isInteger(o.port) || o.port < 1 || o.port > 65535) fail('"port" must be a TCP port');
            if (typeof o.database !== 'string' || !PG_IDENT.test(o.database)) fail('"database" must be a plain identifier');
            if (typeof o.credentialEnv !== 'string') fail('declare "credentialEnv" (a SCOPEHAVEN_TARGET_ variable holding user:password for a REPLICATION role)');
            if (Object.values(object(target.actors) ? target.actors : {}).some(a => a?.credentialEnv === o.credentialEnv)) fail('"credentialEnv" is the REPLICATION role\'s own, never an actor\'s credential');
            const columns = list => list === undefined || (Array.isArray(list) && list.length <= 16 && list.every(c => typeof c === 'string' && PG_IDENT.test(c)) && new Set(list).size === list.length);
            if (!Array.isArray(o.tables) || o.tables.length < 1 || o.tables.length > 32 || !o.tables.every(t => object(t) && Object.keys(t).every(key => ['table', 'key', 'schema', 'resourcePrefix', 'values', 'sensitive', 'reveal'].includes(key))
              && PG_IDENT.test(t.table ?? '') && PG_IDENT.test(t.key ?? '') && (t.schema === undefined || PG_IDENT.test(t.schema)) && (t.resourcePrefix === undefined || /^[A-Za-z0-9_.-]{1,80}$/.test(t.resourcePrefix))
              && columns(t.values) && columns(t.sensitive) && columns(t.reveal))) fail('"tables" lists 1 to 32 { table, key, schema?, resourcePrefix?, values?, sensitive?, reveal? } with plain identifiers (at most 16 distinct columns in each list)');
            if (new Set(o.tables.map(t => t.table)).size !== o.tables.length) fail('each table name is declared once per pg-wal observer (events are named by table; use a second observer for another schema)');
            if (o.statementTimeoutMs !== undefined && !(Number.isInteger(o.statementTimeoutMs) && o.statementTimeoutMs >= 500 && o.statementTimeoutMs <= 60000)) fail('"statementTimeoutMs" must be an integer from 500 to 60000');
            if (o.barrierMs !== undefined && !(Number.isInteger(o.barrierMs) && o.barrierMs >= 100 && o.barrierMs <= 30000)) fail('"barrierMs" must be an integer from 100 to 30000');
            { const problem = pgBackgroundProblem(o); if (problem) fail(problem); }
            if (Object.hasOwn(o, 'actorCapture')) { const problem = actorCaptureProblem(o.actorCapture, target.actors, o.credentialEnv); if (problem) fail(problem); }
            // pg_net on the wire (integrations/observers/pg-net-wire.mjs): the database container whose network a tap reads, the
            // witness role's credential (a role that may call net.http_get), never an actor's, the REPLICATION role's or another observer's, and optionally
            // programRoles, the operator's declaration of the login roles that can run a program in that container (without it, or with
            // another such role read at a mark, a wire window is subject-writable and never counts the queue as observed), and requestRoles, the
            // roles the application's own requests run as (a declared program role they reach is refused; without them nothing is observer-held).
            if (Object.hasOwn(o, 'pgNetWire')) {
              const w = o.pgNetWire, between = (v, min, max) => v === undefined || (Number.isInteger(v) && v >= min && v <= max);
              const roleList = v => v === undefined || (Array.isArray(v) && v.length >= 1 && v.length <= 16 && v.every(r => typeof r === 'string' && /^[A-Za-z_][A-Za-z0-9_$]{0,62}$/.test(r)) && new Set(v).size === v.length);
              if (!object(w) || Object.keys(w).some(key => !['container', 'credentialEnv', 'programRoles', 'requestRoles', 'image', 'witnessWaitMs', 'quietMs'].includes(key)) || typeof w.container !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(w.container)
                || typeof w.credentialEnv !== 'string' || !/^SCOPEHAVEN_TARGET_[A-Z0-9_]{1,110}$/.test(w.credentialEnv) || typeof w.image !== 'string' || !/^[a-z0-9][a-z0-9._/-]{0,199}@sha256:[0-9a-f]{64}$/.test(w.image)
                || !between(w.witnessWaitMs, 1000, 60000) || !between(w.quietMs, 100, 10000)
                || !roleList(w.programRoles) || !roleList(w.requestRoles))
                fail('"pgNetWire" is { container, credentialEnv, programRoles? and requestRoles? (each 1 to 16 distinct role names), image (a local image named by digest, name@sha256:<64 hex>; never pulled), witnessWaitMs? (1000 to 60000), quietMs? (100 to 10000) }: the database container\'s name and a SCOPEHAVEN_TARGET_ variable holding user:password for a role that may call net.http_get');
              if (w.credentialEnv === o.credentialEnv || Object.values(object(target.actors) ? target.actors : {}).some(a => a?.credentialEnv === w.credentialEnv)
                || (Array.isArray(target.observers) ? target.observers : []).some(x => x !== o && x?.credentialEnv === w.credentialEnv)) fail('"pgNetWire.credentialEnv" is the witness role\'s own, never an actor\'s, the REPLICATION role\'s or another observer\'s');
            }
          }
          // A MySQL snapshot observer: loopback only, plain identifiers, the credential only through credentialEnv,
          // and a change column only with its source audit file and the commit lag.
          if (o.type === 'mysql-snapshot') {
            const MY_IDENT = /^[A-Za-z_][A-Za-z0-9_$]{0,63}$/;
            if (Object.keys(o).some(key => !['id', 'type', 'host', 'port', 'database', 'credentialEnv', 'tables', 'settleMs', 'rowsPerTable', 'statementTimeoutMs', 'maxCommitLagMs', 'tableIds'].includes(key))) fail('a mysql-snapshot observer is { id, type, host, port, database, credentialEnv, tables, settleMs?, rowsPerTable?, statementTimeoutMs?, maxCommitLagMs?, tableIds? }; its credential comes only from credentialEnv');
            if (o.tableIds !== undefined && typeof o.tableIds !== 'boolean') fail('"tableIds" is true or false (true compares InnoDB table and tablespace ids; the reader needs PROCESS)');
            if (o.host !== '127.0.0.1') fail('"host" must be the literal loopback address 127.0.0.1');
            if (!Number.isInteger(o.port) || o.port < 1 || o.port > 65535) fail('"port" must be a TCP port');
            if (typeof o.database !== 'string' || !MY_IDENT.test(o.database)) fail('"database" must be a plain identifier');
            if (typeof o.credentialEnv !== 'string') fail('declare "credentialEnv" (a SCOPEHAVEN_TARGET_ variable holding user:password for a read-only account)');
            if (o.rowsPerTable !== undefined && !(Number.isInteger(o.rowsPerTable) && o.rowsPerTable >= 1 && o.rowsPerTable <= 200000)) fail('"rowsPerTable" must be an integer from 1 to 200000');
            if (o.statementTimeoutMs !== undefined && !(Number.isInteger(o.statementTimeoutMs) && o.statementTimeoutMs >= 500 && o.statementTimeoutMs <= 60000)) fail('"statementTimeoutMs" must be an integer from 500 to 60000');
            const changeColumnOk = c => object(c) && Object.keys(c).length === 2 && MY_IDENT.test(c.column ?? '') && typeof c.audit === 'string' && c.audit.length >= 1 && c.audit.length <= 500 && !/[\u0000-\u001f]/.test(c.audit);
            if (!Array.isArray(o.tables) || o.tables.length < 1 || o.tables.length > 32 || !o.tables.every(t => object(t) && Object.keys(t).every(key => ['table', 'key', 'resourcePrefix', 'changeColumn'].includes(key))
              && MY_IDENT.test(t.table ?? '') && MY_IDENT.test(t.key ?? '') && (t.resourcePrefix === undefined || /^[A-Za-z0-9_.-]{1,80}$/.test(t.resourcePrefix)) && (t.changeColumn === undefined || changeColumnOk(t.changeColumn)))) fail('"tables" lists 1 to 32 { table, key, resourcePrefix?, changeColumn?: { column, audit } } with plain identifiers');
            if (new Set(o.tables.map(t => t.table)).size !== o.tables.length) fail('each table name is declared once per mysql-snapshot observer');
            if (o.tables.some(t => t.changeColumn) !== (o.maxCommitLagMs !== undefined)) fail('"maxCommitLagMs" is declared exactly when a table has a changeColumn');
            if (o.maxCommitLagMs !== undefined && !(Number.isInteger(o.maxCommitLagMs) && o.maxCommitLagMs >= 0 && o.maxCommitLagMs <= 600000)) fail('"maxCommitLagMs" must be an integer from 0 to 600000');
          }
          if (Object.hasOwn(o, 'credentialEnv') && (typeof o.credentialEnv !== 'string' || !CREDENTIAL_ENV.test(o.credentialEnv))) fail('credential references must use the dedicated SCOPEHAVEN_TARGET_ namespace');
          jsonValue(o);
        }));
        // A forwarded destination's upstream is never the target origin or another declared observer (src/effect-outcome.mjs), and a
        // provider feed's template pins name its declared labels (src/provider-feed-rules.mjs).
        const clash = forwardPortClash(target) ?? forwardSecretClash(target) ?? signingSecretClash(target) ?? providerFeedClash(target) ?? providerFeedTemplatePins(target) ?? requestFeedClash(target) ?? readBackClash(target); if (clash) fail(clash);
      });
      for (const key of ['id', 'applicationId', 'contextId']) if (!identifier(target[key])) fail(`invalid target identity ("${key}" must be 1-80 letters, digits, "_" or "-")`);
      if (targetIds.has(target.id)) fail('duplicate target identity'); targetIds.add(target.id);
      text(target.name, 160, 'invalid target name'); text(target.buildLabel, 160, 'invalid build label');
      // A remote target's origin is https://host[:port]; every other target's is the literal loopback HTTP origin.
      let normalizedOrigin;
      if (target.targetContext === 'operator-remote') {
        normalizedOrigin = remoteOriginOf(target.origin);
        if (!normalizedOrigin) fail('a remote target\'s origin must be https://host[:port] with a host name or IPv4 address, and nothing else');
      } else {
        const originMatch = typeof target.origin === 'string' && /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/?$/.exec(target.origin);
        if (!originMatch) fail('origin must be literal loopback HTTP (an https origin needs "targetContext": "operator-remote")');
        if (Number(originMatch[1]) > 65535) fail('invalid loopback port');
        normalizedOrigin = `http://127.0.0.1:${Number(originMatch[1])}`;
      }
      if (!object(target.actors) || Object.keys(target.actors).length < 1 || Object.keys(target.actors).length > 50) fail('invalid actor set');
      Object.entries(target.actors).forEach(([alias, actor], index) => within(named('actor', alias, index), () => validActor(alias, actor)));
      const identities = Object.entries(target.actors).filter(([, actor]) => Object.hasOwn(actor, 'identityValue'));
      identities.forEach(([alias, actor], index) => within(named('actor', alias, index), () => { if (identities.some(([other, peer]) => other !== alias && peer.identityValue === actor.identityValue)) fail('"identityValue" must be unique across actors'); }));
      // No other actor may name a header actor's variable (PR456 round 2 N4): it would send that key as its own bearer token,
      // cookie or header. Only the header actor itself reads it.
      Object.entries(target.actors).forEach(([alias, actor], index) => within(named('actor', alias, index), () => {
        if (Object.hasOwn(actor, 'credentialEnv') && Object.entries(target.actors).some(([other, peer]) => other !== alias && Object.hasOwn(peer, 'credentialHeader') && peer.credentialEnv === actor.credentialEnv))
          fail('"credentialEnv" names another actor\'s header key variable: that key is sent only in its own actor\'s header, so give each actor its own SCOPEHAVEN_TARGET_ variable');
      }));
      // A header actor's key (H1 step 4) travels only in its own header: an observer that named its variable would send the key as
      // its own credential, in another header (PR456-REVIEW m1). So no observer field ending in "Env", at any depth (an audit
      // endpoint's or a database's credentialEnv, a forward proofEnv, a signing secretEnv), may name a header actor's credentialEnv.
      const headerKeyEnvs = new Set(Object.values(target.actors).filter(actor => Object.hasOwn(actor, 'credentialHeader')).map(actor => actor.credentialEnv));
      if (headerKeyEnvs.size && Array.isArray(target.observers)) target.observers.forEach((o, index) => within(named('observer', o?.id, index), () => {
        if (envReferences(o).some(name => headerKeyEnvs.has(name))) fail('an observer credential names a header actor\'s "credentialEnv": that key is sent only in its actor\'s header, so give the observer its own SCOPEHAVEN_TARGET_ variable');
      }));
      // Declared tenant values (src/tenant-values.mjs): errors name positions only, never a value or a tenant id.
      // Declared channels (src/channels.mjs), against the target's declared observers.
      if (Object.hasOwn(target, 'channels')) within('"channels"', () => { const problem = channelDeclarationProblem(target.channels, target.observers ?? []); if (problem) fail(problem); });
      if (Object.hasOwn(target, 'tenantValues')) within('"tenantValues"', () => { try { validateTenantValues(target.tenantValues); } catch (error) { fail(error.message); } });
      // The mirror declaration (src/two-identities.mjs): "off", or counterparts that swap one tenant's declared values for another's.
      if (Object.hasOwn(target, 'mirrors')) within('"mirrors"', () => { try { validateMirrorDeclaration(target.mirrors, target.tenantValues, Array.isArray(target.checks) ? target.checks : []); } catch (error) { fail(error.message); } });
      // Supabase identity rules (NC9 item 3), over the declared actor capture.
      if (Object.hasOwn(target, 'supabaseRules')) within('"supabaseRules"', () => { const problem = supabaseRulesProblem(target); if (problem) fail(problem); });
      if (!Array.isArray(target.checks) || target.checks.length < 1 || target.checks.length > PROFILE_LIMITS.checks) fail('invalid check set');
      const checkIds = new Set();
      target.checks.forEach((check, index) => within(named('check', check?.id, index), () => validCheck(check, target, checkIds)));
      // Declared but used by no check would read as protection that is silently off.
      if (Object.hasOwn(target, 'tenantValues') && !target.checks.some(check => check.assertions.some(assertion => assertion.kind === FOREIGN_VALUES_KIND))) within('"tenantValues"', () => fail('declared, but no check uses "json.noForeignValues"'));
      if (target.checks.reduce((total, check) => total + (check.timeoutMs ?? 0), 0) > CHECK_TIMEOUT_BOUNDS.profileTotalMs) fail(`declared "timeoutMs" values exceed ${CHECK_TIMEOUT_BOUNDS.profileTotalMs} ms in total`);
      within('"requiredControlIds"', () => {
        if (!Array.isArray(target.requiredControlIds) || target.requiredControlIds.length < 1 || target.requiredControlIds.length > PROFILE_LIMITS.requiredControls || new Set(target.requiredControlIds).size !== target.requiredControlIds.length) fail('required controls must be nonempty and unique');
        for (const id of target.requiredControlIds) {
          const control = target.checks.find(check => check.id === id);
          if (!identifier(id) || !control || control.severity !== 'control' || control.evidenceRequirement !== 'response' || control.applicability?.applies === false) fail(`invalid required control ${identifier(id) ? `"${id}" ` : ''}(needs an applicable response check with severity "control")`);
        }
      });
      validateCorrelation(target);
      // A webhook key's variable is never another credential's (an actor's, or an observer's under any field), and no header the
      // connector adds to a webhook check's request has the name of one of its provider's headers.
      { const clash = webhookEnvClash(target); if (clash) fail(clash); }
      { const clash = webhookHeaderClash(target); if (clash) fail(clash); }
      // A header key is never sent under the run's correlation header name.
      if (Object.hasOwn(target, 'correlation')) Object.entries(target.actors).forEach(([alias, actor], index) => within(named('actor', alias, index), () => {
        if (typeof actor.credentialHeader === 'string' && actor.credentialHeader.toLowerCase() === String(target.correlation.header).toLowerCase()) fail('"credentialHeader" must not be the target\'s correlation header');
      }));
      validateIdempotency(target);
      validateOutcomeJudged(target);
      validateAttribution(target);
      // An app log reads the application's own action log; it is never an observer, and it can only ever make a clause fail ("use": "admission").
      if (Object.hasOwn(target, 'appLogs')) within('"appLogs"', () => { try { validateAppLogs(target); } catch (error) { fail(error.message); } });
      validateCapturesAndLifecycle(target);
      // Identity option B (src/http-rests-on.mjs restsOnProblem): every listed control can anchor the check (B2).
      if (target.checks.some(check => Object.hasOwn(check, 'restsOn'))) {
        const plan = identityControlPlan(target), postChange = postChangeIndex(target);
        target.checks.forEach((check, index) => { if (Object.hasOwn(check, 'restsOn')) within(named('check', check.id, index), () => within('"restsOn"', () => {
          const problem = restsOnProblem(check, target, { identityIds: plan.get(check.actorId)?.identityControls ?? [], postChange: postChange.has(check.id) });
          if (problem) fail(problem);
        })); });
      }
      validateProfileSize(target);
      // The effect horizon and run budget (src/http-timing.mjs): bounds, a declared settle, and a budget that holds the linear plan.
      if (Object.hasOwn(target, 'timing')) within('"timing"', () => { try { validateTiming(target, { controlPlan: identityControlPlan(target) }); } catch (error) { fail(error.message); } });
      return { ...structuredClone(target), origin: normalizedOrigin, targetContext: target.targetContext ?? 'local-app' };
    };
    const targets = input.targets.map((declaredTarget, targetIndex) => within(named('target', declaredTarget?.id, targetIndex), () => {
      const validated = validTarget(declaredTarget, targetIds);
      // Two identities by default: each boundary check of a tenant identity gets its mirror under the second identity, after
      // the declared checks in canonical order; a check that declares "mirrorOf" must be exactly that mirror. The expanded
      // target must meet every rule above (the check, timeout and request limits among them); a mirror that would break one
      // is left out (check-config lists it as profile-rule), so a profile valid before mirrors existed never stops loading.
      let parts = { declared: validated.checks, mirrors: [] };
      within('"mirrors"', () => { try { parts = mirrorChecks(validated, identityControlPlan(validated)); } catch (error) { fail(error.message); } });
      const attempt = checks => { try { return validTarget({ ...validated, checks }, new Set()); } catch (error) { if (error instanceof ContractValidationError) return null; throw error; } };
      const all = [...parts.declared, ...parts.mirrors];
      if (JSON.stringify(all) === JSON.stringify(validated.checks)) return validated;
      const whole = attempt(all);
      if (whole) return whole;
      // The check limit and the timeout total grow mirror by mirror: keep, in canonical order, each mirror that fits both and
      // validate that set once (every other rule only grows with more checks, so this is the set the loop below would keep).
      let count = parts.declared.length, total = parts.declared.reduce((n, check) => n + (check.timeoutMs ?? 0), 0);
      const fitting = [];
      for (const mirror of parts.mirrors) {
        const t = mirror.timeoutMs ?? 0;
        if (count + 1 <= PROFILE_LIMITS.checks && total + t <= CHECK_TIMEOUT_BOUNDS.profileTotalMs) { fitting.push(mirror); count += 1; total += t; }
      }
      const direct = fitting.length < parts.mirrors.length ? attempt([...parts.declared, ...fitting]) : null;
      if (direct) return direct;
      // Another rule breaks (the request plan): add the mirrors one at a time in canonical order and keep each that holds.
      let kept = parts.declared, last = attempt(kept) ?? validated;
      for (const mirror of parts.mirrors) { const next = attempt([...kept, mirror]); if (next) { kept = [...kept, mirror]; last = next; } }
      return last;
    }));
    return targets;
  } catch (error) {
    const failure = error instanceof ContractValidationError ? error : new ContractValidationError('unreadable configuration');
    failure.message = `Invalid HTTP contract: ${failure.where.length ? `${failure.where.join(' > ')}: ` : ''}${failure.reason}.`;
    throw failure;
  }
}

function lookup(root, tokens) {
  let value = root;
  for (const token of tokens) {
    if (value === null || typeof value !== 'object' || !Object.hasOwn(value, token)) return { present: false, type: 'absent' };
    value = value[token];
  }
  return { present: true, type: value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value, value };
}
// ---------------------------------------------------------------------------
// Predicate records (N6-E1, recheck rehearsal 2026-10-29 gaps 2 and 4): what an HTTP contract row keeps of each json.equals,
// json.exists and json.notContains predicate, so a reviewer holding only the exported run can recompute its outcome
// (integrations/verdict-check/verify_verdicts.py does) and read a failure.
//
// Two modes, chosen per run (runHttpAssessment's predicateRecord option, or SCOPEHAVEN_PREDICATE_RECORD):
//   - digest (the default): the field's JSON pointer, json.exists's expected true or false, and for json.equals and
//     json.notContains a keyed SHA-256 of the configured value; json.equals also keeps a keyed SHA-256 of the value the
//     response held at the pointer, under the same key. Equal digests are equal values (valueDigest below), so a json.equals
//     outcome is recomputed without either value or the key in the run. A json.notContains outcome over a present string is
//     not: no digest shows containment.
//   - value: the field's pointer, the configured value and the response's value at the pointer, in clear (a string of at most
//     VALUE_LIMIT characters; a longer one is marked omitted). Every outcome is recomputed, and a failure reads with the
//     expected and actual values. Use it only for synthetic data or with the data owner's consent.
// Without a mode (outcome-only, the record every run made before predicate records) a predicate keeps its kind, presence, type
// and outcome only. The digest key (security review F12, 2026-10-30) is 32 random bytes per run that neither the run nor a
// pack keeps: under a public salt, a guessable value (a refund in cents, a boolean, a short id) is found by trying candidates
// against its digest. The check id and the predicate's place are digested with the key, so two equal values under different
// predicates do not share a digest; digests do not compare across runs. An operator who must let a named reviewer test a
// value sets the key (the predicateKey option, or SCOPEHAVEN_PREDICATE_KEY) and hands it over apart from the pack.
// They live in this file so the HTTP evaluator identity (evaluatorHash), which digests it, covers them with the rest of the rules.

export const PREDICATE_RECORDS = Object.freeze(['digest', 'value']);
// Every mode a run may be asked for: 'outcome' keeps the earlier record.
export const PREDICATE_RECORD_MODES = Object.freeze([...PREDICATE_RECORDS, 'outcome']);
export const PREDICATE_RECORD_DEFAULT = 'digest';
export const PREDICATE_RECORD_KINDS = Object.freeze(['json.equals', 'json.exists', 'json.notContains']);
export const PREDICATE_VALUE_LIMIT = 65536;
const PREDICATE_TEXT_LIMIT = 200;
const recordHex = (value, n) => typeof value === 'string' && new RegExp(`^[a-f0-9]{${n}}$`).test(value);
const primitiveType = type => ['null', 'boolean', 'number', 'string'].includes(type);
const jsonTypeOf = value => value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
// The digest a record keeps of one value: SHA-256 of the run's key, the predicate's place and the value in ScopeHaven's
// canonical form (src/domain.mjs digest), as src/http-captures.mjs keys a capture's.
export const valueDigest = (key, { checkId, index }, value) => digest({ record: 'scopehaven-predicate-record/2', key, checkId, index, value });
// A predicate key: 32 bytes as 64 lowercase hex characters.
export const validPredicateKey = key => recordHex(key, 64);

// The mode a run uses: the option, else the environment, else digest. Anything else is refused before a request is sent.
export function predicateRecordMode(option, env = {}) {
  const mode = option ?? env.SCOPEHAVEN_PREDICATE_RECORD ?? PREDICATE_RECORD_DEFAULT;
  if (!PREDICATE_RECORD_MODES.includes(mode)) throw new Error(`Invalid predicate record mode: use one of ${PREDICATE_RECORD_MODES.join(', ')}.`);
  return mode;
}

// The fields a predicate record adds to { kind, present, type, outcome }. found is the lookup at the pointer; place is the
// check id and the assertion's index in the check; key is the run's predicate key (digest mode only).
export function predicateRecordFields(mode, assertion, completeJSON, found, { checkId, index, key }) {
  if (!PREDICATE_RECORDS.includes(mode) || !PREDICATE_RECORD_KINDS.includes(assertion.kind)) return {};
  const fields = { record: mode, pointer: assertion.pointer };
  const seen = completeJSON && found.present;
  if (assertion.kind === 'json.exists') return { ...fields, expected: assertion.expected };
  // A number JSON.parse read as Infinity (1e400) has no JSON form: its digest is of a marker object, which never equals a configured
  // value's, and value mode marks it omitted. It never equals a configured value, which is finite.
  const nonFinite = seen && found.type === 'number' && !Number.isFinite(found.value);
  if (mode === 'digest') {
    if (!validPredicateKey(key)) throw new Error('A digest-mode predicate record needs the run\'s predicate key.');
    const place = { checkId, index };
    return { ...fields, expectedSha256: valueDigest(key, place, assertion.expected),
      ...(assertion.kind === 'json.equals' ? { observedSha256: seen ? valueDigest(key, place, nonFinite ? { nonFinite: String(found.value) } : found.value) : null } : {}) };
  }
  const keep = seen && primitiveType(found.type) && (assertion.kind === 'json.equals' || found.type === 'string');
  return { ...fields, expected: assertion.expected,
    ...(keep ? (nonFinite ? { omitted: 'non-finite' } : found.type === 'string' && found.value.length > PREDICATE_VALUE_LIMIT ? { omitted: 'over-limit' } : { observed: found.value }) : {}) };
}

// The outcome a record gives, recomputed from its own fields (null when the record cannot give one): the rules of
// evaluateHttpCheck below. A value of a configured json.equals is at most 8192 characters and finite, so an omitted value
// (a longer string, or a number with no JSON form) never equals it.
export function recordedOutcome(p, completeJSON) {
  if (!completeJSON) return 'inconclusive';
  if (p.kind === 'json.exists') return p.present === p.expected ? 'pass' : 'fail';
  if (p.kind === 'json.equals') {
    if (!p.present) return 'fail';
    if (p.record === 'digest') return p.observedSha256 === p.expectedSha256 ? 'pass' : 'fail';
    if (Object.hasOwn(p, 'observed')) return p.observed === p.expected ? 'pass' : 'fail';
    return 'fail';
  }
  if (!p.present || p.type !== 'string') return 'inconclusive';
  return p.record === 'value' && Object.hasOwn(p, 'observed') ? (p.observed.includes(p.expected) ? 'fail' : 'pass') : null;
}

const recordKeys = p => Object.keys(p).sort().join(',');
const RECORD_BASE_KEYS = ['kind', 'outcome', 'pointer', 'present', 'record', 'type'];
// The saved-evidence check of one predicate record: exactly its mode's fields, of the right form, and an outcome its fields
// give (a json.notContains digest record keeps the outcome it was given, which the caller checks as before).
export function validPredicateRecord(p, { completeJSON, pointerValid }) {
  if (!PREDICATE_RECORDS.includes(p.record) || !PREDICATE_RECORD_KINDS.includes(p.kind) || typeof p.pointer !== 'string' || !pointerValid(p.pointer)) return false;
  const seen = completeJSON && p.present === true;
  let extra;
  if (p.kind === 'json.exists') { if (typeof p.expected !== 'boolean') return false; extra = ['expected']; }
  else if (p.record === 'digest') {
    if (!recordHex(p.expectedSha256, 64)) return false;
    extra = ['expectedSha256'];
    if (p.kind === 'json.equals') { if (seen ? !recordHex(p.observedSha256, 64) : p.observedSha256 !== null) return false; extra.push('observedSha256'); }
  } else {
    if (p.kind === 'json.equals' ? !(p.expected === null || typeof p.expected === 'boolean' || (typeof p.expected === 'number' && Number.isFinite(p.expected)) || (typeof p.expected === 'string' && p.expected.length <= 8192))
      : !(typeof p.expected === 'string' && p.expected.length >= 1 && p.expected.length <= 200)) return false;
    extra = ['expected'];
    const keep = seen && primitiveType(p.type) && (p.kind === 'json.equals' || p.type === 'string');
    if (keep && Object.hasOwn(p, 'omitted')) { if (p.omitted !== (p.type === 'string' ? 'over-limit' : p.type === 'number' ? 'non-finite' : null) || Object.hasOwn(p, 'observed')) return false; extra.push('omitted'); }
    else if (keep) { if (!Object.hasOwn(p, 'observed') || jsonTypeOf(p.observed) !== p.type || (p.type === 'string' && p.observed.length > PREDICATE_VALUE_LIMIT) || (p.type === 'number' && !Number.isFinite(p.observed))) return false; extra.push('observed'); }
  }
  if (recordKeys(p) !== [...RECORD_BASE_KEYS, ...extra].sort().join(',')) return false;
  const outcome = recordedOutcome(p, completeJSON);
  return outcome === null || outcome === p.outcome;
}

const shownValue = value => { const text = JSON.stringify(value); return text.length > PREDICATE_TEXT_LIMIT ? `${text.slice(0, PREDICATE_TEXT_LIMIT)}... (${text.length} characters)` : text; };
// The assertion's expected and actual texts for a recorded predicate: the field compared, and in value mode the expected and
// actual values, so a failure reads without the profile. Outcome-only predicates keep their earlier texts.
export function predicateTexts(p, completeJSON, status) {
  const at = `JSON value at ${JSON.stringify(p.pointer)}`;
  const expected = p.kind === 'json.exists' ? `${at} ${p.expected ? 'is present' : 'is absent'}`
    : p.kind === 'json.equals' ? `${at} equals ${p.record === 'value' ? shownValue(p.expected) : 'the configured value (keyed digest in the predicate record)'}`
      : `${at} is a string that does not contain ${p.record === 'value' ? shownValue(p.expected) : 'the configured text (keyed digest in the predicate record)'}`;
  if (!completeJSON) return { expected, actual: 'Complete valid JSON unavailable' };
  const value = Object.hasOwn(p, 'observed') ? `; value ${shownValue(p.observed)}` : p.omitted === 'over-limit' ? `; value over ${PREDICATE_VALUE_LIMIT} characters, not kept` : p.omitted === 'non-finite' ? '; value a number with no JSON form, not kept' : '';
  return { expected, actual: `${p.present ? 'Present' : 'Absent'}; type ${p.type}${value}; predicate ${status}` };
}

// "HTTP 403" for one status; "HTTP 401, 403 or 404" for an accepted set.
export const statusLabel = codes => codes.length === 1 ? `HTTP ${codes[0]}` : `HTTP ${codes.slice(0, -1).join(', ')} or ${codes.at(-1)}`;
// The mirror phase (src/two-identities.mjs): a generated mirror answered with a rate-limit status (429, or one its target's "mirrors"
// declaration names, mirrorLimitStatuses) was answered by a per-user rate or question limit, not by the tenant boundary. Its status
// assertion reads inconclusive, it carries MIRROR_LIMIT_ASSERTION naming the status, and it reads inconclusive whatever else failed,
// except a json.noForeignValues predicate: another tenant's value in the limit's own answer is still a leak (FAIL). It never passes:
// no limit status is one a mirror expects. The validator recomputes it from the row's recorded status (validateHttpObservation).
export const MIRROR_LIMIT_ASSERTION = 'Mirror answered by the tenant boundary, not a per-user limit';
export const MIRROR_LIMIT_EXPECTED = 'A response from the tenant boundary, not from a per-user rate or question limit';
export const mirrorLimitActual = status => `HTTP ${status} is a rate-limit status: a per-user rate or question limit answered the mirror, so the boundary was not observed`;
const MIRROR_LIMIT_SUMMARY = 'A per-user rate or question limit answered this mirror, so the tenant boundary was not observed.';
const foreignAssertion = assertion => typeof assertion?.name === 'string' && assertion.name.startsWith(`${FOREIGN_VALUES_KIND} predicate `);
// context.foreignValues: the json.noForeignValues matcher for this check (src/tenant-values.mjs matcherFor); absent reads inconclusive.
// context.limitStatuses: for a generated mirror only, the run's rate-limit statuses (above).
export function evaluateHttpCheck(check, observation, context = {}) {
  const knownStatus = Number.isInteger(observation.status) && observation.status >= 100 && observation.status <= 599;
  const completeJSON = observation.complete === true && observation.jsonParsed === true && !observation.error;
  const limited = knownStatus && Array.isArray(context.limitStatuses) && context.limitStatuses.includes(observation.status);
  const assertions = [], predicates = [];
  for (const assertion of check.assertions) {
    if (STATUS_KINDS.includes(assertion.kind)) {
      const accepted = assertion.kind === 'status.in' ? assertion.expected : [assertion.expected];
      const status = !knownStatus ? 'inconclusive' : accepted.includes(observation.status) ? 'pass' : limited ? 'inconclusive' : 'fail';
      assertions.push({ name: 'HTTP status matches contract', status, expected: statusLabel(accepted), actual: knownStatus ? `HTTP ${observation.status}` : 'HTTP status unavailable' });
      continue;
    }
    const found = completeJSON ? lookup(observation.json, pointerTokens(assertion.pointer)) : { present: false, type: 'unavailable' };
    if (assertion.kind === FOREIGN_VALUES_KIND) {
      // Counts and 1-based positions only; the response value itself is never kept. The transport's count of repeated
      // member names (observeHttp) decides whether the parsed body is the whole body (unknown reads inconclusive), and its
      // jsonSource tree gives each number's source text (without it, numbers read as String(n)).
      const sourced = completeJSON && observation.jsonSource !== undefined ? lookup(observation.jsonSource, pointerTokens(assertion.pointer)) : null;
      const predicate = foreignValuesPredicate(completeJSON, found, context.foreignValues ?? null, { repeatedKeys: observation.repeatedKeys, sourced: sourced?.present ? sourced.value : undefined, body: completeJSON ? observation.jsonSource : undefined });
      predicates.push(predicate);
      assertions.push({ name: `${assertion.kind} predicate ${predicates.length}`, status: predicate.outcome, expected: FOREIGN_VALUES_EXPECTED, actual: foreignValuesActual(predicate) });
      continue;
    }
    let status = 'inconclusive';
    if (completeJSON) {
      if (assertion.kind === 'json.exists') status = found.present === assertion.expected ? 'pass' : 'fail';
      else if (assertion.kind === 'json.equals') status = found.present && found.value === assertion.expected ? 'pass' : 'fail';
      else if (assertion.kind === 'json.notContains' && found.present && found.type === 'string') status = found.value.includes(assertion.expected) ? 'fail' : 'pass';
    }
    // context.predicateRecord (predicate records, above): what the row keeps so the outcome can be recomputed from the export.
    const predicate = { kind: assertion.kind, present: completeJSON ? found.present : null, type: found.type, outcome: status, ...predicateRecordFields(context.predicateRecord, assertion, completeJSON, found, { checkId: check.id, index: check.assertions.indexOf(assertion), key: context.predicateKey }) };
    predicates.push(predicate);
    const texts = Object.hasOwn(predicate, 'record') ? predicateTexts(predicate, completeJSON, status)
      : { expected: 'Configured JSON predicate holds', actual: !completeJSON ? 'Complete valid JSON unavailable' : `${found.present ? 'Present' : 'Absent'}; type ${found.type}; predicate ${status}` };
    assertions.push({ name: `${assertion.kind} predicate ${predicates.length}`, status, ...texts });
  }
  if (check.evidenceRequirement === 'backend') assertions.push({ name: 'Trusted backend observation available', status: 'inconclusive', expected: 'Independent backend evidence required', actual: 'Backend evidence unavailable' });
  if (limited) assertions.push({ name: MIRROR_LIMIT_ASSERTION, status: 'inconclusive', expected: MIRROR_LIMIT_EXPECTED, actual: mirrorLimitActual(observation.status) });
  const failed = assertions.some(assertion => assertion.status === 'fail' && (!limited || foreignAssertion(assertion)));
  const transportError = observation.complete !== true || ['timeout', 'network', 'too-large'].includes(observation.error);
  const status = failed ? 'fail' : transportError ? 'error' : assertions.some(assertion => assertion.status === 'inconclusive') ? 'inconclusive' : 'pass';
  const summaries = { fail: 'An observable response contract predicate failed.', error: 'The response observation could not be completed.', inconclusive: limited ? MIRROR_LIMIT_SUMMARY : 'Required evidence or a JSON predicate could not be verified.', pass: 'Response contract predicates passed; backend effects remain unverified.' };
  return { status, assertions, observed: { httpStatus: knownStatus ? observation.status : null, complete: observation.complete === true, jsonParsed: observation.jsonParsed === true, predicates, evidenceScope: 'response-only' }, summary: summaries[status] };
}

const readBackDigestedObservers = observers => (Array.isArray(observers) && observers.some(o => o?.type === 'pg-snapshot' && Array.isArray(o.tables) && o.tables.some(t => object(t) && Object.hasOwn(t, 'readBack')))
  ? observers.map(o => (o?.type === 'pg-snapshot' && Array.isArray(o.tables) ? { ...o, tables: o.tables.map(t => (object(t) && Object.hasOwn(t, 'readBack') ? { ...t, readBack: readBackDigestOf(t) } : t)) } : o)) : observers);
export function contractDigest(target) {
  const actors = Object.fromEntries(Object.entries(target.actors).map(([alias, actor]) => [alias, Object.fromEntries(['principalId', 'tenantId', 'role', 'credentialEnv', 'credentialCookie', 'credentialHeader', 'identityValue', 'signInRedirectStatus', 'refusesWith401'].filter(key => Object.hasOwn(actor, key)).map(key => [key, actor[key]]))]));
  return digest({ schemaVersion: 1, assertionSchemaVersion: ASSERTION_SCHEMA_VERSION, id: target.id, applicationId: target.applicationId, contextId: target.contextId, origin: target.origin, actors, checks: target.checks, requiredControlIds: target.requiredControlIds,
    // A pg-snapshot table's readBack is read through its view's digest (src/http-readback.mjs readBackDigestOf), so no sealed expected value
    // sits in this unsalted digest; a profile without readBack digests its observers exactly as before.
    ...(Object.hasOwn(target, 'observers') ? { observers: readBackDigestedObservers(target.observers) } : {}), targetContext: target.targetContext ?? 'local-app', ...(Object.hasOwn(target, 'targetLabel') ? { targetLabel: target.targetLabel } : {}),
    ...(Object.hasOwn(target, 'lifecycle') ? { lifecycle: target.lifecycle } : {}),
    // Correlation and the settlement mode (fast-loop W2), only when declared: profiles without them keep their digest.
    ...(Object.hasOwn(target, 'correlation') ? { correlation: target.correlation } : {}), ...(Object.hasOwn(target, 'settlement') ? { settlement: target.settlement } : {}),
    // Background attribution (readiness gap 5), only when declared.
    ...(Object.hasOwn(target, 'attribution') ? { attribution: target.attribution } : {}),
    // The effect horizon and run budget (readiness gap 2), only when declared.
    ...(Object.hasOwn(target, 'timing') ? { timing: target.timing } : {}),
    // Declared tenant values (json.noForeignValues), only when declared: profiles without them keep their digest.
    ...(Object.hasOwn(target, 'tenantValues') ? { tenantValues: target.tenantValues } : {}),
    // Declared app logs (src/app-log-rules.mjs), only when declared: profiles without them keep their digest.
    ...(Object.hasOwn(target, 'appLogs') ? { appLogs: target.appLogs } : {}),
    // Declared channels (src/channels.mjs), only when declared: profiles without them keep their digest.
    ...(Object.hasOwn(target, 'channels') ? { channels: target.channels } : {}),
    // The mirror declaration (src/two-identities.mjs), only when declared; generated mirrors are in "checks".
    ...(Object.hasOwn(target, 'mirrors') ? { mirrors: target.mirrors } : {}),
    // Supabase identity rules (NC9 item 3), only when declared: profiles without them keep their digest.
    ...(Object.hasOwn(target, 'supabaseRules') ? { supabaseRules: target.supabaseRules } : {}) });
}

// ---------------------------------------------------------------------------
// Actor identity (connector v2). One rule set used by the connector when it
// produces evidence, and by validateHttpRunEvidence for the regression gate,
// run comparison and later evidence views.
// actor-identity/4 (stated, versioned rules; runs saved as actor-identity/3 keep the earlier rules):
//   - surface controls: a credentialed actor's required GET allowed-use controls on routes other than its
//     identity controls are re-sent in its brackets with the identity controls, so a credential the
//     protected routes stop accepting mid-run is caught even when the who-am-I route still accepts it
//   - each surface probe in a bracket must pass in full (its status and every predicate), as an identity
//     probe must: one refused (401, 403 or the declared redirect) leaves the login unproven (surface-refused);
//     any other failed, inconclusive or unfinished surface probe leaves the actor not established
//     (surface-not-passed), so a 500, a 404 or a failing 200 on a protected route never establishes it
//   - a non-control row answered with a status other than 2xx (a 403, a 404, any refusal) reads inconclusive
//     (surface-unproven) when the actor has no surface control: its login was proven only on the identity
//     route, and a refusal counts only after the same actor's earlier complete 2xx on a protected route
//   - a credentialed 401 on a non-control row is an authentication failure (unauthenticated-401), not an
//     authorization refusal, unless the actor declares "refusesWith401" (the app answers denials with 401);
//     a lifecycle post-change row expects the declared refusal and is exempt from all three
// actor-identity/5 (per-check identity provenance; runs saved as /3 or /4 keep their rules):
//   - the identity and surface controls are re-sent at a probe point before the actor's first bracketed check
//     and after each of them ("before", "between" and "after"), so every bracketed check is covered by the
//     point before it and the point after it, with no change of the actor's standing shown in between
//   - identity is judged per check: the identity route's own proof (its controls passed, and were refused
//     without the credential, with a look-alike and with other actors' credentials) holds for the whole run;
//     a probe point that did not pass invalidates only the checks it covers, never an earlier check whose own
//     two points passed, and its reason is ranked across both covering points with the actor-level precedence;
//     the actor-level reason, loginProven and established still summarise every point
//   - the exception is a probe refused with the actor's own credential: at any point, it withholds every row of the
//     actor, required and identity controls included, since a credential that flaps can be refused for a check between
//     two accepting points; a surface probe is refused when it answers 401, 403 or the declared redirect, and reads
//     surface-refused; an identity probe is refused as identityRefused judges it (one of those statuses, or a complete
//     2xx JSON response that names another principal or none), and reads bracket-not-passed; when both were refused,
//     bracket-not-passed (the order of the actor-level reason); a probe that did not pass otherwise (a 500, a 404, an
//     unfinished probe) stays point-level
//   - a boundary row whose own predicates and effects passed and whose identity or allowed use was not
//     established for it (any identity reason) is the distinct state "prohibition observed, identity or allowed
//     use not established" (its decision; its status stays inconclusive, it is never a pass and the gate credits
//     no repair on it); an allowed-use control in that position is plainly inconclusive, since no prohibition was
//     observed
//   - a lifecycle change is attributed only when the changer's login was proven for the change check; a
//     post-change refusal after an unattributed change reads changer-login-unproven
//   - who created a captured value is established by the creator's identity at the capturing check
// actor-identity/6 (identity option B, src/http-rests-on.mjs; runs saved as /3, /4 or /5 keep their rules):
//   - a credentialed boundary check that declares restsOn drops control-not-passed only when its listed allowed-use controls
//     showed a served record on its own route at another record and passed untagged, every failed required control of
//     its actor showed a served record and failed only on positive readings that coverage gaps alone left missing (or
//     whose pass background attribution withheld), none of them is related to the check, and a listed control was sent
//     after the check and every failed control; every later step of the row's identity reason still runs
//   - every sent or not-sent row records its route segments and its controlScope (keyed digests, src/http-rests-on.mjs),
//     and a check that declares restsOn records the ids; the suite binds them with each check's record predicates, each
//     required control's declared partners and each restsOn check's related controls
//   - a run whose rows rest on a release validates only against its exported suite (rests-on-needs-suite)
//   - a withheld row that passed names its reason, and for control-not-passed the controls that did not pass, in its summary
//   - self-change (2026-10-23, src/http-lifecycle.mjs): a lifecycle change check sent by the changed actor itself is outside that
//     actor's brackets, like its post-change checks, so every probe point of the actor comes before it; its row's login rests on
//     the actor's whole pre-change proof (rowIdentityReason selfChange); earlier rule versions never carry one
//   - mirror phase (2026-10-25, NC11, src/two-identities.mjs): a generated mirror's row records mirrorOf and is sent in the mirror phase,
//     after every declared check, the final mark, the observers' stop and every actor's identity-refusal probes, outside its actor's
//     brackets. The actor's entry then carries mirrorPhase, probe points of its own laid out as the brackets are (before the actor's first
//     mirror, between its mirrors, after its last). Those points bind mirror rows only: the actor-level reason, loginProven, established
//     and every declared row read the declared points alone, and a probe refused at a mirror-phase point withholds every mirror row of the
//     actor (a refusal at a declared point still withholds every row, mirrors included). A mirror answered with a rate-limit status reads
//     inconclusive (evaluateHttpCheck, limitStatuses). A run whose rows record no mirrorOf (one main wrote before 2026-10-25, where a mirror was an ordinary
//     bracketed check) keeps those rules; earlier rule versions never carry one
export const IDENTITY_EVIDENCE_SCHEMA = 'actor-identity/6';
export const IDENTITY_EVIDENCE_SCHEMAS = Object.freeze(['actor-identity/3', 'actor-identity/4', 'actor-identity/5', IDENTITY_EVIDENCE_SCHEMA]);
// The rule version (3 to 6) an identity evidence schema names.
export const identityRulesOf = schema => schema === IDENTITY_EVIDENCE_SCHEMA ? 6 : schema === 'actor-identity/5' ? 5 : schema === 'actor-identity/4' ? 4 : 3;
// The distinct third state of a boundary row (actor-identity/5): the expected refusal was observed, and the actor's
// identity or allowed use was not established for this check (a login not proven for it, a required control or a
// surface probe that did not pass, an unattributed change). Never a pass; a pre-registered study scores it as an abstain.
export const IDENTITY_UNPROVEN_DECISION = 'prohibition-observed-identity-unproven';
export const ROW_DECISIONS = Object.freeze(['pass', 'fail', 'inconclusive', 'error', IDENTITY_UNPROVEN_DECISION]);
export const IDENTITY_UNPROVEN_SUMMARY = "Prohibition observed, identity or allowed use not established: the response matched the expected refusal, but this actor's identity or allowed use was not established for this check. A distinct state, never a pass.";
export const IDENTITY_REASONS = Object.freeze({
  'no-identity-control': 'This credentialed actor has no required GET control that returns its declared identity',
  'identity-control-not-passed': "This actor's identity control did not pass",
  'identity-probe-incomplete': 'An identity check could not complete (timeout, network error or run budget), so the login was not proven',
  'bracket-not-passed': "An identity control did not pass before or after the actor's other checks",
  'not-refused-without-credential': 'An identity control was not refused when sent without the credential',
  'accepted-invalid-credential': 'An identity control was not refused when sent with an invalid credential',
  'accepted-other-actor-credential': "An identity control was not refused when sent with another actor's credential",
  'control-not-passed': 'A required control for this actor did not pass',
  'sign-in-redirect': "The request was redirected to sign-in, so the actor's login did not hold for it",
  'surface-refused': "A surface control (an allowed GET on a protected route) was refused before or after the actor's other checks: the protected routes did not accept the credential the identity route accepted",
  'unauthenticated-401': 'The request was answered 401: the credential did not authenticate for it, so it is not an authorization refusal (the actor does not declare that the app answers denials with 401)',
  'surface-unproven': "This actor's login was proven only on its identity route: no required allowed-use GET control on a protected route was bracketed around its checks, so a refusal cannot be told apart from a credential the protected routes reject",
  'surface-not-passed': "A surface control (an allowed GET on a protected route) did not pass before or after the actor's other checks, so the credential was not shown to be accepted on the protected routes",
  'changer-login-unproven': "The account change was sent by an actor whose login was not proven for the change check, so the change is not attributed to a proven login and the post-change refusal cannot be credited",
});
// A login is proven when every identity check held; the actor is also
// established when all of its other required controls passed.
// surface-not-passed (actor-identity/4): the identity route accepted the credential and no protected route refused it,
// but a surface bracket did not pass, so the actor is not established.
export const LOGIN_PROVEN_REASONS = Object.freeze(['control-not-passed', 'surface-not-passed', 'established']);
// actor-identity/6: the identity assertion's expected text, and a withheld row's summary, which names the reason (and, for
// control-not-passed, the required controls of the actor that did not pass) instead of a lost login. From PR #275.
export const IDENTITY_EXPECTED = "The actor's identity, and any allowed use this check depends on, are established in this run";
export const IDENTITY_EXPECTED_LEGACY = "The actor's login is proven by its identity controls in this run";
export function withheldSummary(reason, controlIds = [], third = false) {
  const ids = reason === 'control-not-passed' ? controlIds : [];
  const why = `${IDENTITY_REASONS[reason]}${ids.length ? ` (${ids.join(', ')})` : ''}.`;
  return third ? `${IDENTITY_UNPROVEN_SUMMARY} Reason: ${why}` : `Response predicates passed, but this check was withheld: ${why}`;
}
// Index of the identity predicate among a check's JSON predicates, or -1.
export const identityIndexOf = (check, identityValue) => typeof identityValue === 'string' ? check.assertions.filter(a => a.kind.startsWith('json.')).findIndex(a => a.kind === 'json.equals' && a.expected === identityValue) : -1;
// Identity controls per credentialed actor: required GET controls with a 2xx
// status (enforced by validation) and a json.equals on the declared identityValue.
// Profile size (readiness gap 1). Count caps refuse a profile at load; nothing is truncated. The request bound counts what the
// run would send before it sends anything: one request per check, the identity probe points (actor-identity/5: the identity
// and surface controls before an actor's first bracketed check and after each of them), the cross probes (each identity
// control without a credential, with a look-alike, and with each other judged actor's credential) and the witness requests
// (one per observed check for each observer that sends one). A saved run takes about 600 to 760 bytes per planned request,
// so 2500 keeps a run within the store's 2 MiB file cap instead of sending everything and then being refused at save.
export const PROFILE_LIMITS = Object.freeze({ checks: 200, requiredControls: 50, assertions: 32, predicates: 31, effects: MAX_EFFECTS, clauses: 1000, captures: CAPTURE_LIMITS.perProfile, plannedRequests: 2500, crossProbes: 1000 });
// The identity plan's shape per credentialed actor with an applicable check, shared with the connector (planIdentity), so the
// request bound counts exactly what the connector plans. others: the bracketed checks (profile indices, in order). mirrors: the
// actor's generated mirrors (src/two-identities.mjs), outside its brackets: the connector sends them in the mirror phase, each
// between probe points of their own (one before the actor's first mirror and one after each).
export function identityPlanShape(target) {
  const control = identityControlPlan(target), postChange = postChangeIndex(target), selfChange = selfChangeIds(target), shapes = [];
  for (const [actorId, actor] of Object.entries(target.actors)) {
    const applicable = target.checks.map((check, index) => ({ check, index })).filter(({ check }) => check.actorId === actorId && check.applicability?.applies !== false);
    if (!actor.credentialEnv || !applicable.length) continue;
    const { identityControls, surfaceControls, refusesWith401, refusalStatuses } = control.get(actorId);
    const required = target.requiredControlIds.filter(id => target.checks.find(c => c.id === id).actorId === actorId);
    // A self-change check (src/http-lifecycle.mjs) is outside the brackets too: the point after it would carry the changed credential.
    const others = applicable.filter(({ check }) => !identityControls.includes(check.id) && !postChange.has(check.id) && !selfChange.has(check.id) && !Object.hasOwn(check, 'mirrorOf')).map(({ index }) => index);
    const mirrors = applicable.filter(({ check }) => Object.hasOwn(check, 'mirrorOf')).map(({ index }) => index);
    shapes.push({ actorId, actor, required, identityControls, surfaceControls, refusesWith401, refusalStatuses, others, mirrors });
  }
  return shapes;
}
export function requestPlan(target) {
  const shapes = identityPlanShape(target), judged = shapes.length;
  let probePointRequests = 0, crossProbes = 0;
  for (const s of shapes) {
    if (s.identityControls.length && s.others.length) probePointRequests += (s.identityControls.length + s.surfaceControls.length) * (s.others.length + 1);
    if (s.identityControls.length && s.mirrors.length) probePointRequests += (s.identityControls.length + s.surfaceControls.length) * (s.mirrors.length + 1);
    crossProbes += s.identityControls.length * (2 + judged - 1);
  }
  const checkRequests = target.checks.length;
  // A witness request per observed check (one with effects or claim rules) for each observer that sends one: every audit-file
  // observer, and an egress, SMTP or payments observer that declares a witness.
  const witnessing = (target.observers ?? []).filter(o => o?.type === 'audit-file' || (o !== null && typeof o === 'object' && o.witness !== undefined)).length;
  const observed = target.checks.filter(c => Array.isArray(c.effects) || Array.isArray(c.claims)).length;
  const witnessRequests = witnessing * observed;
  return { checkRequests, probePointRequests, crossProbes, witnessRequests, total: checkRequests + probePointRequests + crossProbes + witnessRequests };
}
function validateProfileSize(target) {
  const clauses = target.checks.reduce((n, check) => n + (Array.isArray(check.effects) ? check.effects.length : 0) + (Array.isArray(check.claims) ? check.claims.length : 0), 0);
  if (clauses > PROFILE_LIMITS.clauses) fail(`clause-limit: ${clauses} effect clauses and claim rules over ${PROFILE_LIMITS.clauses} in one profile`);
  const plan = requestPlan(target);
  if (plan.crossProbes > PROFILE_LIMITS.crossProbes) fail(`request-plan: crossProbes ${plan.crossProbes} over ${PROFILE_LIMITS.crossProbes}`);
  if (plan.total > PROFILE_LIMITS.plannedRequests) fail(`request-plan: total ${plan.total} over ${PROFILE_LIMITS.plannedRequests}`);
}
export function identityControlPlan(target) {
  const byId = new Map(target.checks.map(check => [check.id, check])), plan = new Map();
  for (const [actorId, actor] of Object.entries(target.actors)) {
    if (!actor.credentialEnv) continue;
    const controls = target.requiredControlIds.filter(id => byId.get(id).actorId === actorId && byId.get(id).method === 'GET' && identityIndexOf(byId.get(id), actor.identityValue) >= 0);
    // Surface controls (actor-identity/4): the actor's other required GET controls, on protected routes.
    const surface = target.requiredControlIds.filter(id => byId.get(id).actorId === actorId && byId.get(id).method === 'GET' && !controls.includes(id));
    plan.set(actorId, { identityControls: controls, surfaceControls: surface, refusesWith401: actor.refusesWith401 === true, predicateIndex: Object.fromEntries(controls.map(id => [id, identityIndexOf(byId.get(id), actor.identityValue)])),
      refusalStatuses: [401, 403, ...(actor.signInRedirectStatus ? [actor.signInRedirectStatus] : [])] });
  }
  return plan;
}
// A probe sent without the actor's own credential counts as refused for 401,
// 403, the declared sign-in redirect, or a complete 2xx JSON response whose
// identity predicate fails (the response does not name the actor). The same
// test judges an identity probe sent with it at a probe point (Decision 3b).
export function identityRefused(probe, refusalStatuses) {
  if (!probe.requestAttempted || probe.httpStatus === null) return false;
  if (refusalStatuses.includes(probe.httpStatus)) return true;
  return probe.httpStatus >= 200 && probe.httpStatus <= 299 && probe.transportOutcome === 'complete' && probe.predicates.some(p => p.identity && p.outcome === 'fail');
}
// surfaceControls (actor-identity/4): a bracket probe of these controls that is refused (401, 403 or the declared
// redirect) leaves the login unproven; one that does not pass for another reason (a 500, a 404, a failing or
// inconclusive 200) leaves the actor not established (surface-not-passed, or control-not-passed when a required
// control also failed). Checked after the credential probes, so it never hides them.
// between (actor-identity/5): the probes of every intermediate probe point, flattened; the actor-level reason reads
// every point, so loginProven and established still summarise the whole run.
export function identityReason({ identityControls, identityControlsPassed, requiredPassed, before, after, anonymous, invalid, cross, refusalStatuses, surfaceControls = [], between = [] }) {
  if (!identityControls.length) return 'no-identity-control';
  if (!identityControlsPassed) return 'identity-control-not-passed';
  const brackets = [...before, ...between, ...after];
  if ([...brackets, ...anonymous, ...invalid, ...cross].some(probe => probe.outcome === 'error')) return 'identity-probe-incomplete';
  const surface = probe => surfaceControls.includes(probe.controlId);
  if (brackets.some(probe => !surface(probe) && probe.outcome !== 'pass')) return 'bracket-not-passed';
  if (brackets.some(probe => surface(probe) && refusalStatuses.includes(probe.httpStatus))) return 'surface-refused';
  if (anonymous.some(probe => !identityRefused(probe, refusalStatuses))) return 'not-refused-without-credential';
  if (invalid.some(probe => !identityRefused(probe, refusalStatuses))) return 'accepted-invalid-credential';
  if (cross.some(probe => !identityRefused(probe, refusalStatuses))) return 'accepted-other-actor-credential';
  if (!requiredPassed) return 'control-not-passed';
  return brackets.some(probe => surface(probe) && probe.outcome !== 'pass') ? 'surface-not-passed' : 'established';
}
// One probe point (actor-identity/5): the identity and surface controls re-sent before or after one check. The same
// precedence as the actor-level reason: an unfinished probe, an identity probe that did not pass, a refused surface
// probe (login not proven), then a surface probe that did not pass for another reason (not established).
export function pointReason(probes, surfaceControls, refusalStatuses) {
  const surface = probe => surfaceControls.includes(probe.controlId);
  if (probes.some(probe => probe.outcome === 'error')) return 'identity-probe-incomplete';
  if (probes.some(probe => !surface(probe) && probe.outcome !== 'pass')) return 'bracket-not-passed';
  if (probes.some(probe => surface(probe) && refusalStatuses.includes(probe.httpStatus))) return 'surface-refused';
  if (probes.some(probe => surface(probe) && probe.outcome !== 'pass')) return 'surface-not-passed';
  return null;
}
// The two probe points that cover one check (actor-identity/5): the one before it and the one after it. others: the
// actor's bracketed checks in run order (its non-identity, non-post-change applicable checks). null for any other check.
export function coveringPoints(entry, others, id) {
  const k = others.indexOf(id);
  if (k < 0) return null;
  const between = Array.isArray(entry.between) ? entry.between : [];
  return [k === 0 ? entry.before : between[k - 1]?.probes ?? [], k === others.length - 1 ? entry.after : between[k]?.probes ?? []];
}
// The identity route's own proof, read without any probe point (actor-identity/5): a login-level reason here holds
// for every check of the actor; 'control-not-passed' and 'established' are the other two outcomes.
export const routeReason = entry => identityReason({ ...entry, before: [], after: [], between: [] });
export const loginLevel = reason => reason !== null && !LOGIN_PROVEN_REASONS.includes(reason);
// Did a surface probe of the actor answer a refusal status at any probe point, before, between or after (actor-identity/5)?
// Read from the probes themselves, never from the actor-level reason, where bracket-not-passed outranks surface-refused.
// Memoized per entry object: rows read these per row, and an entry's probes never change once recorded.
const refusedMemo = new WeakMap();
const memoOnEntry = (key, fn) => entry => { let m = refusedMemo.get(entry); if (!m) refusedMemo.set(entry, m = {}); if (!(key in m)) m[key] = fn(entry); return m[key]; };
export const surfaceRefusedAnywhere = memoOnEntry('surface', entry => [...entry.before, ...(Array.isArray(entry.between) ? entry.between : []).flatMap(point => point.probes), ...entry.after]
  .some(probe => entry.surfaceControlIds.includes(probe.controlId) && entry.refusalStatuses.includes(probe.httpStatus)));
// Was an identity probe of the actor refused at any probe point, before, between or after (actor-identity/5)?
// Each probe at a probe point carries the actor's own credential, and one that is not a surface probe is an identity probe.
// Refused has the meaning identityRefused gives it (Decision 3b): a refusal status, or a complete 2xx JSON response whose
// identity predicate fails (it names another principal, or null, as a signed-out session route does).
// Read from the probes, never from the actor-level reason, where an identity probe answering 500 also reads bracket-not-passed.
export const identityRefusedAnywhere = memoOnEntry('identity', entry => [...entry.before, ...(Array.isArray(entry.between) ? entry.between : []).flatMap(point => point.probes), ...entry.after]
  .some(probe => !entry.surfaceControlIds.includes(probe.controlId) && identityRefused(probe, entry.refusalStatuses)));
// The mirror phase (2026-10-25): the same two readings over the actor's mirror-phase points only (entry.mirrorPhase), which bind its
// mirror rows alone.
const mirrorPhaseProbes = entry => { const m = entry.mirrorPhase; return m !== null && typeof m === 'object' && Array.isArray(m.before) && Array.isArray(m.between) && Array.isArray(m.after)
  ? [...m.before, ...m.between.flatMap(point => Array.isArray(point?.probes) ? point.probes : []), ...m.after] : []; };
export const mirrorIdentityRefused = memoOnEntry('mirror-identity', entry => mirrorPhaseProbes(entry).some(probe => !entry.surfaceControlIds.includes(probe.controlId) && identityRefused(probe, entry.refusalStatuses)));
export const mirrorSurfaceRefused = memoOnEntry('mirror-surface', entry => mirrorPhaseProbes(entry).some(probe => entry.surfaceControlIds.includes(probe.controlId) && entry.refusalStatuses.includes(probe.httpStatus)));
// A row's decision (actor-identity/5): its status, except that a boundary row whose own predicates and effects passed
// and whose identity reason is non-null (identity or allowed use not established for it) is the distinct state
// IDENTITY_UNPROVEN_DECISION.
export const rowDecision = (row, identityReasonForRow) => identityReasonForRow !== null && row.severity !== 'control' && passedBeforeIdentity(row) ? IDENTITY_UNPROVEN_DECISION : row.status;
// Which rows carry the inconclusive identity assertion, and why. For a
// credentialed actor: every row when its login was not proven (so a passing
// required control of that actor is inconclusive and no per-run view can show
// a clean pass), every row except its required controls when the login was
// proven but a required control failed, and otherwise a non-control row
// redirected to its declared sign-in status. For an uncredentialed actor: its
// non-control rows when one of its required controls did not pass.
// A post-change row (lifecycle) expects the refusal, so its sign-in redirect is the declared outcome, not a lost login.
// rules: the identity rule version (3, 4 or 5, from the evidence schema); see IDENTITY_EVIDENCE_SCHEMA.
// Under rules 5 (per check): route is routeReason(entry); points is coveringPoints(entry, others, id) for a bracketed
// check (null otherwise); changerUnproven says the post-change row's change was sent by an actor whose login was not
// proven for the change check. The connector (identityJudge) and the validator (httpIdentity) both call this function.
// Under rules 6: released says option B released the row from control-not-passed (src/http-rests-on.mjs restsOnReleases);
// every later step still runs. mirror says the row is a generated mirror sent in the mirror phase (it records mirrorOf); its
// points are then its two covering mirror-phase points (coveringPoints over entry.mirrorPhase and the actor's mirror ids).
export function rowIdentityReason({ credentialed, required, control, entry, httpStatus, controlFailed, postChange = false, rules = 4, route = null, points = null, changerUnproven = false, released = false, selfChange = false, mirror = false }) {
  if (credentialed) {
    if (rules >= 5) {
      // A probe refused with the actor's own credential at any probe point withholds every row of the actor, required and
      // identity controls included (route-level): a credential that flaps (an intermittent session store, a rate limiter)
      // can be refused for a check that sits between two accepting points, and the run already holds direct evidence of a
      // refusal. A refused identity probe reads bracket-not-passed (Decisions 3a and 3b: a refusal status, or a complete 2xx
      // naming another principal or null) and a refused surface probe surface-refused (Decision 3); when both were refused,
      // bracket-not-passed, which identityReason ranks first. A probe that did not pass for another reason (a 500, a 404,
      // an unfinished probe) binds only the checks its point covers, below. A probe refused at a mirror-phase point withholds
      // the actor's mirror rows the same way, and never a declared row.
      if (identityRefusedAnywhere(entry) || (mirror && mirrorIdentityRefused(entry))) return 'bracket-not-passed';
      if (surfaceRefusedAnywhere(entry) || (mirror && mirrorSurfaceRefused(entry))) return 'surface-refused';
      // The identity route's own proof holds for the whole run; a probe point binds only the checks it covers.
      if (loginLevel(route)) return route;
      // A self-change check (src/http-lifecycle.mjs) has no probe point after it: its login rests on the actor's whole
      // pre-change proof, every probe point of which came before it.
      if (selfChange) return loginLevel(entry.reason) ? entry.reason : null;
      // The two covering points are ranked together with the actor-level precedence (pointReason over both), so a
      // login-level reason at either point outranks a surface-not-passed at the other, whichever point comes first.
      const point = points === null ? null : pointReason([...points[0], ...points[1]], entry.surfaceControlIds, entry.refusalStatuses);
      // A required control is demoted only when the login was not proven for it, never when a surface probe failed for another
      // reason or another required control failed; an identity control is covered by no point and rests on the route proof.
      if (required) return loginLevel(point) ? point : null;
      // A post-change row rests on the actor's whole pre-change proof, then on the attribution of the change itself.
      if (postChange) return !entry.established ? entry.reason : changerUnproven ? 'changer-login-unproven' : null;
      // The same precedence as the actor-level reason: a probe point that did not pass before a failed required control.
      if (point !== null) return point;
      if (route === 'control-not-passed' && !(rules >= 6 && released)) return route;
      const redirect = entry.refusalStatuses[2];
      if (!control && redirect !== undefined && httpStatus === redirect) return 'sign-in-redirect';
      if (control || httpStatus === null || (httpStatus >= 200 && httpStatus <= 299)) return null;
      if (httpStatus === 401 && entry.refusesWith401 !== true) return 'unauthenticated-401';
      return !entry.surfaceControlIds.length ? 'surface-unproven' : null;
    }
    if (required) return entry.loginProven ? null : entry.reason;
    if (!entry.established) return entry.reason;
    const redirect = entry.refusalStatuses[2];
    if (!control && !postChange && redirect !== undefined && httpStatus === redirect) return 'sign-in-redirect';
    if (rules < 4 || control || postChange || httpStatus === null || (httpStatus >= 200 && httpStatus <= 299)) return null;
    // A credentialed 401 counts as a refusal only when declared and when a surface control brackets the actor's checks.
    if (httpStatus === 401 && entry.refusesWith401 !== true) return 'unauthenticated-401';
    // Any other refusal (a 403, a 404, a redirect) counts only after the same actor's earlier complete 2xx on a protected
    // route: a surface control in its passed before-bracket. Without one, the identity route alone proved the login.
    return !entry.surfaceControlIds.length ? 'surface-unproven' : null;
  }
  return !control && controlFailed ? 'control-not-passed' : null;
}
// actor-identity/6 (src/http-rests-on.mjs recordForm, from PR #275): was a required control's own identity proven strictly
// enough for it to show a served record? Its row's identity reason is null and, for a credentialed actor, the actor's login
// was proven and every probe at every probe point of the actor passed (before, between and after), not only the two points
// covering the control: a required control keeps a null reason when a surface probe around it answered, say, 500, and an
// identity control rests on the route proof alone. args: rowIdentityReason's arguments; the connector (identityJudge) and the
// validator (httpIdentity) both call it.
export function recordIdentityProven(args) {
  if (rowIdentityReason({ ...args, released: false }) !== null) return false;
  if (!args.credentialed) return true;
  const entry = args.entry;
  if (!entry || entry.loginProven !== true || !Array.isArray(entry.before) || !Array.isArray(entry.after)) return false;
  const between = Array.isArray(entry.between) ? entry.between.flatMap(point => Array.isArray(point?.probes) ? point.probes : [point]) : [];
  return pointReason([...entry.before, ...between, ...entry.after], entry.surfaceControlIds, entry.refusalStatuses) === null;
}

// ---------------------------------------------------------------------------
// Request preconditions (typed captures and the lifecycle phase). A check whose precondition did
// not hold when it was due is not sent; a sent check whose captured value came from an actor whose
// login was not proven carries the same assertion. Either way the row is inconclusive, never pass.
export const PRECONDITION_ASSERTION = 'Request precondition established';
export const PRECONDITION_EXPECTED = 'Every value this check uses was captured from its declared creator, and any declared account change took effect';
export const PRECONDITION_REASONS = Object.freeze({
  'change-not-confirmed': 'The declared account change did not pass when it was sent, so the pre-change credential was not re-sent',
  'capture-unavailable': 'A value this check uses was not captured from its creating check, so the request was not sent',
  'creator-login-unproven': "The login of the actor that created a captured value was not proven, so who created that resource is not established",
  'change-not-attributed': "The declared account change passed when it was sent, but the run's attribution withheld its pass, so the change is not attributed to its check and this check never passes (a credential that still works still fails)",
  [RUN_BUDGET_EXHAUSTED]: "The declared run budget could not hold this check's request, effect horizon and window close, so the request was not sent",
  [SUSPEND_STOPPED]: "A host sleep left an earlier check's wait short of its declared awake time, so a send that check's request caused could have landed in this check's window; the run stopped and the request was not sent",
});
// run-budget-exhausted only in a run whose target declared timing (capturePreconditions), and from the first such row on;
// host-suspend-run-stopped only in a run without one, on every applicable row after the first check whose wait a sleep left short or
// that took the later checks' time to make it up (capturePreconditions).
export const NOT_SENT_REASONS = Object.freeze(['change-not-confirmed', 'capture-unavailable', RUN_BUDGET_EXHAUSTED, SUSPEND_STOPPED]);
// A row's status when it was decided, before end-of-run assertions (actor identity, a creator's unproven login).
export const passedAtSend = row => row?.status === 'pass' || (row?.status === 'inconclusive' && Array.isArray(row.assertions)
  && row.assertions.every(a => a?.status === 'pass' || a?.name === IDENTITY_ASSERTION || (a?.name === PRECONDITION_ASSERTION && a?.actual === PRECONDITION_REASONS['creator-login-unproven'])));
// A change check that passed when it was sent and whose allowed-use control's positive pass was then withheld because its effect
// may be another's: by the run's attribution (src/http-attribution.mjs, an attribution tag) or by settlement under another check's
// correlation token (src/http-settlement.mjs, the settlement tag effect-correlated-elsewhere). Its only other non-passing rows are
// effect or claim rows carrying that tag, which the validator recomputes. Its post-change checks were sent and read
// change-not-attributed (the reason's text names attribution; a correlated-elsewhere withhold is the same "not attributed to its
// check", and the stored text stays as saved runs carry it).
// Later outcomes (provider-feed/6, ADDENDUM-R1 M5): a change check whose positive pass the later-outcome stage withheld (its email later
// bounced, say; a control's lowering is always inconclusive, carrying the later tag) is not attributed to its check either.
const withheldRow = a => a?.status === 'inconclusive' && (typeof a?.attribution === 'string' || a?.settlement === 'effect-correlated-elsewhere' || typeof a?.later === 'string') && (EFFECT_ASSERTION_PATTERN.test(String(a?.name)) || CLAIM_ASSERTION_PATTERN.test(String(a?.name)));
export const withheldByAttribution = row => row?.status === 'inconclusive' && Array.isArray(row.assertions) && row.assertions.some(withheldRow)
  && row.assertions.every(a => a?.status === 'pass' || a?.name === IDENTITY_ASSERTION || (a?.name === PRECONDITION_ASSERTION && a?.actual === PRECONDITION_REASONS['creator-login-unproven'])
    || withheldRow(a));
// A change check that passed when it was sent and that an app-log admission (src/app-log-verdicts.mjs) then made fail: its own
// application's log records an action the check forbids. Like an attribution withhold, the change is not attributed to its
// check: its post-change checks were sent and read change-not-attributed, so the run stays valid evidence. Its only other
// non-passing rows are attribution-withheld ones.
const admittedRow = a => a?.status === 'fail' && a?.appLog?.finding === 'app-log-unobserved-admission' && (EFFECT_ASSERTION_PATTERN.test(String(a?.name)) || CLAIM_ASSERTION_PATTERN.test(String(a?.name)));
export const withheldByAdmission = row => row?.status === 'fail' && Array.isArray(row.assertions) && row.assertions.some(admittedRow)
  && row.assertions.every(a => a?.status === 'pass' || a?.name === IDENTITY_ASSERTION || (a?.name === PRECONDITION_ASSERTION && a?.actual === PRECONDITION_REASONS['creator-login-unproven'])
    || withheldRow(a) || admittedRow(a));
// A change check that passed when it was sent and that rls-zero-row (NC9 item 3, src/http-effects.mjs) then made fail: its declared write
// changed no row although another write had matched its clause. Like an admission, the change is not attributed to its check: its
// post-change checks were sent and read change-not-attributed (PR520 review MAJOR 1). Only a clause that passed when sent, or that a
// later stage withheld after it passed, counts (PR520 review R2-1): one that read missing when sent was never confirmed, so its
// post-change checks were not sent, and the run reads as without the stage.
const zeroRowRow = a => a?.status === 'fail' && a?.zeroRow?.finding === 'rls-zero-row' && EFFECT_ASSERTION_PATTERN.test(String(a?.name))
  && (a.zeroRow.priorVerdict === 'pass' || (a.zeroRow.priorVerdict === 'inconclusive' && (typeof a.attribution === 'string' || a.settlement === 'effect-correlated-elsewhere' || typeof a.later === 'string')));
export const withheldByZeroRow = row => row?.status === 'fail' && Array.isArray(row.assertions) && row.assertions.some(zeroRowRow)
  && row.assertions.every(a => a?.status === 'pass' || a?.name === IDENTITY_ASSERTION || (a?.name === PRECONDITION_ASSERTION && a?.actual === PRECONDITION_REASONS['creator-login-unproven'])
    || withheldRow(a) || admittedRow(a) || zeroRowRow(a));
export const withheldAfterSend = row => withheldByAttribution(row) || withheldByAdmission(row) || withheldByZeroRow(row);
// Read one JSON pointer from a parsed response: { present, value }.
export function readPointer(json, pointer) { const found = lookup(json, pointerTokens(pointer)); return { present: found.present, value: found.value }; }

// ---------------------------------------------------------------------------
// Saved HTTP run evidence. validateHttpRunEvidence is the one validator for
// local-http-response runs: supported version pairs, the v1 downgrade check,
// per-row observation consistency, the expected suite when given, and for v2
// the recomputed actor-identity/3 evidence. It checks internal consistency
// only: saved evidence is unsigned, so a fully consistent forgery is out of scope.
export const HTTP_EVIDENCE_VERSIONS = Object.freeze([
  Object.freeze({ adapterVersion: 'loopback-response-contract/1', assertionSchemaVersion: 'http-contract/2' }),
  Object.freeze({ adapterVersion: 'loopback-response-contract/2', assertionSchemaVersion: 'http-contract/3' }),
  // v3: v2 plus declared observers and sealed effect windows (http-contract/4).
  Object.freeze({ adapterVersion: 'loopback-response-contract/3', assertionSchemaVersion: ASSERTION_SCHEMA_VERSION }),
]);
// detail: why, when the code alone does not say (for example effect-window-exact: a sealed window an observer could not have produced).
export class HttpEvidenceError extends Error { constructor(code, detail) { super(code); this.code = code; if (detail !== undefined) this.detail = detail; } }
const effectDetail = error => error?.name === 'EffectError' && typeof error.code === 'string' ? `effect-window-${error.code}` : ['effect-trace', 'effect-verdict'].includes(error?.message) ? error.message : 'effect-recompute-failed';
const need = (ok, code = 'invalid-run-evidence') => { if (!ok) throw new HttpEvidenceError(code); };
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const same = (a, b) => stable(a) === stable(b);
const sortedCopy = values => [...values].sort();
const hash64 = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const isPair = (run, index) => run.adapterVersion === HTTP_EVIDENCE_VERSIONS[index].adapterVersion && run.assertionSchemaVersion === HTTP_EVIDENCE_VERSIONS[index].assertionSchemaVersion;
// v2 and v3 runs carry actor-identity evidence; v3 runs may also carry effect windows.
const isV2Run = run => isPair(run, 1) || isPair(run, 2);
const isV3Run = run => isPair(run, 2);
const probeOutcomes = ['pass', 'fail', 'inconclusive', 'error'], transportOutcomes = ['complete', 'invalid-json', 'timeout', 'network', 'too-large'];
export function statusCodes(label, v2) {
  const single = /^HTTP ([1-5][0-9]{2})$/.exec(label);
  if (single) return [Number(single[1])];
  const set = v2 && /^HTTP ((?:[3-5][0-9]{2}, ){0,3}[3-5][0-9]{2}) or ([3-5][0-9]{2})$/.exec(label);
  if (!set) return null;
  const codes = [...set[1].split(', '), set[2]].map(Number);
  return new Set(codes).size === codes.length ? codes : null;
}
// Recompute a probe's verdict from its stored status, transport result and
// predicate outcomes, using the control row's declared status and predicate kinds.
// A surface probe (actor-identity/4, brackets only) re-sends a protected-route control: it has no identity predicate.
function validateIdentityProbe(probe, controlRow, kind, crossActorId, surface = false) {
  need(record(probe) && probe.kind === kind && (kind === 'cross' ? probe.crossActorId === crossActorId : !Object.hasOwn(probe, 'crossActorId')));
  need(typeof probe.requestAttempted === 'boolean' && transportOutcomes.includes(probe.transportOutcome) && probeOutcomes.includes(probe.outcome));
  need(Number.isSafeInteger(probe.requestTimeoutMs) && probe.requestTimeoutMs >= 0 && (probe.requestAttempted ? probe.requestTimeoutMs > 0 : probe.requestTimeoutMs === 0));
  need(probe.httpStatus === null || (Number.isInteger(probe.httpStatus) && probe.httpStatus >= 100 && probe.httpStatus <= 599));
  const terminal = ['complete', 'invalid-json'].includes(probe.transportOutcome);
  if (!probe.requestAttempted) need(probe.httpStatus === null && probe.transportOutcome === 'timeout');
  if (terminal) need(probe.requestAttempted && probe.httpStatus !== null);
  const declared = /^HTTP (2[0-9]{2})$/.exec(controlRow?.assertions?.find(a => a?.name === 'HTTP status matches contract')?.expected ?? '');
  need(declared !== null);
  need(probe.statusOutcome === (probe.httpStatus === null ? 'inconclusive' : probe.httpStatus === Number(declared[1]) ? 'pass' : 'fail'));
  need(Array.isArray(probe.predicates) && same(probe.predicates.map(p => p?.kind), controlRow.observed.predicates.map(p => p.kind)));
  need(probe.predicates.every(p => typeof p.identity === 'boolean' && ['pass', 'fail', 'inconclusive'].includes(p.outcome)));
  need(surface ? probe.predicates.every(p => p.identity === false) : probe.predicates.filter(p => p.identity).length === 1 && probe.predicates.find(p => p.identity).kind === 'json.equals');
  if (probe.transportOutcome !== 'complete') need(probe.predicates.every(p => p.outcome === 'inconclusive'));
  else need(probe.predicates.every(p => p.kind === 'json.notContains' || p.kind === FOREIGN_VALUES_KIND || p.outcome !== 'inconclusive'));
  const outcomes = [probe.statusOutcome, ...probe.predicates.map(p => p.outcome)];
  need(probe.outcome === (outcomes.includes('fail') ? 'fail' : !terminal ? 'error' : outcomes.includes('inconclusive') ? 'inconclusive' : 'pass'));
  return surface ? null : probe.predicates.findIndex(p => p.identity);
}
// A row's status before the identity assertion was added: the connector judges
// identity first, then turns a passing row of an unproven actor inconclusive.
// validateHttpObservation separately checks the row's status against its assertions.
const passedBeforeIdentity = row => row?.status === 'pass' || (row?.status === 'inconclusive' && Array.isArray(row.assertions)
  && row.assertions.some(a => a?.name === IDENTITY_ASSERTION) && row.assertions.every(a => a?.name === IDENTITY_ASSERTION || a?.status === 'pass'));
// mirrorIds: the rows sent in the mirror phase (mirrorPhaseOf), outside their actors' brackets.
function httpIdentity(run, expectedSuite, mirrorIds = new Set()) {
  const rowsById = new Map(run.results.map(row => [row?.id, row]));
  const observation = row => row?.status !== 'not_applicable' && row?.trace?.[0]?.type === 'http-observation' ? row.trace[0].data : null;
  const actorOf = row => observation(row)?.actorId, required = Array.isArray(run.requiredControlIds) ? run.requiredControlIds : [];
  const modes = new Map();
  for (const row of run.results) {
    const evidence = observation(row); if (!record(evidence)) continue;
    need(['none', 'bearer', 'cookie', 'header'].includes(evidence.credentialMode));
    need(!modes.has(evidence.actorId) || modes.get(evidence.actorId) === evidence.credentialMode); modes.set(evidence.actorId, evidence.credentialMode);
  }
  const credentialed = actor => modes.has(actor) && modes.get(actor) !== 'none';
  for (const row of run.results) if (row?.severity === 'control' && credentialed(actorOf(row))) need(/^HTTP 2[0-9]{2}$/.test(row.assertions?.find(a => a?.name === 'HTTP status matches contract')?.expected ?? ''));
  const evidence = run.identityEvidence;
  need(record(evidence) && IDENTITY_EVIDENCE_SCHEMAS.includes(evidence.schema) && Array.isArray(evidence.actors) && evidence.actors.length <= 50);
  const rules = identityRulesOf(evidence.schema);
  // The exported suite names the identity rules its runs follow.
  if (expectedSuite?.identitySchema !== undefined) need(expectedSuite.identitySchema === evidence.schema, 'unexpected-suite-evidence');
  const judged = sortedCopy([...modes.keys()].filter(credentialed));
  need(same(sortedCopy(evidence.actors.map(entry => entry?.actorId)), judged));
  const entries = new Map(), postChange = new Map(), derived = new Map(), lifecycles = [], selfChanges = new Set();
  for (const entry of evidence.actors) {
    need(record(entry) && entry.credentialMode === modes.get(entry.actorId) && typeof entry.established === 'boolean' && typeof entry.loginProven === 'boolean');
    const actor = entry.actorId, own = required.filter(id => actorOf(rowsById.get(id)) === actor);
    need(same(entry.requiredControlIds, own));
    need(Array.isArray(entry.identityControlIds) && new Set(entry.identityControlIds).size === entry.identityControlIds.length
      && entry.identityControlIds.every(id => own.includes(id) && observation(rowsById.get(id))?.method === 'GET' && rowsById.get(id).observed.predicates.some(p => p.kind === 'json.equals')));
    need(Array.isArray(entry.refusalStatuses) && entry.refusalStatuses[0] === 401 && entry.refusalStatuses[1] === 403 && entry.refusalStatuses.length <= 3
      && entry.refusalStatuses.slice(2).every(code => [301, 302, 303, 307, 308].includes(code)));
    if (expectedSuite) {
      const suiteIdentity = (expectedSuite.checks || []).filter(c => c.actorId === actor && c.identityControl === true);
      need(same(sortedCopy(entry.identityControlIds), sortedCopy(suiteIdentity.map(c => c.id))), 'unexpected-suite-evidence');
      need(suiteIdentity.every(c => same(c.refusalStatuses, entry.refusalStatuses)), 'unexpected-suite-evidence');
      if (rules >= 4 && expectedSuite.identitySchema !== undefined) need(suiteIdentity.every(c => c.refusesWith401 === entry.refusesWith401), 'unexpected-suite-evidence');
    }
    // actor-identity/4: the surface controls are the actor's other required GET controls; refusesWith401 is declared.
    const surface = rules >= 4 ? own.filter(id => observation(rowsById.get(id))?.method === 'GET' && !entry.identityControlIds.includes(id)) : [];
    if (rules >= 4) need(Array.isArray(entry.surfaceControlIds) && same(entry.surfaceControlIds, surface) && typeof entry.refusesWith401 === 'boolean');
    else need(!Object.hasOwn(entry, 'surfaceControlIds') && !Object.hasOwn(entry, 'refusesWith401'));
    // Lifecycle: post-change rows re-send the pre-change credential; the identity proof brackets only the rows before the change.
    const post = lifecycleOf(entry, actor, { run, rowsById, actorOf, required, expectedSuite, rules });
    if (post.size) lifecycles.push({ entry, actor, change: rowsById.get(entry.lifecycle.changeCheckId) });
    // actor-identity/4: a changed actor's post-change refusals rest on its pre-change acceptance on the protected routes.
    if (post.size && rules >= 4) need(Array.isArray(entry.surfaceControlIds) && entry.surfaceControlIds.length >= 1);
    // The actor's bracketed checks, in run order: every sent row of its own that is neither an identity control nor post-change.
    const selfId = post.size && actorOf(rowsById.get(entry.lifecycle.changeCheckId)) === actor ? entry.lifecycle.changeCheckId : null;
    if (selfId !== null) selfChanges.add(selfId);
    // The mirror phase: the actor's mirror rows are outside its brackets, between probe points of their own (entry.mirrorPhase).
    const bracketedIds = run.results.filter(row => actorOf(row) === actor && !entry.identityControlIds.includes(row.id) && !post.has(row.id) && row.id !== selfId && !mirrorIds.has(row.id)).map(row => row.id);
    const mirrorRowIds = run.results.filter(row => actorOf(row) === actor && mirrorIds.has(row.id)).map(row => row.id);
    const bracketed = entry.identityControlIds.length && bracketedIds.length ? [...entry.identityControlIds, ...surface] : [];
    const others = judged.filter(other => other !== actor);
    const expected = { before: bracketed.map(id => [id]), after: bracketed.map(id => [id]), anonymous: entry.identityControlIds.map(id => [id]), invalid: entry.identityControlIds.map(id => [id]),
      cross: entry.identityControlIds.flatMap(id => others.map(other => [id, other])) };
    const identityIndex = new Map();
    const checkProbe = (probe, kind) => {
      const isSurface = surface.includes(probe.controlId);
      const index = validateIdentityProbe(probe, rowsById.get(probe.controlId), kind, kind === 'cross' ? probe.crossActorId : undefined, isSurface);
      if (isSurface) return;
      need(!identityIndex.has(probe.controlId) || identityIndex.get(probe.controlId) === index); identityIndex.set(probe.controlId, index);
    };
    for (const kind of ['before', 'after', 'anonymous', 'invalid', 'cross']) {
      need(Array.isArray(entry[kind]) && same(entry[kind].map(probe => kind === 'cross' ? [probe?.controlId, probe?.crossActorId] : [probe?.controlId]), expected[kind]));
      for (const probe of entry[kind]) checkProbe(probe, kind);
    }
    // actor-identity/5: one intermediate probe point after each bracketed check but the last, named by that check.
    if (rules >= 5) {
      const after = bracketedIds.slice(0, -1);
      need(Array.isArray(entry.between) && entry.between.length === after.length);
      entry.between.forEach((point, k) => {
        need(record(point) && Object.keys(point).length === 2 && point.afterCheckId === after[k] && Array.isArray(point.probes) && same(point.probes.map(probe => [probe?.controlId]), expected.before));
        for (const probe of point.probes) checkProbe(probe, 'between');
      });
    } else need(!Object.hasOwn(entry, 'between'));
    // The mirror phase: exactly when the actor has mirror rows, its points are laid out as the brackets are, over those rows (a probe point
    // before the first, one after each but the last, named by it, and one after the last), each the identity and surface controls.
    if (mirrorRowIds.length) {
      const phase = entry.mirrorPhase, controls = [...entry.identityControlIds, ...surface], layout = controls.map(id => [id]);
      need(entry.identityControlIds.length >= 1 && record(phase) && same(Object.keys(phase), ['before', 'between', 'after']));
      for (const side of ['before', 'after']) {
        need(Array.isArray(phase[side]) && same(phase[side].map(probe => [probe?.controlId]), layout));
        for (const probe of phase[side]) checkProbe(probe, side);
      }
      const named = mirrorRowIds.slice(0, -1);
      need(Array.isArray(phase.between) && phase.between.length === named.length);
      phase.between.forEach((point, k) => {
        need(record(point) && Object.keys(point).length === 2 && point.afterCheckId === named[k] && Array.isArray(point.probes) && same(point.probes.map(probe => [probe?.controlId]), layout));
        for (const probe of point.probes) checkProbe(probe, 'between');
      });
    } else need(!Object.hasOwn(entry, 'mirrorPhase'));
    if (expectedSuite) for (const [id, index] of identityIndex) need((expectedSuite.checks || []).find(c => c.id === id)?.identityPredicate === index, 'unexpected-suite-evidence');
    const inputs = { identityControls: entry.identityControlIds, identityControlsPassed: entry.identityControlIds.every(id => passedBeforeIdentity(rowsById.get(id))),
      requiredPassed: own.every(id => passedBeforeIdentity(rowsById.get(id))), before: entry.before, after: entry.after, anonymous: entry.anonymous, invalid: entry.invalid, cross: entry.cross, refusalStatuses: entry.refusalStatuses, surfaceControls: surface,
      between: rules >= 5 ? entry.between.flatMap(point => point.probes) : [] };
    const reason = identityReason(inputs);
    need(entry.reason === reason && entry.loginProven === LOGIN_PROVEN_REASONS.includes(reason) && entry.established === (reason === 'established'));
    entries.set(actor, entry);
    derived.set(actor, { bracketedIds, mirrorRowIds, route: rules >= 5 ? routeReason(inputs) : null });
    for (const id of post) postChange.set(id, entry);
  }
  // The exported suite fixes the declared lifecycle entries.
  if (expectedSuite) need(same(sortedCopy((expectedSuite.lifecycle ?? []).map(e => stable(e))), sortedCopy([...entries.values()].filter(e => e.lifecycle !== undefined).map(e => stable({ changeCheckId: e.lifecycle.changeCheckId, actorId: e.actorId, after: e.lifecycle.after })))), 'unexpected-suite-evidence');
  const controlFailed = new Set(required.filter(id => rowsById.get(id)?.status !== 'pass' && !credentialed(actorOf(rowsById.get(id)))).map(id => actorOf(rowsById.get(id))));
  const argsUnder = (row, released) => {
    const actor = actorOf(row), entry = entries.get(actor), own = derived.get(actor), mirror = mirrorIds.has(row.id);
    return { credentialed: credentialed(actor), required: required.includes(row.id), control: row.severity === 'control', entry, httpStatus: observation(row).httpStatus, controlFailed: controlFailed.has(actor), postChange: postChange.has(row.id), rules,
      route: own?.route ?? null, points: rules >= 5 && entry ? (mirror ? coveringPoints(entry.mirrorPhase, own.mirrorRowIds, row.id) : coveringPoints(entry, own.bracketedIds, row.id)) : null,
      changerUnproven: rules >= 5 && postChange.has(row.id) && entry.lifecycle?.changerLoginProven === false, released, selfChange: selfChanges.has(row.id), mirror };
  };
  const reasonUnder = releasedSet => row => actorOf(row) ? rowIdentityReason(argsUnder(row, releasedSet.has(row.id))) : null;
  // actor-identity/6, identity option B (src/http-rests-on.mjs): the rows that rest on their listed controls, recomputed from
  // the rows with the connector's readings. A credentialed required control failed when it did not pass before the identity
  // assertion. A failed control's failure is read from its own sealed windows, bound again as the effect recompute binds
  // them (the run's follow rule and its sealed late resolution records included, IDR-2); a window that does not bind admits nothing.
  const failedRequired = row => credentialed(actorOf(row)) ? !passedBeforeIdentity(row) : row?.status !== 'pass';
  const windowsOf = row => { try { return bindSealedResolutions(bindSealedWindows(row.trace[1].data.windows, run.observers, { scoped: true, unfollowed: unfollowedOf(run, row) }), row.trace[1].data.resolutions); } catch { return null; } };
  const view = rules >= 6 ? restsOnView(run.results, { required, failed: failedRequired, identityProven: row => Boolean(actorOf(row)) && recordIdentityProven(argsUnder(row, false)),
    refusalStatusesOf: actor => credentialed(actor) ? entries.get(actor)?.refusalStatuses : [401, 403], codesOf: label => statusCodes(label, true), principals: record(run.principals) ? run.principals : {},
    // The sealed data is validated only later (the effect recompute): anything this reading cannot read admits nothing.
    credentialed, admitted: row => { try { return failureAdmitted(row, windowsOf(row), record(run.principals) ? run.principals[actorOf(row)] : undefined); } catch { return false; } } }) : null;
  // The exported suite binds what a release reads from the rows: each row's restsOn ids and record predicates (the suite's
  // check lists), each required control's declared partners (recomputed from the recorded route segments and ranks), and
  // each restsOn check's related controls (recomputed from the recorded segments), so a run cannot edit segments, ranks or
  // ids to release a row. What only the run shows (a served record's status, clean object, key set, passing record
  // predicates and sent route; the order; the failed controls' readings) is recomputed from the rows. A suite that cannot
  // bind them is a configuration error (suite-rests-on-missing), never a silent skip.
  if (expectedSuite && view) {
    const configured = ok => { if (!ok) throw new HttpEvidenceError('unexpected-suite-evidence', 'suite-rests-on-missing'); };
    const suiteChecks = Array.isArray(expectedSuite.checks) ? expectedSuite.checks.filter(record) : [], suiteById = new Map(suiteChecks.map(c => [c.id, c]));
    configured(expectedSuite.identitySchema === IDENTITY_EVIDENCE_SCHEMA && suiteChecks.length === (expectedSuite.checks?.length ?? -1));
    for (const c of suiteChecks) {
      const requiredHere = required.includes(c.id), applies = c.applicability?.applies !== false;
      configured(Array.isArray(c.recordPredicates) && c.recordPredicates.length <= 10 && c.recordPredicates.every(e => Array.isArray(e) && e.length === 3 && e.every(Number.isInteger)));
      if (requiredHere && applies) configured(Array.isArray(c.recordPartners) && c.recordPartners.length <= required.length && c.recordPartners.every(id => typeof id === 'string'));
      else configured(!Object.hasOwn(c, 'recordPartners'));
      if (Object.hasOwn(c, 'restsOn')) configured(!requiredHere && Array.isArray(c.restsOn) && c.restsOn.length >= 1 && c.restsOn.length <= RESTS_ON_LIMITS.ids && c.restsOn.every(id => typeof id === 'string')
        && Array.isArray(c.restsOnRelated) && c.restsOnRelated.length <= required.length && c.restsOnRelated.every(id => typeof id === 'string'));
      else configured(!Object.hasOwn(c, 'restsOnRelated'));
    }
    // The run's rows are the suite's checks, every one in the suite's order: the release reads which controls failed and the
    // order rows were sent in (B4(b) and (d)), so a run cannot drop a failed control or move a row (check note F6).
    need(same(run.results.map(row => row?.id), suiteChecks.map(c => c.id)), 'unexpected-suite-evidence');
    for (const row of run.results) if (record(observation(row))) {
      const evidence = observation(row), suiteCheck = suiteById.get(row.id);
      need(same(evidence.controlScope?.recordPredicates, suiteCheck?.recordPredicates), 'unexpected-suite-evidence');
      need(same(evidence.restsOn ?? null, suiteCheck?.restsOn ?? null), 'unexpected-suite-evidence');
    }
    const controls = view.rows.filter(row => row.required), partnersOf = declaredPartners(controls);
    for (const row of controls) need(same(partnersOf.get(row.id) ?? [], sortedCopy(suiteById.get(row.id)?.recordPartners ?? [])), 'unexpected-suite-evidence');
    for (const row of view.rows) if (row.restsOn) need(same(relatedByRoute(row, controls.filter(c => c.actorId === row.actorId)), sortedCopy(suiteById.get(row.id)?.restsOnRelated ?? [])), 'unexpected-suite-evidence');
  }
  // Without an exported suite nothing binds the recorded segments, ranks or ids, so nothing is released, and a run whose rows
  // rest on a release (a row whose reason differs when its listed controls may release it) is refused, never read as released.
  const released = view && expectedSuite ? restsOnReleases(view) : new Set();
  const reasonFor = reasonUnder(released);
  if (view && !expectedSuite) {
    const would = reasonUnder(restsOnReleases(view));
    for (const row of run.results) if (record(observation(row)) && reasonFor(row) !== would(row)) throw new HttpEvidenceError('invalid-run-evidence', 'rests-on-needs-suite');
  }
  // actor-identity/6: the required controls of each actor that did not pass, named by a control-not-passed summary.
  const failedControlsOf = actor => required.filter(id => actorOf(rowsById.get(id)) === actor && failedRequired(rowsById.get(id)));
  // actor-identity/5: a change is attributed only when sent by a credentialed actor with an identity control whose login
  // was proven for the change check; the stored flag is recomputed from the change row's own identity reason.
  for (const { entry, change } of lifecycles) {
    if (rules < 5) continue;
    const changer = actorOf(change);
    need(credentialed(changer) && entries.get(changer)?.identityControlIds.length >= 1);
    need(entry.lifecycle.changerLoginProven === (reasonFor(change) === null));
  }
  // Who created a captured value: under rules 5 the creator's identity at the capturing check; earlier, the actor's login over the run.
  const creatorUnproven = use => credentialed(use.createdBy) && (rules >= 5 ? loginLevel(reasonFor(rowsById.get(use.captureCheckId))) : entries.get(use.createdBy)?.loginProven !== true);
  return { reasonFor, failedControlsOf, unproven: [...entries.values()].filter(e => !e.established).map(e => e.actorId), loginUnproven: [...entries.values()].filter(e => !e.loginProven).map(e => e.actorId),
    credentialed, loginProven: actor => entries.get(actor)?.loginProven === true, creatorUnproven, postChange, rules };
}
// One judged actor's lifecycle evidence (src/http-lifecycle.mjs), recomputed from the rows: the change row
// (another actor's required allowed-use control), whether it passed when it was sent, and the actor's rows
// after it. Each post-change row expects only the declared refusal and, when sent, pairs it with an
// effect.none clause; when the change was not confirmed, none of them was sent. Returns the post-change ids.
function lifecycleOf(entry, actor, { run, rowsById, actorOf, required, expectedSuite, rules = 4 }) {
  if (!Object.hasOwn(entry, 'lifecycle')) {
    if (expectedSuite) need(!(expectedSuite.lifecycle ?? []).some(e => e?.actorId === actor), 'unexpected-suite-evidence');
    return new Set();
  }
  const life = entry.lifecycle;
  need(record(life) && Object.keys(life).length === (rules >= 5 ? 5 : 4) && LIFECYCLE_POLICIES.includes(life.after) && typeof life.changeConfirmed === 'boolean' && Array.isArray(life.postChangeCheckIds));
  // actor-identity/5: whether the changer's login was proven for the change check (recomputed by httpIdentity once every actor is read).
  need(rules >= 5 ? typeof life.changerLoginProven === 'boolean' : !Object.hasOwn(life, 'changerLoginProven'));
  const change = rowsById.get(life.changeCheckId);
  need(record(change) && change.severity === 'control' && required.includes(life.changeCheckId) && actorOf(change) !== undefined);
  // A self-change (src/http-lifecycle.mjs) exists only under rules 6, and is never a GET (a surface control would be re-sent at every point).
  if (actorOf(change) === actor) need(rules >= 6 && change.trace?.[0]?.data?.method !== 'GET');
  const at = run.results.indexOf(change);
  const after = run.results.slice(at + 1).filter(row => record(row) && row.status !== 'not_applicable' && actorOf(row) === actor);
  need(after.length >= 1 && same(life.postChangeCheckIds, after.map(row => row.id)));
  need(life.changeConfirmed === passedAtSend(change));
  // In-doubt resolution (PR348-REVIEW minor 3): a change check takes no late record, so its final row is the row it was gated on when sent.
  need(!Object.hasOwn(change.trace?.[1]?.data ?? {}, 'resolutions'));
  for (const row of after) {
    need(row.severity !== 'control');
    const codes = statusCodes(row.assertions?.find(a => a?.name === 'HTTP status matches contract')?.expected ?? '', true);
    need(codes !== null && codes.every(code => entry.refusalStatuses.includes(code)));
    const notSent = row.trace?.[0]?.data?.notSent;
    // A declared run budget, or a run a host suspend stopped, may have cut the row instead (capturePreconditions decides which reason
    // applies). A change the run's attribution or correlation settlement withheld after it was sent: its post-change checks were sent
    // (capturePreconditions gives them change-not-attributed).
    need(life.changeConfirmed || withheldAfterSend(change) ? notSent !== 'change-not-confirmed' : notSent === 'change-not-confirmed' || notSent === RUN_BUDGET_EXHAUSTED || notSent === SUSPEND_STOPPED);
    if (notSent === undefined) need(Array.isArray(row.trace) && row.trace.length === 2 && Array.isArray(row.trace[1]?.data?.effects) && row.trace[1].data.effects.some(e => e?.kind === 'effect.none'));
  }
  return new Set(after.map(row => row.id));
}
// limitStatuses: for a row sent in the mirror phase (it records mirrorOf), the run's rate-limit statuses (validateHttpRunEvidence);
// null for every other row.
function validateHttpObservation(row, expectedCheck, { v2, v3, reasonFor, failedControlsOf = () => [], observers, findings = null, attribution = null, pairing = null, precondition = null, rules = 0, unfollowed = null, tenantValues = null, appLogs = null, admission = null, later = null, principals = null, limitStatuses = null }) {
  const evidence = row.trace?.[0]?.data, observed = row.observed;
  // v3: a row with declared effects carries a second, sealed trace entry. Its
  // windows are revalidated and every effect decision recomputed here.
  const hasEffects = v3 && Array.isArray(row.trace) && row.trace.length === 2;
  // A check whose precondition did not hold was not sent: no response, no window, inconclusive.
  const notSent = v3 && evidence?.transportOutcome === 'not-sent';
  let effects = null, readBack = null;
  if (hasEffects) {
    // Custody is recomputed under the row's role; with an exported suite, the role (severity) is bound to it.
    if (expectedCheck) need(expectedCheck.severity === row.severity, 'unexpected-suite-evidence');
    // Settlement findings come from the whole run (validateHttpRunEvidence) and are applied after custody.
    // Claim readings: a response that was not complete valid JSON can only have read unreadable.
    const responseRead = record(evidence) && evidence.transportOutcome === 'complete' && evidence.jsonParsed === true;
    try { effects = recomputeEffectTrace(row.trace[1], expectedCheck ? (expectedCheck.effects ?? []) : undefined, observers, { role: roleOfSeverity(row.severity), findings, attribution, pairing, unfollowed, responseRead, appLogs, admission, later,
      // rls-zero-row (NC9 item 3): the row's own principal, method and response contract, read the way the connector read them.
      zeroRow: { principal: record(principals) ? principals[evidence?.actorId] : undefined, method: evidence?.method, succeeded: responseContractSucceeded(row) },
      ...(expectedCheck ? { declaredClaimsDigest: expectedCheck.claimsDigest ?? null } : {}) }); }
    catch (error) { need(error?.message !== 'unexpected-suite-evidence', 'unexpected-suite-evidence'); throw new HttpEvidenceError('invalid-run-evidence', effectDetail(error)); }
    // Read-back (src/http-readback.mjs): each sealed entry judged again under the row's role; with an exported suite, the declared tables.
    try { readBack = recomputeReadBack(row.trace[1].data.readBack, roleOfSeverity(row.severity), { observers, windows: row.trace[1].data.windows, ...(expectedCheck ? { declared: expectedCheck.readBack ?? null } : {}) }); }
    catch (error) { need(error?.message !== 'unexpected-suite-evidence', 'unexpected-suite-evidence'); throw new HttpEvidenceError('invalid-run-evidence', effectDetail(error)); }
    // A control's sealed claim rules (validated by the recompute) declare success only, as validCheck requires: a run made
    // before that rule, whose control could pass on an honest refusal, is refused as such.
    if (row.severity === 'control' && (row.trace[1].data.claims ?? []).some(declaresRefusal)) throw new HttpEvidenceError('invalid-run-evidence', 'control-refusal-claim');
    // A control's sealed effect clauses include a positive one when it declares any, as validCheck requires: a run made before that
    // rule, whose control could pass on nothing happening, is refused as such.
    if (row.severity === 'control' && row.trace[1].data.effects.length && !row.trace[1].data.effects.some(positiveClause)) throw new HttpEvidenceError('invalid-run-evidence', 'control-no-positive-effect');
  }
  if (expectedCheck && v3) need(Boolean(expectedCheck.effects || expectedCheck.claimsDigest || expectedCheck.readBack) === hasEffects || (notSent && !hasEffects), 'unexpected-suite-evidence');
  // rls-zero-row (PR520 review MAJOR 2): with an exported suite, a sent row carries the zero-row record exactly where the suite declares
  // one, for that write and observer, so the record (and its FAIL) cannot be dropped, moved or invented.
  if (expectedCheck && hasEffects) { const sealed = row.trace[1].data.zeroRow, declared = expectedCheck.zeroRow ?? null;
    need(declared === null ? sealed === undefined : record(sealed) && digest({ table: sealed.expect?.table, op: sealed.expect?.op, instanceId: sealed.instanceId }) === digest(declared), 'unexpected-suite-evidence'); }
  // The precondition reason recomputed for this row (validateHttpRunEvidence) is the only one it may carry.
  need(notSent ? NOT_SENT_REASONS.includes(precondition) && evidence.notSent === precondition && evidence.requestAttempted === false && evidence.requestTimeoutMs === 0
    : !record(evidence) || !Object.hasOwn(evidence, 'notSent'));
  need(['response', 'backend'].includes(row.evidenceRequirement) && row.backendEvidence === (effects?.backendObserved ? 'observed' : 'unavailable'));
  need(Array.isArray(row.trace) && row.trace.length === (hasEffects ? 2 : 1) && row.trace[0].type === 'http-observation' && record(evidence) && record(observed));
  need(digest(hasEffects ? { evidence, effects: row.trace[1].data, assertions: row.assertions } : { evidence, assertions: row.assertions }) === row.evidenceDigest);
  need(identifier(evidence.requestId) && identifier(evidence.actorId) && (v3 ? HTTP_CHECK_METHODS : LEGACY_EVIDENCE_METHODS).includes(evidence.method) && hash64(evidence.requestPathHash));
  // actor-identity/6 (src/http-rests-on.mjs): every row records its route segments and its controlScope (whether the answer
  // was a clean JSON object, only on a complete parsed body; its record predicates; the keyed sent route exactly when it was
  // sent, and the key set exactly for a clean object), and a check that declares restsOn records the ids. Earlier rules never do.
  if (rules >= 6) {
    need(recordedRouteShape(evidence.routeSegments, hash64));
    need(controlScopeShape(evidence.controlScope, observed.predicates, { isDigest: hash64, completeJSON: evidence.transportOutcome === 'complete' && evidence.jsonParsed === true, sent: !notSent }));
    need(!Object.hasOwn(evidence, 'restsOn') || (row.severity !== 'control' && Array.isArray(evidence.restsOn) && evidence.restsOn.length >= 1 && evidence.restsOn.length <= RESTS_ON_LIMITS.ids && evidence.restsOn.every(identifier) && new Set(evidence.restsOn).size === evidence.restsOn.length));
  } else need(!['routeSegments', 'controlScope', 'restsOn'].some(key => Object.hasOwn(evidence, key)));
  need(evidence.mutationEffects === (HTTP_WRITE_METHODS.includes(evidence.method) ? MUTATION_EFFECTS.write : MUTATION_EFFECTS.read));
  const knownStatus = Number.isInteger(evidence.httpStatus) && evidence.httpStatus >= 100 && evidence.httpStatus <= 599;
  need(knownStatus || evidence.httpStatus === null);
  need(Number.isSafeInteger(evidence.responseBytes) && evidence.responseBytes >= 0 && evidence.backendEvidence === 'unavailable');
  need(['responseComplete', 'jsonParsed', 'requestAttempted'].every(key => typeof evidence[key] === 'boolean'));
  need(transportOutcomes.includes(evidence.transportOutcome) || notSent);
  need(observed.evidenceScope === (hasEffects ? 'response-and-observers' : 'response-only') && observed.complete === evidence.responseComplete && observed.jsonParsed === evidence.jsonParsed && observed.httpStatus === evidence.httpStatus);
  const terminal = ['complete', 'invalid-json'].includes(evidence.transportOutcome);
  need(evidence.responseComplete === terminal && evidence.jsonParsed === (evidence.transportOutcome === 'complete'));
  if (terminal) need(evidence.requestAttempted && knownStatus);
  // A run budget can expire before a check starts. Keep that valid error shape,
  // but it cannot claim a response, parsed predicates or a passing assertion.
  if (!evidence.requestAttempted) need((evidence.transportOutcome === 'timeout' || notSent) && evidence.httpStatus === null && evidence.responseBytes === 0);
  need(Array.isArray(observed.predicates) && observed.predicates.length <= PROFILE_LIMITS.predicates);
  const completeJSON = terminal && evidence.jsonParsed;
  // The mirror phase: a mirror answered with one of the run's rate-limit statuses (evaluateHttpCheck, limitStatuses), recomputed here.
  const limited = Array.isArray(limitStatuses) && knownStatus && limitStatuses.includes(evidence.httpStatus);
  const kinds = [], jsonKinds = JSON_KINDS;
  let statusAssertions = 0, predicateIndex = 0, backendAssertions = 0, identityAssertions = 0, effectAssertions = 0, readBackAssertions = 0, preconditionAssertions = 0, limitAssertions = 0;
  const identityReasonForRow = v2 ? reasonFor(row) : null;
  for (const assertion of row.assertions) {
    if (assertion.name === 'HTTP status matches contract' && !v2) {
      // v1: exactly the rule used before connector v2.
      statusAssertions++; kinds.push('status.equals');
      const expected = /^HTTP ([1-5][0-9]{2})$/.exec(assertion.expected);
      need(expected !== null);
      need(assertion.status === (!knownStatus ? 'inconclusive' : evidence.httpStatus === Number(expected[1]) ? 'pass' : 'fail'));
      need(assertion.actual === (knownStatus ? `HTTP ${evidence.httpStatus}` : 'HTTP status unavailable'));
    } else if (assertion.name === 'HTTP status matches contract') {
      statusAssertions++;
      const codes = typeof assertion.expected === 'string' ? statusCodes(assertion.expected, true) : null;
      need(codes !== null);
      kinds.push(codes.length === 1 ? 'status.equals' : 'status.in');
      need(assertion.status === (!knownStatus ? 'inconclusive' : codes.includes(evidence.httpStatus) ? 'pass' : limited ? 'inconclusive' : 'fail'));
      need(assertion.actual === (knownStatus ? `HTTP ${evidence.httpStatus}` : 'HTTP status unavailable'));
    } else if (assertion.name === MIRROR_LIMIT_ASSERTION) {
      limitAssertions++; need(limited && assertion.status === 'inconclusive' && assertion.expected === MIRROR_LIMIT_EXPECTED && assertion.actual === mirrorLimitActual(evidence.httpStatus));
    } else if (assertion.name === BACKEND_ASSERTION) {
      // Backend evidence is available only when authoritative observers decided every declared effect.
      backendAssertions++; need(assertion.status === (effects?.backendObserved ? 'pass' : 'inconclusive'));
    } else if (hasEffects && (EFFECT_ASSERTION_PATTERN.test(String(assertion.name)) || CLAIM_ASSERTION_PATTERN.test(String(assertion.name)))) {
      const expected = effects.rows[effectAssertions++];
      need(record(expected) && same(assertion, expected));
    } else if (hasEffects && READBACK_ASSERTION_PATTERN.test(String(assertion.name))) {
      const expected = readBack.rows[readBackAssertions++];
      need(record(expected) && same(assertion, expected));
    } else if (v2 && assertion.name === IDENTITY_ASSERTION) {
      identityAssertions++; need(assertion.status === 'inconclusive' && identityReasonForRow !== null && assertion.actual === IDENTITY_REASONS[identityReasonForRow]);
      if (rules >= 6) need(assertion.expected === IDENTITY_EXPECTED);
    } else if (v3 && assertion.name === PRECONDITION_ASSERTION) {
      preconditionAssertions++; need(assertion.status === 'inconclusive' && precondition !== null && assertion.expected === PRECONDITION_EXPECTED && assertion.actual === PRECONDITION_REASONS[precondition]);
    } else {
      const predicate = observed.predicates[predicateIndex++];
      need(record(predicate) && jsonKinds.includes(predicate.kind) && ['pass', 'fail', 'inconclusive'].includes(predicate.outcome));
      need(assertion.name === `${predicate.kind} predicate ${predicateIndex}` && predicate.outcome === assertion.status);
      kinds.push(predicate.kind);
      // json.noForeignValues (v3 only): its counts, refs and outcome agree with the run's value-free tenant declaration, and its
      // actual text is the canonical one, so an edited outcome, count, ref or actual is refused (src/tenant-values.mjs).
      if (predicate.kind === FOREIGN_VALUES_KIND) need(v3 && validForeignValuesPredicate(predicate, { completeJSON, declared: tenantValues, actorId: evidence.actorId }) && assertion.expected === FOREIGN_VALUES_EXPECTED && assertion.actual === foreignValuesActual(predicate));
      else if (!completeJSON) need(predicate.outcome === 'inconclusive' && predicate.present === null && predicate.type === 'unavailable');
      else {
        need(typeof predicate.present === 'boolean' && (predicate.present ? ['null', 'array', 'object', 'string', 'number', 'boolean'].includes(predicate.type) : predicate.type === 'absent'));
        const unverifiable = predicate.kind === 'json.notContains' && (!predicate.present || predicate.type !== 'string');
        need(unverifiable ? predicate.outcome === 'inconclusive' : predicate.outcome !== 'inconclusive');
        if (predicate.kind === 'json.equals' && !predicate.present) need(predicate.outcome === 'fail');
      }
      // A predicate record (predicate records, above evaluateHttpCheck): exactly its mode's fields, an outcome they give, and the assertion texts they give.
      if (Object.hasOwn(predicate, 'record')) need(validPredicateRecord(predicate, { completeJSON, pointerValid: pointer => { try { pointerTokens(pointer); return true; } catch { return false; } } })
        && same([assertion.expected, assertion.actual], Object.values(predicateTexts(predicate, completeJSON, predicate.outcome))));
      else if (predicate.kind !== FOREIGN_VALUES_KIND) need(['kind', 'outcome', 'present', 'type'].every(key => Object.hasOwn(predicate, key)) && Object.keys(predicate).length === 4);
    }
  }
  need(statusAssertions === 1 && predicateIndex === observed.predicates.length && backendAssertions === (row.evidenceRequirement === 'backend' ? 1 : 0) && effectAssertions === (effects ? effects.rows.length : 0) && readBackAssertions === (readBack ? readBack.rows.length : 0));
  // The identity assertion appears exactly on the rows that depend on an
  // unproven login, with that reason, so a partial edit cannot drop or add it.
  need(identityAssertions === (identityReasonForRow ? 1 : 0) && preconditionAssertions === (precondition ? 1 : 0) && limitAssertions === (limited ? 1 : 0));
  // Reproduce only the core's status precedence, never private JSON values. A request that was not sent is inconclusive. A mirror a
  // limit answered fails only on a json.noForeignValues predicate (evaluateHttpCheck).
  const status = row.assertions.some(a => a.status === 'fail' && (!limited || foreignAssertion(a))) ? 'fail' : notSent ? 'inconclusive' : !terminal ? 'error' : row.assertions.some(a => a.status === 'inconclusive') ? 'inconclusive' : 'pass';
  need(row.status === status);
  // actor-identity/5: the row's decision is recomputed, so the third state cannot be edited into a pass or hidden.
  if (rules >= 5) need(ROW_DECISIONS.includes(row.decision) && row.decision === rowDecision(row, identityReasonForRow));
  else need(!Object.hasOwn(row, 'decision'));
  // actor-identity/6: a withheld row that passed names its reason (and, for control-not-passed, the controls) in its summary.
  if (rules >= 6 && identityReasonForRow !== null && passedBeforeIdentity(row)) need(row.summary === withheldSummary(identityReasonForRow, failedControlsOf(evidence.actorId), row.decision === IDENTITY_UNPROVEN_DECISION));
  if (expectedCheck) need(expectedCheck.method === evidence.method && expectedCheck.evidenceRequirement === row.evidenceRequirement && same(expectedCheck.assertionKinds, kinds), 'unexpected-suite-evidence');
  if (expectedCheck && v2) need(expectedCheck.actorId === evidence.actorId && expectedCheck.credentialMode === evidence.credentialMode, 'unexpected-suite-evidence');
}
// Settlement (src/http-settlement.mjs): the sealed gap windows are bound to the declared observers like a
// check's own, every effect row's clauses are decided again from its windows, and the findings recomputed.
// A run with effect windows and no settlement record was saved before settlement: refused as such.
// Correlated settlement (/2): the tokens are read from the sent rows' requestIds and the declared pairs from the record; a token
// on an event that names a row that was not sent, a malformed token from a declared pair, or a token from a pair that does not
// record one, is refused (settlement-correlation). Judged late effects: the record's outsideWindow (bound to the exported suite in
// validateHttpRunEvidence) sets judge, passed to the same settlementFindings the connector runs.
// The follow rule (coverage v2) over a run's sealed effect rows in run order (src/effect-events.mjs unfollowedLate), recomputed,
// never read from storage: per row, the instance ids of its check windows whose late entries nothing followed.
const followMemo = new WeakMap();
// Coverage v2 Part D: a run may carry drains only when it declares attribution or a forwarded egress destination and every
// egress recorder record carries a Part D or later collector label (src/run-end-drain.mjs drainsDeclared), or (feed v2, Part B)
// it has a drainable provider feed.
// Feed v2, Part B: a witnessed endpoint feed whose record carries provider-feed/3 drains too, whatever the egress gate (drainersOfRun);
// an older feed record never drains.
const drainersOfRun = run => drainersOf({ attribution: run.attribution, observers: run.observers }).filter(o => o.type !== 'provider-feed' || DRAIN_COLLECTOR_LABELS.includes(o.collector?.label));
const drainsAllowedOf = run => { const list = drainersOfRun(run); return list.length > 0 && list.filter(o => o.type === 'egress-recorder').every(o => DRAIN_COLLECTOR_LABELS.includes(o.collector?.label)); };
function unfollowedOf(run, row) {
  if (!followMemo.has(run)) {
    const rows = run.results.filter(r => record(r) && r.status !== 'not_applicable' && Array.isArray(r.trace) && r.trace.length === 2);
    // Only well-formed drains a run may carry follow anything; the settlement record check refuses any other.
    const drains = record(run.settlement) && Object.hasOwn(run.settlement, 'drains') && drainsAllowedOf(run) && validDrains(run.settlement.drains, drainersOfRun(run)) ? run.settlement.drains : null;
    const sets = unfollowedLate(rows.map(r => Array.isArray(r.trace[1]?.data?.windows) ? r.trace[1].data.windows.filter(record) : []), { followed: followedDrains(drains) });
    followMemo.set(run, new Map(rows.map((r, k) => [r, sets[k]])));
  }
  return followMemo.get(run).get(row) ?? null;
}
// What settlementOf read (the decided rows, gaps, correlation, judge and the later list), for the later-outcome stage (laterOf).
const settlementContext = new WeakMap();
// Host suspend records as the connector writes them (src/http-connector.mjs; PR343-REVIEW nit 4): one record or none and one
// unchecked flag or none, alike on all of a check's windows; one record or none, alike on all of a barrier's or the run-end gap's
// windows, never the flag; neither on a gap between checks. Only a check's own windows and its barrier's carry what their wait took
// from the later checks' time (reserveMs): the final settle has no later check to take it from.
const suspendShape = (windows, { held = false, unchecked = false, reserve = held } = {}) => {
  const records = new Set(windows.map(w => (Object.hasOwn(w, 'suspend') ? digest(w.suspend) : null))), flags = new Set(windows.map(w => w.suspendUnchecked === true));
  return records.size <= 1 && flags.size <= 1 && (held || !windows.some(w => Object.hasOwn(w, 'suspend'))) && (unchecked || !windows.some(w => w.suspendUnchecked === true))
    && (reserve || !windows.some(w => record(w.suspend) && Object.hasOwn(w.suspend, 'reserveMs')));
};
function settlementOf(run) {
  const effectRows = run.results.filter(row => record(row) && row.status !== 'not_applicable' && Array.isArray(row.trace) && row.trace.length === 2);
  if (!effectRows.length) { need(!Object.hasOwn(run, 'settlement')); return new Map(); }
  if (!Object.hasOwn(run, 'settlement')) throw new HttpEvidenceError('invalid-run-evidence', 'effect-pre-settlement');
  let rows, gaps, correlated, judge;
  try {
    let correlation;
    let drains, later;
    ({ gaps, correlation, judge, drains, later } = validateSettlementRecord(run.settlement, { effectRowIds: effectRows.map(row => row.id), declaredObservers: run.observers, bind: bindSealedWindows, drainsAllowed: drainsAllowedOf(run), drainers: drainersOfRun(run) }));
    // A drain that reads quiescent or clear over a run-end window its recorder failed (the listener went down, records evicted)
    // is not one the connector makes: refused.
    if (drains) for (const d of drains) if ((d.quiescent || d.markClear) && gaps.at(-1).some(w => w.instanceId === d.instanceId && w.coverage === 'failed')) throw new Error('settlement-drains');
    rows = effectRows.map(row => {
      const data = row.trace[1]?.data;
      if (!record(data) || !Array.isArray(data.effects) || (!data.effects.length && !sealedClaims(data).claims.length && data.readBack === undefined) || data.effects.length > MAX_EFFECTS) throw new Error('effect-trace');
      const windows = bindSealedWindows(data.windows, run.observers, { scoped: true, unfollowed: unfollowedOf(run, row) });
      return { effects: decideSealed(data, windows, roleOfSeverity(row.severity)), windows };
    });
    if (!rows.every(r => suspendShape(r.windows, { held: true, unchecked: true })) || !gaps.every((windows, k) => suspendShape(windows, { held: k === gaps.length - 1, reserve: false }))
      || !(correlation?.barriers ?? []).every(windows => suspendShape(windows, { held: true }))) throw new Error('effect-trace');
    // Keyed retries: a key's first use agrees across every sealed window of the run, and a signing item sits exactly on the sends of
    // a host that declares signing, verified only where a declared secret was usable (src/idempotency.mjs). LATE-FIELDS: a late entry's
    // seq and captured record agree with every sealed event of that instance and seq (src/effect-events.mjs consistentScopedCaptures).
    const sealedWindows = [...rows.flatMap(r => r.windows), ...gaps.flat(), ...(correlation?.barriers ?? []).flat()];
    try { consistentIdempotencyRun(sealedWindows); consistentSigningRun(sealedWindows, run.signing); consistentScopedCaptures(sealedWindows); } catch { throw new Error('effect-trace'); }
    // In-doubt resolution R1: one feed-level read per recorder across every row, and run-wide counts no lower than the sealed windows show.
    try { consistentRequestFeedRun(effectRows.map((row, k) => ({ resolutions: row.trace[1].data.resolutions, windows: rows[k].windows })), sealedWindows); } catch { throw new Error('effect-trace'); }
    // In-doubt resolution R2: one read per group and one identity per credential across every row, and run-wide counts no lower than the sealed
    // windows show (the group's sends, and the sends that surely overlap its window and may touch its read or carry its credential).
    try { consistentReadBackRun(effectRows.map((row, k) => ({ resolutions: row.trace[1].data.resolutions, windows: rows[k].windows })), sealedWindows); } catch { throw new Error('effect-trace'); }
    // Later outcomes (provider-feed/5): every record names a committed send its own feed sealed in some window of this run, and a feed that
    // faulted (a window failed on its integrity) is never clear: the connector cannot read a clean signed head past a fault.
    if (later) for (const entry of later) {
      const own = sealedWindows.filter(w => w.instanceId === entry.instanceId);
      const sends = new Set(own.flatMap(w => w.events).filter(e => e.outcome === 'committed').map(e => e.seq));
      if (!entry.records.every(r => sends.has(r.of))) throw new Error('settlement-later');
      if (entry.clear && own.some(w => w.coverage === 'failed' && w.reason === 'provider-feed-integrity')) throw new Error('settlement-later');
    }
    if (correlation) {
      const declared = correlationDeclared(correlation.recorded), tokens = settlementTokens(run.results, effectRows);
      const unsent = new Set(run.results.filter(row => record(row) && row.status !== 'not_applicable' && record(row.trace?.[0]?.data) && row.trace[0].data.transportOutcome === 'not-sent').map(row => String(row.trace[0].data.requestId).replace(/-/g, '').toLowerCase()));
      const windows = [...rows.flatMap(r => r.windows), ...gaps.flat(), ...(correlation.barriers ?? []).flat()];
      for (const w of windows) for (const e of w.events) {
        if (e.correlation.settlementToken === undefined) continue;
        if (!declared.has(`${w.instanceId}\n${e.name}`)) throw new Error('settlement-correlation');
        if (!/^[0-9a-f]{32}$/.test(e.correlation.settlementToken) || unsent.has(e.correlation.settlementToken)) throw new Error('settlement-correlation');
      }
      correlated = { mode: correlation.mode, ...(correlation.mode === 'per-check' ? { barriers: correlation.barriers } : {}), tokens, declared };
    }
  } catch (error) { throw new HttpEvidenceError('invalid-run-evidence', typeof error?.message === 'string' && error.message.startsWith('settlement-') ? error.message : effectDetail(error)); }
  const findings = settlementFindings(rows, gaps, correlated, { judge });
  settlementContext.set(run, { rows, gaps, correlated, judge, later: run.settlement?.later ?? null });
  return new Map(effectRows.map((row, k) => [row, findings[k]]));
}
// The effect horizon and run budget (src/http-timing.mjs), read after settlementOf has bound the sealed windows. The record
// is bound to the exported suite, to the effect rows in order and to their durations; a row held short (its horizon or its
// barrier) is the last effect row and every applicable row after it was cut; and a window carries effect-horizon-truncated
// exactly when the record says it was held short (an own window of a truncated row, a clipped barrier, a clipped tail), then
// on every authoritative window that did not fail, as partial. Without a record no window carries it. Which check the
// budget cut is the connector's own reading of its clock: no other row recomputes it, so a saved run can move the cut
// (unsigned evidence; see validateHttpRunEvidence), and a cut row only ever reads inconclusive, never pass.
function timingOf(run, expectedSuite) {
  const held = ok => { if (!ok) throw new HttpEvidenceError('invalid-run-evidence', 'timing-record'); };
  const timing = run.timing, declared = Object.hasOwn(run, 'timing');
  if (expectedSuite) need(same(expectedSuite.timing ?? null, declared && record(timing) ? timingDeclarationOf(timing) : null), 'unexpected-suite-evidence');
  const effectRows = run.results.filter(row => record(row) && row.status !== 'not_applicable' && Array.isArray(row.trace) && row.trace.length === 2);
  const own = effectRows.map(row => row.trace[1].data.windows), settlement = record(run.settlement) ? run.settlement : null;
  const gaps = settlement ? settlement.gaps.map(g => g.windows) : [], barriers = Array.isArray(settlement?.barriers) ? settlement.barriers.map(b => b.windows) : [];
  if (!declared) { held([...own, ...gaps, ...barriers].every(windows => !windows.some(carriesHorizon))); return; }
  const maxSettle = maxDeclaredSettle(run.observers), perCheck = settlement?.mode === 'per-check';
  let marks;
  try { marks = validateTimingRecord(timing, { effectRowIds: effectRows.map(row => row.id), maxSettle, perCheck }); } catch { held(false); }
  held(maxSettle > 0 && timing.effectHorizonMs >= maxSettle);
  // Under a timing plan a host suspend's shortfall is sealed as the awake time each wait held, never on a window, and no wait takes the
  // later checks' time (src/http-connector.mjs).
  held([...own, ...gaps, ...barriers].every(windows => windows.every(w => !(record(w) && record(w.suspend) && (Object.hasOwn(w.suspend, 'shortMs') || Object.hasOwn(w.suspend, 'reserveMs'))))));
  effectRows.forEach((row, k) => held(Number.isSafeInteger(row.durationMs) && row.durationMs >= timing.rows[k].waitedMs));
  const downgraded = (windows, short) => windows.every(w => carriesHorizon(w) === (short && w.scope?.evidence === 'authoritative' && w.coverage !== 'failed') && (!carriesHorizon(w) || w.coverage === 'partial'));
  own.forEach((windows, k) => held(downgraded(windows, marks.truncated(k))));
  barriers.forEach((windows, k) => held(downgraded(windows, marks.barrierClipped(k))));
  gaps.forEach((windows, k) => held(downgraded(windows, k === effectRows.length && marks.tailClipped)));
  // Every applicable row after one held short was cut, so it is the last effect row.
  const short = effectRows.findIndex((_, k) => marks.truncated(k) || marks.barrierClipped(k));
  if (short >= 0) held(run.results.slice(run.results.indexOf(effectRows[short]) + 1).every(row => !record(row) || row.status === 'not_applicable' || row.trace?.[0]?.data?.notSent === RUN_BUDGET_EXHAUSTED));
}
// Background attribution (src/http-attribution.mjs): the run's record, revalidated and bound to the exported suite.
// Returns the declaration ({ background }) or null. Only a v3 run carries one.
function attributionRecordOf(run, expectedSuite, v3) {
  const declared = Object.hasOwn(run, 'attribution');
  if (declared) {
    need(v3);
    try { validateAttributionRecord(run.attribution); } catch { throw new HttpEvidenceError('invalid-run-evidence', 'attribution-record'); }
  }
  // The exported suite fixes the declaration, so a run cannot shed or edit it against the suite.
  if (expectedSuite && v3) need(stable(expectedSuite.attribution ?? null) === stable(declared ? { background: run.attribution.background } : null), 'unexpected-suite-evidence');
  return declared ? { background: run.attribution.background } : null;
}
// Attribution findings: every effect row's clauses are decided and settled again from the sealed windows, the gaps and
// barriers are re-read from the settlement record, and each declared source must be visible to some sealed window.
// lateFails: the run's timing record declares late fails (src/http-timing.mjs), which add the late rules with or without sources.
function attributionOf(run, settlement, declaration, lateFails = false) {
  const effectRows = [...settlement.keys()];
  if ((declaration === null && !lateFails) || !effectRows.length) return new Map();
  let rows, gaps, barriers, tokens;
  try {
    const record = validateSettlementRecord(run.settlement, { effectRowIds: effectRows.map(row => row.id), declaredObservers: run.observers, bind: bindSealedWindows, drainsAllowed: drainsAllowedOf(run), drainers: drainersOfRun(run) });
    gaps = record.gaps;
    // The sent rows' correlation tokens, on a correlated run (returned-id seeds need their check's own: src/id-closure.mjs).
    tokens = record.correlation ? settlementTokens(run.results, effectRows) : undefined;
    barriers = record.correlation?.mode === 'per-check' ? record.correlation.barriers : undefined;
    rows = effectRows.map(row => {
      const data = row.trace[1].data, windows = bindSealedWindows(data.windows, run.observers, { scoped: true, unfollowed: unfollowedOf(run, row) }), role = roleOfSeverity(row.severity);
      return { effects: applySettlement(decideSealed(data, windows, role), settlement.get(row), role), windows };
    });
  } catch (error) { throw new HttpEvidenceError('invalid-run-evidence', effectDetail(error)); }
  if (declaration !== null && backgroundUnseen(declaration.background, [...rows.flatMap(r => r.windows), ...gaps.flat(), ...(barriers ?? []).flat()]).length) throw new HttpEvidenceError('invalid-run-evidence', 'attribution-record');
  const findings = attributionFindings(rows, gaps, barriers, { background: declaration?.background ?? [], lateFails, tokens });
  return new Map(effectRows.map((row, k) => [row, findings[k]]));
}
// The run's not-sent checks (a precondition, the run budget or a host suspend kept them from being sent).
const notSentIds = run => run.results.filter(row => record(row) && row.trace?.[0]?.data?.transportOutcome === 'not-sent').map(row => row.id);
// A row's status contract as its check declared it (status.equals or status.in), read from its sealed status assertion; the
// allowed-use guard (src/http-pairing.mjs acceptsSuccess) reads it. An unreadable label declares nothing.
const statusContractOf = row => {
  const codes = statusCodes((Array.isArray(row?.assertions) ? row.assertions : []).find(a => record(a) && a.name === 'HTTP status matches contract')?.expected, true);
  return codes ? [{ kind: codes.length === 1 ? 'status.equals' : 'status.in', expected: codes.length === 1 ? codes[0] : codes }] : [];
};
// Positive-match pairing (src/http-pairing.mjs): the pairs are read from the run's own rows (role, actor, declared
// effects) and its declared principals, every settled and attributed clause is judged again, and the findings recomputed.
function pairingOf(run, settlement, attribution = new Map()) {
  const effectRows = [...settlement.keys()];
  if (!effectRows.length) return new Map();
  const observation = row => row?.trace?.[0]?.data;
  const target = { actors: Object.fromEntries(Object.entries(run.principals ?? {}).map(([alias, principalId]) => [alias, { principalId }])),
    requiredControlIds: Array.isArray(run.requiredControlIds) ? run.requiredControlIds : [], checks: run.results.filter(row => record(row) && row.status !== 'not_applicable').map(row => ({ id: row.id, severity: row.severity, actorId: observation(row)?.actorId, assertions: statusContractOf(row),
      ...(settlement.has(row) ? { effects: row.trace[1].data.effects.map(declaredEffect), ...(Array.isArray(row.trace[1].data.claims) ? { claims: row.trace[1].data.claims.map(declaredClaim) } : {}) } : {}) })) };
  let rows;
  try {
    rows = effectRows.map(row => {
      const data = row.trace[1].data, windows = bindSealedWindows(data.windows, run.observers, { scoped: true, unfollowed: unfollowedOf(run, row) }), role = roleOfSeverity(row.severity);
      return { id: row.id, actorId: observation(row)?.actorId, role, effects: applyAttribution(applySettlement(decideSealed(data, windows, role), settlement.get(row), role), attribution.get(row) ?? null, role), windows };
    });
  } catch (error) { throw new HttpEvidenceError('invalid-run-evidence', effectDetail(error)); }
  const findings = pairingFindings(rows, selectorPairs(target), allowedUseGuards(target, { notSent: notSentIds(run) }));
  // The allowed-use guard (FIX-07): a clause the recompute reads allowed-use-not-declared whose sealed decision and assertion row both
  // still read pass was sealed before the guard (or edited consistently), and the run is refused as such. The connector lowers that pass
  // at this stage, so an honest run never carries one; an edit that changes the sealed clause alone is refused by the row recompute.
  // Read at the pairing stage on purpose: a later stage (later outcomes) may lower a guard's own pass after pairing.
  effectRows.forEach((row, k) => findings[k].forEach((finding, i) => {
    if (finding !== 'allowed-use-not-declared') return;
    const data = row.trace[1].data, own = Array.isArray(data.effects) ? data.effects.length : 0, claim = i >= own;
    const decision = claim ? data.claims?.[i - own] : data.effects[i];
    const named = claim ? `Observed claim ${i - own + 1} (` : `Observed effect ${i + 1} (`;
    const shown = (Array.isArray(row.assertions) ? row.assertions : []).find(a => record(a) && typeof a.name === 'string' && a.name.startsWith(named));
    if (record(decision) && decision.verdict === 'pass' && shown?.status === 'pass') throw new HttpEvidenceError('invalid-run-evidence', 'prohibition-no-allowed-use');
  }));
  return new Map(effectRows.map((row, k) => [row, findings[k]]));
}
// Later outcomes (provider-feed/6, src/later-outcome.mjs): each effect row's clauses as decided, settled, attributed and paired, and the
// stage's findings recomputed across the run from the sealed later list, exactly as the connector computed them. A run without a feed
// whose record carries a stage label has none (a /5 run's records stay inert).
function laterOf(run, settlement, attribution, pairing, declaration, lateFails) {
  const ctx = settlementContext.get(run), effectRows = [...settlement.keys()];
  if (!ctx || !effectRows.length || !laterFeedsOf(run.observers, LATER_STAGE_LABELS).length) return new Map();
  let findings;
  try {
    const rows = effectRows.map((row, k) => {
      const role = roleOfSeverity(row.severity), raw = ctx.rows[k].effects, settled = applySettlement(raw, settlement.get(row), role);
      return { raw, settled, paired: applyPairing(applyAttribution(settled, attribution.get(row) ?? null, role), pairing.get(row) ?? null, role), windows: ctx.rows[k].windows, role };
    });
    findings = laterFindings({ rows, gaps: ctx.gaps, barriers: ctx.correlated?.barriers, correlation: ctx.correlated, judge: ctx.judge,
      attribution: declaration !== null || lateFails ? { background: declaration?.background ?? [], lateFails, tokens: ctx.correlated?.tokens } : null, readingOf: laterReadings(ctx.later, run.observers) });
  } catch (error) { throw new HttpEvidenceError('invalid-run-evidence', effectDetail(error)); }
  return new Map(effectRows.map((row, k) => [row, findings[k]]));
}
// Typed captures (src/http-captures.mjs): each capture's outcome follows its own row's observation, each
// use names an earlier capture with the same type, creator and value digest, and the exported suite fixes
// both. Returns the precondition reason each row must carry: change-not-confirmed or capture-unavailable for
// a row that was not sent, creator-login-unproven for a sent row using a value created by an actor whose login
// was not proven, otherwise null.
function capturePreconditions(run, expectedSuite, identity) {
  const captured = new Map(), reasons = new Map();
  // A declared run budget (run.timing): from the first applicable row it cut, every applicable row is cut.
  const applicable = run.results.filter(row => record(row) && row.status !== 'not_applicable');
  const cutFrom = record(run.timing) ? applicable.findIndex(row => row.trace?.[0]?.data?.notSent === RUN_BUDGET_EXHAUSTED) : -1;
  const cut = new Set(cutFrom >= 0 ? applicable.slice(cutFrom) : []);
  // Without a timing plan (src/http-connector.mjs): the first applicable row whose own windows, or whose barrier's windows, carry a
  // host-suspend record that stops the run (a shortfall, or time taken from the later checks: stopsRun, the connector's own test) is
  // the last one sent, and every applicable row after it was not sent (host-suspend-run-stopped). Recomputed from the sealed windows,
  // which settlementOf binds (a shortfall there is bound to its partial window), never read from the rows.
  const stops = windows => Array.isArray(windows) && windows.some(w => record(w) && record(w.suspend) && stopsRun(w.suspend));
  const barrierOf = new Map((Array.isArray(run.settlement?.barriers) ? run.settlement.barriers : []).filter(record).map(b => [b.after, b.windows]));
  const stopAt = record(run.timing) ? -1 : applicable.findIndex(row => Array.isArray(row.trace) && row.trace.length === 2 && (stops(row.trace[1]?.data?.windows) || stops(barrierOf.get(row.id))));
  const stopped = new Set(stopAt >= 0 ? applicable.slice(stopAt + 1) : []);
  // Rows by id, the last one winning as in httpIdentity (a duplicated id is refused elsewhere).
  const byId = new Map(run.results.map(row => [row?.id, row]));
  for (const row of run.results) {
    if (!record(row) || row.status === 'not_applicable') continue;
    const evidence = row.trace?.[0]?.data; if (!record(evidence)) continue;
    const expectedCheck = expectedSuite?.checks?.find(check => check.id === row.id);
    const uses = evidence.captureUses;
    if (uses !== undefined) need(Array.isArray(uses) && uses.length >= 1 && uses.length <= 16 && new Set(uses.map(u => u?.name)).size === uses.length);
    for (const use of uses ?? []) {
      need(record(use) && Object.keys(use).length === 5 && captured.has(use.name));
      const source = captured.get(use.name);
      need(use.type === source.type && use.createdBy === source.createdBy && use.captureCheckId === source.captureCheckId && use.valueDigest === source.valueDigest);
    }
    if (expectedSuite) need(same((uses ?? []).map(u => ({ name: u.name, type: u.type, createdBy: u.createdBy, captureCheckId: u.captureCheckId })), expectedCheck?.captureUses ?? []), 'unexpected-suite-evidence');
    const caps = evidence.captures;
    if (caps !== undefined) need(Array.isArray(caps) && caps.length >= 1 && caps.length <= 8);
    const complete = evidence.transportOutcome === 'complete', statusPassed = row.assertions?.find(a => a?.name === 'HTTP status matches contract')?.status === 'pass';
    for (const c of caps ?? []) {
      need(record(c) && Object.keys(c).length === 5 && typeof c.name === 'string' && CAPTURE_NAME.test(c.name) && !captured.has(c.name) && CAPTURE_TYPES.includes(c.type) && c.createdBy === evidence.actorId && CAPTURE_OUTCOMES.includes(c.outcome));
      need(c.outcome === 'captured' ? hash64(c.valueDigest) : c.valueDigest === null);
      need(!complete ? c.outcome === 'response-unavailable' : !statusPassed ? c.outcome === 'status-not-matched' : ['captured', 'absent', 'invalid'].includes(c.outcome));
      captured.set(c.name, { type: c.type, createdBy: c.createdBy, captureCheckId: row.id, outcome: c.outcome, valueDigest: c.valueDigest });
    }
    if (expectedSuite) need(same((caps ?? []).map(c => ({ name: c.name, type: c.type })), expectedCheck?.captures ?? []), 'unexpected-suite-evidence');
    // The reason, in the connector's order: a change that did not take effect, a value that was not captured, an unproven creator.
    const life = identity.postChange?.get(row.id)?.lifecycle;
    // A change the run's attribution or correlation settlement withheld after it was sent: a post-change row sent on it reads change-not-attributed, after
    // any reason it was not sent and before an unproven creator.
    const withheld = Boolean(life && !life.changeConfirmed && withheldAfterSend(byId.get(life.changeCheckId)));
    const reason = cut.has(row) ? RUN_BUDGET_EXHAUSTED : stopped.has(row) ? SUSPEND_STOPPED : life && !life.changeConfirmed && !withheld ? 'change-not-confirmed'
      : (uses ?? []).some(u => captured.get(u.name).outcome !== 'captured') ? 'capture-unavailable'
      : withheld ? 'change-not-attributed'
      : (uses ?? []).some(u => identity.creatorUnproven?.(u) === true) ? 'creator-login-unproven' : null;
    // A row that was sent cannot carry a not-sent reason, and one that was not sent must.
    need((evidence.transportOutcome === 'not-sent') === NOT_SENT_REASONS.includes(reason));
    reasons.set(row, reason);
  }
  return row => reasons.get(row) ?? null;
}
// The mirror phase (2026-10-25, NC11; src/two-identities.mjs, src/http-connector.mjs): the rows sent in it, each recording mirrorOf, under
// identity rules 6 only. Each one's id is its source's with the mirror suffix; its source is an earlier row that records none, of another
// actor, with the same method and severity; and every row after the first mirror is a mirror, as the connector sends them. The run carries
// its rate-limit statuses (mirrorPhase.rateLimitStatuses: 429, then the declared ones in ascending order) exactly when it has a mirror row.
// With an exported suite, every sent row records exactly the mirrorOf its suite check carries, and the suite fixes the statuses; without
// one, they are the run's own record, as its other declarations are. Returns the mirror rows' ids and the statuses.
function mirrorPhaseOf(run, expectedSuite, v3) {
  const evidenceOf = row => record(row) && row.trace?.[0]?.type === 'http-observation' && record(row.trace[0].data) ? row.trace[0].data : null;
  const rows = run.results.filter(row => Object.hasOwn(evidenceOf(row) ?? {}, 'mirrorOf'));
  need(Object.hasOwn(run, 'mirrorPhase') === rows.length > 0);
  if (expectedSuite) {
    need(stable(expectedSuite.mirrorPhase ?? null) === stable(run.mirrorPhase ?? null), 'unexpected-suite-evidence');
    const suiteChecks = Array.isArray(expectedSuite.checks) ? expectedSuite.checks : [];
    for (const row of run.results) { const evidence = evidenceOf(row); if (evidence) need((evidence.mirrorOf ?? null) === (suiteChecks.find(c => record(c) && c.id === row.id)?.mirrorOf ?? null), 'unexpected-suite-evidence'); }
  }
  if (!rows.length) return { ids: new Set(), limitStatuses: null };
  need(v3 && record(run.identityEvidence) && identityRulesOf(run.identityEvidence.schema) >= 6 && record(run.mirrorPhase) && same(Object.keys(run.mirrorPhase), ['rateLimitStatuses'])
    && validMirrorLimitStatuses(run.mirrorPhase.rateLimitStatuses));
  const first = run.results.indexOf(rows[0]), declared = run.results.slice(0, first);
  need(run.results.slice(first).every(row => rows.includes(row)));
  for (const row of rows) {
    const evidence = evidenceOf(row), source = declared.find(r => record(r) && r.id === evidence.mirrorOf), from = evidenceOf(source);
    need(typeof evidence.mirrorOf === 'string' && row.id === `${evidence.mirrorOf}${MIRROR_SUFFIX}` && row.severity !== 'control' && from !== null
      && source.severity === row.severity && from.method === evidence.method && from.actorId !== evidence.actorId);
  }
  return { ids: new Set(rows.map(row => row.id)), limitStatuses: run.mirrorPhase.rateLimitStatuses };
}
export function validateHttpRunEvidence(run, { expectedSuite } = {}) {
  need(record(run) && Array.isArray(run.results) && run.evidenceOrigin === 'local-http-response');
  // A run has one row per profile check, so never more rows than a profile may declare.
  need(run.results.length <= PROFILE_LIMITS.checks, 'run-too-large');
  need(HTTP_EVIDENCE_VERSIONS.some(v => v.adapterVersion === run.adapterVersion && v.assertionSchemaVersion === run.assertionSchemaVersion));
  const v2 = isV2Run(run), v3 = isV3Run(run);
  // A v2 label on evidence carrying v3-only fields (effect windows) is a downgrade.
  if (!v3) need(run.results.every(row => !Array.isArray(row?.trace) || row.trace.length <= 1));
  // A v1 label on evidence carrying v2-only fields is a downgrade, not v1 evidence.
  if (!v2) need(!Object.hasOwn(run, 'identityEvidence') && run.results.every(row => !record(row?.trace?.[0]?.data) || !['credentialMode', 'requestTimeoutMs'].some(key => Object.hasOwn(row.trace[0].data, key))));
  // Target context (v3): declared values only, and the scope line must say so.
  if (v3) {
    need(TARGET_CONTEXTS.includes(run.targetContext) && (run.targetLabel === null || (LABELLED_CONTEXTS.includes(run.targetContext) && validTargetLabel(run.targetLabel))));
    need(typeof run.scopeLabel === 'string' && (LABELLED_CONTEXTS.includes(run.targetContext) ? run.scopeLabel.startsWith(targetScopePrefix(run)) : !run.scopeLabel.startsWith('operator-forwarded') && !run.scopeLabel.startsWith('remote target')));
    // The context is bound to the run's target configuration digest and to its limitations.
    need(run.targetConfigHash === targetConfigDigest({ profileHash: run.profileHash, build: run.build, targetContext: run.targetContext, targetLabel: run.targetLabel }));
    need(Array.isArray(run.limitations) && run.limitations.every(l => typeof l === 'string') && run.limitations.some(l => l.includes(FORWARDER_MARKER)) === (run.targetContext === 'operator-forwarded')
      && run.limitations.some(l => l.includes(REMOTE_MARKER)) === (run.targetContext === 'operator-remote'));
    // Header API keys (H1 step 4): one digest entry per actor whose rows sent a header key, and none otherwise.
    need(validCredentialHeaders(run));
    // Signed webhooks (src/webhook-driver.mjs): each sent webhook row's record as its declaration (or the suite's view) gives it.
    need(webhookEvidenceProblem(run, { checks: expectedSuite?.checks ?? null }) === null);
    // Declared observers: { id, type, settleMs } in profile order; every effect window is bound to one.
    if (Object.hasOwn(run, 'observers')) need(Array.isArray(run.observers) && run.observers.length <= 16 && new Set(run.observers.map(o => o?.id)).size === run.observers.length
      && run.observers.every(o => record(o) && Object.keys(o).length === 3 + ['capture', 'captureForm', 'idempotency', 'forward', 'objects', 'collector', 'witnessed', 'feed', 'requestFeed', 'readBack', 'aliases', 'cross'].filter(k => Object.hasOwn(o, k)).length && typeof o.id === 'string' && OBSERVER_ID.test(o.id) && OBSERVER_TYPES.includes(o.type) && (o.settleMs === null || settleDeclared(o.settleMs))
        // The collector that built an egress recorder's or SMTP sink's windows (src/collector-identity.mjs).
        && (!Object.hasOwn(o, 'collector') || (['egress-recorder', 'smtp-sink', 'provider-feed', 'pg-snapshot', 'pg-wal'].includes(o.type) && validCollector(o.type, o.collector)))
        // A provider feed records whether it declares a witness (its windows are authoritative exactly then, src/http-effects.mjs)
        // and its { feedId, keyDigest, route }; a file feed is presence-only in v1. A feed with a template vocabulary (feed v2) lists
        // its labels and publishes capture { [domain]: ["/template"] }, the one together with the other, under a collector that reads it.
        && (o.type === 'provider-feed' ? typeof o.witnessed === 'boolean' && validProviderFeedRecord(o.feed) && !(o.feed.route === 'file' && o.witnessed)
            && validProviderFeedCapture(o.capture, o.feed) && (!Object.hasOwn(o.feed, 'templates') || TEMPLATE_COLLECTOR_LABELS.includes(o.collector?.label))
            // Later outcomes: only a witnessed endpoint feed declares them (its signed head bounds what was read), and only a build that knows
            // the declaration records it: provider-feed/5, or /4 or /3 for a feed that could not read outcomes or take the lift.
            && (!Object.hasOwn(o.feed, 'outcomes') || (o.witnessed === true && ['provider-feed/3', 'provider-feed/4', ...OUTCOME_COLLECTOR_LABELS].includes(o.collector?.label)))
            // FIX-06: a provider-feed/7 record carries the feed's declared key source, which custody reads (src/custody.mjs feedKeyCustody); a record
            // without one is judged as an earlier build judged it, so a /7 record may never drop it.
            && (!KEY_SOURCE_LABELS.includes(o.collector?.label) || Object.hasOwn(o.feed, 'keySource'))
          : !Object.hasOwn(o, 'witnessed') && !Object.hasOwn(o, 'feed'))
        // An egress recorder's declared body-field capture (src/body-fields.mjs): { [host]: [pointer, ...] }, or a provider feed's template capture.
        && (!Object.hasOwn(o, 'capture') || (['egress-recorder', 'provider-feed'].includes(o.type) && validCaptureMap(o.capture)))
        // The hosts also read from form-encoded bodies: a subset of capture.
        && (!Object.hasOwn(o, 'captureForm') || (o.type === 'egress-recorder' && Object.hasOwn(o, 'capture') && validCaptureForm(o.captureForm, o.capture)))
        // The key headers an egress recorder reads (src/idempotency.mjs): { [host]: declaration }.
        && (!Object.hasOwn(o, 'idempotency') || (o.type === 'egress-recorder' && validIdempotencyMap(o.idempotency)))
        // The forwarded hosts, their upstream ports, listed statuses and declared proof (src/effect-outcome.mjs).
        && (!Object.hasOwn(o, 'forward') || (o.type === 'egress-recorder' && validForwardRecord(o.forward)))
        // Object routes (src/egress-rules.mjs): only on forwarded hosts, and only from a recorder that marks exact, query-free sends.
        && (!Object.hasOwn(o, 'objects') || (o.type === 'egress-recorder' && validObjectRecord(o.objects) && TARGET_LABELS.includes(o.collector?.label) && Object.keys(o.objects).every(host => Object.hasOwn(o.forward ?? {}, host))))
        // Verified signature headers: only a recorder built to verify them may declare them.
        && (!Object.values(record(o.idempotency) ? o.idempotency : {}).some(d => record(d?.signing)) || SIGNING_COLLECTOR_LABELS.includes(o.collector?.label))
        // A request feed (in-doubt resolution R1, src/request-feed-rules.mjs): only on a recorder built to read it (egress-recorder/8), with the
        // request-feed collector, and only over hosts the recorder forwards and keys.
        && (!Object.hasOwn(o, 'requestFeed') || (o.type === 'egress-recorder' && record(o.requestFeed) && REQUEST_FEED_LABELS.includes(o.collector?.label) && validCollector('request-feed', o.requestFeed.collector)
          && validRequestFeedRecord((({ collector: _c, ...feed }) => feed)(o.requestFeed)) && o.requestFeed.hosts.every(h => Object.hasOwn(o.forward ?? {}, h) && Object.hasOwn(o.idempotency ?? {}, h))))
        // Read-back (in-doubt resolution R2, src/read-back-rules.mjs): only on a recorder built to read it (egress-recorder/9), every read-back host
        // forwarded under proof /2, and the backend labels naming exactly the recorder's forwarded hosts.
        && (!Object.hasOwn(o, 'readBack') || (o.type === 'egress-recorder' && validReadBackRecord(o.readBack) && READ_BACK_LABELS.includes(o.collector?.label)
          && Object.keys(o.readBack.hosts).every(h => o.forward?.[h]?.proofVersion === 2) && stable(Object.keys(o.readBack.backends).sort()) === stable(Object.keys(o.forward ?? {}).sort())))
        // Aliases (FIX-04 option 2, src/egress-rules.mjs): only on a recorder built to fold them (egress-recorder/11); each window publishes the same.
        && (!Object.hasOwn(o, 'aliases') || (o.type === 'egress-recorder' && SIBLING_LABELS.includes(o.collector?.label) && validAliasRecord(o.aliases, Object.keys(o.aliases))))
        // The run's other recorders' destinations (FIX-08, src/egress-rules.mjs): only on a recorder built to read them (egress-recorder/13); each window publishes the same.
        && (!Object.hasOwn(o, 'cross') || (o.type === 'egress-recorder' && CROSS_LABELS.includes(o.collector?.label) && validCrossRecord(o.cross, Object.keys(o.aliases ?? {}), o.aliases ?? null)))));
    else need(run.results.every(row => !Array.isArray(row?.trace) || row.trace.length <= 1));
    // Which declared signing secrets each recorder could use (src/idempotency.mjs): present exactly when some destination declares signing.
    need(validSigningRun(run.signing, run.observers ?? []));
  } else need(!['targetContext', 'targetLabel', 'observers', 'signing'].some(key => Object.hasOwn(run, key)));
  // App logs (src/app-log-verdicts.mjs): a v3 run that declares them carries their records; every trace binds its app-log windows to them.
  if (Object.hasOwn(run, 'appLogs')) need(v3 && validAppLogRecords(run.appLogs));
  // The catalog identity (N13): only the run's declared database observers, each once, and a digest that recomputes; with an
  // exported suite, the schema it names.
  if (Object.hasOwn(run, 'catalog')) need(v3 && validCatalogIdentity(run.catalog, (run.observers ?? []).filter(o => CATALOG_OBSERVER_TYPES.includes(o?.type)).map(o => observerInstanceId(o.type, o.id))));
  if (expectedSuite && Object.hasOwn(run, 'catalog')) need(expectedSuite.catalogSchema === CATALOG_IDENTITY_SCHEMA && Array.isArray(expectedSuite.catalogObservers)
    && run.catalog.observers.every(r => expectedSuite.catalogObservers.includes(r.instanceId)), 'unexpected-suite-evidence');
  if (expectedSuite) need(expectedSuite.version === run.assertionSchemaVersion && (expectedSuite.evidenceOrigin === undefined || expectedSuite.evidenceOrigin === run.evidenceOrigin), 'unexpected-suite-evidence');
  // The exported suite fixes the target context and the declared observers.
  if (expectedSuite && v3) need((expectedSuite.targetContext ?? 'local-app') === run.targetContext && (expectedSuite.targetLabel ?? null) === run.targetLabel
    && stable(expectedSuite.observers ?? null) === stable(run.observers ?? null), 'unexpected-suite-evidence');
  // It fixes the declared app logs too.
  if (expectedSuite && v3) need(stable(expectedSuite.appLogs ?? null) === stable(run.appLogs ?? null), 'unexpected-suite-evidence');
  // Declared channels (src/channels.mjs): well formed against the run's own observers, and exactly the expected suite's.
  if (Object.hasOwn(run, 'channels')) need(v3 && channelDeclarationProblem(run.channels, run.observers ?? []) === null);
  if (expectedSuite && v3) need(stable(expectedSuite.channels ?? null) === stable(run.channels ?? null), 'unexpected-suite-evidence');
  // The exported suite fixes the correlation header, the recorded pairs and the settlement mode of a run's settlement record,
  // so a correlated record cannot be relabelled to another mode or stripped to /1 against the suite.
  if (expectedSuite && v3 && record(run.settlement)) need(stable(expectedSuite.correlation ?? null) === stable(run.settlement.correlation ? { header: run.settlement.correlation.header, recorded: run.settlement.correlation.recorded, mode: run.settlement.mode } : null), 'unexpected-suite-evidence');
  // It fixes the judged-late-effects declaration too (src/http-settlement.mjs), so a record cannot shed or gain outsideWindow against it.
  if (expectedSuite && v3 && record(run.settlement)) need((expectedSuite.outsideWindow ?? null) === (run.settlement.outsideWindow ?? null), 'unexpected-suite-evidence');
  // Background attribution: the record (v3 only) and, with an exported suite, the declaration it fixes.
  const attributionDeclared = attributionRecordOf(run, expectedSuite, v3);
  // With an exported suite every sent row is one of its checks, so the row's role and expected evidence are always bound
  // to the suite's (a row renamed out of the suite and relabelled an allowed-use control is refused, not judged unbound).
  if (expectedSuite) need(Array.isArray(expectedSuite.checks) && run.results.every(row => !record(row) || row.status === 'not_applicable' || expectedSuite.checks.some(check => check.id === row.id)), 'unexpected-suite-evidence');
  // The connector writes not_applicable only for a check its profile declares "applies": false, and the exported suite
  // carries that declaration: a row relabelled not_applicable (or a declared one that was sent) is refused. Without a
  // suite, a not_applicable row is not checked against any declaration. Read before the identity recompute, which under
  // actor-identity/5 expects a probe point after every sent row of an actor, so the suite's reason is the one reported.
  if (expectedSuite && run.results.some(row => record(row) && (row.status === 'not_applicable') !== (expectedSuite.checks.find(check => check.id === row.id)?.applicability?.applies === false))) throw new HttpEvidenceError('unexpected-suite-evidence', 'applicability-mismatch');
  // A not_applicable row was not decided, so it carries no decision under any rule set (the connector never writes one):
  // a decision there would be exported beside its status as if it had been decided.
  need(run.results.every(row => !record(row) || row.status !== 'not_applicable' || !Object.hasOwn(row, 'decision')));
  // The mirror phase: its rows and the run's rate-limit statuses, read before the identity recompute, which keeps those rows out of the brackets.
  const mirrors = mirrorPhaseOf(run, expectedSuite, v3);
  const identity = v2 ? httpIdentity(run, expectedSuite, mirrors.ids) : { reasonFor: () => null, unproven: [], loginUnproven: [], rules: 0 };
  // json.noForeignValues: a run whose rows use it carries the value-free tenant declaration (counts per tenant and class,
  // the attributesAlone policy, each actor's tenant position); the exported suite fixes it. Never the values.
  const usesForeign = run.results.some(row => record(row) && Array.isArray(row.observed?.predicates) && row.observed.predicates.some(p => p?.kind === FOREIGN_VALUES_KIND));
  if (usesForeign || Object.hasOwn(run, 'tenantValueCounts')) need(v3 && validTenantValueCounts(run.tenantValueCounts));
  if (expectedSuite) need(stable(expectedSuite.tenantValues ?? null) === stable(run.tenantValueCounts ?? null), 'unexpected-suite-evidence');
  // actor-identity/5: the declared principals (alias -> principalId) the absence selectors are paired against; bound to the suite.
  if (identity.rules >= 5) {
    need(record(run.principals) && Object.keys(run.principals).length <= 50 && Object.entries(run.principals).every(([alias, principalId]) => identifier(alias) && identifier(principalId)));
    need(run.results.every(row => !record(row?.trace?.[0]?.data) || row.status === 'not_applicable' || Object.hasOwn(run.principals, row.trace[0].data.actorId)));
    // The redacted suite carries a digest of the principals, never the identifiers themselves.
    if (expectedSuite?.principalsDigest !== undefined) need(digest(run.principals) === expectedSuite.principalsDigest, 'unexpected-suite-evidence');
  } else need(!Object.hasOwn(run, 'principals'));
  // A run saved before custody decided effect verdicts carries no custody field on any effect clause: refused as such
  // (the HTTP evaluator identity moved), not as an edited verdict. Removing it from some clauses still reads effect-verdict.
  const clauses = run.results.flatMap(row => record(row) && Array.isArray(row.trace) && record(row.trace[1]?.data) && Array.isArray(row.trace[1].data.effects) ? [...row.trace[1].data.effects, ...(Array.isArray(row.trace[1].data.claims) ? row.trace[1].data.claims : [])] : []);
  if (clauses.length && clauses.every(e => !record(e) || !Object.hasOwn(e, 'custody'))) throw new HttpEvidenceError('invalid-run-evidence', 'effect-pre-custody');
  // Every sent request has its own requestId: a row copied into another check's slot repeats one.
  const requestIds = run.results.filter(row => record(row) && row.status !== 'not_applicable').map(row => row.trace?.[0]?.data?.requestId);
  if (new Set(requestIds).size !== requestIds.length) throw new HttpEvidenceError('invalid-run-evidence', 'duplicate-request-id');
  // Settlement (v3): a run with effect windows carries its gap windows; each clause's finding is recomputed across the run.
  const findings = v3 ? settlementOf(run) : new Map();
  if (!v3) need(!Object.hasOwn(run, 'settlement'));
  // The effect horizon and run budget (v3): the record, the windows it held short and the suite's declaration agree.
  if (v3) timingOf(run, expectedSuite); else need(!Object.hasOwn(run, 'timing'));
  // Background attribution (declared v3 runs): each settled clause's finding is recomputed across the run.
  const attribution = v3 ? attributionOf(run, findings, attributionDeclared, record(run.timing) && run.timing.lateFails === LATE_FAILS) : new Map();
  // Positive-match pairing (actor-identity/5 runs): each absence clause's finding is recomputed across the run.
  const pairing = v3 && identity.rules >= 5 ? pairingOf(run, findings, attribution) : new Map();
  // Later outcomes (provider-feed/6): each positive pass's later-outcome finding is recomputed across the run.
  const later = v3 ? laterOf(run, findings, attribution, pairing, attributionDeclared, record(run.timing) && run.timing.lateFails === LATE_FAILS) : new Map();
  // Typed captures and request preconditions (v3), recomputed from the rows in run order.
  const preconditionFor = v3 ? capturePreconditions(run, expectedSuite, identity) : () => null;
  // App-log admissions (src/app-log-verdicts.mjs): each observed row's principal, the background sources and earlier same-principal selectors.
  // Read before any row is validated, so a malformed sealed clause is refused here as a trace error, not a raw TypeError.
  let admissionsAt = new Map();
  if (Object.hasOwn(run, 'appLogs')) try { admissionsAt = admissionContexts(run.results, run.principals, attributionDeclared?.background ?? []); } catch { throw new HttpEvidenceError('invalid-run-evidence', 'effect-trace'); }
  for (const row of run.results) if (record(row) && row.status !== 'not_applicable') validateHttpObservation(row, expectedSuite?.checks?.find(check => check.id === row.id), { v2, v3, principals: run.principals, reasonFor: identity.reasonFor, failedControlsOf: identity.failedControlsOf ?? (() => []), observers: run.observers, findings: findings.get(row) ?? null, attribution: attribution.get(row) ?? null, pairing: pairing.get(row) ?? null, precondition: preconditionFor(row), rules: identity.rules, unfollowed: v3 ? unfollowedOf(run, row) : null, tenantValues: run.tenantValueCounts ?? null, appLogs: run.appLogs ?? null, admission: admissionsAt.get(row) ?? null, later: later.get(row) ?? null,
    limitStatuses: mirrors.ids.has(row.id) ? mirrors.limitStatuses : null });
  return { v2, unprovenActors: identity.unproven, loginUnprovenActors: identity.loginUnproven };
}
