// Frozen copy of scopehaven/src/effect-events.mjs at d349c7c (main before readiness edge E1; imports re-pointed), for the E1 differential compat test. Not in any identity list.
// Effect events scopehaven-effect/1 (src/effect-events.mjs; integrations/observers/events.mjs re-exports it): one normalized record for everything an
// independent observer saw the application do (OpenTelemetry GenAI spans, MCP
// JSON-RPC traffic, database changes, an HTTP audit log, a hold proxy, outbound
// requests and mail caught by a loopback egress or SMTP sink). Every
// observer is only a producer of these events; one evaluator judges them.
// Pure: no I/O. Events carry identifiers, outcomes and a digest of any payload, plus
// declared captured body fields where an observer declares them (src/body-fields.mjs: an
// egress destination's opt-in JSON pointers, never secret-like keys, never whole bodies).
import { digest } from '../../src/domain.mjs';
import { validateCaptured, validateFieldPredicates, validCaptureMap, validCaptureForm, fieldState, fieldPointers } from '../../src/body-fields.mjs';
import { localHostAllowed, singleHeader } from '../../src/http.mjs';
import { validateIdempotencyRecord, consistentIdempotencyWindow, validIdempotencyMap, countApplications, applicationsVerdict, applicationsBasis, COUNT_BY, IDEMPOTENCY_BASIS } from '../../src/idempotency.mjs';

// Wall-clock Unix nanoseconds with sub-millisecond resolution. Observers in
// other processes on this machine use the same clock.
export const wallNs = () => BigInt(Math.round((performance.timeOrigin + performance.now()) * 1e3)) * 1000n;

export const EFFECT_SCHEMA = 'scopehaven-effect/1';
export const SOURCES = Object.freeze(['otel-genai', 'mcp-jsonrpc', 'sql-snapshot', 'sql-audit-table', 'http-audit-log', 'file-audit-log', 'hold-proxy', 'http-egress', 'smtp-capture']);
// "send": an outbound request or message the application made (named by its destination).
export const OPERATIONS = Object.freeze(['tool-call', 'read', 'insert', 'update', 'delete', 'claim', 'access-change', 'send']);
// "started" is a tool call or request seen in flight; only "committed" is an effect.
export const OUTCOMES = Object.freeze(['started', 'committed', 'denied', 'error', 'unknown']);
// Coverage of one observer over one window:
//   complete  - every effect of the kinds it can see is in the window
//   net-only  - only net change between two snapshots (a write undone in between is invisible)
//   partial   - something may be missing (dropped, unparsed, in flight, not flushed)
//   failed    - the observer could not report
// Only "complete" supports a pass or a "did not happen" verdict.
export const COVERAGE = Object.freeze(['complete', 'net-only', 'partial', 'failed']);
// What an observer can see. A selector the observer cannot see makes that
// observer irrelevant (never silently "nothing happened").
//   operations       - operations it reports
//   names            - the exact names it reports (tables, gate rules, declared tools or
//                      audit actions); null means undeclared, so it never covers a name-specific check
//   actorAttribution - 'principal' when it names who acted, 'none' when it cannot
//   evidence         - 'authoritative' or 'presence-only' (above)
//   resources        - optional, keyed by destination name: { [name]: [resource, ...] }, the classes it assigns to
//                      that name's effects (the payments double declares its provider host's), each name one it
//                      reports. Not the exact vocabulary it reports: an unmodelled or unclassified effect keeps another
//                      resource. An absence selector naming that exact name and pinned to a listed class needs no
//                      positive twin while every committed effect of that name (with the selector's source and operation,
//                      when it gives them) in the deciding window carries a listed class (src/http-pairing.mjs). Absent means undeclared.
export const ACTOR_ATTRIBUTION = Object.freeze(['principal', 'none']);
// Per declared name at most SCOPE_RESOURCE_LIMIT classes, and at most SCOPE_RESOURCE_NAME_LIMIT names.
export const SCOPE_RESOURCE_LIMIT = 64, SCOPE_RESOURCE_NAME_LIMIT = 16;
// What an observer's silence means. Telemetry proves presence, not absence:
//   authoritative - sits in the request path or reads the application's own
//                   store (audit log, database, hold gate); a complete window
//                   with no matching effect shows the effect did not happen
//   presence-only - target-reported telemetry (traces, MCP tool-call logs);
//                   exporters drop, sample and reject data, so a matching
//                   effect proves it happened, but no match proves nothing
export const EVIDENCE_KINDS = Object.freeze(['authoritative', 'presence-only']);
export const PRESENCE_ONLY_SOURCES = Object.freeze(['otel-genai', 'mcp-jsonrpc']);
// Listener guard for every new loopback listener, matching src/server.mjs:
// exact 127.0.0.1:port Host, and no cross-origin browser request (DNS rebinding).
export function loopbackRequestAllowed(req, port) {
  if (!localHostAllowed(req, { port })) return false;
  const origin = singleHeader(req, 'origin');
  if (req.headers.origin !== undefined && origin !== `http://127.0.0.1:${port}`) return false;
  const site = req.headers['sec-fetch-site'];
  return site === undefined || site === 'same-origin' || site === 'none';
}
// An origin-form request target: a path, never "http://host/..." or "//host/...".
// Proxies refuse anything else, so a request cannot move the forward off the upstream.
export const originForm = target => typeof target === 'string' && target.startsWith('/') && !target.startsWith('//') && !target.includes('\\');
// Credentials are read only from the dedicated namespace (same rule as src/contracts.mjs).
export const CREDENTIAL_ENV = /^SCOPEHAVEN_TARGET_[A-Z0-9_]{1,110}$/;
export function credentialFrom(env, name, where = 'credential') {
  if (typeof name !== 'string' || !CREDENTIAL_ENV.test(name)) throw new Error(`${where}: credential references must use the dedicated SCOPEHAVEN_TARGET_ namespace.`);
  return env[name];
}
export const EFFECT_LIMITS = Object.freeze({ eventsPerWindow: 5000, name: 128, resource: 200, principal: 128, correlation: 128 });

export class EffectError extends Error { constructor(code, where) { super(`Invalid effect event: ${code}${where ? ` at ${where}` : ''}.`); this.name = 'EffectError'; this.code = code; } }
const fail = (code, where) => { throw new EffectError(code, where); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const bounded = (value, maximum) => typeof value === 'string' && value.length >= 1 && value.length <= maximum && !/[\u0000-\u001f\u007f]/.test(value);
const KEYS = ['schema', 'source', 'observer', 'seq', 'observedAt', 'actor', 'operation', 'name', 'resource', 'outcome', 'correlation', 'contentDigest'];
// Optional: `captured`, the declared body fields an egress sink read (http-egress only; src/body-fields.mjs), and
// `idempotency`, the key record of a send to a destination that declares a key header (http-egress sends only; src/idempotency.mjs).
const OPTIONAL_KEYS = ['captured', 'idempotency'];
// settlementToken: the value of a correlation header an egress-recorder destination declared (src/egress-rules.mjs).
// The application writes that value, so it is kept apart from every key a selector or a pairing pin reads: only
// src/http-settlement.mjs reads it, and only to withhold a pass. It appears only on http-egress events, which never
// carry a traceId (the recorder writes none), so a traceId selector or pin never reads a value the application chose there.
const CORRELATION_KEYS = ['traceId', 'spanId', 'parentSpanId', 'requestId', 'rpcId', 'settlementToken'];

export function validateEffect(event, where = 'event') {
  if (!plain(event)) fail('not-object', where);
  const extra = Reflect.ownKeys(event).find(key => !KEYS.includes(key) && !OPTIONAL_KEYS.includes(key));
  if (extra !== undefined) fail('unsupported-field', where);
  const missing = KEYS.find(key => !Object.hasOwn(event, key));
  if (missing !== undefined) fail(`missing-${missing}`, where);
  if (event.schema !== EFFECT_SCHEMA) fail('schema', where);
  if (!SOURCES.includes(event.source)) fail('source', where);
  if (!plain(event.observer) || !bounded(event.observer.kind, 64) || !bounded(event.observer.instanceId, 128) || Object.keys(event.observer).length !== 2) fail('observer', where);
  if (!Number.isSafeInteger(event.seq) || event.seq < 1) fail('seq', where);
  if (typeof event.observedAt !== 'string' || Number.isNaN(Date.parse(event.observedAt))) fail('observedAt', where);
  if (event.actor !== null && !bounded(event.actor, EFFECT_LIMITS.principal)) fail('actor', where);
  if (!OPERATIONS.includes(event.operation)) fail('operation', where);
  if (!bounded(event.name, EFFECT_LIMITS.name)) fail('name', where);
  if (event.resource !== null && !bounded(event.resource, EFFECT_LIMITS.resource)) fail('resource', where);
  if (!OUTCOMES.includes(event.outcome)) fail('outcome', where);
  if (!plain(event.correlation) || Reflect.ownKeys(event.correlation).some(key => !CORRELATION_KEYS.includes(key) || !bounded(event.correlation[key], EFFECT_LIMITS.correlation))) fail('correlation', where);
  if (event.source === 'http-egress' ? Object.hasOwn(event.correlation, 'traceId') : Object.hasOwn(event.correlation, 'settlementToken')) fail('correlation', where);
  if (event.contentDigest !== null && !/^[a-f0-9]{64}$/.test(event.contentDigest)) fail('contentDigest', where);
  if (Object.hasOwn(event, 'captured')) {
    if (event.source !== 'http-egress') fail('captured-source', where);
    try { validateCaptured(event.captured); } catch (error) { fail(error.message, where); }
  }
  if (Object.hasOwn(event, 'idempotency')) {
    if (event.source !== 'http-egress' || event.operation !== 'send') fail('idempotency-source', where);
    try { validateIdempotencyRecord(event.idempotency, event.seq); } catch (error) { fail(error.message, where); }
  }
  return event;
}

// Build a valid event. `content` (arguments, row values, a request body) is
// reduced to its digest here and never stored. `captured` is passed only by an
// observer that declares capture (the egress recorder), never derived from content.
export function makeEffect({ source, observer, seq, observedAt = new Date().toISOString(), actor = null, operation, name, resource = null, outcome, correlation = {}, content, captured, idempotency }) {
  const clean = Object.fromEntries(Object.entries(correlation).filter(([, value]) => value !== undefined && value !== null && value !== '').map(([key, value]) => [key, String(value).slice(0, EFFECT_LIMITS.correlation)]));
  return validateEffect({ schema: EFFECT_SCHEMA, source, observer, seq, observedAt, actor: actor === null || actor === undefined ? null : String(actor), operation, name: String(name).slice(0, EFFECT_LIMITS.name),
    resource: resource === null || resource === undefined ? null : String(resource).slice(0, EFFECT_LIMITS.resource), outcome, correlation: clean, contentDigest: content === undefined ? null : digest(content),
    ...(captured === undefined ? {} : { captured }), ...(idempotency === undefined ? {} : { idempotency }) });
}

// A selector names the effect a check is about. Every given field must match;
// `resource` and `name` accept an exact string or { prefix }.
// `fields` (src/body-fields.mjs) matches declared captured body fields, three-valued (matchState).
// Only callers that judge the third value opt in ({ fields: true }): HTTP effect clauses, effect.only
// and claim rules. Everyone else refuses it, because a boolean match would read "unknown" as "no".
// A selector with fields names an exact destination.
const SELECTOR_KEYS = ['source', 'actor', 'operation', 'name', 'resource', 'outcome', 'traceId', 'fields'];
export function validateSelector(selector, where = 'selector', { fields = false } = {}) {
  if (!plain(selector) || Reflect.ownKeys(selector).some(key => !SELECTOR_KEYS.includes(key)) || !Object.keys(selector).length) fail('selector', where);
  if (Object.hasOwn(selector, 'fields')) {
    if (!fields) fail('selector-fields-unsupported', where);
    try { validateFieldPredicates(selector.fields); } catch (error) { fail(error.message, where); }
    if (typeof selector.name !== 'string') fail('selector-fields-name', where);
  }
  for (const key of ['name', 'resource']) if (Object.hasOwn(selector, key) && !(bounded(selector[key], 200) || (plain(selector[key]) && Object.keys(selector[key]).length === 1 && bounded(selector[key].prefix, 200)))) fail(`selector-${key}`, where);
  if (Object.hasOwn(selector, 'operation') && !OPERATIONS.includes(selector.operation)) fail('selector-operation', where);
  if (Object.hasOwn(selector, 'outcome') && !OUTCOMES.includes(selector.outcome)) fail('selector-outcome', where);
  if (Object.hasOwn(selector, 'source') && !SOURCES.includes(selector.source)) fail('selector-source', where);
  return selector;
}
const textMatches = (rule, value) => typeof rule === 'string' ? value === rule : typeof value === 'string' && value.startsWith(rule.prefix);
// Three-valued: 'match', 'no' or 'unknown'. The base keys decide first (any miss is 'no'); then each
// field predicate: any 'no' gives 'no', otherwise any 'unknown' (no captured record, an unreadable body,
// an absent or unusable field, a type that does not fit the operand) gives 'unknown'.
export function matchState(event, selector) {
  const base = Object.entries(selector).every(([key, rule]) => key === 'fields' ? true : key === 'traceId' ? event.correlation.traceId === rule : ['name', 'resource'].includes(key) ? textMatches(rule, event[key]) : event[key] === rule);
  if (!base) return 'no';
  if (selector.fields === undefined) return 'match';
  const states = selector.fields.map(entry => fieldState(event.captured, entry));
  return states.includes('no') ? 'no' : states.includes('unknown') ? 'unknown' : 'match';
}
// Boolean, for every existing caller: only a decided match counts.
export const matches = (event, selector) => matchState(event, selector) === 'match';

// Effect assertions, judged over the events every observer reported for one
// window, together with each observer's coverage and scope.
//   effect.none   - no committed effect matches (a forbidden action did not happen)
//   effect.exists - at least one committed effect matches (an allowed action did happen)
//   effect.count  - exactly `expected` committed effects match; needs a named source and
//                   exactly one authoritative observer instance that can see it
// For an actor-scoped check, a matching effect with no known actor, or an actor
// that is not a declared principal, is unattributable: never a pass.
// Rules: one observed committed match from any relevant observer is enough to
// fail effect.none (or pass effect.exists). Every absence verdict needs at least
// one authoritative observer, and every authoritative observer that can see the
// selected effect to be complete: a failed one gives observer-failure, any
// other gap gives missing, and no authoritative observer able to see it gives
// unobservable. Traces and tool-call logs can show an action happened; only an
// authoritative log in the request path or the database can show it did not.
export const EFFECT_ASSERTIONS = Object.freeze(['effect.none', 'effect.exists', 'effect.count']);
// countBy: "idempotency-key" (effect.count only, src/idempotency.mjs) counts applications instead of sends. Only HTTP effect
// clauses opt in ({ countBy: true }); every other caller refuses it.
export function validateEffectAssertion(assertion, where = 'assertion', { fields = false, countBy = false } = {}) {
  if (!plain(assertion) || !EFFECT_ASSERTIONS.includes(assertion.kind)) fail('effect-assertion', where);
  if (Object.hasOwn(assertion, 'countBy')) {
    if (!countBy) fail('effect-count-by-unsupported', where);
    if (!COUNT_BY.includes(assertion.countBy)) fail('effect-count-by', where);
    if (assertion.kind !== 'effect.count') fail('effect-assertion', where);
    if (!(Number.isSafeInteger(assertion.expected) && assertion.expected >= 1)) fail('effect-count-by-absence', where);
    if (!plain(assertion.select) || assertion.select.source !== 'http-egress') fail('effect-count-by-source', where);
    if (typeof assertion.select.name !== 'string') fail('effect-count-by-name', where);
    if (assertion.select.operation !== undefined && assertion.select.operation !== 'send') fail('effect-count-by-operation', where);
  }
  const allowed = assertion.kind === 'effect.count' ? ['kind', 'select', 'expected', ...(Object.hasOwn(assertion, 'countBy') ? ['countBy'] : [])] : ['kind', 'select'];
  if (Reflect.ownKeys(assertion).some(key => !allowed.includes(key)) || !Object.hasOwn(assertion, 'select')) fail('effect-assertion', where);
  if (assertion.kind === 'effect.count' && !(Number.isSafeInteger(assertion.expected) && assertion.expected >= 0 && assertion.expected <= 1000)) fail('effect-count', where);
  validateSelector(assertion.select, `${where} > select`, { fields });
  if (assertion.kind === 'effect.count' && assertion.select.source === undefined) fail('effect-count-needs-source', where);
  return assertion;
}
export function validateScope(scope, where = 'scope') {
  if (!plain(scope) || !Array.isArray(scope.operations) || !scope.operations.length || !scope.operations.every(op => OPERATIONS.includes(op))) fail('scope-operations', where);
  if (!(scope.names === null || (Array.isArray(scope.names) && scope.names.every(n => bounded(n, EFFECT_LIMITS.name))))) fail('scope-names', where);
  if (!ACTOR_ATTRIBUTION.includes(scope.actorAttribution)) fail('scope-actor', where);
  if (!EVIDENCE_KINDS.includes(scope.evidence)) fail('scope-evidence', where);
  // The resource vocabulary is keyed by a name the observer reports: a class vouches only for the name that lists it.
  if (scope.resources !== undefined && !(plain(scope.resources) && Array.isArray(scope.names) && Object.keys(scope.resources).length >= 1 && Object.keys(scope.resources).length <= SCOPE_RESOURCE_NAME_LIMIT
    && Object.entries(scope.resources).every(([name, list]) => scope.names.includes(name) && Array.isArray(list) && list.length >= 1 && list.length <= SCOPE_RESOURCE_LIMIT && list.every(r => bounded(r, EFFECT_LIMITS.resource))))) fail('scope-resources', where);
  // capture: { [name]: [pointer, ...] }, the body fields the observer reads for each declared name (src/body-fields.mjs).
  if (scope.capture !== undefined && !(validCaptureMap(scope.capture) && Array.isArray(scope.names) && Object.keys(scope.capture).every(name => scope.names.includes(name)))) fail('scope-capture', where);
  // idempotency: { [name]: declaration }, the key header the observer reads for each declared name (src/idempotency.mjs).
  if (scope.idempotency !== undefined && !(validIdempotencyMap(scope.idempotency) && Array.isArray(scope.names) && Object.keys(scope.idempotency).every(name => scope.names.includes(name)))) fail('scope-idempotency', where);
  // captureForm: the names whose declared fields are also read from form-encoded bodies, each a key of capture.
  if (scope.captureForm !== undefined && !validCaptureForm(scope.captureForm, scope.capture)) fail('scope-capture-form', where);
  return scope;
}
// Can this window's observer see effects matching the selector at all?
export function windowSees(window, select) {
  if (select.source !== undefined && window.source !== select.source) return false;
  const scope = window.scope;
  if (select.operation !== undefined && !scope.operations.includes(select.operation)) return false;
  // An observer without a declared name vocabulary cannot vouch for a specific name.
  if (select.name !== undefined && (scope.names === null || !scope.names.some(n => textMatches(select.name, n)))) return false;
  if ((select.actor !== undefined) && scope.actorAttribution !== 'principal') return false;
  // Field predicates are visible only where the observer declares capture of every pointer they use for
  // that exact name: a pointer typo or an undeclared field is unobservable, never "absent".
  if (select.fields !== undefined) {
    const declared = scope.capture?.[select.name];
    if (typeof select.name !== 'string' || !Array.isArray(declared) || !fieldPointers(select.fields).every(p => declared.includes(p))) return false;
  }
  return true;
}
// The selector without its body-field predicates: what an observer that cannot read the fields still sees.
export const baseSelector = select => { if (select.fields === undefined) return select; const { fields, ...rest } = select; return rest; };
// Does this window see the selector's base effect (name, operation, source, actor) but not its declared
// body fields? Such an observer cannot decide a fields clause either way, but a base-matching committed
// send it recorded may be the selected one: it holds the clause at missing (never a pass, never a fail),
// and a coverage gap in it is a gap for the clause.
export const blindToFields = (window, select) => select.fields !== undefined && windowSees(window, baseSelector(select)) && !windowSees(window, select);
// Exact update coverage from a change column (sql-snapshot only): the operator
// asserted, with a recorded source audit, that every committed update of a row
// in that table changes the column, so a row whose column is unchanged between
// the two snapshots had no committed update. Rows within the same-second guard
// are ambiguous, and a row whose content changed without the column voids the
// assertion for the whole window.
// A changed column proves at least one update, not how many: exactness never
// applies to effect.count, only to effect.none and effect.exists.
export function exactFor(window, select, kind) {
  if (!['effect.none', 'effect.exists'].includes(kind)) return null;
  if (window.source !== 'sql-snapshot' || !Array.isArray(window.exact) || select.operation !== 'update' || typeof select.name !== 'string') return null;
  const entry = window.exact.find(e => e.name === select.name);
  if (!entry || entry.violated) return null;
  if (!Array.isArray(entry.ambiguousResources) || !Array.isArray(entry.presentResources)) return null;
  // A row-specific absence needs that row seen at both marks and not ambiguous.
  if (typeof select.resource === 'string') return entry.ambiguousResources.includes(select.resource) || !entry.presentResources.includes(select.resource) ? null : entry;
  // A table-wide or prefix selector would also cover rows never seen at both marks, so it is
  // exact only on a quiescent window (no transaction committed or in progress anywhere during it).
  return entry.quiescent === true && !entry.ambiguousResources.length ? entry : null;
}
// countBy: only the HTTP effect clauses pass it (src/http-effects.mjs); every other caller refuses a countBy clause.
export function evaluateEffectAssertion(assertion, windows, { countBy = false } = {}) {
  validateEffectAssertion(assertion, 'assertion', { fields: true, countBy });
  const relevant = windows.filter(w => windowSees(w, assertion.select));
  if (!relevant.length) return { kind: assertion.kind, verdict: 'unobservable', matched: 0, basis: 'No configured observer can see this effect.', evidence: [] };
  // Presence: any relevant observer's committed match counts.
  const committed = relevant.flatMap(w => w.events).filter(e => matches(e, { ...assertion.select, outcome: 'committed' }));
  // For an actor-scoped check, a matching committed effect whose actor is unknown
  // (null) or not a declared principal ("unlisted:") could be the selected actor.
  const { actor: selectedActor, ...withoutActor } = assertion.select;
  const unknownActor = e => e.actor === null || e.actor.startsWith('unlisted:');
  const unattributed = selectedActor === undefined ? [] : relevant.flatMap(w => w.events).filter(e => unknownActor(e) && matches(e, { ...withoutActor, outcome: 'committed' }));
  // Undecided: committed sends whose declared body fields could not be read (matchState 'unknown'),
  // also those with an unknown actor that could be the selected one. Never a pass, never "absent".
  // A window blind to the fields (blindToFields) counts every base-matching committed send it recorded as undecided.
  const blind = windows.filter(w => blindToFields(w, assertion.select));
  const baseOnly = baseSelector(withoutActor), baseWithActor = baseSelector(assertion.select);
  const undecided = assertion.select.fields === undefined ? [] : [
    ...relevant.flatMap(w => w.events).filter(e => matchState(e, { ...assertion.select, outcome: 'committed' }) === 'unknown'
      || (selectedActor !== undefined && unknownActor(e) && matchState(e, { ...withoutActor, outcome: 'committed' }) === 'unknown')),
    ...blind.flatMap(w => w.events).filter(e => matches(e, { ...baseWithActor, outcome: 'committed' }) || (selectedActor !== undefined && unknownActor(e) && matches(e, { ...baseOnly, outcome: 'committed' }))),
  ];
  const undecidedBasis = `${undecided.length} committed send(s) whose declared body fields could not be read (no captured record, an unreadable body, an absent or unusable field, a value of another type, or an observer that does not capture those fields).`;
  // Absence: only authoritative observers, and only with complete coverage. An authoritative observer blind to the
  // fields decides nothing, but a gap in its coverage could hide a send that is the selected one.
  const authoritative = relevant.filter(w => w.scope.evidence === 'authoritative');
  const blindAuthoritative = blind.filter(w => w.scope.evidence === 'authoritative');
  // A net-only snapshot window counts as complete for an exact-name update
  // selector on a table with a source-audited change column (see exactFor).
  const exactEntries = authoritative.map(w => w.coverage === 'net-only' ? exactFor(w, assertion.select, assertion.kind) : null).filter(Boolean);
  const gaps = [...authoritative, ...blindAuthoritative].filter(w => w.coverage !== 'complete' && !(w.coverage === 'net-only' && exactFor(w, assertion.select, assertion.kind)));
  const gapVerdict = gaps.some(w => w.coverage === 'failed') ? 'observer-failure' : 'missing';
  // A net-only window whose exact entry for this name is violated says so: the table's rows decided nothing.
  const violatedNote = w => Array.isArray(w.exact) && w.exact.some(e => e.name === assertion.select.name && e.violated === true) ? `, ${assertion.select.name} violated` : '';
  const gapBasis = `Not every authoritative observer that can see this effect covered the window (${gaps.map(w => `${w.instanceId}: ${w.coverage}${w.reason ? `, ${w.reason}` : ''}${violatedNote(w)}`).join('; ')}).`;
  const presenceOnlyBasis = 'Only presence-only observers (traces, tool-call logs) can see this effect: they can show it happened, not that it did not.';
  const unattributedBasis = `${unattributed.length} matching committed effect(s) could not be attributed to a declared actor.`;
  const evidence = committed.slice(0, 20).map(e => ({ source: e.source, seq: e.seq, observer: e.observer.instanceId, digest: digest(e) }));
  const decided = (verdict, basis, matched = committed.length) => ({ kind: assertion.kind, verdict, matched, basis, evidence });
  // An absence verdict, once nothing positive decided the check.
  // Absence is claimed only about an exact name the authoritative observer declares it logs.
  const exactName = typeof assertion.select.name === 'string';
  const exactBasis = 'An absence verdict needs an exact action or tool name from an authoritative observer\'s declared vocabulary; a prefix or name-free selector can only show presence.';
  const absence = (passOrFail, basis) => !exactName ? decided('unobservable', exactBasis)
    : unattributed.length ? decided('missing', unattributedBasis)
    : !authoritative.length ? decided('unobservable', presenceOnlyBasis)
    : gaps.length ? decided(gapVerdict, gapBasis) : decided(passOrFail, basis);
  if (assertion.kind === 'effect.none') {
    if (committed.length) return decided('fail', 'An observer recorded a committed effect the check forbids.');
    if (undecided.length) return decided('missing', undecidedBasis);
    return absence('pass', `Every authoritative observer that can see this effect (${authoritative.map(w => w.instanceId).join(', ')}) covered the window and recorded no matching committed effect.${exactEntries.length ? ` Coverage basis: ${exactEntries.map(e => e.basis).join('; ')}.` : ''}`);
  }
  if (assertion.kind === 'effect.exists') {
    if (committed.length) return decided('pass', 'An observer recorded the expected committed effect.');
    if (undecided.length) return decided('missing', undecidedBasis);
    return absence('fail', 'Every authoritative observer that can see this effect covered the window and recorded no matching committed effect.');
  }
  // An exact count is an absence claim beyond the counted effects: one authoritative observer only.
  if (!exactName) return decided('unobservable', exactBasis);
  if (!authoritative.length) return decided('unobservable', presenceOnlyBasis);
  if (authoritative.length !== 1) return decided('missing', 'An exact count needs exactly one authoritative observer instance that can see the effect; two observers would count the same effect twice.');
  const countedEvents = authoritative[0].events.filter(e => matches(e, { ...assertion.select, outcome: 'committed' })), counted = countedEvents.length;
  if (undecided.length) return decided('missing', undecidedBasis, counted);
  if (gaps.length) return decided(gapVerdict, gapBasis, counted);
  if (unattributed.length) return decided('missing', unattributedBasis, counted);
  // Applications (src/idempotency.mjs): only from a window that records keys for this exact name.
  if (assertion.countBy !== undefined) {
    if (authoritative[0].scope.idempotency?.[assertion.select.name] === undefined) return { ...decided('unobservable', `No key record: ${IDEMPOTENCY_BASIS['idempotency-key-unrecorded']}.`, counted), applications: null };
    const applications = countApplications(authoritative[0], assertion.select.name, countedEvents);
    return { ...decided(applicationsVerdict(applications, assertion.expected), applicationsBasis(applications, counted, assertion.expected), counted), applications: { low: applications.low, high: applications.high, reason: applications.reason } };
  }
  return decided(counted === assertion.expected ? 'pass' : 'fail', `Observed ${counted} matching committed effects; expected ${assertion.expected}.`, counted);
}

// The observer interface every producer implements. Windows are bounded by
// observer cursors taken at marks, not by wall-clock comparison where the
// observer has its own order (audit ids, log sequence, snapshots).
//   kind, instanceId, source, scope
//   async start()                     begin observing; throws if it cannot
//   async mark() -> cursor            an opaque position
//   async collect(from, to) -> { events, coverage, reason }
//   async stop()
// Window reasons are machine codes (or a comma-separated list of them), never free text.
export const REASON_PATTERN = /^(?=.{1,200}$)[a-z0-9]+(?:-[a-z0-9]+)*(?:,[a-z0-9]+(?:-[a-z0-9]+)*)*$/;
const validMarks = m => plain(m) && Object.keys(m).length === 3 && [m.startXmax, m.endXmax].every(x => typeof x === 'string' && /^[1-9]\d{0,19}$/.test(x)) && Number.isSafeInteger(m.inProgress) && m.inProgress >= 0;
export function validateWindow(window, where = 'window') {
  if (!plain(window) || !SOURCES.includes(window.source) || !COVERAGE.includes(window.coverage) || !Array.isArray(window.events) || window.events.length > EFFECT_LIMITS.eventsPerWindow) fail('window', where);
  if (!(window.reason === null || window.reason === undefined || (typeof window.reason === 'string' && REASON_PATTERN.test(window.reason)))) fail('reason', where);
  validateScope(window.scope, `${where} > scope`);
  // Target-reported telemetry can never be declared authoritative.
  if (PRESENCE_ONLY_SOURCES.includes(window.source) && window.scope.evidence !== 'presence-only') fail('scope-evidence-source', where);
  if (window.exact !== undefined) {
    if (window.source !== 'sql-snapshot' || !Array.isArray(window.exact) || window.exact.length > 32 || new Set(window.exact.map(e => e?.name)).size !== window.exact.length) fail('exact', where);
    // method: 'change-column' (the default; an operator assertion backed by a source audit) or
    // 'xmin' (Postgres row versions; no assertion, so no audit). recomputeEffectTrace binds the method to the observer type.
    for (const e of window.exact) if (!plain(e) || !bounded(e.name, EFFECT_LIMITS.name) || !bounded(e.basis, 512) || typeof e.violated !== 'boolean'
      // The lists first: every later clause may read them.
      || !Array.isArray(e.ambiguousResources) || e.ambiguousResources.length > 10000 || !e.ambiguousResources.every(r => bounded(r, EFFECT_LIMITS.resource))
      // presentResources: the selected rows the observer saw at both marks (required on every entry).
      || !Array.isArray(e.presentResources) || e.presentResources.length > 1000 || !e.presentResources.every(r => bounded(r, EFFECT_LIMITS.resource))
      || !(e.method === undefined || e.method === 'change-column' || e.method === 'xmin')
      || (e.method === 'xmin' ? e.auditSha256 !== null : !/^[a-f0-9]{64}$/.test(e.auditSha256 ?? ''))
      // marks: the transaction-id facts an xmin entry rests on, recorded so they can be checked.
      || (e.method === 'xmin' ? !validMarks(e.marks) : e.marks !== undefined)
      || (e.method === 'xmin' && BigInt(e.marks.endXmax) < BigInt(e.marks.startXmax) && e.violated !== true)
      // quiescent: only an xmin entry, and only when its marks show the whole cluster was idle during the window.
      || (e.quiescent !== undefined && !(e.quiescent === true && e.method === 'xmin' && e.marks.startXmax === e.marks.endXmax && e.marks.inProgress === 0 && e.ambiguousResources.length === 0))) fail('exact', where);
  }
  window.events.forEach((event, i) => { validateEffect(event, `${where} > event ${i + 1}`); if (event.source !== window.source) fail('source-mismatch', `${where} > event ${i + 1}`); });
  // A violated table's rows decide nothing: its observer reports none of its changes.
  if (window.exact !== undefined) { const violated = new Set(window.exact.filter(e => e.violated).map(e => e.name)); if (window.events.some(e => violated.has(e.name))) fail('violated-table-events', where); }
  for (let i = 1; i < window.events.length; i++) if (window.events[i].observer.instanceId === window.events[i - 1].observer.instanceId && window.events[i].seq <= window.events[i - 1].seq) fail('seq-order', where);
  if (window.events.some(e => e.idempotency)) { try { consistentIdempotencyWindow(window.events); } catch (error) { fail(error.message, where); } }
  return window;
}
export async function collectWindow(observer, from, to) {
  const base = { source: observer.source, instanceId: observer.instanceId, scope: observer.scope };
  try {
    const { events, coverage, reason, exact } = await observer.collect(from, to);
    // An event still in flight at the window end leaves its outcome unknown.
    const inFlight = coverage === 'complete' && events.some(e => e.outcome === 'started' || e.outcome === 'unknown');
    return validateWindow({ ...base, coverage: inFlight ? 'partial' : coverage, reason: inFlight ? 'action-in-flight-at-window-end' : reason ?? null, events, ...(exact === undefined ? {} : { exact }) });
  } catch (error) {
    return { ...base, scope: observer.scope ?? { operations: [...OPERATIONS], names: null, actorAttribution: 'none', evidence: 'presence-only' }, coverage: 'failed', reason: error instanceof EffectError ? error.code : 'collect-failed', events: [] };
  }
}
