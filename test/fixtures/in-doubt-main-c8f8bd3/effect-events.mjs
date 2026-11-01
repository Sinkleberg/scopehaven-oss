// Frozen copy of scopehaven/src/effect-events.mjs at c8f8bd3 (main with IDR-2, F4c and F4d and the #356 to #360 docs, before in-doubt resolution IDR-4; imports re-pointed: the frozen
// in-doubt, http-effects, effect-outcome, effect-events, idempotency, only.mjs and suspend-clock import one another, everything else the live
// src/). For test/in-doubt-r1.test.mjs differentials only. Not in any identity list.
// Effect events scopehaven-effect/1 (src/effect-events.mjs; integrations/observers/events.mjs re-exports it): one normalized record for everything an
// independent observer saw the application do (OpenTelemetry GenAI spans, MCP
// JSON-RPC traffic, database changes, an HTTP audit log, a hold proxy, outbound
// requests and mail caught by a loopback egress or SMTP sink). Every
// observer is only a producer of these events; one evaluator judges them.
// Pure: no I/O. Events carry identifiers, outcomes and a digest of any payload, plus
// declared captured body fields where an observer declares them (src/body-fields.mjs: an
// egress destination's opt-in JSON pointers, never secret-like keys, never whole bodies), and the upstream
// outcome of a forwarded egress send (src/effect-outcome.mjs).
import { digest } from '../../../src/domain.mjs';
import { validateCaptured, validateTemplateRecord, validateFieldPredicates, validCaptureMap, validCaptureForm, fieldState, fieldPointers, captureEncodingOf, TEMPLATE_POINTER, ABSENT_DECLARATION } from '../../../src/body-fields.mjs';
import { localHostAllowed, singleHeader } from '../../../src/http.mjs';
import { validateIdempotencyRecord, consistentIdempotencyWindow, validIdempotencyMap, countApplications, applicationsVerdict, applicationsBasis, COUNT_BY, IDEMPOTENCY_BASIS } from './idempotency.mjs';
import { validUpstreamRecord, validForwardScope, validUpstreamPredicate, upstreamState, forwardSees } from './effect-outcome.mjs';
// Suspend-aware custody time: a window's record of a host suspend it overlapped is validated here and named in the gap basis; it decides nothing.
import { validSuspendRecord, suspendNote } from './suspend-clock.mjs';
// In-doubt resolution (IDR-1): a window copy keeps its gate-B admission (src/in-doubt.mjs carryInDoubt).
import { carryInDoubt } from './in-doubt.mjs';

// Wall-clock Unix nanoseconds with sub-millisecond resolution. Observers in
// other processes on this machine use the same clock.
export const wallNs = () => BigInt(Math.round((performance.timeOrigin + performance.now()) * 1e3)) * 1000n;

export const EFFECT_SCHEMA = 'scopehaven-effect/1';
export const SOURCES = Object.freeze(['otel-genai', 'mcp-jsonrpc', 'sql-snapshot', 'sql-audit-table', 'http-audit-log', 'file-audit-log', 'hold-proxy', 'http-egress', 'smtp-capture', 'provider-feed', 'app-log']);
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
export const PRESENCE_ONLY_SOURCES = Object.freeze(['otel-genai', 'mcp-jsonrpc', 'app-log']);
// Report-only sources (src/app-log-rules.mjs): the application's own action log. Its windows are sealed beside a check's
// observer windows (data.appLogWindows) and never enter a custody decision. custodyWindows is the one choke point: every
// custody entry point (decide, settle, attribute, pair, the restsOn admission, the follow rule, collect, and the integrations
// that judge windows) passes its windows through it, and it refuses one from a report-only source, so a missed call site
// fails loudly instead of letting the application's own record decide (test/app-log-separation.test.mjs enumerates them).
export const REPORT_ONLY_SOURCES = Object.freeze(['app-log']);
const reportOnly = w => w !== null && typeof w === 'object' && REPORT_ONLY_SOURCES.includes(w.source);
export function custodyWindows(windows, where = 'windows') {
  if (Array.isArray(windows) && windows.some(reportOnly)) throw new EffectError('app-log-in-custody-path', where);
  return windows;
}
// The same over a run's rows ({ windows }), gaps and barriers (lists of windows), as settlement and attribution take them.
// where: the entry point's name, so a refusal says which call site saw the window.
export function custodyRunWindows(rows, gaps = [], barriers = [], where = 'run windows') {
  const lists = [...(Array.isArray(rows) ? rows.map(r => r?.windows) : []), ...(Array.isArray(gaps) ? gaps : []), ...(Array.isArray(barriers) ? barriers : [])];
  for (const list of lists) custodyWindows(list, where);
}
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
// Optional: `captured`, the declared body fields an egress sink read (http-egress; src/body-fields.mjs) or a provider feed's
// template record (provider-feed sends; validateTemplateRecord), and
// `idempotency`, the key record of a send to a destination that declares a key header (http-egress sends only; src/idempotency.mjs).
// `upstream`, the outcome of a forwarded send (http-egress sends only; src/effect-outcome.mjs).
const OPTIONAL_KEYS = ['captured', 'idempotency', 'upstream'];
// settlementToken: the value of a correlation header an egress-recorder destination declared (src/egress-rules.mjs).
// The application writes that value, so it is kept apart from every key a selector or a pairing pin reads: only
// src/http-settlement.mjs reads it, and only to withhold a pass. It appears only on http-egress events, which never
// carry a traceId (the recorder writes none), so a traceId selector or pin never reads a value the application chose there,
// and on app-log events (src/app-log-rules.mjs fields.trace), which no custody path reads: there admissions read it, only to
// set a line aside.
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
  if (event.source === 'http-egress' ? Object.hasOwn(event.correlation, 'traceId') : event.source !== 'app-log' && Object.hasOwn(event.correlation, 'settlementToken')) fail('correlation', where);
  if (event.contentDigest !== null && !/^[a-f0-9]{64}$/.test(event.contentDigest)) fail('contentDigest', where);
  if (Object.hasOwn(event, 'captured')) {
    // A provider feed's only captured field is its template record (src/body-fields.mjs validateTemplateRecord).
    // An app log's captured record holds its rule's declared constants and values its closed word maps name (src/app-log-rules.mjs).
    if (event.source !== 'http-egress' && !(event.source === 'provider-feed' && event.operation === 'send') && event.source !== 'app-log') fail('captured-source', where);
    try { (event.source === 'provider-feed' ? validateTemplateRecord : validateCaptured)(event.captured); } catch (error) { fail(error.message, where); }
  }
  if (Object.hasOwn(event, 'idempotency')) {
    if (event.source !== 'http-egress' || event.operation !== 'send') fail('idempotency-source', where);
    try { validateIdempotencyRecord(event.idempotency, event.seq); } catch (error) { fail(error.message, where); }
  }
  // A decided upstream outcome belongs only to a send that reached the recorder in full.
  if (Object.hasOwn(event, 'upstream') && !(event.source === 'http-egress' && event.operation === 'send' && validUpstreamRecord(event.upstream) && (event.upstream.outcome === 'unknown' || event.outcome === 'committed'))) fail('upstream', where);
  return event;
}

// Build a valid event. `content` (arguments, row values, a request body) is
// reduced to its digest here and never stored. `captured` is passed only by an
// observer that declares capture (the egress recorder), never derived from content.
export function makeEffect({ source, observer, seq, observedAt = new Date().toISOString(), actor = null, operation, name, resource = null, outcome, correlation = {}, content, captured, idempotency, upstream }) {
  const clean = Object.fromEntries(Object.entries(correlation).filter(([, value]) => value !== undefined && value !== null && value !== '').map(([key, value]) => [key, String(value).slice(0, EFFECT_LIMITS.correlation)]));
  return validateEffect({ schema: EFFECT_SCHEMA, source, observer, seq, observedAt, actor: actor === null || actor === undefined ? null : String(actor), operation, name: String(name).slice(0, EFFECT_LIMITS.name),
    resource: resource === null || resource === undefined ? null : String(resource).slice(0, EFFECT_LIMITS.resource), outcome, correlation: clean, contentDigest: content === undefined ? null : digest(content),
    ...(captured === undefined ? {} : { captured }), ...(idempotency === undefined ? {} : { idempotency }), ...(upstream === undefined ? {} : { upstream }) });
}

// A selector names the effect a check is about. Every given field must match;
// `resource` and `name` accept an exact string or { prefix }.
// `fields` (src/body-fields.mjs) matches declared captured body fields, three-valued (matchState).
// Only callers that judge the third value opt in ({ fields: true }): HTTP effect clauses, effect.only
// and claim rules. Everyone else refuses it, because a boolean match would read "unknown" as "no".
// A selector with fields names an exact destination.
// `upstream: "applied"` (src/effect-outcome.mjs) requires a forwarded send's recorded upstream outcome, three-valued like
// fields; only callers that opt in ({ upstream: true }: HTTP effect clauses and claim rules) accept it, never effect.only.
const SELECTOR_KEYS = ['source', 'actor', 'operation', 'name', 'resource', 'outcome', 'traceId', 'fields', 'upstream'];
export function validateSelector(selector, where = 'selector', { fields = false, upstream = false } = {}) {
  if (!plain(selector) || Reflect.ownKeys(selector).some(key => !SELECTOR_KEYS.includes(key)) || !Object.keys(selector).length) fail('selector', where);
  if (Object.hasOwn(selector, 'fields')) {
    if (!fields) fail('selector-fields-unsupported', where);
    try { validateFieldPredicates(selector.fields); } catch (error) { fail(error.message, where); }
    if (typeof selector.name !== 'string') fail('selector-fields-name', where);
  }
  if (Object.hasOwn(selector, 'upstream')) {
    if (!upstream) fail('selector-upstream-unsupported', where);
    if (!validUpstreamPredicate(selector.upstream)) fail('selector-upstream', where);
    if (typeof selector.name !== 'string') fail('selector-upstream-name', where);
  }
  for (const key of ['name', 'resource']) if (Object.hasOwn(selector, key) && !(bounded(selector[key], 200) || (plain(selector[key]) && Object.keys(selector[key]).length === 1 && bounded(selector[key].prefix, 200)))) fail(`selector-${key}`, where);
  if (Object.hasOwn(selector, 'operation') && !OPERATIONS.includes(selector.operation)) fail('selector-operation', where);
  if (Object.hasOwn(selector, 'outcome') && !OUTCOMES.includes(selector.outcome)) fail('selector-outcome', where);
  if (Object.hasOwn(selector, 'source') && !SOURCES.includes(selector.source)) fail('selector-source', where);
  // A report-only source (the application's own action log) is never named by a declared selector: nothing judges it.
  if (Object.hasOwn(selector, 'source') && REPORT_ONLY_SOURCES.includes(selector.source)) fail('selector-source-report-only', where);
  return selector;
}
const textMatches = (rule, value) => typeof rule === 'string' ? value === rule : typeof value === 'string' && value.startsWith(rule.prefix);

// Coverage v2: destination-scoped egress entries (integrations/observers/egress-recorder.mjs collect({ scoped: true })). A
// scoped window stays 'partial' for every reader; only coverageFor reads its entries, and only on a window the HTTP connector
// collected or the HTTP validator bound (admitScoped). Any other object, a copy included, reads window.coverage.
// Provider feed v2, Part B: a witnessed endpoint feed's check window scopes its entries after the witness request the same way
// (integrations/observers/provider-feed.mjs collect({ scoped: true })): one code, FEED_LATE_CODE, and an entry per recipient domain
// and resource (a declared address or "*", never null).
export const SCOPED_CODES = Object.freeze(['egress-path-ambiguous', 'egress-request-after-witness-request', 'egress-request-in-flight']);
export const FEED_LATE_CODE = 'provider-feed-entry-after-witness-request';
export const LATE_CODES = Object.freeze(['egress-request-after-witness-request', 'egress-request-in-flight', FEED_LATE_CODE]);
const SCOPED_SOURCES = Object.freeze(['http-egress', 'provider-feed']);
export const SCOPED_LIMIT = 32;
const admittedScoped = new WeakSet(), unfollowedWindows = new WeakSet(), templateLiftWindows = new WeakSet();
export const admitScoped = window => { if (plain(window) && Object.hasOwn(window, 'scoped')) admittedScoped.add(window); return window; };
// Feed v2, Part C: a provider-feed window whose only late entry may lift effect.only through a template-pinned allow (onlyCoverageFor).
// The connector admits a window it collected from a feed that says so (observer.templateLift, provider-feed/4); the validator admits
// a sealed window only under a provider-feed/4 record, so a run judged by an earlier build keeps the semantics it was judged with.
export const admitTemplateLift = window => { if (plain(window) && window.source === 'provider-feed') templateLiftWindows.add(window); return window; };
// The late feed entries a clause's windows hold under the template lift (admitted, not unfollowed, template-lift windows). "More than
// one late entry never lifts" holds per check: a caller passes onlyCoverageFor templateLift only when this is at most one across every
// window the clause reads (integrations/collateral/only.mjs onlyScopedComplete, for a check's own windows and for settlement's later ones).
export const templateLiftCount = windows => (Array.isArray(windows) ? windows : []).reduce((n, w) => n + (templateLiftWindows.has(w) && admittedScoped.has(w) && !unfollowedWindows.has(w) && Array.isArray(w.scoped) ? w.scoped.length : 0), 0);
// The follow rule (Part A): a window whose late entries no later window or drain follows is read window-wide.
export const markUnfollowed = window => { unfollowedWindows.add(window); return window; };
// Later outcomes (src/later-outcome.mjs): a copy of a window without some of its events, read exactly as the window is (its scoped
// admission, follow-rule mark and template lift carried over). Only the later-outcome stage uses it, to judge a positive clause again
// without the sends that did not credit; removing committed events keeps every scoped invariant (scopedEventsCovered reads fewer events).
export function withoutEvents(window, drop) {
  const copy = { ...window, events: window.events.filter(e => !drop.has(e)) };
  if (admittedScoped.has(window)) admittedScoped.add(copy);
  if (unfollowedWindows.has(window)) unfollowedWindows.add(copy);
  if (templateLiftWindows.has(window)) templateLiftWindows.add(copy);
  return carryInDoubt(window, copy);
}
export const lateEntries = window => plain(window) && Array.isArray(window.scoped) && window.scoped.some(e => plain(e) && Array.isArray(e.codes) && e.codes.some(c => LATE_CODES.includes(c)));
// The follow rule, from the effect rows' windows in run order: per row, the instance ids of its windows with a late entry that
// nothing follows. An after-witness entry (an egress recorder's or a provider feed's) is followed by a later row's window of the
// same observer that did not fail; an in-flight entry (a pending forward) is followed by nothing here (only a quiet run-end drain
// could follow it).
// followed (Part D): the instance ids of egress recorders and provider feeds whose run-end drain followed (src/run-end-drain.mjs
// followedDrains); such a drain follows every late entry of its observer, after-witness and in-flight alike, on any check window.
export function unfollowedLate(rowsWindows, { followed = new Set() } = {}) {
  custodyRunWindows([], rowsWindows, [], 'unfollowedLate');
  return rowsWindows.map((windows, k) => new Set(windows.filter(w => lateEntries(w)).filter(w => {
    if (followed.has(w.instanceId)) return false;
    const codes = new Set(w.scoped.flatMap(e => e.codes));
    if (codes.has('egress-request-in-flight')) return true;
    return !rowsWindows.slice(k + 1).some(later => later.some(x => x.instanceId === w.instanceId && x.coverage !== 'failed'));
  }).map(w => w.instanceId)));
}
const SCOPED_RESOURCE = /^[A-Z]{1,16} (?:\*|\/[^\s]*)$/;
// LATE-FIELDS (egress-recorder/4): an entry the recorder built from exactly one completed after-witness request, not path-ambiguous,
// on a host that declares capture also carries that request's ledger seq and captured record. Bound as an event's record is: the
// pointers declared for its name, and a form reading only on a host declared that way. The validator binds the seq after the sealed
// window's own events (src/http-effects.mjs bindSealedWindows); settlement's re-judge appends that request's own event to a copy.
const LATE_CAPTURED_KEYS = 'captured,codes,name,resource,seq';
function lateCaptured(window, e) {
  if (e.codes.join(',') !== 'egress-request-after-witness-request' || e.resource === null || !Number.isSafeInteger(e.seq) || e.seq < 1) return false;
  try { validateCaptured(e.captured); } catch { return false; }
  const declared = plain(window.scope?.capture) && Object.hasOwn(window.scope.capture, e.name) ? window.scope.capture[e.name] : null;
  if (!Array.isArray(declared) || (e.captured.status === 'captured' && digest(Object.keys(e.captured.values).sort()) !== digest([...declared].sort()))) return false;
  const encoding = captureEncodingOf(e.captured);
  return encoding === null || (encoding === 'form') === (Array.isArray(window.scope.captureForm) && window.scope.captureForm.includes(e.name));
}
// Feed v2, Part B: a feed entry that is exactly one recipient of one after-witness entry, on a declared domain of a feed with a
// template vocabulary, carries that send's event seq and its template record (src/body-fields.mjs validateTemplateRecord), bound to
// the capture the scope publishes for its name.
function feedLateCaptured(window, e) {
  if (e.codes.join(',') !== FEED_LATE_CODE || e.resource === null || !Number.isSafeInteger(e.seq) || e.seq < 1) return false;
  try { validateTemplateRecord(e.captured); } catch { return false; }
  const declared = plain(window.scope?.capture) && Object.hasOwn(window.scope.capture, e.name) ? window.scope.capture[e.name] : null;
  return Array.isArray(declared) && declared.length === 1 && declared[0] === TEMPLATE_POINTER;
}
// A feed entry's resource, as the feed names events: "*" or a lowercase address in the entry's domain.
const FEED_RESOURCE = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9.-]{1,253}$/;
export function validScoped(window) {
  if (!plain(window) || !SCOPED_SOURCES.includes(window.source) || window.coverage !== 'partial' || !Array.isArray(window.scoped) || window.scoped.length < 1 || window.scoped.length > SCOPED_LIMIT) return false;
  const feed = window.source === 'provider-feed';
  const keys = new Set(), seqs = new Set();
  for (const e of window.scoped) {
    if (!plain(e) || !['codes,name,resource', LATE_CAPTURED_KEYS].includes(Object.keys(e).sort().join(',')) || !bounded(e.name, EFFECT_LIMITS.name) || !(e.resource === null || bounded(e.resource, EFFECT_LIMITS.resource))) return false;
    if (!Array.isArray(e.codes) || !e.codes.length || !e.codes.every(c => (feed ? [FEED_LATE_CODE] : SCOPED_CODES).includes(c)) || e.codes.join(',') !== [...new Set(e.codes)].sort().join(',')) return false;
    if (feed ? e.resource === null : e.codes.includes('egress-path-ambiguous') !== (e.resource === null)) return false;
    // As the recorder writes them: a declared host of the window's scope, and a resource "METHOD /declared-path" or "METHOD *"; as
    // the feed writes them: a declared domain, and "*" or an address in it.
    if (!Array.isArray(window.scope?.names) || !window.scope.names.includes(e.name)) return false;
    if (feed ? !(e.resource === '*' || (FEED_RESOURCE.test(e.resource) && e.resource.endsWith(`@${e.name}`))) : !(e.resource === null || SCOPED_RESOURCE.test(e.resource))) return false;
    if (Object.hasOwn(e, 'captured') && (!(feed ? feedLateCaptured : lateCaptured)(window, e) || seqs.has(e.seq))) return false;
    if (Object.hasOwn(e, 'captured')) seqs.add(e.seq);
    const key = `${e.name}\n${e.resource}`;
    if (keys.has(key)) return false;
    keys.add(key);
  }
  // In the recorder's order (by host, then resource), each entry once.
  const order = window.scoped.map(e => [e.name, String(e.resource)]);
  if (!order.every((k, i) => i === 0 || order[i - 1][0] < k[0] || (order[i - 1][0] === k[0] && order[i - 1][1] < k[1]))) return false;
  return window.reason === [...new Set(window.scoped.flatMap(e => e.codes))].sort().join(',');
}
// Could an entry be a send the selector selects? Only source (the window's), operation, name and resource are tested; everything
// else (actor, fields, upstream, traceId, outcome) could match. hostWide: a countBy clause, whose key folds span the host.
const entryFits = (entry, select, hostWide, source = 'http-egress') => (select.source === undefined || select.source === source) && (select.operation === undefined || select.operation === 'send')
  && (select.name === undefined || textMatches(select.name, entry.name)) && (hostWide || entry.resource === null || select.resource === undefined || textMatches(select.resource, entry.resource));
// Feed v2, Part B (ADDENDUM-R1 2): a provider-feed entry that carries its own signed template record (exactly one send) is outside a
// selector whose /template pin reads "no" on that record: the provider signed that this send used a declared template the pin does
// not accept, so it cannot be a selected send, whichever check it belongs to. Only "no" rules it out: an absent, undeclared or
// variant template reads unknown and still fits, and a merged entry carries no record. Selector-scoped clauses only (coverageFor:
// effect.exists, effect.none, effect.count, and settlement, custody and attribution through it); effect.only (onlyCoverageFor) judges
// every feed send regardless of template. Egress entries keep could-fit. Only on a window that sees every field the selector pins
// (windowSees): on a feed window blind to one of them (blindToFields), the same send seen there would be undecided, never "no".
const templateRulesOut = (window, entry, select) => window.source === 'provider-feed' && Object.hasOwn(entry, 'captured') && Array.isArray(select.fields)
  && windowSees(window, select) && select.fields.some(f => plain(f) && f.pointer === TEMPLATE_POINTER && fieldState(entry.captured, f) === 'no');
// The coverage a scoped window gives one clause: 'complete' only when every entry is a send the clause cannot select, on a window
// whose late entries the follow rule found followed (an unfollowed window is marked and read window-wide). Then coverage for that
// selector is complete, so a pass, a fail and a count are all decided on it (SETTLE-V3 fix A: a non-pass outcome no longer reads a
// non-fitting followed late entry as a gap). Callers still pass outcome, the verdict the clause would have with no gaps; since fix A
// every outcome reads alike, so it is not read.
export function coverageFor(window, select, { hostWide = false } = {}) {
  if (!admittedScoped.has(window) || unfollowedWindows.has(window) || !validScoped(window) || !plain(select)) return window?.coverage;
  if (!scopedEventsCovered(window)) return window.coverage;
  if (window.scoped.some(x => entryFits(x, select, hostWide, window.source) && !templateRulesOut(window, x, select))) return window.coverage;
  return 'complete';
}
// Every event the window did not record as committed is one of its entries' sends.
const scopedEventsCovered = window => window.events.every(e => e.outcome === 'committed' || window.scoped.some(x => x.name === e.name && (x.resource === null || x.resource === e.resource)));
// SETTLE-V3 fix C: the coverage a scoped window gives an effect.only clause toward a pass. 'complete' only on an admitted window
// that is not unfollowed and whose every entry (1) fits no expected selector (could-fit, entryFits, on its resource) and, for a
// countBy clause, is not on a host the window records keys for (host-wide fitting applies only on such a keyed host, whose key
// folds span the host, and an entry there never lifts) and (2) has a resource and definitely fits an allowed selector that pins
// only source, operation, name and resource, matched by the same text rule as an event. Such a send is allowed in any number and fills no expected slot,
// so whether it happened can neither offend nor fill a count: the allow list's own meaning, not a background assumption. An allow
// with an actor, upstream, traceId or outcome pin cannot be decided for a send never seen, so it never lifts; one with a fields
// pin lifts only an entry carrying its own request's captured record (LATE-FIELDS, capturedFits).
// expects, allows: the clause's expected and allowed selectors. Only judgeOnly's scopedComplete reads it, and only toward a pass.
const DECIDABLE_KEYS = Object.freeze(['source', 'operation', 'name', 'resource']);
const definitelyFits = (entry, select, source = 'http-egress') => plain(select) && Object.keys(select).every(key => DECIDABLE_KEYS.includes(key)) && entry.resource !== null
  && (select.source === undefined || select.source === source) && (select.operation === undefined || select.operation === 'send')
  && select.name !== undefined && textMatches(select.name, entry.name) && (select.resource === undefined || textMatches(select.resource, entry.resource));
// LATE-FIELDS: an entry carrying its own request's captured record (validScoped: exactly one completed after-witness request) also
// definitely fits an allowed selector that pins nothing beyond source, operation, name, resource and fields when that record reads
// 'match' under it: every pinned field known and equal (src/body-fields.mjs), never unknown, path-undeclared or over a capture cap.
// The fields are the request's own bytes as the recorder received them on the request path. The send is read as the recorder
// would record it (committed, no actor), so it is never allowed here where the same send seen in the window would not be.
const FIELD_DECIDABLE_KEYS = Object.freeze([...DECIDABLE_KEYS, 'fields']);
// source: the window's (feed v2 Part C reads a provider-feed entry as the feed records its send).
const capturedFits = (entry, select, source = 'http-egress') => plain(select) && Object.hasOwn(entry, 'captured') && entry.resource !== null && select.name !== undefined
  && Object.keys(select).every(key => FIELD_DECIDABLE_KEYS.includes(key))
  && matchState({ source, operation: 'send', name: entry.name, resource: entry.resource, outcome: 'committed', actor: null, correlation: {}, captured: entry.captured }, select) === 'match';
// templateLift (feed v2 Part C): the caller's per-check verdict that at most one late feed entry is in play (templateLiftCount); off by
// default, so a caller that does not count never lifts by template.
export function onlyCoverageFor(window, { expects, allows, hostWide = false, templateLift: perCheck = false } = {}) {
  if (!admittedScoped.has(window) || unfollowedWindows.has(window) || !validScoped(window) || !Array.isArray(expects) || !Array.isArray(allows)) return window?.coverage;
  if (!scopedEventsCovered(window)) return window.coverage;
  // Under countBy an unseen send to a host that records keys could share a key with a send the window did see and make it an
  // unproven resend (judgeOnly reads that missing, allowed or not), so such an entry never lifts (fail-open review of SETTLE-V3):
  // an unseen send is never read more leniently than the same send seen.
  const keyedHost = name => hostWide && plain(window.scope?.idempotency) && Object.hasOwn(window.scope.idempotency, name);
  // A host that records no keys is judged under countBy as without it (judgeOnly), so an entry there fits on its resource.
  // Feed v2, Part B: a provider-feed entry lifts only by fix C's template-blind rule (no capturedFits), and never while the #312 rule
  // (integrations/collateral/only.mjs) would hold that send undecided: an expected selector with a template pin under which the
  // entry reads unknown. Could-fit already blocks such an entry (unknown needs every base key, the source, operation, name and resource
  // could-fit tests among them, to match), so this guard is unreachable today; it is kept as the rule's own statement, defense in depth.
  const feed = window.source === 'provider-feed';
  const sent = x => ({ source: window.source, operation: 'send', name: x.name, resource: x.resource, outcome: 'committed', actor: null, correlation: {}, ...(Object.hasOwn(x, 'captured') ? { captured: x.captured } : {}) });
  const undecided = x => feed && expects.some(s => plain(s) && Array.isArray(s.fields) && matchState(sent(x), s) === 'unknown');
  // Feed v2, Part C (provider-feed/4 only): the window's only late entry, when it is one signed send (it carries its own record) whose
  // template is a declared label, also lifts by an allow that pins only source, operation, name, resource and fields and reads match on
  // that record (capturedFits, the LATE-FIELDS rule read as the feed's send). Absent, undeclared or variant templates never lift; two
  // or more late entries never lift this way, across the check's windows (perCheck, templateLiftCount; the window's own single-entry
  // test below is then implied, kept as defense in depth); the could-fit and #316 guards above hold it first, template-blind.
  const templateLift = x => perCheck === true && feed && templateLiftWindows.has(window) && window.scoped.length === 1 && Object.hasOwn(x, 'captured') && x.captured?.values?.[TEMPLATE_POINTER]?.type === 'string';
  const lifts = x => !keyedHost(x.name) && !expects.some(s => !plain(s) || entryFits(x, s, keyedHost(x.name), window.source)) && !undecided(x)
    && allows.some(s => definitelyFits(x, s, window.source) || (!feed && capturedFits(x, s)) || (templateLift(x) && capturedFits(x, s, window.source)));
  return window.scoped.every(lifts) ? 'complete' : window.coverage;
}
// LATE-FIELDS: a captured entry's request is the same ledger record as the event of that instance and seq in any other sealed window
// of the run (the gap or barrier after its check). Every such event, and every entry naming that seq, must agree with it on name,
// resource and captured record; a disagreement throws (the validator's effect-trace fault). An absent event (a failed or capped
// window) is not a disagreement: the lift rests on the entry's own record.
export function consistentScopedCaptures(windows) {
  const entries = new Map();
  const reading = (name, resource, captured) => digest({ name, resource, captured: captured ?? null });
  for (const w of windows) for (const e of plain(w) && Array.isArray(w.scoped) ? w.scoped : []) {
    if (!plain(e) || !Object.hasOwn(e, 'captured')) continue;
    const key = `${w.instanceId}\n${e.seq}`, value = reading(e.name, e.resource, e.captured);
    if (entries.has(key) && entries.get(key) !== value) throw new Error('scoped-captured');
    entries.set(key, value);
  }
  if (!entries.size) return;
  for (const w of windows) for (const ev of plain(w) && Array.isArray(w.events) ? w.events : []) {
    const key = `${w.instanceId}\n${ev.seq}`;
    if (entries.has(key) && entries.get(key) !== reading(ev.name, ev.resource, ev.captured)) throw new Error('scoped-captured');
  }
}
// Three-valued: 'match', 'no' or 'unknown'. The base keys decide first (any miss is 'no'); then each
// field predicate: any 'no' gives 'no', otherwise any 'unknown' (no captured record, an unreadable body,
// an absent or unusable field, a type that does not fit the operand) gives 'unknown'. The upstream predicate
// is one more: applied matches, rejected is 'no', and any other outcome or none is 'unknown'.
// formDecimals: only the fail-only judgements below (evaluateEffectAssertion, and judgeOnly in integrations/collateral/only.mjs) pass it;
// a form decimal that no common reading makes the pinned value then reads 'no' (src/body-fields.mjs decimalDiffers).
// absentFields: only the fail-only judgement in evaluateEffectAssertion passes it; a field whose pin declares absent: "fails" and that is
// definitely absent (definitelyAbsent) then reads 'no'. An absent field without the declaration, and every other unknown, stays unknown.
export function matchState(event, selector, { formDecimals = false, absentFields = false } = {}) {
  const base = Object.entries(selector).every(([key, rule]) => key === 'fields' || key === 'upstream' ? true : key === 'traceId' ? event.correlation.traceId === rule : ['name', 'resource'].includes(key) ? textMatches(rule, event[key]) : event[key] === rule);
  if (!base) return 'no';
  if (selector.fields === undefined && selector.upstream === undefined) return 'match';
  const states = [...(selector.fields ?? []).map(entry => absentFields === true && entry.absent === ABSENT_DECLARATION && definitelyAbsent(event, entry.pointer) ? 'no' : fieldState(event.captured, entry, { formDecimals })), ...(selector.upstream === undefined ? [] : [upstreamState(event, selector.upstream)])];
  return states.includes('no') ? 'no' : states.includes('unknown') ? 'unknown' : 'match';
}
// Boolean, for every existing caller: only a decided match counts.
export const matches = (event, selector) => matchState(event, selector) === 'match';
// Absent fields (fail direction only). The bytes' absence: the egress recorder read the send's body in full and parsed it without error
// (captured status "captured", so not over the cap, not compressed, not ambiguous), and the declared pointer resolved to nothing
// ({ type: 'absent' }; src/body-fields.mjs records a JSON field missing beside a URL query, or under a root that is not an object, as
// unusable instead). It decides only under a pin that declares absent: "fails", the operator's statement that the receiver neither
// defaults nor aliases the field. No captured record, an unreadable or truncated body, an unusable or mistyped value, a pointer the
// observer does not capture, and a provider feed's template record (a signed entry naming no template is not a body) are never this.
export const definitelyAbsent = (event, pointer) => event.source === 'http-egress' && plain(event.captured) && event.captured.status === 'captured'
  && plain(event.captured.values) && Object.hasOwn(event.captured.values, pointer) && plain(event.captured.values[pointer]) && event.captured.values[pointer].type === 'absent';

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
export function validateEffectAssertion(assertion, where = 'assertion', { fields = false, countBy = false, upstream = false } = {}) {
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
  validateSelector(assertion.select, `${where} > select`, { fields, upstream });
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
  // forward: { [name]: { rejected } }, the names whose sends the observer forwards and records an upstream outcome for.
  if (scope.forward !== undefined && !validForwardScope(scope.forward, scope.names)) fail('scope-forward', where);
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
  // that exact name: a pointer typo in the pin alone, or an undeclared field, is unobservable, never "absent". A typo made in both the
  // capture and a pin that declares absent: "fails" reads absent on every send, and the operator owns it (docs/KNOWN-LIMITS.md).
  if (select.fields !== undefined) {
    const declared = scope.capture?.[select.name];
    if (typeof select.name !== 'string' || !Array.isArray(declared) || !fieldPointers(select.fields).every(p => declared.includes(p))) return false;
  }
  // An upstream outcome is visible only where the observer forwards that exact name.
  if (select.upstream !== undefined && !forwardSees(scope, select.name)) return false;
  return true;
}
// The selector without its body-field and upstream predicates: what an observer that cannot read them still sees.
export const baseSelector = select => { if (select.fields === undefined && select.upstream === undefined) return select; const { fields, upstream, ...rest } = select; return rest; };
// Does this window see the selector's base effect (name, operation, source, actor) but not its declared
// body fields or upstream outcome? Such an observer cannot decide the clause either way, but a base-matching committed
// send it recorded may be the selected one: it holds the clause at missing (never a pass, never a fail),
// and a coverage gap in it is a gap for the clause.
export const blindToFields = (window, select) => (select.fields !== undefined || select.upstream !== undefined) && windowSees(window, baseSelector(select)) && !windowSees(window, select);
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
// Decisions whose verdict coverage gaps alone decided (missing or observer-failure from gapsWith, after no committed,
// undecided or unattributed send decided first). Identity option B (src/http-rests-on.mjs) admits a failed allowed-use
// control only when each non-pass positive reading is one of these; a side set, so no decision's fields change.
const decidedByGapsSet = new WeakSet();
export const decidedByGaps = decision => decidedByGapsSet.has(decision);
const byGaps = decision => { decidedByGapsSet.add(decision); return decision; };
// Does any relevant or field-blind window hold a committed send that fits the clause without its actor pin, under an
// actor other than `principal` (null, unlisted:, or another declared principal)? A field that could not be read counts as
// fitting. Direct evidence that a credential did not carry its principal (identity option B, src/http-rests-on.mjs).
export function otherActorCommit(assertion, windows, principal) {
  custodyWindows(windows, 'otherActorCommit');
  const { actor: _pinned, ...withoutActor } = assertion.select, baseOnly = baseSelector(withoutActor);
  const other = e => e.outcome === 'committed' && e.actor !== principal;
  return windows.filter(w => windowSees(w, assertion.select)).some(w => w.events.some(e => other(e) && matchState(e, { ...withoutActor, outcome: 'committed' }) !== 'no'))
    || windows.filter(w => blindToFields(w, assertion.select)).some(w => w.events.some(e => other(e) && matches(e, { ...baseOnly, outcome: 'committed' })));
}
// countBy: only the HTTP effect clauses pass it (src/http-effects.mjs); every other caller refuses a countBy clause.
// scoped (coverage v2): the HTTP path's opt-in to destination-scoped egress entries (coverageFor); every other caller reads
// window.coverage exactly as before.
// Form decimals, fail direction only: a clause is judged as before; when that reads missing and the clause pins body fields, it is
// judged once more with a form decimal that no common reading makes the pinned value read 'no' (src/body-fields.mjs decimalDiffers),
// and that judgement is kept only when it fails. So a verdict is the one before or fail, never a new pass, and it moves only from
// missing: effect.none never moves (it fails only on a match), effect.count fails when the decided count is wrong, effect.exists
// fails on absence. Every caller reads the same verdict: the HTTP clauses, claims, and the settlement, attribution and rests-on
// re-judges.
// Absent fields, fail direction only, opt-in per pin (the same pattern, tried after form decimals, alone): an omitted field may mean
// the receiver's default (a refund without an amount may be a full one) or an alias it reads instead, so an absent field stays unknown
// unless its pin declares absent: "fails", and even then everywhere a 'no' could pass (effect.none, an over-count dropping to the
// expected count, effect.only, settlement, attribution, rests-on, coverage). A clause still missing and pinning body fields is judged
// once more with every definitely absent field of a declaring pin (definitelyAbsent) read 'no', and that judgement is kept only when
// it fails and some committed send was decided that way: effect.exists fails when no send can be the expected one; effect.count fails
// when the decided matches plus every send still undecided are fewer than expected (that bound counts sends, so not for countBy), or,
// with none undecided, when the decided count or application interval is wrong (countBy included); effect.none never moves. Such a
// fail carries absenceDecided: true, so src/runner.mjs compareRuns never credits a repair over it. Every caller reads it like any fail:
// the HTTP clauses, success claims (a claimed success the records contradict), the later-outcome stage's re-judge of a positive clause
// (src/later-outcome.mjs), and the settlement, attribution and rests-on re-judges.
export function evaluateEffectAssertion(assertion, windows, { countBy = false, scoped = false } = {}) {
  custodyWindows(windows, 'evaluateEffectAssertion');
  validateEffectAssertion(assertion, 'assertion', { fields: true, countBy, upstream: true });
  const before = judgeEffect(assertion, windows, { countBy, scoped }, false);
  if (before.verdict !== 'missing' || assertion.select.fields === undefined) return before;
  const decided = judgeEffect(assertion, windows, { countBy, scoped }, true);
  const sends = windows.filter(w => windowSees(w, assertion.select)).flatMap(w => w.events);
  if (decided.verdict === 'fail') return { ...decided, basis: `${decided.basis} ${formDecimalBasis(formDecimalSends(sends, [assertion.select]))}` };
  if (assertion.kind === 'effect.none') return before;
  const absent = judgeEffect(assertion, windows, { countBy, scoped, absentFields: true }, false);
  const n = absentFieldSends(sends, assertion.select);
  return absent.verdict === 'fail' && n > 0 ? { ...absent, absenceDecided: true, basis: `${absent.basis} ${absentFieldBasis(n)}` } : before;
}
// The committed sends a definite absence decided under the selector: unknown before, 'no' with absentFields (as formDecimalSends).
function absentFieldSends(events, s) {
  const differs = (e, sel) => matchState(e, sel) === 'unknown' && matchState(e, sel, { absentFields: true }) === 'no';
  return events.filter(e => e.outcome === 'committed' && (differs(e, { ...s, outcome: 'committed' })
    || (s.actor !== undefined && (e.actor === null || e.actor.startsWith('unlisted:')) && differs(e, { ...withoutActorPin(s), outcome: 'committed' })))).length;
}
export const absentFieldBasis = n => `Decided by ${n} committed send(s) with a declared field absent from a fully captured body (the pin declares absent: "fails"; read as not the pinned value toward a fail only, and never credited as the baseline of a repair).`;
// The committed sends a form decimal decided under some of the selectors: unknown before, 'no' with formDecimals.
export function formDecimalSends(events, selectors) {
  const differs = (e, s) => matchState(e, s) === 'unknown' && matchState(e, s, { formDecimals: true }) === 'no';
  return events.filter(e => e.outcome === 'committed' && selectors.some(s => plain(s) && s.fields !== undefined && (differs(e, { ...s, outcome: 'committed' })
    || (s.actor !== undefined && (e.actor === null || e.actor.startsWith('unlisted:')) && differs(e, { ...withoutActorPin(s), outcome: 'committed' }))))).length;
}
const withoutActorPin = select => { const { actor: _actor, ...rest } = select; return rest; };
export const formDecimalBasis = n => `Decided by ${n} committed send(s) whose form-encoded decimal differs from the pinned value under every common reading (the separator as a decimal or group mark, and any rounding to the pinned precision).`;
function judgeEffect(assertion, windows, { countBy, scoped, absentFields = false }, formDecimals) {
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
  const undecided = assertion.select.fields === undefined && assertion.select.upstream === undefined ? [] : [
    ...relevant.flatMap(w => w.events).filter(e => matchState(e, { ...assertion.select, outcome: 'committed' }, { formDecimals, absentFields }) === 'unknown'
      || (selectedActor !== undefined && unknownActor(e) && matchState(e, { ...withoutActor, outcome: 'committed' }, { formDecimals, absentFields }) === 'unknown')),
    ...blind.flatMap(w => w.events).filter(e => matches(e, { ...baseWithActor, outcome: 'committed' }) || (selectedActor !== undefined && unknownActor(e) && matches(e, { ...baseOnly, outcome: 'committed' }))),
  ];
  const undecidedBasis = assertion.select.upstream === undefined ? `${undecided.length} committed send(s) whose declared body fields could not be read (no captured record, an unreadable body, an absent or unusable field, a value of another type, or an observer that does not capture those fields).`
    : `${undecided.length} committed send(s) whose upstream outcome or declared body fields could not be decided (an upstream that did not answer in full, timed out, or answered 3xx, 5xx or a status the destination does not declare as not applied; an observer that does not forward that destination; or a body field that could not be read).`;
  // Absence: only authoritative observers, and only with complete coverage. An authoritative observer blind to the
  // fields decides nothing, but a gap in its coverage could hide a send that is the selected one.
  const authoritative = relevant.filter(w => w.scope.evidence === 'authoritative');
  const blindAuthoritative = blind.filter(w => w.scope.evidence === 'authoritative');
  // A net-only snapshot window counts as complete for an exact-name update
  // selector on a table with a source-audited change column (see exactFor).
  const exactEntries = authoritative.map(w => w.coverage === 'net-only' ? exactFor(w, assertion.select, assertion.kind) : null).filter(Boolean);
  // The gaps for a clause whose verdict without gaps would be `outcome`: a scoped egress window reads complete only for a
  // selector none of its entries fits, on a window whose late entries were followed (coverageFor).
  const coverageOf = (w, outcome) => scoped ? coverageFor(w, assertion.select, { outcome, hostWide: assertion.countBy !== undefined }) : w.coverage;
  const gapsWith = outcome => [...authoritative, ...blindAuthoritative].filter(w => coverageOf(w, outcome) !== 'complete' && !(w.coverage === 'net-only' && exactFor(w, assertion.select, assertion.kind)));
  const gapVerdictOf = gaps => gaps.some(w => w.coverage === 'failed') ? 'observer-failure' : 'missing';
  // A net-only window whose exact entry for this name is violated says so: the table's rows decided nothing.
  const violatedNote = w => Array.isArray(w.exact) && w.exact.some(e => e.name === assertion.select.name && e.violated === true) ? `, ${assertion.select.name} violated` : '';
  // A window a host suspend overlapped names it first (src/suspend-clock.mjs): text only, never read by a verdict.
  const gapBasisOf = gaps => `Not every authoritative observer that can see this effect covered the window (${gaps.map(w => `${w.instanceId}: ${w.coverage}${suspendNote(w.suspend)}${w.reason ? `, ${w.reason}` : ''}${violatedNote(w)}`).join('; ')}).`;
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
    : gapsWith(passOrFail).length ? byGaps(decided(gapVerdictOf(gapsWith(passOrFail)), gapBasisOf(gapsWith(passOrFail)))) : decided(passOrFail, basis);
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
  // Absent fields (fail direction only, evaluateEffectAssertion): with every declared definite absence read 'no', fewer decided matches
  // than expected even if every send still undecided matched. Sends, not applications: a countBy clause keeps today's missing while any
  // send stays undecided (with none undecided, its application interval decides as below).
  const short = absentFields === true && assertion.countBy === undefined && undecided.length > 0 && counted + undecided.length < assertion.expected;
  if (undecided.length && !short) return decided('missing', undecidedBasis, counted);
  // The verdict this count would have without gaps: by applications for countBy, never by the number of sends.
  const keyed = assertion.countBy !== undefined && authoritative[0].scope.idempotency?.[assertion.select.name] !== undefined;
  const wouldBe = short ? 'fail' : keyed ? applicationsVerdict(countApplications(authoritative[0], assertion.select.name, countedEvents), assertion.expected) : counted === assertion.expected ? 'pass' : 'fail';
  const countGaps = gapsWith(wouldBe);
  if (countGaps.length) return byGaps(decided(gapVerdictOf(countGaps), gapBasisOf(countGaps), counted));
  if (unattributed.length) return decided('missing', unattributedBasis, counted);
  if (short) return decided('fail', `Observed ${counted} matching committed effects and ${undecided.length} committed send(s) still undecided; expected ${assertion.expected}, more than every undecided send could make.`, counted);
  // Applications (src/idempotency.mjs): only from a window that records keys for this exact name.
  if (assertion.countBy !== undefined) {
    if (authoritative[0].scope.idempotency?.[assertion.select.name] === undefined) return { ...decided('unobservable', `No key record: ${IDEMPOTENCY_BASIS['idempotency-key-unrecorded']}.`, counted), applications: null };
    const applications = countApplications(authoritative[0], assertion.select.name, countedEvents, { resolved: assertion.select.upstream === 'resolved' });
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
// Destination-scoped entries (coverage v2) must be well formed wherever they appear; they are read only through coverageFor, and
// only on an admitted window, so a field on any other window is inert.
export function validateWindow(window, where = 'window') {
  if (plain(window) && Object.hasOwn(window, 'scoped') && !validScoped(window)) fail('scoped', where);
  if (!plain(window) || !SOURCES.includes(window.source) || !COVERAGE.includes(window.coverage) || !Array.isArray(window.events) || window.events.length > EFFECT_LIMITS.eventsPerWindow) fail('window', where);
  if (!(window.reason === null || window.reason === undefined || (typeof window.reason === 'string' && REASON_PATTERN.test(window.reason)))) fail('reason', where);
  // A host suspend the window overlapped (src/suspend-clock.mjs suspendRecord), exactly as recorded; read only by the gap basis text.
  if (Object.hasOwn(window, 'suspend') && !validSuspendRecord(window.suspend)) fail('suspend', where);
  // No suspend could be checked while the window was open (the timers count sleep, no awake clock could be read): only ever true.
  if (Object.hasOwn(window, 'suspendUnchecked') && window.suspendUnchecked !== true) fail('suspend', where);
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
// scoped (coverage v2): only the HTTP connector passes it, and only egress recorders and provider feeds (feed v2) read it.
export async function collectWindow(observer, from, to, { scoped = false } = {}) {
  custodyWindows([observer], 'collectWindow');
  const base = { source: observer.source, instanceId: observer.instanceId, scope: observer.scope };
  try {
    const v2 = scoped && SCOPED_SOURCES.includes(observer.source);
    const { events, coverage, reason, exact, scoped: entries } = await (v2 ? observer.collect(from, to, { scoped: true }) : observer.collect(from, to));
    // An event still in flight at the window end leaves its outcome unknown.
    const inFlight = coverage === 'complete' && events.some(e => e.outcome === 'started' || e.outcome === 'unknown');
    const window = validateWindow({ ...base, coverage: inFlight ? 'partial' : coverage, reason: inFlight ? 'action-in-flight-at-window-end' : reason ?? null, events, ...(exact === undefined ? {} : { exact }), ...(v2 && entries !== undefined && !inFlight ? { scoped: entries } : {}) });
    // Feed v2, Part C: a feed that says its lone late entries may lift by their own template (provider-feed/4).
    if (v2 && observer.source === 'provider-feed' && observer.templateLift === true) admitTemplateLift(window);
    return v2 ? admitScoped(window) : window;
  } catch (error) {
    return { ...base, scope: observer.scope ?? { operations: [...OPERATIONS], names: null, actorAttribution: 'none', evidence: 'presence-only' }, coverage: 'failed', reason: error instanceof EffectError ? error.code : 'collect-failed', events: [] };
  }
}
