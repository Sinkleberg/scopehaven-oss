// Frozen copy of scopehaven/src/effect-outcome.mjs at 4b2e2f7 (main with IDR-0, before in-doubt resolution IDR-1; imports re-pointed: the frozen
// effect-outcome, effect-events, idempotency and only.mjs import one another, everything else the live src/). For test/in-doubt-core.test.mjs
// differentials only. Not in any identity list.
// Upstream outcome of a forwarded egress send (readiness edge E1). Pure: no I/O.
//
// By default the egress recorder answers every request itself, so a recorded send is the app's attempt.
// A destination may opt in to forwarding (src/egress-rules.mjs, integrations/observers/egress-forward.mjs):
//   forward: { upstream: "http://127.0.0.1:<port>", applied?: [2xx, ...], rejected?: [4xx, ...], proofEnv?, timeoutMs?, maxReplyBytes? }
// Each send to it is recorded exactly as before, then its recorded bytes are forwarded to the declared
// loopback upstream, and the upstream's reply goes back to the app. The send event then carries
//   upstream: { outcome, status, proven }
// status: the upstream's HTTP status for a reply read in full within timeoutMs and maxReplyBytes, otherwise null.
// proven: the reply carried a valid proof (egress-forward.mjs): an HMAC, under the secret in the destination's
// proofEnv, over the per-request nonce the recorder sent, the request the upstream received (method, path and
// query, body digest, content type) and the status it answered. The application is never given that secret (a
// proofEnv that is also a credential the profile sends is refused, forwardSecretClash), so it cannot answer for the
// upstream, or change those fields or the status in between, with a valid proof. Other headers are not bound.
// outcome is derived from status and proven alone (outcomeOf), never from anything the app wrote:
//   applied   a proven status the destination lists in `applied` (default 200, 201, 204; one of 200, 201, 203, 204 and
//             205: never 202 Accepted, nor 206, 207 or 208, whose body may report partial work), answered to a method
//             that can change state (never GET, HEAD, OPTIONS or TRACE)
//   rejected  a proven 4xx the destination lists in `rejected` (default: none), meaning "not applied"
//   unknown   everything else: no proof declared or a proof missing or wrong, no reply, a timeout, a connection
//             error, a reply over its bound or cut off, an invalid status, or any status not listed
// Allowlists only: a status decides nothing unless the destination lists it, and nothing decides without a proof.
// The body of a reply is never read, so an upstream that answers a listed 2xx with a failure in its body reads applied.
// The upstream must be the literal loopback address: a host name (localhost too), another address, https,
// a path, a query or userinfo is refused at validation, and a port that is the recorder's own, another
// declared observer's or the target origin's is refused (forwardPortClash).
//
// Judging (src/effect-events.mjs): a selector may add `upstream: "applied"`, only in the HTTP evaluator's core
// clauses and claim rules (never effect.only or a sequence). It is three-valued like `fields`: applied matches,
// rejected is no, and anything else is unknown, so a clause that needs the outcome and cannot get it reads
// missing (inconclusive), never pass. Only an observer that forwards that exact name sees the predicate
// (forwardSees); one that records the name without forwarding it is blind and holds the clause at missing.
// In-doubt resolution, gate A (IN-DOUBT-DESIGN-ADDENDUM-R1 1.3): `upstream: "resolved"` is a second predicate, accepted only on a
// clause that declares `semantics` agent-write or exactly-n; "applied" keeps reading the proven record alone, exactly as before. An
// effect.only clause opts in per selector instead (`outcomeJudged`, integrations/collateral/only.mjs) and never takes `upstream`.
// Returned ids (readiness edge E3, src/id-closure.mjs): a destination that declares proofVersion 2 has its proof cover the
// reply body too (egress-forward.mjs, scopehaven-forward-proof/2). One that also declares
//   ids: { minted: [pointer, ...], references?: [pointer, ...] }
// has the string values (8 to 200 characters) at those JSON pointers of each /2-proven reply body recorded as salted
// digests: upstream.minted for the ids the upstream creates for this request (the new object's own id), upstream.references
// for ids of other objects the upstream names in its reply (a parent charge, the object a notification is about), and
// upstream.echoed for a value at a minted pointer that the forwarded request itself carried (copied, encoded, re-cased or
// embedded): it is never a minted id, and it contests the id everywhere. Only minted ids build
// closures; a reference only ties a send to an existing one, and it is as good as the upstream's own check of it. A
// request body, a /1 reply or an unproven one is never read for ids. proofVersion 1 (the default) keeps the /1 message and
// records exactly as before.
//
// The key is not `outcome`: every clause evaluator spreads `{ ...select, outcome: 'committed' }`, which would
// silently drop an outcome requirement. It is a pairing pin (src/http-pairing.mjs), and settlement ignores it
// when asking whether a send fits an earlier check (withoutUpstream): what the upstream answered says nothing
// about which check caused the send.

import { validateCaptureDeclaration, CAPTURE_BOUNDS } from '../../../src/body-fields.mjs';

export const UPSTREAM_OUTCOMES = Object.freeze(['applied', 'rejected', 'unknown']);
// The values a selector's `upstream` may require. "resolved" (in-doubt resolution, IDR-0 gate A; IN-DOUBT-DESIGN-ADDENDUM-R1 1.3) is
// accepted only on a declared clause or claim rule whose `semantics` is agent-write or exactly-n (clauseSemanticsProblem below; the
// HTTP evaluator checks it at src/http-effects.mjs and src/http-claims.mjs). With no resolver it reads exactly as "applied".
export const UPSTREAM_PREDICATES = Object.freeze(['applied', 'resolved']);
// Check-semantics types (ADDENDUM-R1 1.2). A declared core clause may name one; a clause without it keeps main's reading.
//   forbidden-attempt  effect.none only: every committed matching attempt counts; never reads a resolution (no `upstream` pin)
//   agent-write        effect.exists (and a claim rule, src/http-claims.mjs): reads outcomes through `upstream: "resolved"`
//   exactly-n          effect.count: reads outcomes through `upstream: "resolved"`
// final-state (a state.holds clause) is designed but not built: refused. effect.only opts in per selector (outcomeJudged).
export const CLAUSE_SEMANTICS = Object.freeze({ 'effect.none': Object.freeze(['forbidden-attempt']), 'effect.exists': Object.freeze(['agent-write']), 'effect.count': Object.freeze(['exactly-n']) });
export const RESOLVING_SEMANTICS = Object.freeze(['agent-write', 'exactly-n']);
// The gate-A rule for one clause of `kind` (effect.none, effect.exists or effect.count) with `select`, declaring `semantics` or not:
// the type fits the kind, and `upstream: "resolved"` appears exactly when the type reads resolutions (forbidden-attempt pins no
// upstream outcome at all). Returns a machine code, or null.
export function clauseSemanticsProblem(kind, semantics, select) {
  const resolved = plain(select) && select.upstream === 'resolved';
  if (semantics === undefined) return resolved ? 'upstream-resolved-needs-semantics' : null;
  if (!Object.hasOwn(CLAUSE_SEMANTICS, kind) || !CLAUSE_SEMANTICS[kind].includes(semantics)) return 'semantics';
  if (RESOLVING_SEMANTICS.includes(semantics)) return resolved ? null : 'semantics-needs-upstream-resolved';
  return plain(select) && select.upstream !== undefined ? 'forbidden-attempt-upstream' : null;
}
export const FORWARD_BOUNDS = Object.freeze({ timeoutMs: Object.freeze([100, 30000]), defaultTimeoutMs: 5000, maxReplyBytes: Object.freeze([1024, 1048576]),
  defaultMaxReplyBytes: 65536, requestBytes: 1048576, statuses: 16, defaultApplied: Object.freeze([200, 201, 204]), proofSecretChars: 32 });
// A request with one of these methods applies nothing (RFC 9110 section 9.2.1), whatever the upstream answers.
export const SAFE_METHODS = Object.freeze(['GET', 'HEAD', 'OPTIONS', 'TRACE']);
const APPLIABLE = Object.freeze([200, 201, 203, 204, 205]);
const FORWARD_KEYS = ['upstream', 'applied', 'rejected', 'proofEnv', 'proofVersion', 'ids', 'timeoutMs', 'maxReplyBytes'];
// Returned ids: at most 8 pointers per destination (minted and references together) and 8 digests per list on a send; a usable
// value is a string of 8 to 200 characters.
export const RETURNED_BOUNDS = Object.freeze({ pointers: 8, values: 8, chars: Object.freeze([8, 200]) });
// echoed: values at a minted pointer that the request itself carried (never minted ids; they only contest).
export const ID_KINDS = Object.freeze(['minted', 'references', 'echoed']);
const DIGEST = /^[a-f0-9]{64}$/;
const validReturned = list => Array.isArray(list) && list.length >= 1 && list.length <= RETURNED_BOUNDS.values && list.every((d, i) => typeof d === 'string' && DIGEST.test(d) && (i === 0 || list[i - 1] < d));
const UPSTREAM = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/;
// The dedicated credential namespace (the same rule as CREDENTIAL_ENV in src/effect-events.mjs and src/contracts.mjs).
const PROOF_ENV = /^SCOPEHAVEN_TARGET_[A-Z0-9_]{1,110}$/;
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const intIn = (value, [lo, hi]) => Number.isInteger(value) && value >= lo && value <= hi;
const isStatus = value => Number.isInteger(value) && value >= 100 && value <= 599;
// A status that can be listed as applied: never 202 Accepted ("might or might not eventually be acted upon"), nor 206, 207 or 208.
const appliable = status => APPLIABLE.includes(status);
const is4xx = status => Number.isInteger(status) && status >= 400 && status <= 499;
// A 4xx that may be answered while the backend still applies the request (a timeout, too early, rate limited, client closed): never
// declarable as "not applied".
export const UNREJECTABLE = Object.freeze([408, 425, 429, 499]);
const rejectable = status => is4xx(status) && !UNREJECTABLE.includes(status);
const ascending = list => Array.isArray(list) && list.every((s, i) => i === 0 || list[i - 1] < s);
const statusList = (list, allowed) => Array.isArray(list) && list.length <= FORWARD_BOUNDS.statuses && list.every(allowed) && new Set(list).size === list.length;

// A destination's `forward` declaration, normalized: { port, applied, rejected (ascending), proofEnv, timeoutMs, maxReplyBytes }.
// ownPort: the recorder's own port, which can never be its upstream. Throws a profile-facing message.
export function validateForwardDeclaration(forward, ownPort) {
  if (!plain(forward) || Object.keys(forward).some(key => !FORWARD_KEYS.includes(key))) throw new Error(`a destination's "forward" is { ${FORWARD_KEYS.join(', ')} } (all but upstream optional)`);
  const m = typeof forward.upstream === 'string' ? UPSTREAM.exec(forward.upstream) : null;
  if (!m || !intIn(Number(m[1]), [1024, 65535])) throw new Error('"forward.upstream" must be "http://127.0.0.1:<port>" (literal loopback, plain HTTP, port 1024 to 65535, no path): a send never leaves this machine');
  const port = Number(m[1]);
  if (port === ownPort) throw new Error('"forward.upstream" cannot be the recorder\'s own port');
  const applied = forward.applied ?? FORWARD_BOUNDS.defaultApplied, rejected = forward.rejected ?? [];
  if (!statusList(applied, appliable) || !applied.length) throw new Error('"forward.applied" lists 1 to 5 distinct statuses of 200, 201, 203, 204 and 205 this destination answers only when it applied the request (never 202 Accepted)');
  if (!statusList(rejected, rejectable)) throw new Error('"forward.rejected" lists up to 16 distinct 4xx statuses this destination answers only when it did not apply the request (2xx, 3xx and 5xx are never "not applied", nor 408, 425, 429 or 499, which may be answered while the backend still applies it)');
  if (forward.proofEnv !== undefined && !(typeof forward.proofEnv === 'string' && PROOF_ENV.test(forward.proofEnv))) throw new Error('"forward.proofEnv" names the upstream\'s proof secret in the dedicated SCOPEHAVEN_TARGET_ namespace (never given to the application)');
  if (forward.timeoutMs !== undefined && !intIn(forward.timeoutMs, FORWARD_BOUNDS.timeoutMs)) throw new Error('"forward.timeoutMs" must be an integer from 100 to 30000');
  if (forward.maxReplyBytes !== undefined && !intIn(forward.maxReplyBytes, FORWARD_BOUNDS.maxReplyBytes)) throw new Error('"forward.maxReplyBytes" must be an integer from 1024 to 1048576');
  const sorted = list => Object.freeze([...list].sort((a, b) => a - b));
  const proofVersion = forward.proofVersion ?? 1;
  if (![1, 2].includes(proofVersion) || (proofVersion === 2 && forward.proofEnv === undefined)) throw new Error('"forward.proofVersion" is 1 (the default) or 2, and 2 needs "proofEnv": the /2 proof also covers the reply body');
  let ids = null;
  if (forward.ids !== undefined) {
    if (proofVersion !== 2) throw new Error('"forward.ids" needs "proofVersion": 2: ids are read only from a reply body the proof covers');
    const minted = forward.ids?.minted ?? [], references = forward.ids?.references ?? [];
    if (!plain(forward.ids) || Object.keys(forward.ids).some(key => !ID_KINDS.includes(key)) || !Array.isArray(minted) || !Array.isArray(references) || minted.length + references.length < 1
      || minted.length + references.length > RETURNED_BOUNDS.pointers || new Set([...minted, ...references]).size !== minted.length + references.length)
      throw new Error(`"forward.ids" is { minted?, references? }: JSON pointers to the id the upstream creates for the request and to ids of other objects it names, 1 to ${RETURNED_BOUNDS.pointers} in all and distinct`);
    let capture;
    try { capture = validateCaptureDeclaration({ pointers: [...minted, ...references], maxBytes: Math.min(forward.maxReplyBytes ?? FORWARD_BOUNDS.defaultMaxReplyBytes, CAPTURE_BOUNDS.maxBytes[1]) }, Infinity); }
    catch (error) { throw new Error(`"forward.ids": ${error.message}`); }
    ids = Object.freeze({ minted: Object.freeze([...minted]), references: Object.freeze([...references]), pointers: Object.freeze([...capture.pointers]), maxBytes: capture.maxBytes });
  }
  return Object.freeze({ port, applied: sorted(applied), rejected: sorted(rejected), proofEnv: forward.proofEnv ?? null, ...(proofVersion === 2 ? { proofVersion } : {}), ...(ids ? { ids } : {}), timeoutMs: forward.timeoutMs ?? FORWARD_BOUNDS.defaultTimeoutMs, maxReplyBytes: forward.maxReplyBytes ?? FORWARD_BOUNDS.defaultMaxReplyBytes });
}

// The outcome a reply's status reads, given whether its proof verified and the request's method, under the destination's
// declared lists (entry: { applied, rejected }). Without a proof nothing is decided; a safe method never reads applied.
export function outcomeOf(status, proven, entry, method) {
  if (proven !== true || !isStatus(status) || !plain(entry)) return 'unknown';
  if (Array.isArray(entry.applied) && entry.applied.includes(status) && appliable(status)) return typeof method === 'string' && !SAFE_METHODS.includes(method) ? 'applied' : 'unknown';
  return is4xx(status) && Array.isArray(entry.rejected) && entry.rejected.includes(status) ? 'rejected' : 'unknown';
}
// The event record for a settled forward ({ complete, status, proven } from egress-forward.mjs) of a request with this
// method: status only for a complete reply with a valid status, proven only with that status.
// minted, references, echoed: the salted digests of the reply's declared ids (the recorder reads them only from a /2-proven reply), or none.
export const upstreamRecord = ({ complete, status, proven, minted, references, echoed }, entry, method) => {
  const kept = complete && isStatus(status) ? status : null;
  const proof = kept !== null && proven === true;
  return { outcome: outcomeOf(kept, proof, entry, method), status: kept, proven: proof, ...(proof && validReturned(minted) ? { minted } : {}), ...(proof && validReturned(references) ? { references } : {}), ...(proof && validReturned(echoed) ? { echoed } : {}) };
};
// A sealed send's method: the first word of its resource ("POST /v1/refunds"), which the recorder writes from the request.
const methodOf = event => typeof event?.resource === 'string' ? event.resource.split(' ', 1)[0] : null;
// The record of a send that was never forwarded (over the body bound, aborted, a CONNECT tunnel).
export const UNFORWARDED = Object.freeze({ outcome: 'unknown', status: null, proven: false });

// An event's `upstream`, by shape alone: { outcome, status, proven, minted?, references?, echoed?, target? }, with an outcome its status
// and proof allow (applied only for a proven listable 2xx; rejected only for a proven 4xx; proven only with a status; the id
// lists only proven: each 1 to 8 sorted, distinct 64-hex digests).
export function validUpstreamRecord(record) {
  const keys = plain(record) ? Reflect.ownKeys(record) : [];
  if (!plain(record) || keys.length !== 3 + [...ID_KINDS, 'target'].filter(key => Object.hasOwn(record, key)).length || !['outcome', 'status', 'proven'].every(key => Object.hasOwn(record, key))) return false;
  const { outcome, status, proven } = record;
  if (!UPSTREAM_OUTCOMES.includes(outcome) || !(status === null || isStatus(status)) || typeof proven !== 'boolean' || (proven && status === null)) return false;
  // target (egress-recorder/6): { exact, query }, two booleans the recorder wrote at the forward's settle.
  if (Object.hasOwn(record, 'target') && !(plain(record.target) && Reflect.ownKeys(record.target).length === 2 && typeof record.target.exact === 'boolean' && typeof record.target.query === 'boolean')) return false;
  if (ID_KINDS.some(key => Object.hasOwn(record, key) && !(proven && validReturned(record[key])))) return false;
  if (outcome === 'applied') return proven && appliable(status);
  if (outcome === 'rejected') return proven && is4xx(status);
  return true;
}

// One forward entry as a scope or run record states it: { upstreamPort, applied, rejected, proof }, plus proofVersion: 2 and
// ids: { minted, references } only when declared (a /1 entry is exactly the four keys).
const FORWARD_ENTRY_KEYS = ['upstreamPort', 'applied', 'rejected', 'proof'];
const validIdsEntry = ids => plain(ids) && Reflect.ownKeys(ids).length === 2 && Array.isArray(ids.minted) && Array.isArray(ids.references) && ids.minted.length + ids.references.length >= 1
  && ids.minted.length + ids.references.length <= RETURNED_BOUNDS.pointers && new Set([...ids.minted, ...ids.references]).size === ids.minted.length + ids.references.length
  && (() => { try { validateCaptureDeclaration({ pointers: [...ids.minted, ...ids.references] }, Infinity); return true; } catch { return false; } })();
const validForwardEntry = entry => plain(entry) && Reflect.ownKeys(entry).length === FORWARD_ENTRY_KEYS.length + ['proofVersion', 'ids'].filter(key => Object.hasOwn(entry, key)).length
  && FORWARD_ENTRY_KEYS.every(key => Object.hasOwn(entry, key))
  && (!Object.hasOwn(entry, 'proofVersion') || (entry.proofVersion === 2 && entry.proof === true)) && (!Object.hasOwn(entry, 'ids') || (entry.proofVersion === 2 && validIdsEntry(entry.ids)))
  && intIn(entry.upstreamPort, [1024, 65535]) && typeof entry.proof === 'boolean'
  && statusList(entry.applied, appliable) && entry.applied.length >= 1 && ascending(entry.applied) && statusList(entry.rejected, rejectable) && ascending(entry.rejected);
// scope.forward: { [name]: entry }, each name one the observer reports.
export function validForwardScope(forward, names) {
  return plain(forward) && Array.isArray(names) && Object.keys(forward).length >= 1 && Object.entries(forward).every(([name, entry]) => names.includes(name) && validForwardEntry(entry));
}
// A run record's forward map: the same shape, its names its own keys.
export const validForwardRecord = forward => plain(forward) && validForwardScope(forward, Object.keys(forward));
// Does this observer scope record the upstream outcome for this exact name?
export const forwardSees = (scope, name) => typeof name === 'string' && plain(scope?.forward) && Object.hasOwn(scope.forward, name);
export const validUpstreamPredicate = value => UPSTREAM_PREDICATES.includes(value);
// Three-valued: does this event's recorded outcome meet the predicate? Rejected is the only decided "no".
// "resolved" (gate A) reads the same proven record as "applied"; nothing else is read for it here.
export function upstreamState(event, predicate) {
  const outcome = plain(event?.upstream) ? event.upstream.outcome : undefined;
  if (outcome === (predicate === 'resolved' ? 'applied' : predicate)) return 'match';
  return outcome === 'rejected' ? 'no' : 'unknown';
}
// The selector without its upstream predicate (settlement's attribution test reads only what the app sent).
export const withoutUpstream = select => { if (!plain(select) || select.upstream === undefined) return select; const { upstream, ...rest } = select; return rest; };

// The scope or record entry of a normalized forward declaration.
const entryOf = forward => ({ upstreamPort: forward.port, applied: [...forward.applied], rejected: [...forward.rejected], proof: forward.proofEnv !== null,
  ...(forward.proofVersion === 2 ? { proofVersion: 2 } : {}), ...(forward.ids ? { ids: { minted: [...forward.ids.minted], references: [...forward.ids.references] } } : {}) });
// The forward scope of a recorder's normalized destinations, or null when none forwards.
export function forwardScopeOf(destinations) {
  const forwarded = destinations.filter(d => d.forward);
  return forwarded.length ? Object.freeze(Object.fromEntries(forwarded.map(d => [d.host, Object.freeze(entryOf(d.forward))]))) : null;
}
// The run-level record of an egress-recorder observer as the profile declares it (validated): { forward: { [host]: entry } } or {}.
export function forwardRecordOf(observer) {
  const destinations = observer?.type === 'egress-recorder' && Array.isArray(observer.destinations) ? observer.destinations.filter(d => plain(d?.forward)) : [];
  return destinations.length ? { forward: Object.fromEntries(destinations.map(d => [d.host, entryOf(validateForwardDeclaration(d.forward, observer.port))])) } : {};
}
// A sealed window's events agree with its forward scope: every event of a forwarded name is a send that carries
// an outcome, a proof only where the name declares one, minted or referenced ids only where it declares ids, and the outcome its
// status and proof read under that name's declared lists; no other event carries one.
export function upstreamBound(window) {
  const forward = plain(window?.scope?.forward) ? window.scope.forward : null;
  return Array.isArray(window?.events) && window.events.every(e => {
    const forwarded = forward !== null && Object.hasOwn(forward, e.name);
    if (!forwarded) return e.upstream === undefined;
    const entry = forward[e.name];
    return e.operation === 'send' && validUpstreamRecord(e.upstream) && (!e.upstream.proven || entry.proof === true) && (ID_KINDS.every(key => e.upstream[key] === undefined) || plain(entry.ids)) && e.upstream.outcome === outcomeOf(e.upstream.status, e.upstream.proven, entry, methodOf(e));
  });
}
// A profile's forward proofEnv that is also a credential the profile names (an actor's or an observer's credentialEnv): the
// connector would send that secret to the application, or an observer would hold it. Returns a message, or null.
export function forwardSecretClash(target) {
  const named = new Map();
  for (const [alias, actor] of Object.entries(plain(target?.actors) ? target.actors : {})) for (const [key, value] of Object.entries(plain(actor) ? actor : {})) if (/Env$/.test(key) && typeof value === 'string') named.set(value, `actor "${alias}"`);
  for (const o of Array.isArray(target?.observers) ? target.observers : []) for (const [key, value] of Object.entries(plain(o) ? o : {})) if (/Env$/.test(key) && typeof value === 'string') named.set(value, `observer "${o.id}"`);
  for (const o of Array.isArray(target?.observers) ? target.observers : []) {
    if (o?.type !== 'egress-recorder' || !Array.isArray(o.destinations)) continue;
    for (const d of o.destinations) if (typeof d?.forward?.proofEnv === 'string' && named.has(d.forward.proofEnv)) return `the forward proofEnv of "${d.host}" is also the credential of ${named.get(d.forward.proofEnv)}: the application must never be given the proof secret`;
  }
  return null;
}
// A profile's forward upstream that is also the target origin's port or another declared observer's port: the
// app or a ScopeHaven sink would answer for the upstream. Returns a message, or null.
export function forwardPortClash(target) {
  const observers = Array.isArray(target?.observers) ? target.observers : [];
  const origin = typeof target?.origin === 'string' ? /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/?$/.exec(target.origin) : null;
  const taken = new Map(observers.filter(o => Number.isInteger(o?.port)).map(o => [o.port, `observer "${o.id}"`]));
  if (origin) taken.set(Number(origin[1]), 'the target origin');
  for (const o of observers) {
    if (o?.type !== 'egress-recorder' || !Array.isArray(o.destinations)) continue;
    for (const d of o.destinations) {
      const m = typeof d?.forward?.upstream === 'string' ? UPSTREAM.exec(d.forward.upstream) : null;
      if (m && taken.has(Number(m[1]))) return `the forward upstream of "${d.host}" uses the port of ${taken.get(Number(m[1]))}: the upstream must be a service of its own, not the app or a ScopeHaven sink`;
    }
  }
  return null;
}
