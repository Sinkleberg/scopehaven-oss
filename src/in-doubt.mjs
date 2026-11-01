// In-doubt resolution core (IDR-1; IN-DOUBT-DESIGN.md with ADDENDUM-R1 1.1, 1.3 to 1.5 and 2, ADDENDUM-R2 2.1 to 2.5, and the IDR-1
// conditions of IN-DOUBT-REVIEW-R2 and PR342-REVIEW). Pure: no I/O. Its two imports, src/request-feed-rules.mjs (R1) and src/read-back-rules.mjs
// (R2), import nothing that imports this module, so src/effect-outcome.mjs and src/effect-events.mjs can read it without a cycle.
//
// An attempt is one recorded send. An operation is the logical write a clause is about, over every attempt the clause selects.
// An attempt is in doubt when it is a committed http-egress send that carries an upstream record (only a forwarded name does) whose
// outcome is unknown, to a method that can change state. A proven reply decides an attempt as before (applied or rejected); nothing here
// reads past it or changes it.
//
// Resolvers, per attempt, read the attempt's own event and their own records only, never another resolver's verdict. Which resolvers
// apply to an attempt is decided here (RESOLVER_TABLE, PR342-REVIEW finding 4), never by the caller: a resolver that reads the event
// produces its record itself, and one whose records come from elsewhere takes the record supplied for it, a missing or doubled one
// reading failed by construction. Each applicable resolver yields { resolver, status: 'succeeded', result: 'confirms' | 'refutes' |
// 'silent' } or { resolver, status: 'failed', reason }.
//   r0  the forwarder's transport record, written by the egress recorder (egress-recorder/7) on the send's upstream record when its
//       forward settled: upstream.transport = { connected, mono, wall }. connected false (the TCP connect never completed: refused,
//       unreachable, a connect timeout) refutes the attempt: Node writes request bytes only after the socket connects, so no byte left
//       this machine and the upstream cannot have applied it. connected true is silent: a reset after connect, even before the body,
//       may have delivered headers. No record (a forward that never settled, a recorder before /7) is failed: record-missing.
//       mono and wall are the connection end on the recorder's monotonic clock (performance.now, ms, relative to its process) and on
//       the wall clock (ms, or null when the recorder was given none), read by R1's refutation bound (ADDENDUM-R2 section 5). From
//       egress-recorder/8 a send to a host a request feed declares also carries arrivedMono and arrivedWall: the request's arrival at the
//       recorder on the same two clocks, read by R1's binding interval.
//   r1  the request feed (IDR-4, src/request-feed-rules.mjs): a provider-signed record of the requests it received, joined to the attempt by
//       its exact idempotency key. A later resolver: its record is a sealed read the recorder makes at run end, and the result is derived
//       from that read (deriveRequestFeed), on the connector's side and the validator's alike, never trusted from storage.
//   r2  read-back of the system of record (IDR-3, src/read-back-rules.mjs): ScopeHaven's own proven reads of a declared collection, a pre-image
//       before the attempt's group was forwarded and reads after a declared settlement bound, joined to the attempt by its group (route, object,
//       binding, write credential and scope). A later resolver like R1: its record is the group's sealed read the recorder makes, and the result
//       is derived from that read (deriveReadBack) on both sides.
// Late records (IDR-2; ADDENDUM-R1 1.6, ADDENDUM-R2 m7): a later resolver's record arrives after its attempt's window was sealed. The
// connector's run-end stage binds it onto the attempt's sealed event (the overlay below; bindResolutions), decides again every row with an
// opted-in clause that reads a changed attempt, and seals the row's records; the validator binds the sealed records onto the windows it bound
// before it decides. A sealed later record is the resolver's read, never its conclusion (PR348-REVIEW minor 5): binding derives the result
// from the read with the resolver's own pure derive, and a record that carries a bare result is refused.
// Strict combination (ADDENDUM-R1 1.4): confirmed when some applicable resolver confirms, every applicable resolver succeeded and none
// refutes; refuted the same with the roles swapped; anything else in doubt. A failed record can only move an attempt to in doubt, never
// between confirmed and refuted. In doubt is the existing 'unknown', on which no clause passes.
// An operation is confirmed when some attempt applied or was confirmed, in doubt while any attempt is, refuted only when every attempt
// was refuted or proven rejected and every route was accounted for (the caller's `covered`), and none with no attempt. R0 refutes one
// attempt, never the operation.
// Groups (ADDENDUM-R2 2.2 and 2.4): P is the members proven applied by their own reply, D the members neither proven nor refuted by R0
// (an R0 refutation removes a member before any interval forms), and F = [P, P + D] the full interval. The members' own per-attempt
// decisions give [P + confirmed, P + D - refuted] (a later resolver's strict decisions; PR342-REVIEW-R2 N1), which the core always
// intersects itself, whatever group results the caller passes. A group's interval I is F, that interval and every group resolver's
// interval intersected, when every member's records and every group result succeeded and nothing disagrees; any failure, a member whose
// resolvers disagree, or an empty intersection gives F: no information. So failing any record can only widen I, never narrow it. R2 (IDR-3)
// computes its group interval inside its own derivation and reaches clauses only through per-attempt results: a singleton among members of one
// identity is assigned to them (src/read-back-rules.mjs), so no clause reads a group result and this interface stays as it was.
//
// Gate A: only `upstream: "resolved"` (src/effect-outcome.mjs upstreamState), an effect.only outcomeJudged selector, and the key collapse
// of such clauses (src/idempotency.mjs resolved fate) read a resolution.
// Gate B: a transport record exists only on a window an egress-recorder/7 or later collected (src/http-effects.mjs bindSealedWindows refuses
// one under an earlier label), and the backend-tier condition reads only windows admitted here (admitInDoubt): the connector admits the check
// windows its current recorder collected, the validator only windows whose run record carries a label in IN_DOUBT_LABELS
// (src/collector-identity.mjs). A copy of an admitted window stays admitted (carryInDoubt, called by src/effect-events.mjs withoutEvents).
// R1 applies only to the events of an admitted window whose scope declares a request feed (egress-recorder/8, REQUEST_FEED_LABELS): the
// admission marks them, so an event copy is unmarked and reads R0 alone. R2 likewise applies only to events of hosts an admitted window's scope
// declares read-back for (egress-recorder/9, READ_BACK_LABELS). A run sealed by an earlier build recomputes exactly as it was judged.

import { requestFeedApplies, deriveRequestFeed, validRequestFeedRead, requestFeedDisagreeing } from './request-feed-rules.mjs';
import { readBackApplies, deriveReadBack, validReadBackRead, readBackDisagreeing } from './read-back-rules.mjs';

const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
// Equal to SAFE_METHODS in src/effect-outcome.mjs (RFC 9110 section 9.2.1; test/in-doubt-core.test.mjs holds them equal), kept here so
// this module imports nothing.
const SAFE = Object.freeze(['GET', 'HEAD', 'OPTIONS', 'TRACE']);
const methodOf = event => typeof event?.resource === 'string' ? event.resource.split(' ', 1)[0] : null;

export const RESOLVER_RESULTS = Object.freeze(['confirms', 'refutes', 'silent']);
export const ATTEMPT_VERDICTS = Object.freeze(['confirmed', 'refuted', 'in-doubt']);
export const OPERATION_VERDICTS = Object.freeze(['confirmed', 'refuted', 'in-doubt', 'none']);
// An attempt's fate as a clause reads it: applied (a proven reply or a confirmation), refuted (a proven rejection or a refutation), in doubt.
export const FATES = Object.freeze(['applied', 'refuted', 'in-doubt']);
export const TRANSPORT_BOUNDS = Object.freeze({ mono: 1e13, wall: 8.64e15 });

// upstream.transport, by shape: exactly { connected, mono, wall }, connected a boolean, mono a non-negative finite number of
// milliseconds, wall a non-negative integer of milliseconds or null; or (egress-recorder/8, a send to a request-feed host) those and
// arrivedMono (at most mono) and arrivedWall alike. Which sends may carry the arrival is bound by src/http-effects.mjs bindSealedWindows.
// A record of a connect that never completed carries no reply.
const monoValid = v => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= TRANSPORT_BOUNDS.mono;
const wallValid = v => v === null || (Number.isSafeInteger(v) && v >= 0 && v <= TRANSPORT_BOUNDS.wall);
export function validTransport(t, upstream) {
  if (!plain(t) || typeof t.connected !== 'boolean') return false;
  const keys = Reflect.ownKeys(t), arrival = Object.hasOwn(t, 'arrivedMono') || Object.hasOwn(t, 'arrivedWall');
  if (keys.length !== (arrival ? 5 : 3)) return false;
  if (!monoValid(t.mono) || !wallValid(t.wall)) return false;
  if (arrival && !(monoValid(t.arrivedMono) && t.arrivedMono <= t.mono && wallValid(t.arrivedWall))) return false;
  return t.connected || !plain(upstream) || (upstream.outcome === 'unknown' && upstream.status === null && upstream.proven === false);
}
export const transportArrival = t => plain(t) && Object.hasOwn(t, 'arrivedMono');
// The transport record the recorder writes at a forward's settle: connected only when the forwarder saw the TCP connect complete. arrived:
// { mono, wall } at the request's arrival, given only for a send to a request-feed host (egress-recorder/8).
const round = mono => Math.round(mono * 1000) / 1000;
export const transportRecord = ({ connected }, mono, wall, arrived = null) => ({ connected: connected !== false, mono: round(mono), wall: Number.isSafeInteger(wall) ? wall : null,
  ...(plain(arrived) ? { arrivedMono: Math.min(round(arrived.mono), round(mono)), arrivedWall: Number.isSafeInteger(arrived.wall) ? arrived.wall : null } : {}) });

export const inDoubtAttempt = e => plain(e) && e.source === 'http-egress' && e.operation === 'send' && e.outcome === 'committed' && plain(e.upstream)
  && e.upstream.outcome === 'unknown' && typeof methodOf(e) === 'string' && !SAFE.includes(methodOf(e));

// R0's record for an in-doubt attempt, from its own event only.
export function r0Record(e) {
  const t = e?.upstream?.transport;
  if (t === undefined) return { resolver: 'r0', status: 'failed', reason: 'record-missing' };
  if (!validTransport(t, e.upstream)) return { resolver: 'r0', status: 'failed', reason: 'record-invalid' };
  return { resolver: 'r0', status: 'succeeded', result: t.connected ? 'silent' : 'refutes' };
}
// The events of admitted windows whose scope declares a request feed, each with that declaration (admitInDoubt below). R1 applies only to
// a marked event; a copy of an event is unmarked.
const requestFeedOf = new WeakMap();
// The events of admitted windows whose scope declares read-back for their host, each with the window's read-back record (R2).
const readBackOf = new WeakMap();
// Later resolvers join the table here, each { applies(event), readValid(read), derive({ window, reads }) } with no read of the event: its
// record for an attempt arrives after the attempt's window was sealed, and only through the run-end stage's binding (bindResolutions below).
// A later resolver applies only to an attempt that connected (upstream.transport.connected true): an attempt that never connected has only
// R0 (ADDENDUM-R1 1.4). Its sealed record is { resolver, read } (readValid holds) or { resolver, status: 'failed', reason }; derive turns
// the reads of one window's attempts into { resolver, status, result | reason } per attempt (PR348-REVIEW minor 5: a later resolver must
// bring a pure derivation; one without derive and readValid is never a later resolver, so its records never bind).
//   r1  the request feed (src/request-feed-rules.mjs): applies to an in-doubt attempt of a request-feed window that connected, carries a
//       keyed record, goes to a feed host, is exact and query-free and names a declared route; derive is deriveRequestFeed.
//   r2  read-back (src/read-back-rules.mjs): applies to an in-doubt attempt of a read-back window that connected and that its recorder bound to a
//       declared read-back route; derive is deriveReadBack.
// disagreeing(items): optional; the observers whose supplied reads cannot all be one read of theirs (every such record is failed).
const R1 = Object.freeze({ applies: e => inDoubtAttempt(e) && requestFeedApplies(e, requestFeedOf.get(e)), readValid: validRequestFeedRead,
  derive: ({ window, reads }) => deriveRequestFeed({ window, reads, inDoubt: inDoubtAttempt, applies: e => R1.applies(e) }), disagreeing: requestFeedDisagreeing });
const R2 = Object.freeze({ applies: e => inDoubtAttempt(e) && readBackApplies(e, readBackOf.get(e)), readValid: validReadBackRead,
  derive: ({ window, reads }) => deriveReadBack({ window, reads, inDoubt: inDoubtAttempt, applies: e => R2.applies(e) }), disagreeing: readBackDisagreeing });
const LATER_RESOLVERS = Object.freeze({ r1: R1, r2: R2 });
// Resolver applicability: name -> { applies(event), read?(event) } or a later resolver. R0 applies to every in-doubt attempt and reads its own event.
export const RESOLVER_TABLE = Object.freeze({ r0: Object.freeze({ applies: inDoubtAttempt, read: r0Record }), ...LATER_RESOLVERS });
export const RESOLVERS = Object.freeze(Object.keys(RESOLVER_TABLE));
// The resolvers whose records the run-end stage binds (those that do not read the event and bring a read check and a derivation), in table order.
export const LATER_RESOLVER_NAMES = Object.freeze(RESOLVERS.filter(name => typeof RESOLVER_TABLE[name].read !== 'function' && typeof RESOLVER_TABLE[name].derive === 'function' && typeof RESOLVER_TABLE[name].readValid === 'function'));
const validRecord = r => plain(r) && typeof r.resolver === 'string' && (r.status === 'succeeded' ? RESOLVER_RESULTS.includes(r.result) : r.status === 'failed');
// A failed record, as sealed and as read: exactly { resolver, status: 'failed', reason }, a reason a short label.
export const RECORD_REASON = /^[a-z][a-z0-9-]{0,47}$/;
const failedRecord = r => plain(r) && Reflect.ownKeys(r).length === 3 && typeof r.resolver === 'string' && r.status === 'failed' && typeof r.reason === 'string' && RECORD_REASON.test(r.reason);
// A later record as it is sealed: exactly { resolver, read } with a read its resolver accepts, or a failed record. Never a bare result.
const readRecord = r => plain(r) && Reflect.ownKeys(r).length === 2 && typeof r.resolver === 'string' && Object.hasOwn(r, 'read') && LATER_RESOLVER_NAMES.includes(r.resolver)
  && RESOLVER_TABLE[r.resolver].readValid(r.read) === true;
const sealedRecord = r => readRecord(r) || failedRecord(r);

// The event overlay (IN-DOUBT-DESIGN 1.4; ADDENDUM-R1 1.6): a module-private WeakMap from a sealed event to the later resolvers' records the
// run-end stage bound for it: { sealed, effective }, the records as sealed (reads) and as derived (results). Sealed events are never edited.
// A copy of an event has no entry, so its later resolvers read record-missing (failed: in doubt). A window copy that keeps its event objects
// (src/effect-events.mjs withoutEvents, markUnfollowed, which adds the window to a WeakSet and copies nothing, ADDENDUM-R2 m7) keeps the
// overlay. The default records of every reading below (fateOf, attemptResolution, groupMember, attemptBasis, resolvedState) are the event's
// bound, derived ones.
const overlay = new WeakMap();
const NONE = Object.freeze([]);
export const boundRecords = e => overlay.get(e)?.effective ?? NONE;
// The records bound on an event as they are sealed (a later resolver's read, or a failed record).
export const sealedRecordsOf = e => overlay.get(e)?.sealed ?? NONE;
// Does this event carry a later resolver's record (bound by the run-end stage, or by the validator from the sealed row)?
export const lateBound = e => (overlay.get(e)?.sealed.length ?? 0) > 0;
// The applicable resolvers of an attempt, in table order.
export const applicableResolvers = (e, table = RESOLVER_TABLE) => Object.keys(table).filter(name => table[name].applies(e) === true);
// Each applicable resolver's record: its own reading of the event, or the one record supplied for it (none or two read failed). A record
// supplied for a resolver that reads the event, or for one that does not apply, is ignored.
export function attemptRecords(e, supplied = [], table = RESOLVER_TABLE) {
  const list = Array.isArray(supplied) ? supplied : [];
  return applicableResolvers(e, table).map(name => {
    if (typeof table[name].read === 'function') return table[name].read(e);
    const found = list.filter(r => plain(r) && r.resolver === name);
    if (found.length !== 1) return { resolver: name, status: 'failed', reason: found.length ? 'record-duplicate' : 'record-missing' };
    return validRecord(found[0]) ? found[0] : { resolver: name, status: 'failed', reason: 'record-invalid' };
  });
}
// Strict combination over one attempt's applicable records. No record, or anything malformed, is in doubt.
export function combine(records) {
  if (!Array.isArray(records) || !records.length || !records.every(validRecord) || records.some(r => r.status !== 'succeeded')) return 'in-doubt';
  const confirms = records.some(r => r.result === 'confirms'), refutes = records.some(r => r.result === 'refutes');
  return confirms && !refutes ? 'confirmed' : refutes && !confirms ? 'refuted' : 'in-doubt';
}
// Every applicable record of an attempt succeeded (the strict combination ran on complete evidence).
export const strictlyDecided = records => Array.isArray(records) && records.length > 0 && records.every(r => validRecord(r) && r.status === 'succeeded');
// One in-doubt attempt: its applicable resolvers and their records, its verdict, whether every record succeeded, and whether they disagree.
export function attemptResolution(e, supplied = boundRecords(e), table = RESOLVER_TABLE) {
  const records = attemptRecords(e, supplied, table), strict = strictlyDecided(records);
  const conflict = strict && records.some(r => r.result === 'confirms') && records.some(r => r.result === 'refutes');
  return { verdict: combine(records), strict, conflict, records, resolvers: records.map(r => r.resolver) };
}
// The fate a resolved clause reads for any send: a proven reply decides; an in-doubt attempt reads its strict combination; any other
// send with no decided outcome (a safe method, no upstream record) is in doubt.
export function fateOf(e, supplied = boundRecords(e), table = RESOLVER_TABLE) {
  const outcome = plain(e?.upstream) ? e.upstream.outcome : undefined;
  if (outcome === 'applied') return 'applied';
  if (outcome === 'rejected') return 'refuted';
  if (!inDoubtAttempt(e)) return 'in-doubt';
  const { verdict } = attemptResolution(e, supplied, table);
  return verdict === 'confirmed' ? 'applied' : verdict === 'refuted' ? 'refuted' : 'in-doubt';
}
// Three-valued, for src/effect-outcome.mjs upstreamState(event, "resolved"): applied matches, refuted is "no", in doubt is unknown.
export const resolvedState = e => { const fate = fateOf(e); return fate === 'applied' ? 'match' : fate === 'refuted' ? 'no' : 'unknown'; };
// What decided an attempt's fate, for the sealed operation record: the proven reply, a resolver (R0), or nothing (in doubt, with the first
// failed record's reason, or the reason no resolver decided), and the resolvers that applied to it.
export function attemptBasis(e) {
  const outcome = plain(e?.upstream) ? e.upstream.outcome : undefined;
  if (outcome === 'applied' || outcome === 'rejected') return { by: 'proof', resolvers: [] };
  if (!inDoubtAttempt(e)) return { by: 'none', reason: 'not-in-doubt', resolvers: [] };
  const { verdict, records, resolvers } = attemptResolution(e);
  if (verdict !== 'in-doubt') return { by: records.find(r => r.result === (verdict === 'refuted' ? 'refutes' : 'confirms')).resolver, resolvers };
  const failed = records.find(r => r.status === 'failed');
  return { by: 'none', reason: failed ? failed.reason : records.some(r => r.result !== 'silent') ? 'resolvers-disagree' : 'r0-connected', resolvers };
}

// The operation over a clause's selected attempts (their fates). covered: every route to the system of record was accounted for.
export function operationOf(fates, { covered = false } = {}) {
  const list = Array.isArray(fates) ? fates : [];
  const applied = list.filter(f => f === 'applied').length, refuted = list.filter(f => f === 'refuted').length, inDoubt = list.length - applied - refuted;
  const operation = applied ? 'confirmed' : inDoubt ? 'in-doubt' : !list.length ? 'none' : covered === true ? 'refuted' : 'in-doubt';
  return { operation, applied, refuted, inDoubt };
}
// One group member, from its own event and the records supplied for it: proven ('applied', 'rejected' or null, from its reply alone),
// whether R0 refuted it under the strict combination (it then leaves D), its strict decision by any other resolver ('confirmed', 'refuted'
// or null), whether every applicable record succeeded, and whether its resolvers disagree. A send that is neither proven nor an in-doubt
// attempt has no applicable resolver and stays in D undecided.
export function groupMember(e, supplied = boundRecords(e), table = RESOLVER_TABLE) {
  const outcome = plain(e?.upstream) ? e.upstream.outcome : undefined;
  if (outcome === 'applied' || outcome === 'rejected') return { proven: outcome, r0Refuted: false, decided: null, strict: true, conflict: false };
  if (!inDoubtAttempt(e)) return { proven: null, r0Refuted: false, decided: null, strict: true, conflict: false };
  const { verdict, strict, conflict, records } = attemptResolution(e, supplied, table);
  const r0Refuted = strict && verdict === 'refuted' && records.some(r => r.resolver === 'r0' && r.result === 'refutes');
  return { proven: null, r0Refuted, decided: strict && !r0Refuted && (verdict === 'confirmed' || verdict === 'refuted') ? verdict : null, strict, conflict };
}
const validMember = m => plain(m) && ['applied', 'rejected', null].includes(m.proven) && typeof m.r0Refuted === 'boolean' && [null, 'confirmed', 'refuted'].includes(m.decided)
  && typeof m.strict === 'boolean' && typeof m.conflict === 'boolean' && (m.decided === null || (m.proven === null && !m.r0Refuted));
const validResult = r => plain(r) && typeof r.resolver === 'string' && r.status === 'succeeded' && Number.isSafeInteger(r.low) && Number.isSafeInteger(r.high) && r.low >= 0 && r.low <= r.high;
// A group's interval (ADDENDUM-R2 2.4). members: groupMember(...) entries. results: the group resolvers' results, { resolver, status:
// 'succeeded', low, high } or { resolver, status: 'failed', reason } (none until IDR-3). Returns { admitted, low, high, conflict }:
// admitted when I came from a full and consistent set (it may still equal F); otherwise F, with conflict set when resolvers disagreed
// (a member's, or an empty intersection), so a caller makes every member in doubt.
export function admitGroupCount(members, results = []) {
  const list = Array.isArray(members) ? members : [];
  const P = list.filter(m => m?.proven === 'applied').length;
  const D = list.filter(m => plain(m) && m.proven === null && m.r0Refuted !== true).length;
  const full = conflict => ({ admitted: false, low: P, high: P + D, conflict });
  if (!list.length || !list.every(validMember)) return full(false);
  if (list.some(m => m.conflict)) return full(true);
  if (list.some(m => !m.strict) || !Array.isArray(results) || !results.every(validResult)) return full(false);
  // The members' own decisions, always (N1): confirmed members are applications, refuted ones are not.
  const confirmed = list.filter(m => m.decided === 'confirmed').length, refuted = list.filter(m => m.decided === 'refuted').length;
  const low = Math.max(P + confirmed, ...results.map(r => r.low)), high = Math.min(P + D - refuted, ...results.map(r => r.high));
  return low > high ? full(true) : { admitted: true, low, high, conflict: false };
}

// Gate B for the backend tier: windows whose collector is egress-recorder/7 or later. An admitted window whose scope declares a request feed
// (egress-recorder/8; the validator binds the scope to the run record first) marks its events for R1, and one whose scope declares read-back
// (egress-recorder/9) marks the events of its read-back hosts for R2.
const gateB = new WeakSet();
export const admitInDoubt = window => {
  if (!plain(window) || window.source !== 'http-egress') return window;
  gateB.add(window);
  if (plain(window.scope?.requestFeed) && Array.isArray(window.events)) for (const e of window.events) if (plain(e)) requestFeedOf.set(e, window.scope.requestFeed);
  const rb = window.scope?.readBack;
  if (plain(rb) && plain(rb.hosts) && Array.isArray(window.events)) for (const e of window.events) if (plain(e) && Object.hasOwn(rb.hosts, e.name)) readBackOf.set(e, rb);
  return window;
};
export const inDoubtAdmitted = window => gateB.has(window);
// A copy of a window (src/effect-events.mjs withoutEvents) reads as its original does: an admitted window's copy stays admitted.
export const carryInDoubt = (from, to) => { if (gateB.has(from) && plain(to)) gateB.add(to); return to; };

// Late records (IDR-2; ADDENDUM-R1 1.6). An entry names one attempt and carries its later resolvers' records:
// { observer: <window instance id>, seq, records: [record, ...] }, the records sealed records of distinct later resolvers that apply to that
// attempt, in table order. Records only, as counts, flags, times and labels: no body, id, key or address (#312).
const ENTRY_KEYS = 3;
const laterOf = e => applicableResolvers(e).filter(name => LATER_RESOLVER_NAMES.includes(name));
const deepFreeze = value => { if (value !== null && typeof value === 'object') { for (const v of Object.values(value)) deepFreeze(v); Object.freeze(value); } return value; };
// The run-end stage's entries for one row's windows, from what its observers' resolver reads returned (supplied: { observer, seq, records }
// items, anything else ignored): for each in-doubt attempt in an admitted (gate-B) window, the record supplied for each later resolver that
// applies to it: a read the resolver accepts as { resolver, read }, a failed one with a label as failed, anything else (a bare result
// included) as failed (record-invalid), two as failed (record-duplicate); a record for a resolver that does not apply, or for any other
// send, is dropped. An attempt with no record gets no entry: its later resolvers stay record-missing (failed), as at seal time. In window
// and event order, the order sealedResolutions reads them back in.
export function lateEntriesFor(windows, supplied) {
  const list = Array.isArray(supplied) ? supplied.filter(x => plain(x) && typeof x.observer === 'string' && Array.isArray(x.records)) : [];
  const failed = (resolver, reason) => ({ resolver, status: 'failed', reason });
  // A later resolver's reads that cannot all be one observer's (src/request-feed-rules.mjs requestFeedDisagreeing) read failed, whole.
  const disagreeing = new Map(LATER_RESOLVER_NAMES.map(name => { try { return [name, RESOLVER_TABLE[name].disagreeing?.(list) ?? new Set()]; } catch { return [name, new Set(list.map(x => x.observer))]; } }));
  const asSealed = r => (Object.hasOwn(r, 'read') && !Object.hasOwn(r, 'status') && RESOLVER_TABLE[r.resolver].readValid(r.read) === true ? { resolver: r.resolver, read: structuredClone(r.read) }
    : r.status === 'failed' && !Object.hasOwn(r, 'read') ? failed(r.resolver, typeof r.reason === 'string' && RECORD_REASON.test(r.reason) ? r.reason : 'record-invalid') : failed(r.resolver, 'record-invalid'));
  const out = [];
  for (const w of Array.isArray(windows) ? windows : []) {
    if (!inDoubtAdmitted(w) || !Array.isArray(w.events)) continue;
    for (const e of w.events) {
      if (!inDoubtAttempt(e)) continue;
      const mine = list.filter(x => x.observer === w.instanceId && x.seq === e.seq).flatMap(x => x.records);
      const records = laterOf(e).flatMap(name => {
        const found = mine.filter(r => plain(r) && r.resolver === name);
        if (!found.length) return [];
        if (found.length > 1) return [failed(name, 'record-duplicate')];
        if (disagreeing.get(name).has(w.instanceId)) return [failed(name, 'record-inconsistent')];
        try { return [asSealed(found[0])]; } catch { return [failed(name, 'record-invalid')]; }
      });
      if (records.length) out.push({ observer: w.instanceId, seq: e.seq, records });
    }
  }
  return out;
}
// Bind one row's entries onto the attempts of its windows (the connector's run-end stage, and the validator from the sealed row). Every event of
// every window is first unbound, so the overlay is exactly these entries whatever was bound before. Each entry must name exactly one in-doubt
// attempt in an admitted window, carry at least one record, and every record must be a sealed record (a read its resolver accepts, or a
// failed record) of a later resolver that applies to that attempt, distinct and in table order; anything else, a bare result included,
// throws resolution-record, with nothing left bound. Then each later resolver derives, per window, the results of the reads bound on that
// window's attempts (its derive sees the whole window, so a group's members are read together); a read it gives no valid result for reads
// failed (record-underived), and a derive that throws refuses the binding.
export function bindResolutions(windows, entries = []) {
  const list = Array.isArray(windows) ? windows.filter(plain) : [];
  for (const w of list) for (const e of Array.isArray(w.events) ? w.events : []) if (plain(e)) overlay.delete(e);
  const refuse = () => { throw new Error('resolution-record'); };
  if (!Array.isArray(entries)) refuse();
  const seen = new Set(), plan = new Map();
  for (const entry of entries) {
    if (!plain(entry) || Reflect.ownKeys(entry).length !== ENTRY_KEYS || typeof entry.observer !== 'string' || !Number.isSafeInteger(entry.seq) || entry.seq < 1 || !Array.isArray(entry.records) || !entry.records.length) refuse();
    const key = `${entry.observer}\n${entry.seq}`;
    if (seen.has(key)) refuse();
    seen.add(key);
    const hits = list.filter(w => inDoubtAdmitted(w) && w.instanceId === entry.observer && Array.isArray(w.events)).flatMap(w => w.events.filter(e => plain(e) && e.seq === entry.seq).map(e => [w, e]));
    if (hits.length !== 1 || !inDoubtAttempt(hits[0][1])) refuse();
    const [w, e] = hits[0], later = laterOf(e);
    let at = -1;
    for (const r of entry.records) { const i = sealedRecord(r) ? later.indexOf(r.resolver) : -1; if (i <= at) refuse(); at = i; }
    plan.set(e, { window: w, sealed: Object.freeze(entry.records.map(r => deepFreeze(structuredClone(r)))) });
  }
  // Derive each later resolver's results, one window at a time.
  const effective = new Map([...plan.keys()].map(e => [e, []]));
  for (const name of LATER_RESOLVER_NAMES) for (const w of list) {
    const reads = new Map([...plan].filter(([, p]) => p.window === w).flatMap(([e, p]) => p.sealed.filter(r => r.resolver === name && Object.hasOwn(r, 'read')).map(r => [e, r.read])));
    let derived = new Map();
    if (reads.size) { try { derived = RESOLVER_TABLE[name].derive({ window: w, reads }); } catch { refuse(); } }
    for (const [e, p] of plan) if (p.window === w) for (const r of p.sealed) if (r.resolver === name) {
      const d = Object.hasOwn(r, 'read') ? derived.get(e) : r;
      effective.get(e).push(Object.freeze(validRecord(d) && d.resolver === name ? { ...d } : { resolver: name, status: 'failed', reason: 'record-underived' }));
    }
  }
  for (const [e, p] of plan) overlay.set(e, { sealed: p.sealed, effective: Object.freeze(effective.get(e)) });
  return windows;
}
// The entries bound on these windows' attempts, as the row seals them (trace data.resolutions): admitted windows in order, events in order.
export const sealedResolutions = windows => (Array.isArray(windows) ? windows : []).filter(w => inDoubtAdmitted(w) && Array.isArray(w.events))
  .flatMap(w => w.events.filter(lateBound).map(e => ({ observer: w.instanceId, seq: e.seq, records: overlay.get(e).sealed.map(r => structuredClone(r)) })));
