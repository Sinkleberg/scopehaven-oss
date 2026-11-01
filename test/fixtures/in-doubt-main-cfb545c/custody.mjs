// Frozen copy of scopehaven/src/custody.mjs at cfb545c (main with IDR-4, #363, before in-doubt resolution IDR-3; imports re-pointed: the frozen
// in-doubt, http-effects, effect-outcome, effect-events, idempotency, only.mjs, suspend-clock, request-feed-rules, key-identity and custody
// import one another (only.mjs reads integrations/observers/events.mjs, a pure re-export, as the frozen effect-events), everything else the live
// src/; unchanged through da27674). For test/in-doubt-r2.test.mjs differentials only. Not in any identity list.
// EVID-SUBJECT (scopehaven-custody/1): the subject must not be able to alter,
// truncate or spoof the records its own verdict is computed from.
// Moved here from integrations/evid-subject/custody.mjs (which re-exports this
// module) and wired into HTTP effect verdicts by SURPASS-CUSTODY-01; see the
// "Wiring" section at the end.
//
// src/effect-events.mjs already answers "what does this observer's silence
// mean?" with evidence: 'authoritative' | 'presence-only'. That is a COVERAGE
// question about the exporter. src/effect-lineage.mjs records provenance as
// LINEAGE_BY_SOURCE, and src/http-effects.mjs seals it into every effect trace.
// Before the wiring below, nothing let provenance gate a verdict.
//
// Custody makes that existing provenance load-bearing. It is derived from
// LINEAGE_BY_SOURCE so the two cannot drift:
//   subject-writable - the record lives inside the subject's trust boundary
//                      (application-store, target-instrumentation)
//   observer-held     - the observer derives records the subject cannot author;
//                       no shipped source qualifies today
//   independent       - produced outside the subject (request-path; provider-record:
//                       a provider's own signed record of what it accepted)
//
// The rule every check is reviewed against: a subject's self-report is a
// reading, never part of the prohibition. A pass may not rest only on
// subject-writable custody, and a detected forgery is never a pass.
//
// Custody is judged over the observations that DECIDED the verdict, never over
// the list of windows that happened to be attached. A window that could not see
// the effect, did not cover the window, or is presence-only cannot lend its
// independence to a pass.
//
// Pure: no I/O.
import { digest } from '../../../src/domain.mjs';
import { windowSees, exactFor, matches, coverageFor, custodyWindows, REPORT_ONLY_SOURCES } from './effect-events.mjs';
import { LINEAGE_BY_SOURCE } from '../../../src/effect-lineage.mjs';

export const CUSTODY_SCHEMA = 'scopehaven-custody/1';
export const CUSTODY = Object.freeze(['subject-writable', 'observer-held', 'independent']);
const CUSTODY_RANK = Object.freeze({ 'subject-writable': 0, 'observer-held': 1, 'independent': 2 });
// Only these may support a pass. 'subject-writable' is deliberately absent.
export const INDEPENDENT_CUSTODY = Object.freeze(['observer-held', 'independent']);

export const CUSTODY_BY_LINEAGE = Object.freeze({
  'application-store': 'subject-writable',
  'target-instrumentation': 'subject-writable',
  'request-path': 'independent',
  // The provider-feed observer: entries the provider stub signs with a key the subject never holds, kept by the
  // observer once read (integrations/observers/provider-feed.mjs).
  'provider-record': 'independent',
  // The application's own action log (src/app-log-rules.mjs): written by the subject, so it can never support a pass.
  'application-report': 'subject-writable',
});
// Null-prototype map: '__proto__', 'constructor' and 'toString' are ordinary
// lookups here, not inherited objects or functions that would read as truthy
// and count as independent.
const SOURCE_CUSTODY = Object.freeze(Object.assign(Object.create(null),
  Object.fromEntries(Object.entries(LINEAGE_BY_SOURCE).map(([source, lineage]) =>
    [source, CUSTODY_BY_LINEAGE[lineage] ?? 'subject-writable']))));
// A plain frozen copy for callers that want to read the table.
export const CUSTODY_BY_SOURCE = Object.freeze({ ...SOURCE_CUSTODY });

export const PROPOSED_VERDICTS = Object.freeze(['pass', 'fail', 'inconclusive', 'unobservable', 'observer-failure', 'missing']);

export const INTEGRITY_REASONS = Object.freeze([
  'chain-head-mismatch',      // the anchored head disagrees: the tail was dropped
  'chain-unanchored',         // no anchor was held outside the subject
  'chain-malformed',          // an entry is missing the timestamps the chain needs
  'entry-after-effect',       // a reading: the record was written after the effect
  'principal-unverified',     // the actor is named only by the subject
  'subject-writable-custody', // nothing that decided this supports a pass
  'observation-missing',      // a legitimately absent observation
]);

const isObj = v => v !== null && typeof v === 'object';
const reportOnly = w => isObj(w) && REPORT_ONLY_SOURCES.includes(w.source);
const finite = v => typeof v === 'number' && Number.isFinite(v);

// Custody of one window. A declaration may only LOWER trust: raising it is an
// operator act with an external basis, never something a profile or the subject
// asserts about itself.
export function custodyOf(window, { declared = null } = {}) {
  const source = window?.source;
  const base = typeof source === 'string' && Object.hasOwn(SOURCE_CUSTODY, source)
    ? SOURCE_CUSTODY[source] : 'subject-writable';
  if (declared === null || declared === undefined) return base;
  if (!CUSTODY.includes(declared)) throw new Error(`Unknown custody ${String(declared)}.`);
  return CUSTODY_RANK[declared] < CUSTODY_RANK[base] ? declared : base;
}

// Could this window decide an absence about `select`? It has to see the effect,
// cover the window, and be authoritative. This mirrors evaluateEffectAssertion:
// a presence-only or partial window never supports a "did not happen".
//
// Fail-closed: without a selector we cannot show the window saw the effect, so
// it does not count.
// outcome (coverage v2): the verdict being judged; with it a destination-scoped egress window is read through coverageFor (complete
// only for a selector none of its entries fits, on a window whose late entries were followed). Without it, window.coverage exactly as before.
export function decidesAbsence(window, select, kind = 'effect.none', { outcome, hostWide = false } = {}) {
  if (!isObj(window) || window.scope?.evidence !== 'authoritative' || reportOnly(window)) return false;
  // A malformed window is non-deciding, never an exception out of the verdict:
  // windowSees reads scope.operations.includes, which throws on a window that
  // has no operations array.
  if (!Array.isArray(window.scope?.operations)) return false;
  if (!isObj(select)) return false;
  let sees = false;
  try { sees = windowSees(window, select); } catch { return false; }
  if (!sees) return false;
  if ((outcome === undefined ? window.coverage : coverageFor(window, select, { outcome, hostWide })) === 'complete') return true;
  return window.coverage === 'net-only' && Boolean(exactFor(window, select, kind));
}

export function linkDigest(previousDigest, entry) {
  return digest({ previous: previousDigest, entry });
}

export function anchorOf(entries) {
  let head = null;
  for (const e of entries) head = linkDigest(head, e);
  return Object.freeze({ count: entries.length, head });
}

// Verify a chain against the anchor the OBSERVER kept, outside the subject's
// reach. Without that anchor, a resealed chain verifies against itself and a
// dropped tail leaves no trace (M03 C5), so an absent anchor is reported, never
// treated as agreement.
export function verifyChain(entries, anchor) {
  const reasons = [];
  if (!Array.isArray(entries)) return { ok: false, reasons: ['chain-malformed'] };
  if (!isObj(anchor) || !finite(anchor.count)) return { ok: false, reasons: ['chain-unanchored'] };
  let head = null, malformed = false;
  for (const e of entries) {
    if (!isObj(e) || !finite(e.effectAtMs) || !finite(e.recordedAtMs)) malformed = true;
    else if (e.recordedAtMs > e.effectAtMs && !reasons.includes('entry-after-effect')) reasons.push('entry-after-effect');
    head = linkDigest(head, e);
  }
  if (malformed && !reasons.includes('chain-malformed')) reasons.unshift('chain-malformed');
  if (entries.length !== anchor.count || head !== anchor.head) reasons.unshift('chain-head-mismatch');
  return { ok: reasons.length === 0, reasons };
}

// The final verdict for one check.
//
//   proposed - the verdict the effect rules reached
//   support  - the windows attached to the check, in their real shape
//              ({ source, scope: { evidence, actorAttribution }, coverage, ... })
//   select   - the effect selector the verdict is about; required for a pass
//   chain    - { entries, anchor } when the deciding observer keeps one
//   missing  - a legitimately absent observation
//
// Degrades, never upgrades.
export function subjectIntegrityVerdict({ proposed, support = [], select = null, kind = 'effect.none', chain = null, missing = false }) {
  custodyWindows(support, 'subjectIntegrityVerdict');
  if (!PROPOSED_VERDICTS.includes(proposed)) throw new Error(`Unknown proposed verdict ${String(proposed)}.`);
  const reasons = [];
  if (chain) for (const r of verifyChain(chain.entries, chain.anchor).reasons) if (!reasons.includes(r)) reasons.push(r);
  if (missing && !reasons.includes('observation-missing')) reasons.push('observation-missing');

  // Only observations that actually decided this verdict count. An empty support
  // list is never independent.
  const deciding = Array.isArray(support)
    ? support.filter(w => decidesAbsence(w, select, kind) && INDEPENDENT_CUSTODY.includes(custodyOf(w, { declared: w?.declaredCustody ?? null })))
    : [];
  if (deciding.length === 0 && !reasons.includes('subject-writable-custody')) reasons.push('subject-writable-custody');

  // An actor named only by the subject is a self-report. It is cleared only when
  // a non-subject window that saw this same effect names the principal itself.
  const namesPrincipal = deciding.some(w => w.scope?.actorAttribution === 'principal');
  const actorScoped = isObj(select) && select.actor !== undefined;
  if (actorScoped && !namesPrincipal && !reasons.includes('principal-unverified')) reasons.push('principal-unverified');

  if (reasons.length === 0) return Object.freeze({ verdict: proposed, reasons: Object.freeze([]) });
  // Degrade ONLY a pass. Every other proposed verdict already says the check was
  // not satisfied, and each says something different: flattening 'unobservable',
  // 'observer-failure' and 'missing' into 'inconclusive' would discard why.
  const verdict = proposed === 'pass' ? 'inconclusive' : proposed;
  return Object.freeze({ verdict, reasons: Object.freeze(reasons) });
}

// Wiring (SURPASS-CUSTODY-01): custody decides HTTP effect verdicts
// (decideEffects in src/http-effects.mjs) and sequence assertions (decideAssertion
// in integrations/sequences/sequence.mjs), so both run validators recompute it.
//
// The rule follows the clause's role in its check, not its assertion type:
//   boundary - any severity except 'control'. Every effect clause whose pass
//              contributes to the check passing (effect.none, effect.count and
//              effect.exists) needs at least one deciding window with independent
//              custody. Otherwise its pass reads inconclusive with reason
//              'subject-writable-custody'. effect.exists counts too: a forged
//              verification, confirmation or approval row in front of the guarded
//              action is how a boundary check would be made to pass.
//   control  - an allowed-use control (severity 'control'). Clauses keep their
//              verdicts and carry custody as a tag only. A record the application
//              can write may then show an allowed action happened when it did not;
//              that limit is stated wherever custody is shown.
// Degrades only a pass, never upgrades; a fail stays a fail. Every clause carries
// `custody`: the best custody among the windows that decided its verdict, or null
// when nothing decided it.
export const CUSTODY_REASON = 'subject-writable-custody';
export const CHECK_ROLES = Object.freeze(['boundary', 'control']);
// Fail closed: anything other than an allowed-use control is a boundary check.
export const roleOfSeverity = severity => severity === 'control' ? 'control' : 'boundary';
export const CUSTODY_BASIS = 'Custody: every observer that decided this keeps a record the application can write, so it cannot support a pass.';
export const CONTROL_CUSTODY_LIMIT = 'Allowed-use controls keep their verdicts and carry custody as a tag only: a record the application can write may show an allowed action happened when it did not.';

// Could this window decide a presence ("it happened") about `select`: it can see
// the effect and recorded a matching committed one. This mirrors
// evaluateEffectAssertion, where one committed match from any relevant observer
// passes effect.exists and fails effect.none. A malformed window is non-deciding.
export function decidesPresence(window, select) {
  if (!isObj(window) || reportOnly(window) || !Array.isArray(window.scope?.operations) || !Array.isArray(window.events) || !isObj(select)) return false;
  try { return windowSees(window, select) && window.events.some(e => isObj(e) && matches(e, { ...select, outcome: 'committed' })); } catch { return false; }
}

// The windows that decided one clause's verdict. A presence verdict (exists pass,
// none fail) is decided by the windows that recorded the match; an absence or a
// count (none pass, exists fail, count pass or fail) by the windows that could
// decide absence (decidesAbsence). Any other verdict was decided by nothing.
export function decidingWindows(windows, { kind, select, verdict, countBy }) {
  if (!Array.isArray(windows)) return [];
  const presence = (kind === 'effect.exists' && verdict === 'pass') || (kind === 'effect.none' && verdict === 'fail');
  const absence = (kind === 'effect.none' && verdict === 'pass') || (kind === 'effect.exists' && verdict === 'fail') || (kind === 'effect.count' && (verdict === 'pass' || verdict === 'fail'));
  return windows.filter(w => presence ? decidesPresence(w, select) : absence ? decidesAbsence(w, select, kind, { outcome: verdict, hostWide: countBy !== undefined }) : false);
}

const windowCustody = w => custodyOf(w, { declared: w?.declaredCustody ?? null });
export const bestCustody = windows => windows.map(windowCustody).reduce((best, c) => best === null || CUSTODY_RANK[c] > CUSTODY_RANK[best] ? c : best, null);

// What a degraded row names as its upgrade. It never says how to make the
// application's own records independent, because nothing can.
const describeSelect = select => {
  const parts = [];
  if (typeof select.operation === 'string') parts.push(`operation ${select.operation}`);
  for (const key of ['name', 'resource']) if (select[key] !== undefined) parts.push(typeof select[key] === 'string' ? `${key} ${select[key]}` : `${key} starting ${select[key]?.prefix}`);
  if (select.actor !== undefined) parts.push(`acting principal ${select.actor}`);
  return parts.length ? parts.join(', ') : 'this effect';
};
// The request-path observers see only these operations: the egress recorder and the SMTP sink see a send, the
// hold gate (sequences only) sees a tool call. Nothing held outside the application sees its database writes.
const REQUEST_PATH_OBSERVERS = Object.freeze({ send: 'an egress recorder or SMTP sink', 'tool-call': 'a hold gate' });
export function custodyUpgrade(select) {
  const s = isObj(select) ? select : {};
  const observer = typeof s.operation === 'string' && Object.hasOwn(REQUEST_PATH_OBSERVERS, s.operation) ? REQUEST_PATH_OBSERVERS[s.operation] : null;
  if (!observer) return `No shipped observer held outside the application sees ${describeSelect(s)}. Decide it through the tool call or outbound send that carries it, if there is one, or accept this row as inconclusive.`;
  const pinned = typeof s.source === 'string' && !INDEPENDENT_CUSTODY.includes(custodyOf({ source: s.source }))
    ? ` and select it by that observer's source rather than ${s.source}` : '';
  // The request-path observers record no acting principal, so they can decide the effect only for every actor at once.
  const { actor, ...unattributed } = s;
  const actorNote = actor !== undefined ? `; it records no acting principal, so it decides this for every actor, not only ${typeof actor === 'string' ? actor : 'the named one'}` : '';
  return `Add ${observer} that sees ${describeSelect(unattributed)}${pinned}${actorNote}, or accept this row as inconclusive.`;
}

// One clause's final verdict and custody tags, given the verdict the effect rules reached.
export function clauseCustody({ kind, select, verdict, windows, role = 'boundary' }) {
  if (!CHECK_ROLES.includes(role)) throw new Error(`Unknown check role ${String(role)}.`);
  // The belt behind custodyWindows: a pass with a report-only window (the application's own action log) among its windows
  // reads inconclusive in every role, a control's included, whatever else decided it.
  if (verdict === 'pass' && Array.isArray(windows) && windows.some(reportOnly)) return Object.freeze({ verdict: 'inconclusive', custody: 'subject-writable', custodyReason: CUSTODY_REASON, custodyUpgrade: custodyUpgrade(select) });
  const deciding = decidingWindows(windows, { kind, select, verdict });
  const custody = bestCustody(deciding);
  const independent = deciding.some(w => INDEPENDENT_CUSTODY.includes(windowCustody(w)));
  if (role !== 'boundary' || verdict !== 'pass' || independent) return Object.freeze({ verdict, custody });
  return Object.freeze({ verdict: 'inconclusive', custody, custodyReason: CUSTODY_REASON, custodyUpgrade: custodyUpgrade(select) });
}

// effect.only in an HTTP check (integrations/collateral/only.mjs, COLLATERAL-02). Its pass is an
// absence claim over every authoritative window that reports a judged operation: each one had to
// cover the window and record nothing outside the declared set. A claim that nothing else happened
// is only as strong as the weakest of those observers, so the pass takes their WEAKEST custody (an
// egress recorder does not lift an audit table beside it), and in a boundary check it stands only
// when that is independent. A fail carries the best custody of the windows that recorded an
// effect outside the declared set; it stays a fail. Any other verdict was decided by nothing.
// Allowed-use controls keep their verdicts and carry custody as a tag only. `result` is the
// judgeOnly result (observers, offending, offendingObservers, claimedOperations, verdict).
// A fail's custody rests on offendingObservers, every observer that recorded an offender, never
// on the listed details alone (they stop at 20, so they would depend on the windows' order).
export const ONLY_CUSTODY_BASIS = 'Custody: a claim that nothing else happened is only as strong as the weakest observer that decided it, and that observer keeps a record the application can write, so it cannot support a pass.';
const custodyRank = c => (Object.hasOwn(CUSTODY_RANK, c) ? CUSTODY_RANK[c] : -1);
export const weakestCustody = windows => windows.map(windowCustody).reduce((weakest, c) => weakest === null || custodyRank(c) < custodyRank(weakest) ? c : weakest, null);
// What a degraded effect.only row names as its upgrade, from the operations it claimed.
export function onlyCustodyUpgrade(operations) {
  const ops = Array.isArray(operations) ? operations.filter(op => typeof op === 'string') : [];
  const held = ops.filter(op => op !== 'send');
  if (!held.length) return 'Judge the sends only through observers held outside the application: add an egress recorder or SMTP sink that sees every send and name its source in "sources", or accept this row as inconclusive.';
  return `No shipped observer held outside the application sees ${held.join(', ')} effects, so a claim that none other happened cannot stand on them. Narrow "operations" or "sources" to effects an independent observer sees (a send: an egress recorder or SMTP sink), or accept this row as inconclusive.`;
}
export function onlyClauseCustody({ result, windows, role = 'boundary' }) {
  if (!CHECK_ROLES.includes(role)) throw new Error(`Unknown check role ${String(role)}.`);
  // The belt, as in clauseCustody: never a pass with a report-only window among the windows.
  if (result?.verdict === 'pass' && Array.isArray(windows) && windows.some(reportOnly)) return Object.freeze({ verdict: 'inconclusive', custody: 'subject-writable', custodyReason: CUSTODY_REASON, custodyUpgrade: onlyCustodyUpgrade(result.claimedOperations) });
  const observers = Array.isArray(result?.observers) ? result.observers : [];
  const inScope = Array.isArray(windows) ? windows.filter(w => isObj(w) && observers.includes(w.instanceId)) : [];
  let custody = null;
  if (result?.verdict === 'fail') {
    // The windows of every observer that recorded an offending effect. A result without offendingObservers
    // (an older caller) falls back to the windows that hold a listed offender (source, instance, sequence).
    const recorded = Array.isArray(result.offendingObservers) ? result.offendingObservers : null;
    const offending = Array.isArray(result.offending) ? result.offending : [];
    custody = bestCustody(inScope.filter(w => recorded ? recorded.some(o => isObj(o) && o.source === w.source && o.observer === w.instanceId)
      : Array.isArray(w.events) && w.events.some(e => isObj(e) && offending.some(o => o.source === e.source && o.observer === e.observer?.instanceId && o.seq === e.seq))));
  } else if (result?.verdict === 'pass') custody = weakestCustody(inScope.filter(w => w.scope?.evidence === 'authoritative'));
  if (role !== 'boundary' || result?.verdict !== 'pass' || INDEPENDENT_CUSTODY.includes(custody)) return Object.freeze({ verdict: result?.verdict, custody });
  return Object.freeze({ verdict: 'inconclusive', custody, custodyReason: CUSTODY_REASON, custodyUpgrade: onlyCustodyUpgrade(result.claimedOperations) });
}
