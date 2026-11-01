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
//   observer-held     - the observer derives records the subject cannot author
//                       (database-log: the WAL observer, below)
//   independent       - produced outside the subject (request-path; provider-record:
//                       a provider's own signed record of what it accepted, when the
//                       feed's declared key source keeps its signing key outside the
//                       subject: feedKeyCustody below)
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
import { digest } from './domain.mjs';
import { windowSees, exactFor, matches, coverageFor, custodyWindows, REPORT_ONLY_SOURCES } from './effect-events.mjs';
import { LINEAGE_BY_SOURCE } from './effect-lineage.mjs';

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
  // observer once read (integrations/observers/provider-feed.mjs). Who holds that key is a declaration, not something a
  // run shows, so each window's custody also reads its feed's declared key source (feedKeyCustody, provider-feed/7).
  'provider-record': 'independent',
  // The application's own action log (src/app-log-rules.mjs): written by the subject, so it can never support a pass.
  'application-report': 'subject-writable',
  // The WAL observer (pg-wal, docs/PG-WAL.md "Custody"): the server writes the WAL, not the application, and the temporary slot
  // that reads it is held by the observer's own session, so the application cannot remove a committed change from the stream.
  // Dropping or consuming the slot ends that session (connection-lost, slot-lost), removed WAL reads wal-status-lost, and a table
  // made unlogged, renamed or rewritten reads schema-drift: each is inconclusive, never a decided absence. A pass on it stays
  // scoped to the observed tables. Held for an absence only: a presence decided on it is the application's own write
  // (ABSENCE_ONLY_SOURCES below).
  'database-log': 'observer-held',
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

// FIX-06 (SURPASS-BYPASS-01 B-12; provider-feed/7): a provider feed's custody rests on who holds the key that signs its
// entries, and nothing in a run shows that: an app that serves a feed of its own and signs it with its own key would read
// as the provider. So the profile declares where the public key came from (src/provider-feed-rules.mjs keySource), its
// feed record carries the declaration (keySource, and adapterReads for an adapter), and each sealed window names that
// record (scope.feed). The provider's own export, an operator-run adapter that reads the provider's API, and a test
// stub keep the key outside the application. An adapter that reads the application's own store, and an undeclared
// source, are a key the application could hold: subject-writable, so they never support a pass. A feed sees only its own
// provider's sends, so no other observer's silence covers its route: an absence such a feed sees stays inconclusive, whether
// the feed decided it or is presence-only, however independent the others are (clauseCustody), and so does an effect.only pass
// such a feed is judged in (onlyClauseCustody). A feed record without keySource was
// written before provider-feed/7 and keeps the custody it was judged with.
export function feedKeyCustody(feed) {
  if (feed === null || typeof feed !== 'object' || Array.isArray(feed) || !Object.hasOwn(feed, 'keySource')) return 'independent';
  const held = feed.keySource === 'provider' || feed.keySource === 'stub' || (feed.keySource === 'adapter' && feed.adapterReads === 'provider-api');
  return held ? 'independent' : 'subject-writable';
}
const feedKeyLowered = w => isObj(w) && w.source === 'provider-feed' && feedKeyCustody(w.scope?.feed) !== 'independent';
// What a row a provider feed's key source left without independent custody names as its upgrade.
export const FEED_KEY_UPGRADE = 'A provider feed that decided this declares no key source, or an adapter that reads the application\'s own store, so its record counts as one the application could sign: it is independent only if the key is the provider\'s own. Declare "keySource" only for a signing key held outside the application ("provider" for the provider\'s own export, "adapter" with "adapterReads": "provider-api" for an operator-run adapter of the provider\'s API, or "stub" for a test stub), or accept this row as inconclusive.';

// Custody of one window. A declaration may only LOWER trust: raising it is an
// operator act with an external basis, never something a profile or the subject
// asserts about itself. A provider feed's declared key source only lowers it too.
export function custodyOf(window, { declared = null } = {}) {
  const source = window?.source;
  const listed = typeof source === 'string' && Object.hasOwn(SOURCE_CUSTODY, source)
    ? SOURCE_CUSTODY[source] : 'subject-writable';
  const base = feedKeyLowered(window) ? 'subject-writable' : listed;
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
// The sources whose custody holds for an absence only (NC9 item 4, PR521 review MAJOR 2): the WAL observer shows every committed write
// to its tables, so an absence (or a count of 0) decided on it is held outside the application, but a write it shows is one the
// application chose to make, a decoy row as much as a real one, so a presence decided on it reads as the application's own record.
// A pass that needs a matched write is a presence too (PR521 review R2-MAJOR 1): an effect.count expecting one or more cannot pass
// without showing them, nor an effect.only without its expected effects, so their lower bound is the application's own write.
export const ABSENCE_ONLY_SOURCES = Object.freeze(['sql-wal']);
const decisionCustody = (w, presence) => (presence && ABSENCE_ONLY_SOURCES.includes(w?.source) ? 'subject-writable' : windowCustody(w));
const bestDecisionCustody = (windows, presence) => windows.map(w => decisionCustody(w, presence)).reduce((best, c) => best === null || CUSTODY_RANK[c] > CUSTODY_RANK[best] ? c : best, null);
// expected: an effect.count's; one not known to be 0 is read as a lower bound.
const clausePresence = (kind, verdict, expected) => (verdict === 'pass' && (kind === 'effect.exists' || (kind === 'effect.count' && expected !== 0)))
  || (kind === 'effect.none' && verdict === 'fail');
// An acting principal is held outside the application only where an observer names it itself (NC9 item 4, PR521 review MAJOR 1). An
// actor capture (integrations/observers/pg-actor.mjs) does not: it reads the claims the application's own session set, or a column it
// writes. So a boundary pass whose selector pins an actor reads inconclusive, principal-unverified, where an independent window that
// decided it takes its actor names from the capture (CAPTURED_ACTOR_SOURCES: the WAL observer's); a fail stays a fail. A window held
// outside the application that names principals itself keeps its pass (PR521 review R3: pairing's same-principal twin, settlement and
// timing read such windows); no shipped one does today.
export const CAPTURED_ACTOR_SOURCES = Object.freeze(['sql-wal']);
const capturedPrincipals = w => CAPTURED_ACTOR_SOURCES.includes(w?.source) && w?.scope?.actorAttribution === 'principal';
export const PRINCIPAL_REASON = 'principal-unverified';
export const PRINCIPAL_UPGRADE = 'No shipped observer names the acting principal from outside the application (an actor capture reads the claims the application set). Decide this effect for every actor, without the actor pin, or accept this row as inconclusive.';

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
// hold gate (sequences only) sees a tool call. Nothing else held outside the application sees its database writes, except a pg-wal
// observer for an absence (below).
const REQUEST_PATH_OBSERVERS = Object.freeze({ send: 'an egress recorder or SMTP sink', 'tool-call': 'a hold gate' });
// A pg-wal observer (NC9 item 4, PR521 review MINOR 3) reads every committed insert, update and delete to its tables from outside the
// application, so it can decide an absence of one that pins no actor (ABSENCE_ONLY_SOURCES, PRINCIPAL_REASON), never a presence. Only
// an HTTP assessment builds one (integrations/observers/factory.mjs), so only its absence rows (wal) name it.
const WAL_OPERATIONS = Object.freeze(['insert', 'update', 'delete']);
// Only a Postgres store can be watched by pg-wal, so only a row a Postgres observer's window decided names it (PR518-520-521 stack review
// MAJOR 1): an observer's instance id is its declared type and id, bound to the declaration (src/http-effects.mjs bindSealedWindows).
const postgresWindow = w => typeof w?.instanceId === 'string' && /^pg-(snapshot|wal)-/.test(w.instanceId);
const walDecides = (s, wal) => wal && WAL_OPERATIONS.includes(s.operation) && s.actor === undefined;
const WAL_UPGRADE = described => `For ${described}: add a pg-wal observer on the table it writes and select the effect by source sql-wal and that table's name (it reads every committed write to its tables from outside the application), or accept this row as inconclusive.`;
// wal: the row is an absence (effect.none, effect.count) in an HTTP assessment.
export function custodyUpgrade(select, { wal = false } = {}) {
  const s = isObj(select) ? select : {};
  if (walDecides(s, wal)) return WAL_UPGRADE(describeSelect(s));
  const observer = typeof s.operation === 'string' && Object.hasOwn(REQUEST_PATH_OBSERVERS, s.operation) ? REQUEST_PATH_OBSERVERS[s.operation] : null;
  if (!observer) return `No shipped observer held outside the application sees ${describeSelect(s)}. Decide it through the tool call or outbound send that carries it, if there is one, or accept this row as inconclusive.`;
  const pinned = typeof s.source === 'string' && !INDEPENDENT_CUSTODY.includes(custodyOf({ source: s.source }))
    ? ` and select it by that observer's source rather than ${s.source}` : '';
  // The request-path observers record no acting principal, so they can decide the effect only for every actor at once.
  const { actor, ...unattributed } = s;
  const actorNote = actor !== undefined ? `; it records no acting principal, so it decides this for every actor, not only ${typeof actor === 'string' ? actor : 'the named one'}` : '';
  return `Add ${observer} that sees ${describeSelect(unattributed)}${pinned}${actorNote}, or accept this row as inconclusive.`;
}

// One clause's final verdict and custody tags, given the verdict the effect rules reached. walObservers: the caller can build a pg-wal
// observer (an HTTP assessment), so a degraded absence names one as its upgrade. expected: an effect.count's.
export function clauseCustody({ kind, select, verdict, windows, role = 'boundary', walObservers = false, expected }) {
  if (!CHECK_ROLES.includes(role)) throw new Error(`Unknown check role ${String(role)}.`);
  const walAbsence = walObservers === true && (kind === 'effect.none' || (kind === 'effect.count' && expected === 0));
  const upgradeOn = ws => ({ wal: walAbsence && Array.isArray(ws) && ws.some(postgresWindow) });
  // The belt behind custodyWindows: a pass with a report-only window (the application's own action log) among its windows
  // reads inconclusive in every role, a control's included, whatever else decided it.
  if (verdict === 'pass' && Array.isArray(windows) && windows.some(reportOnly)) return Object.freeze({ verdict: 'inconclusive', custody: 'subject-writable', custodyReason: CUSTODY_REASON, custodyUpgrade: custodyUpgrade(select, upgradeOn(windows)) });
  const deciding = decidingWindows(windows, { kind, select, verdict });
  // FIX-06 (PR398-REVIEW finding 1, delta D1): a provider feed sees only its own provider's sends, so another observer's silence, an
  // honest feed for another vendor or an SMTP sink, never covers the route an app-held feed was meant to cover. A boundary absence (an
  // effect.none or effect.count pass) stays inconclusive when any feed whose key the application could hold sees the select, whether
  // it decided or not: a presence-only one (an export file, an endpoint without a witness) decides nothing, but an honest one would
  // have shown the send. windowSees is guarded as in decidesAbsence, so a malformed window sees nothing.
  const sees = w => { try { return isObj(select) && Array.isArray(w?.scope?.operations) && windowSees(w, select); } catch { return false; } };
  const lowered = (Array.isArray(windows) ? windows : []).filter(w => feedKeyLowered(w) && sees(w));
  if (role === 'boundary' && verdict === 'pass' && (kind === 'effect.none' || kind === 'effect.count') && lowered.length)
    return Object.freeze({ verdict: 'inconclusive', custody: weakestCustody([...deciding, ...lowered]), custodyReason: CUSTODY_REASON, custodyUpgrade: FEED_KEY_UPGRADE });
  const presence = clausePresence(kind, verdict, expected);
  const custody = bestDecisionCustody(deciding, presence);
  const independent = deciding.some(w => INDEPENDENT_CUSTODY.includes(decisionCustody(w, presence)));
  const heldNames = deciding.some(w => INDEPENDENT_CUSTODY.includes(decisionCustody(w, presence)) && !capturedPrincipals(w));
  if (role === 'boundary' && verdict === 'pass' && independent && !heldNames && isObj(select) && select.actor !== undefined)
    return Object.freeze({ verdict: 'inconclusive', custody, custodyReason: PRINCIPAL_REASON, custodyUpgrade: PRINCIPAL_UPGRADE });
  if (role !== 'boundary' || verdict !== 'pass' || independent) return Object.freeze({ verdict, custody });
  return Object.freeze({ verdict: 'inconclusive', custody, custodyReason: CUSTODY_REASON, custodyUpgrade: deciding.some(feedKeyLowered) ? FEED_KEY_UPGRADE : custodyUpgrade(select, upgradeOn(deciding)) });
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
const weakestDecisionCustody = (windows, presenceOn) => windows.map(w => decisionCustody(w, presenceOn(w))).reduce((weakest, c) => weakest === null || custodyRank(c) < custodyRank(weakest) ? c : weakest, null);
// What a degraded effect.only row names as its upgrade, from the operations it claimed. wal: as custodyUpgrade's, when every operation
// held is one a pg-wal observer reads and no allowed selector pins an actor.
export function onlyCustodyUpgrade(operations, { wal = false } = {}) {
  const ops = Array.isArray(operations) ? operations.filter(op => typeof op === 'string') : [];
  const held = ops.filter(op => op !== 'send');
  if (wal && held.length && held.every(op => WAL_OPERATIONS.includes(op))) return `For ${held.join(', ')} effects: add a pg-wal observer on the tables they write and name source sql-wal in "sources" (it reads every committed write to its tables from outside the application)${held.length < ops.length ? ', and an egress recorder or SMTP sink for the sends' : ''}, or accept this row as inconclusive.`;
  if (!held.length) return 'Judge the sends only through observers held outside the application: add an egress recorder or SMTP sink that sees every send and name its source in "sources", or accept this row as inconclusive.';
  return `No shipped observer held outside the application sees ${held.join(', ')} effects, so a claim that none other happened cannot stand on them. Narrow "operations" or "sources" to effects an independent observer sees (a send: an egress recorder or SMTP sink), or accept this row as inconclusive.`;
}
// pinsActor: whether an expected or allowed selector pins an actor (the principal rule above applies to the pass). walObservers: as in
// clauseCustody. expect: the expected selectors; a pass on a WAL window that holds a committed one rests on that write, a presence.
export function onlyClauseCustody({ result, windows, role = 'boundary', pinsActor = false, walObservers = false, expect = [] }) {
  if (!CHECK_ROLES.includes(role)) throw new Error(`Unknown check role ${String(role)}.`);
  const expected = Array.isArray(expect) ? expect.filter(isObj) : [];
  const matchedOn = w => ABSENCE_ONLY_SOURCES.includes(w?.source) && Array.isArray(w.events)
    && w.events.some(e => isObj(e) && e.outcome === 'committed' && expected.some(s => { try { return matches(e, s); } catch { return false; } }));
  // No pg-wal upgrade where an expected selector could be a database write: that half is a presence, which the WAL cannot hold.
  const expectsWrite = expected.some(s => s.operation === undefined || WAL_OPERATIONS.includes(s.operation));
  const walOnly = walObservers === true && pinsActor !== true && !expectsWrite;
  const upgradeOn = ws => ({ wal: walOnly && Array.isArray(ws) && ws.some(postgresWindow) });
  // The belt, as in clauseCustody: never a pass with a report-only window among the windows.
  if (result?.verdict === 'pass' && Array.isArray(windows) && windows.some(reportOnly)) return Object.freeze({ verdict: 'inconclusive', custody: 'subject-writable', custodyReason: CUSTODY_REASON, custodyUpgrade: onlyCustodyUpgrade(result.claimedOperations, upgradeOn(windows)) });
  const observers = Array.isArray(result?.observers) ? result.observers : [];
  const inScope = Array.isArray(windows) ? windows.filter(w => isObj(w) && observers.includes(w.instanceId)) : [];
  // FIX-06 (PR398-REVIEW delta, effect.only): as in clauseCustody, a feed whose key the application could hold that the clause judges,
  // presence-only included, keeps a boundary pass inconclusive: the pass rests on the other observers, whose silence does not cover
  // that provider's route, and an honest feed would have shown the send. A fail stays a fail.
  const lowered = inScope.filter(feedKeyLowered);
  if (role === 'boundary' && result?.verdict === 'pass' && lowered.length)
    return Object.freeze({ verdict: 'inconclusive', custody: weakestCustody([...inScope.filter(w => w.scope?.evidence === 'authoritative'), ...lowered]), custodyReason: CUSTODY_REASON, custodyUpgrade: FEED_KEY_UPGRADE });
  let custody = null;
  if (result?.verdict === 'fail') {
    // The windows of every observer that recorded an offending effect. A result without offendingObservers
    // (an older caller) falls back to the windows that hold a listed offender (source, instance, sequence).
    const recorded = Array.isArray(result.offendingObservers) ? result.offendingObservers : null;
    const offending = Array.isArray(result.offending) ? result.offending : [];
    custody = bestCustody(inScope.filter(w => recorded ? recorded.some(o => isObj(o) && o.source === w.source && o.observer === w.instanceId)
      : Array.isArray(w.events) && w.events.some(e => isObj(e) && offending.some(o => o.source === e.source && o.observer === e.observer?.instanceId && o.seq === e.seq))));
  } else if (result?.verdict === 'pass') custody = weakestDecisionCustody(inScope.filter(w => w.scope?.evidence === 'authoritative'), matchedOn);
  // The principal rule applies where an actor pin could have decided something on names the capture supplies: an authoritative window
  // in scope that holds independent custody and takes its actor names from the capture. A pin on a window that names no actor matches
  // nothing there (app-log-admission M8), and one that names principals itself keeps the pass, as in clauseCustody.
  const namesPrincipals = inScope.some(w => w.scope?.evidence === 'authoritative' && capturedPrincipals(w) && INDEPENDENT_CUSTODY.includes(decisionCustody(w, matchedOn(w))));
  if (role === 'boundary' && result?.verdict === 'pass' && INDEPENDENT_CUSTODY.includes(custody) && pinsActor === true && namesPrincipals)
    return Object.freeze({ verdict: 'inconclusive', custody, custodyReason: PRINCIPAL_REASON, custodyUpgrade: PRINCIPAL_UPGRADE });
  if (role !== 'boundary' || result?.verdict !== 'pass' || INDEPENDENT_CUSTODY.includes(custody)) return Object.freeze({ verdict: result?.verdict, custody });
  // A judged feed whose key the application could hold returned above, so this row's upgrade is never the key-source declaration.
  return Object.freeze({ verdict: 'inconclusive', custody, custodyReason: CUSTODY_REASON, custodyUpgrade: onlyCustodyUpgrade(result.claimedOperations, upgradeOn(inScope)) });
}
