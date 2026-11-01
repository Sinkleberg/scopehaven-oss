// Observed effects for HTTP checks (http-contract/4). Pure: no I/O. The
// connector uses it to turn a check's declared effects and the windows its
// observers reported into assertions; the shared run validator uses the same
// functions to recompute them from the sealed windows, so a stored verdict is
// never trusted.
//
// A check's "effects" are effect assertions (integrations/observers/events.mjs):
// effect.none / effect.exists / effect.count with a selector. Each becomes one
// assertion "Observed effect N (kind)". Its status is pass or fail only when
// the evaluator decided it; missing, unobservable, observer-failure or
// conflicting evidence reads inconclusive, never pass.
//
// The row's "Trusted backend observation available" assertion passes only when
// every declared effect was decided by an authoritative observer (an audit log,
// the database or the request-path gate). Presence-only telemetry (traces, MCP
// logs) can still fail an effect, but never makes backend evidence available.
//
// Custody (src/custody.mjs, SURPASS-CUSTODY-01) is the second, orthogonal
// dimension: who can write the record that decided a clause. In a boundary check
// (any severity except 'control') a clause's pass needs a deciding window held
// outside the application, otherwise it reads inconclusive with reason
// subject-writable-custody. Allowed-use controls carry custody as a tag only.
// "Trusted backend observation available" keeps its coverage meaning: an
// authoritative observer decided every declared effect, whoever can write it.
//
// effect.only (COLLATERAL-02, integrations/collateral/only.mjs, in the evaluator
// hash) is the fourth kind: every committed effect the observers in scope saw is
// an expected one within its count, or allowed. Its verdict rules are only.mjs's,
// unchanged. Its pass is an absence claim, so custody takes the weakest custody of
// the windows that decided it (onlyClauseCustody in src/custody.mjs).
//
// Selectors here may use `fields` (declared captured body fields, src/body-fields.mjs), judged
// three-valued: a send whose fields could not be read holds a pass at missing, never passes. Core clauses and
// claim rules (not effect.only) may also use `upstream: "applied"` (a forwarded send's upstream outcome,
// src/effect-outcome.mjs), judged the same way: an outcome that is not applied or rejected holds a pass at missing.
// In-doubt resolution, gate A (IN-DOUBT-DESIGN-ADDENDUM-R1 1.2 and 1.3): a core clause may declare `semantics` (forbidden-attempt on
// effect.none; agent-write on effect.exists; exactly-n on effect.count), and `upstream: "resolved"` is accepted exactly on an
// agent-write or exactly-n clause (src/effect-outcome.mjs clauseSemanticsProblem). effect.only opts in per selector with
// `outcomeJudged` (integrations/collateral/only.mjs), and no outcomeJudged selector may overlap an effect.none of the same check
// (validateCheckEffects). A clause without either keeps main's reading, byte for byte.
// In-doubt resolution core (IDR-1, src/in-doubt.mjs): an opted-in clause reads each in-doubt send through its resolvers' strict combination
// (R0: a forward whose TCP connect never completed is refuted), and carries `resolution`, its operation over the attempts it selects in
// gate-B windows (egress-recorder/7): { operation, applied, refuted, inDoubt, attempts }, sealed and recomputed. Such a clause is
// authoritative for the backend tier only when none of those attempts is still in doubt; a clause without the opt-in, and every clause
// of a run sealed by an earlier build, keeps that build's backend reading.
// The run-end re-decide stage (IDR-2, redecideResolved below; ADDENDUM-R1 1.6): a later resolver's records arrive after a window was sealed.
// The connector binds them onto the attempts they name and decides again, with decideEffects, every row with an opted-in clause that reads a
// changed attempt (its record then says `redecided: true`), and seals the row's records as data.resolutions; the validator binds them onto
// the windows bindSealedWindows returns before deciding (bindSealedResolutions), in the same order. The one later resolver is R1, the
// request feed (IDR-4, src/request-feed-rules.mjs): a sealed record is the feed's read, and both sides derive its result from it. R2, the
// read-back of the system of record (IDR-3, src/read-back-rules.mjs), rides the same stage: a sealed record is the group's read. A
// lifecycle change check's row takes no late record (PR348-REVIEW minor 3; src/contracts.mjs refuses one there).
//
// Claim rules (src/http-claims.mjs) are a check's `claims`: the response's reading selects
// effect.exists (a success claim) or effect.none (a refusal claim) over the same windows, and the
// records decide it exactly as a declared clause (custody, settlement, pairing). They are decided
// after the declared effects, stored apart from them (trace data.claims, so a run's declared
// effects signature never depends on what a reply said), and shown as "Observed claim N (reading)".
// An ambiguous, unreadable or untriggered reading is inconclusive; an untriggered claim declared
// no-requirement is not-required: no assertion row, and not counted for backend observation.
import { digest } from './domain.mjs';
import { evaluateEffectAssertion, validateEffectAssertion, validateSelector, validateWindow, windowSees, matches, matchState, EFFECT_LIMITS, REASON_PATTERN } from './effect-events.mjs';
import { admitInDoubt, inDoubtAdmitted, fateOf, attemptBasis, operationOf, lateBound, lateEntriesFor, bindResolutions, sealedResolutions, transportArrival } from './in-doubt.mjs';
import { validateClaims, declaredClaim, claimClause, validReading, readingFields, claimAssertionName, CLAIM_ASSERTION_PATTERN, CLAIM_BASIS, NOT_REQUIRED, CLAIM_LIMITS } from './http-claims.mjs';
import { LINEAGE_BY_SOURCE } from './effect-lineage.mjs';
import { clauseCustody, onlyClauseCustody, roleOfSeverity, CUSTODY_BASIS, ONLY_CUSTODY_BASIS } from './custody.mjs';
import { judgeOnly, validateOnlyAssertion, onlyScopedComplete, outcomeJudgedOverlap, outcomeJudgedProfileProblem, outcomeJudgedSends, OnlyError, ONLY_KIND } from '../integrations/collateral/only.mjs';
export { outcomeJudgedProfileProblem };
import { objectRecordOf, aliasRecordOf, siblingsOf, crossDestinationsOf, crossRecordOf } from './egress-rules.mjs';
import { suspendHeldNote, applySuspendShort, carriesSuspendShort, SUSPEND_UNCHECKED_NOTE } from './suspend-clock.mjs';
// Settlement across a run's windows (src/http-settlement.mjs) and the positive-match pairing of absence selectors
// (src/http-pairing.mjs): both applied after custody, settlement first, never upgrading.
import { applySettlement, settlementFields } from './http-settlement.mjs';
import { formEnabled, captureEncodingOf, TEMPLATE_POINTER } from './body-fields.mjs';
import { idempotencyRecordOf } from './idempotency.mjs';
import { applyPairing, pairingFields } from './http-pairing.mjs';
// Background attribution (src/http-attribution.mjs), applied after settlement and before pairing on runs that declare it.
import { applyAttribution, attributionFields } from './http-attribution.mjs';
import { forwardRecordOf, upstreamBound, clauseSemanticsProblem, withoutUpstream } from './effect-outcome.mjs';
import { EffectError, SIBLING_CODE, admitDisclosure, disclosureAdmitted } from './effect-events.mjs';
import { COLLECTOR_RECORDS, SCOPED_COLLECTOR_LABELS, CAPTURED_ENTRY_LABELS, TEMPLATE_LIFT_LABELS, TARGET_LABELS, IN_DOUBT_LABELS, REQUEST_FEED_LABELS, READ_BACK_LABELS, SIBLING_LABELS, CROSS_LABELS } from './collector-identity.mjs';
import { requestFeedRecordOf } from './request-feed-rules.mjs';
import { readBackRecordOf, validReadBackSend } from './read-back-rules.mjs';
import { providerFeedRecord, providerFeedCapture } from './provider-feed-rules.mjs';
import { admitScoped, admitTemplateLift, markUnfollowed, custodyWindows, custodyRunWindows } from './effect-events.mjs';
// App logs (src/app-log-rules.mjs): sealed beside a check's windows as data.appLogWindows, never decided here.
import { sealAppLogWindows, bindAppLogWindows, admissionsFor, applyAdmissions, appLogFields } from './app-log-verdicts.mjs';

export const EFFECT_EVIDENCE_SCHEMA = 'scopehaven-effect-evidence/1';
export const EFFECT_ASSERTION_PATTERN = /^Observed effect (\d{1,2}) \((effect\.none|effect\.exists|effect\.count|effect\.only)\)$/;
export const BACKEND_ASSERTION = 'Trusted backend observation available';
export const MAX_EFFECTS = 32;
// Observer types a profile may declare (built by integrations/observers/factory.mjs),
// and the effect source and observer kind each one produces. A sealed window must
// come from a declared observer: its instance id, source and kind are bound to it.
export const OBSERVER_TYPES = Object.freeze(['otel', 'sqlite-audit', 'sqlite-snapshot', 'http-audit', 'mcp-log', 'audit-file', 'pg-snapshot', 'egress-recorder', 'smtp-sink', 'mysql-snapshot', 'provider-feed', 'pg-wal']);
export const OBSERVER_OUTPUT = Object.freeze({
  otel: Object.freeze({ source: 'otel-genai', kind: 'otlp-http-json-receiver' }),
  'sqlite-audit': Object.freeze({ source: 'sql-audit-table', kind: 'sqlite-audit-table' }),
  'sqlite-snapshot': Object.freeze({ source: 'sql-snapshot', kind: 'sqlite-snapshot-diff' }),
  'http-audit': Object.freeze({ source: 'http-audit-log', kind: 'http-audit-endpoint' }),
  'mcp-log': Object.freeze({ source: 'mcp-jsonrpc', kind: 'mcp-stdio-recorder' }),
  'audit-file': Object.freeze({ source: 'file-audit-log', kind: 'audit-log-file' }),
  'pg-snapshot': Object.freeze({ source: 'sql-snapshot', kind: 'postgres-snapshot-diff' }),
  'egress-recorder': Object.freeze({ source: 'http-egress', kind: 'http-egress-recorder' }),
  'smtp-sink': Object.freeze({ source: 'smtp-capture', kind: 'smtp-sink-recorder' }),
  'mysql-snapshot': Object.freeze({ source: 'sql-snapshot', kind: 'mysql-snapshot-diff' }),
  'provider-feed': Object.freeze({ source: 'provider-feed', kind: 'provider-feed-reader' }),
  // NC9 item 4: the Postgres logical-decoding observer (integrations/observers/pg-wal.mjs), with a source of its own (custody
  // observer-held, src/custody.mjs).
  'pg-wal': Object.freeze({ source: 'sql-wal', kind: 'postgres-wal-decode' }),
});
export const OBSERVER_ID = /^[A-Za-z0-9_-]{1,48}$/;
export const observerInstanceId = (type, id) => `${type}-${id}`;
// Post-response settle: after a check's response, the connector waits the largest
// declared settleMs before the end marks, so an effect the app commits shortly
// after answering still lands in that check's window. An authoritative window
// without a declared settle cannot support absence: it is capped at "partial".
// Effects committed later than settleMs after the response may be missed or counted in a later check's window.
export const SETTLE_BOUNDS = Object.freeze({ minMs: 250, maxMs: 30000 });
export const settleDeclared = ms => Number.isInteger(ms) && ms >= SETTLE_BOUNDS.minMs && ms <= SETTLE_BOUNDS.maxMs;
export const NO_SETTLE_REASON = 'no-post-response-settle';
export function applySettle(window, settleMs) {
  if (window.scope?.evidence !== 'authoritative' || settleDeclared(settleMs)) return window;
  // A destination-scoped window (coverage v2) with no declared settle loses its entries: nothing bounds how late a send came.
  if (Object.hasOwn(window, 'scoped')) { const { scoped, ...rest } = window; return { ...rest, coverage: 'partial', reason: NO_SETTLE_REASON }; }
  if (!['complete', 'net-only'].includes(window.coverage)) return window;
  return { ...window, coverage: 'partial', reason: NO_SETTLE_REASON };
}
// Lineage of an observer's evidence, by source (recorded on each sealed window).
// Defined in src/effect-lineage.mjs (shared with src/custody.mjs); re-exported here unchanged.
export { LINEAGE_BY_SOURCE, roleOfSeverity };
const STATUS_OF = Object.freeze({ pass: 'pass', fail: 'fail' });
export const effectStatus = verdict => STATUS_OF[verdict] ?? 'inconclusive';
export const effectAssertionName = (index, kind) => `Observed effect ${index + 1} (${kind})`;
// Later outcomes (src/later-outcome.mjs, provider-feed/6): the stage's tag on a positive clause it lowered (later: a reason), and the strength
// of a positive pass whose every matched send the provider later recorded as succeeded (laterStrength: "succeeded").
export const laterFields = d => ({ ...(d?.later ? { later: d.later } : {}), ...(d?.laterStrength ? { laterStrength: d.laterStrength } : {}) });
// Absent fields (src/effect-events.mjs evaluateEffectAssertion): a fail a declared absence decided, while it is still a fail. src/runner.mjs
// compareRuns reads a baseline row that fails only on such clauses as unverified, never as a verified repair.
export const absenceFields = d => (d?.verdict === 'fail' && d?.absenceDecided === true ? { absenceDecided: true } : {});
// Apply one row's later-outcome findings (src/later-outcome.mjs laterFindings), after app-log admissions: a finding replaces its decision only
// while that decision still passes (an admitted clause keeps its admission, which a repair comparison reads); nothing else changes.
export const applyLater = (decisions, findings) => decisions.map((d, i) => findings?.[i] && d.verdict === 'pass' ? findings[i] : d);
// The custody fields a decided clause carries (custodyReason and custodyUpgrade only when degraded).
const custodyFields = d => ({ custody: d.custody ?? null, ...(d.custodyReason ? { custodyReason: d.custodyReason, custodyUpgrade: d.custodyUpgrade } : {}) });

// A declared effect as a profile states it: { kind, select, expected?, countBy?, semantics? } for the core kinds, and for
// effect.only exactly the fields it declares, in any order (validateOnlyAssertion refuses others). semantics only when declared.
export const ONLY_FIELDS = Object.freeze(['kind', 'expect', 'allow', 'operations', 'sources', 'counterparts', 'countBy', 'outcomeJudged']);
export const declaredEffect = e => e?.kind === ONLY_KIND ? Object.fromEntries(ONLY_FIELDS.filter(key => Object.hasOwn(e, key)).map(key => [key, e[key]]))
  : { kind: e.kind, select: e.select, ...(e.kind === 'effect.count' ? { expected: e.expected } : {}), ...(e.kind === 'effect.count' && e.countBy !== undefined ? { countBy: e.countBy } : {}),
    ...(e.semantics !== undefined ? { semantics: e.semantics } : {}) };
// The core clause the effect rules judge (src/effect-events.mjs): the declared clause without its semantics type, which only gate A reads.
const coreOf = e => { if (e?.semantics === undefined) return e; const { semantics: _semantics, ...core } = e; return core; };
// A countBy clause's application interval (src/idempotency.mjs): { low, high, reason }, or null when no key record decided it.
const applicationsFields = d => d?.countBy !== undefined && d.kind !== ONLY_KIND ? { applications: d.applications ?? null } : {};
// Profile validation: effect.only by only.mjs (codes: field, allow, expect, expect-count, selector,
// selector-name, selector-outcome, selectors, operations, sources, counterparts, and the outcome-judged-* codes), the rest by the core,
// after gate A: a declared semantics type that fits the kind, with `upstream: "resolved"` exactly when it reads resolutions.
export function validateDeclaredEffect(effect, where) {
  if (effect?.kind === ONLY_KIND) return validateOnlyAssertion(effect, where, { fields: true, countBy: true });
  if (effect !== null && typeof effect === 'object' && !Array.isArray(effect)) {
    const problem = clauseSemanticsProblem(effect.kind, effect.semantics, effect.select);
    if (problem) throw new EffectError(`effect-${problem}`, where);
  }
  validateEffectAssertion(coreOf(effect), where, { fields: true, countBy: true, upstream: true });
  return effect;
}
// One check's absence selectors read as attempts: its effect.none selects, and the select of each claim rule that declares a refusal and
// is not judged by outcome (no upstream "resolved"; src/http-claims.mjs). A forbidden selector is never judged by outcome.
export function forbiddenSelectors(effects, claims = []) {
  const refusal = c => { const spec = c !== null && typeof c === 'object' && c.trigger !== null && typeof c.trigger === 'object' ? Object.values(c.trigger)[0] : null; return Array.isArray(spec?.refusal) && spec.refusal.length > 0; };
  return [...(Array.isArray(effects) ? effects : []).filter(e => e?.kind === 'effect.none').map(e => e.select),
    ...(Array.isArray(claims) ? claims : []).filter(c => refusal(c) && c?.select?.upstream !== 'resolved').map(c => c.select)];
}
// One check's declared effects and claims together (ADDENDUM-R1 1.3, IN-DOUBT-LEAD-RULING-IDR0 R-3): no effect.only outcomeJudged selector
// overlaps one of the check's absence selectors (forbiddenSelectors; the same source and operation, the same canonical host, and
// resources equal or one a prefix of the other; an absent key overlaps every value). Throws an OnlyError (code outcome-judged-overlap).
export function validateCheckEffects(effects, claims = []) {
  const forbidden = forbiddenSelectors(effects, claims);
  (Array.isArray(effects) ? effects : []).forEach((e, i) => { if (e?.kind === ONLY_KIND && outcomeJudgedOverlap(e, forbidden)) throw new OnlyError('outcome-judged-overlap', `effect ${i + 1}`); });
  return effects;
}
// Egress destinations as a run record declares them (declaredObserverRecord): host, forward entry, captured pointers and object routes. Its
// paths are not recorded, so the profile check skips that one test here (src/contracts.mjs makes it at load).
export const recordedDestinations = observers => (Array.isArray(observers) ? observers : []).filter(o => o?.type === 'egress-recorder').flatMap(o => {
  const hosts = [...new Set([...Object.keys(o.forward ?? {}), ...Object.keys(o.objects ?? {}), ...Object.keys(o.capture ?? {})])];
  return hosts.map(host => ({ host, ...(o.forward?.[host] ? { forward: o.forward[host] } : {}), ...(o.capture?.[host] ? { capture: { pointers: o.capture[host] } } : {}),
    ...(o.objects?.[host]?.paths ? { objectPaths: o.objects[host].paths } : {}), ...(o.objects?.[host]?.fields ? { objectFields: o.objects[host].fields } : {}) }));
});
// A check's claim rules (src/http-claims.mjs), with selectors that may use fields.
export const validateDeclaredClaims = claims => validateClaims(claims, select => validateSelector(select, 'claim select', { fields: true, upstream: true }));
export { CLAIM_ASSERTION_PATTERN, declaredClaim };
// What an effect.only clause counted: judged, expected, allowed, outside the set (offending),
// unattributable, and transient or sent (labels only: they never change the verdict).
const ONLY_COUNTS = ['judged', 'expected', 'allowed', 'offending', 'unattributable', 'transient'];
const onlyCounts = counts => Object.fromEntries(ONLY_COUNTS.map(key => [key, Number.isSafeInteger(counts?.[key]) ? counts[key] : 0]));
const offendingText = list => list.slice(0, 5).map(o => `${o.operation} ${o.name}${o.resource ? ` ${o.resource}` : ''} [${o.label}${o.reason ? `, ${o.reason}` : ''}]`).join('; ');
// In-doubt resolution (IDR-1): an opted-in clause's operation over the attempts it selects in gate-B windows (src/in-doubt.mjs), or null
// when none of its windows is admitted. Per attempt: its observer and seq, its fate, what decided it (the proven reply, R0, or nothing,
// with the reason) and the resolvers that applied to it, at most RESOLUTION_LISTED of them; counts and labels only. The operation is
// refuted only when every attempt was and every authoritative window that can see the clause covered the window completely. It is
// informational: no verdict reads it.
// redecided (IDR-2): true when a send whose fate the clause reads carries a later resolver's record (src/in-doubt.mjs lateBound): the
// clause was decided again at run end. read: those sends, the selected ones, and for a countBy clause or an effect.only outcomeJudged clause
// every committed send of its admitted windows (a key collapse, and effect.only's replay hint with or without countBy, read the fate of each
// send in a key group, outcome-judged or not; PR348-REVIEW minor 1). Present only when true, so a run with no late record seals main's bytes.
export const RESOLUTION_LISTED = 20;
function resolutionOf(selected, windows, select, read = selected) {
  if (!windows.some(inDoubtAdmitted)) return null;
  const relevant = windows.filter(w => w.scope?.evidence === 'authoritative' && (select ? windowSees(w, select) : true));
  const covered = relevant.length > 0 && relevant.every(w => w.coverage === 'complete');
  const fates = selected.map(({ e }) => fateOf(e));
  const listed = selected.slice(0, RESOLUTION_LISTED).map(({ e, w }, i) => { const b = attemptBasis(e); return { observer: w.instanceId, seq: e.seq, fate: fates[i], by: b.by, ...(b.reason ? { reason: b.reason } : {}), resolvers: b.resolvers }; });
  return { ...operationOf(fates, { covered }), attempts: listed, ...(read.some(({ e }) => lateBound(e)) ? { redecided: true } : {}) };
}
// Every committed send of the admitted windows (what a countBy clause's key collapse may read the fate of).
const admittedSends = windows => windows.filter(inDoubtAdmitted).flatMap(w => w.events.filter(e => e.outcome === 'committed').map(e => ({ e, w })));
// The sends a resolved core clause selects in admitted windows: committed, and fitting its selector without the upstream pin (a field that
// could not be read counts as fitting).
const resolvedSelected = (select, windows) => windows.filter(w => inDoubtAdmitted(w) && windowSees(w, select))
  .flatMap(w => w.events.filter(e => matchState(e, { ...withoutUpstream(select), outcome: 'committed' }) !== 'no').map(e => ({ e, w })));
// A basis note only when some selected attempt had no proven reply: the operation and its counts.
const resolutionBasis = r => r && r.attempts.some(a => a.by !== 'proof')
  ? ` In-doubt resolution: operation ${r.operation}; ${r.applied} applied, ${r.refuted} refuted (a proven rejection, or a connection to the upstream that never completed), ${r.inDoubt} still in doubt.` : '';
const resolutionFields = d => d?.resolution ? { resolution: d.resolution } : {};
function decideOnly(effect, index, windows, role, walUpgrade = true) {
  validateOnlyAssertion(effect, `effect ${index + 1}`, { fields: true, countBy: true });
  // SETTLE-V3 fix C: a scoped egress window whose every unattributed send is allowed and not expected covers it toward a pass.
  const result = judgeOnly(effect, windows, { fields: true, countBy: true, scopedComplete: onlyScopedComplete(effect, windows) });
  const pinsActor = [...(Array.isArray(effect.expect) ? effect.expect.map(x => x?.select ?? x) : []), ...(Array.isArray(effect.allow) ? effect.allow : [])].some(s => s !== null && typeof s === 'object' && s.actor !== undefined);
  const expect = Array.isArray(effect.expect) ? effect.expect.map(x => x?.select ?? x) : [];
  const held = onlyClauseCustody({ result, windows, role, pinsActor, walObservers: walUpgrade, expect });
  const counts = onlyCounts(result.counts);
  // Backend evidence: a pass is reached only on authoritative coverage; a fail only when an
  // authoritative observer recorded an effect outside the declared set (any offender, not only the listed ones).
  const authoritative = result.verdict === 'pass' || (result.verdict === 'fail' && windows.some(w => w.scope?.evidence === 'authoritative'
    && result.offendingObservers.some(o => o.source === w.source && o.observer === w.instanceId)));
  const outside = result.offending.length ? ` Outside the declared set: ${offendingText(result.offending)}${counts.offending > 5 ? `; ${counts.offending - 5} more` : ''}.` : '';
  // outcomeJudged under gate B (IDR-1): the operation over the outcome-judged sends; backend evidence only when none is still in doubt.
  const judged = Array.isArray(effect.outcomeJudged) ? outcomeJudgedSends(effect, windows.filter(inDoubtAdmitted)) : null;
  const resolution = judged ? resolutionOf(judged, windows, null, [...judged, ...admittedSends(windows)]) : null;
  return { ...declaredEffect(effect), verdict: held.verdict, matched: counts.offending, counts,
    basis: `${result.basis}${outside}${resolutionBasis(resolution)}${held.custodyReason ? ` ${ONLY_CUSTODY_BASIS}` : ''}`, authoritative: authoritative && !(resolution && resolution.inDoubt), ...custodyFields(held), ...(resolution ? { resolution } : {}) };
}

// A core clause (effect.none, effect.exists, effect.count) decided over the windows, custody included. Exported for the later-outcome
// stage (src/later-outcome.mjs), which judges a positive clause again over its own windows without the sends that did not credit.
export function decideClause(effect, windows, role, { walUpgrade = true } = {}) {
  // scoped: the HTTP path reads destination-scoped egress entries (coverageFor reads only windows the connector or validator admitted).
  const decision = evaluateEffectAssertion(coreOf(effect), windows, { countBy: true, scoped: true });
  const held = clauseCustody({ kind: effect.kind, select: effect.select, verdict: decision.verdict, windows, role, walObservers: walUpgrade, expected: effect.expected });
  // upstream "resolved" under gate B (IDR-1): the operation over the attempts the clause selects; backend evidence only when none is in doubt.
  const selected = effect.select?.upstream === 'resolved' ? resolvedSelected(effect.select, windows) : null;
  const resolution = selected ? resolutionOf(selected, windows, effect.select, effect.countBy !== undefined ? [...selected, ...admittedSends(windows)] : selected) : null;
  const basis = `${decision.basis}${resolutionBasis(resolution)}`;
  return { ...declaredEffect(effect), ...(effect.countBy !== undefined ? { applications: decision.applications ?? null } : {}), verdict: held.verdict, matched: decision.matched,
    basis: held.custodyReason ? `${basis} ${CUSTODY_BASIS}` : basis,
    // Coverage, not custody: decided on the effect rules' own verdict.
    authoritative: decidedAuthoritatively(effect, decision.verdict, windows) && !(resolution && resolution.inDoubt), ...custodyFields(held), ...absenceFields({ verdict: held.verdict, absenceDecided: decision.absenceDecided }), ...(resolution ? { resolution } : {}) };
}
// Decide each declared effect over the windows of one check, then each claim rule under its reading.
// `role` is the check's role ('boundary' unless its severity is 'control'; see roleOfSeverity),
// and custody may degrade a boundary pass (src/custody.mjs). A claim decision carries `claim` (its
// index), its declared fields, its reading, and `kind`: the clause its reading selected, or null.
export function decideEffects(effects, windows, { role = 'boundary', claims = [], readings = [], walUpgrade = true } = {}) {
  custodyWindows(windows, 'decideEffects');
  validateCheckEffects(effects, claims);
  const decided = effects.map((effect, index) => {
    if (effect?.kind === ONLY_KIND) return decideOnly(effect, index, windows, role, walUpgrade);
    validateDeclaredEffect(effect, `effect ${index + 1}`);
    return decideClause(effect, windows, role, { walUpgrade });
  });
  if (claims.length !== readings.length) throw new Error('claim-readings');
  const claimed = claims.map((claim, index) => {
    const reading = readings[index];
    if (!validReading(claim, reading)) throw new Error('claim-reading');
    const base = { claim: index, ...declaredClaim(claim), ...readingFields(reading) };
    const kind = claimClause(reading.reading);
    if (kind) { const d = decideClause({ kind, select: claim.select }, windows, role, { walUpgrade }); return { ...base, ...d, kind, select: claim.select }; }
    const notRequired = reading.reading === 'untriggered' && claim.untriggered === 'no-requirement';
    return { ...base, kind: null, verdict: notRequired ? NOT_REQUIRED : 'inconclusive', matched: 0, basis: CLAIM_BASIS[notRequired ? NOT_REQUIRED : reading.reading], authoritative: false, custody: null };
  });
  // Suspend-aware custody time (src/suspend-clock.mjs): every decision carries its check's suspend record and unchecked flag. They
  // are not sealed with it (the validator recomputes them from the sealed windows), and only the row's text reads them
  // (effectAssertionRows), after every later stage has added its reason. No verdict reads them.
  // FIX-04 option 3: each core clause, and each claim that selected one, carries the hosts its egress windows saw sends to that are not
  // declared destinations (undeclaredHostsSeen), the same way: recomputed from the sealed windows, read only by the row's text.
  const listed = [...decided, ...claimed].map(d => { const hosts = d.kind && d.kind !== ONLY_KIND ? undeclaredHostsSeen(d.select, windows) : []; return hosts.length ? { ...d, undeclaredSeen: hosts } : d; })
    // Supabase rules (NC9 item 3): a declared clause pinned to a principal that reads missing names the service-role tools whose
    // writes it selects without its pin (serviceRoleSeen), the same way: recomputed from the sealed windows, read only by the text.
    .map(d => { const tools = !isClaim(d) && d.kind && d.kind !== ONLY_KIND && d.verdict === 'missing' ? serviceRoleToolsSeen(d.select, windows) : []; return tools.length ? { ...d, serviceRoleSeen: tools } : d; });
  const held = windows.find(w => w?.suspend)?.suspend ?? null, unchecked = windows.some(w => w?.suspendUnchecked === true);
  if (!held && !unchecked) return listed;
  return listed.map(d => ({ ...d, ...(held ? { suspendHeld: held } : {}), ...(unchecked ? { suspendUnchecked: true } : {}) }));
}
// FIX-04 option 3 (SURPASS-BYPASS-01 A-32): the hosts, sorted, that the egress windows which can see a clause's selector recorded sends to
// although they are not declared destinations (a stray request to the witness host included). A declared alias is recorded under its
// destination, so it is never listed. Only windows admitted for it are read (src/effect-events.mjs admitDisclosure: this build's own, or
// a sealed one under egress-recorder/11), so an earlier build's run keeps its text. Text only: no verdict reads it. FIX-08: a window that
// sees the clause through another recorder's destination (scope.cross) is read too, and that destination is a declared one, never listed.
export function undeclaredHostsSeen(select, windows) {
  const hosts = new Set();
  const declared = (w, name) => w.scope.names.includes(name) || (w.scope.cross !== null && typeof w.scope.cross === 'object' && Object.hasOwn(w.scope.cross, name));
  if (select !== null && typeof select === 'object') for (const w of windows) if (w?.source === 'http-egress' && disclosureAdmitted(w) && Array.isArray(w.scope?.names) && windowSees(w, select)) for (const e of w.events) if (!declared(w, e.name)) hosts.add(e.name);
  return [...hosts].sort();
}
export const UNDECLARED_LISTED = 5;
// Supabase rules (NC9 item 3; integrations/observers/supabase-rules.mjs serviceRoleNotes): a capture whose resolver is the Supabase
// rules' names a service-role write's actor unlisted:tool:<tool>, never an end user. The tools whose committed writes a clause pinned to
// a declared principal selects without its pin, in the Postgres windows that name principals (pg-snapshot and pg-wal with actor
// capture), sorted. Text only: no verdict reads it.
export const SERVICE_ACTOR_PREFIX = 'unlisted:tool:';
export function serviceRoleToolsSeen(select, windows) {
  if (select === null || typeof select !== 'object' || typeof select.actor !== 'string' || select.actor.startsWith('unlisted:')) return [];
  const { actor: _pin, ...rest } = select, tools = new Set();
  for (const w of windows) if (/^pg-(snapshot|wal)-/.test(w?.instanceId ?? '') && w.scope?.actorAttribution === 'principal' && Array.isArray(w.events))
    for (const e of w.events) if (typeof e.actor === 'string' && e.actor.startsWith(SERVICE_ACTOR_PREFIX) && matches(e, { ...rest, outcome: 'committed' })) tools.add(e.actor.slice(SERVICE_ACTOR_PREFIX.length));
  return [...tools].sort();
}
// rls-zero-row (NC9 item 3; integrations/observers/supabase-rules.mjs rlsZeroRow), FAIL-only. An allowed-use control that declares its
// expected write (a target's supabaseRules.allowedWrites, src/contracts.mjs) seals its capturing observer's zero-row facts for the
// control's own window (data.zeroRow: { instanceId, expect: { table, op }, facts }; the facts are the collector's, read from the actor
// capture's ledger, integrations/observers/supabase-rules.mjs zeroRowFacts). The control's positive clause on that write reads fail,
// rls-zero-row, when all of these hold:
//   - the response contract decided success: the status assertion and every response predicate passed on a complete response;
//   - the capture verified intact at both marks, and no write of the window was left unlisted (omitted);
//   - the window holds an UPDATE or DELETE of that table that changed no row (with no other change to the table in its transaction),
//     by the control's own principal and not under a service role;
//   - no statement of that table and operation changed a row in the window by that principal or under a service role.
// Otherwise nothing changes. It reads after every other stage (src/http-connector.mjs resealEffects; recomputeEffectTrace below),
// never passes and never touches a fail; another principal's write of the table is named on the finding (alsoWrittenBy). It is not
// authoritative: backend evidence stays what the windows decided.
export const ZERO_ROW_SCHEMA = 'scopehaven-pg-zero-row/1'; // integrations/observers/supabase-rules.mjs ZERO_ROW_FACTS_SCHEMA
export const ZERO_ROW_FINDING = 'rls-zero-row';
const ZERO_ROW_LISTED = 64, ZERO_ROW_WRITES = Object.freeze(['POST', 'PUT', 'PATCH', 'DELETE']), CAPTURE_STATES = Object.freeze(['intact', 'absent', 'altered', 'unreadable']);
const qualifiedTable = t => typeof t === 'string' && /^[A-Za-z_][A-Za-z0-9_]{0,62}\.[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(t);
const zeroActor = a => a === null || (typeof a === 'string' && a.length >= 1 && a.length <= 200);
const exactKeys = (o, keys) => o !== null && typeof o === 'object' && !Array.isArray(o) && Reflect.ownKeys(o).length === keys.length && keys.every(k => Object.hasOwn(o, k));
// The positive clause a declared write is judged on: an effect.exists, or an effect.count of at least one, selecting the snapshot
// source, the table's name (as pg-snapshot names its events) and the operation.
export const zeroRowClause = (e, table, op) => (e?.kind === 'effect.exists' || (e?.kind === 'effect.count' && Number.isInteger(e.expected) && e.expected >= 1))
  && e.select?.source === 'sql-snapshot' && e.select.name === table && typeof op === 'string' && e.select.operation === op.toLowerCase();
export function validZeroRowRecord(r, declaredObservers = []) {
  if (!exactKeys(r, ['instanceId', 'expect', 'facts']) || !exactKeys(r.expect, ['table', 'op']) || !qualifiedTable(r.expect.table) || !['UPDATE', 'DELETE'].includes(r.expect.op)) return false;
  if (!(Array.isArray(declaredObservers) && declaredObservers.some(o => o?.type === 'pg-snapshot' && observerInstanceId(o.type, o.id) === r.instanceId))) return false;
  const f = r.facts;
  if (!exactKeys(f, ['schema', 'capture', 'statements', 'writes', 'omitted']) || f.schema !== ZERO_ROW_SCHEMA || !CAPTURE_STATES.includes(f.capture) || !exactKeys(f.omitted, ['statements', 'writes'])
    || ![f.omitted.statements, f.omitted.writes].every(n => Number.isSafeInteger(n) && n >= 0)) return false;
  if (!Array.isArray(f.statements) || f.statements.length > ZERO_ROW_LISTED || !f.statements.every(x => exactKeys(x, ['table', 'op', 'actor', 'serviceRole', 'depth']) && qualifiedTable(x.table)
    && ['UPDATE', 'DELETE'].includes(x.op) && zeroActor(x.actor) && typeof x.serviceRole === 'boolean' && Number.isInteger(x.depth) && x.depth >= 1 && x.depth <= 999)) return false;
  if (!Array.isArray(f.writes) || f.writes.length > ZERO_ROW_LISTED || !f.writes.every(x => exactKeys(x, ['table', 'op', 'actor', 'serviceRole']) && qualifiedTable(x.table)
    && ['INSERT', 'UPDATE', 'DELETE'].includes(x.op) && zeroActor(x.actor) && typeof x.serviceRole === 'boolean')) return false;
  // A capture that did not verify intact lists nothing.
  return f.capture === 'intact' || (!f.statements.length && !f.writes.length && f.omitted.statements === 0 && f.omitted.writes === 0);
}
// The record against its observer's sealed window (PR520 review MAJOR 2, hardening): an intact record that lists every write names a
// write of each table by each principal the window attributes an event to, so facts that contradict the window are refused.
export const zeroRowAgreesWithWindow = (r, windows) => r.facts.capture !== 'intact' || r.facts.omitted.writes !== 0
  || (windows.find(w => w?.instanceId === r.instanceId)?.events ?? []).filter(e => typeof e?.actor === 'string').every(e => r.facts.writes.some(x => x.table.slice(x.table.indexOf('.') + 1) === e.name && x.actor === e.actor));
// The response contract decided as success: a complete response on which the status assertion and every response predicate passed (the
// effect, claim, backend, identity and precondition assertions are read elsewhere). The connector and the validator read the same row.
const NOT_RESPONSE = Object.freeze([BACKEND_ASSERTION, 'Actor identity established by required controls', 'Request precondition established']);
export const responseContractSucceeded = row => row?.observed?.complete === true && Array.isArray(row.assertions) && row.assertions.some(a => a?.name === 'HTTP status matches contract')
  && row.assertions.filter(a => !(EFFECT_ASSERTION_PATTERN.test(a?.name ?? '') || CLAIM_ASSERTION_PATTERN.test(a?.name ?? '') || NOT_RESPONSE.includes(a?.name))).every(a => a?.status === 'pass');
// The finding for one control row: { finding, table, op, statements, trigger?, alsoWrittenBy? } when it fails, else null.
export function zeroRowFinding(record, { principal, role, method, succeeded } = {}) {
  if (!record || role !== 'control' || !ZERO_ROW_WRITES.includes(method) || succeeded !== true || typeof principal !== 'string') return null;
  const { expect, facts } = record;
  if (facts.capture !== 'intact' || facts.omitted.writes !== 0) return null;
  const mine = facts.statements.filter(x => !x.serviceRole && x.actor === principal && x.table === expect.table && x.op === expect.op);
  const writers = facts.writes.filter(x => x.table === expect.table && x.op === expect.op);
  // A write no one is named for (another backend session, a claim the capture could not bind) may be the control's own: no FAIL
  // (PR520 review MINOR 1); another named principal's write is named on the finding.
  if (!mine.length || writers.some(x => x.serviceRole || x.actor === principal || x.actor === null)) return null;
  const others = [...new Set(writers.map(x => x.actor))].sort().slice(0, 8);
  return { finding: ZERO_ROW_FINDING, table: expect.table, op: expect.op, statements: mine.length, ...(mine.every(x => x.depth > 1) ? { trigger: true } : {}), ...(others.length ? { alsoWrittenBy: others } : {}) };
}
const zeroRowBasis = f => `${ZERO_ROW_FINDING}: the allowed-use control's declared ${f.op} on ${f.table} changed no row in ${f.statements} statement(s) under its own principal${f.trigger ? ' (issued by a trigger the request fired)' : ''}, although its response contract decided success, and no statement of that table and operation by it or a service role changed a row in the window, so the write the application reported was refused (row-level security, or a filter that matched nothing).${f.alsoWrittenBy ? ` Another principal changed rows of that table meanwhile: ${f.alsoWrittenBy.join(', ')}.` : ''} The windows alone read ${f.priorVerdict}; backend evidence stays what they decided.`;
// Apply a control's finding to its positive clause on the declared write; a fail is never touched.
export function applyZeroRow(decisions, finding, expect) {
  if (!finding || !expect) return decisions;
  const table = expect.table.slice(expect.table.indexOf('.') + 1);
  const at = decisions.findIndex(d => !isClaim(d) && zeroRowClause(d, table, expect.op));
  if (at < 0) return decisions;
  return decisions.map((d, i) => (i !== at || d.verdict === 'fail' ? d : { ...d, verdict: 'fail', basis: `${d.basis} ${zeroRowBasis({ ...finding, priorVerdict: d.verdict })}`, zeroRow: { ...finding, priorVerdict: d.verdict } }));
}
export const zeroRowFields = d => (d?.zeroRow ? { zeroRow: d.zeroRow } : {});
const serviceRoleText = d => (Array.isArray(d.serviceRoleSeen) && d.serviceRoleSeen.length ? ` A committed write this clause selects without its actor pin was made with a service role by ${d.serviceRoleSeen.slice(0, UNDECLARED_LISTED).join(', ')}, which carries no end user, so it is never ${d.select.actor}'s (service-role-write).` : '');
const undeclaredText = d => (Array.isArray(d.undeclaredSeen) && d.undeclaredSeen.length ? ` Its egress windows also recorded sends to hosts that are not declared destinations: ${d.undeclaredSeen.slice(0, UNDECLARED_LISTED).join(', ')}${d.undeclaredSeen.length > UNDECLARED_LISTED ? `, and ${d.undeclaredSeen.length - UNDECLARED_LISTED} more` : ''}.` : '');
// A decision that complete coverage decided: an effect.none pass, an effect.exists fail, an effect.count pass or fail, an effect.only pass.
const restsOnCoverage = d => (d.kind === 'effect.none' && d.verdict === 'pass') || (d.kind === 'effect.exists' && d.verdict === 'fail')
  || (d.kind === 'effect.count' && ['pass', 'fail'].includes(d.verdict)) || (d.kind === ONLY_KIND && d.verdict === 'pass');
// The sentences a row decided on complete coverage ends with when its check's windows carry a suspend record or could not be checked.
// Appended after the basis and every stage's reason in it (the undeclared-host note, FIX-04 option 3, after it), so the 600-character cap
// cuts these notes, never a reason.
const suspendText = d => (restsOnCoverage(d) ? `${d.suspendHeld ? ` ${suspendHeldNote(d.suspendHeld)}` : ''}${d.suspendUnchecked ? ` ${SUSPEND_UNCHECKED_NOTE}` : ''}` : '');
const isClaim = d => d?.claim !== undefined;
// The declared-effect decisions and the claim decisions of one check's decision list.
export const effectDecisionsOf = decisions => decisions.filter(d => !isClaim(d));
export const claimDecisionsOf = decisions => decisions.filter(isClaim);
// Which verdicts an authoritative observer decided. Absence (effect.none pass,
// effect.exists fail) is only ever reached on authoritative coverage, and an
// exact count only on one authoritative observer (effect-events.mjs). A recorded
// match (effect.exists pass, effect.none fail) counts only when an authoritative
// observer recorded it: presence-only telemetry shows an effect happened, but
// never makes backend evidence observed on its own.
function decidedAuthoritatively(effect, verdict, windows) {
  if (!['pass', 'fail'].includes(verdict)) return false;
  if (effect.kind === 'effect.count') return true;
  if ((effect.kind === 'effect.none') === (verdict === 'pass')) return true;
  return windows.some(w => w.scope?.evidence === 'authoritative' && windowSees(w, effect.select) && w.events.some(e => matches(e, { ...effect.select, outcome: 'committed' })));
}
// A not-required claim (untriggered, declared no-requirement) is not counted.
export const backendObserved = decisions => { const counted = decisions.filter(d => d.verdict !== NOT_REQUIRED); return counted.length > 0 && counted.every(d => d.authoritative); };

// The assertions a row carries for its declared effects, then for its claims (a not-required claim has none).
const CLAIM_EXPECTED = Object.freeze({ success: 'The response claimed success: a matching committed effect in the records', refusal: 'The response claimed a refusal: no matching committed effect in the records' });
export function effectAssertionRows(decisions) {
  const effects = effectDecisionsOf(decisions).map((d, index) => ({ name: effectAssertionName(index, d.kind), status: effectStatus(d.verdict),
    expected: d.kind === ONLY_KIND ? `Every committed effect is an expected one within its count, or allowed${d.countBy !== undefined ? '; an exact keyed replay counts with its application' : ''}` : d.kind === 'effect.none' ? 'No matching committed effect' : d.kind === 'effect.exists' ? 'A matching committed effect' : d.countBy !== undefined ? `Exactly ${d.expected} application(s): matching committed sends, an exact keyed replay counted once` : `Exactly ${d.expected} matching committed effect(s)`,
    actual: `${d.verdict}: ${d.basis}${suspendText(d)}${undeclaredText(d)}${serviceRoleText(d)}`.slice(0, 600), ...custodyFields(d), ...settlementFields(d), ...attributionFields(d), ...pairingFields(d), ...appLogFields(d), ...laterFields(d), ...absenceFields(d), ...zeroRowFields(d) }));
  const claims = claimDecisionsOf(decisions).filter(d => d.verdict !== NOT_REQUIRED).map(d => ({ name: claimAssertionName(d.claim, d.reading), status: effectStatus(d.verdict),
    expected: CLAIM_EXPECTED[d.reading] ?? 'A declared claim the records can decide', actual: `${d.verdict}: ${d.basis}${suspendText(d)}${undeclaredText(d)}`.slice(0, 600), ...custodyFields(d), ...settlementFields(d), ...attributionFields(d), ...pairingFields(d), ...appLogFields(d), ...laterFields(d), ...absenceFields(d) }));
  return [...effects, ...claims];
}
// A stored claim record: the declared claim, its reading and what was decided.
const CLAIM_RECORD_KEYS = Object.freeze(['trigger', 'select', 'untriggered', 'semantics', 'reading', 'phraseIndex', 'valueIndex', 'clause', 'verdict', 'matched', 'custody', 'custodyReason', 'custodyUpgrade', 'settlement', 'settlementNote', 'attribution', 'pairing', 'appLog', 'later', 'laterStrength', 'absenceDecided', 'resolution']);
const claimRecord = d => ({ ...declaredClaim(d), ...readingFields(d), clause: d.kind, verdict: d.verdict, matched: d.matched, ...custodyFields(d), ...settlementFields(d), ...attributionFields(d), ...pairingFields(d), ...appLogFields(d), ...laterFields(d), ...absenceFields(d), ...resolutionFields(d) });
// The sealed trace entry: the declared effects, their decisions and every window,
// events included. meta maps an instance id to its observer kind and declared settle.
// appLogWindows: the check's app-log windows (one per declared app log), sealed as data.appLogWindows; null without app logs.
// resolutions (IDR-2): the late resolver records the run-end stage bound on the windows' attempts (src/in-doubt.mjs sealedResolutions), only
// when there are any, so they are under the row's evidence digest and a row without them seals exactly as before.
// zeroRow: an allowed-use control's sealed zero-row record (NC9 item 3, below), or null.
export function effectTrace(decisions, windows, meta, appLogWindows = null, zeroRow = null) {
  const claims = claimDecisionsOf(decisions), resolutions = sealedResolutions(windows);
  return { type: 'effect-observation', label: 'Independent observer windows for this check; events carry identifiers and digests, plus declared captured body fields where an observer declares them',
    data: { schema: EFFECT_EVIDENCE_SCHEMA,
      effects: effectDecisionsOf(decisions).map(d => ({ ...declaredEffect(d), ...applicationsFields(d), verdict: d.verdict, matched: d.matched, ...(d.kind === ONLY_KIND ? { counts: d.counts } : {}), ...custodyFields(d), ...settlementFields(d), ...attributionFields(d), ...pairingFields(d), ...appLogFields(d), ...laterFields(d), ...absenceFields(d), ...resolutionFields(d), ...zeroRowFields(d) })),
      ...(claims.length ? { claims: claims.map(claimRecord) } : {}),
      windows: sealWindows(windows, meta), ...(appLogWindows ? { appLogWindows: sealAppLogWindows(appLogWindows) } : {}), ...(resolutions.length ? { resolutions } : {}), ...(zeroRow ? { zeroRow } : {}) } };
}
// The run-end re-decide stage (IDR-2; IN-DOUBT-DESIGN-ADDENDUM-R1 1.6, ADDENDUM-R2 m7). The connector runs it after the final mark's resolver
// reads and the follow rule, before settlement (src/http-connector.mjs). rows: the run's effect rows in order, each { effects, claims,
// readings, role, windows } as the connector decided them (windows the admitted, possibly unfollowed, check windows); supplied: what the
// observers' resolver reads returned, { observer, seq, records } items. Per row, the records for its own attempts (src/in-doubt.mjs
// lateEntriesFor) are bound onto their events and the row is decided again by decideEffects. When some clause reads an attempt whose records
// changed (its resolution says redecided), those decisions are returned; otherwise the binding is undone and the row reads null, unchanged.
// resealEffects never decides; only this stage and the follow rule do, both through decideEffects, as the validator decides a sealed row.
// skip(row): a row that takes no late record (the connector passes a lifecycle change check's: its post-change checks were gated on its
// status when it was sent, and the validator compares that with the final row, so a late lift would refuse the run; PR348-REVIEW minor 3).
export function redecideResolved(rows, supplied, { skip = () => false } = {}) {
  custodyRunWindows(rows, [], [], 'redecideResolved');
  return (Array.isArray(rows) ? rows : []).map(r => {
    if (skip(r) === true) return null;
    const entries = lateEntriesFor(r.windows, supplied);
    if (!entries.length) return null;
    bindResolutions(r.windows, entries);
    const decisions = decideEffects(r.effects, r.windows, { role: r.role, claims: r.claims, readings: r.readings });
    if (decisions.some(d => d.resolution?.redecided === true)) return decisions;
    bindResolutions(r.windows, []);
    return null;
  });
}
// The validator's side of the stage: a sealed row's late records (data.resolutions: absent, or a non-empty list exactly as sealedResolutions
// reads it back) bound onto the windows bindSealedWindows returned, before anything decides them; absent, every attempt is unbound. A
// malformed, reordered, misplaced or inapplicable record is refused (effect-trace), and nothing stays bound. In this build every record is.
export function bindSealedResolutions(windows, resolutions) {
  const refuse = () => { bindResolutions(windows, []); throw new Error('effect-trace'); };
  if (resolutions !== undefined && !(Array.isArray(resolutions) && resolutions.length > 0)) refuse();
  try { bindResolutions(windows, resolutions ?? []); } catch { refuse(); }
  if (resolutions !== undefined && digest(sealedResolutions(windows)) !== digest(resolutions)) refuse();
  return windows;
}
// The claims and readings a sealed trace carries, revalidated: each record has only its own keys, a valid
// declared claim, and a reading consistent with it. Returns { claims, readings } (empty when there are none).
export function sealedClaims(data) {
  if (data?.claims === undefined) return { claims: [], readings: [] };
  if (!Array.isArray(data.claims) || !data.claims.length || data.claims.length > CLAIM_LIMITS.claims || data.claims.some(c => c === null || typeof c !== 'object' || Array.isArray(c) || Reflect.ownKeys(c).some(key => !CLAIM_RECORD_KEYS.includes(key)))) throw new Error('effect-trace');
  const claims = data.claims.map(declaredClaim);
  try { validateDeclaredClaims(claims); } catch { throw new Error('effect-trace'); }
  const readings = data.claims.map(readingFields);
  if (!readings.every((r, i) => validReading(claims[i], r))) throw new Error('effect-trace');
  return { claims, readings };
}
// Decide a sealed trace's clauses again (declared effects, then claims), as the run validator does, with the row's sealed late records bound.
export const decideSealed = (data, windows, role) => decideEffects(data.effects.map(declaredEffect), bindSealedResolutions(windows, data.resolutions), { role, ...sealedClaims(data) });
// Sealed windows (a check's own, or a run's settlement gaps): events and coverage, with each observer's declared settle and lineage.
// suspend: a host suspend the window overlapped (src/suspend-clock.mjs), sealed so the validator recomputes the same basis text.
// declaration: a pg-wal window's pg_net declaration (src/effect-events.mjs collectWindow), sealed word for word so a reader sees whose word it rests on.
export const sealWindows = (windows, meta) => windows.map(w => ({ source: w.source, instanceId: w.instanceId, scope: w.scope, coverage: w.coverage, reason: w.reason ?? null, events: w.events, ...(w.exact ? { exact: w.exact } : {}), ...(w.declaration ? { declaration: w.declaration } : {}), ...(w.scoped ? { scoped: w.scoped } : {}), ...(w.suspend ? { suspend: w.suspend } : {}), ...(w.suspendUnchecked === true ? { suspendUnchecked: true } : {}),
  settleMs: meta.get(w.instanceId)?.settleMs ?? null,
  lineage: { observer: meta.get(w.instanceId)?.kind ?? 'unknown', independence: LINEAGE_BY_SOURCE[w.source] ?? 'unknown' } }));
// Recompute a sealed effect trace: windows are revalidated and bound to the
// declared observers (one window per observer, its source, kind and settle),
// the settle rule is re-applied, and every decision is recomputed (custody
// included, under the check's role); the row's effect assertions and backend
// fields must match.
// findings: this row's settlement findings (src/http-settlement.mjs), attribution: its attribution findings
// (src/http-attribution.mjs) and pairing: its pairing findings (src/http-pairing.mjs), all recomputed by the caller from the
// whole run. The attribution tag is compared on every clause, so a tag on a run that declares no attribution is refused.
// declaredClaimsDigest: with an exported suite, the digest of the check's declared claims (or null when it declares none).
// responseRead: whether the row's response was complete valid JSON; when it was not, every claim must read unreadable.
// appLogs: the run's app-log records (src/app-log-verdicts.mjs), or null: a trace carries its app-log windows exactly when the run
// declares app logs, and they are bound to those records apart from the observer windows. admission: { principal, background,
// earlier } for this row (src/app-log-verdicts.mjs admissionsFor), applied last, after pairing; only fails, never a pass.
// later: this row's later-outcome findings (src/later-outcome.mjs laterFindings, recomputed by the caller from the whole run), applied after
// admissions to a clause that still passes; admissions are read from the decisions after pairing, as before.
export function recomputeEffectTrace(trace, declaredEffects, declaredObservers, { role = 'boundary', findings = null, attribution = null, pairing = null, declaredClaimsDigest, responseRead = true, unfollowed = null, appLogs = null, admission = null, later = null, zeroRow: zeroRowContext = null } = {}) {
  const data = trace?.data;
  if (trace?.type !== 'effect-observation' || data === null || typeof data !== 'object' || data.schema !== EFFECT_EVIDENCE_SCHEMA || !Array.isArray(data.effects) || !Array.isArray(data.windows)) throw new Error('effect-trace');
  const sealed = sealedClaims(data);
  // A row's effect trace carries at least one declared effect, claim rule or read-back table (src/http-readback.mjs).
  if ((!data.effects.length && !sealed.claims.length && data.readBack === undefined) || data.effects.length > MAX_EFFECTS || data.windows.length > 16) throw new Error('effect-trace');
  // The run-end re-decide stage, mirrored (IDR-2): the row's sealed late records are bound onto its windows before any decision.
  const windows = bindSealedResolutions(bindSealedWindows(data.windows, declaredObservers, { scoped: true, unfollowed }), data.resolutions);
  const appLogWindows = bindAppLogWindows(data.appLogWindows, appLogs);
  // A stored effect.only clause carries its declared fields and what was decided, nothing else (settlementNote: the judged note
  // of src/http-settlement.mjs, compared below with the recomputed one like every settlement field).
  if (data.effects.some(e => e?.kind === ONLY_KIND && Reflect.ownKeys(e).some(key => ![...ONLY_FIELDS, 'verdict', 'matched', 'counts', 'custody', 'custodyReason', 'custodyUpgrade', 'settlement', 'settlementNote', 'attribution', 'pairing', 'appLog', 'resolution'].includes(key)))) throw new Error('effect-trace');
  // Later-outcome fields belong only to a positive core clause (src/later-outcome.mjs).
  if (data.effects.some(e => e !== null && typeof e === 'object' && (Object.hasOwn(e, 'later') || Object.hasOwn(e, 'laterStrength')) && !(e.kind === 'effect.exists' || (e.kind === 'effect.count' && e.expected >= 1)))) throw new Error('effect-trace');
  // An absence tag is only ever true, and only on a fail (its value is then compared with the recomputed one below).
  if ([...data.effects, ...(data.claims ?? [])].some(e => e !== null && typeof e === 'object' && Object.hasOwn(e, 'absenceDecided') && !(e.absenceDecided === true && e.verdict === 'fail'))) throw new Error('effect-trace');
  // A stored application interval belongs only to a countBy clause.
  if (data.effects.some(e => e !== null && typeof e === 'object' && Object.hasOwn(e, 'applications') && e.countBy === undefined)) throw new Error('effect-trace');
  const effects = data.effects.map(declaredEffect);
  if (declaredEffects !== undefined && digest(effects) !== digest(declaredEffects ?? [])) throw new Error('unexpected-suite-evidence');
  // outcomeJudged, checked again against the run's declared object routes (IN-DOUBT-LEAD-RULING-IDR0 R-3): a sealed clause the profile
  // loader would refuse is refused here too.
  const destinations = recordedDestinations(declaredObservers), forbidden = forbiddenSelectors(effects, sealed.claims);
  if (effects.some(e => e?.kind === ONLY_KIND && Array.isArray(e.outcomeJudged) && outcomeJudgedProfileProblem(e, destinations, forbidden) !== null)) throw new Error('effect-trace');
  if (declaredClaimsDigest !== undefined && (sealed.claims.length ? digest(sealed.claims) : null) !== declaredClaimsDigest) throw new Error('unexpected-suite-evidence');
  // The reply is discarded after reading: a response that was not complete valid JSON can only have read unreadable.
  if (!responseRead && sealed.readings.some(r => r.reading !== 'unreadable')) throw new Error('effect-verdict');
  // walUpgrade: whether a degraded Postgres absence names a pg-wal observer as its upgrade (NC9 item 4). A run recorded before that
  // carries the text main wrote, which is accepted as well, so an earlier record still validates (PR518-520-521 stack review MAJOR 1):
  // only that text differs, and custody and its reason are bound either way.
  const decide = walUpgrade => {
    const raw = decideEffects(effects, windows, { role, ...sealed, walUpgrade });
    // Late records are sealed only on a row the stage decided again: some clause read an attempt they changed.
    if (data.resolutions !== undefined && !raw.some(d => d.resolution?.redecided === true)) throw new Error('effect-trace');
    const paired = applyPairing(applyAttribution(applySettlement(raw, findings, role), attribution, role), pairing, role);
    const admitted = applyLater(applyAdmissions(paired, admissionsFor(paired, { windows, appLogWindows, records: appLogs, ...(admission ?? {}) })), later);
    // rls-zero-row (NC9 item 3), last: a sealed record only on an allowed-use control that writes, and the finding only from it.
    if (data.zeroRow !== undefined && !(role === 'control' && ZERO_ROW_WRITES.includes(zeroRowContext?.method) && validZeroRowRecord(data.zeroRow, declaredObservers) && zeroRowAgreesWithWindow(data.zeroRow, windows))) throw new Error('effect-trace');
    return data.zeroRow === undefined ? admitted : applyZeroRow(admitted, zeroRowFinding(data.zeroRow, { ...zeroRowContext, role }), data.zeroRow.expect);
  };
  const stored = [...data.effects, ...(data.claims ?? [])];
  const differs = (d, i) => (d.verdict !== stored[i].verdict || d.matched !== stored[i].matched || digest(custodyFields(d)) !== digest(custodyFields(stored[i]))
    || digest(settlementFields(d)) !== digest(settlementFields(stored[i])) || digest(attributionFields(d)) !== digest(attributionFields(stored[i])) || digest(pairingFields(d)) !== digest(pairingFields(stored[i])) || digest(zeroRowFields(d)) !== digest(zeroRowFields(stored[i])) || digest(appLogFields(d)) !== digest(appLogFields(stored[i])) || digest(laterFields(d)) !== digest(laterFields(stored[i])) || digest(absenceFields(d)) !== digest(absenceFields(stored[i])) || digest(applicationsFields(d)) !== digest(applicationsFields(stored[i])) || digest(resolutionFields(d)) !== digest(resolutionFields(stored[i])) || (d.kind === ONLY_KIND && digest(d.counts) !== digest(stored[i].counts ?? null))
    || (isClaim(d) && stored[i].clause !== d.kind));
  let decisions = decide(true);
  if (decisions.some(differs)) { decisions = decide(false); if (decisions.some(differs)) throw new Error('effect-verdict'); }
  return { decisions, rows: effectAssertionRows(decisions), backendObserved: backendObserved(decisions) };
}
// Revalidate sealed windows and bind them to the declared observers: one window per observer, its
// source, kind and settle; the settle rule is re-applied and exact entries are bound to the observer type.
// scoped (coverage v2): a row's own check windows may carry destination-scoped entries, admitted only for an egress-recorder
// record whose collector label is egress-recorder/2, /3 or /4, and an entry carrying a late request's seq and captured record
// (LATE-FIELDS) only under /4, with that seq after every event of the sealed window; unfollowed: the instance ids the run's follow
// rule left unfollowed for that row. Every other caller (settlement gaps and barriers included) refuses entries.
export function bindSealedWindows(sealed, declaredObservers, { scoped = false, unfollowed = null } = {}) {
  if (!Array.isArray(sealed) || sealed.length > 16 || !Array.isArray(declaredObservers) || sealed.length !== declaredObservers.length) throw new Error('effect-trace');
  const byInstance = new Map(declaredObservers.map(o => [observerInstanceId(o.type, o.id), o]));
  const windows = sealed.map((w, i) => {
    if (w === null || typeof w !== 'object' || typeof w.lineage !== 'object' || w.lineage === null || Object.keys(w.lineage).length !== 2) throw new Error('effect-trace');
    const { lineage, settleMs, ...window } = w;
    const declared = byInstance.get(window.instanceId);
    if (!declared || window.source !== OBSERVER_OUTPUT[declared.type].source || lineage.observer !== OBSERVER_OUTPUT[declared.type].kind
      || lineage.independence !== LINEAGE_BY_SOURCE[window.source] || settleMs !== declared.settleMs) throw new Error('effect-trace');
    if (!(window.reason === null || (typeof window.reason === 'string' && REASON_PATTERN.test(window.reason)))) throw new Error('effect-trace');
    if (window.events.length > EFFECT_LIMITS.eventsPerWindow) throw new Error('effect-trace');
    validateWindow(window, `window ${i + 1}`);
    // The settle cap is part of the evidence: an unsettled authoritative window cannot be stored complete.
    if (applySettle(window, settleMs) !== window) throw new Error('effect-trace');
    // Suspend-aware custody time (src/suspend-clock.mjs): a window whose sealed record holds a shortfall (its wait held less awake time
    // than declared) cannot be stored complete or scoped, and only such a window carries the shortfall code.
    if (applySuspendShort(window) !== window || (carriesSuspendShort(window) && !(window.suspend?.shortMs > 0 && window.scope?.evidence === 'authoritative' && window.coverage === 'partial'))) throw new Error('effect-trace');
    // Exact entries: change-column only from a SQLite or MySQL snapshot, xmin only from a Postgres snapshot.
    if (window.exact !== undefined && !window.exact.every(e => (e.method === 'xmin') === (declared.type === 'pg-snapshot') && ['sqlite-snapshot', 'pg-snapshot', 'mysql-snapshot'].includes(declared.type))) throw new Error('effect-trace');
    // Body-field capture: the window's scope publishes exactly the declared capture, and every captured record
    // on an event carries exactly the pointers declared for its name. A forged or partial declaration is refused.
    if (digest(window.scope.capture ?? null) !== digest(declared.capture ?? null)) throw new Error('effect-trace');
    if (!window.events.every(e => e.captured === undefined || (Array.isArray(window.scope.capture?.[e.name]) && (e.captured.status !== 'captured'
      || digest(Object.keys(e.captured.values).sort()) === digest([...window.scope.capture[e.name]].sort()))))) throw new Error('effect-trace');
    // Form-encoded capture: the scope lists exactly the declared form names, and a record read as a form (or refused as
    // not JSON) belongs only to a name declared that way.
    if (digest(window.scope.captureForm ?? null) !== digest(declared.captureForm ?? null)) throw new Error('effect-trace');
    if (!window.events.every(e => { const k = captureEncodingOf(e.captured); return k === null || (k === 'form') === (window.scope.captureForm ?? []).includes(e.name); })) throw new Error('effect-trace');
    // Keyed retries: the scope publishes exactly the declared key headers, and an event carries a key record exactly when
    // it is a send to a name declared that way.
    if (digest(window.scope.idempotency ?? null) !== digest(declared.idempotency ?? null)) throw new Error('effect-trace');
    if (!window.events.every(e => Object.hasOwn(e, 'idempotency') === (e.operation === 'send' && Object.hasOwn(window.scope.idempotency ?? {}, e.name)))) throw new Error('effect-trace');
    // Forwarding: the scope publishes exactly the declared forward, and every event's upstream outcome is the one its
    // recorded status reads under its name's declared statuses (only forwarded names carry one, and all of their sends do).
    if (digest(window.scope.forward ?? null) !== digest(declared.forward ?? null) || !upstreamBound(window)) throw new Error('effect-trace');
    // A forwarded send's target flags (exact, query) only from an egress recorder whose label is in TARGET_LABELS (egress-recorder/6).
    if (!(declared.type === 'egress-recorder' && TARGET_LABELS.includes(declared.collector?.label)) && window.events.some(e => e.upstream?.target !== undefined)) throw new Error('effect-trace');
    // In-doubt resolution, gate B (IDR-1): a send's transport record only from an egress recorder whose label is in IN_DOUBT_LABELS, and
    // only such a window is admitted for the backend tier's in-doubt condition (src/in-doubt.mjs).
    const inDoubtGate = declared.type === 'egress-recorder' && IN_DOUBT_LABELS.includes(declared.collector?.label);
    if (!inDoubtGate && window.events.some(e => e.upstream?.transport !== undefined)) throw new Error('effect-trace');
    // In-doubt resolution R1 (IDR-4): a window publishes exactly its recorder record's request feed (less the record's collector), only under a
    // label in REQUEST_FEED_LABELS (egress-recorder/8), and a send's transport carries an arrival exactly when it goes to one of that feed's hosts.
    // Admission (below) then marks the window's events for R1 (src/in-doubt.mjs).
    const feedDeclared = declared.type === 'egress-recorder' && declared.requestFeed !== null && typeof declared.requestFeed === 'object' ? (({ collector: _c, ...feed }) => feed)(declared.requestFeed) : null;
    if (digest(window.scope.requestFeed ?? null) !== digest(feedDeclared) || (feedDeclared !== null && !REQUEST_FEED_LABELS.includes(declared.collector?.label))) throw new Error('effect-trace');
    if (window.events.some(e => e.upstream?.transport !== undefined && transportArrival(e.upstream.transport) !== (feedDeclared !== null && Array.isArray(feedDeclared.hosts) && feedDeclared.hosts.includes(e.name)))) throw new Error('effect-trace');
    // In-doubt resolution R2 (IDR-3): a window publishes exactly its recorder record's read-back record, only under a label in READ_BACK_LABELS
    // (egress-recorder/9), and a send's upstream carries a read-back record exactly when it is a settled forward (one with its transport record)
    // to a host that record declares, its route index within that host's routes. Admission (below) then marks those events for R2.
    const readBackDeclared = declared.type === 'egress-recorder' && declared.readBack !== null && typeof declared.readBack === 'object' ? declared.readBack : null;
    if (digest(window.scope.readBack ?? null) !== digest(readBackDeclared) || (readBackDeclared !== null && !READ_BACK_LABELS.includes(declared.collector?.label))) throw new Error('effect-trace');
    if (window.events.some(e => (e.upstream?.readBack !== undefined) !== (readBackDeclared !== null && Object.hasOwn(readBackDeclared.hosts ?? {}, e.name) && e.upstream?.transport !== undefined)
      || (e.upstream?.readBack !== undefined && !validReadBackSend(e.upstream.readBack, readBackDeclared.hosts[e.name].routes)))) throw new Error('effect-trace');
    if (inDoubtGate) admitInDoubt(window);
    // FIX-04 (egress-recorder/11): a window publishes exactly its recorder record's aliases, only under a label in SIBLING_LABELS. Under such a
    // label, a window holding a send to an undeclared host that may be a destination under another name (src/egress-rules.mjs siblingsOf, read
    // from the window's own scope and events) is never complete, and when it carries entries, each such destination has one with the sibling
    // code; an entry with the sibling code names only such a destination. An earlier label's window carries neither aliases nor that code.
    const siblingGate = declared.type === 'egress-recorder' && SIBLING_LABELS.includes(declared.collector?.label);
    if (digest(window.scope.aliases ?? null) !== digest(declared.aliases ?? null) || (declared.aliases !== undefined && !siblingGate)) throw new Error('effect-trace');
    // FIX-08 (egress-recorder/13): a window publishes exactly its recorder record's cross destinations, only under a label in CROSS_LABELS, and
    // siblings are read over the run's names (its own and those). An earlier label's window publishes none and reads its own names alone.
    if (digest(window.scope.cross ?? null) !== digest(declared.cross ?? null) || (declared.cross !== undefined && !(declared.type === 'egress-recorder' && CROSS_LABELS.includes(declared.collector?.label)))) throw new Error('effect-trace');
    const runNames = [...(window.scope.names ?? []), ...Object.keys(window.scope.cross ?? {})], runAliases = window.scope.cross ? { ...(window.scope.aliases ?? {}), ...window.scope.cross } : window.scope.aliases ?? null;
    const siblingNames = new Set(siblingGate ? window.events.flatMap(e => siblingsOf(e.name, runNames, runAliases)) : []);
    const siblingEntries = Array.isArray(window.scoped) ? window.scoped.filter(e => e.codes.includes(SIBLING_CODE)) : [];
    if (siblingEntries.some(e => !siblingNames.has(e.name)) || (siblingNames.size && (window.coverage === 'complete'
      || (Array.isArray(window.scoped) && ![...siblingNames].every(n => siblingEntries.some(e => e.name === n)))))) throw new Error('effect-trace');
    // A /11 recorder records an alias's send under its destination, so no event is named by a published alias.
    if (window.scope.aliases !== undefined && window.events.some(e => Object.values(window.scope.aliases).some(list => Array.isArray(list) && list.includes(e.name)))) throw new Error('effect-trace');
    // A /13 recorder records a send to another recorder's alias under that destination, so no event is named by a published cross alias either.
    if (window.scope.cross !== undefined && window.events.some(e => Object.values(window.scope.cross).some(list => Array.isArray(list) && list.includes(e.name)))) throw new Error('effect-trace');
    if (siblingGate) admitDisclosure(window);
    // A provider feed is authoritative exactly when its declaration has a witness (the run record's "witnessed"), and every
    // window names the feed and key the run record does.
    if (declared.type === 'provider-feed' && (window.scope.evidence !== (declared.witnessed === true ? 'authoritative' : 'presence-only') || digest(window.scope.feed ?? null) !== digest(declared.feed ?? null))) throw new Error('effect-trace');
    // A provider feed's template records (feed v2) name only labels its run record lists (the capture binding above holds them to
    // declared domains and to /template alone).
    if (declared.type === 'provider-feed' && !window.events.every(e => e.captured?.values?.[TEMPLATE_POINTER]?.type !== 'string' || (Array.isArray(declared.feed?.templates) && declared.feed.templates.includes(e.captured.values[TEMPLATE_POINTER].value)))) throw new Error('effect-trace');
    if (Object.hasOwn(window, 'scoped')) {
      // Feed v2, Part B: a witnessed endpoint feed's check windows may carry them too (provider-feed/3), a lone entry's template
      // record naming a label the run record lists.
      const feedScoped = declared.type === 'provider-feed' && declared.witnessed === true && declared.feed?.route === 'endpoint';
      if (!scoped || !(declared.type === 'egress-recorder' || feedScoped) || !SCOPED_COLLECTOR_LABELS.includes(declared.collector?.label)
        || window.scoped.some(e => Object.hasOwn(e, 'captured') && (!CAPTURED_ENTRY_LABELS.includes(declared.collector?.label) || window.events.some(ev => ev.seq >= e.seq)))
        || (feedScoped && !window.scoped.every(e => e.captured?.values?.[TEMPLATE_POINTER]?.type !== 'string' || (Array.isArray(declared.feed?.templates) && declared.feed.templates.includes(e.captured.values[TEMPLATE_POINTER].value))))) throw new Error('effect-trace');
      admitScoped(window);
      // Feed v2, Part C: the template lift only for a run whose feed collector reads provider-feed/4.
      if (feedScoped && TEMPLATE_LIFT_LABELS.includes(declared.collector?.label)) admitTemplateLift(window);
      if (unfollowed?.has(window.instanceId)) markUnfollowed(window);
    }
    return window;
  });
  if (new Set(windows.map(w => w.instanceId)).size !== windows.length) throw new Error('effect-trace');
  return windows;
}
// The run-level record of declared observers: { id, type, settleMs } in profile order, and for an egress
// recorder that declares body-field capture, capture: { [host]: [pointer, ...] } (src/body-fields.mjs), and
// captureForm: [host, ...] in profile order when some of those hosts also read form-encoded bodies, and
// idempotency: { [host]: declaration } when some destination declares a key header (src/idempotency.mjs).
// forward: { [host]: { upstreamPort, applied, rejected, proof } } when some destination forwards (src/effect-outcome.mjs).
// requestFeed: for an egress recorder that declares one (in-doubt resolution R1), its record (src/request-feed-rules.mjs requestFeedRecord)
// and the request-feed collector (request-feed/1, src/collector-identity.mjs). readBack: for an egress recorder some of whose destinations
// declare readBack (in-doubt resolution R2), its read-back record (src/read-back-rules.mjs readBackRecord); its reader is in the recorder's own
// collector files (egress-recorder/9).
// witnessed: for a provider feed, whether it declares a witness (its windows are authoritative only then), and feed: its
// { feedId, keyDigest, route } plus its template labels when it declares a vocabulary (src/provider-feed-rules.mjs), with
// capture: { [domain]: ["/template"] } then (feed v2).
const captureOf = o => {
  const destinations = o.type === 'egress-recorder' && Array.isArray(o.destinations) ? o.destinations : [];
  const form = destinations.filter(d => formEnabled(d?.capture)).map(d => d.host);
  return { ...(destinations.some(d => d?.capture) ? { capture: Object.fromEntries(destinations.filter(d => d?.capture).map(d => [d.host, [...d.capture.pointers]])) } : {}),
    ...(form.length ? { captureForm: form } : {}), ...forwardRecordOf(o), ...(o.type === 'provider-feed' && providerFeedCapture(o) ? { capture: providerFeedCapture(o) } : {}) };
};
// objects: { [host]: { paths?, fields? } } when some destination declares object routes (src/egress-rules.mjs objectRecordOf).
export const declaredObserverRecord = observers => observers.map(o => ({ id: o.id, type: o.type, settleMs: settleDeclared(o.settleMs) ? o.settleMs : null, ...captureOf(o), ...(idempotencyRecordOf(o) ? { idempotency: idempotencyRecordOf(o) } : {}), ...(objectRecordOf(o) ? { objects: objectRecordOf(o) } : {}), ...(COLLECTOR_RECORDS[o.type] ? { collector: COLLECTOR_RECORDS[o.type] } : {}),
  ...(o.type === 'provider-feed' ? { witnessed: o.witness !== undefined, feed: providerFeedRecord(o) } : {}),
  ...(o.type === 'egress-recorder' && o.requestFeed !== undefined ? { requestFeed: { ...requestFeedRecordOf(o.requestFeed), collector: COLLECTOR_RECORDS['request-feed'] } } : {}),
  ...(readBackRecordOf(o) ? { readBack: readBackRecordOf(o) } : {}), ...(aliasRecordOf(o) ? { aliases: aliasRecordOf(o) } : {}),
  // FIX-08 (egress-recorder/13): the destinations the run's other egress recorders declare that this one does not ({ [host]: [alias, ...] }).
  ...(crossRecordOf(crossDestinationsOf(o, observers)) ? { cross: crossRecordOf(crossDestinationsOf(o, observers)) } : {}) }));
