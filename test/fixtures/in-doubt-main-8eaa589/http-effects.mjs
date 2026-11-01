// Frozen copy of scopehaven/src/http-effects.mjs at 8eaa589 (main with IDR-1 and the suspend-aware lead-in and stop #344, before in-doubt resolution
// IDR-2; imports re-pointed: the frozen in-doubt, http-effects, effect-outcome, effect-events, idempotency, only.mjs and suspend-clock import
// one another, everything else the live src/). For test/in-doubt-redecide.test.mjs and test/in-doubt-redecide-stub.test.mjs differentials
// only. Not in any identity list.
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
//
// Claim rules (src/http-claims.mjs) are a check's `claims`: the response's reading selects
// effect.exists (a success claim) or effect.none (a refusal claim) over the same windows, and the
// records decide it exactly as a declared clause (custody, settlement, pairing). They are decided
// after the declared effects, stored apart from them (trace data.claims, so a run's declared
// effects signature never depends on what a reply said), and shown as "Observed claim N (reading)".
// An ambiguous, unreadable or untriggered reading is inconclusive; an untriggered claim declared
// no-requirement is not-required: no assertion row, and not counted for backend observation.
import { digest } from '../../../src/domain.mjs';
import { evaluateEffectAssertion, validateEffectAssertion, validateSelector, validateWindow, windowSees, matches, matchState, EFFECT_LIMITS, REASON_PATTERN } from './effect-events.mjs';
import { admitInDoubt, inDoubtAdmitted, fateOf, attemptBasis, operationOf } from './in-doubt.mjs';
import { validateClaims, declaredClaim, claimClause, validReading, readingFields, claimAssertionName, CLAIM_ASSERTION_PATTERN, CLAIM_BASIS, NOT_REQUIRED, CLAIM_LIMITS } from '../../../src/http-claims.mjs';
import { LINEAGE_BY_SOURCE } from '../../../src/effect-lineage.mjs';
import { clauseCustody, onlyClauseCustody, roleOfSeverity, CUSTODY_BASIS, ONLY_CUSTODY_BASIS } from '../../../src/custody.mjs';
import { judgeOnly, validateOnlyAssertion, onlyScopedComplete, outcomeJudgedOverlap, outcomeJudgedProfileProblem, outcomeJudgedSends, OnlyError, ONLY_KIND } from './only.mjs';
export { outcomeJudgedProfileProblem };
import { objectRecordOf } from '../../../src/egress-rules.mjs';
import { suspendHeldNote, applySuspendShort, carriesSuspendShort, SUSPEND_UNCHECKED_NOTE } from './suspend-clock.mjs';
// Settlement across a run's windows (src/http-settlement.mjs) and the positive-match pairing of absence selectors
// (src/http-pairing.mjs): both applied after custody, settlement first, never upgrading.
import { applySettlement, settlementFields } from '../../../src/http-settlement.mjs';
import { formEnabled, captureEncodingOf, TEMPLATE_POINTER } from '../../../src/body-fields.mjs';
import { idempotencyRecordOf } from './idempotency.mjs';
import { applyPairing, pairingFields } from '../../../src/http-pairing.mjs';
// Background attribution (src/http-attribution.mjs), applied after settlement and before pairing on runs that declare it.
import { applyAttribution, attributionFields } from '../../../src/http-attribution.mjs';
import { forwardRecordOf, upstreamBound, clauseSemanticsProblem, withoutUpstream } from './effect-outcome.mjs';
import { EffectError } from './effect-events.mjs';
import { COLLECTOR_RECORDS, SCOPED_COLLECTOR_LABELS, CAPTURED_ENTRY_LABELS, TEMPLATE_LIFT_LABELS, TARGET_LABELS, IN_DOUBT_LABELS } from '../../../src/collector-identity.mjs';
import { providerFeedRecord, providerFeedCapture } from '../../../src/provider-feed-rules.mjs';
import { admitScoped, admitTemplateLift, markUnfollowed, custodyWindows } from './effect-events.mjs';
// App logs (src/app-log-rules.mjs): sealed beside a check's windows as data.appLogWindows, never decided here.
import { sealAppLogWindows, bindAppLogWindows, admissionsFor, applyAdmissions, appLogFields } from '../../../src/app-log-verdicts.mjs';

export const EFFECT_EVIDENCE_SCHEMA = 'scopehaven-effect-evidence/1';
export const EFFECT_ASSERTION_PATTERN = /^Observed effect (\d{1,2}) \((effect\.none|effect\.exists|effect\.count|effect\.only)\)$/;
export const BACKEND_ASSERTION = 'Trusted backend observation available';
export const MAX_EFFECTS = 32;
// Observer types a profile may declare (built by integrations/observers/factory.mjs),
// and the effect source and observer kind each one produces. A sealed window must
// come from a declared observer: its instance id, source and kind are bound to it.
export const OBSERVER_TYPES = Object.freeze(['otel', 'sqlite-audit', 'sqlite-snapshot', 'http-audit', 'mcp-log', 'audit-file', 'pg-snapshot', 'egress-recorder', 'smtp-sink', 'mysql-snapshot', 'provider-feed']);
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
export const RESOLUTION_LISTED = 20;
function resolutionOf(selected, windows, select) {
  if (!windows.some(inDoubtAdmitted)) return null;
  const relevant = windows.filter(w => w.scope?.evidence === 'authoritative' && (select ? windowSees(w, select) : true));
  const covered = relevant.length > 0 && relevant.every(w => w.coverage === 'complete');
  const fates = selected.map(({ e }) => fateOf(e));
  const listed = selected.slice(0, RESOLUTION_LISTED).map(({ e, w }, i) => { const b = attemptBasis(e); return { observer: w.instanceId, seq: e.seq, fate: fates[i], by: b.by, ...(b.reason ? { reason: b.reason } : {}), resolvers: b.resolvers }; });
  return { ...operationOf(fates, { covered }), attempts: listed };
}
// The sends a resolved core clause selects in admitted windows: committed, and fitting its selector without the upstream pin (a field that
// could not be read counts as fitting).
const resolvedSelected = (select, windows) => windows.filter(w => inDoubtAdmitted(w) && windowSees(w, select))
  .flatMap(w => w.events.filter(e => matchState(e, { ...withoutUpstream(select), outcome: 'committed' }) !== 'no').map(e => ({ e, w })));
// A basis note only when some selected attempt had no proven reply: the operation and its counts.
const resolutionBasis = r => r && r.attempts.some(a => a.by !== 'proof')
  ? ` In-doubt resolution: operation ${r.operation}; ${r.applied} applied, ${r.refuted} refuted (a proven rejection, or a connection to the upstream that never completed), ${r.inDoubt} still in doubt.` : '';
const resolutionFields = d => d?.resolution ? { resolution: d.resolution } : {};
function decideOnly(effect, index, windows, role) {
  validateOnlyAssertion(effect, `effect ${index + 1}`, { fields: true, countBy: true });
  // SETTLE-V3 fix C: a scoped egress window whose every unattributed send is allowed and not expected covers it toward a pass.
  const result = judgeOnly(effect, windows, { fields: true, countBy: true, scopedComplete: onlyScopedComplete(effect, windows) });
  const held = onlyClauseCustody({ result, windows, role });
  const counts = onlyCounts(result.counts);
  // Backend evidence: a pass is reached only on authoritative coverage; a fail only when an
  // authoritative observer recorded an effect outside the declared set (any offender, not only the listed ones).
  const authoritative = result.verdict === 'pass' || (result.verdict === 'fail' && windows.some(w => w.scope?.evidence === 'authoritative'
    && result.offendingObservers.some(o => o.source === w.source && o.observer === w.instanceId)));
  const outside = result.offending.length ? ` Outside the declared set: ${offendingText(result.offending)}${counts.offending > 5 ? `; ${counts.offending - 5} more` : ''}.` : '';
  // outcomeJudged under gate B (IDR-1): the operation over the outcome-judged sends; backend evidence only when none is still in doubt.
  const resolution = Array.isArray(effect.outcomeJudged) ? resolutionOf(outcomeJudgedSends(effect, windows.filter(inDoubtAdmitted)), windows, null) : null;
  return { ...declaredEffect(effect), verdict: held.verdict, matched: counts.offending, counts,
    basis: `${result.basis}${outside}${resolutionBasis(resolution)}${held.custodyReason ? ` ${ONLY_CUSTODY_BASIS}` : ''}`, authoritative: authoritative && !(resolution && resolution.inDoubt), ...custodyFields(held), ...(resolution ? { resolution } : {}) };
}

// A core clause (effect.none, effect.exists, effect.count) decided over the windows, custody included. Exported for the later-outcome
// stage (src/later-outcome.mjs), which judges a positive clause again over its own windows without the sends that did not credit.
export function decideClause(effect, windows, role) {
  // scoped: the HTTP path reads destination-scoped egress entries (coverageFor reads only windows the connector or validator admitted).
  const decision = evaluateEffectAssertion(coreOf(effect), windows, { countBy: true, scoped: true });
  const held = clauseCustody({ kind: effect.kind, select: effect.select, verdict: decision.verdict, windows, role });
  // upstream "resolved" under gate B (IDR-1): the operation over the attempts the clause selects; backend evidence only when none is in doubt.
  const resolution = effect.select?.upstream === 'resolved' ? resolutionOf(resolvedSelected(effect.select, windows), windows, effect.select) : null;
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
export function decideEffects(effects, windows, { role = 'boundary', claims = [], readings = [] } = {}) {
  custodyWindows(windows, 'decideEffects');
  validateCheckEffects(effects, claims);
  const decided = effects.map((effect, index) => {
    if (effect?.kind === ONLY_KIND) return decideOnly(effect, index, windows, role);
    validateDeclaredEffect(effect, `effect ${index + 1}`);
    return decideClause(effect, windows, role);
  });
  if (claims.length !== readings.length) throw new Error('claim-readings');
  const claimed = claims.map((claim, index) => {
    const reading = readings[index];
    if (!validReading(claim, reading)) throw new Error('claim-reading');
    const base = { claim: index, ...declaredClaim(claim), ...readingFields(reading) };
    const kind = claimClause(reading.reading);
    if (kind) { const d = decideClause({ kind, select: claim.select }, windows, role); return { ...base, ...d, kind, select: claim.select }; }
    const notRequired = reading.reading === 'untriggered' && claim.untriggered === 'no-requirement';
    return { ...base, kind: null, verdict: notRequired ? NOT_REQUIRED : 'inconclusive', matched: 0, basis: CLAIM_BASIS[notRequired ? NOT_REQUIRED : reading.reading], authoritative: false, custody: null };
  });
  // Suspend-aware custody time (src/suspend-clock.mjs): every decision carries its check's suspend record and unchecked flag. They
  // are not sealed with it (the validator recomputes them from the sealed windows), and only the row's text reads them
  // (effectAssertionRows), after every later stage has added its reason. No verdict reads them.
  const held = windows.find(w => w?.suspend)?.suspend ?? null, unchecked = windows.some(w => w?.suspendUnchecked === true);
  if (!held && !unchecked) return [...decided, ...claimed];
  return [...decided, ...claimed].map(d => ({ ...d, ...(held ? { suspendHeld: held } : {}), ...(unchecked ? { suspendUnchecked: true } : {}) }));
}
// A decision that complete coverage decided: an effect.none pass, an effect.exists fail, an effect.count pass or fail, an effect.only pass.
const restsOnCoverage = d => (d.kind === 'effect.none' && d.verdict === 'pass') || (d.kind === 'effect.exists' && d.verdict === 'fail')
  || (d.kind === 'effect.count' && ['pass', 'fail'].includes(d.verdict)) || (d.kind === ONLY_KIND && d.verdict === 'pass');
// The sentences a row decided on complete coverage ends with when its check's windows carry a suspend record or could not be checked.
// Appended last, after the basis and every stage's reason in it, so the 600-character cap cuts this note, never a reason.
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
    actual: `${d.verdict}: ${d.basis}${suspendText(d)}`.slice(0, 600), ...custodyFields(d), ...settlementFields(d), ...attributionFields(d), ...pairingFields(d), ...appLogFields(d), ...laterFields(d), ...absenceFields(d) }));
  const claims = claimDecisionsOf(decisions).filter(d => d.verdict !== NOT_REQUIRED).map(d => ({ name: claimAssertionName(d.claim, d.reading), status: effectStatus(d.verdict),
    expected: CLAIM_EXPECTED[d.reading] ?? 'A declared claim the records can decide', actual: `${d.verdict}: ${d.basis}${suspendText(d)}`.slice(0, 600), ...custodyFields(d), ...settlementFields(d), ...attributionFields(d), ...pairingFields(d), ...appLogFields(d), ...laterFields(d), ...absenceFields(d) }));
  return [...effects, ...claims];
}
// A stored claim record: the declared claim, its reading and what was decided.
const CLAIM_RECORD_KEYS = Object.freeze(['trigger', 'select', 'untriggered', 'semantics', 'reading', 'phraseIndex', 'valueIndex', 'clause', 'verdict', 'matched', 'custody', 'custodyReason', 'custodyUpgrade', 'settlement', 'settlementNote', 'attribution', 'pairing', 'appLog', 'later', 'laterStrength', 'absenceDecided', 'resolution']);
const claimRecord = d => ({ ...declaredClaim(d), ...readingFields(d), clause: d.kind, verdict: d.verdict, matched: d.matched, ...custodyFields(d), ...settlementFields(d), ...attributionFields(d), ...pairingFields(d), ...appLogFields(d), ...laterFields(d), ...absenceFields(d), ...resolutionFields(d) });
// The sealed trace entry: the declared effects, their decisions and every window,
// events included. meta maps an instance id to its observer kind and declared settle.
// appLogWindows: the check's app-log windows (one per declared app log), sealed as data.appLogWindows; null without app logs.
export function effectTrace(decisions, windows, meta, appLogWindows = null) {
  const claims = claimDecisionsOf(decisions);
  return { type: 'effect-observation', label: 'Independent observer windows for this check; events carry identifiers and digests, plus declared captured body fields where an observer declares them',
    data: { schema: EFFECT_EVIDENCE_SCHEMA,
      effects: effectDecisionsOf(decisions).map(d => ({ ...declaredEffect(d), ...applicationsFields(d), verdict: d.verdict, matched: d.matched, ...(d.kind === ONLY_KIND ? { counts: d.counts } : {}), ...custodyFields(d), ...settlementFields(d), ...attributionFields(d), ...pairingFields(d), ...appLogFields(d), ...laterFields(d), ...absenceFields(d), ...resolutionFields(d) })),
      ...(claims.length ? { claims: claims.map(claimRecord) } : {}),
      windows: sealWindows(windows, meta), ...(appLogWindows ? { appLogWindows: sealAppLogWindows(appLogWindows) } : {}) } };
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
// Decide a sealed trace's clauses again (declared effects, then claims), as the run validator does.
export const decideSealed = (data, windows, role) => decideEffects(data.effects.map(declaredEffect), windows, { role, ...sealedClaims(data) });
// Sealed windows (a check's own, or a run's settlement gaps): events and coverage, with each observer's declared settle and lineage.
// suspend: a host suspend the window overlapped (src/suspend-clock.mjs), sealed so the validator recomputes the same basis text.
export const sealWindows = (windows, meta) => windows.map(w => ({ source: w.source, instanceId: w.instanceId, scope: w.scope, coverage: w.coverage, reason: w.reason ?? null, events: w.events, ...(w.exact ? { exact: w.exact } : {}), ...(w.scoped ? { scoped: w.scoped } : {}), ...(w.suspend ? { suspend: w.suspend } : {}), ...(w.suspendUnchecked === true ? { suspendUnchecked: true } : {}),
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
export function recomputeEffectTrace(trace, declaredEffects, declaredObservers, { role = 'boundary', findings = null, attribution = null, pairing = null, declaredClaimsDigest, responseRead = true, unfollowed = null, appLogs = null, admission = null, later = null } = {}) {
  const data = trace?.data;
  if (trace?.type !== 'effect-observation' || data === null || typeof data !== 'object' || data.schema !== EFFECT_EVIDENCE_SCHEMA || !Array.isArray(data.effects) || !Array.isArray(data.windows)) throw new Error('effect-trace');
  const sealed = sealedClaims(data);
  // A row's effect trace carries at least one declared effect, or at least one claim rule.
  if ((!data.effects.length && !sealed.claims.length) || data.effects.length > MAX_EFFECTS || data.windows.length > 16) throw new Error('effect-trace');
  const windows = bindSealedWindows(data.windows, declaredObservers, { scoped: true, unfollowed });
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
  const paired = applyPairing(applyAttribution(applySettlement(decideEffects(effects, windows, { role, ...sealed }), findings, role), attribution, role), pairing, role);
  const decisions = applyLater(applyAdmissions(paired, admissionsFor(paired, { windows, appLogWindows, records: appLogs, ...(admission ?? {}) })), later);
  const stored = [...data.effects, ...(data.claims ?? [])];
  decisions.forEach((d, i) => { if (d.verdict !== stored[i].verdict || d.matched !== stored[i].matched || digest(custodyFields(d)) !== digest(custodyFields(stored[i]))
    || digest(settlementFields(d)) !== digest(settlementFields(stored[i])) || digest(attributionFields(d)) !== digest(attributionFields(stored[i])) || digest(pairingFields(d)) !== digest(pairingFields(stored[i])) || digest(appLogFields(d)) !== digest(appLogFields(stored[i])) || digest(laterFields(d)) !== digest(laterFields(stored[i])) || digest(absenceFields(d)) !== digest(absenceFields(stored[i])) || digest(applicationsFields(d)) !== digest(applicationsFields(stored[i])) || digest(resolutionFields(d)) !== digest(resolutionFields(stored[i])) || (d.kind === ONLY_KIND && digest(d.counts) !== digest(stored[i].counts ?? null))
    || (isClaim(d) && stored[i].clause !== d.kind)) throw new Error('effect-verdict'); });
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
    if (inDoubtGate) admitInDoubt(window);
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
  ...(o.type === 'provider-feed' ? { witnessed: o.witness !== undefined, feed: providerFeedRecord(o) } : {}) }));
