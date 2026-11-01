// Settlement and correlation of effect windows across one HTTP run. Pure: no I/O.
//
// When a run has checks that declare effects, every declared observer is marked once
// before the first check and once after the last check plus the largest declared settle
// (the final mark). Together with each check's own window, the sealed gap windows cover
// that whole span in order: the window before the first effect check, one gap after each
// effect check, and the tail up to the final mark (gaps[k] comes before effect row k;
// the last gap is the tail). Sink and audit-file observers start each gap where the
// previous check's window stopped attributing records, so a record lands in one window.
//
// A clause's verdict rests on its own window. Later evidence can unsettle it:
//   effect-outside-window         a committed effect matching the clause's selector was
//                                 recorded after its window (in a gap, a later check's window
//                                 or the tail): it may be this check's late effect, so an
//                                 effect.none or effect.count pass is withheld. An effect.only
//                                 pass is an absence claim too ("nothing else happened"): any
//                                 later committed effect of an operation it judged, from an
//                                 observer in its scope (expected, allowed or outside its set
//                                 alike), withholds it
//   effect-ambiguous-attribution  every committed effect that decided an effect.exists pass,
//                                 or any one an effect.count pass counted, also fits a
//                                 selector of an earlier check: it may be that check's late
//                                 effect, so the pass is withheld. An earlier effect.only
//                                 clause's selectors are its expected and allowed ones
//   settlement-unobserved         an observer that decided an absence pass (effect.none,
//                                 effect.count or effect.only) could not decide absence in a
//                                 later window: the window failed, was partial, or (a net-only
//                                 snapshot) was not exact for the selector. A late effect could
//                                 have been missed, so the pass is withheld
// Only a pass is withheld, as custody does. A boundary check (any severity except "control")
// withholds it under every reason. An allowed-use control keeps its verdict and carries the
// finding as a tag, except a positive pass (effect.exists, or effect.count of at least one)
// whose deciding effect carries another check's correlation token (effect-correlated-elsewhere):
// a control establishes its actor only on its own effect, so that pass is withheld, as
// attribution does (src/http-attribution.mjs). Selector-only ambiguity on a control
// (effect-ambiguous-attribution) stays a tag: withholding on it made most multi-check layouts'
// controls inconclusive (a documented residual; pin control selectors or declare correlation).
// A fail stays a fail. Effects committed after the final mark are outside every
// window and every claim: no result says an effect never happened later.
//
// Correlation (fast-loop fix W2, decision of 2026-10-10; lead direction of 2026-10-10, review round 3): a target may
// declare a correlation header that the connector sets on every sent check request (src/egress-rules.mjs), and
// egress-recorder destinations that record the value the app forwards in that header (event.correlation.settlementToken, a
// key no selector or pairing pin reads: src/effect-events.mjs). With no
// correlation declared, settlementFindings runs the rules above exactly. With it, a committed event from a declared
// (observer, destination) pair is tagged with the run-order row whose token it carries, or "unattributed"; every other
// event is "undeclared". The app writes the token, so it is a self-report about causation, and a self-report is never
// positive evidence: a token can only make settlement stricter. It never releases a pass that the rules above withhold
// and never fails a pass; every finding below withholds a boundary pass (inconclusive) like the rules above.
//   effect-correlated-late            an event tagged to this check, after its window, decided-matches its absence
//                                     clause, and the clause judged over its own window plus its late tagged events
//                                     would fail: the pass is withheld (the token alone never fails a clause)
//   effect-correlated-late-unsettled  an event tagged to this check, after its window, could change the clause (it only
//                                     fits, or it is in an effect.only clause's expected or allowed set): withheld
//   effect-correlated-elsewhere       every matched own-window event of an effect.exists pass, or any one an
//                                     effect.count pass counted, carries another sent row's token: withheld
// Both late findings name an event the rules above already withhold the pass for (effect-outside-window); the token
// only says which check it may belong to. Per-check mode (settlement "per-check", correlation required) adds a drain
// barrier after each check with effects or claim rules: the connector waits the largest settle, marks every observer
// and seals the barrier window B(k) before any later request. The barriers are more later windows: every rule above reads them as well (an
// event in B(k) is after k's window; a failed or partial barrier is settlement-unobserved), so they can only add
// findings. They keep a check's late effects out of the next check's own window, where they would otherwise decide it.
// A selector with declared body fields (src/body-fields.mjs) fits a later event whose fields could not be
// read (matchState 'unknown'), as an unknown actor fits: it could be this check's effect. A claim rule's
// clause (src/http-claims.mjs) is settled like a declared one, and its selector counts as an earlier
// check's selector whatever its reply read. A later window that sees the selector's base effect but does not
// capture its fields (blindToFields) withholds an absence pass on any base-matching committed send, and a
// later gap in an authoritative one leaves a late send possibly unseen.
//
// Judged late effects (settlement re-judge part 1; opt-in by the target's settlement "outsideWindow": "judge"; lead ruling
// of 2026-10-11). The 2026-10-10 effect.only rule above (any later committed effect of an operation it judged withholds the
// pass) is relaxed ONLY under this declaration, and only for effect.only. Every later effect the rule names (a candidate) is
// counted as this check's own, the worst case: it is added to the check's own window of the same observer instance and the
// clause is judged again by only.mjs. The pass stands, with the note effect-outside-window-judged (settlementNote, never a
// withholding reason), only when that judgement still reads pass. Everything else keeps the rule: a candidate from a window
// that is not authoritative (a self-report only tightens), one whose instance has no single own window of the same source and
// scope, a seq that is not after its own window's events or that two candidates share, a window over the event cap, a result
// that is not pass (an unexpected or beyond-count effect, unreadable fields, an unknown actor against an actor pin, more than
// ONLY_LIMITS.optionGroups combinations), and any throw. It never fails a pass and reads no timestamp, horizon, token or
// returned id. Downward closed: only.mjs's expected counts are upper bounds and every other ground is decided per event, so a
// pass over the own windows plus every candidate is a pass over the own windows plus any subset of them, whichever of them
// were really this check's. settlement-unobserved and the correlated rules still run before the note is final.
// An effect.only clause that declares countBy (keyed applications) is judged the same way, worst case (SETTLE-V3 fix B): its own
// windows' sends keep their keyed collapse, and every candidate is its own send, never collapsed into or absorbed by an
// application, so a late exact keyed replay of its own send counts again. A late countBy release is part 2 and not built.
// Under the declaration, a later scoped egress window of a deciding observer whose every unattributed send is allowed and not
// expected for the clause (SETTLE-V3 fix C, src/effect-events.mjs onlyCoverageFor) does not give settlement-unobserved.
// effect.none, effect.count (send units and countBy alike), effect.exists and claim rules keep the rules above exactly. A run
// without the declaration reads exactly as above.
import { matches, matchState, windowSees, baseSelector, blindToFields, evaluateEffectAssertion, custodyRunWindows, seesThroughCross } from './effect-events.mjs';
import { digest } from './domain.mjs';
import { withoutUpstream } from './effect-outcome.mjs';
import { correlationHeaderValid, correlationToken, egressHost } from './egress-rules.mjs';
import { decidingWindows, decidesAbsence } from './custody.mjs';
import { judgeOnly, quiescent, expectedOf, onlyScopedComplete, ONLY_KIND } from '../integrations/collateral/only.mjs';
import { validDrains } from './run-end-drain.mjs';
import { laterFeedsOf, validLater } from './provider-feed-rules.mjs';
import { OUTCOME_COLLECTOR_LABELS } from './collector-identity.mjs';

export const SETTLEMENT_SCHEMA = 'scopehaven-settlement/1';
// A run whose target declares correlation keeps this record (its header, the recorded pairs, the mode and, per check, the barriers).
export const SETTLEMENT_SCHEMA_CORRELATED = 'scopehaven-settlement/2';
export const SETTLEMENT_MODES = Object.freeze(['run', 'per-check']);
export const SETTLEMENT_REASONS = Object.freeze(['effect-outside-window', 'effect-ambiguous-attribution', 'settlement-unobserved', 'effect-correlated-late', 'effect-correlated-late-unsettled', 'effect-correlated-elsewhere']);
export const SETTLEMENT_BASIS = Object.freeze({
  'effect-correlated-late': 'Settlement: a committed effect carrying this check\'s own correlation token was recorded after its window closed, and the clause judged with it would fail (effect-correlated-late). The token is the application\'s own account of which request caused the effect, so the pass is withheld, not failed.',
  'effect-correlated-late-unsettled': 'Settlement: a committed effect carrying this check\'s own correlation token was recorded after its window closed and could change this clause (effect-correlated-late-unsettled), so it may be this check\'s late effect.',
  'effect-correlated-elsewhere': 'Settlement: the matched effect carries another check\'s correlation token (effect-correlated-elsewhere), so it may be that check\'s effect.',
  'effect-outside-window': 'Settlement: a matching committed effect was recorded after this check\'s window closed (effect-outside-window), so it may be this check\'s late effect.',
  'effect-ambiguous-attribution': 'Settlement: the matched effect also fits an earlier check\'s selector (effect-ambiguous-attribution), so it may be that check\'s late effect.',
  'settlement-unobserved': 'Settlement: an observer that decided this could not decide absence in a later window (failed, partial or not exact for this selector; settlement-unobserved), so a late effect could have been missed.',
});
// Judged late effects (see the header): the one declared value, and the note a pass that stands carries. The note is not a
// reason: applySettlement keeps the verdict for every role and stores it apart, as settlementNote.
export const SETTLEMENT_OUTSIDE_WINDOW = Object.freeze(['judge']);
export const SETTLEMENT_NOTES = Object.freeze(['effect-outside-window-judged']);
export const SETTLEMENT_NOTE_BASIS = Object.freeze({
  'effect-outside-window-judged': 'Settlement: committed effects of an operation this clause judged were recorded after its window closed; judged again with every one of them counted as this check\'s own, the clause still passes (effect-outside-window-judged).',
});
const JUDGED = SETTLEMENT_NOTES[0];
// The fields a clause or its assertion row carries for a finding, and for the judged note.
export const settlementFields = d => ({ ...(d?.settlement ? { settlement: d.settlement } : {}), ...(d?.settlementNote ? { settlementNote: d.settlementNote } : {}) });

// Could this committed event be one the selector describes? As in evaluateEffectAssertion,
// an actor-scoped selector also takes an event with no known or no declared actor.
export function fitsSelector(event, select) {
  if (matchState(event, { ...select, outcome: 'committed' }) !== 'no') return true;
  const { actor, ...rest } = select;
  return actor !== undefined && (event.actor === null || event.actor.startsWith('unlisted:')) && matchState(event, { ...rest, outcome: 'committed' }) !== 'no';
}
// The committed events a decided clause rested on in its own window: any seeing observer's
// for effect.exists, the authoritative seeing observers' for effect.count.
function matchedEvents(effect, windows) {
  const seeing = windows.filter(w => windowSees(w, effect.select) && (effect.kind !== 'effect.count' || w.scope.evidence === 'authoritative'));
  return seeing.flatMap(w => w.events).filter(e => matches(e, { ...effect.select, outcome: 'committed' }));
}

// The selectors a decided clause names: its own, or an effect.only clause's expected and allowed ones.
export const selectorsOf = effect => effect.kind === ONLY_KIND ? [...(effect.expect ?? []).map(item => expectedOf(item).select), ...(effect.allow ?? [])] : [effect.select];
// A decided clause carries its verdict and counts beside the declared fields; only the declared ones are judged again.
// countBy (an effect.only keyed clause, src/idempotency.mjs keyedReplays) travels with the clause into every re-judge.
const ONLY_DECLARED = Object.freeze(['kind', 'expect', 'allow', 'operations', 'sources', 'counterparts', 'countBy', 'outcomeJudged']);
// An effect.only pass, judged again over its own windows (only.mjs): the operations it judged, the observers in its
// scope that report them, and the authoritative ones among those that decided "nothing else happened".
function onlyScope(effect, windows) {
  const declared = Object.fromEntries(ONLY_DECLARED.filter(key => Object.hasOwn(effect, key)).map(key => [key, effect[key]]));
  const result = judgeOnly(declared, windows, { fields: true, countBy: true }), relevant = new Set(result.observers);
  const deciders = windows.filter(w => relevant.has(w.instanceId) && w.scope.evidence === 'authoritative');
  return { operations: result.operations, claimed: result.claimedOperations, relevant, deciders };
}
// Could a later window of a deciding observer still exclude this clause's late effect? The same rule as its own
// window: decidesAbsence for a core clause; for effect.only, complete coverage of every claimed operation the
// observer reports (a quiescent Postgres xmin window covers updates only, as in only.mjs).
const onlyCovers = (w, claimed) => claimed.filter(op => w.scope.operations.includes(op)).every(op => w.coverage === 'complete' || (op === 'update' && quiescent(w)));
// Judged late effects (judge declared; effect.only only; see the header): does the pass still hold with every candidate counted
// as this check's own? own: the check's own windows; after: every window after them; candidate(w, e): the 2026-10-10 rule's
// test. Each candidate is added to the one own window of its instance (same instance id, source and scope), after that
// window's events in seq order; the same event object reached twice counts once. Only a pass from only.mjs over those windows
// stands; every other outcome and any throw withholds.
function judgedStands(effect, own, after, candidate) {
  // An effect.only clause that declares countBy is judged with it (SETTLE-V3 fix B), worst case. Its own windows' sends keep their
  // keyed collapse (#294, read over the own window's events alone), and every candidate is passed as `separate`: judged as its own
  // send, never a replay or an unproven resend. So a late exact keyed replay of the check's own send is never absorbed into that
  // send's application (that would be a late countBy release, part 2, not built): it counts again, as one more application. One
  // send is at most one application, so this is the most the candidates can be, and the judgement stays downward closed.
  // SETTLE-V3 fix C: an own scoped window that reads complete for the clause toward a pass carries that to its augmented copy
  // (a copy is never admitted, so it is read on the own window).
  const lifted = onlyScopedComplete(effect, own), scopedComplete = new Set();
  try {
    const added = new Map(), seen = new Set();
    for (const w of after) {
      const late = w.events.filter(e => candidate(w, e));
      if (!late.length) continue;
      if (w.scope?.evidence !== 'authoritative' || typeof w.instanceId !== 'string') return false;
      const mine = own.filter(o => o.instanceId === w.instanceId);
      if (mine.length !== 1 || mine[0].source !== w.source || digest(mine[0].scope) !== digest(w.scope)) return false;
      if (!added.has(mine[0])) added.set(mine[0], []);
      for (const e of late) if (!seen.has(e)) { seen.add(e); added.get(mine[0]).push(e); }
    }
    const augmented = [];
    for (const o of own) {
      const late = added.get(o);
      if (!late) { augmented.push(o); if (lifted.has(o)) scopedComplete.add(o); continue; }
      const sorted = [...late].sort((x, y) => x.seq - y.seq), last = o.events.reduce((m, e) => Math.max(m, e.seq), -Infinity);
      // A later window's effect comes after every effect of its own window, and two different effects never share a seq.
      if (sorted.some((e, i) => !Number.isSafeInteger(e.seq) || e.seq <= last || (i > 0 && e.seq === sorted[i - 1].seq))) return false;
      const copy = { ...o, events: [...o.events, ...sorted] };
      augmented.push(copy);
      if (lifted.has(o)) scopedComplete.add(copy);
    }
    return judgeOnly(onlyDeclared(effect), augmented, { fields: true, countBy: true, separate: seen, scopedComplete }).verdict === 'pass';
  } catch { return false; }
}

// rows: the rows that have an effect window, in run order: [{ effects: decisions, windows }].
// gaps: [windows] with gaps.length === rows.length + 1. Returns, per row and clause, a reason, the judged note, or null.
// correlation: undefined or null (no correlation declared: the rules above, unchanged), or
// { mode, barriers, tokens, declared } (correlatedFindings below).
// judge: true only when the target declares settlement "outsideWindow": "judge" (judged late effects, see the header);
// otherwise every finding is the rules' above.
export function settlementFindings(rows, gaps, correlation, { judge = false } = {}) {
  custodyRunWindows(rows, gaps, correlation?.barriers, 'settlementFindings');
  if (typeof judge !== 'boolean') throw new Error('settlement-judge');
  if (correlation === undefined || correlation === null) return runLevelFindings(rows, gaps, judge);
  return correlatedFindings(rows, gaps, correlation, judge);
}
function runLevelFindings(rows, gaps, judge) {
  if (!Array.isArray(gaps) || gaps.length !== rows.length + 1) throw new Error('settlement-gaps');
  return selectorFindings(rows, k => [...rows.slice(k + 1).flatMap(r => r.windows), ...gaps.slice(k + 1).flat()], judge);
}
// The rules above, given every window after row k's own window (later(k), read once per row).
// The selectors of earlier rows' clauses (upstream set aside) are kept once each, growing row by row, and each matched event's
// fit against them is tested once per row: the same answers as testing every clause's selector list, at a cost linear in the
// distinct selectors and the matched events.
function selectorFindings(rows, later, judge = false) {
  const earlier = [], seen = new Set();
  return rows.map((row, k) => {
    const after = later(k);
    if (k > 0) for (const s of rows[k - 1].effects.flatMap(selectorsOf)) { const t = withoutUpstream(s), key = JSON.stringify(t); if (!seen.has(key)) { seen.add(key); earlier.push(t); } }
    const fitsEarlier = new Map();
    const fitsAnyEarlier = e => { if (!fitsEarlier.has(e)) fitsEarlier.set(e, earlier.some(s => fitsSelector(e, s))); return fitsEarlier.get(e); };
    return row.effects.map(effect => {
      if (effect.verdict !== 'pass') return null;
      if (effect.kind === ONLY_KIND) {
        const scope = onlyScope(effect, row.windows);
        let judged = false;
        if (after.some(w => scope.relevant.has(w.instanceId) && w.events.some(e => e.outcome === 'committed' && scope.operations.includes(e.operation)))) {
          // The 2026-10-10 rule withholds here. It is relaxed only when the target declares "outsideWindow": "judge" (lead
          // ruling of 2026-10-11): then the pass may stand, with the note, on the worst-case judgement alone.
          if (!judge || !judgedStands(effect, row.windows, after, (w, e) => scope.relevant.has(w.instanceId) && e.outcome === 'committed' && scope.operations.includes(e.operation))) return 'effect-outside-window';
          judged = true;
        }
        const deciders = new Set(scope.deciders.map(w => w.instanceId));
        // SETTLE-V3 fix C, under the declaration only: a later scoped egress window whose every unattributed send is allowed and not
        // expected for this clause covers it; such a send, counted as this check's own (the judge's worst case), leaves the pass
        // standing. Without the declaration any later send withholds, so an unseen one is not read more leniently than a seen one.
        const liftedLater = judge ? onlyScopedComplete(effect, after.filter(w => deciders.has(w.instanceId))) : new Set();
        if (after.some(w => deciders.has(w.instanceId) && !onlyCovers(w, scope.claimed) && !liftedLater.has(w))) return 'settlement-unobserved';
        return judged ? JUDGED : null;
      }
      const absence = effect.kind === 'effect.none' || effect.kind === 'effect.count';
      const fitsIn = (w, e) => fitsSelector(e, windowSees(w, effect.select) ? effect.select : baseSelector(effect.select));
      if (absence && after.some(w => windowSees(w, baseSelector(effect.select)) && w.events.some(e => fitsIn(w, e)))) return 'effect-outside-window';
      if (effect.kind === 'effect.exists' || effect.kind === 'effect.count') {
        // An earlier clause's upstream outcome requirement says nothing about which check caused a send: it is set aside (earlier).
        const matched = matchedEvents(effect, row.windows), ambiguous = matched.filter(fitsAnyEarlier);
        if (effect.kind === 'effect.exists' ? matched.length > 0 && ambiguous.length === matched.length : ambiguous.length > 0) return 'effect-ambiguous-attribution';
      }
      if (absence) {
        // Every later window of a deciding observer must itself decide absence for this selector: one that failed,
        // was partial, or (a net-only snapshot) is not exact for it leaves a late effect possibly unseen.
        const deciders = new Set(decidingWindows(row.windows, effect).map(w => w.instanceId));
        // Coverage v2: a later scoped egress window decides through coverageFor with this clause's verdict (only passes are judged here).
        const scope = { outcome: effect.verdict, hostWide: effect.countBy !== undefined };
        if (after.some(w => deciders.has(w.instanceId) && !decidesAbsence(w, effect.select, effect.kind, scope))) return 'settlement-unobserved';
        const blind = new Set(row.windows.filter(w => w.scope?.evidence === 'authoritative' && blindToFields(w, effect.select)).map(w => w.instanceId));
        if (after.some(w => blind.has(w.instanceId) && !decidesAbsence(w, baseSelector(effect.select), effect.kind, scope))) return 'settlement-unobserved';
        // FIX-08: a later window of any recorder that sees the selector only through another recorder's destination (a send to its sibling
        // there, src/effect-events.mjs crossSeen) holds a send that may be the selected one, so it too must decide absence.
        if (after.some(w => !deciders.has(w.instanceId) && seesThroughCross(w, effect.select) && !decidesAbsence(w, effect.select, effect.kind, scope))) return 'settlement-unobserved';
      }
      return null;
    });
  });
}

// Correlated settlement. tokens: Map token -> run-order effect row index, or null for a sent row with no
// effect window (settlementTokens). declared: Set of "<instanceId>\n<destination host>" pairs that record the
// token (correlationDeclared). barriers: per effect row, its barrier windows (per-check mode only).
// A clause's finding is a correlated one (a late own-token event, or a pass resting on another row's token) or else
// exactly the rules above over every later window, barriers included: correlation never returns null where those rules
// withhold. A positive clause (effect.exists, or effect.count of at least one) resting on another row's token reads that reason
// first, before a late own-token event or a selector finding, since it is the one reason that withholds a control's pass. The correlated part indexes every tagged event once and reads, per clause, only the events carrying its own
// row's token (linear in the run's events); the rules above read, per clause, the windows after its row (at most 50
// checks, MAX_EFFECTS clauses each, EFFECT_LIMITS.eventsPerWindow events per window). No search over combinations.
const UNDECLARED = 'undeclared', UNATTRIBUTED = 'unattributed', OTHER_ROW = 'other-row';
const ABSENCE_KINDS = Object.freeze(['effect.none', 'effect.count', ONLY_KIND]);
// The committed events a decided exists or count clause rested on in its own window, with their windows (as matchedEvents).
export const matchedLocated = (effect, windows) => windows.filter(w => windowSees(w, effect.select) && (effect.kind !== 'effect.count' || w.scope.evidence === 'authoritative'))
  .flatMap(w => w.events.filter(e => matches(e, { ...effect.select, outcome: 'committed' })).map(e => ({ e, w })));
const coreDeclared = d => ({ kind: d.kind, select: d.select, ...(d.kind === 'effect.count' ? { expected: d.expected } : {}) });
export const onlyDeclared = d => Object.fromEntries(ONLY_DECLARED.filter(key => Object.hasOwn(d, key)).map(key => [key, d[key]]));
function correlatedFindings(rows, gaps, { mode, barriers, tokens, declared } = {}, judge = false) {
  if (!Array.isArray(gaps) || gaps.length !== rows.length + 1) throw new Error('settlement-gaps');
  if (!SETTLEMENT_MODES.includes(mode) || !(tokens instanceof Map) || !(declared instanceof Set)) throw new Error('settlement-correlation');
  const perCheck = mode === 'per-check';
  if (perCheck ? !(Array.isArray(barriers) && barriers.length === rows.length && barriers.every(Array.isArray)) : barriers !== undefined) throw new Error('settlement-barriers');
  // Every window after row k's own window: its barrier, later checks' windows, later barriers, then the gaps and tail.
  const later = k => [
    ...(perCheck ? barriers[k] : []),
    ...rows.slice(k + 1).flatMap(r => r.windows),
    ...(perCheck ? barriers.slice(k + 1).flat() : []),
    ...gaps.slice(k + 1).flat(),
  ];
  const selector = selectorFindings(rows, later, judge);
  const tagOf = (e, w) => {
    if (!declared.has(`${w.instanceId}\n${e.name}`)) return UNDECLARED;
    const token = e.correlation?.settlementToken;
    return typeof token === 'string' && tokens.has(token) ? tokens.get(token) ?? OTHER_ROW : UNATTRIBUTED;
  };
  // Could this later event be one the clause is about? A fitting event (effect.none, effect.count), or a committed
  // event of a judged operation from an observer in scope (effect.only): the effect-outside-window candidates.
  const relevantTo = (d, scope) => d.kind === ONLY_KIND ? (e, w) => scope.relevant.has(w.instanceId) && e.outcome === 'committed' && scope.operations.includes(e.operation)
    : (e, w) => windowSees(w, d.select) && fitsSelector(e, d.select);
  // Would the clause, judged over its own windows plus its late own-token events, fail on a decided match outside its set?
  // This only names the withholding reason; it never fails the clause. The later windows are not read in time order, so
  // the late events are deduplicated and put in seq order; a set that still cannot form a valid window names the other
  // reason (both withhold).
  const lateWouldFail = (d, windows, own) => {
    const lateOf = id => [...new Set(own.filter(x => x.w.instanceId === id).map(x => x.e))].sort((x, y) => x.seq - y.seq);
    const augmented = windows.map(w => ({ ...w, events: [...w.events, ...lateOf(w.instanceId)] }));
    try {
      if (d.kind !== ONLY_KIND) return own.some(({ e, w }) => windowSees(w, d.select) && matches(e, { ...d.select, outcome: 'committed' })) && evaluateEffectAssertion(coreDeclared(d), augmented).verdict === 'fail';
      const inSet = [...(d.expect ?? []).map(item => expectedOf(item).select), ...(d.allow ?? [])];
      return own.some(({ e }) => !inSet.some(sel => matches(e, { ...sel, outcome: 'committed' }))) && judgeOnly(onlyDeclared(d), augmented, { fields: true, countBy: true }).verdict === 'fail';
    } catch { return false; }
  };
  // effect-correlated-elsewhere for a decided exists or count clause.
  const elsewhere = (d, k, windows) => {
    if (d.kind !== 'effect.exists' && d.kind !== 'effect.count') return false;
    const other = ({ e, w }) => { const tag = tagOf(e, w); return tag === OTHER_ROW || (typeof tag === 'number' && tag !== k); };
    const matched = matchedLocated(d, windows);
    return d.kind === 'effect.exists' ? matched.length > 0 && matched.every(other) : matched.some(other);
  };
  // Every event that carries a row's token, indexed once by that row, with where it sits: barrier j and gap j follow
  // rows up to j and before j respectively, row j's window follows rows before j. One pass over every window.
  const byTag = new Map();
  const index = (windows, after) => { for (const w of windows) for (const e of w.events) { const tag = tagOf(e, w); if (typeof tag === 'number') { if (!byTag.has(tag)) byTag.set(tag, []); byTag.get(tag).push({ e, w, after }); } } };
  rows.forEach((r, j) => index(r.windows, k => j > k));
  if (perCheck) barriers.forEach((b, j) => index(b, k => j >= k));
  gaps.forEach((g, j) => index(g, k => j > k));
  return rows.map((row, k) => {
    const tagged = (byTag.get(k) ?? []).filter(x => x.after(k));
    return row.effects.map((d, c) => {
      if (d.verdict !== 'pass') return null;
      const found = selector[k][c];
      // A positive pass resting on another check's token is withheld for every role (ANOTHER_CHECKS), and every other reason only
      // tags an allowed-use control's pass, so that reason is read first: a tag-only reason (a late own-token send, or a selector
      // finding such as effect-ambiguous-attribution) never hides it. For a boundary check only the reason's name can change.
      if (positive(d) && elsewhere(d, k, row.windows)) return 'effect-correlated-elsewhere';
      // Judge declared and the judgement stood (the note): every later candidate, the own-token ones included (they are a
      // subset of the candidates), was already counted as this check's own, so the own-token branch is skipped. Elsewhere is
      // still checked before the note. Without the declaration found is never the note, and this reads as before.
      if (ABSENCE_KINDS.includes(d.kind) && tagged.length && found !== JUDGED) {
        const fit = relevantTo(d, d.kind === ONLY_KIND ? onlyScope(d, row.windows) : null);
        const own = tagged.filter(({ e, w }) => fit(e, w));
        if (own.length) return lateWouldFail(d, row.windows, own) ? 'effect-correlated-late' : 'effect-correlated-late-unsettled';
      }
      if (found !== null && found !== JUDGED) return found;
      return elsewhere(d, k, row.windows) ? 'effect-correlated-elsewhere' : found;
    });
  });
}
// The tokens of a run's sent rows (results in run order; effectRows the rows that have an effect window, in order):
// token -> effect row index, or null for a sent row without one. A row that was not sent has no token.
export function settlementTokens(results, effectRows) {
  const index = new Map(effectRows.map((row, k) => [row, k])), tokens = new Map();
  for (const row of results) {
    const data = row?.trace?.[0]?.data;
    if (!data || row.status === 'not_applicable' || data.requestAttempted !== true || data.transportOutcome === 'not-sent') continue;
    const token = correlationToken(data.requestId);
    if (token !== null) tokens.set(token, index.has(row) ? index.get(row) : null);
  }
  return tokens;
}
// The (observer instance, destination host) pairs that record the token, from the record's "recorded" list
// (instance ids as src/http-effects.mjs observerInstanceId names an egress recorder).
export const correlationDeclared = recorded => new Set(recorded.flatMap(r => r.names.map(name => `egress-recorder-${r.observer}\n${name}`)));

// Apply one row's findings to its decided clauses under the check's role. Only a pass is ever settled: a
// finding handed in for a fail, an inconclusive or an undecided clause leaves it exactly as decided. A boundary
// pass is withheld (inconclusive) under every reason, correlated ones included: settlement never fails a pass.
// A control keeps its verdict and carries the reason as a tag, except a positive pass whose effect carries another
// check's token (ANOTHER_CHECKS), which is withheld. The judged note (judge declared) keeps the verdict for every role,
// appends its basis and is stored as settlementNote, apart from the reasons, so no reader takes it for a withholding (a
// control carries the note instead of a tag). Only an effect.only pass carries it, so the control rule never meets it.
const ANOTHER_CHECKS = Object.freeze(['effect-correlated-elsewhere']);
const positive = d => d.kind === 'effect.exists' || (d.kind === 'effect.count' && Number.isSafeInteger(d.expected) && d.expected >= 1);
export function applySettlement(decisions, findings, role = 'boundary') {
  return decisions.map((d, i) => {
    const reason = findings?.[i] ?? null;
    if (reason === null || d.verdict !== 'pass') return d;
    if (SETTLEMENT_NOTES.includes(reason)) {
      if (d.kind !== ONLY_KIND) throw new Error('settlement-reason');
      return { ...d, basis: `${d.basis} ${SETTLEMENT_NOTE_BASIS[reason]}`, settlementNote: reason };
    }
    if (!SETTLEMENT_REASONS.includes(reason)) throw new Error('settlement-reason');
    if (role === 'control' && !(positive(d) && ANOTHER_CHECKS.includes(reason))) return { ...d, settlement: reason };
    return { ...d, verdict: 'inconclusive', basis: `${d.basis} ${SETTLEMENT_BASIS[reason]}`, settlement: reason };
  });
}
// The largest declared settle: the wait before the final mark.
export const finalSettleMs = declared => Math.max(0, ...declared.map(o => o.settleMs ?? 0));

// Revalidate a sealed settlement record. bind(windows, declaredObservers) revalidates and
// binds one gap's windows (the same rule as a check's own windows) and returns them.
// Returns { gaps, correlation, judge, drains, later }: correlation is null for a /1 record, else { mode, header, recorded, barriers }.
// Judged late effects: a /1 or /2 record carries "outsideWindow": "judge" exactly when the target declares it (judge: true);
// the key is counted with the others and any other value is refused.
// Coverage v2 Part D: a drains record (src/run-end-drain.mjs) is checked there, then the record is read as before without it.
// Later outcomes (provider-feed/5): a later list is present exactly when a declared feed record reads later outcomes (laterFeedsOf), one
// entry per such feed in order (src/provider-feed-rules.mjs validLater); it is checked on its own like drains. Which sealed events its
// records name is the caller's check (src/contracts.mjs). Nothing here reads it.
// drainers (feed v2, Part B): the observers expected to have drained (src/run-end-drain.mjs drainersOf), else every declared one.
export function validateSettlementRecord(input, { effectRowIds, declaredObservers, bind, drainsAllowed = false, drainers = declaredObservers }) {
  const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  // The drains field (Part D) is checked on its own, then the record is read as before without it.
  let record = input, drains = null, later = null;
  if (plain(input) && Object.hasOwn(input, 'drains')) {
    if (!drainsAllowed || !validDrains(input.drains, drainers)) throw new Error('settlement-drains');
    ({ drains, ...record } = input);
  }
  const laterFeeds = laterFeedsOf(declaredObservers, OUTCOME_COLLECTOR_LABELS);
  if (plain(record) && (Object.hasOwn(record, 'later') !== (laterFeeds.length > 0) || (laterFeeds.length > 0 && !validLater(record.later, laterFeeds)))) throw new Error('settlement-later');
  if (plain(record) && Object.hasOwn(record, 'later')) ({ later, ...record } = record);
  const read = validateSettlementBody(record, { effectRowIds, declaredObservers, bind, plain });
  return { ...read, drains, later };
}
function validateSettlementBody(record, { effectRowIds, declaredObservers, bind, plain }) {
  const judge = plain(record) && Object.hasOwn(record, 'outsideWindow');
  if (judge && !SETTLEMENT_OUTSIDE_WINDOW.includes(record.outsideWindow)) throw new Error('settlement-record');
  if (plain(record) && record.schema === SETTLEMENT_SCHEMA_CORRELATED) return { ...correlatedRecord(record, { effectRowIds, declaredObservers, bind, plain, judge }), judge };
  if (!plain(record) || Object.keys(record).length !== 3 + (judge ? 1 : 0) || record.schema !== SETTLEMENT_SCHEMA || !Array.isArray(record.gaps)) throw new Error('settlement-record');
  return { gaps: recordGaps(record, { effectRowIds, declaredObservers, bind, plain }), correlation: null, judge };
}
function recordGaps(record, { effectRowIds, declaredObservers, bind, plain }) {
  if (record.settleMs !== finalSettleMs(declaredObservers)) throw new Error('settlement-record');
  if (record.gaps.length !== effectRowIds.length + 1) throw new Error('settlement-record');
  return record.gaps.map((gap, k) => {
    if (!plain(gap) || Object.keys(gap).length !== 3 || !Array.isArray(gap.windows)) throw new Error('settlement-record');
    if (gap.before !== (effectRowIds[k] ?? null) || gap.after !== (k > 0 ? effectRowIds[k - 1] : null)) throw new Error('settlement-record');
    return bind(gap.windows, declaredObservers);
  });
}
// A /2 record: { schema, settleMs, mode, correlation: { header, recorded: [{ observer, names }] }, gaps, barriers? }, with
// one barrier per effect row exactly when the mode is "per-check", and outsideWindow exactly when declared (judge). Every
// recorded observer is a declared egress recorder.
function correlatedRecord(record, { effectRowIds, declaredObservers, bind, plain, judge }) {
  const perCheck = record.mode === 'per-check', keys = ['schema', 'settleMs', 'mode', 'correlation', 'gaps', ...(perCheck ? ['barriers'] : []), ...(judge ? ['outsideWindow'] : [])];
  if (Object.keys(record).length !== keys.length || !keys.every(key => Object.hasOwn(record, key)) || !SETTLEMENT_MODES.includes(record.mode) || !Array.isArray(record.gaps)) throw new Error('settlement-record');
  const corr = record.correlation, recorders = new Set(declaredObservers.filter(o => o?.type === 'egress-recorder').map(o => o.id)), seen = new Set();
  if (!plain(corr) || Object.keys(corr).length !== 2 || !correlationHeaderValid(corr.header) || !Array.isArray(corr.recorded) || !corr.recorded.length || corr.recorded.length > 16) throw new Error('settlement-correlation');
  for (const r of corr.recorded) {
    if (!plain(r) || Object.keys(r).length !== 2 || !recorders.has(r.observer) || seen.has(r.observer) || !Array.isArray(r.names) || !r.names.length || r.names.length > 64
      || !r.names.every(egressHost) || new Set(r.names).size !== r.names.length) throw new Error('settlement-correlation');
    seen.add(r.observer);
  }
  const gaps = recordGaps(record, { effectRowIds, declaredObservers, bind, plain });
  let barriers;
  if (perCheck) {
    if (!Array.isArray(record.barriers) || record.barriers.length !== effectRowIds.length) throw new Error('settlement-record');
    barriers = record.barriers.map((b, k) => {
      if (!plain(b) || Object.keys(b).length !== 2 || b.after !== effectRowIds[k] || !Array.isArray(b.windows)) throw new Error('settlement-record');
      return bind(b.windows, declaredObservers);
    });
  }
  return { gaps, correlation: { mode: record.mode, header: corr.header, recorded: corr.recorded, barriers } };
}
