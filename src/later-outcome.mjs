// Later outcomes, the verdict stage (PROVIDER-LATER-OUTCOME design with ADDENDUM-R1 and the R1 review; PR-2, collector provider-feed/6).
// Pure: no I/O.
//
// A provider feed that declares outcomes seals, per run, the provider's later words on its sends (src/provider-feed-rules.mjs validLater:
// { instanceId, clear, waitedMs, records: [{ of: <event seq>, outcome }] }). Under provider-feed/6 this stage reads them, after pairing
// and before app-log admissions, and only ever lowers a positive pass (effect.exists, effect.count of at least one, a success claim):
//   - absence clauses (effect.none, a count of 0, refusal claims) and effect.only never read outcomes: every accepted attempt counts
//     there, so a forbidden send that bounced is still a forbidden attempt, and a bounce never rescues anything;
//   - a send's reading folds its words in feed order (laterReading): ambiguous, conflicting (a success after a failure or reversal),
//     withdrawn (a failure or reversal after the last success), contested (a dispute or unmapped type not followed by a failure),
//     succeeded, or pending (no terminal word). A feed whose later horizon is not clear reads every send "unobserved";
//   - a send credits a positive clause when it is pending or succeeded on a clear horizon (the default reading: accepted and not
//     failed within the horizon); a send from a window without later outcomes credits as before;
//   - when any matched send of a passing positive clause does not credit (B1), the clause is judged again over its own windows without
//     those sends, through custody (decideClause), settlement (its own-window rules, every later window as sealed) and attribution
//     (background, returned-id owners, late fails). The pass stands only when that judgement passes and a crediting send in a window of
//     independent custody remains, so a record the application wrote never keeps it. Otherwise:
//       boundary check, only withdrawn sends removed: the judgement's verdict (a fail on a decided window), tagged effect-later-failed;
//       any withheld send removed, or an allowed-use control: inconclusive, tagged with the reason (effect-later-failed for a control
//       whose send later failed, the provider-later-failure tag of the lead's answer 4);
//   - a countBy clause with a send that does not credit is withheld (a replay can keep its application count), never judged again (only
//     egress sends are counted by key, and only feed sends carry readings, so this guards the payments link to come);
//   - a passing positive clause whose every matched send reads succeeded on a clear horizon carries laterStrength "succeeded", the
//     only strength a repair over a later failure is credited on (src/runner.mjs compareRuns).
// The stage never reads a clause that did not pass, and it returns pass only where main passed: verdicts move only toward not-pass. Its
// findings are applied after app-log admissions, and only to a clause that still passes there (src/http-effects.mjs applyLater).
import { custodyRunWindows, withoutEvents } from './effect-events.mjs';
import { decideClause, declaredEffect } from './http-effects.mjs';
import { settlementFindings, applySettlement, matchedLocated } from './http-settlement.mjs';
import { attributionFindings, applyAttribution } from './http-attribution.mjs';
import { custodyOf, INDEPENDENT_CUSTODY } from './custody.mjs';
// The custody a window holds, read as src/custody.mjs reads it (a declared custody included).
const windowCustody = w => custodyOf(w, { declared: w?.declaredCustody ?? null });
import { laterFeedsOf } from './provider-feed-rules.mjs';
import { LATER_STAGE_LABELS } from './collector-identity.mjs';

export const LATER_REASONS = Object.freeze(['effect-later-failed', 'effect-later-unobserved', 'effect-later-ambiguous', 'effect-later-conflicting', 'effect-later-contested', 'effect-later-limit']);
export const LATER_BASIS = Object.freeze({
  'effect-later-failed': 'Later outcome: the provider later recorded a matching send as failed or reversed (effect-later-failed), so it is not the effect this check expected.',
  'effect-later-unobserved': 'Later outcome: the feed\'s later horizon is not clear (a refused outcome or status entry, a gap, a fault or a head not read; effect-later-unobserved), so whether a matching send later failed is not known.',
  'effect-later-ambiguous': 'Later outcome: a matching send\'s message id was seen more than once, or an outcome could not be bound to it alone (effect-later-ambiguous).',
  'effect-later-conflicting': 'Later outcome: the provider recorded a matching send as succeeding after it had failed or been reversed (effect-later-conflicting).',
  'effect-later-contested': 'Later outcome: the provider left a matching send open, a dispute or a type its adapter could not map (effect-later-contested).',
  'effect-later-limit': 'Later outcome: more clauses needed judging again than the run allows (effect-later-limit).',
});
// The stage judges again at most this many clauses per run; past it, such a clause reads inconclusive.
export const LATER_STAGE_LIMIT = 128;

const NEGATIVE = ['failed', 'reversed'];
// A send's words in feed order, folded (ADDENDUM-R1 m1): a success after any failure or reversal is conflicting for good; otherwise a
// failure or reversal after the last success withdraws; a contested word stays open until a later failure or reversal (a success never
// closes it).
export function laterReading(words) {
  if (words.includes('ambiguous')) return 'ambiguous';
  let negative = false, conflicting = false, positive = false, contested = false;
  for (const w of words) {
    if (w === 'succeeded') { if (negative) conflicting = true; positive = true; }
    else if (NEGATIVE.includes(w)) { negative = true; contested = false; }
    else if (w === 'contested') contested = true;
  }
  return conflicting ? 'conflicting' : negative ? 'withdrawn' : contested ? 'contested' : positive ? 'succeeded' : 'pending';
}
// The readings a run's later list gives, for feeds whose record carries a stage label (observers: the run's observer records, or the
// connector's declared records). Returns readingOf(instanceId, seq): null for a send of any other window (it credits as before), else
// "unobserved" on a horizon that is not clear, else laterReading of its words.
export function laterReadings(later, observers) {
  const feeds = new Map(laterFeedsOf(observers, LATER_STAGE_LABELS).map(o => [`provider-feed-${o.id}`, null]));
  for (const entry of Array.isArray(later) ? later : []) {
    if (!feeds.has(entry?.instanceId)) continue;
    const words = new Map();
    for (const r of entry.records) words.set(r.of, [...(words.get(r.of) ?? []), r.outcome]);
    feeds.set(entry.instanceId, { clear: entry.clear === true, words });
  }
  return (instanceId, seq) => {
    if (!feeds.has(instanceId)) return null;
    const feed = feeds.get(instanceId);
    if (!feed?.clear) return 'unobserved';
    return laterReading(feed.words.get(seq) ?? []);
  };
}
const credits = reading => reading === null || reading === 'pending' || reading === 'succeeded';
const WITHHELD_ORDER = ['unobserved', 'ambiguous', 'conflicting', 'contested'];
const positive = d => d?.verdict === 'pass' && (d.kind === 'effect.exists' || (d.kind === 'effect.count' && Number.isSafeInteger(d.expected) && d.expected >= 1));
const replace = (list, i, value) => list.map((x, j) => j === i ? value : x);

// rows: per effect row in run order, { raw, settled, paired, windows, role }: its decisions as decided, after settlement, and after
// attribution and pairing (the verdicts the stage reads), its own windows and its role. gaps, barriers, correlation and judge: as the
// run's settlementFindings took them; attribution: null when the run declares neither attribution nor late fails, else the options its
// attributionFindings took ({ background, lateFails, tokens }); readingOf: laterReadings. Returns, per row and decision, null or the
// decision that replaces it (applyLater).
export function laterFindings({ rows, gaps, barriers, correlation, judge = false, attribution = null, readingOf }) {
  custodyRunWindows(rows.map(r => ({ windows: r.windows })), gaps, barriers, 'laterFindings');
  let judged = 0;
  return rows.map((row, k) => row.paired.map((d, c) => {
    if (!positive(d)) return null;
    const located = matchedLocated(d, row.windows).map(x => ({ ...x, reading: readingOf(x.w.instanceId, x.e.seq) }));
    const removed = located.filter(x => !credits(x.reading));
    if (!removed.length) return located.length && located.every(x => x.reading === 'succeeded') ? { ...d, laterStrength: 'succeeded' } : null;
    const withheld = WITHHELD_ORDER.find(reason => removed.some(x => x.reading === reason));
    const reason = withheld ? `effect-later-${withheld}` : 'effect-later-failed';
    const hold = why => ({ ...d, verdict: 'inconclusive', basis: `${d.basis} ${LATER_BASIS[why]}`, later: why });
    if (d.countBy !== undefined) return hold(reason);
    if (++judged > LATER_STAGE_LIMIT) return hold('effect-later-limit');
    // Judged again over its own windows without the sends that do not credit (every other window as sealed).
    const drop = new Set(removed.map(x => x.e)), reduced = row.windows.map(w => w.events.some(e => drop.has(e)) ? withoutEvents(w, drop) : w);
    const core = decideClause(declaredEffect({ kind: d.kind, select: d.select, ...(d.kind === 'effect.count' ? { expected: d.expected } : {}) }), reduced, row.role);
    // The clause as decided again: a claim keeps its own fields (its index, rule and reading), and no finding of main's carries over.
    const { verdict: _v, matched: _m, basis: _b, authoritative: _a, custody: _c, custodyReason: _cr, custodyUpgrade: _cu, settlement: _s, settlementNote: _sn, attribution: _at, pairing: _p, appLog: _l, applications: _ap, later: _lt, laterStrength: _ls, resolution: _rs, ...base } = d;
    const raw = { ...base, ...core };
    const settleRows = rows.map((r, j) => ({ effects: j === k ? replace(r.raw, c, raw) : r.raw, windows: j === k ? reduced : r.windows }));
    const settled = applySettlement([raw], [settlementFindings(settleRows, gaps, correlation, { judge })[k][c]], row.role)[0];
    let result = settled;
    if (attribution) {
      const attributeRows = rows.map((r, j) => ({ effects: j === k ? replace(r.settled, c, settled) : r.settled, windows: j === k ? reduced : r.windows }));
      result = applyAttribution([settled], [attributionFindings(attributeRows, gaps, barriers, attribution)[k][c]], row.role)[0];
    }
    const kept = new Set(removed.map(x => x.e));
    const independentLeft = located.some(x => !kept.has(x.e) && INDEPENDENT_CUSTODY.includes(windowCustody(x.w)));
    if (result.verdict === 'pass' && independentLeft) return null;
    if (withheld || row.role === 'control' || result.verdict === 'pass') return hold(reason);
    return { ...result, basis: `${result.basis} ${LATER_BASIS['effect-later-failed']}`, later: 'effect-later-failed' };
  }));
}
// The findings are read from the decisions after pairing and applied by src/http-effects.mjs applyLater after app-log admissions, on both
// sides, only to a clause that still passes there (an admitted clause keeps its fail and its app-log tag).
