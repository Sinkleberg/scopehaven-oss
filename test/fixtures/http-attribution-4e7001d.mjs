// Frozen copy of scopehaven/src/http-attribution.mjs at 4e7001d (main before readiness edge E3; imports re-pointed), for the E3 differential compat test. Not in any identity list.
// Background attribution (readiness gap 5, W4 part 1). Pure: no I/O.
//
// A target may declare its background sources: the sync workers, queues and cron jobs that commit effects on their own
// schedule, named by the actor, operation and name their effects carry:
//   "attribution": { "background": [ { "id": "sync-worker", "select": { "actor": "svc-sync", "operation": "update", "name": "orders" } } ] }
// A committed event that fits a source's select (src/http-settlement.mjs fitsSelector: an actor pin also takes an event
// with no known or no declared actor) is background-possible (a BPE). A BPE is attributed to no check. It never decides a
// clause, in either direction:
//   - a pass stands only where the clause's own evidence, with every BPE removed, still passes, and no BPE that could be the
//     clause's own effect (it fits the clause's selector without its actor and traceId pins: a background principal can act
//     for any requester, under its own trace) sits in the check's window or any later window;
//   - a fail stands only where it still fails both with every BPE removed and with every such BPE added.
// A clause whose verdict depends on how BPEs are attributed reads inconclusive:
//   background-unattributed   a BPE could change the verdict (it decided it, or it could be the clause's own effect)
//   background-unobserved     no BPE was seen, but an authoritative observer that could record one (it sees the clause's
//                             effect once the actor and traceId pins are dropped) did not decide absence in the check's window or a
//                             later one: failed, partial, or a net-only snapshot not exact for the selector
// Attribution only ever moves a settled pass or fail to inconclusive (an allowed-use control keeps an absence pass and
// any fail as a tag; its positive pass is withheld, since a repair is released on it). It never releases a pass,
// never creates a fail, never reads a correlation token and never runs without the declaration. Events committed after the
// final mark stay outside every window (the run-end window is the last settlement gap, whose length is the final settle).
// Classification is inclusive: no source or resource pin on a background select (copies of one effect in an audit table
// and a snapshot differ in both), a null or unlisted actor fits an actor pin, an unreadable field fits, an event with no
// resource fits any resource pin in every "could be" test, and no vocabulary gate applies on the BPE side.
import { windowSees, baseSelector, validateSelector, EFFECT_LIMITS } from '../../src/effect-events.mjs';
import { fitsSelector, matchedLocated, selectorsOf, onlyDeclared } from '../../src/http-settlement.mjs';
import { withoutUpstream } from '../../src/effect-outcome.mjs';
import { decidesAbsence } from '../../src/custody.mjs';
import { judgeOnly, ONLY_KIND } from '../../integrations/collateral/only.mjs';

export const ATTRIBUTION_SCHEMA = 'scopehaven-attribution/1';
export const ATTRIBUTION_LIMITS = Object.freeze({ sources: 16 });
export const BACKGROUND_SELECT_KEYS = Object.freeze(['actor', 'operation', 'name']);
export const ATTRIBUTION_REASONS = Object.freeze(['background-unattributed', 'background-unobserved']);
export const ATTRIBUTION_BASIS = Object.freeze({
  'background-unattributed': 'Attribution: a committed effect from a declared background source could change this verdict (it decided it, or it could be this check\'s own effect done by the background source), so neither verdict is attributed to this check (background-unattributed).',
  'background-unobserved': 'Attribution: an authoritative observer that could record a declared background source\'s effect did not decide absence in this check\'s window or a later one (failed, partial or not exact; background-unobserved), so a background effect could have been missed.',
});
// The fields a clause or its assertion row carries for a finding.
export const attributionFields = d => d?.attribution ? { attribution: d.attribution } : {};

const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const bounded = (value, maximum) => typeof value === 'string' && value.length >= 1 && value.length <= maximum && !/[\u0000-\u001f\u007f]/.test(value);
const SOURCE_ID = /^[A-Za-z0-9_-]{1,48}$/;
// The background list's problem, naming positions only (never values), or null when it is valid.
export function backgroundProblem(background) {
  if (!Array.isArray(background) || background.length < 1 || background.length > ATTRIBUTION_LIMITS.sources) return `"background" must be a list of 1 to ${ATTRIBUTION_LIMITS.sources} sources`;
  const ids = new Set();
  for (const [i, source] of background.entries()) {
    const at = `background source ${i + 1}`;
    if (!plain(source) || Reflect.ownKeys(source).length !== 2 || !Object.hasOwn(source, 'id') || !Object.hasOwn(source, 'select')) return `${at}: each source is exactly { id, select }`;
    if (typeof source.id !== 'string' || !SOURCE_ID.test(source.id) || ids.has(source.id)) return `${at}: needs a unique "id" (1-48 letters, digits, "_" or "-")`;
    ids.add(source.id);
    if (!plain(source.select) || !Reflect.ownKeys(source.select).length || Reflect.ownKeys(source.select).some(key => !BACKGROUND_SELECT_KEYS.includes(key))) return `${at}: "select" pins only ${BACKGROUND_SELECT_KEYS.join(', ')} (at least one); source, resource, outcome, traceId and fields are refused`;
    try { validateSelector(source.select, at); } catch { return `${at}: "select" needs a known operation and a name of at most 200 characters (exact, or { "prefix" })`; }
    if (Object.hasOwn(source.select, 'actor') && !bounded(source.select.actor, EFFECT_LIMITS.principal)) return `${at}: "actor" must be a principal of 1 to ${EFFECT_LIMITS.principal} characters`;
  }
  return null;
}
// The declaration's problem, or null: exactly { background }.
export function attributionDeclarationProblem(declaration) {
  if (!plain(declaration) || Reflect.ownKeys(declaration).length !== 1 || !Object.hasOwn(declaration, 'background')) return 'attribution is { "background": [ { "id", "select" } ] }';
  return backgroundProblem(declaration.background);
}
// The positions (1-based) of the sources no observer can see once the actor pin is dropped (an observer that cannot name
// actors still records the worker's effect). observers: the started observers at run start, or a sealed run's windows.
export function backgroundUnseen(background, observers) {
  return background.flatMap((source, i) => {
    const { actor, ...rest } = source.select;
    return observers.some(o => { try { return windowSees({ source: o.source, scope: o.scope }, rest); } catch { return false; } }) ? [] : [i + 1];
  });
}
// Is this committed event background-possible? Memoised per event object.
export function backgroundClassifier(background) {
  const memo = new WeakMap();
  return event => {
    if (!memo.has(event)) memo.set(event, event.outcome === 'committed' && background.some(source => fitsSelector(event, source.select)));
    return memo.get(event);
  };
}
// Could this event be the one a selector describes? An event with no resource never proves exclusion by a resource pin.
const withoutKey = (select, key) => { const { [key]: _, ...rest } = select; return rest; };
export const fitsWide = (event, select) => fitsSelector(event, event.resource === null && Object.hasOwn(select, 'resource') ? withoutKey(select, 'resource') : select);
// Do two name or operation rules (exact text or { prefix }, or absent) admit a common value?
const textRule = rule => typeof rule === 'string' ? { exact: rule } : rule?.prefix !== undefined ? { prefix: rule.prefix } : null;
function overlaps(a, b) {
  const x = textRule(a), y = textRule(b);
  if (x === null || y === null) return true;
  if (x.exact !== undefined && y.exact !== undefined) return x.exact === y.exact;
  if (x.exact !== undefined) return x.exact.startsWith(y.prefix);
  if (y.exact !== undefined) return y.exact.startsWith(x.prefix);
  return x.prefix.startsWith(y.prefix) || y.prefix.startsWith(x.prefix);
}
const sourceOverlaps = (source, sa) => (source.select.operation === undefined || sa.operation === undefined || source.select.operation === sa.operation) && overlaps(source.select.name, sa.name);
const positive = d => d.kind === 'effect.exists' || (d.kind === 'effect.count' && Number.isSafeInteger(d.expected) && d.expected >= 1);

// rows: the rows that have an effect window, in run order: [{ effects: settled decisions (declared effects, then claims), windows }].
// gaps: [windows] with gaps.length === rows.length + 1 (gaps[k] before row k; the last gap is the run-end window).
// barriers: per row, its barrier windows (per-check settlement), or undefined. Returns, per row and clause, a reason or null.
// Positions order every window: gap j is 3j, row j's own window 3j + 1, barrier j 3j + 2, so "at or after row k's window"
// is pos >= 3k + 1. A clause is examined only when its verdict is pass or fail and it has a kind (an untriggered claim has
// none). A boundary pass settlement withheld is already inconclusive; an allowed-use control's pass that settlement only
// tagged is examined like any other, so a weaker later window (a settlement tag) never releases what a stronger one
// withholds. Cost: each BPE is classified once against at most 16 sources; per clause, the BPEs named
// like its selector (an index by exact name, plus prefix-named ones) at or after its window, and the authoritative windows
// that did not cover theirs. No search over combinations.
export function attributionFindings(rows, gaps, barriers, { background } = {}) {
  if (!Array.isArray(rows) || !Array.isArray(gaps) || gaps.length !== rows.length + 1 || !gaps.every(Array.isArray)) throw new Error('attribution-gaps');
  if (barriers !== undefined && !(Array.isArray(barriers) && barriers.length === rows.length && barriers.every(Array.isArray))) throw new Error('attribution-barriers');
  if (backgroundProblem(background) !== null) throw new Error('attribution-background');
  const isBg = backgroundClassifier(background);
  const located = [
    ...gaps.flatMap((g, j) => g.map(w => ({ w, pos: 3 * j }))),
    ...rows.flatMap((r, j) => r.windows.map(w => ({ w, pos: 3 * j + 1 }))),
    ...(barriers ?? []).flatMap((b, j) => b.map(w => ({ w, pos: 3 * j + 2 }))),
  ];
  // Every BPE once, with its observer instance and position; indexed by exact name (each event has one name).
  const bpes = located.flatMap(({ w, pos }) => w.events.filter(isBg).map(e => ({ e, instance: w.instanceId, pos })));
  const byName = new Map();
  for (const b of bpes) { if (!byName.has(b.e.name)) byName.set(b.e.name, []); byName.get(b.e.name).push(b); }
  const candidates = sa => typeof sa.name === 'string' ? byName.get(sa.name) ?? [] : bpes;
  // Per observer instance, the BPEs at or after row k's window that could be the clause's effect (no windowSees gate:
  // a vocabulary limits absence claims, not presence).
  const fittingBpes = (sa, k) => {
    const per = new Map();
    for (const b of candidates(sa)) if (b.pos >= 3 * k + 1 && fitsWide(b.e, sa)) per.set(b.instance, (per.get(b.instance) ?? 0) + 1);
    return per;
  };
  // Authoritative windows that did not cover theirs: only these can be blind (a complete window that sees the base
  // selector decides absence for it, and for the selector itself when it sees that).
  const uncovered = located.filter(({ w }) => w.scope?.evidence === 'authoritative' && w.coverage !== 'complete');
  const blind = (sa, kind, k) => uncovered.some(({ w, pos }) => {
    if (pos < 3 * k + 1) return false;
    const base = baseSelector(sa);
    return windowSees(w, base) && !decidesAbsence(w, windowSees(w, sa) ? sa : base, kind);
  });
  const relevant = sa => background.some(source => sourceOverlaps(source, sa));
  // The first row whose selectors (every clause and claim, whatever its verdict) could explain the event. An upstream outcome
  // requirement (src/effect-outcome.mjs) says nothing about which check caused a send, so it is set aside, as in settlement.
  const rowSelectors = rows.map(r => r.effects.flatMap(selectorsOf).filter(plain).map(withoutUpstream));
  const firstFitMemo = new WeakMap();
  const firstFit = e => {
    if (!firstFitMemo.has(e)) firstFitMemo.set(e, rowSelectors.findIndex(list => list.some(s => fitsWide(e, s))));
    return firstFitMemo.get(e);
  };
  const earlier = (e, k) => { const j = firstFit(e); return j !== -1 && j < k; };
  return rows.map((row, k) => row.effects.map(d => {
    if (!plain(d) || !['pass', 'fail'].includes(d.verdict) || d.kind === null || d.kind === undefined) return null;
    if (d.kind === ONLY_KIND) {
      if (d.verdict !== 'fail') return null;
      // An effect.only fail stands only when it still fails with every BPE removed.
      if (!row.windows.some(w => w.events.some(isBg))) return null;
      try { return judgeOnly(onlyDeclared(d), row.windows.map(w => ({ ...w, events: w.events.filter(e => !isBg(e)) })), { fields: true }).verdict === 'fail' ? null : 'background-unattributed'; }
      catch { return 'background-unattributed'; }
    }
    // Who acted and under which trace are attribution, not content: a background principal can act for any requester,
    // under its own trace, so neither pin excludes a BPE.
    const sa = withoutKey(withoutKey(d.select, 'actor'), 'traceId');
    const own = matchedLocated(d, row.windows).map(x => x.e);
    const unobserved = () => relevant(sa) && blind(sa, d.kind, k) ? 'background-unobserved' : null;
    if (d.kind === 'effect.none') {
      if (d.verdict === 'fail') return own.length > 0 && own.every(isBg) ? 'background-unattributed' : null;
      return fittingBpes(sa, k).size > 0 ? 'background-unattributed' : unobserved();
    }
    if (d.kind === 'effect.exists') {
      if (d.verdict === 'pass') return own.length > 0 && own.every(e => isBg(e) || earlier(e, k)) ? 'background-unattributed' : null;
      return fittingBpes(sa, k).size > 0 ? 'background-unattributed' : unobserved();
    }
    if (d.kind !== 'effect.count') return null;
    // A keyed count (countBy, src/idempotency.mjs) is decided in applications, not sends, so the send interval below is in
    // other units: any background effect that could be the clause's own leaves it unattributed; with none, only a pass or a
    // too-few fail can rest on an unobserved window.
    if (d.countBy !== undefined) {
      if (fittingBpes(sa, k).size > 0) return 'background-unattributed';
      return d.verdict === 'pass' || !(Number.isSafeInteger(d.applications?.high) && d.applications.high > d.expected) ? unobserved() : null;
    }
    // The count's units must be the evaluator's: otherwise no interval below is in the same units as expected.
    if (own.length !== d.matched) return 'background-unattributed';
    const counting = row.windows.find(w => w.scope?.evidence === 'authoritative' && windowSees(w, d.select))?.instanceId;
    const per = fittingBpes(sa, k), n = d.expected;
    const lo = own.filter(e => !isBg(e)).length;
    // Two observers of one store record one effect twice, so other observers bound it by a max, not a sum.
    const hi = Math.max(lo + (per.get(counting) ?? 0), ...[...per].filter(([instance]) => instance !== counting).map(([, x]) => x));
    if (d.verdict === 'pass') return lo < n || hi > n ? 'background-unattributed' : unobserved();
    if (lo <= n && n <= hi) return 'background-unattributed';
    return n > hi ? unobserved() : null;
  }));
}

// Apply one row's findings to its settled clauses under the check's role. Only a pass or a fail is ever touched. A
// boundary clause reads inconclusive; an allowed-use control keeps an absence pass or a fail and carries the reason as a
// tag, and its positive pass (effect.exists, or effect.count of at least one) is withheld, since compareRuns releases a
// repair only on passing controls.
export function applyAttribution(decisions, findings, role = 'boundary') {
  return decisions.map((d, i) => {
    const reason = findings?.[i] ?? null;
    if (reason === null || !['pass', 'fail'].includes(d.verdict)) return d;
    if (!ATTRIBUTION_REASONS.includes(reason)) throw new Error('attribution-reason');
    if (role === 'control' && !(d.verdict === 'pass' && positive(d))) return { ...d, attribution: reason };
    return { ...d, verdict: 'inconclusive', basis: `${d.basis} ${ATTRIBUTION_BASIS[reason]}`, attribution: reason };
  });
}

// The run record: present exactly when the target declares attribution.
export const attributionRecord = declaration => ({ schema: ATTRIBUTION_SCHEMA, background: declaration.background });
// Revalidate a sealed record; returns the declaration it carries ({ background }).
export function validateAttributionRecord(record) {
  if (!plain(record) || Reflect.ownKeys(record).length !== 2 || record.schema !== ATTRIBUTION_SCHEMA || !Object.hasOwn(record, 'background') || backgroundProblem(record.background) !== null) throw new Error('attribution-record');
  return { background: record.background };
}
