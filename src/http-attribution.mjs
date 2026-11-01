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
// Classification is inclusive: no source pin and, except on an egress send (coverage v2 Part C), no resource pin on a
// background select (copies of one effect in an audit table and a snapshot differ in both), a null or unlisted actor fits an actor pin, an unreadable field fits, an event with no
// resource fits any resource pin in every "could be" test, and no vocabulary gate applies on the BPE side.
// Returned ids (readiness edge E3, src/id-closure.mjs) are one override, applied in one place below (bgNotOwn): an
// effect.exists pass that gap 5 would withhold stands when a matched background-possible send is owned by this check through
// a returned id, that is, it refers to an object one of this check's own sends had the upstream create (a seed: carrying
// this check's own correlation token, not background-possible, fitting this check's own selectors and no earlier check's). An object link is not causation, so it
// never decides a fail, never excuses a send owned by another check (a check that makes the application act on another
// check's object produces exactly that), and never touches an absence clause, effect.count or effect.only.
//
// Late fails (readiness gap 2, opt-in by the target's "timing": { ..., "lateFails": "withhold" }, src/http-timing.mjs): a
// fail that a late effect could explain is not charged to the check. Only where no background rule applied:
//   effect.none fail   every deciding event is background-possible or fits an earlier check's selector (its late effect)
//   effect.exists fail an event fitting the clause's own selector was recorded after its window (its own effect, seen late)
//   effect.count fail  the count, without the earlier-explained events and with the late fitting ones, could be the expected one
//   effect.only fail   it no longer fails once the earlier-explained and background-possible events are removed
// each read late-unattributed. Like the rules above it only ever moves a fail to inconclusive (an allowed-use control keeps
// the fail with a tag); it never touches a pass, never releases a withheld one, and reads no timestamp or horizon.
import { windowSees, baseSelector, validateSelector, EFFECT_LIMITS, custodyWindows, custodyRunWindows } from './effect-events.mjs';
import { fitsSelector, matchedLocated, selectorsOf, onlyDeclared } from './http-settlement.mjs';
import { withoutUpstream } from './effect-outcome.mjs';
import { closureOwners } from './id-closure.mjs';
import { decidesAbsence } from './custody.mjs';
import { judgeOnly, ONLY_KIND } from '../integrations/collateral/only.mjs';

export const ATTRIBUTION_SCHEMA = 'scopehaven-attribution/1';
export const ATTRIBUTION_LIMITS = Object.freeze({ sources: 16 });
export const BACKGROUND_SELECT_KEYS = Object.freeze(['actor', 'operation', 'name', 'resource']);
// Coverage v2 Part C: an egress source may pin the resource the egress recorder names a send by, "<METHOD> <declared path>" or
// "<METHOD> *" for a path outside the declared ones, exact (the recorder's vocabulary is finite), with operation send and an
// exact host. Which resources a declared destination can produce is checked against the profile (contracts.mjs). A copy of the
// effect another observer records under another resource is simply not background: narrowing never widens what is background.
export const EGRESS_RESOURCE = /^[A-Z]{3,7} (\*|\/[\x21-\x7e]{0,190})$/;
export const ATTRIBUTION_REASONS = Object.freeze(['background-unattributed', 'background-unobserved', 'late-unattributed']);
export const ATTRIBUTION_BASIS = Object.freeze({
  'background-unattributed': 'Attribution: a committed effect from a declared background source could change this verdict (it decided it, or it could be this check\'s own effect done by the background source), so neither verdict is attributed to this check (background-unattributed).',
  'background-unobserved': 'Attribution: an authoritative observer that could record a declared background source\'s effect did not decide absence in this check\'s window or a later one (failed, partial or not exact; background-unobserved), so a background effect could have been missed.',
  'late-unattributed': 'Attribution: this fail could rest on an earlier check\'s late effect landing in this check\'s window, or on this check\'s own effect arriving after its window (late-unattributed), so it is not attributed to this check.',
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
    if (!plain(source.select) || !Reflect.ownKeys(source.select).length || Reflect.ownKeys(source.select).some(key => !BACKGROUND_SELECT_KEYS.includes(key))) return `${at}: "select" pins only ${BACKGROUND_SELECT_KEYS.join(', ')} (at least one, and resource only on an egress send); source, outcome, traceId and fields are refused`;
    try { validateSelector(source.select, at); } catch { return `${at}: "select" needs a known operation and a name of at most 200 characters (exact, or { "prefix" })`; }
    if (Object.hasOwn(source.select, 'actor') && !bounded(source.select.actor, EFFECT_LIMITS.principal)) return `${at}: "actor" must be a principal of 1 to ${EFFECT_LIMITS.principal} characters`;
    if (Object.hasOwn(source.select, 'resource') && !(source.select.operation === 'send' && typeof source.select.name === 'string' && typeof source.select.resource === 'string' && EGRESS_RESOURCE.test(source.select.resource) && !source.select.resource.startsWith('CONNECT ')))
      return `${at}: a "resource" pin needs operation "send", an exact host "name" and an exact egress resource "<METHOD> <declared path>" or "<METHOD> *"`;
  }
  return null;
}
// The declaration's problem, or null: exactly { background }.
export function attributionDeclarationProblem(declaration) {
  if (!plain(declaration) || Reflect.ownKeys(declaration).length !== 1 || !Object.hasOwn(declaration, 'background')) return 'attribution is { "background": [ { "id", "select" } ] }';
  return backgroundProblem(declaration.background);
}
// The positions (1-based) of the sources no observer can see once the actor and resource pins are dropped (an observer that
// cannot name actors still records the worker's effect; an egress resource pin is checked against the profile instead). observers: the started observers at run start, or a sealed run's windows.
export function backgroundUnseen(background, observers) {
  custodyWindows(observers, 'backgroundUnseen');
  return background.flatMap((source, i) => {
    const { actor, resource, ...rest } = source.select;
    return observers.some(o => { try { return windowSees({ source: o.source, scope: o.scope }, rest); } catch { return false; } }) ? [] : [i + 1];
  });
}
// Egress events whose resource the recorder could not name for certain (Part C review): the recorder names a send by the declared
// path its raw and decoded paths match, and flags a path whose decoding fails or whose two readings differ only on the window (a
// v1 reason egress-path-ambiguous, which names no send, or a v2 scoped entry for the host with no resource). Every event of such a
// window (v1), or of such a host in it (v2), may be another resource, so it fits every resource pin: a pin never releases on it.
export function resourceUncertain(windows) {
  custodyWindows(windows, 'resourceUncertain');
  const uncertain = new WeakSet();
  for (const w of windows) {
    if (w?.source !== 'http-egress' || !Array.isArray(w.events)) continue;
    // A scoped (v2) window's reason only summarises its entries, so it names the ambiguity per host there.
    const v1 = !Array.isArray(w.scoped) && typeof w.reason === 'string' && w.reason.split(',').includes('egress-path-ambiguous');
    const hosts = new Set(Array.isArray(w.scoped) ? w.scoped.filter(e => e !== null && typeof e === 'object' && e.resource === null).map(e => e.name) : []);
    for (const e of w.events) if (v1 || hosts.has(e.name)) uncertain.add(e);
  }
  return uncertain;
}
// Is this committed event background-possible? Memoised per event object. uncertain: resourceUncertain's set.
export function backgroundClassifier(background, uncertain = null) {
  const memo = new WeakMap();
  return event => {
    if (!memo.has(event)) memo.set(event, event.outcome === 'committed' && background.some(source => fitsWide(uncertain?.has(event) ? { ...event, resource: null } : event, source.select)));
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
// lateFails: true adds the late rules (the background list may then be empty).
// tokens: on a correlated run, the sent rows' correlation tokens (src/http-settlement.mjs settlementTokens: token -> row index or
// null); a returned-id seed must carry its own check's token. Without them no send seeds a closure.
export function attributionFindings(rows, gaps, barriers, { background, lateFails = false, tokens } = {}) {
  custodyRunWindows(rows, gaps, barriers, 'attributionFindings');
  if (!Array.isArray(rows) || !Array.isArray(gaps) || gaps.length !== rows.length + 1 || !gaps.every(Array.isArray)) throw new Error('attribution-gaps');
  if (barriers !== undefined && !(Array.isArray(barriers) && barriers.length === rows.length && barriers.every(Array.isArray))) throw new Error('attribution-barriers');
  if (typeof lateFails !== 'boolean') throw new Error('attribution-late');
  if (!(tokens === undefined || tokens instanceof Map)) throw new Error('attribution-tokens');
  if (!(lateFails && Array.isArray(background) && background.length === 0) && backgroundProblem(background) !== null) throw new Error('attribution-background');
  const isBg = backgroundClassifier(background, resourceUncertain([...rows.flatMap(r => r.windows), ...gaps.flat(), ...(barriers ?? []).flat()]));
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
  // Coverage v2: a scoped egress window is read through coverageFor (complete for a selector none of its entries fits, once followed).
  const blind = (sa, kind, k, verdict, countBy) => uncovered.some(({ w, pos }) => {
    if (pos < 3 * k + 1) return false;
    const base = baseSelector(sa);
    return windowSees(w, base) && !decidesAbsence(w, windowSees(w, sa) ? sa : base, kind, { outcome: verdict, hostWide: countBy !== undefined });
  });
  const relevant = sa => background.some(source => sourceOverlaps(source, sa));
  // The first row whose selectors (every clause and claim, whatever its verdict) could explain the event. An upstream outcome
  // requirement (src/effect-outcome.mjs) says nothing about which check caused a send, so it is set aside, as in settlement.
  const rowSelectors = rows.map(r => r.effects.flatMap(selectorsOf).filter(plain).map(withoutUpstream));
  // Each distinct selector once, with the first row that declares it, in that order: the first one that fits gives the first row
  // whose selectors fit (the same answer as scanning every row's list), linear in the distinct selectors.
  const distinct = [], seenSelector = new Set();
  rowSelectors.forEach((list, row) => { for (const s of list) { const key = JSON.stringify(s); if (!seenSelector.has(key)) { seenSelector.add(key); distinct.push({ s, row }); } } });
  const firstFitMemo = new WeakMap();
  const firstFit = e => {
    if (!firstFitMemo.has(e)) firstFitMemo.set(e, distinct.find(({ s }) => fitsWide(e, s))?.row ?? -1);
    return firstFitMemo.get(e);
  };
  const earlier = (e, k) => { const j = firstFit(e); return j !== -1 && j < k; };
  // Returned-id owners (E3): a seed of check k must be k's own by every test available here, its own correlation token included
  // (the application writes the token, so requiring it only removes seeds; without correlation nothing seeds).
  const rowToken = new Map([...(tokens ?? [])].filter(([, k]) => Number.isInteger(k)).map(([token, k]) => [k, token]));
  const owner = closureOwners(rows, gaps, barriers, (e, k) => rowToken.has(k) && e.correlation?.settlementToken === rowToken.get(k)
    && !isBg(e) && rowSelectors[k].some(s => fitsWide(e, s)) && !earlier(e, k));
  // Late fails: the committed events after row k's window that fit a selector, per observer instance. An upstream outcome
  // requirement is set aside: a later send could be the clause's own whatever its outcome reads.
  const lateFitting = (select, k) => {
    const per = new Map();
    for (const { w, pos } of located) if (pos > 3 * k + 1) for (const e of w.events) if (e.outcome === 'committed' && !isBg(e) && fitsWide(e, withoutUpstream(select))) per.set(w.instanceId, (per.get(w.instanceId) ?? 0) + 1);
    return per;
  };
  const late = (d, row, k) => {
    if (d.verdict !== 'fail') return null;
    const explained = e => isBg(e) || earlier(e, k);
    if (d.kind === ONLY_KIND) {
      try { return judgeOnly(onlyDeclared(d), row.windows.map(w => ({ ...w, events: w.events.filter(e => !explained(e)) })), { fields: true, countBy: true }).verdict === 'fail' ? null : 'late-unattributed'; }
      catch { return 'late-unattributed'; }
    }
    const own = matchedLocated(d, row.windows).map(x => x.e);
    if (d.kind === 'effect.none') return own.length > 0 && own.every(explained) ? 'late-unattributed' : null;
    if (d.kind === 'effect.exists') return lateFitting(d.select, k).size > 0 ? 'late-unattributed' : null;
    if (d.kind !== 'effect.count') return null;
    const sa = withoutKey(withoutKey(d.select, 'actor'), 'traceId'), lateOwn = lateFitting(d.select, k);
    // A keyed count is in applications, not sends: an earlier-explained send leaves it unattributed, and a late fitting one
    // only when the count was not already too high (a later send can only add applications).
    if (d.countBy !== undefined || own.length !== d.matched) {
      const tooMany = d.countBy !== undefined ? Number.isSafeInteger(d.applications?.low) && d.applications.low > d.expected : d.matched > d.expected;
      return own.some(explained) || (lateOwn.size > 0 && !tooMany) ? 'late-unattributed' : null;
    }
    const counting = row.windows.find(w => w.scope?.evidence === 'authoritative' && windowSees(w, d.select))?.instanceId;
    const per = fittingBpes(sa, k), n = d.expected, lo = own.filter(e => !explained(e)).length, loBg = own.filter(e => !isBg(e)).length;
    const hi = Math.max(loBg + (per.get(counting) ?? 0) + (lateOwn.get(counting) ?? 0), ...[...new Set([...per.keys(), ...lateOwn.keys()])].filter(i => i !== counting).map(i => (per.get(i) ?? 0) + (lateOwn.get(i) ?? 0)));
    return lo <= n && n <= hi ? 'late-unattributed' : null;
  };
  return rows.map((row, k) => row.effects.map(d => {
    if (!plain(d) || !['pass', 'fail'].includes(d.verdict) || d.kind === null || d.kind === undefined) return null;
    // The background rules run only with declared sources; the late rules only on what they left alone.
    const reason = background.length ? backgroundRule(d, row, k) : null;
    return reason === null && lateFails ? late(d, row, k) : reason;
  }));
  function backgroundRule(d, row, k) {
    // E3, the one use of returned ids: a matched BPE owned by this check is its own effect for an effect.exists pass.
    const bgNotOwn = e => isBg(e) && owner(e) !== k;
    if (d.kind === ONLY_KIND) {
      if (d.verdict !== 'fail') return null;
      // An effect.only fail stands only when it still fails with every BPE removed.
      if (!row.windows.some(w => w.events.some(isBg))) return null;
      try { return judgeOnly(onlyDeclared(d), row.windows.map(w => ({ ...w, events: w.events.filter(e => !isBg(e)) })), { fields: true, countBy: true }).verdict === 'fail' ? null : 'background-unattributed'; }
      catch { return 'background-unattributed'; }
    }
    // Who acted and under which trace are attribution, not content: a background principal can act for any requester,
    // under its own trace, so neither pin excludes a BPE.
    const sa = withoutKey(withoutKey(d.select, 'actor'), 'traceId');
    const own = matchedLocated(d, row.windows).map(x => x.e);
    const unobserved = () => relevant(sa) && blind(sa, d.kind, k, d.verdict, d.countBy) ? 'background-unobserved' : null;
    if (d.kind === 'effect.none') {
      if (d.verdict === 'fail') return own.length > 0 && own.every(isBg) ? 'background-unattributed' : null;
      return fittingBpes(sa, k).size > 0 ? 'background-unattributed' : unobserved();
    }
    if (d.kind === 'effect.exists') {
      if (d.verdict === 'pass') return own.length > 0 && own.every(e => bgNotOwn(e) || earlier(e, k)) ? 'background-unattributed' : null;
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
  }
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
