// App logs in a run (src/app-log-rules.mjs): the run record of each declared app log, the sealing and binding of the windows a
// check's trace carries beside its observer windows (data.appLogWindows), and admissions. Custody decision paths never see
// these windows (src/effect-events.mjs custodyWindows refuses one).
//
// Admissions ("use": "admission"; APP-LOG design R0 section 4.2 as amended by addendum R1 sections 1 and 6). After every custody
// rule (decide, settle, attribute, pair) a clause that did not fail is read once more against the application's own log: it
// fails when the log records, as committed, an action of the check's own actor in the check's own window that the clause
// forbids. That is all an admission can do. It never makes, extends or rescues a pass, and a custody fail stays a custody fail.
// Which entries are the check's (B1): an entry of the check's app-log window (logged between its request and its cut, taken
// before any witness request, so never a late line) whose actor maps to the check's own principal, whose outcome is committed,
// that fits no declared background source (an actor-pinned source never fits the check's own actor; a shape-only one fits by
// operation and name, its resource set aside, except that an exact egress resource pin is kept for a name every rule of which is
// an egress rule with an exact resource: both then name the send the same way, by the application's own action word; PR-1c
// item e), and that fits no selector of an earlier check by the same principal (that check's late effect). Every other entry is
// unattributed and decides nothing.
// What it reads (addendum R1 6.1 and 6.4; PR-1c items a and b): a clause's selector pinned to an observer source is read on the
// log only for an exact name every rule of which lists that source in observedAs (the record's projection). Field pins read a
// rule's declared constants, or a value read from the line through the rule's closed word map (a word the map does not list
// captures nothing, so the field reads unknown; its values are strings, so only equals and in can decide on it); an upstream or
// trace pin never matches. effect.none (and a refusal claim): any such entry decided-matches, when the selector can be read.
// effect.count without countBy: more such entries than expected (never on a window with a repeated entry id). effect.only
// without countBy: judged over the check's entries alone, an entry outside the declared set or beyond its count (never on a
// window with a repeated entry id; an allow pinned to a background actor never excuses the check's own actor, the strict
// reading). A selector of the clause the log cannot read is dropped only for the entries provably not its effect: every rule of
// the entry's exact name lists the selector's source in distinctFrom. Any other entry is set aside (never offending, never
// counted), so a dropped selector never makes an entry offending that the whole clause would excuse. effect.exists, a success
// claim, countBy, an unreadable field and absence in the log are never admissions.
// The admitted clause reads fail with custody subject-writable (the application's own record decided it), backend observation
// not authoritative, the finding app-log-unobserved-admission and the log named as its source; contradicts says whether an
// authoritative observer that sees the clause covered the window and recorded no matching committed effect.
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { validateWindow, matchState, custodyWindows, REASON_PATTERN } from './effect-events.mjs';
import { APP_LOG_SOURCE, APP_LOG_USES, DISTINCT_SOURCES, appLogInstanceId, appLogMappingDigest, appLogProjection, appLogScope, appLogReads } from './app-log-rules.mjs';
import { validateCaptured } from './body-fields.mjs';
import { decidesAbsence } from './custody.mjs';
import { fitsSelector, selectorsOf, onlyDeclared } from './http-settlement.mjs';
import { correlationToken } from './egress-rules.mjs';
import { withoutUpstream } from './effect-outcome.mjs';
import { fitsWide } from './http-attribution.mjs';
import { judgeOnly, expectedOf, ONLY_KIND, ONLY_LIMITS } from '../integrations/collateral/only.mjs';
import { digest } from './domain.mjs';

// The collector identity of the reader (integrations/observers/app-log.mjs): its bytes and the Node version, as the
// egress, SMTP and provider-feed collectors are named (src/collector-identity.mjs). It enters each run's appLogs record.
// app-log/2: events may carry the line's correlation token (fields.trace) and its key's digest (fields.key).
export const APP_LOG_COLLECTOR_LABEL = 'app-log/2';
const collectorDigest = async () => createHash('sha256').update('app-log.mjs\n').update(await readFile(new URL('../integrations/observers/app-log.mjs', import.meta.url))).update('\n').digest('hex');
export const APP_LOG_COLLECTOR = Object.freeze({ label: APP_LOG_COLLECTOR_LABEL, digest: await collectorDigest(), node: process.versions.node });
const validCollector = c => c !== null && typeof c === 'object' && !Array.isArray(c) && Object.keys(c).sort().join(',') === 'digest,label,node'
  && c.label === APP_LOG_COLLECTOR_LABEL && /^[a-f0-9]{64}$/.test(c.digest) && typeof c.node === 'string' && /^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(c.node);

// The run record: [{ id, use, route, mappingDigest, scope, principals, projection, reads, collector }] in profile order (the file
// path stays local). scope: what its windows can name; principals: the principals its actor map names; projection: { name:
// [source] }, which observer sources each exact name is the same effect as (admissions read a source-pinned selector on the log
// only there); reads: { values, distinct, exact } (src/app-log-rules.mjs appLogReads): the values each name's fields can capture,
// the sources each name is never the effect of, and the names whose resources are exact egress resources.
export const appLogRecords = appLogs => appLogs.map(o => ({ id: o.id, use: o.use, route: 'file', mappingDigest: appLogMappingDigest(o), scope: appLogScope(o),
  principals: Object.keys(o.logActors).sort(), projection: appLogProjection(o), reads: appLogReads(o), collector: APP_LOG_COLLECTOR }));
const plainObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
// A record map's own entry (names and pointers are data: "constructor" or "__proto__" never reads an inherited property).
const own = (map, key) => plainObject(map) && typeof key === 'string' && Object.hasOwn(map, key) ? map[key] : undefined;
const validProjection = p => plainObject(p) && Object.keys(p).length <= 256 && Object.entries(p).every(([name, list]) => name.length >= 1 && name.length <= 253 && Array.isArray(list) && list.length >= 1 && list.every(s => typeof s === 'string'));
const typeOf = v => v === null ? 'null' : typeof v;
const sortedUnique = list => list.every((x, i) => i === 0 || list[i - 1] < x);
// A record's reads, as appLogReads writes them, bound to its scope: values only for names and pointers the scope captures (the
// same pointers), each a valid captured scalar listed once; distinct sources from the declared menu, sorted and unique; exact
// names among the scope's names, sorted and unique.
const validReads = (r, scope) => {
  if (!plainObject(r) || Object.keys(r).sort().join(',') !== 'backgroundAllows,distinct,exact,perApplication,trace,values' || !plainObject(r.values) || !plainObject(r.distinct) || !Array.isArray(r.exact)
    || !Array.isArray(r.perApplication) || typeof r.trace !== 'boolean' || !Array.isArray(r.backgroundAllows) || r.backgroundAllows.length > 64) return false;
  const markKey = m => `${m.check}\n${String(m.effect).padStart(4, '0')}\n${String(m.allow).padStart(4, '0')}`;
  if (!r.backgroundAllows.every(m => plainObject(m) && Object.keys(m).sort().join() === 'allow,check,effect,source' && typeof m.check === 'string' && m.check.length >= 1 && m.check.length <= 80
    && Number.isSafeInteger(m.effect) && m.effect >= 0 && m.effect < 32 && Number.isSafeInteger(m.allow) && m.allow >= 0 && m.allow < ONLY_LIMITS.selectors && typeof m.source === 'string' && /^[A-Za-z0-9_-]{1,48}$/.test(m.source))
    || !r.backgroundAllows.every((m, i) => i === 0 || markKey(r.backgroundAllows[i - 1]) < markKey(m))) return false;
  const names = Array.isArray(scope?.names) ? scope.names : [];
  const valuesOk = Object.entries(r.values).every(([name, byPointer]) => {
    const declared = own(scope?.capture, name);
    if (!Array.isArray(declared) || !plainObject(byPointer) || Object.keys(byPointer).sort().join('\n') !== [...declared].sort().join('\n')) return false;
    return Object.entries(byPointer).every(([pointer, list]) => Array.isArray(list) && list.length >= 1 && list.length <= 4096
      && list.every((v, i) => { try { validateCaptured({ status: 'captured', values: { [pointer]: { type: typeOf(v), value: v } } }); } catch { return false; } return !list.slice(0, i).some(x => typeOf(x) === typeOf(v) && x === v); }));
  });
  const capturedNames = plainObject(scope?.capture) ? Object.keys(scope.capture) : [];
  return valuesOk && capturedNames.every(name => Object.hasOwn(r.values, name))
    && Object.entries(r.distinct).every(([name, list]) => names.includes(name) && Array.isArray(list) && list.length >= 1 && list.every(x => DISTINCT_SOURCES.includes(x)) && sortedUnique(list))
    && r.exact.every(name => typeof name === 'string' && names.includes(name)) && sortedUnique(r.exact)
    && r.perApplication.every(name => typeof name === 'string' && names.includes(name)) && sortedUnique(r.perApplication);
};
export const validAppLogRecords = records => Array.isArray(records) && records.length === 1 && records.every(r => plainObject(r)
  && Object.keys(r).sort().join(',') === 'collector,id,mappingDigest,principals,projection,reads,route,scope,use' && validReads(r.reads, r.scope) && typeof r.id === 'string' && /^[A-Za-z0-9_-]{1,48}$/.test(r.id)
  && APP_LOG_USES.includes(r.use) && r.route === 'file' && /^[a-f0-9]{64}$/.test(r.mappingDigest) && plainObject(r.scope) && r.scope.evidence === 'presence-only'
  && Array.isArray(r.principals) && r.principals.length >= 1 && r.principals.every(p => typeof p === 'string' && p.length >= 1 && p.length <= 128) && validProjection(r.projection) && validCollector(r.collector));

// A check's app-log windows as sealed: one per declared app log, in record order.
export const sealAppLogWindows = windows => windows.map(w => ({ source: w.source, instanceId: w.instanceId, scope: w.scope, coverage: w.coverage, reason: w.reason ?? null, events: w.events }));

// Revalidate a trace's sealed app-log windows against the run's records: exactly one per record, in order, each a valid
// presence-only app-log window of that record's instance. records null: the run declares no app log, so a trace carrying
// app-log windows is refused (and a trace of a run that declares one must carry them). Throws 'effect-trace'.
export function bindAppLogWindows(sealed, records) {
  if (records === null || records === undefined) { if (sealed !== undefined) throw new Error('effect-trace'); return []; }
  if (!Array.isArray(sealed) || !Array.isArray(records) || sealed.length !== records.length) throw new Error('effect-trace');
  return sealed.map((w, i) => {
    if (w === null || typeof w !== 'object' || Array.isArray(w) || Object.keys(w).sort().join(',') !== 'coverage,events,instanceId,reason,scope,source') throw new Error('effect-trace');
    if (w.source !== APP_LOG_SOURCE || w.instanceId !== appLogInstanceId(records[i].id)) throw new Error('effect-trace');
    if (!(w.reason === null || (typeof w.reason === 'string' && REASON_PATTERN.test(w.reason)))) throw new Error('effect-trace');
    try { validateWindow(w, `app-log window ${i + 1}`); } catch { throw new Error('effect-trace'); }
    if (w.scope.evidence !== 'presence-only' || !w.events.every(e => e.observer.kind === 'app-action-log' && e.observer.instanceId === w.instanceId)) throw new Error('effect-trace');
    // The window names what its record declared, and each event is one the reader could have written: an operation of the scope,
    // an actor that is a principal of the actor map, an unlisted digest or none, and captured values only at a pointer its name
    // declares, each one of the values its rules can capture there (a constant, or a selector value of a word map).
    if (digest(w.scope) !== digest(records[i].scope)) throw new Error('effect-trace');
    const capturable = (name, pointer, v) => (own(own(records[i].reads.values, name), pointer) ?? []).some(x => typeOf(x) === v.type && x === v.value);
    // Its correlation holds only what the reader writes: the token of fields.trace (when the log declares it) and a key digest.
    const correlationOk = c => plainObject(c) && Object.entries(c).every(([key, value]) => (key === 'settlementToken' && records[i].reads.trace === true && /^[0-9a-f]{32}$/.test(value))
      || (key === 'requestId' && /^key:([0-9a-f]{16}|unreadable)$/.test(value)));
    if (!w.events.every(e => correlationOk(e.correlation) && w.scope.operations.includes(e.operation) && (e.actor === null || records[i].principals.includes(e.actor) || /^unlisted:[0-9a-f]{16}$/.test(e.actor))
      && (e.captured === undefined || Object.entries(e.captured.values).every(([p, v]) => (own(w.scope.capture, e.name) ?? []).includes(p) && capturable(e.name, p, v))))) throw new Error('effect-trace');
    return w;
  });
}

// ---------------------------------------------------------------------------------------------------------------------------
// Admissions.
export const ADMISSION_FINDING = 'app-log-unobserved-admission';
// The fields a clause or its assertion row carries when an admission made it fail.
export const appLogFields = d => d?.appLog ? { appLog: d.appLog } : {};
const withoutKeys = (select, keys) => Object.fromEntries(Object.entries(select).filter(([key]) => !keys.includes(key)));
// A selector as the log names it: without its source pin, when that pin is a source the projection lists for its exact name.
// null when the log cannot name it.
export function projectSelector(select, projection) {
  if (!plainObject(select)) return null;
  if (select.source === undefined) return select;
  if (typeof select.name !== 'string' || !Array.isArray(own(projection, select.name)) || !own(projection, select.name).includes(select.source)) return null;
  return withoutKeys(select, ['source']);
}
// The check's own entries (B1 a to e): committed, by its principal, fitting no declared background source and no selector of
// an earlier check by the same principal (its source, trace, upstream and field pins set aside). Only entries of the check's own
// window are ever offered (the cut is before any witness).
// An earlier selector is read as attribution reads rowSelectors (fitsWide): an entry with no resource fits a resource-pinned one,
// and a selector left empty once its source, trace and upstream pins are set aside fits every entry. An earlier check that
// declares no effect and no claim offers no selector, so its late line is not set aside (a documented limit).
// exact: the names whose entries carry an exact egress resource in the recorder's form (the record's reads.exact). A background
// source's exact egress resource pin ("<METHOD> /path") is kept for those; for every other entry, and for a "<METHOD> *" pin, the
// resource is set aside (the entry then fits by operation and name).
const EXACT_EGRESS = /^[A-Z]{3,7} \//;
export function ownEntries(events, { principal, background = [], earlier = [], exact = [] }) {
  if (typeof principal !== 'string') return [];
  const kept = new Set(exact);
  const bg = background.map(source => ({ wide: withoutKeys(source.select, ['resource']), pinned: typeof source.select.resource === 'string' && EXACT_EGRESS.test(source.select.resource) ? source.select : null }));
  const isBackground = e => bg.some(({ wide, pinned }) => fitsSelector(e, pinned !== null && kept.has(e.name) && e.resource !== null ? pinned : wide));
  // Its field pins are set aside too: an earlier clause's pin says what that check must or must not do, not what it did, and a field
  // read from the line can read "no" where its late line is exactly that check's allowed send.
  const prior = earlier.filter(plainObject).map(s => withoutKeys(withoutUpstream(s), ['source', 'traceId', 'fields']));
  return events.filter(e => e.outcome === 'committed' && e.actor === principal && !isBackground(e) && !prior.some(s => fitsWide(e, s)));
}
const decided = (e, select) => matchState(e, { ...select, outcome: 'committed' }) === 'match';
// One clause's admission over the check's entries, or null.
// The applications a set of entries is (PR-1c item c): entries that share a key digest (fields.key) and their name and resource
// are one application; a keyless entry is one on its own. Only read on names whose rules declare "lines": "per-application".
const applicationKey = (e, i) => typeof e.correlation?.requestId === 'string' ? `${e.name}\n${e.resource}\n${e.correlation.requestId}` : `#${i}`;
const applications = list => { const seen = new Set(); return list.filter((e, i) => { const key = applicationKey(e, i); if (seen.has(key)) return false; seen.add(key); return true; }); };
// A line whose key the reader could not read: its application cannot be told, so no countBy clause is read on a window holding one.
export const UNREADABLE_KEY = 'key:unreadable';
// opts: { drop: Set of allow indices that are a background source's alone (never excuse the check's own actor), perApplication }
// drop: Map of allow index -> the background source's shape that entry must be (a mark that does not point at exactly that shape
// reads nothing: the clause is not read at all).
function admitOne(d, entries, window, projection, duplicate, distinct = {}, { drop = new Map(), perApplication = [] } = {}) {
  const perApp = new Set(perApplication);
  if (d.kind === 'effect.count' && d.countBy !== undefined) {
    // countBy: applications, not lines, and only where every matching line is one per application; never on a duplicated window.
    const select = projectSelector(d.select, projection);
    if (select === null || duplicate) return null;
    const matched = entries.filter(e => decided(e, select));
    if (!matched.length || matched.some(e => !perApp.has(e.name) || e.correlation?.requestId === UNREADABLE_KEY)) return null;
    const n = applications(matched).length;
    return n > d.expected ? n : null;
  }
  if (d.kind === 'effect.none' || (d.kind === 'effect.count' && d.countBy === undefined)) {
    const select = projectSelector(d.select, projection);
    if (select === null) return null;
    const n = entries.filter(e => decided(e, select)).length;
    if (d.kind === 'effect.none') return n > 0 ? n : null;
    return !duplicate && n > d.expected ? n : null;
  }
  if (d.kind === ONLY_KIND) {
    // A repeated entry id can double a line, and "beyond its count" would then read it; no admission on such a window.
    if (duplicate) return null;
    const declared = onlyDeclared(d);
    if ([...drop].some(([k, shape]) => !Array.isArray(declared.allow) || k >= declared.allow.length || shape === null || digest(declared.allow[k]) !== digest(shape))) return null;
    const items = (declared.expect ?? []).map(item => { const x = expectedOf(item); return { declared: x.select, select: projectSelector(x.select, projection), count: x.count }; });
    // An allow that is a background source's alone (allowBackground) never excuses the check's own actor: dropped here. Every
    // entry still judged is the check's own (B1), and the custody tier reads that allow as the plain shape allow it is.
    const allows = (declared.allow ?? []).flatMap((s, k) => drop.has(k) ? [] : [{ declared: s, select: projectSelector(s, projection) }]);
    const expect = items.filter(x => x.select !== null).map(({ select, count }) => ({ select, count }));
    const allow = allows.filter(x => x.select !== null).map(x => x.select);
    // The selectors the log cannot read (each pinned to a source; one without a source pin always projects). An entry is judged
    // only when it is provably none of them: every rule of its exact name lists each one's source in distinctFrom. Any other entry
    // is set aside: it could be one of them, so it is never offending and never counted toward an expected item.
    const unread = [...items, ...allows].filter(x => x.select === null).map(x => x.declared);
    if (unread.some(u => !plainObject(u) || typeof u.source !== 'string')) return null;
    const provablyNone = e => unread.every(u => (own(distinct, e.name) ?? []).includes(u.source));
    // Declared sources: only entries whose name is the same effect as one of them.
    let judged = (declared.sources ? entries.filter(e => (own(projection, e.name) ?? []).some(s => declared.sources.includes(s))) : entries).filter(provablyNone);
    if (!judged.length) return null;
    // countBy: only where every judged line is one per application; lines of one application collapse to it.
    if (declared.countBy !== undefined) { if (judged.some(e => !perApp.has(e.name) || e.correlation?.requestId === UNREADABLE_KEY)) return null; judged = applications(judged); }
    const { sources, counterparts, countBy, ...rest } = declared;
    let result;
    try { result = judgeOnly({ ...rest, expect, allow }, [{ ...window, coverage: 'complete', reason: null, events: judged }], { fields: true }); } catch { return null; }
    return result.verdict === 'fail' && result.counts.offending > 0 ? result.counts.offending : null;
  }
  return null;
}
// Per clause (declared effects, then claims, as decideEffects lists them): null, or { log, entries, contradicts }.
// windows: the check's observer windows (custody); appLogWindows: its sealed app-log windows; records: run.appLogs.
// check: the row's check id; token: its own correlation token (src/egress-rules.mjs correlationToken of its requestId) or null;
// foreign: the other rows' tokens.
// A background job may log its lines under the requesting user, and may carry the request's trace context. So an own entry that
// fits an actor-pinned background source's shape (its actor and resource set aside) is the check's only when, in this check's own
// window, either custody recorded nothing the source could be (its select, the actor pin also taking an effect with no known
// actor) or the log names the job's own principal on a committed line of that shape; and only when the line carries the check's
// own correlation token (fields.trace). Any other such entry is set aside (PR-1c item d). With fields.trace, a line carrying
// another check's token is that check's, never this one's.
export function admissionsFor(decisions, { windows = [], appLogWindows = [], records = null, principal, background = [], earlier = [], check = null, token = null, foreign = [] } = {}) {
  custodyWindows(windows, 'admissionsFor');
  if (!Array.isArray(records) || !Array.isArray(appLogWindows)) return decisions.map(() => null);
  const pinned = background.filter(s => plainObject(s?.select) && typeof s.select.actor === 'string').map(s => ({ id: s.id, select: s.select, shape: withoutKeys(s.select, ['actor', 'resource']) }));
  const others = new Set(foreign);
  return decisions.map((d, k) => {
    if (!plainObject(d) || d.kind === null || d.kind === undefined || d.kind === 'effect.exists') return null;
    for (const [i, record] of records.entries()) {
      const w = appLogWindows[i];
      if (record.use !== 'admission' || !plainObject(w) || w.source !== APP_LOG_SOURCE || w.coverage === 'failed') continue;
      const traced = record.reads?.trace === true;
      const ownToken = e => traced && typeof token === 'string' && e.correlation?.settlementToken === token;
      // In this check's own window: did custody record anything the job could be, and does the log name the job on such a line?
      const confirmedHere = s => !windows.some(x => x.events.some(e => e.outcome === 'committed' && fitsSelector(e, s.select)))
        || w.events.some(e => e.outcome === 'committed' && e.actor === s.select.actor && fitsSelector(e, s.shape));
      const told = e => pinned.every(s => !fitsSelector(e, s.shape) || (confirmedHere(s) && ownToken(e)));
      const notForeign = e => !(traced && typeof e.correlation?.settlementToken === 'string' && others.has(e.correlation.settlementToken));
      const entries = ownEntries(w.events, { principal, background, earlier, exact: record.reads?.exact ?? [] }).filter(told).filter(notForeign);
      const duplicate = typeof w.reason === 'string' && w.reason.split(',').includes('app-log-duplicate-id');
      const sourceShape = id => { const s = background.find(x => x?.id === id); return plainObject(s?.select) ? withoutKeys(s.select, ['actor']) : null; };
      const drop = new Map((record.reads?.backgroundAllows ?? []).filter(m => m.check === check && m.effect === k).map(m => [m.allow, sourceShape(m.source)]));
      const n = entries.length ? admitOne(d, entries, w, record.projection, duplicate, record.reads?.distinct ?? {}, { drop, perApplication: record.reads?.perApplication ?? [] }) : null;
      if (n === null) continue;
      const contradicts = d.kind !== ONLY_KIND && windows.some(x => decidesAbsence(x, d.select, d.kind) && !x.events.some(e => decided(e, d.select)));
      return { log: record.id, entries: n, contradicts };
    }
    return null;
  });
}
// The earlier checks' selectors an entry must not fit (B1 c): every clause, claim, expected and allowed selector.
export const earlierSelectors = decisionsList => decisionsList.flatMap(list => list.filter(d => plainObject(d) && d.kind !== null && d.kind !== undefined).flatMap(selectorsOf));
const admissionBasis = a => `Admission: the application's own action log (app log ${a.log}) records ${a.entries} committed action(s) of this check's own actor in its window that this clause forbids, so it fails (${ADMISSION_FINDING}${a.contradicts ? '; an observer held outside the application covered the window and recorded none' : ''}). The application wrote that record.`;
// Does a row's fail rest only on admissions (every failing assertion admitted)? Such a fail is never credited as repaired
// (compareRuns reads it unverified) and is never counted as over-blocking.
export const restsOnAdmissions = row => row?.status === 'fail' && Array.isArray(row.assertions) && row.assertions.some(a => a?.status === 'fail')
  && row.assertions.every(a => a?.status !== 'fail' || a?.appLog?.finding === ADMISSION_FINDING);
// Apply the admissions: a clause that did not fail and was admitted reads fail. Nothing else changes; a fail is never touched.
export function applyAdmissions(decisions, admissions) {
  return decisions.map((d, i) => {
    const a = admissions?.[i] ?? null;
    if (a === null || d.verdict === 'fail') return d;
    const { custodyReason, custodyUpgrade, ...rest } = d;
    return { ...rest, verdict: 'fail', custody: 'subject-writable', authoritative: false, basis: `${d.basis} ${admissionBasis(a)}`,
      appLog: { finding: ADMISSION_FINDING, log: a.log, entries: a.entries, contradicts: a.contradicts, custodyVerdict: d.verdict } };
  });
}
// Each observed row's admission context, in run order: rows [{ id, principal, requestId, decisions, windows }] (decisions: its
// declared clauses then claims; windows: its custody windows). Returns [{ principal, background, earlier, check, token, foreign }]:
// the selectors of the earlier rows by the same principal, the row's own correlation token, and every other row's token.
export function admissionRows(rows, { background = [] } = {}) {
  for (const r of rows) custodyWindows(Array.isArray(r.windows) ? r.windows : [], 'admissionRows');
  const tokens = rows.map(r => correlationToken(r.requestId));
  const prior = [];
  return rows.map((r, i) => {
    const context = { principal: r.principal, background, earlier: earlierSelectors(prior.filter(p => p.principal === r.principal).map(p => p.decisions)), check: r.id ?? null, token: tokens[i], foreign: tokens.filter((t, j) => j !== i && t !== null) };
    prior.push({ principal: r.principal, decisions: r.decisions });
    return context;
  });
}
// The validator's admission context per observed row (a sealed run, in run order), as the connector computed it.
export function admissionContexts(results, principals, background = []) {
  const observed = (Array.isArray(results) ? results : []).filter(row => plainObject(row?.trace?.[1]?.data) && Array.isArray(row.trace[1].data.effects));
  const rows = observed.map(row => {
    const data = row.trace[1].data;
    return { id: row.id, principal: plainObject(principals) ? principals[row.trace[0]?.data?.actorId] : undefined, requestId: row.trace[0]?.data?.requestId,
      decisions: [...data.effects, ...(Array.isArray(data.claims) ? data.claims.map(c => ({ kind: c?.clause ?? null, select: c?.select })) : [])], windows: data.windows, appLogWindows: data.appLogWindows };
  });
  const contexts = admissionRows(rows, { background });
  return new Map(observed.map((row, i) => [row, contexts[i]]));
}
