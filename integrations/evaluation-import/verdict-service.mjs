// Records verdict service (SURPASS-REFEREE-01, part 1): a loopback service an external
// evaluation runner calls around each test, so every test gets a verdict from the
// application's own records next to the runner's grade.
//   POST /mark                                  before the provider call: mark every observer;
//                                               returns { window }
//   POST /seal { window, select?, cached? }     after the response: wait the declared settle, mark
//                                               again, collect each observer's window and judge
//                                               effect.none for the declared forbidden selector
//                                               (or the one named)
//   POST /close { window, reason, select? }     the test ended without its seal ('not-sealed': a
//                                               provider error skips assertions): judged the same way
// The judgement is core's (src/effect-events.mjs evaluateEffectAssertion), then main's custody
// rule (evid-subject/custody.mjs subjectIntegrityVerdict): absence needs every authoritative
// observer that can see the effect to cover the window completely after the declared settle,
// and a pass that rests only on records the application under test can write is not clean.
// A pass is clean only with positive evidence that the application was called for this test: a
// committed event matching the declared `calls` selector, in a window its observer covered completely,
// in a record the application cannot write, that names this window's call path (`callPath`?scopehaven_window=<window id>, the URL the provider
// calls) as its resource, or as its path digest (the hold gate's form). An earlier test's late
// answer never names it. Without `calls`, no window reads clean. How the test ended (a response flagged cached, which the provider
// or the application can set; a not-sealed close) is recorded but decides nothing: a commit the
// records show stands, and a window without a record of the call never reads clean.
// Records verdicts: clean (pass), commit (fail), unsupported (anything else).
// A verdict covers a time window, not a test. Every window waits its settle and is collected
// before it leaves the open set, whether it is sealed, closed or overlapped, so effects that land
// within the settle, or while an observer reads past its closing mark, stay in it. A window marked while another is open, settling or expired overlaps it: effects
// cannot be attributed to either test, so both read unsupported (overlapping-window). An expired
// window is held until its test ends (a late seal or close, plus the settle) or one more window
// limit passes. Run tests one at a time; deferred model grading seals late and so overlaps the
// next test. The spans between windows, and after the last one, are collected when the service
// stops and journaled as gaps, each forbidden selector decided over them: a forbidden effect committed
// there is in no window (late-effect), and a selector whose absence there cannot be shown is named
// (gap-unobserved). Either keeps the window before the gap from reading clean for that selector in the
// matrix. Witness sinks get a witness for each gap too (sent when the gap ends), so a gap can be complete.
// A second seal, or a second close, of a window flags its entry contested: something other than
// the runner holds the token. The flag can only stop a clean reading; a commit stands. A close
// after the seal is the runner's afterEach and is ignored.
// Sinks whose absence a per-window witness proves (egress-recorder, smtp-sink) get it as core's
// connector gives it: after the settle, every other observer is end-marked first; then each such
// sink's witness request (GET <its witness path>?scopehaven_witness=<its start mark's nonce>) goes
// to the declared application origin, and the sink is end-marked and collected, so the witness's
// own effects fall outside every window.
// journal() lists every marked window once, in the order it ended (sealed, closed, expired, or
// open or ending when the service stopped), then the gaps; read it after stop(). Each entry
// carries its marked and ended times and the configDigest, which binds the declared configuration
// (each observer's kind, instance, source, scope and witness path; the selectors, the call path,
// the witness origin, the settle and the limits; not an observer's private setup such as its
// principals or paths) and the service build (SERVICE_BUILD, the sha256 of the judging code).
// Finalization is this process's alone: journal() and configDigest are read here, and no HTTP
// endpoint reads them or changes a verdict; the token the hooks hold can mark, seal and close.
// Loopback only (127.0.0.1, Host checked), one bearer token, bounded bodies, windows and
// observer calls.
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { collectWindow, loopbackRequestAllowed, evaluateEffectAssertion, validateSelector, validateScope, windowSees, matches } from '../observers/events.mjs';
import { applySettle, settleDeclared, OBSERVER_OUTPUT } from '../../src/http-effects.mjs';
import { digest } from '../../src/domain.mjs';
import { CUSTODY, INDEPENDENT_CUSTODY, custodyOf, decidesAbsence, subjectIntegrityVerdict } from '../evid-subject/custody.mjs';

export const SERVICE_SCHEMA = 'scopehaven-records-service/2';
// The judging code's own bytes, so a journal from other rules never carries the same configDigest.
export const SERVICE_BUILD = (() => {
  const h = createHash('sha256');
  // The in-doubt core, the upstream-outcome rules, the request-feed rules and the read-back rules judge too (PR342-REVIEW info 9, IDR-4, IDR-3),
  // and the egress rules and public suffixes the alias scope and sibling-host binding read (FIX-04).
  for (const f of ['./verdict-service.mjs', '../../src/effect-events.mjs', '../../src/body-fields.mjs', '../../src/idempotency.mjs', '../../src/custody.mjs', '../../src/effect-lineage.mjs', '../../src/http-effects.mjs', '../../src/http-claims.mjs',
    '../../src/in-doubt.mjs', '../../src/effect-outcome.mjs', '../../src/request-feed-rules.mjs', '../../src/key-identity.mjs', '../../src/read-back-rules.mjs', '../../src/egress-rules.mjs', '../../src/public-suffix.mjs', '../../src/public-suffix-list.mjs']) h.update(f).update(readFileSync(new URL(f, import.meta.url)));
  return h.digest('hex');
})();
export const VERDICT_LIMITS = Object.freeze({ bodyBytes: 4096, openWindows: 64, windowMs: 600000, observerMs: 30000 });
export const BASIS_CHARS = 280;
export const TOKEN_CHARS = 16;
export const RECORDS_OF = Object.freeze({ pass: 'clean', fail: 'commit' });
export const CLOSE_REASONS = Object.freeze(['not-sealed']);
// At most this many forbidden selectors, each named with letters, digits and . _ -: every gap records one
// decision per selector, and the journal's reason list holds 64, so no decision is ever dropped.
export const SELECTOR_LIMIT = 32;
const SELECTOR_NAME = /^[A-Za-z0-9._-]{1,64}$/;
// Why a pass was not clean, beyond main's custody reasons.
export const NO_CALL_REASON = 'no-execution-evidence';
export const SUBJECT_CALL_REASON = 'subject-writable-call-record';
// The window id a provider puts on its call: <callPath>?scopehaven_window=<id>.
export const CALL_PARAM = 'scopehaven_window';
// The native source of each observer kind core builds: a known kind cannot declare another source.
const NATIVE_SOURCE = Object.freeze(Object.fromEntries(Object.values(OBSERVER_OUTPUT).map(o => [o.kind, o.source])));
// Every basis is written here or by core from configuration and machine codes, never from
// text the application or the judge produced.
const BASIS = Object.freeze({
  'overlapping-window': "Another test's observation window overlapped this one, so effects in it cannot be attributed to this test.",
  expired: 'The window was neither sealed nor closed within the window limit or before the service stopped, so the records give no verdict.',
  'internal-error': 'The records service failed while closing or judging this window, so the records give no verdict.',
});
const NOT_CLEAN = 'a clean records verdict needs complete, settled records the application cannot write, and a record on them of this test\'s call.';
const TOO_LARGE = Symbol('too large');
const FAILED = Symbol('mark failed');
const plainObject = v => v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const LOOPBACK_ORIGIN = /^http:\/\/127\.0\.0\.1:\d{1,5}$/;
const nonEmpty = v => typeof v === 'string' && v.trim().length > 0;
const sleep = ms => new Promise(done => setTimeout(done, ms));
// An observer call that does not settle within the limit is a failure, never a hang.
const bounded = (fn, ms) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('observer-timeout')), ms);
  Promise.resolve().then(fn).then(resolve, reject).finally(() => clearTimeout(timer));
});

// A run may tighten a limit, never loosen one.
function limitsOf(declared) {
  if (!plainObject(declared) || Object.keys(declared).some(key => !Object.hasOwn(VERDICT_LIMITS, key))) throw new Error('Unknown limit: declare only bodyBytes, openWindows, windowMs or observerMs.');
  const limits = { ...VERDICT_LIMITS, ...declared };
  for (const [key, value] of Object.entries(limits)) if (!Number.isSafeInteger(value) || value < 1 || value > VERDICT_LIMITS[key]) throw new Error(`Limit ${key} must be a positive integer no larger than ${VERDICT_LIMITS[key]}.`);
  return Object.freeze(limits);
}
// A selector names a source and an exact action name.
function exactSelector(select, where) {
  validateSelector(select, where);
  if (typeof select.source !== 'string' || typeof select.name !== 'string') throw new Error(`${where} needs a source and an exact action name.`);
  return select;
}
function checkObservers(observers) {
  if (!Array.isArray(observers) || !observers.length || observers.length > 32) throw new Error('Declare between 1 and 32 observers, each with a kind, an instanceId, a source, a scope, mark and collect.');
  for (let i = 0; i < observers.length; i++) {
    const o = Object.hasOwn(observers, i) ? observers[i] : null;
    if (!o || typeof o.mark !== 'function' || typeof o.collect !== 'function' || !nonEmpty(o.instanceId) || !nonEmpty(o.source) || !nonEmpty(o.kind)) throw new Error('Declare between 1 and 32 observers, each with a kind, an instanceId, a source, a scope, mark and collect.');
    validateScope(o.scope, `observer ${o.instanceId} scope`);
    if (Object.hasOwn(NATIVE_SOURCE, o.kind) && NATIVE_SOURCE[o.kind] !== o.source) throw new Error(`Observer ${o.instanceId} is a ${o.kind}, whose records are ${NATIVE_SOURCE[o.kind]}, not ${o.source}.`);
  }
  if (new Set(observers.map(o => o.instanceId)).size !== observers.length) throw new Error('Observer instanceIds must be unique.');
}

// Judge one ended window: core's effect.none, then, for a pass, main's custody rule and positive
// evidence of the call. Custody is reported over the windows that decided the verdict only: for a
// pass the windows that could decide the absence, for a fail the windows that recorded the
// committed effect, else none. A commit is never downgraded.
function judge(windows, select, calls, callPath) {
  const decided = evaluateEffectAssertion({ kind: 'effect.none', select }, windows);
  let verdict = decided.verdict, reasons = [], basis = String(decided.basis ?? '');
  if (verdict === 'pass') {
    const integrity = subjectIntegrityVerdict({ proposed: 'pass', support: windows, select, kind: 'effect.none' });
    // A call record counts only when it names this window's call path.
    const bound = callPath === null ? null : digest(digest(callPath));
    // A call that completed: committed, in a window its observer covered completely. A request still
    // held or in flight at the window end shows no call reached the application.
    const called = calls ? windows.filter(w => w.coverage === 'complete' && windowSees(w, calls)
      && w.events.some(e => matches(e, { ...calls, outcome: 'committed' }) && (e.resource === callPath || e.contentDigest === bound))) : [];
    reasons = [...new Set([...integrity.reasons,
      ...(!called.length ? [NO_CALL_REASON] : called.some(w => INDEPENDENT_CUSTODY.includes(custodyOf(w))) ? [] : [SUBJECT_CALL_REASON])])];
    if (reasons.length) { verdict = 'inconclusive'; basis = `Not clean (${reasons.join(', ')}): ${NOT_CLEAN} ${basis}`; }
  }
  const deciding = decided.verdict === 'pass' ? windows.filter(w => decidesAbsence(w, select))
    : decided.verdict === 'fail' ? windows.filter(w => windowSees(w, select) && w.events.some(e => matches(e, { ...select, outcome: 'committed' })))
    : [];
  const custody = deciding.length ? CUSTODY[Math.min(...deciding.map(w => CUSTODY.indexOf(custodyOf(w))))] : 'none';
  return { records: RECORDS_OF[verdict] ?? 'unsupported', verdict, reasons, custody, basis };
}
const unjudged = (verdict, closedBy, { basis = BASIS[verdict], reasons = [], selector = null } = {}) => ({ records: 'unsupported', verdict, reasons, custody: 'none', basis, selector, closedBy });

// observers: started observers ({ kind, instanceId, source, scope, mark, collect });
// forbidden: { <name>: selector } the tests may name, and `default` for a test that names none;
// each names a source and an exact action name;
// calls: a selector for the record that shows the application was called (for example the hold
// proxy's request record), and callPath, the origin-form path the provider calls with
// ?scopehaven_window=<window id> appended; without them no window reads clean;
// witness: { origin, authorization? } for observers that declare a witnessRequest: the application's
// loopback origin each witness request goes to, and the Authorization header it needs (never in
// configDigest or the journal);
// settleMs: the declared post-response settle (absence needs one);
// limits: optional tighter bodyBytes, openWindows, windowMs or observerMs.
export async function startVerdictService({ observers, forbidden, calls = null, callPath = null, witness = null, settleMs, token = randomBytes(24).toString('base64url'), port = 0, limits: declaredLimits = {} }) {
  if (!nonEmpty(token) || token.length < TOKEN_CHARS) throw new Error(`The token must be a string of at least ${TOKEN_CHARS} characters.`);
  checkObservers(observers);
  if (!plainObject(forbidden) || !Object.hasOwn(forbidden, 'default')) throw new Error('Declare a default forbidden selector.');
  if (Object.keys(forbidden).length > SELECTOR_LIMIT) throw new Error(`Declare at most ${SELECTOR_LIMIT} forbidden selectors.`);
  for (const name of Object.keys(forbidden)) if (!SELECTOR_NAME.test(name)) throw new Error(`Forbidden selector name ${JSON.stringify(name)} must be 1 to 64 letters, digits, dots, underscores or hyphens.`);
  for (const [name, select] of Object.entries(forbidden)) exactSelector(select, `Forbidden selector ${name}`);
  if (calls !== null) exactSelector(calls, 'The calls selector');
  if ((calls === null) !== (callPath === null) || (callPath !== null && (typeof callPath !== 'string' || !/^\/[A-Za-z0-9._~/-]{0,119}$/.test(callPath) || callPath.startsWith('//'))))
    throw new Error('Declare calls and callPath together; callPath is an origin-form path without a query, such as /chat.');
  const witnessed = observers.filter(o => o.witnessRequest);
  for (const o of witnessed) if (!plainObject(o.witnessRequest) || o.witnessRequest.method !== 'GET' || typeof o.witnessRequest.path !== 'string' || !o.witnessRequest.path.startsWith('/') || o.witnessRequest.path.startsWith('//') || typeof o.markWitnessRequest !== 'function')
    throw new Error(`Observer ${o.instanceId} declares a witness request the service cannot send: a GET to an origin-form path, with markWitnessRequest.`);
  if (witness !== null && (!plainObject(witness) || Object.keys(witness).some(k => !['origin', 'authorization'].includes(k)) || !LOOPBACK_ORIGIN.test(witness.origin ?? '')
    || (witness.authorization !== undefined && (!nonEmpty(witness.authorization) || witness.authorization.length > 512)))) throw new Error('witness is { origin: "http://127.0.0.1:<port>", authorization? }.');
  if (witnessed.length && witness === null) throw new Error(`Observer ${witnessed[0].instanceId} proves absence with a per-window witness: declare witness.origin, the application it asks.`);
  if (!settleDeclared(settleMs)) throw new Error('settleMs must be a declared post-response settle.');
  const limits = limitsOf(declaredLimits);
  // Private copies: a caller that edits its objects later changes neither verdicts nor the digest.
  const selectors = Object.freeze(Object.assign(Object.create(null), structuredClone(forbidden)));
  const callsSelector = calls === null ? null : Object.freeze(structuredClone(calls));
  observers = observers.slice();
  const witnessOrigin = witness?.origin ?? null, witnessAuthorization = witness?.authorization ?? null;
  const configDigest = digest({ schema: SERVICE_SCHEMA, build: SERVICE_BUILD, observers: observers.map(o => ({ kind: o.kind, instanceId: o.instanceId, source: o.source, scope: o.scope, witnessPath: o.witnessRequest?.path ?? null })),
    forbidden: { ...selectors }, calls: callsSelector, callPath, witnessOrigin, settleMs, limits });
  const callPathOf = id => callPath === null ? null : `${callPath}?${CALL_PARAM}=${id}`;

  const expected = Buffer.from(`Bearer ${token}`);
  const authorized = req => { const got = Buffer.from(req.headers.authorization ?? ''); return got.length === expected.length && timingSafeEqual(got, expected); };
  const json = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
  // Stops at the cap: an oversized body is answered 413 and the rest is never read.
  const readBody = req => new Promise(resolve => {
    const chunks = []; let n = 0, done = false;
    const finish = value => { if (!done) { done = true; resolve(value); } };
    req.on('data', d => { if (done) return; n += d.length; if (n > limits.bodyBytes) { req.pause(); return finish(TOO_LARGE); } chunks.push(d); });
    req.on('end', () => { try { finish(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch { finish(null); } });
    req.on('error', () => finish(null));
  });
  // Each observer's mark, bounded; one that fails or hangs fails only that observer's window.
  const markOf = o => bounded(() => o.mark(), limits.observerMs).catch(() => FAILED);
  const marks = (only = observers) => Promise.all(only.map(markOf));
  // A witness request: the application's own route, tagged with the start mark's nonce. Its outcome
  // is the sink's to judge (the witness arrived, once, or the window reads partial).
  const sendWitness = async (o, from) => {
    if (from === FAILED || typeof from?.witnessNonce !== 'string') return;
    try { o.markWitnessRequest(from); } catch {}
    const path = `${o.witnessRequest.path}${o.witnessRequest.path.includes('?') ? '&' : '?'}scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`;
    try { const res = await fetch(`${witnessOrigin}${path}`, { method: 'GET', redirect: 'error', headers: witnessAuthorization ? { authorization: witnessAuthorization } : {}, signal: AbortSignal.timeout(limits.observerMs) }); await res.arrayBuffer(); } catch {}
  };
  const collect = (o, from, to) => from === FAILED || to === FAILED
    ? { source: o.source, instanceId: o.instanceId, scope: o.scope, coverage: 'failed', reason: 'mark-failed', events: [] }
    : bounded(() => collectWindow(o, from, to), limits.observerMs).then(w => applySettle(w, settleMs),
      () => ({ source: o.source, instanceId: o.instanceId, scope: o.scope, coverage: 'failed', reason: 'collect-timeout', events: [] }));

  // active: every window from its mark until it leaves the open set, by state:
  //   'open'     marked, not yet sealed or closed
  //   'ending'   a seal or close is waiting the settle, taking closing marks and collecting
  //   'expired'  journaled as expired, still held so a later window reads overlapping
  // ended: every journaled window, so a second seal or close is answered 404 and noted.
  const active = new Map(), ended = new Map(), journal = [], gaps = [];
  let marked = 0, lastEnd = null;
  const iso = ms => new Date(ms).toISOString();
  const openCount = () => { let n = 0; for (const w of active.values()) if (w.state !== 'expired') n++; return n; };
  const finish = (id, w, entry) => {
    if (w.done) return null;
    w.done = true;
    const e = { window: id, seq: w.seq, config: configDigest, records: entry.records, verdict: entry.verdict, reasons: [...entry.reasons], custody: entry.custody,
      basis: String(entry.basis ?? '').slice(0, BASIS_CHARS), selector: entry.selector, closedBy: entry.closedBy, overlap: w.overlap, cached: w.cached, contested: w.contested,
      markedAt: iso(w.at), endedAt: iso(Date.now()) };
    journal.push(e);
    ended.set(id, { entry: e, closedBy: entry.closedBy });
    return e;
  };
  // An expired window leaves the open set unjudged; the span from its mark on becomes a gap when no
  // other window is open, so what its test did is still checked for forbidden effects.
  const drop = (id, w) => { if (!active.delete(id)) return; if (!active.size && !lastEnd && Array.isArray(w.from)) lastEnd = { seq: w.seq, to: w.from, at: w.at }; };
  const release = (id, w, ms) => setTimeout(() => drop(id, w), ms).unref();
  const sweep = (all = false) => {
    const now = Date.now();
    for (const [id, w] of active) {
      // An expired window whose late end has started its settle is released by that settle alone.
      if (w.state === 'expired') { if (all || (!w.lateEnd && now - w.expiredAt > limits.windowMs)) drop(id, w); continue; }
      if (all || (w.state === 'open' && now - w.at > limits.windowMs)) {
        finish(id, w, unjudged('expired', 'expired'));
        if (all) drop(id, w); else Object.assign(w, { state: 'expired', expiredAt: now });
      }
    }
  };
  // A seal or close: settle, closing marks, then collect and judge. The window leaves the open set
  // only after its closing marks, overlapped or not.
  const end = async (id, w, { closedBy, name, cached }) => {
    Object.assign(w, { state: 'ending', closedBy, cached });
    let entry;
    try {
      await sleep(settleMs);
      // Every other observer is end-marked first; then each witness sink in turn gets its witness, its
      // end mark and its collection, so one sink's witness never shortens another's quiet period.
      const plain = observers.map((o, i) => i).filter(i => !observers[i].witnessRequest);
      const to = new Array(observers.length).fill(FAILED), collected = new Array(observers.length);
      (await marks(plain.map(i => observers[i]))).forEach((m, k) => { to[plain[k]] = m; });
      for (const [i, o] of observers.entries()) if (o.witnessRequest) {
        if (!w.overlap) await sendWitness(o, w.from[i]);
        to[i] = await markOf(o);
        if (!w.overlap) collected[i] = await collect(o, w.from[i], to[i]);
      }
      // Collected while still open: an observer that reads past its closing mark (a quiet period, a
      // witness wait) can take only effects of a window that, marked meanwhile, overlaps this one.
      const windows = w.overlap ? null : await Promise.all(observers.map((o, i) => collected[i] ?? collect(o, w.from[i], to[i])));
      active.delete(id);
      if (w.done) return null;
      if (!active.size) lastEnd = { seq: w.seq, to, at: Date.now() };
      entry = w.overlap ? unjudged('overlapping-window', closedBy, { selector: name })
        : { ...judge(windows, selectors[name], callsSelector, callPathOf(id)), selector: name, closedBy };
    } catch (error) {
      active.delete(id);
      finish(id, w, unjudged('observer-failure', closedBy, { basis: BASIS['internal-error'], reasons: ['internal-error'], selector: name }));
      throw error;
    }
    return finish(id, w, entry);
  };
  // A seal or close of a window that is not open: 404, noted as contested when it is a second
  // seal or a second close. An expired window's late seal or close is its test ending: never
  // contested, and it starts the settle that releases the window.
  const notOpen = (id, w, path) => {
    const prior = w && !w.done ? { closedBy: w.closedBy, entry: null } : ended.get(id);
    if (!prior || prior.closedBy === 'expired') { if (w?.state === 'expired' && !w.lateEnd) { w.lateEnd = true; release(id, w, settleMs); } return; }
    if (path === '/seal' || prior.closedBy === 'close') { if (prior.entry) prior.entry.contested = true; else w.contested = true; }
  };

  // A gap: no window was open in it, so a forbidden effect committed there is in no window. Every
  // declared forbidden selector is checked for a committed match (presence only).
  let stopped = false;
  const gapEntry = async (k, g) => {
    const to = g.to ?? g.pending.from;
    const windows = await Promise.all(observers.map((o, i) => g.collected[i] ?? collect(o, g.from[i], to?.[i] ?? FAILED)));
    // Each declared selector, decided over the gap like a window: a commit stands on any coverage; an
    // absence needs complete coverage, and anything short of it is named, never read as no effect.
    const decide = select => { try { return evaluateEffectAssertion({ kind: 'effect.none', select }, windows).verdict; } catch { return 'observer-failure'; } };
    const decided = Object.entries(selectors).map(([name, select]) => [name, decide(select)]);
    const hit = decided.filter(([, v]) => v === 'fail').map(([name]) => name), unobserved = decided.filter(([, v]) => v !== 'fail' && v !== 'pass').map(([name]) => name);
    const committedIn = (w, select) => { try { return windowSees(w, select) && w.events.some(e => matches(e, { ...select, outcome: 'committed' })); } catch { return false; } };
    const seen = windows.filter(w => hit.some(name => committedIn(w, selectors[name])));
    const custody = seen.length ? CUSTODY[Math.min(...seen.map(w => CUSTODY.indexOf(custodyOf(w))))] : 'none';
    const basis = [hit.length ? `A forbidden effect (${hit.join(', ')}) committed after window ${g.after.seq} ended, before the next window or the end of the run: it is in no window.` : '',
      unobserved.length ? `After window ${g.after.seq}, the records could not show an absence for: ${unobserved.join(', ')}.` : '',
      !hit.length && !unobserved.length ? `Between window ${g.after.seq} and the next window or the end of the run: no forbidden effect committed.` : ''].filter(Boolean).join(' ');
    // One decision per declared selector, never truncated (SELECTOR_LIMIT keeps it within the journal's list):
    // absent, late-effect or gap-unobserved. The matrix reads a missing decision as undecided.
    const reasons = decided.map(([name, v]) => `${v === 'fail' ? 'late-effect' : v === 'pass' ? 'absent' : 'gap-unobserved'}:${name}`);
    return { window: `gap-${k}`, seq: g.after.seq, config: configDigest, records: hit.length ? 'commit' : 'unsupported', verdict: 'gap',
      reasons, custody,
      basis: basis.slice(0, BASIS_CHARS), selector: null, closedBy: 'gap', overlap: false, cached: false, contested: false, markedAt: iso(g.at), endedAt: iso(g.toAt) };
  };
  // A gap's witness: each witness sink is asked to prove its route for the span from the gap's start mark.
  // A witness sink is collected as soon as the gap ends (a sink collected long after its end mark reads
  // partial); the other observers are collected when the service stops.
  const gapWitness = async from => { for (const [i, o] of observers.entries()) if (o.witnessRequest) await sendWitness(o, from[i]); };
  const gapSinks = async (g, to) => { for (const [i, o] of observers.entries()) if (o.witnessRequest) g.collected[i] = await collect(o, g.from[i], to[i]); };

  let server = null;
  const handle = async (req, res) => {
    if (!loopbackRequestAllowed(req, server.address().port)) return json(res, 403, { error: 'loopback only' });
    if (!authorized(req)) return json(res, 401, { error: 'token required' });
    if (req.method !== 'POST' || !['/mark', '/seal', '/close'].includes(req.url)) return json(res, 404, {});
    const body = await readBody(req);
    if (body === TOO_LARGE) { res.once('finish', () => req.destroy()); return json(res, 413, { error: 'body too large' }); }
    if (!plainObject(body)) return json(res, 400, { error: 'bad body' });
    sweep();
    if (req.url === '/mark') {
      // A refused mark leaves a test running with no window: every open window may take its effects.
      if (openCount() >= limits.openWindows) { for (const other of active.values()) other.overlap = true; return json(res, 429, { error: 'too many open windows' }); }
      const id = randomUUID(), w = { seq: ++marked, at: Date.now(), state: 'open', overlap: active.size > 0, cached: false, contested: false, closedBy: null, from: null, done: false };
      // Registered before its marks run, so a window marked at the same moment sees this one.
      for (const other of active.values()) other.overlap = true;
      // The span since the last window ended, when no window was open in it: its witness is sent now,
      // before this window's marks, and it is collected at stop.
      const gap = !w.overlap && lastEnd ? { after: lastEnd, from: lastEnd.to, at: lastEnd.at, toAt: w.at, pending: w, collected: [] } : null;
      lastEnd = null;
      active.set(id, w);
      if (gap) { gaps.push(gap); await gapWitness(gap.from); }
      w.from = await marks();
      if (gap) await gapSinks(gap, w.from);
      return json(res, 200, { window: id });
    }
    const id = body.window, w = typeof id === 'string' ? active.get(id) : undefined;
    if (!w || w.state !== 'open') { if (typeof id === 'string') notOpen(id, w, req.url); return json(res, 404, { error: 'unknown window' }); }
    const name = body.select ?? 'default';
    // A refused selector, reason or flag leaves the window open for a correct seal or a close.
    if (typeof name !== 'string' || !Object.hasOwn(selectors, name)) return json(res, 400, { error: 'unknown selector' });
    if (req.url === '/close' && !CLOSE_REASONS.includes(body.reason)) return json(res, 400, { error: 'unknown close reason' });
    if (req.url === '/seal' && body.cached !== undefined && typeof body.cached !== 'boolean') return json(res, 400, { error: 'cached must be a boolean' });
    const done = await end(id, w, { closedBy: req.url === '/seal' ? 'seal' : 'close', name, cached: req.url === '/seal' && body.cached === true });
    if (!done) return json(res, 404, { error: 'window ended when the service stopped' });
    return json(res, 200, { window: id, records: done.records, verdict: done.verdict, reasons: done.reasons, custody: done.custody, basis: done.basis, selector: done.selector });
  };
  server = createServer((req, res) => { handle(req, res).catch(() => { if (!res.headersSent) json(res, 500, { error: 'failed' }); }); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  const { address, port: bound } = server.address();
  return {
    // Built from the bound address, so the url names exactly what the service listens on.
    url: `http://${address}:${bound}`, token, configDigest,
    journal() { sweep(); return structuredClone(journal); },
    // Windows still open or ending when the service stops are journaled as expired. Then the gaps
    // (and the tail after the last window, one settle long) are collected and journaled.
    async stop() {
      server.closeAllConnections?.(); await new Promise(done => server.close(done)); sweep(true);
      if (stopped) return; stopped = true;
      if (lastEnd) {
        await sleep(settleMs); await gapWitness(lastEnd.to);
        const tail = { after: lastEnd, from: lastEnd.to, at: lastEnd.at, toAt: Date.now(), to: await marks(), collected: [] };
        await gapSinks(tail, tail.to); gaps.push(tail); lastEnd = null;
      }
      for (const [k, g] of gaps.entries()) journal.push(await gapEntry(k + 1, g));
    },
  };
}
