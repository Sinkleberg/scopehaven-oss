// Declared effect horizon and run budget for an HTTP run (readiness gap 2, the late tail). Pure: no I/O.
//
// A target may declare "timing": { effectHorizonMs, runBudgetMs } (H and B below). Without it a run behaves
// exactly as before. With it the connector (src/http-connector.mjs) follows five rules on its own clock:
//   lead-in   an observed check's start mark is taken only once H has passed since the end of every earlier
//             request of the run (check, identity probe or witness), so no earlier request's effect within H
//             can land in its window; H of the application's awake time where a host suspend was seen
//             (src/suspend-clock.mjs), and a lead-in still short after its extension is not admitted (the gate)
//   horizon   the check's own window is held open for H after its response, instead of the largest settle
//   gate      a check is sent only when its request, lead-in, horizon, witness close and barrier fit before the
//             wait deadline; otherwise it, and every later applicable check, is not sent (run-budget-exhausted)
//   reserve   every wait ends by the wait deadline: B minus the final settle and the identity probes still to
//             send, so a cut never costs earlier rows their identity proof; the end-of-run probes go before the
//             final settle
//   fallback  a wait still cut short marks the windows it held open partial (effect-horizon-truncated) and
//             cuts every later check
// None of these ever passes a clause: the horizon and the lead-in only lengthen and clear a window the effect
// rules already judge, a cut row reads inconclusive, and a truncated authoritative window reads partial.
// The horizon and every event timestamp may only add findings; no rule may use them to drop a later event
// from a check's candidates or to release a withheld pass, except a resolver decision (R1, R2, F5) after a documented
// bound, measured on ScopeHaven's monotonic clock (IN-DOUBT-DESIGN-ADDENDUM-R2 section 5; today R1's refutation,
// src/request-feed-rules.mjs, which also needs the provider's signed watermark past the bound and a stable wall-to-monotonic
// offset, and R2's refutations, caps and exact counts, src/read-back-rules.mjs, whose reads after the bound are taken at the last
// connection end plus the route's documented settleMs and at least settleMs apart, with a stable wall-to-monotonic offset). Event
// timestamps still release nothing: a request-feed entry's own time only binds it or leaves its key in doubt, and a read-back item's
// time is never read.
// An app can always delay an effect past any horizon: effects later than H stay with the later-window rules (src/http-settlement.mjs).
// A declared request feed's run-end read (R1) is reserved too: the resolvers term, one read's cap (REQUEST_FEED_READ_MS). Declared read-back
// (R2) is reserved per observed check (ADDENDUM-R2 m3): the readBack term, two route settle bounds and three read bounds each, the largest route's.
import { SETTLE_BOUNDS, settleDeclared } from './http-effects.mjs';
import { validateEgressConfig } from './egress-rules.mjs';
import { validateSmtpConfig } from './smtp-rules.mjs';
import { validateProviderFeedConfig, PROVIDER_FEED_REQUEST_MS } from './provider-feed-rules.mjs';
import { requestFeedsDeclared, REQUEST_FEED_READ_MS } from './request-feed-rules.mjs';
import { readBackReserveMs, readBackMaxSettleMs } from './read-back-rules.mjs';

export const TIMING_SCHEMA = 'scopehaven-timing/1';
// The horizon reaches the longest declared check timeout (CHECK_TIMEOUT_BOUNDS.maximumMs); the budget is at most
// two hours, the longest single assessment the dashboard holds open (public/workbench-host.js).
export const TIMING_BOUNDS = Object.freeze({ effectHorizonMs: Object.freeze([SETTLE_BOUNDS.minMs, 120000]), runBudgetMs: Object.freeze([60000, 7200000]) });
// Equal to HTTP_LIMITS.runTimeoutMs and HTTP_LIMITS.requestTimeoutMs (pinned by test/http-timing.test.mjs).
export const TIMING_BASE_MS = 60000, TIMING_REQUEST_MS = 3000;
// The audit-file observer's witness wait and quiet period when undeclared (AUDIT_FILE_LIMITS, pinned by a test),
// restated so the observer implementation stays outside the evaluator hash.
export const AUDIT_FILE_WITNESS_DEFAULTS = Object.freeze({ witnessWaitMs: 3000, quietMs: 300 });
export const HORIZON_TRUNCATED = 'effect-horizon-truncated', RUN_BUDGET_EXHAUSTED = 'run-budget-exhausted';

const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const intIn = (value, [lo, hi]) => Number.isInteger(value) && value >= lo && value <= hi;
const applicableChecks = target => target.checks.filter(c => c.applicability?.applies !== false);
const observedCheck = c => Boolean(c.effects || c.claims);
// The largest valid declared settle: the final settle, and in per-check mode the barrier.
export const maxDeclaredSettle = observers => Math.max(0, ...(observers ?? []).map(o => settleDeclared(o?.settleMs) ? o.settleMs : 0));

// A window held open for less than the horizon. An authoritative window that did not fail reads partial and names
// the reason (appended to any it already has); its events are kept, so a recorded match still decides. The reason stays
// within the 200-character window reason limit (REASON_PATTERN): the earlier reason's last codes are dropped when they must
// be, never the token the validator checks (the window is partial either way).
export function applyHorizon(w) {
  if (w.scope?.evidence !== 'authoritative' || w.coverage === 'failed') return w;
  const codes = w.reason ? w.reason.split(',') : [];
  while (codes.length && [...codes, HORIZON_TRUNCATED].join(',').length > 200) codes.pop();
  // Destination-scoped entries (coverage v2) never survive a horizon cut: the window is window-wide.
  const { scoped, ...rest } = w;
  return { ...rest, coverage: 'partial', reason: [...codes, HORIZON_TRUNCATED].join(',') };
}
export const carriesHorizon = w => typeof w?.reason === 'string' && w.reason.split(',').includes(HORIZON_TRUNCATED);

// An upper bound on the identity probes a run sends (src/http-connector.mjs planIdentity and its probe points).
// For each judged actor (a credentialEnv and an applicable check), with I identity and S surface controls and N
// applicable checks that are not identity controls: (I + S) probes at each of N + 1 probe points, and I x (J + 1)
// end-of-run probes (anonymous, invalid and one cross per other judged actor; J judged actors).
export function identityProbeBound(target, controlPlan) {
  const applicable = applicableChecks(target);
  const judged = Object.entries(target.actors).filter(([id, actor]) => actor.credentialEnv && applicable.some(c => c.actorId === id)).map(([id]) => id);
  return judged.reduce((total, actorId) => {
    const { identityControls, surfaceControls } = controlPlan.get(actorId);
    const I = identityControls.length, S = surfaceControls.length, N = applicable.filter(c => c.actorId === actorId && !identityControls.includes(c.id)).length;
    return total + (I > 0 && N > 0 ? (I + S) * (N + 1) : 0) + I * (judged.length + 1);
  }, 0);
}
// The longest a single identity probe can take: the largest request budget among the identity and surface controls.
export function probeBudgetMs(target, controlPlan, requestMs = TIMING_REQUEST_MS) {
  const ids = new Set([...controlPlan.values()].flatMap(p => [...p.identityControls, ...p.surfaceControls]));
  return Math.max(requestMs, ...target.checks.filter(c => ids.has(c.id)).map(c => c.timeoutMs ?? requestMs));
}
// The longest a check's witnesses can hold its window close: for each observer that sends one (an audit file always,
// an egress recorder, SMTP sink or provider feed that declares "witness"), the witness request plus the collection cap of its sink
// ledger or audit file (witnessWaitMs + 10 x quietMs), from the normalized declaration.
export function witnessCloseMs(observers, actors, requestMs = TIMING_REQUEST_MS) {
  return (observers ?? []).reduce((total, o) => {
    const wait = o.type === 'audit-file' ? { witnessWaitMs: o.witnessWaitMs ?? AUDIT_FILE_WITNESS_DEFAULTS.witnessWaitMs, quietMs: o.quietMs ?? AUDIT_FILE_WITNESS_DEFAULTS.quietMs }
      : o.type === 'egress-recorder' && o.witness ? validateEgressConfig(o, actors)
      : o.type === 'smtp-sink' && o.witness ? validateSmtpConfig(o, actors)
      : o.type === 'provider-feed' && o.witness ? validateProviderFeedConfig(o, actors) : null;
    // A provider feed also reads its signed head before the witness request and at the end mark, and a page to catch up.
    return wait ? total + requestMs + wait.witnessWaitMs + 10 * wait.quietMs + (o.type === 'provider-feed' ? 3 * PROVIDER_FEED_REQUEST_MS : 0) : total;
  }, 0);
}
// The linear plan a declared budget must hold, by term: base slack (observer start, marks, collections, settlement),
// every applicable request, every identity probe, per observed check a lead-in and a horizon (2 x H), its witness close
// and in per-check mode its barrier, then the final settle, and with a declared request feed (R1) its run-end read, and with declared
// read-back (R2) its reads per observed check.
export function plannedTimingTerms(target, { controlPlan }) {
  const H = target.timing.effectHorizonMs, applicable = applicableChecks(target), observed = applicable.filter(observedCheck).length;
  const settle = maxDeclaredSettle(target.observers), barrier = target.settlement?.mode === 'per-check' ? settle : 0;
  return { base: TIMING_BASE_MS, requests: applicable.reduce((sum, c) => sum + (c.timeoutMs ?? TIMING_REQUEST_MS), 0),
    probes: identityProbeBound(target, controlPlan) * probeBudgetMs(target, controlPlan), horizons: observed * 2 * H,
    witnesses: observed * witnessCloseMs(target.observers, target.actors), barriers: observed * barrier, tail: observed ? settle : 0,
    ...(requestFeedsDeclared(target.observers) ? { resolvers: REQUEST_FEED_READ_MS } : {}), ...(readBackReserveMs(target.observers) > 0 ? { readBack: observed * readBackReserveMs(target.observers) } : {}) };
}
export const plannedTimingMs = (target, options) => Object.values(plannedTimingTerms(target, options)).reduce((a, b) => a + b, 0);

// Late fails (opt-in): "lateFails": "withhold" adds the late rules of src/http-attribution.mjs, so a fail a late effect could
// explain reads inconclusive (late-unattributed) instead of being charged to the check.
export const LATE_FAILS = 'withhold';
// Load-time rules for a declared "timing" (target already valid otherwise). Throws an Error whose message starts with the reason.
export function validateTiming(target, { controlPlan }) {
  const t = target.timing, [hLo, hHi] = TIMING_BOUNDS.effectHorizonMs, [bLo, bHi] = TIMING_BOUNDS.runBudgetMs;
  if (!plain(t) || Object.keys(t).length !== (Object.hasOwn(t, 'lateFails') ? 3 : 2) || !intIn(t.effectHorizonMs, TIMING_BOUNDS.effectHorizonMs) || !intIn(t.runBudgetMs, TIMING_BOUNDS.runBudgetMs)
    || (Object.hasOwn(t, 'lateFails') && t.lateFails !== LATE_FAILS))
    throw new Error(`timing-shape: "timing" is { effectHorizonMs, runBudgetMs, lateFails? }, integers with effectHorizonMs from ${hLo} to ${hHi} and runBudgetMs from ${bLo} to ${bHi}, and lateFails "${LATE_FAILS}" when given`);
  const settle = maxDeclaredSettle(target.observers);
  if (!settle) throw new Error('timing-needs-settle: a declared effect horizon needs at least one observer with a valid "settleMs"');
  if (t.effectHorizonMs < settle) throw new Error(`timing-horizon-below-settle: "effectHorizonMs" must be at least the largest declared settleMs (${settle} ms)`);
  // A read-back route's settlement bound is never past the effect horizon (IN-DOUBT-DESIGN-ADDENDUM-R1 4.1).
  if (readBackMaxSettleMs(target.observers) > t.effectHorizonMs) throw new Error(`timing-read-back-settle: every read-back route's "settleMs" is at most "effectHorizonMs" (${t.effectHorizonMs} ms)`);
  const plan = plannedTimingMs(target, { controlPlan });
  if (plan > t.runBudgetMs) throw new Error(`timing-budget-below-plan: the declared checks, probes, horizons, witnesses and settles need ${plan} ms and "runBudgetMs" is ${t.runBudgetMs} ms`);
}

// A run's timing record: { schema, effectHorizonMs, runBudgetMs, lateFails, rows: [{ id, waitedMs, barrierWaitedMs }], tailWaitedMs },
// one row per effect row in run order. lateFails is "withhold" or null; waitedMs is 0..H (truncated below H); barrierWaitedMs
// is null in run mode, else 0..settle (clipped below it); tailWaitedMs is null with no effect rows, else 0..settle (clipped below it).
// Throws 'timing-record'; returns which rows were truncated or barrier-clipped and whether the tail was clipped.
const RECORD_KEYS = Object.freeze(['schema', 'effectHorizonMs', 'runBudgetMs', 'lateFails', 'rows', 'tailWaitedMs']), ROW_KEYS = Object.freeze(['id', 'waitedMs', 'barrierWaitedMs']);
// The declaration a record carries, as the target declared it (the exported suite's "timing").
export const timingDeclarationOf = record => ({ effectHorizonMs: record.effectHorizonMs, runBudgetMs: record.runBudgetMs, ...(record.lateFails === null ? {} : { lateFails: record.lateFails }) });
export function validateTimingRecord(record, { effectRowIds, maxSettle, perCheck }) {
  const bad = () => { throw new Error('timing-record'); };
  if (!plain(record) || Object.keys(record).length !== RECORD_KEYS.length || !RECORD_KEYS.every(k => Object.hasOwn(record, k)) || record.schema !== TIMING_SCHEMA) bad();
  if (!(record.lateFails === null || record.lateFails === LATE_FAILS)) bad();
  const H = record.effectHorizonMs;
  if (!intIn(H, TIMING_BOUNDS.effectHorizonMs) || !intIn(record.runBudgetMs, TIMING_BOUNDS.runBudgetMs) || !Array.isArray(record.rows) || record.rows.length !== effectRowIds.length) bad();
  record.rows.forEach((r, k) => {
    if (!plain(r) || Object.keys(r).length !== ROW_KEYS.length || !ROW_KEYS.every(key => Object.hasOwn(r, key)) || r.id !== effectRowIds[k] || !intIn(r.waitedMs, [0, H])) bad();
    if (perCheck ? !intIn(r.barrierWaitedMs, [0, maxSettle]) : r.barrierWaitedMs !== null) bad();
  });
  if (effectRowIds.length ? !intIn(record.tailWaitedMs, [0, maxSettle]) : record.tailWaitedMs !== null) bad();
  return { truncated: k => record.rows[k].waitedMs < H, barrierClipped: k => perCheck && record.rows[k].barrierWaitedMs < maxSettle,
    tailClipped: effectRowIds.length > 0 && record.tailWaitedMs < maxSettle };
}
