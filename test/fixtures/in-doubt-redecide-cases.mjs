// Seeded synthetic cases for the IDR-2 run-end re-decide tests (test/in-doubt-redecide.test.mjs and test/in-doubt-redecide-stub.test.mjs).
// One egress recorder (egress-recorder/7) forwarding two hosts: CRM, which the stub later resolver of the stub test applies to, and ALT,
// which only R0 reads. A case is plain data (its window kind, events, clauses, claim readings and the later records an observer would
// return), built into windows as the connector collects and admits them: complete, partial, destination-scoped and followed, scoped and
// unfollowed (marked after the check-time decision, as the follow rule does), and held short by a host suspend (#343). For tests only; not
// in any identity list. Owned synthetic data only: destination hosts are names, never resolved or contacted.
import { createHash } from 'node:crypto';
import { makeEffect } from '../../src/effect-events.mjs';
import { declaredObserverRecord, observerInstanceId } from '../../src/http-effects.mjs';
import { applySuspendShort } from '../../src/suspend-clock.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../../src/contracts.mjs';
import { createRegistry } from '../../src/registry.mjs';

export const CRM = 'crm.example', ALT = 'alt.example', WITNESS = 'witness.scopehaven.invalid';
export const INST = observerInstanceId('egress-recorder', 'sink');
export const CLOSE = 'POST /tickets/T-1/close';
export const AFTER = 'egress-request-after-witness-request';
const hex = text => createHash('sha256').update(text).digest('hex');

// The recorder as a profile declares it (keyed: CRM declares an idempotency header), and its run record (src/http-effects.mjs).
export const declaration = keyed => ({ id: 'sink', type: 'egress-recorder', port: 40999, routing: 'proxy', settleMs: 250, quietMs: 150, witness: { actorId: 'member', method: 'GET', path: '/ping', host: WITNESS },
  destinations: [{ host: CRM, paths: ['/tickets/T-1/close', '/tickets/T-2/close', '/tickets/T-1'], forward: { upstream: 'http://127.0.0.1:47103', rejected: [409], proofEnv: 'SCOPEHAVEN_TARGET_CRM_PROOF' },
    objectPaths: ['POST /tickets/{ticket}/close'], ...(keyed ? { idempotency: { header: 'idempotency-key' } } : {}) },
  { host: ALT, paths: ['/tickets/T-1/close'], forward: { upstream: 'http://127.0.0.1:47104', rejected: [409], proofEnv: 'SCOPEHAVEN_TARGET_ALT_PROOF' } }] });
export const RECORDS = Object.freeze({ plain: declaredObserverRecord([declaration(false)])[0], keyed: declaredObserverRecord([declaration(true)])[0] });
export const META = new Map([[INST, { kind: 'http-egress-recorder', settleMs: 250 }]]);
const scopeOf = keyed => ({ operations: ['send'], names: [ALT, CRM], actorAttribution: 'none', evidence: 'authoritative', forward: RECORDS[keyed ? 'keyed' : 'plain'].forward,
  ...(keyed ? { idempotency: RECORDS.keyed.idempotency } : {}) });

// Upstream records as the recorder writes them (a proven reply, or unknown with the forward's transport record; 'missing' has none).
const T = Object.freeze({ refused: { connected: false, mono: 10.5, wall: 1760000000000 }, reset: { connected: true, mono: 11.25, wall: 1760000000001 } });
export const UP = Object.freeze({
  applied: { outcome: 'applied', status: 201, proven: true }, rejected: { outcome: 'rejected', status: 409, proven: true }, missing: { outcome: 'unknown', status: null, proven: false },
  refused: { outcome: 'unknown', status: null, proven: false, transport: T.refused }, reset: { outcome: 'unknown', status: null, proven: false, transport: T.reset },
  server: { outcome: 'unknown', status: 503, proven: true, transport: T.reset },
});
const EXACT = Object.freeze({ exact: true, query: false });

export const sel = (name = CRM, resource = CLOSE, upstream) => ({ source: 'http-egress', operation: 'send', name, ...(resource ? { resource } : {}), ...(upstream ? { upstream } : {}) });
export const CLOSE_SEL = Object.freeze(sel());
// Opted-in clauses (gate A), and clauses with no opt-in.
export const EXISTS = { kind: 'effect.exists', select: sel(CRM, CLOSE, 'resolved'), semantics: 'agent-write' };
export const count = n => ({ kind: 'effect.count', select: sel(CRM, CLOSE, 'resolved'), expected: n, semantics: 'exactly-n' });
export const ONLY = { kind: 'effect.only', expect: [], allow: [], outcomeJudged: [CLOSE_SEL] };
export const ONLY_ONCE = { ...ONLY, expect: [{ select: CLOSE_SEL, count: 1 }] };
export const KEYED_ONLY = expect => ({ kind: 'effect.only', expect, allow: [], countBy: 'idempotency-key', outcomeJudged: [CLOSE_SEL] });
export const KEYED_COUNT = { kind: 'effect.count', select: sel(CRM, null, 'resolved'), expected: 1, countBy: 'idempotency-key', semantics: 'exactly-n' };
export const ALT_EXISTS = { kind: 'effect.exists', select: sel(ALT, CLOSE, 'resolved'), semantics: 'agent-write' };
export const OPTED = [EXISTS, count(0), count(1), count(2), ONLY, ONLY_ONCE, ALT_EXISTS];
export const OPTED_KEYED = [KEYED_ONLY([]), KEYED_ONLY([{ select: CLOSE_SEL, count: 1 }]), KEYED_COUNT];
export const MAIN = [{ kind: 'effect.exists', select: sel(CRM, CLOSE, 'applied') }, { kind: 'effect.none', select: sel(CRM, CLOSE, 'applied') }, { kind: 'effect.count', select: sel(CRM, CLOSE, 'applied'), expected: 1 },
  { kind: 'effect.none', select: { source: 'http-egress', name: ALT } }, { kind: 'effect.count', select: { source: 'http-egress', name: CRM, resource: CLOSE }, expected: 1 },
  { kind: 'effect.only', expect: [{ select: CLOSE_SEL, count: 1 }], allow: [] }];
export const MAIN_KEYED = [{ kind: 'effect.count', select: sel(CRM, null), expected: 1, countBy: 'idempotency-key' }];
export const CLAIM_RESOLVED = { trigger: { field: { pointer: '/closed', success: [true], refusal: [false] } }, select: sel(CRM, CLOSE, 'resolved'), semantics: 'agent-write' };
export const CLAIM_PLAIN = { trigger: { field: { pointer: '/closed', success: [true] } }, select: sel(CRM, CLOSE) };
export const opted = clause => clause?.select?.upstream === 'resolved' || Array.isArray(clause?.outcomeJudged);

export function rng(seed) { let s = seed >>> 0; return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; }; }
export const pick = (g, list) => list[Math.floor(g() * list.length)];
const OUTCOMES = ['applied', 'rejected', 'missing', 'refused', 'refused', 'reset', 'reset', 'server'];
const RESOURCES = [CLOSE, CLOSE, CLOSE, 'POST /tickets/T-2/close', 'PATCH /tickets/T-1', 'GET /tickets/T-1'];
const TARGETS = [EXACT, EXACT, EXACT, EXACT, { exact: false, query: false }, { exact: true, query: true }];
export const KINDS = ['complete', 'complete', 'partial', 'scoped', 'unfollowed', 'unfollowed', 'short'];

// One case: { keyed, kind, events, effects, claims, readings, role, supplied }. supplied: what an observer's resolver read would return,
// { observer, seq, records } items, with noise: duplicates, malformed records, records for ALT or R0, and seqs no event has.
export function randomCase(g, { later = 'rx' } = {}) {
  const keyed = g() < 0.4, kind = pick(g, KINDS), first = new Map();
  const events = Array.from({ length: 1 + Math.floor(g() * 5) }, (_, i) => {
    const host = g() < 0.8 ? CRM : ALT;
    const key = keyed && host === CRM && g() < 0.9 ? pick(g, ['1', '2']) : undefined;
    const resource = key && g() < 0.85 ? CLOSE : pick(g, RESOURCES), content = key && g() < 0.8 ? `k${key}` : pick(g, ['c', 'd']);
    const seq = i + 1, spec = { host, outcome: pick(g, OUTCOMES), resource, target: pick(g, TARGETS), key, firstSeq: key ? first.get(key) ?? seq : undefined, content, seq };
    if (key && !first.has(key)) first.set(key, seq);
    return spec;
  });
  let effects = [...OPTED, ...(keyed ? OPTED_KEYED : []), ...MAIN, ...(keyed ? MAIN_KEYED : [])].filter(() => g() < 0.45);
  if (!effects.length) effects = [pick(g, OPTED)];
  // No outcome-judged selector may overlap an effect.none of the same check (validateCheckEffects): such a check is dropped to its opted clauses.
  if (effects.some(e => Array.isArray(e.outcomeJudged))) effects = effects.filter(e => e.kind !== 'effect.none');
  const claimed = g() < 0.4 ? [g() < 0.7 ? CLAIM_RESOLVED : CLAIM_PLAIN] : [];
  const readings = claimed.map(c => (c.trigger.field.refusal && g() < 0.5 ? { reading: 'refusal', valueIndex: 0 } : { reading: 'success', valueIndex: 0 }));
  const supplied = [];
  for (const e of events) {
    if (g() < 0.25) continue;
    const r = g();
    // A later resolver's record is its read (IDR-4: a test resolver's read is { result }); a bare result, or a read it does not accept, is invalid.
    const record = r < 0.6 ? { resolver: later, read: { result: pick(g, ['confirms', 'refutes', 'refutes', 'silent']) } }
      : r < 0.75 ? { resolver: later, status: 'failed', reason: pick(g, ['read-failed', 'read-not-run']) }
      : r < 0.82 ? { resolver: later, read: { result: 'maybe' } } : r < 0.85 ? { resolver: later, status: 'succeeded', result: 'confirms' } : r < 0.88 ? { resolver: 'r0', status: 'succeeded', result: 'refutes' } : { resolver: later, read: { result: 'confirms' } };
    supplied.push({ observer: INST, seq: e.seq, records: r >= 0.88 && r < 0.94 ? [record, { ...record }] : [record] });
  }
  if (g() < 0.2) supplied.push({ observer: INST, seq: 99, records: [{ resolver: later, read: { result: 'refutes' } }] });
  if (g() < 0.1) supplied.push({ observer: 'egress-recorder-other', seq: 1, records: [{ resolver: later, read: { result: 'confirms' } }] });
  return { keyed, kind, events, effects, claims: claimed, readings, role: g() < 0.85 ? 'boundary' : 'control', supplied };
}

// The case's one window, built fresh: events from specs (a later-resolver test reads each event object's own overlay), the scope, the kind's
// coverage, the destination-scoped entries and the suspend record. mark: { scoped: [fn], inDoubt: [fn] } applied to the window, so a frozen
// module instance can admit the same object (src/effect-events.mjs and src/in-doubt.mjs keep their admissions in module-private sets).
// upstreamOf(spec) may replace an event's upstream record (an oracle's proven reply).
// A proven 201 to a safe method reads unknown (src/effect-outcome.mjs outcomeOf), as the recorder writes it.
const recorded = (s, up) => (s.resource.startsWith('GET ') && up.outcome === 'applied' ? { ...up, outcome: 'unknown' } : up);
export function buildWindow(c, { mark = { scoped: [], inDoubt: [] }, upstreamOf = s => UP[s.outcome] } = {}) {
  const events = c.events.map(s => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST }, seq: s.seq, observedAt: '2026-10-16T00:00:00.000Z', operation: 'send',
    name: s.host, resource: s.resource, outcome: 'committed', content: { content: s.content, resource: s.resource }, upstream: { ...structuredClone(recorded(s, upstreamOf(s))), target: s.target },
    ...(c.keyed && s.host === CRM ? { idempotency: s.key ? { status: 'keyed', key: hex(`key-${s.key}`), fold: hex(`key-${s.key}`), head: hex(`head ${s.resource}`), firstSeq: s.firstSeq } : { status: 'absent', key: null, fold: null, head: hex(`head ${s.resource}`), firstSeq: null } } : {}) }));
  const scoped = c.kind === 'scoped' || c.kind === 'unfollowed';
  let w = { source: 'http-egress', instanceId: INST, scope: scopeOf(c.keyed), coverage: c.kind === 'complete' || c.kind === 'short' ? 'complete' : 'partial', reason: c.kind === 'partial' ? 'synthetic-partial' : scoped ? AFTER : null, events,
    ...(scoped ? { scoped: [{ name: ALT, resource: 'POST *', codes: [AFTER] }, { name: CRM, resource: 'POST /tickets/T-1/close', codes: [AFTER] }] } : {}) };
  if (c.kind === 'short') w = applySuspendShort({ ...w, suspend: { cause: 'host-sleep', count: 1, ms: 70000, from: '2026-10-16T00:00:01.000Z', to: '2026-10-16T00:01:11.000Z', shortMs: 150 } });
  for (const f of scoped ? mark.scoped : []) f(w);
  for (const f of mark.inDoubt) f(w);
  return w;
}
// What the connector would have sealed and the validator binds the window against.
export const recordOf = c => RECORDS[c.keyed ? 'keyed' : 'plain'];
export const unfollowedOf = c => new Set(c.kind === 'unfollowed' ? [INST] : []);

// --- End to end: a profile with this recorder, an injected recorder, and runs validated by the shared validator -------------------------
// The injected recorder: batches[n] gives the events of the n-th check window, gaps[n] those of the n-th settlement gap window (none by
// default), scoped late entries when late[n] is set, and its resolver read (resolutionRecords, read at the final mark) returns reads(events
// sent so far, gap sends included).
export function recorderFactory(batches, { late = [], gaps = [], reads = () => [], sent = [] } = {}) {
  return configs => configs.map(c => {
    const instanceId = `${c.type}-${c.id}`, keyed = Boolean(c.destinations[0].idempotency);
    const scope = { operations: ['send'], names: c.destinations.map(d => d.host).sort(), actorAttribution: 'none', evidence: 'authoritative', forward: RECORDS[keyed ? 'keyed' : 'plain'].forward,
      ...(keyed ? { idempotency: RECORDS.keyed.idempotency } : {}) };
    let n = 0, m = 0, mark = 0;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope, witnessRequest: null, async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect(from, to, options) {
        if (options?.gap) { const events = (gaps[m++] ?? (() => []))().map(e => ({ ...e, observer: { kind: 'http-egress-recorder', instanceId } })); sent.push(...events); return { events, coverage: 'complete', reason: null }; }
        const k = n++, events = (batches[k] ?? (() => []))().map(e => ({ ...e, observer: { kind: 'http-egress-recorder', instanceId } }));
        sent.push(...events);
        return late[k] ? { events, coverage: 'partial', reason: AFTER, scoped: [{ name: CRM, resource: 'POST /tickets/T-9/close', codes: [AFTER] }] } : { events, coverage: 'complete', reason: null };
      },
      async resolutionRecords() { return reads(sent); } };
  });
}
export const transport = async (origin, check) => ({ status: check.path === '/me' ? 200 : 201, complete: true, jsonParsed: true, json: check.path === '/me' ? {} : { closed: true }, bytes: 10 });
// A WHOAMI control, an optional control twin, and one high-severity task check per entry of tasks (its declared effects).
// requiredTwin: the twin is also a required control, so it guards the tasks' unpinned absences (FIX-07, src/http-pairing.mjs allowedUseGuards).
export const profileOf = (tasks, { keyed = false, twin = null, requiredTwin = false } = {}) => ({ id: 'idr2-app', name: 'IDR-2 app', applicationId: 'idr2-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-idr2',
  actors: { member: { principalId: 'member-1' } }, requiredControlIds: twin && requiredTwin ? ['WHOAMI', 'TWIN'] : ['WHOAMI'], observers: [declaration(keyed)],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    ...(twin ? [{ id: 'TWIN', title: 'Allowed close', category: 'Allowed use', severity: 'control', actorId: 'member', method: 'POST', path: '/twin', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }], effects: twin }] : []),
    ...tasks.map((effects, i) => ({ id: `TASK${i + 1}`, title: `Close ${i + 1}`, category: 'collateral', severity: 'high', actorId: 'member', method: 'POST', path: `/task/${i + 1}`, body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 201 }], effects }))] });
export const suiteOf = p => createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
// A run, validated with its exported suite, also after a JSON round trip.
export async function runOf(p, factory, options = {}) {
  const run = await runHttpAssessment(p, { env: {}, transport, observerFactory: factory, ...options });
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  validateHttpRunEvidence(JSON.parse(JSON.stringify(run)), { expectedSuite: suiteOf(p) });
  return run;
}
export const rowOf = (run, id = 'TASK1') => run.results.find(r => r.id === id);
export const clauseVerdicts = row => row.trace[1].data.effects.map(e => e.verdict);
