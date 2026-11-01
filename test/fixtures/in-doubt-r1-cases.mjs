// Synthetic cases for in-doubt resolution R1, the request feed (IDR-4; test/request-feed.test.mjs and test/in-doubt-r1.test.mjs). One
// egress recorder (egress-recorder/8) forwarding crm.example, which declares an idempotency header and a request feed, and alt.example, which
// does neither. A case is plain data: its sends (outcome, key, identity, clocks, target flags), the feed's entries per key and its feed-level
// read, built into an admitted window and the { observer, seq, records } items the recorder's resolver read would return. Clocks are fixed
// numbers, so every derivation is deterministic. For tests only; not in any identity list. Owned synthetic data only: hosts are names, never
// resolved or contacted.
import { createHash } from 'node:crypto';
import { makeEffect } from '../../src/effect-events.mjs';
import { admitInDoubt } from '../../src/in-doubt.mjs';
import { declaredObserverRecord, observerInstanceId } from '../../src/http-effects.mjs';
import { requestFeedRecordOf } from '../../src/request-feed-rules.mjs';
import { feedKeys } from './request-feed-stub.mjs';

export const CRM = 'crm.example', ALT = 'alt.example', WITNESS = 'witness.scopehaven.invalid';
export const INST = observerInstanceId('egress-recorder', 'sink');
export const CLOSE = 'POST /tickets/T-1/close', OTHER = 'POST /tickets/T-2/close';
export const SKEW = 50, SETTLE = 200;
const hex = text => createHash('sha256').update(text).digest('hex');
export const KEYS = feedKeys();
// The request feed as a profile declares it, and the recorder as a profile declares it (with or without the feed).
export const requestFeed = (extra = {}) => ({ feedId: 'crm-requests', endpoint: { port: 47120, path: '/requests' }, publicKey: KEYS.publicKey, hosts: [CRM],
  routes: [{ write: CLOSE, types: ['ticket.closed', 'ticket.updated'], applied: ['closed', 'pending'], notApplied: ['declined'], settleMs: SETTLE, source: 'synthetic provider document, section 4' },
    { write: OTHER, types: ['ticket.closed'], applied: ['closed'] }], maxSkewMs: SKEW, watermark: true, ...extra });
// signing: crm.example also declares verified signature headers (stripe, dedupeSeconds 1): the key collapse's retention bound (PR363-REVIEW
// major 1). The secret variable is a name only; no test reads it.
export const SIGNING = Object.freeze({ scheme: 'stripe', signature: 'stripe-signature', dedupeSeconds: 1, secretEnv: ['SCOPEHAVEN_TARGET_CRM_SIGNING'] });
export const declaration = ({ feed = requestFeed(), port = 40999, upstream = 47103, altUpstream = upstream + 1, signing = false } = {}) => ({ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', settleMs: 250, quietMs: 150,
  witness: { actorId: 'member', method: 'GET', path: '/ping', host: WITNESS },
  destinations: [{ host: CRM, paths: ['/tickets/T-1/close', '/tickets/T-2/close'], forward: { upstream: `http://127.0.0.1:${upstream}`, rejected: [409], proofEnv: 'SCOPEHAVEN_TARGET_CRM_PROOF' },
    idempotency: { header: 'idempotency-key', ...(signing ? { signing: SIGNING } : {}) }, objectPaths: ['POST /tickets/{ticket}/close'] },
  { host: ALT, paths: ['/tickets/T-1/close'], forward: { upstream: `http://127.0.0.1:${altUpstream}`, rejected: [409], proofEnv: 'SCOPEHAVEN_TARGET_ALT_PROOF' } }], ...(feed ? { requestFeed: feed } : {}) });
export const RECORD = declaredObserverRecord([declaration()])[0];
export const RECORD_PLAIN = declaredObserverRecord([declaration({ feed: null })])[0];
export const RECORD_SIGNING = declaredObserverRecord([declaration({ signing: true })])[0];
export const RECORD_SIGNING_PLAIN = declaredObserverRecord([declaration({ feed: null, signing: true })])[0];
export const recordFor = ({ feed = true, signing = false } = {}) => (signing ? (feed ? RECORD_SIGNING : RECORD_SIGNING_PLAIN) : feed ? RECORD : RECORD_PLAIN);
export const FEED = requestFeedRecordOf(requestFeed());
export const META = new Map([[INST, { kind: 'http-egress-recorder', settleMs: 250 }]]);
export const scopeOf = (feed = FEED, { signing = false } = {}) => ({ operations: ['send'], names: [ALT, CRM], actorAttribution: 'none', evidence: 'authoritative', forward: RECORD.forward,
  idempotency: (signing ? RECORD_SIGNING : RECORD).idempotency, ...(feed ? { requestFeed: feed } : {}) });
// The Unix second the arrivals count from on a signing host (a signing item's arrival second).
export const SEC0 = 1760000000;

// One send. outcome: applied | rejected (proven), reset (connected, unknown), refused (never connected), server (connected, 503 unproven),
// missing (no transport record). Clocks: arrival and connection end in ms (wall), and the monotonic ones a fixed offset below them.
export const OFFSET = 1760000000000;
export function send({ seq, host = CRM, resource = CLOSE, outcome = 'reset', key = 'K1', fold, firstSeq, status, content = 'c1', head = 'h1', token, exact = true, query = false,
  arrived = 1000, ended = 1100, feedHost, arrivedWall, endWall, observer = INST, signingAt }) {
  const transport = outcome === 'missing' ? undefined : { connected: outcome !== 'refused', mono: ended, wall: endWall === undefined ? OFFSET + ended : endWall,
    ...((feedHost ?? host === CRM) ? { arrivedMono: Math.min(arrived, ended), arrivedWall: arrivedWall === undefined ? OFFSET + arrived : arrivedWall } : {}) };
  const up = outcome === 'applied' ? { outcome: 'applied', status: status ?? 201, proven: true } : outcome === 'rejected' ? { outcome: 'rejected', status: 409, proven: true }
    : outcome === 'server' ? { outcome: 'unknown', status: 503, proven: true } : { outcome: 'unknown', status: null, proven: false };
  return makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: observer }, seq, observedAt: '2026-10-16T00:00:00.000Z', operation: 'send', name: host, resource,
    outcome: 'committed', correlation: token ? { settlementToken: token } : {}, content: { content, resource },
    upstream: { ...up, target: { exact, query }, ...(transport ? { transport } : {}) },
    ...(host === CRM ? { idempotency: key === null ? { status: 'absent', key: null, fold: null, head: hex(`head ${head}`), firstSeq: null }
      : typeof key === 'object' ? key : { status: 'keyed', key: hex(`key ${key}`), fold: hex(`fold ${fold ?? key}`), head: hex(`head ${head}`), firstSeq: firstSeq ?? seq } } : {}) });
}
// The same send on a signing host: its key record also carries the signing item (no signature header: verified null, t null, at its arrival
// second), as the recorder writes it for every send to such a host.
export function signedSend(fields) {
  const e = send(fields), at = fields.signingAt ?? SEC0 + Math.floor((fields.arrived ?? 1000) / 1000);
  return makeEffect({ source: e.source, observer: e.observer, seq: e.seq, observedAt: e.observedAt, operation: e.operation, name: e.name, resource: e.resource, outcome: e.outcome, correlation: e.correlation,
    content: { content: fields.content ?? 'c1', resource: e.resource }, upstream: e.upstream,
    ...(e.idempotency ? { idempotency: { ...e.idempotency, signing: { scheme: SIGNING.scheme, verified: null, t: null, at } } } : {}) });
}
// An admitted check window over these events (gate B, and R1 marks for its events when the scope declares the feed).
export const windowOf = (events, { feed = FEED, coverage = 'complete', reason = null, signing = false } = {}) => admitInDoubt({ source: 'http-egress', instanceId: INST, scope: scopeOf(feed, { signing }), coverage, reason, events });

// A sealed read (src/request-feed-rules.mjs validRequestFeedRead). Entries: { at (ms, default inside the interval), route, type, tenant, state, object }.
export const entry = (fields = {}) => ({ at: OFFSET + 1050, route: true, type: true, tenant: true, state: 'applied', object: 1, ...fields });
export const read = (fields = {}) => ({ clear: true, headMono: 5000, headWall: OFFSET + 5000, watermark: OFFSET + 4900, key: 'a'.repeat(64), history: 0, variants: 0, otherHosts: 0, keySends: 1, dirtySends: 0, entries: [], more: false, ...fields });
// The recorder's record for one send: its read, bound to the send's own salted key digest (key: another one, for a mismatch).
export const supplied = (e, r, { key = e.idempotency?.key ?? 'a'.repeat(64) } = {}) => ({ observer: INST, seq: e.seq, records: [{ resolver: 'r1', read: { ...r, key } }] });

// Opted-in clauses (gate A) and clauses without the opt-in.
export const sel = (name = CRM, resource = CLOSE, upstream) => ({ source: 'http-egress', operation: 'send', name, ...(resource ? { resource } : {}), ...(upstream ? { upstream } : {}) });
export const CLOSE_SEL = Object.freeze(sel());
export const EXISTS = { kind: 'effect.exists', select: sel(CRM, CLOSE, 'resolved'), semantics: 'agent-write' };
export const count = n => ({ kind: 'effect.count', select: sel(CRM, CLOSE, 'resolved'), expected: n, semantics: 'exactly-n' });
export const ONLY = expect => ({ kind: 'effect.only', expect, allow: [], outcomeJudged: [CLOSE_SEL] });
export const KEYED_ONLY = expect => ({ kind: 'effect.only', expect, allow: [], countBy: 'idempotency-key', outcomeJudged: [CLOSE_SEL] });
export const KEYED_COUNT = n => ({ kind: 'effect.count', select: sel(CRM, null, 'resolved'), expected: n, countBy: 'idempotency-key', semantics: 'exactly-n' });
export const OPTED = [EXISTS, count(0), count(1), count(2), ONLY([]), ONLY([{ select: CLOSE_SEL, count: 1 }]), KEYED_ONLY([]), KEYED_ONLY([{ select: CLOSE_SEL, count: 1 }]), KEYED_COUNT(1), KEYED_COUNT(2)];
export const MAIN = [{ kind: 'effect.exists', select: sel(CRM, CLOSE, 'applied') }, { kind: 'effect.count', select: sel(CRM, CLOSE, 'applied'), expected: 1 },
  { kind: 'effect.count', select: { source: 'http-egress', name: CRM, resource: CLOSE }, expected: 1 }, { kind: 'effect.only', expect: [{ select: CLOSE_SEL, count: 1 }], allow: [] },
  { kind: 'effect.count', select: sel(CRM, null), expected: 1, countBy: 'idempotency-key' }];
export const opted = clause => clause?.select?.upstream === 'resolved' || Array.isArray(clause?.outcomeJudged);

export function rng(seed) { let s = seed >>> 0; return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; }; }
export const pick = (g, list) => list[Math.floor(g() * list.length)];

// A random case: 1 to 4 sends to CRM (mostly keyed, under one or two keys, retries and other identities included) and sometimes one to ALT;
// per key, the feed's entries; the feed-level read; and the records the recorder would return (every in-doubt keyed connected send to CRM).
// The entries and flags lean toward decidable groups so that confirmations and refutations are common.
const OUTCOMES = ['reset', 'reset', 'reset', 'server', 'applied', 'rejected', 'refused'];
export function randomCase(g) {
  // Seqs start at 10, so a key's first use can lie before the window (seq 1: the key was used earlier in the run).
  const sends = [], firsts = new Map(), earlier = new Map([['K1', g() < 0.05], ['K2', g() < 0.05]]), n = 1 + Math.floor(g() * 4);
  let clock = 1000;
  for (let i = 0; i < n; i++) {
    const seq = i + 10, alt = g() < 0.1, key = alt ? undefined : g() < 0.9 ? pick(g, ['K1', 'K1', 'K2']) : null;
    const arrived = clock, ended = clock + 20 + Math.floor(g() * 60); clock = ended + 5;
    if (key && !firsts.has(key)) firsts.set(key, earlier.get(key) ? 1 : seq);
    sends.push({ seq, host: alt ? ALT : CRM, outcome: pick(g, OUTCOMES), key, firstSeq: key ? firsts.get(key) : undefined, content: g() < 0.85 ? `c-${key}` : 'other',
      exact: g() < 0.95, arrived, ended, resource: g() < 0.92 ? CLOSE : OTHER });
  }
  const lastEnd = clock;
  const keyEntries = new Map(['K1', 'K2'].map(k => {
    const r = g(), list = [];
    const count = r < 0.35 ? 0 : r < 0.85 ? 1 : 2;
    for (let j = 0; j < count; j++) list.push(entry({ at: OFFSET + 1000 + Math.floor(g() * (lastEnd - 1000)), state: g() < 0.75 ? 'applied' : g() < 0.8 ? 'not-applied' : 'other',
      route: g() < 0.95, type: g() < 0.97, tenant: g() < 0.97, object: g() < 0.95 ? 1 : 2 }));
    if (list.length && list[0].object === 2) list[0].object = 1;
    return [k, list];
  }));
  const feedRead = { clear: g() < 0.92, headMono: lastEnd + SETTLE + (g() < 0.8 ? 500 : -150), headWall: OFFSET + lastEnd + SETTLE + 500, watermark: g() < 0.8 ? OFFSET + lastEnd + SETTLE + SKEW + 100 : g() < 0.5 ? null : OFFSET + lastEnd };
  const effects = [...OPTED, ...MAIN].filter(() => g() < 0.4);
  const c = { sends, keyEntries, feedRead, effects: effects.length ? effects : [pick(g, OPTED)], role: g() < 0.85 ? 'boundary' : 'control', history: new Map([['K1', g() < 0.05 ? 1 : 0], ['K2', 0]]) };
  // A third of the cases run on a signing host (dedupeSeconds 1): each send's arrival second steps by 0 or 5, so some retries arrive past the
  // receiver's dedupe window and the key collapse reads them as their own applications (PR363-REVIEW major 1).
  c.signing = g() < 0.33;
  if (c.signing) { let sec = SEC0; for (const x of sends) { sec += g() < 0.4 ? 5 : 0; x.signingAt = sec; } }
  return c;
}
// The case's events, window and the recorder's records. A fresh window and fresh events every time (overlays are per event object).
// admit: extra admissions for the window (a frozen module's gate B). upstreamOf(send, spec) may replace an event's upstream record (an oracle).
export function buildCase(c, { feed = FEED, admit = [], upstreamOf = null } = {}) {
  const make = c.signing ? signedSend : send;
  const events = c.sends.map(s => { const e = make({ seq: s.seq, host: s.host, outcome: s.outcome, key: s.host === CRM ? s.key ?? null : undefined, firstSeq: s.firstSeq, content: s.content, exact: s.exact, arrived: s.arrived, ended: s.ended, resource: s.resource, feedHost: feed !== null && s.host === CRM, signingAt: s.signingAt });
    return !upstreamOf ? e : makeEffect({ source: e.source, observer: e.observer, seq: e.seq, observedAt: e.observedAt, operation: e.operation, name: e.name, resource: e.resource, outcome: e.outcome,
      correlation: e.correlation, content: { content: s.content, resource: s.resource }, ...(e.idempotency ? { idempotency: e.idempotency } : {}), upstream: upstreamOf(e, s) }); });
  const w = windowOf(events, { feed, signing: c.signing === true });
  for (const f of admit) f(w);
  const foldCount = k => c.sends.filter(s => s.host === CRM && s.key === k).length;
  const records = events.filter((e, i) => c.sends[i].host === CRM && c.sends[i].key && ['reset', 'server'].includes(c.sends[i].outcome)).map(e => {
    const s = c.sends.find(x => x.seq === e.seq);
    return supplied(e, read({ ...c.feedRead, history: c.history.get(s.key) ?? 0, keySends: foldCount(s.key), entries: c.keyEntries.get(s.key).map(x => ({ ...x, route: x.route && s.resource === CLOSE })) }));
  });
  return { events, window: w, records };
}

// --- End to end: the connector with an injected recorder that declares this feed ------------------------------------------------------
// batches[n]() gives the events of the n-th check window (gap windows hold none); reads(events sent so far) is what its run-end resolver read
// returns ({ seq, records } items). Its scope is the one the real recorder publishes for declaration(), so the run validates against it.
export function r1RecorderFactory(batches, { reads = () => [], feed = FEED, signing = false } = {}) {
  return configs => configs.map(c => {
    const instanceId = `${c.type}-${c.id}`, sent = [];
    let n = 0, mark = 0;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope: scopeOf(feed, { signing }), witnessRequest: null, async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect(from, to, options) {
        if (options?.gap) return { events: [], coverage: 'complete', reason: null };
        const events = (batches[n++] ?? (() => []))();
        sent.push(...events);
        return { events, coverage: 'complete', reason: null };
      },
      async resolutionRecords() { return reads(sent); } };
  });
}
export const transport = async (origin, check) => ({ status: check.path === '/me' ? 200 : 201, complete: true, jsonParsed: true, json: check.path === '/me' ? {} : { closed: true }, bytes: 10 });
export const profileOf = (tasks, { feed = requestFeed(), signing = false } = {}) => ({ id: 'r1-app', name: 'R1 app', applicationId: 'r1-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-r1',
  actors: { member: { principalId: 'member-1' } }, requiredControlIds: ['WHOAMI'], observers: [declaration({ feed, signing })],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    ...tasks.map((effects, i) => ({ id: `TASK${i + 1}`, title: `Close ${i + 1}`, category: 'collateral', severity: 'high', actorId: 'member', method: 'POST', path: `/task/${i + 1}`, body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 201 }], effects }))] });
