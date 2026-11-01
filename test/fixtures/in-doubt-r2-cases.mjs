// Synthetic cases for in-doubt resolution R2, read-back (IDR-3; test/read-back.test.mjs and test/in-doubt-r2.test.mjs). One egress recorder
// (egress-recorder/9) forwarding crm.example, which declares a read-back route for its ticket notes (backend "crm"), and alt.example, which
// declares none (backend "other"). A case is plain data: the sends of one write group (and sometimes another group on the same ticket, or a
// send elsewhere), what the modelled system of record holds at each read (its notes, their authors, states and texts), and the faults a
// provider could show (a hidden view, lag, a removal, an author left out, normalized text). Its sealed reads are built with the recorder's own
// counting function (integrations/observers/read-back.mjs sealedReadOf), so they are reads the recorder could have made. Clocks are fixed
// numbers, so every derivation is deterministic. For tests only; not in any identity list. Owned synthetic data only: hosts are names, never
// resolved or contacted.
import { createHash } from 'node:crypto';
import { makeEffect } from '../../src/effect-events.mjs';
import { admitInDoubt } from '../../src/in-doubt.mjs';
import { declaredObserverRecord, observerInstanceId } from '../../src/http-effects.mjs';
import { sealedReadOf } from '../../integrations/observers/read-back.mjs';
import { localCounts } from '../../src/read-back-rules.mjs';

export const CRM = 'crm.example', ALT = 'alt.example', WITNESS = 'witness.scopehaven.invalid';
export const INST = observerInstanceId('egress-recorder', 'sink');
export const NOTES_T1 = 'POST /tickets/T-1/notes', NOTES_T2 = 'POST /tickets/T-2/notes', ALT_RES = 'POST /x';
export const SETTLE = 200, OFFSET = 1760000000000, START = 10;
export const hex = text => createHash('sha256').update(text).digest('hex');
// The route as a profile declares it, with every guarantee; variants drop or weaken one key at a time (each only removes decisions).
const ROUTE = Object.freeze({ write: 'POST /tickets/{ticket}/notes', read: 'GET /tickets/{ticket}/notes', items: '/notes', id: '/id', author: { pointer: '/author', serverAssigned: true }, settleMs: SETTLE,
  complete: { pointer: '/complete', equals: true }, match: { fields: { '/text': '/body' } },
  guarantees: { consistency: 'strong', completeness: 'exhaustive-pagination', removal: 'never', settleMs: SETTLE, source: 'synthetic CRM API reference, notes section' },
  view: { covers: ['app', 'jobs'], items: 'all-items' }, deferredFields: ['/send_at'], control: { bind: { ticket: 'T-CTRL' } }, touches: ['GET /tickets/{ticket}/notes'] });
const drop = (o, key) => { const { [key]: _x, ...rest } = o; return rest; };
export const VARIANTS = Object.freeze({
  full: ROUTE,
  lifecycle: { ...ROUTE, lifecycle: { pointer: '/state', applied: ['posted'], notApplied: ['declined'], nonFinal: ['pending'] } },
  noGuarantees: drop(ROUTE, 'guarantees'), noComplete: drop(ROUTE, 'complete'), noMatch: drop(ROUTE, 'match'), noView: drop(ROUTE, 'view'), noControl: drop(ROUTE, 'control'), noTouches: drop(ROUTE, 'touches'),
  eventual: { ...ROUTE, guarantees: { ...ROUTE.guarantees, consistency: 'eventual' } }, observed: { ...ROUTE, guarantees: { ...ROUTE.guarantees, source: 'observed' } },
  removable: { ...ROUTE, guarantees: { ...ROUTE.guarantees, removal: 'possible' } }, appOnly: { ...ROUTE, view: { covers: ['jobs'], items: 'all-items' } }, partialView: { ...ROUTE, view: { covers: ['app', 'jobs'], items: 'partial' } },
  // Writes that change an item in place (PR373-REVIEW blocker 1): every guarantee declared, yet they confirm only.
  patch: { ...ROUTE, write: 'PATCH /tickets/{ticket}/notes' }, put: { ...ROUTE, write: 'PUT /tickets/{ticket}/notes/{note}' },
});
export const VARIANT_NAMES = Object.freeze(Object.keys(VARIANTS));
export const readBackOf = (variant = 'full', extra = {}) => ({ credential: { env: 'SCOPEHAVEN_TARGET_CRM_READ', header: 'authorization', scheme: 'Bearer' }, timeoutMs: 1000, scopeHeaders: [],
  identities: { app: { env: 'SCOPEHAVEN_TARGET_CRM_APP', scheme: 'Bearer' }, jobs: { env: 'SCOPEHAVEN_TARGET_CRM_JOBS', scheme: 'Bearer' } }, routes: [VARIANTS[variant]], ...extra });
// minted: false drops forward.ids from crm.example (refutation then needs a minted-id declaration it lacks).
export const declaration = ({ variant = 'full', readBack = true, port = 40999, upstream = 47103, altUpstream = upstream + 1, extra = {}, minted = true } = {}) => ({ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', settleMs: 250, quietMs: 150,
  witness: { actorId: 'member', method: 'GET', path: '/ping', host: WITNESS },
  destinations: [{ host: CRM, paths: ['/tickets/T-1/notes', '/tickets/T-2/notes', '/tickets/T-CTRL/notes'], capture: { pointers: ['/body', '/send_at'] },
    forward: { upstream: `http://127.0.0.1:${upstream}`, rejected: [409], proofEnv: 'SCOPEHAVEN_TARGET_CRM_PROOF', proofVersion: 2, ...(minted ? { ids: { minted: ['/id'] } } : {}) }, idempotency: { header: 'idempotency-key' },
    objectPaths: ['POST /tickets/{ticket}/notes'], backend: 'crm', ...(readBack ? { credentialHeader: 'authorization', readBack: readBackOf(variant, extra) } : {}) },
  { host: ALT, paths: ['/x'], forward: { upstream: `http://127.0.0.1:${altUpstream}`, rejected: [409], proofEnv: 'SCOPEHAVEN_TARGET_ALT_PROOF' }, backend: 'other' }] });
export const RECORDS = Object.freeze(Object.fromEntries([...VARIANT_NAMES.map(v => [v, declaredObserverRecord([declaration({ variant: v })])[0]]), ['plain', declaredObserverRecord([declaration({ readBack: false })])[0]],
  ['noMinted', declaredObserverRecord([declaration({ minted: false })])[0]]]));
export const recordOf = variant => RECORDS[variant ?? 'plain'];
export const META = new Map([[INST, { kind: 'http-egress-recorder', settleMs: 250 }]]);
export const scopeOf = variant => { const r = recordOf(variant); return { operations: ['send'], names: [CRM, ALT], actorAttribution: 'none', evidence: 'authoritative', capture: r.capture, forward: r.forward, idempotency: r.idempotency, ...(r.readBack ? { readBack: r.readBack } : {}) }; };

// Credentials, groups and objects as the recorder's salted digests (fixed strings here).
export const CRED = { app: hex('credential Bearer tok-app'), jobs: hex('credential Bearer tok-jobs'), rotated: hex('credential Bearer tok-rotated') };
export const OBJ = { T1: hex('object crm.example /tickets/T-1/notes'), T2: hex('object crm.example /tickets/T-2/notes') };
export const groupDigest = ({ object = 'T1', binding = 'hello', credential = 'app' } = {}) => hex(`group ${object} ${binding} ${credential}`);
export const mintedOf = id => hex(`id ${id}`);

// One send. outcome: applied (proven 201, minting `minted`), rejected (proven 409), reset (connected, unknown), server (connected, proven 503),
// refused (never connected), missing (no transport record: a forward that never settled). readBack: the per-send record's overrides (null: none).
export function send({ seq, host = CRM, resource = NOTES_T1, outcome = 'reset', minted, binding = 'hello', credential = 'app', object = 'T1', preImage = 'first', preImageMs = 2, end = 1100, wall,
  body = binding, sendAt = 'absent', query = false, scopeUndeclared = false, authorInBody = false, touches, key = 'K1', firstSeq, route = 0, readBack = {}, captured, forwardMono }) {
  const transport = outcome === 'missing' ? undefined : { connected: outcome !== 'refused', mono: end, wall: wall === undefined ? OFFSET + end : wall };
  // Only crm.example declares returned ids (forward ids.minted), so only its proven replies carry a minted id.
  const up = outcome === 'applied' ? { outcome: 'applied', status: 201, proven: true, ...(minted === null || host !== CRM ? {} : { minted: [mintedOf(minted ?? `m${seq}`)] }) } : outcome === 'rejected' ? { outcome: 'rejected', status: 409, proven: true }
    : outcome === 'server' ? { outcome: 'unknown', status: 503, proven: true } : { outcome: 'unknown', status: null, proven: false };
  const rb = host === CRM && transport && readBack !== null ? { route, group: groupDigest({ object, binding, credential }), object: OBJ[object], touches: touches === undefined ? [OBJ[object]] : touches,
    credential: CRED[credential], scopeUndeclared, authorInBody, preImage, preImageMs, forwardMono: forwardMono === undefined ? end - 4 : forwardMono, ...readBack } : null;
  return makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST }, seq, observedAt: '2026-10-16T00:00:00.000Z', operation: 'send', name: host, resource, outcome: 'committed',
    content: { target: `${host} ${resource} ${query}`, body, sendAt }, ...(host === CRM ? { captured: captured ?? { status: 'captured', values: { '/body': { type: 'string', value: body }, '/send_at': sendAt === 'absent' ? { type: 'absent' } : sendAt === null ? { type: 'null', value: null } : { type: 'string', value: sendAt } } } } : {}),
    ...(host === CRM ? { idempotency: key === null ? { status: 'absent', key: null, fold: null, head: hex('head'), firstSeq: null } : { status: 'keyed', key: hex(`key ${key}`), fold: hex(`fold ${key}`), head: hex('head'), firstSeq: firstSeq ?? seq } } : {}),
    upstream: { ...up, target: { exact: true, query }, ...(transport ? { transport } : {}), ...(rb ? { readBack: rb } : {}) } });
}
export const windowOf = (events, { variant = 'full', coverage = 'complete', reason = null } = {}) => admitInDoubt({ source: 'http-egress', instanceId: INST, scope: scopeOf(variant), coverage, reason, events });

// --- The modelled system of record ------------------------------------------------------------------------------------------------------
// An item: { id, author, state, text }. A read at kind k of a list of items: what the reader records (ids digested as the recorder seals them).
// lifecycle: the route declares the lifecycle variant's words (posted applied, declined not applied, pending and anything else other);
// without it every listed item is applied.
const classOf = (word, lifecycle) => (!lifecycle ? 'applied' : word === 'posted' ? 'applied' : word === 'declined' ? 'not-applied' : 'other');
const view = (items, { text, lifecycle = false }) => items.map(i => ({ id: mintedOf(i.id), author: i.author, state: classOf(i.state, lifecycle), matches: i.text === text }));
export const okRead = (atMono, items, ctx, { complete = true, wallOffset = 0 } = {}) => ({ outcome: 'ok', atMono, doneMono: atMono + 5, atWall: OFFSET + atMono + wallOffset, complete, items: view(items, ctx) });
export const badRead = (outcome, atMono) => (outcome === 'not-run' ? { outcome, atMono: null, doneMono: null, atWall: null, complete: false, items: [] } : { outcome, atMono, doneMono: atMono + 5, atWall: OFFSET + atMono, complete: false, items: [] });
// The sealed read for a group from its modelled reads. state: the state word mapping (the lifecycle variant's words, or every item applied).
export const sealed = ({ group = groupDigest(), credential = CRED.app, identity = 'app', early = false, counts = {}, reads, M = [], matchDeclared = true }) =>
  sealedReadOf({ group, credential, identity, early, counts: { groupSends: 1, intervening: 0, credOthers: 0, laterCred: 0, laterRemovals: 0, laterTouching: 0, ...counts }, reads, M: new Set(M.map(mintedOf)), matchDeclared });
// A simple honest group read: S0 the pre-existing items, S1 S2 S3 those plus `added`, a control item of the identity.
export function honest({ pre = [], added = [], identity = 'app', text = 'hello', lastEnd = 1100, counts = {}, M = [], control = true, s3extra = [], matchDeclared = true, group, credential, lifecycle = false } = {}) {
  const ctx = { identity, text, lifecycle }, at1 = lastEnd + SETTLE + 1, at2 = at1 + SETTLE + 6, at3 = at2 + 50;
  // The pre-image just before the group's forward (60 ms before its last connection end, so before every member's).
  return sealed({ identity, counts, M, matchDeclared, group, credential, reads: { pre: okRead(lastEnd - 60, pre, ctx), s1: okRead(at1, [...pre, ...added], ctx), s2: okRead(at2, [...pre, ...added], ctx), s3: okRead(at3, [...pre, ...added, ...s3extra], ctx),
    control: control ? okRead(at3, [{ id: 'ctl-1', author: identity, state: 'applied', text: 'seed' }], ctx) : null } });
}
export const supplied = (e, read) => ({ observer: INST, seq: e.seq, records: [{ resolver: 'r2', read }] });

// Opted-in clauses (gate A) and clauses without the opt-in.
export const sel = (resource = NOTES_T1, upstream) => ({ source: 'http-egress', operation: 'send', name: CRM, ...(resource ? { resource } : {}), ...(upstream ? { upstream } : {}) });
export const NOTE_SEL = Object.freeze(sel());
export const EXISTS = { kind: 'effect.exists', select: sel(NOTES_T1, 'resolved'), semantics: 'agent-write' };
export const count = n => ({ kind: 'effect.count', select: sel(NOTES_T1, 'resolved'), expected: n, semantics: 'exactly-n' });
export const ONLY = expect => ({ kind: 'effect.only', expect, allow: [], outcomeJudged: [NOTE_SEL] });
export const KEYED_COUNT = n => ({ kind: 'effect.count', select: sel(null, 'resolved'), expected: n, countBy: 'idempotency-key', semantics: 'exactly-n' });
export const OPTED = [EXISTS, count(0), count(1), count(2), ONLY([]), ONLY([{ select: NOTE_SEL, count: 1 }]), KEYED_COUNT(1), KEYED_COUNT(2)];
export const MAIN = [{ kind: 'effect.exists', select: sel(NOTES_T1, 'applied') }, { kind: 'effect.count', select: sel(NOTES_T1, 'applied'), expected: 1 },
  { kind: 'effect.count', select: { source: 'http-egress', name: CRM, resource: NOTES_T1 }, expected: 1 }, { kind: 'effect.only', expect: [{ select: NOTE_SEL, count: 1 }], allow: [] }];
export const opted = clause => clause?.select?.upstream === 'resolved' || Array.isArray(clause?.outcomeJudged);

export function rng(seed) { let s = seed >>> 0; return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; }; }
export const pick = (g, list) => list[Math.floor(g() * list.length)];

// A random case. One group G on T-1 (1 to 3 members, sometimes a retry of another body or credential, which is another group, or a send to T-2 or
// alt.example); the truth of each in-doubt member (applied or not); the backend's items at each read; faults that break a declared guarantee
// (then a decision may be wrong by the declaration's own fault, so truth is checked only without one); and the declaration variant.
const OUTCOMES = ['reset', 'reset', 'reset', 'reset', 'server', 'applied', 'applied', 'rejected', 'refused'];
export const FAULTS = Object.freeze(['hidden', 'lag', 'removed', 'anonymous', 'normalized', 'other-credential', 'pre-deleted', 'pending']);
export function randomCase(g) {
  const variant = g() < 0.55 ? 'full' : g() < 0.3 ? 'lifecycle' : pick(g, VARIANT_NAMES);
  const n = 1 + Math.floor(g() * 3), sends = [];
  let clock = 1000;
  for (let i = 0; i < n; i++) {
    const end = clock + 20 + Math.floor(g() * 60); clock = end + 5;
    const r = g();
    // Mostly members of G (same body, same credential); sometimes another group on T-1 (another body or credential), T-2, or alt.example.
    const kind = r < 0.78 ? 'member' : r < 0.85 ? 'body' : r < 0.9 ? 'cred' : r < 0.95 ? 'T2' : 'alt';
    // ownKey: a member under its own idempotency key (a new key per retry), so the key collapse counts it apart (PR373-REVIEW major 1).
    sends.push({ seq: START + i, kind, outcome: pick(g, OUTCOMES), end, applied: g() < 0.5, sendAt: g() < 0.93 ? 'absent' : g() < 0.5 ? null : '2026-10-20T00:00:00Z', query: g() < 0.04, scopeUndeclared: g() < 0.03, authorInBody: g() < 0.03, ownKey: g() < 0.35 });
  }
  if (!sends.some(s => s.kind === 'member')) sends[0].kind = 'member';
  const faults = FAULTS.filter(() => g() < 0.06);
  const pre = [...(g() < 0.5 ? [{ id: 'old-1', author: 'app', state: 'posted', text: g() < 0.3 ? 'hello' : 'older' }] : []), ...(g() < 0.4 ? [{ id: 'old-2', author: 'jobs', state: 'posted', text: 'note' }] : [])];
  const effects = [...OPTED, ...MAIN].filter(() => g() < 0.4);
  return { variant, sends, faults, pre, others: g() < 0.15 ? [{ id: 'bg-1', author: 'jobs', state: 'posted', text: 'background' }] : [], effects: effects.length ? effects : [pick(g, OPTED)], role: g() < 0.85 ? 'boundary' : 'control',
    extraCounts: g() < 0.08 ? { intervening: 1 } : g() < 0.08 ? { credOthers: 1 } : {}, early: g() < 0.03, clockFault: g() < 0.04 ? pick(g, ['before-bound', 'too-close', 'drift']) : null, readFault: g() < 0.05 ? pick(g, ['status', 'unproven', 'timeout', 'not-run', 'incomplete', 'abandoned']) : null };
}
const stateWord = (variant, applied) => (variant === 'lifecycle' ? (applied ? 'posted' : 'declined') : 'posted');
// The case's events, window and the recorder's records: one sealed read per in-doubt connected member of G (as the recorder returns them).
// Truth: which members applied. upstreamOf(event, spec) may replace an event's upstream record (an oracle).
export function buildCase(c, { variant = c.variant, readBack = true, admit = [], upstreamOf = null } = {}) {
  const groupKey = s => (s.kind === 'member' ? { object: 'T1', binding: 'hello', credential: 'app' } : s.kind === 'body' ? { object: 'T1', binding: 'other text', credential: 'app' } : s.kind === 'cred' ? { object: 'T1', binding: 'hello', credential: 'jobs' } : { object: 'T2', binding: 'hello', credential: 'app' });
  const firstOf = new Map(), keyFirst = new Map();
  const events = c.sends.map(s => {
    const k = groupKey(s), id = `${k.object}|${k.binding}|${k.credential}`, first = !firstOf.has(id); firstOf.set(id, true);
    const host = s.kind === 'alt' ? ALT : CRM, resource = s.kind === 'alt' ? ALT_RES : s.kind === 'T2' ? NOTES_T2 : NOTES_T1;
    const key = s.kind === 'member' && !s.ownKey ? 'K1' : `K${s.seq}`; if (!keyFirst.has(key)) keyFirst.set(key, s.seq);
    const e = send({ seq: s.seq, host, resource, outcome: s.outcome, minted: `m${s.seq}`, ...k, preImage: first ? 'first' : 'member', end: s.end, sendAt: s.sendAt, query: s.query, scopeUndeclared: s.scopeUndeclared, authorInBody: s.authorInBody, key, firstSeq: keyFirst.get(key),
      readBack: readBack ? {} : null });
    if (!upstreamOf) return e;
    return makeEffect({ source: e.source, observer: e.observer, seq: e.seq, observedAt: e.observedAt, operation: e.operation, name: e.name, resource: e.resource, outcome: e.outcome, correlation: e.correlation,
      content: { target: `${host} ${resource} ${s.query}`, body: s.kind === 'body' ? 'other text' : 'hello', sendAt: s.sendAt }, ...(e.captured ? { captured: e.captured } : {}), ...(e.idempotency ? { idempotency: e.idempotency } : {}), upstream: upstreamOf(e, s) });
  });
  const w = windowOf(events, { variant: readBack ? variant : null });
  for (const f of admit) f(w);
  const members = c.sends.filter(s => s.kind === 'member');
  const truthApplied = s => s.outcome === 'applied' || (['reset', 'server'].includes(s.outcome) && s.applied);
  // The backend: the pre-image items, then one note per applied member of G (its minted id when proven), and the faults.
  const has = f => c.faults.includes(f);
  const added = [], lagged = [];
  for (const s of members) {
    const proven = s.outcome === 'applied';
    if (truthApplied(s)) {
      const item = { id: proven ? `m${s.seq}` : `n${s.seq}`, author: has('anonymous') && !proven ? null : 'app', state: has('pending') && !proven ? 'pending' : stateWord(variant, true), text: has('normalized') && !proven ? 'Hello' : 'hello' };
      if (!proven && has('hidden')) continue;
      (has('lag') && !proven ? lagged : added).push(item);
    } else if (['reset', 'server'].includes(s.outcome) && variant === 'lifecycle' && s.applied === false && c.sends.length % 2 === 0) added.push({ id: `d${s.seq}`, author: 'app', state: 'declined', text: 'hello' });
  }
  if (has('other-credential')) added.push({ id: 'x-1', author: 'jobs', state: stateWord(variant, true), text: 'hello' });
  const pre = c.pre.map(i => ({ ...i, state: variant === 'lifecycle' ? i.state : 'posted' })), later = [...c.others];
  const atPre = START + 100, lastEnd = Math.max(...members.map(s => s.end)), at1 = lastEnd + SETTLE + (c.clockFault === 'before-bound' ? -20 : 1), at2 = at1 + (c.clockFault === 'too-close' ? SETTLE - 30 : SETTLE + 6), at3 = at2 + 50;
  const kept = has('pre-deleted') ? pre.slice(1) : pre, removed = has('removed') ? added.filter(i => !i.id.startsWith('m')).map(i => i.id) : [];
  const ctx = { identity: 'app', text: 'hello', lifecycle: variant === 'lifecycle' }, drift = c.clockFault === 'drift' ? 4000 : 0;
  const list = extra => [...kept, ...added.filter(i => !removed.includes(i.id)), ...later, ...extra];
  const reads = { pre: c.readFault === 'abandoned' ? badRead('abandoned', atPre) : okRead(atPre, pre, ctx), s1: c.readFault === 'status' ? badRead('status', at1) : okRead(at1, list([]), ctx, { wallOffset: drift }),
    s2: c.readFault === 'timeout' ? badRead('timeout', at2) : c.readFault === 'incomplete' ? badRead('incomplete', at2) : okRead(at2, list([]), ctx), s3: c.readFault === 'not-run' ? badRead('not-run', at3) : c.readFault === 'unproven' ? badRead('unproven', at3) : okRead(at3, list(lagged), ctx),
    control: VARIANTS[variant]?.control ? okRead(at3, [{ id: 'ctl-1', author: 'app', state: stateWord(variant, true), text: 'seed' }], ctx) : null };
  const M = members.filter(s => s.outcome === 'applied').map(s => `m${s.seq}`);
  // The recorder's run-wide counts: at least what this window shows (src/read-back-rules.mjs localCounts), plus the case's extra (sends outside it).
  const first = events.find((e, i) => c.sends[i].kind === 'member'), local = readBack ? localCounts(scopeOf(variant).readBack, first, events, reads.pre.atMono ?? 0, reads.s2.doneMono ?? at2 + 5) : { intervening: 0, credOthers: 0 };
  const read = sealed({ early: c.early, counts: { groupSends: members.length, intervening: local.intervening + (c.extraCounts.intervening ?? 0), credOthers: local.credOthers + (c.extraCounts.credOthers ?? 0) }, reads, M,
    matchDeclared: VARIANTS[variant]?.match !== undefined });
  const records = events.filter((e, i) => c.sends[i].kind === 'member' && ['reset', 'server'].includes(c.sends[i].outcome)).map(e => supplied(e, read));
  const truth = new Map(events.map((e, i) => [e, truthApplied(c.sends[i])]));
  // Faults that break a declared guarantee (a view that hides the write's item, a removal before S1): a decision may then be wrong by the
  // declaration's own fault. Every other fault (lag, a missing author, normalized text, a pending state, a deleted pre-image item, another
  // identity's item, clock drift) must only remove decisions.
  return { events, window: w, records, truth, faulted: c.faults.includes('hidden') || c.faults.includes('removed') };
}

// --- End to end: the connector with an injected recorder that declares read-back -----------------------------------------------------
// batches[n]() gives the events of the n-th check window (gap windows hold none); reads(events sent so far) is what its run-end resolver read
// returns ({ seq, records } items). Its scope is the one the real recorder publishes for declaration(variant), so the run validates against it.
export function r2RecorderFactory(batches, { reads = () => [], variant = 'full' } = {}) {
  return configs => configs.map(c => {
    const instanceId = `${c.type}-${c.id}`, sent = [];
    let n = 0, mark = 0;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope: scopeOf(variant), witnessRequest: null, async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect(from, to, options) {
        if (options?.gap) return { events: [], coverage: 'complete', reason: null };
        const events = (batches[n++] ?? (() => []))();
        sent.push(...events);
        return { events, coverage: 'complete', reason: null };
      },
      async resolutionRecords() { return reads(sent); } };
  });
}
export const transport = async (origin, check) => ({ status: check.path === '/me' ? 200 : 201, complete: true, jsonParsed: true, json: check.path === '/me' ? {} : { posted: true }, bytes: 10 });
// guard: a required allowed-use control of the tasks' actor (GUARD) whose positive clause is a proven applied send to alt.example (another
// backend, so no read-back group of crm.example reads it), so a task's effect.only clauses are guarded (FIX-07, src/http-pairing.mjs
// allowedUseGuards); its window takes the recorder's first batch (guardBatch).
export const GUARD_EXISTS = { kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: ALT, resource: ALT_RES } };
export const guardBatch = () => [send({ seq: 1, host: ALT, resource: ALT_RES, outcome: 'applied', end: 100 })];
export const profileOf = (tasks, { variant = 'full', readBack = true, guard = false } = {}) => ({ id: 'r2-app', name: 'R2 app', applicationId: 'r2-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-r2',
  actors: { member: { principalId: 'member-1' } }, requiredControlIds: guard ? ['WHOAMI', 'GUARD'] : ['WHOAMI'], observers: [declaration({ variant, readBack })],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    ...(guard ? [{ id: 'GUARD', title: 'Allowed alt write', category: 'Allowed use', severity: 'control', actorId: 'member', method: 'POST', path: '/guard', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }], effects: [GUARD_EXISTS] }] : []),
    ...tasks.map((effects, i) => ({ id: `TASK${i + 1}`, title: `Note ${i + 1}`, category: 'collateral', severity: 'high', actorId: 'member', method: 'POST', path: `/task/${i + 1}`, body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 201 }], effects }))] });
