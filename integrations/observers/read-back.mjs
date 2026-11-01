// Read-back reader (in-doubt resolution R2, IDR-3; declaration, sealed shapes and derivation: src/read-back-rules.mjs). Built by an egress
// recorder whose destinations declare `readBack`; it reads the system of record those destinations write to, never the application's account.
// The recorder hands it every forwarded send just before the send is forwarded (admit), when its forward starts (forwarding) and when its forward
// settles (settled), and asks it once at run end for the sealed reads (records). The recorder's salt never leaves the recorder: the reader gets
// its seal function, so ids, credentials, objects, bindings and scope values are compared only as the recorder's salted digests and never kept.
//
// Custody. Every read is a GET of a declared collection, filled only from the write's own bound path segments, sent by forwardRequest
// (egress-forward.mjs) to the destination's forward upstream on the literal 127.0.0.1 (never a name, never through the app or the recorder's
// listener, no redirect), under the destination's read credential (read once from its SCOPEHAVEN_TARGET_ variable and held only in this closure)
// with the write's declared scope headers copied, and proven under the destination's forward proof /2, which covers the reply body: a reply the
// application could have written reads unproven. When reads are taken, per group (one route of one host, one bound object, one binding, one
// write credential, one set of scope values):
//   pre  before any member is forwarded: the group's first member takes it and every member's forward waits for it, bounded by
//        min(1000 ms, timeoutMs); past that it is abandoned and the write goes on (the app is never blocked longer), and the group decides nothing
//   s1   once every member's forward settled and one is in doubt: at the last connection end plus the route's settleMs (monotonic clock)
//   s2   settleMs after s1. A new member arriving cancels both, and they are taken again after it settles
//   s3   at run end, and control (the route's seeded control object, when declared) beside it
// A route's control object is also read once when the recorder starts (controlStart), without waiting for it, where the destination declares
// no scope headers (with them, a view key is known only from a write).
// Each read is bounded by timeoutMs and the reply by the forward's maxReplyBytes; the run-end reads by the connector's cap. A read the cap cut,
// or one never taken, reads not-run. Only counts, flags and times leave this module (src/read-back-rules.mjs validReadBackRead).
import { forwardRequest } from './egress-forward.mjs';
import { credentialFrom } from './events.mjs';
import { stable } from '../../src/domain.mjs';
import { READ_BACK_BOUNDS, READ_BACK_LABELS_TEXT as LABEL, TENANT_HEADERS, parseTemplate, bindTemplate, fillTemplate, valueAt } from '../../src/read-back-rules.mjs';

export const READ_BACK_LIMITS = Object.freeze({ tracked: 20000, groups: READ_BACK_BOUNDS.groups, members: READ_BACK_BOUNDS.members });
const EMPTY = Buffer.alloc(0);
const SAFE = Object.freeze(['GET', 'HEAD', 'OPTIONS', 'TRACE']);
const round = v => Math.round(v * 1000) / 1000;
const utf8 = new TextDecoder('utf-8', { fatal: true });
const headerValues = (rawHeaders, name) => { const out = []; for (let i = 0; i + 1 < rawHeaders.length; i += 2) if (String(rawHeaders[i]).toLowerCase() === name) out.push(String(rawHeaders[i + 1])); return out; };
const sleep = ms => new Promise(resolve => setTimeout(resolve, Math.max(0, ms)));

// destinations: the recorder's normalized destinations. env: where read and identity credentials are read. seal(label, text): the recorder's
// salted digest. keyDigest(host, key): the recorder's exact key digest (its key records seal keys so). secrets: host -> forward proof secret.
// clocks: { mono(), wall() } (wall may return null). signal(): the recorder's current abort signal (stop aborts every read in flight).
export function createReadBackReader({ destinations, env, seal, keyDigest, secrets, clocks, signal = () => undefined }) {
  const byHost = new Map(destinations.map(d => [d.host, d]));
  const declared = destinations.filter(d => d.readBack);
  // Per read-back destination: the read credential's header value (read once; a missing one refuses the recorder, as a missing proof secret
  // does), the parsed templates, and the identities by the salted digest of the credential header value each one's writes carry.
  const reading = new Map(declared.map(d => {
    const value = credentialFrom(env, d.readBack.credential.env, `read-back credential of ${d.host}`);
    if (typeof value !== 'string' || value.length < 8 || /[\r\n]/.test(value)) throw new Error(`read-back credential of ${d.host}: ${d.readBack.credential.env} must hold a credential of at least 8 characters`);
    const identities = new Map();
    for (const [name, id] of Object.entries(d.readBack.identities)) {
      const v = credentialFrom(env, id.env, `read-back identity ${name} of ${d.host}`);
      if (typeof v !== 'string' || !v.length) continue;
      const digest = seal(LABEL.credential, id.scheme ? `${id.scheme} ${v}` : v);
      if (identities.has(digest)) throw new Error(`read-back identities of ${d.host}: two identities hold the same credential, so an item's author could not be told apart`);
      identities.set(digest, name);
    }
    const templates = d.readBack.routes.map(r => ({ write: parseTemplate(r.write, 'write'), read: parseTemplate(r.read, 'read'), touches: (r.touches ?? []).map(t => parseTemplate(t, 'read')) }));
    return [d.host, { header: d.readBack.credential.header, value: d.readBack.credential.scheme ? `${d.readBack.credential.scheme} ${value}` : value, identities, templates }];
  }));
  const tracked = [], groups = new Map(), startControls = new Map();
  let overflow = false, startMono = null, closed = false;

  // One GET of a group's read path (or its control path). kind: pre, s1, s2, s3, control. Returns { outcome, atMono, doneMono, atWall,
  // complete, items } with items [{ id, author, state, matches }] (ids as salted digests) only when ok.
  async function takeRead(G, kind, path = G.readPath) {
    const d = G.d, rd = reading.get(G.host), route = G.route;
    if (closed) return notRun();
    const timeoutMs = kind === 'pre' ? Math.min(READ_BACK_BOUNDS.preImageMs, d.readBack.timeoutMs) : d.readBack.timeoutMs;
    const atMono = round(clocks.mono()), wall = clocks.wall?.(), atWall = Number.isSafeInteger(wall) ? wall : null;
    let res;
    try {
      res = await forwardRequest({ port: d.forward.port, host: G.host, method: 'GET', path, rawHeaders: [rd.header, rd.value, 'Accept', 'application/json', ...G.scopePairs], body: EMPTY,
        timeoutMs, maxReplyBytes: d.forward.maxReplyBytes, secret: secrets.get(G.host) ?? null, proofVersion: 2, signal: signal() });
    } catch { res = { complete: false, reason: 'failed' }; }
    const doneMono = Math.max(atMono, round(clocks.mono()));
    const out = (outcome, extra = {}) => ({ kind, outcome, atMono, doneMono, atWall, complete: false, items: [], ...extra });
    if (!res.complete) return out(res.reason === 'timeout' ? (kind === 'pre' ? 'abandoned' : 'timeout') : res.reason === 'reply-over-limit' ? 'over-cap' : 'failed');
    if (res.status !== 200) return out('status');
    if (res.proven !== true) return out('unproven');
    let root;
    try { root = JSON.parse(utf8.decode(res.body)); } catch { return out('not-json'); }
    const list = valueAt(root, route.items);
    if (!Array.isArray(list)) return out('shape');
    if (list.length > READ_BACK_BOUNDS.items) return out('over-cap');
    const items = [], seen = new Set();
    for (const item of list) {
      const raw = valueAt(item, route.id);
      const text = typeof raw === 'string' && raw.length >= 1 && raw.length <= 200 ? raw : Number.isSafeInteger(raw) ? String(raw) : null;
      if (text === null) return out('ids');
      const id = seal('scopehaven-returned-id/1\n', text);
      if (seen.has(id)) return out('ids');
      seen.add(id);
      const author = valueAt(item, route.author.pointer);
      const word = route.lifecycle ? valueAt(item, route.lifecycle.pointer) : null;
      const state = !route.lifecycle ? 'applied' : route.lifecycle.applied.includes(word) ? 'applied' : route.lifecycle.notApplied.includes(word) ? 'not-applied' : 'other';
      items.push({ id, author: typeof author === 'string' ? author : null, state, matches: matchesBinding(G, item) });
    }
    if (route.complete && valueAt(root, route.complete.pointer) !== route.complete.equals) return out('incomplete');
    return { kind, outcome: 'ok', atMono, doneMono, atWall, complete: route.complete !== null, items };
  }
  const notRun = (kind = null) => ({ kind, outcome: 'not-run', atMono: null, doneMono: null, atWall: null, complete: false, items: [] });
  // An item belongs to the group's write: every matched field equal to the members' captured value (same JSON type), or the key at the declared
  // pointer is the members' exact key (as its salted digest).
  function matchesBinding(G, item) {
    const b = G.binding;
    if (b.kind === 'fields') return b.values.every(([pointer, v]) => { const x = valueAt(item, pointer); return x !== undefined && typeof x === typeof v && (x === v || (x === null && v === null)); });
    if (b.kind === 'key') { const x = valueAt(item, b.pointer); return typeof x === 'string' && keyDigest(G.host, x) === b.key; }
    return false;
  }

  // A send's group key parts, or null where one cannot be read (then the send gets no group, and so no R2 decision).
  function bindingOf(route, { captured, idem }) {
    if (route.match?.fields) {
      const values = [];
      for (const [itemPointer, requestPointer] of Object.entries(route.match.fields)) {
        const v = captured?.status === 'captured' ? captured.values?.[requestPointer] : undefined;
        if (!v || !['string', 'number', 'boolean', 'null'].includes(v.type)) return null;
        values.push([itemPointer, v.type === 'null' ? null : v.value]);
      }
      return { kind: 'fields', values, digest: seal(LABEL.binding, stable(['fields', values])) };
    }
    if (route.match?.key) return idem && ['keyed', 'overlap'].includes(idem.status) && typeof idem.key === 'string' ? { kind: 'key', pointer: route.match.key, key: idem.key, digest: seal(LABEL.binding, stable(['key', idem.key])) } : null;
    return { kind: 'none', digest: seal(LABEL.binding, stable(['none'])) };
  }
  // Whether the request body carries a value at the route's author or key pointer (an app-settable author or key decides nothing). A body that
  // is not JSON could carry either in another encoding, so it counts as carrying them.
  function authorInBody(route, body) {
    if (!body?.length) return false;
    let root;
    try { root = JSON.parse(utf8.decode(body)); } catch { return true; }
    return valueAt(root, route.author.pointer) !== undefined || (route.match?.key !== undefined && valueAt(root, route.match.key) !== undefined);
  }

  // A group's S1 and S2, once every member's forward settled and one is in doubt. Any new member cancels them (gen).
  // A wait in progress ends at once when cancelled (cancel), so no promise is left hanging on a cleared timer.
  const cancel = G => { G.gen++; clearTimeout(G.timer); G.wake?.(); G.wake = null; G.s1 = null; G.s2 = null; G.scheduled = null; };
  function schedule(G) {
    cancel(G);
    const gen = G.gen;
    if (!G.members.every(x => x.end !== null) || !G.members.some(x => inDoubt(x.r))) return;
    const lastEnd = Math.max(...G.members.map(x => x.end)), settleMs = G.route.settleMs;
    const at = async due => {
      while (!closed && gen === G.gen && clocks.mono() < due) await new Promise(resolve => { G.wake = resolve; G.timer = setTimeout(resolve, Math.max(1, Math.ceil(due - clocks.mono()))); });
      return !closed && gen === G.gen;
    };
    G.scheduled = (async () => {
      if (!(await at(lastEnd + settleMs + 1))) return;
      const s1 = await takeRead(G, 's1');
      if (gen !== G.gen) return;
      G.s1 = s1;
      if (s1.outcome === 'not-run' || !(await at(s1.atMono + settleMs + 1))) return;
      const s2 = await takeRead(G, 's2');
      if (gen === G.gen) G.s2 = s2;
    })();
  }
  const inDoubt = r => r.done === true && r.upstream?.outcome === 'unknown' && r.upstream.transport?.connected === true;

  // The run-wide counts for G, over every tracked forwarded send that is not a member (src/read-back-rules.mjs validReadBackRead).
  function countsOf(G, t0, t2, t3) {
    const host = G.host, backend = byHost.get(host)?.backend ?? null, members = new Set(G.members);
    let intervening = overflow ? 1 : 0, credOthers = overflow ? 1 : 0, laterCred = 0, laterRemovals = 0, laterTouching = 0;
    for (const x of tracked) {
      if (members.has(x) || x.forwardStart === null || SAFE.includes(x.method)) continue;
      const u = x.r.upstream, settled = x.end !== null;
      if (settled && (u?.transport?.connected === false || (u?.proven === true && u.outcome === 'rejected'))) continue;
      const xb = byHost.get(x.host)?.backend ?? null, same = backend === null || xb === null || backend === xb;
      if (!same) continue;
      const settle = x.route === null ? Infinity : byHost.get(x.host).readBack.routes[x.route].settleMs;
      const touching = x.host !== host || x.touches === null || x.touches.includes(G.object);
      if (t0 !== null && x.forwardStart <= t2 && (settled ? x.end : Infinity) + settle >= t0) {
        if (touching) intervening++;
        if (x.credential === null || x.credential === G.credential) credOthers++;
      }
      // After S2 and by S3: sends surely to G's object (the same host and a touches path naming it) explain what S3 shows.
      if (x.forwardStart > t2 && x.forwardStart <= t3 && x.host === host && x.touches?.includes(G.object)) {
        laterTouching++;
        if (x.credential !== null && x.credential === G.credential) laterCred++;
        if (x.method !== 'POST') laterRemovals++;
      }
    }
    return { intervening, credOthers, laterCred, laterRemovals, laterTouching };
  }
  // The sealed read for G from its reads (sealedReadOf below).
  function sealedRead(G, reads) {
    const M = new Set(G.members.filter(x => x.r.upstream?.proven === true && x.r.upstream.outcome === 'applied').flatMap(x => (Array.isArray(x.r.upstream.minted) ? x.r.upstream.minted : [])));
    const t0 = reads.pre.outcome === 'not-run' ? null : reads.pre.atMono, t2 = reads.s2.doneMono ?? round(clocks.mono()), t3 = reads.s3.doneMono ?? round(clocks.mono());
    return sealedReadOf({ group: G.digest, credential: G.credential, identity: G.identity, early: startMono === null || t0 === null || t0 < startMono + G.route.settleMs,
      counts: { groupSends: G.members.length, ...countsOf(G, t0, t2, t3) }, reads, M, matchDeclared: G.route.match !== null });
  }

  return {
    // The recorder started listening: a pre-image within a route's settleMs of this moment could miss a write sent before (m5).
    started() {
      startMono = clocks.mono(); closed = false;
      for (const d of declared) if (!d.readBack.scopeHeaders.length) d.readBack.routes.forEach((route, i) => {
        if (!route.control) return;
        const view = { d, host: d.host, route, scopePairs: [], binding: { kind: 'none' } };
        startControls.set(`${d.host}\n${i}`, takeRead(view, 'control', fillTemplate(reading.get(d.host).templates[i].read, route.control.bind)));
      });
    },
    // One forwarded send, at the end of its request and before it is forwarded. Returns { record, ready, entry }: record is the per-send record the
    // recorder seals on the send's upstream (null for a destination without readBack), ready a promise the forward waits for (the group's
    // pre-image) or null, entry the handle for forwarding() and settled().
    admit(r, { host, method, path, rawHeaders, body, captured, idem }) {
      const entry = { r, host, method, credential: null, route: null, object: null, touches: null, forwardStart: null, end: null, group: null };
      if (tracked.length < READ_BACK_LIMITS.tracked) tracked.push(entry); else overflow = true;
      const d = byHost.get(host), rd = reading.get(host);
      if (!d?.readBack || !rd) return { record: null, ready: null, entry };
      const credential = headerValues(rawHeaders, d.credentialHeader);
      entry.credential = credential.length === 1 ? seal(LABEL.credential, credential[0]) : null;
      const scopeUndeclared = TENANT_HEADERS.some(h => !d.readBack.scopeHeaders.includes(h) && headerValues(rawHeaders, h).length > 0);
      const none = extra => { const record = { route: null, group: null, object: null, touches: null, credential: entry.credential, scopeUndeclared, authorInBody: false, preImage: 'none', preImageMs: null, forwardMono: null, ...extra }; entry.record = record; return { record, ready: null, entry }; };
      const bound = rd.templates.map((t, i) => ({ i, b: bindTemplate(t.write, method, path) })).filter(x => x.b !== null);
      if (bound.length !== 1) return none();
      const { i, b } = bound[0], route = d.readBack.routes[i], t = rd.templates[i];
      const readPath = fillTemplate(t.read, b), objectOf = p => seal(LABEL.object, `${host}\n${p}`);
      entry.route = i; entry.object = objectOf(readPath);
      entry.touches = route.touches ? [...new Set(t.touches.map(x => objectOf(fillTemplate(x, b))))].sort() : null;
      const values = d.readBack.scopeHeaders.map(h => headerValues(rawHeaders, h));
      const scope = values.some(v => v.length > 1) ? null : seal(LABEL.scope, `${host}\n${stable(values.map(v => v[0] ?? null))}`);
      const binding = bindingOf(route, { captured, idem }), inBody = authorInBody(route, body);
      const base = { route: i, object: entry.object, touches: entry.touches, credential: entry.credential, scopeUndeclared, authorInBody: inBody };
      const groupless = () => { const record = { ...base, group: null, preImage: 'none', preImageMs: null, forwardMono: null }; entry.record = record; return { record, ready: null, entry }; };
      if (entry.credential === null || binding === null || scope === null) return groupless();
      const digest = seal(LABEL.group, stable([host, i, entry.object, binding.digest, entry.credential, scope]));
      let G = groups.get(digest);
      if (!G && groups.size >= READ_BACK_LIMITS.groups) return groupless();
      const first = !G;
      if (first) {
        G = { digest, host, d, route, readPath, controlPath: route.control ? fillTemplate(rd.templates[i].read, route.control.bind) : null, object: entry.object, credential: entry.credential,
          identity: rd.identities.get(entry.credential) ?? null, binding, scopePairs: d.readBack.scopeHeaders.flatMap((h, k) => (values[k].length ? [h, values[k][0]] : [])),
          members: [], pre: null, s1: null, s2: null, gen: 0, timer: null, wake: null, scheduled: null };
        groups.set(digest, G);
        G.pre = takeRead(G, 'pre');
      }
      G.members.push(entry); entry.group = G; cancel(G);
      const record = { ...base, group: digest, preImage: first ? 'first' : 'member', preImageMs: null, forwardMono: null };
      entry.record = record;
      const waitFrom = clocks.mono();
      return { record, ready: G.pre.then(() => { record.preImageMs = round(Math.max(0, clocks.mono() - waitFrom)); }), entry };
    },
    // The send's forward starts now (after its pre-image, if any); a read-back send's record carries the moment (forwardMono).
    forwarding(entry) { if (!entry) return; entry.forwardStart = round(clocks.mono()); if (entry.record) entry.record.forwardMono = entry.forwardStart; },
    // The send's forward settled: its connection end is its transport record's (the clock the derivation reads). A group with every member settled
    // and one in doubt schedules S1 and S2.
    settled(entry) {
      if (!entry) return;
      const t = entry.r.upstream?.transport;
      entry.end = typeof t?.mono === 'number' ? t.mono : round(clocks.mono());
      if (entry.group) schedule(entry.group);
    },
    // The run-end resolver read, within capMs: for each group with a member in doubt that connected, its pending S1 and S2, then S3 and the control
    // read; one { seq, records: [{ resolver: 'r2', read }] } per such member.
    async records({ capMs = 0 } = {}) {
      const need = [...groups.values()].filter(G => G.members.some(x => inDoubt(x.r)));
      if (!need.length || !(capMs > 0)) return [];
      const deadline = clocks.mono() + capMs, left = () => Math.max(0, deadline - clocks.mono());
      const capped = async (promise, fallback) => { let timer; const cut = new Promise(resolve => { timer = setTimeout(() => resolve(fallback), left()); }); try { return await Promise.race([promise, cut]); } finally { clearTimeout(timer); } };
      await capped(Promise.all(need.map(G => G.scheduled ?? null)), null);
      const results = await Promise.all(need.map(async G => {
        const pre = await capped(G.pre, notRun('pre')), s1 = G.s1 ?? notRun('s1'), s2 = G.s2 ?? notRun('s2');
        const [s3, control] = await Promise.all([left() > 0 ? capped(takeRead(G, 's3'), notRun('s3')) : notRun('s3'), G.controlPath === null ? null : left() > 0 ? capped(takeRead(G, 'control', G.controlPath), notRun('control')) : notRun('control')]);
        const startKey = `${G.host}\n${G.d.readBack.routes.indexOf(G.route)}`;
        const controlStart = G.controlPath === null || G.scopePairs.length || !startControls.has(startKey) ? null : await capped(startControls.get(startKey), notRun('control'));
        const read = sealedRead(G, { pre, s1, s2, s3, control, controlStart });
        return G.members.filter(x => inDoubt(x.r)).map(x => ({ seq: x.r.seq, records: [{ resolver: 'r2', read: structuredClone(read) }] }));
      }));
      closed = true;
      return results.flat();
    },
    stop() { closed = true; for (const G of groups.values()) cancel(G); },
  };
}

// The sealed read (src/read-back-rules.mjs validReadBackRead) from a group's reads, pure, so the counting is one function the recorder and the
// tests share. reads: { pre, s1, s2, s3, control and controlStart (each or null) }, each { outcome, atMono, doneMono, atWall, complete, items: [{ id, author, state,
// matches }] } (ids as digests, author a string or null, state applied | not-applied | other); M: the set of the proven members' minted id
// digests; identity: the identity G's credential maps to, or null; matchDeclared: the route declares match. Every count is against the
// pre-image S0 and M, and N is the new items outside M authored by the identity.
export function sealedReadOf({ group, credential, identity, early, counts, reads, M, matchDeclared }) {
  const pre = reads.pre, S0 = new Set(pre.outcome === 'ok' ? pre.items.map(i => i.id) : []);
  const zero = { total: 0, missingPre: 0, newIds: 0, newInM: 0, mInRead: 0, credItems: 0, credNew: 0, credApplied: 0, credNotApplied: 0, credOther: 0, credUnmatched: 0, credChanged: 0, anonNew: 0, lateNew: 0 };
  const shell = x => ({ outcome: x.outcome, atMono: x.atMono, doneMono: x.doneMono, atWall: x.atWall, complete: x.outcome === 'ok' && x.complete === true });
  const Ns = {}, seenNew = new Set();
  const one = (x, k) => {
    if (x.outcome !== 'ok') return { ...shell(x), ...zero };
    const ids = new Set(x.items.map(i => i.id)), mine = i => identity !== null && i.author === identity;
    const base = { ...shell(x), ...zero, total: x.items.length, credItems: x.items.filter(mine).length };
    if (k === 'control') return base;
    if (k === 'pre') return { ...base, mInRead: [...M].filter(m => ids.has(m)).length };
    const fresh = x.items.filter(i => !S0.has(i.id)), N = fresh.filter(i => !M.has(i.id) && mine(i));
    Ns[k] = new Set(N.map(i => i.id));
    const outside = fresh.filter(i => !M.has(i.id)), lateNew = k === 's3' ? outside.filter(i => !seenNew.has(i.id)).length : 0;
    if (k !== 's3') for (const i of outside) seenNew.add(i.id);
    const before = Ns[k === 's2' ? 's1' : 's2'] ?? new Set();
    const changed = k === 's2' ? [...Ns.s2].filter(id => !before.has(id)).length + [...before].filter(id => !Ns.s2.has(id)).length : k === 's3' ? [...Ns.s3].filter(id => !before.has(id)).length : 0;
    return { ...base, missingPre: [...S0].filter(id => !ids.has(id)).length, newIds: fresh.length, newInM: fresh.filter(i => M.has(i.id)).length, mInRead: [...M].filter(m => ids.has(m)).length, credNew: N.length,
      credApplied: N.filter(i => i.state === 'applied').length, credNotApplied: N.filter(i => i.state === 'not-applied').length, credOther: N.filter(i => i.state === 'other').length,
      credUnmatched: matchDeclared ? N.filter(i => !i.matches).length : N.length, credChanged: changed, anonNew: outside.filter(i => typeof i.author !== 'string').length, lateNew };
  };
  return { group, credential, identity, early, groupSends: counts.groupSends, intervening: counts.intervening, credOthers: counts.credOthers, laterCred: counts.laterCred, laterRemovals: counts.laterRemovals, laterTouching: counts.laterTouching,
    pre: one(pre, 'pre'), s1: one(reads.s1, 's1'), s2: one(reads.s2, 's2'), s3: one(reads.s3, 's3'), control: reads.control == null ? null : one(reads.control, 'control'),
    controlStart: reads.controlStart == null ? null : one(reads.controlStart, 'control') };
}
