// Request feed: in-doubt resolution R1 (IDR-4; IN-DOUBT-DESIGN.md section 3, ADDENDUM-R1 section 3 and M7, ADDENDUM-R2 sections 2 and 5,
// minors m1 and m6). Pure: no I/O. The declaration, its record, the sealed read and the derivation of an attempt's R1 result from that
// read. Shared by src/egress-rules.mjs (the declaration), src/in-doubt.mjs (applicability and the derivation), src/http-effects.mjs (the
// run record), src/contracts.mjs (profile and run checks), src/http-timing.mjs (the read's reserve) and the reader in
// integrations/observers/request-feed.mjs. It imports nothing that imports src/in-doubt.mjs, so the core reads it without a cycle; the key
// collapse's identity and retention rule comes from src/key-identity.mjs, the one function src/idempotency.mjs reads too.
//
// What a request feed is. A provider-signed record of the write requests a provider received on declared hosts: per request, the exact
// idempotency key it carried, the route, the provider object it touched and that object's lifecycle state word, in the contract
// scopehaven-request-feed/1. A loopback provider stub, or an operator-run adapter whose signing key the application never holds, signs
// it with Ed25519; ScopeHaven holds only the public key. Mail provider feeds (src/provider-feed-rules.mjs) are a separate contract.
//   entry  { body, sig }: sig is the Ed25519 signature of "scopehaven-request-feed/1\n" + body; body is the JSON text
//          { feed, epoch, seq: 1, id, at, type: "epoch-start" } (the genesis) or
//          { feed, epoch, seq, id, at, type, host, route, key, object, state, tenant? }: type the provider's event type word, route a
//          declared write ("POST /v1/refunds"), key the exact idempotency key, object the provider's object id, state its lifecycle word,
//          tenant the provider's tenant (account) when the provider has one
//   head   GET <path>/head?nonce=<uuid>: { body, sig } over "scopehaven-request-feed/1 head\n" + body, body { feed, epoch, lastSeq, nonce,
//          watermark? }. watermark (ISO time): the provider attests that every request it received on the declared hosts before that
//          time has its entries at or before this head
//   page   GET <path>?after=<seq>&limit=<n>: { schema, entries, more }
// Declared on the egress recorder whose sends it resolves (its `requestFeed`), so its records bind only onto that recorder's own sends:
//   { feedId, endpoint: { port, path }, publicKey, hosts, routes, maxSkewMs, watermark?, tenant? }
//   hosts      forwarded destinations of this recorder that declare idempotency (the key the join reads)
//   routes     [{ write, types, applied, notApplied?, settleMs?, source? }]: write is a method that can change state and one of a feed
//              host's declared paths, as the recorder names a send's resource; types the provider event types an entry for it may
//              carry; applied and notApplied the lifecycle words that mean the write took effect, or did not (disjoint); settleMs the
//              provider's documented bound from the end of the forward connection to the last moment a received write can commit, with
//              source naming that document. Any other type or word reads in doubt for its key
//   maxSkewMs  how far the provider's clock may differ from this one (required: 0 to 2000)
//   watermark  true: the head's signed watermark is the provider's attestation above. Absent: no refutation (ADDENDUM-R2 m1, every
//              guarantee key absent reads the least permissive way: no watermark and no settleMs mean R1 can only confirm)
//   tenant     { header }: the request header that names the provider tenant (an account header). Each entry's tenant must then
//              equal the send's header value (absent on both is the default tenant); without it, an entry that names a tenant reads in
//              doubt for its key
//
// The sealed read (ADDENDUM-R2 m2 style, PR348-REVIEW minor 5): what the recorder read for one attempt, counts, flags and times only (no
// key, id, object, tenant or address), from which deriveRequestFeed re-derives the result on both sides. Feed-level: clear (the start read
// and the run-end read each reached a fresh signed head with no gap, fault or malformed entry), headMono and headWall (the paired clocks,
// read just before the run-end head request, on the recorder's own process clock and the wall clock), watermark (ms, only when declared
// and signed). Key-level: key (the attempt's own salted key digest, as its sealed key record carries it, so a read is bound to the key it was
// read for), history (entries for the attempt's exact key and host in the start read), variants (entries, before or after the start read, for a
// case or quote variant of the key on its host: the key's fold, another exact key), otherHosts (entries for the same raw
// key on another host), keySends (the recorder's sends under the key's fold, run-wide), dirtySends (sends to the host whose key could not
// be read, run-wide), entries (the key's entries after the start read, in feed order: at, route equal to the send's resource, type listed
// for its route, tenant equal, state class and object ordinal) and more (entries past the cap).
import { createPublicKey, createHash } from 'node:crypto';
import { stable } from './domain.mjs';
import { keyGroupIdentity } from './key-identity.mjs';

export const REQUEST_FEED_SCHEMA = 'scopehaven-request-feed/1';
// One feed or head request's deadline, and the run-end read's cap (a head and pages); the timing plan reserves the cap (src/http-timing.mjs).
export const REQUEST_FEED_REQUEST_MS = 2000, REQUEST_FEED_READ_MS = 6000;
export const REQUEST_FEED_BOUNDS = Object.freeze({ hosts: 16, routes: 16, words: 16, entriesPerKey: 16, maxSkewMs: Object.freeze([0, 2000]), settleMs: Object.freeze([1, 120000]), port: Object.freeze([1024, 65535]), sourceChars: 200, counts: 1e6 });
export const REQUEST_FEED_STATES = Object.freeze(['applied', 'not-applied', 'other']);
// Equal to IDEMPOTENCY_DIRTY and IDEMPOTENCY_METHODS in src/idempotency.mjs (test/request-feed.test.mjs holds them equal), restated so
// this module imports nothing that imports the in-doubt core.
export const DIRTY_STATUSES = Object.freeze(['method-undeclared', 'repeated', 'malformed', 'over-cap', 'unreadable', 'untracked']);
const WRITE_METHODS = Object.freeze(['POST', 'PUT', 'PATCH', 'DELETE']);
const KEYS = Object.freeze(['feedId', 'endpoint', 'publicKey', 'hosts', 'routes', 'maxSkewMs', 'watermark', 'tenant']);
const ROUTE_KEYS = Object.freeze(['write', 'types', 'applied', 'notApplied', 'settleMs', 'source']);
const RESERVED_HEADERS = Object.freeze(['host', 'authorization', 'proxy-authorization', 'cookie', 'content-type', 'content-length', 'transfer-encoding', 'connection', 'traceparent']);
const FEED_ID = /^[A-Za-z0-9_.-]{1,64}$/;
const WORD = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HEADER = /^[a-z0-9][a-z0-9-]{0,63}$/;
const HOST = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const WRITE = /^(POST|PUT|PATCH|DELETE) (\/[A-Za-z0-9._~\-/]{0,199})$/;
const SOURCE = /^[\x20-\x7e]{1,200}$/;
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const intIn = (value, [lo, hi]) => Number.isSafeInteger(value) && value >= lo && value <= hi;
const words = (list, { min = 1 } = {}) => Array.isArray(list) && list.length >= min && list.length <= REQUEST_FEED_BOUNDS.words && list.every(w => typeof w === 'string' && WORD.test(w)) && new Set(list).size === list.length;
const originPath = path => typeof path === 'string' && path.startsWith('/') && !path.startsWith('//') && path.length <= 200 && !/[?#\s\\]/.test(path) && !path.endsWith('/');

// The Ed25519 public key a declaration names (SPKI DER, base64), or null.
export function requestFeedKey(text) {
  if (typeof text !== 'string' || text.length > 200 || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) return null;
  const der = Buffer.from(text, 'base64');
  if (der.toString('base64') !== text) return null;
  try { const key = createPublicKey({ key: der, format: 'der', type: 'spki' }); return key.asymmetricKeyType === 'ed25519' ? key : null; } catch { return null; }
}
export const requestFeedKeyDigest = text => createHash('sha256').update(Buffer.from(text, 'base64')).digest('hex');

// A route, normalized: { write, types, applied, notApplied, settleMs, source } (settleMs and source null when not declared).
function validRoute(r) {
  if (!plain(r) || Object.keys(r).some(key => !ROUTE_KEYS.includes(key))) return null;
  if (typeof r.write !== 'string' || !WRITE.test(r.write) || !words(r.types) || !words(r.applied) || (r.notApplied !== undefined && !words(r.notApplied, { min: 0 }))) return null;
  const notApplied = r.notApplied ?? [];
  if (r.applied.some(w => notApplied.includes(w))) return null;
  if ((r.settleMs === undefined) !== (r.source === undefined)) return null;
  if (r.settleMs !== undefined && !(intIn(r.settleMs, REQUEST_FEED_BOUNDS.settleMs) && typeof r.source === 'string' && SOURCE.test(r.source))) return null;
  return { write: r.write, types: [...r.types], applied: [...r.applied], notApplied: [...notApplied], settleMs: r.settleMs ?? null, source: r.source ?? null };
}
// A recorder's `requestFeed` (src/egress-rules.mjs validateEgressConfig): destinations its normalized destinations, witnessHost its
// witness host or null, port its own listening port. Throws with a profile-facing message; returns the normalized declaration.
export function validateRequestFeedConfig(rf, { destinations = [], witnessHost = null, port = null } = {}) {
  if (!plain(rf) || Object.keys(rf).some(key => !KEYS.includes(key))) throw new Error(`"requestFeed" is { ${KEYS.join(', ')} } (watermark and tenant optional)`);
  if (typeof rf.feedId !== 'string' || !FEED_ID.test(rf.feedId)) throw new Error('"requestFeed.feedId" is the feed name every signed entry carries: 1 to 64 letters, digits, ".", "_" or "-"');
  const e = rf.endpoint;
  if (!plain(e) || Object.keys(e).length !== 2 || !intIn(e.port, REQUEST_FEED_BOUNDS.port) || e.port === port || !originPath(e.path)) throw new Error('"requestFeed.endpoint" is { port, path }: a port from 1024 to 65535 other than the recorder\'s own, and an origin-form path without a query, a fragment or a trailing "/" (read on 127.0.0.1 only; its signed head is <path>/head)');
  if (!requestFeedKey(rf.publicKey)) throw new Error('"requestFeed.publicKey" must be the provider stub\'s or adapter\'s Ed25519 public key (SPKI DER, base64); a private key or any other key type is refused');
  const byHost = new Map((Array.isArray(destinations) ? destinations : []).map(d => [d?.host, d]));
  if (!Array.isArray(rf.hosts) || !rf.hosts.length || rf.hosts.length > REQUEST_FEED_BOUNDS.hosts || new Set(rf.hosts).size !== rf.hosts.length
    || !rf.hosts.every(h => typeof h === 'string' && HOST.test(h) && h !== witnessHost && byHost.get(h)?.forward && byHost.get(h)?.idempotency)) throw new Error('"requestFeed.hosts" lists 1 to 16 distinct destination hosts of this recorder, each declaring "forward" and "idempotency" (the key the feed joins by)');
  if (!Array.isArray(rf.routes) || !rf.routes.length || rf.routes.length > REQUEST_FEED_BOUNDS.routes) throw new Error('"requestFeed.routes" lists 1 to 16 { write, types, applied, notApplied?, settleMs?, source? }');
  const routes = rf.routes.map(r => {
    const route = validRoute(r);
    if (!route) throw new Error('each request-feed route is { write: "POST /v1/refunds", types: [...], applied: [...], notApplied?: [...], settleMs?, source? }: a method that can change state and a path, 1 to 16 distinct lowercase words in each list, applied and notApplied disjoint, and settleMs (1 to 120000) with source (the provider document that states it) together or not at all');
    const path = WRITE.exec(route.write)[2];
    if (!rf.hosts.some(h => (byHost.get(h)?.paths ?? []).includes(path))) throw new Error(`request-feed route "${route.write}" names a path no feed host declares in its "paths": a send's resource is its method and declared path`);
    return route;
  });
  if (new Set(routes.map(r => r.write)).size !== routes.length) throw new Error('each request-feed route "write" is declared once');
  if (!intIn(rf.maxSkewMs, REQUEST_FEED_BOUNDS.maxSkewMs)) throw new Error('"requestFeed.maxSkewMs" is required: an integer from 0 to 2000, how far the provider\'s clock may differ from this one');
  if (rf.watermark !== undefined && rf.watermark !== true) throw new Error('"requestFeed.watermark" is true (the feed\'s signed head carries the provider\'s watermark) or absent');
  let tenant = null;
  if (rf.tenant !== undefined) {
    if (!plain(rf.tenant) || Object.keys(rf.tenant).length !== 1 || typeof rf.tenant.header !== 'string' || !HEADER.test(rf.tenant.header) || RESERVED_HEADERS.includes(rf.tenant.header) || rf.tenant.header.includes('scopehaven')
      || rf.hosts.some(h => byHost.get(h)?.idempotency?.header === rf.tenant.header)) throw new Error('"requestFeed.tenant" is { header }: the lowercase request header that names the provider tenant, never an identity, framing or key header');
    tenant = rf.tenant.header;
  }
  return { feedId: rf.feedId, endpoint: { port: e.port, path: e.path }, publicKey: rf.publicKey, keyDigest: requestFeedKeyDigest(rf.publicKey), hosts: [...rf.hosts], routes, maxSkewMs: rf.maxSkewMs, watermark: rf.watermark === true, tenant };
}
// The record a recorder's scope and a run's observer record carry (the declaration less its endpoint and key text): { feedId, keyDigest,
// hosts, routes, maxSkewMs, watermark, tenant }.
export const requestFeedRecord = cfg => ({ feedId: cfg.feedId, keyDigest: cfg.keyDigest, hosts: [...cfg.hosts], routes: cfg.routes.map(r => ({ ...r, types: [...r.types], applied: [...r.applied], notApplied: [...r.notApplied] })),
  maxSkewMs: cfg.maxSkewMs, watermark: cfg.watermark, tenant: cfg.tenant });
// The same record from a profile's raw (already validated) declaration (src/http-effects.mjs declaredObserverRecord).
export const requestFeedRecordOf = rf => requestFeedRecord({ feedId: rf.feedId, keyDigest: requestFeedKeyDigest(rf.publicKey), hosts: rf.hosts, routes: rf.routes.map(validRoute), maxSkewMs: rf.maxSkewMs,
  watermark: rf.watermark === true, tenant: rf.tenant?.header ?? null });
const RECORD_KEYS = Object.freeze(['feedId', 'keyDigest', 'hosts', 'routes', 'maxSkewMs', 'watermark', 'tenant']);
export const validRequestFeedRecord = rec => plain(rec) && Object.keys(rec).length === RECORD_KEYS.length && RECORD_KEYS.every(k => Object.hasOwn(rec, k))
  && typeof rec.feedId === 'string' && FEED_ID.test(rec.feedId) && typeof rec.keyDigest === 'string' && /^[a-f0-9]{64}$/.test(rec.keyDigest)
  && Array.isArray(rec.hosts) && rec.hosts.length >= 1 && rec.hosts.length <= REQUEST_FEED_BOUNDS.hosts && rec.hosts.every(h => typeof h === 'string' && HOST.test(h)) && new Set(rec.hosts).size === rec.hosts.length
  && Array.isArray(rec.routes) && rec.routes.length >= 1 && rec.routes.length <= REQUEST_FEED_BOUNDS.routes
  && rec.routes.every(r => plain(r) && Object.keys(r).length === ROUTE_KEYS.length && stable(validRoute({ write: r.write, types: r.types, applied: r.applied, notApplied: r.notApplied, ...(r.settleMs === null ? {} : { settleMs: r.settleMs, source: r.source }) })) === stable(r))
  && new Set(rec.routes.map(r => r.write)).size === rec.routes.length && intIn(rec.maxSkewMs, REQUEST_FEED_BOUNDS.maxSkewMs) && typeof rec.watermark === 'boolean'
  && (rec.tenant === null || (typeof rec.tenant === 'string' && HEADER.test(rec.tenant)));
// The route a send's resource names in a declaration, or null.
export const routeOf = (decl, resource) => (Array.isArray(decl?.routes) ? decl.routes.find(r => r.write === resource) ?? null : null);

// R1 applies to an in-doubt attempt (the core checks that) only when it connected, carries a keyed record, goes to a feed host, was marked
// exact and query-free (egress-recorder/6 target flags) and names a declared route. Every other attempt has R0 alone.
export const requestFeedApplies = (e, decl) => plain(decl) && e?.upstream?.transport?.connected === true && plain(e.idempotency) && ['keyed', 'overlap'].includes(e.idempotency.status)
  && Array.isArray(decl.hosts) && decl.hosts.includes(e.name) && e.upstream.target?.exact === true && e.upstream.target?.query === false && routeOf(decl, e.resource) !== null;

const READ_KEYS = Object.freeze(['clear', 'headMono', 'headWall', 'watermark', 'key', 'history', 'variants', 'otherHosts', 'keySends', 'dirtySends', 'entries', 'more']);
const ENTRY_KEYS = Object.freeze(['at', 'route', 'type', 'tenant', 'state', 'object']);
const WALL = [0, 8.64e15], COUNT = [0, REQUEST_FEED_BOUNDS.counts];
const monoOk = v => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1e13;
// A sealed read, by shape: exactly its keys, counts and flags in range, the paired clocks both present or both absent, and object ordinals
// numbered by first appearance.
export function validRequestFeedRead(read) {
  if (!plain(read) || Object.keys(read).length !== READ_KEYS.length || !READ_KEYS.every(k => Object.hasOwn(read, k))) return false;
  if (typeof read.clear !== 'boolean' || typeof read.more !== 'boolean') return false;
  if (!((read.headMono === null && read.headWall === null) || (monoOk(read.headMono) && (read.headWall === null || intIn(read.headWall, WALL))))) return false;
  if (!(read.watermark === null || intIn(read.watermark, WALL)) || typeof read.key !== 'string' || !/^[a-f0-9]{64}$/.test(read.key)) return false;
  if (!['history', 'variants', 'otherHosts', 'keySends', 'dirtySends'].every(k => intIn(read[k], COUNT))) return false;
  if (!Array.isArray(read.entries) || read.entries.length > REQUEST_FEED_BOUNDS.entriesPerKey) return false;
  let objects = 0;
  for (const x of read.entries) {
    if (!plain(x) || Object.keys(x).length !== ENTRY_KEYS.length || !ENTRY_KEYS.every(k => Object.hasOwn(x, k))) return false;
    if (!intIn(x.at, WALL) || typeof x.route !== 'boolean' || typeof x.type !== 'boolean' || typeof x.tenant !== 'boolean' || !REQUEST_FEED_STATES.includes(x.state)) return false;
    if (!intIn(x.object, [1, objects + 1])) return false;
    objects = Math.max(objects, x.object);
  }
  return true;
}

// The derivation (both the connector's run-end stage and the validator run it, src/in-doubt.mjs bindResolutions). window: one admitted
// check window whose scope declares this feed; reads: Map(event -> sealed read) of the attempts R1 applies to that carry one; inDoubt and
// applies: the core's predicates. Returns Map(event -> { resolver: 'r1', status: 'succeeded', result } or { resolver: 'r1', status:
// 'failed', reason }) for every event of reads.
// Groups are exact-key groups inside the fold groups of keyed sends (src/idempotency.mjs): one window, one host, one fold. A group is
// decided only when it is one application's sends as the key collapse reads them (no send to the host whose key could not be read, in the
// window or anywhere in the run; the fold's first use is the group's first send; no other send under the fold anywhere in the run; one
// exact key; no two in flight at once; one identity among the sends a proven rejection or R0 leaves, read through the collapse's own
// identity and retention function, src/key-identity.mjs keyGroupIdentity: on a host that declares signing, a member that arrived past the
// receiver's dedupeSeconds is its own application, and re-signed members compare by their signed items) and every in-doubt member R0 does not
// refute carries an equal read (ADDENDUM-R2 2.4: every applicable resolver of every member succeeded). Then, from the key's own entries
// only (m6): a feed not clear, an entry before the start read (history), the key on another host, entries past the cap, an entry whose
// route, type, tenant or state word is not declared, two objects, or an entry stamped outside [first connected arrival - skew, last
// connection end + settleMs + skew] (M7) leaves the group failed; so does an entry for a case or quote variant of the key (the key's fold under
// another exact key: a provider that folds keys could be reporting this request under it). Applied and not-applied words together: failed. An applied word: the
// provider applied the key once, so one application stands for the group: with a member proven applied every in-doubt member is refuted
// as a further application, and otherwise the first in-doubt member is confirmed and the others refuted (they share one identity, so no
// clause can tell them apart; the count is the provider's one). No applied word: refuted only when the feed declares a watermark, the
// route a settleMs, no member is proven applied, and for every connected member the head was read at monotonic time at or past its
// connection end plus settleMs, the signed watermark is at or past its wall connection end plus settleMs plus skew, both wall clocks
// were read, and the wall-minus-monotonic offset moved by at most the skew between them (ADDENDUM-R2 section 5; PR342-REVIEW-R2 finding
// 7), and the key has at least as many entries as members with a proven reply (a positive control, as R2's C1: the provider answered
// those, so a feed that lists fewer is not showing every request it received; PR363-REVIEW minor 1). Otherwise silent: R1 decides nothing.
export function deriveRequestFeed({ window, reads, inDoubt, applies }) {
  const out = new Map();
  const failed = reason => ({ resolver: 'r1', status: 'failed', reason });
  const decl = window?.scope?.requestFeed;
  const events = Array.isArray(window?.events) ? window.events : [];
  if (!validRequestFeedRecord(decl)) { for (const e of reads.keys()) out.set(e, failed('declaration-invalid')); return out; }
  const sends = events.filter(x => plain(x) && x.operation === 'send' && x.outcome === 'committed');
  const done = new Set();
  for (const e of reads.keys()) {
    if (done.has(e)) continue;
    const fold = e.idempotency?.fold;
    const members = sends.filter(x => x.name === e.name && plain(x.idempotency) && x.idempotency.fold === fold);
    const needing = members.filter(x => inDoubt(x) && x.upstream?.transport?.connected !== false);
    const group = needing.filter(x => reads.has(x));
    for (const x of group) done.add(x);
    const settle = result => { for (const x of group) out.set(x, result(x)); };
    if (group.length !== needing.length || !needing.every(applies)) { settle(() => failed('group-unresolved')); continue; }
    // Two exact keys under one fold (a case or quote variant): each member's read is for its own key, so the window decides this first.
    if (members.some(x => x.idempotency.key !== e.idempotency.key)) { settle(() => failed('key-variant')); continue; }
    const read = reads.get(group[0]), text = stable(read);
    if (!group.every(x => stable(reads.get(x)) === text)) { settle(() => failed('record-mismatch')); continue; }
    const reason = groupProblem({ window, e, members, sends, read, decl });
    if (reason) { settle(() => failed(reason)); continue; }
    const proven = members.filter(x => x.upstream?.proven === true && x.upstream.outcome === 'applied').length;
    const applied = read.entries.filter(x => x.state === 'applied').length, notApplied = read.entries.filter(x => x.state === 'not-applied').length;
    if (applied && notApplied) { settle(() => failed('state-mixed')); continue; }
    const ordered = [...group].sort((a, b) => a.seq - b.seq);
    if (applied) { settle(x => ({ resolver: 'r1', status: 'succeeded', result: !proven && x === ordered[0] ? 'confirms' : 'refutes' })); continue; }
    settle(() => ({ resolver: 'r1', status: 'succeeded', result: !proven && refutable({ members, read, decl, route: routeOf(decl, e.resource) }) ? 'refutes' : 'silent' }));
  }
  return out;
}
const connectedOf = members => members.filter(x => x.upstream?.transport?.connected === true);
// Why a group cannot be decided, or null.
function groupProblem({ window, e, members, sends, read, decl }) {
  const hostSends = sends.filter(x => x.name === e.name);
  if (hostSends.some(x => !plain(x.idempotency) || DIRTY_STATUSES.includes(x.idempotency.status)) || read.dirtySends !== 0) return 'host-dirty';
  if (read.key !== e.idempotency.key) return 'key-mismatch';
  if (members.some(x => x.idempotency.status === 'overlap')) return 'key-concurrent';
  const first = [...members].sort((a, b) => a.seq - b.seq)[0];
  if (first.idempotency.firstSeq !== first.seq) return 'key-earlier-use';
  if (read.keySends !== members.length) return 'key-other-window';
  // One identity among the members a proven rejection or R0 leaves, by the key collapse's own function over the whole group (rejected members
  // included, as src/idempotency.mjs reads it): content, head, settlement token, signed items and the receiver's dedupe window.
  const identity = keyGroupIdentity(window, e.name, hostSends)(members);
  const standing = members.filter(x => !(x.upstream?.proven === true && x.upstream.outcome === 'rejected') && x.upstream?.transport?.connected !== false);
  if (new Set(standing.map(identity)).size > 1) return 'key-identity-differs';
  if (!read.clear) return 'feed-unclear';
  if (read.more) return 'entries-capped';
  if (read.history > 0) return 'key-history';
  // A provider that recorded a case or quote variant of the key (or folded it) may be reporting this send's request under another spelling.
  if (read.variants > 0) return 'key-variant-entry';
  if (read.otherHosts > 0) return 'key-other-host';
  if (read.entries.some(x => !x.route)) return 'route-mismatch';
  if (read.entries.some(x => !x.type)) return 'type-unlisted';
  if (read.entries.some(x => !x.tenant)) return 'tenant-mismatch';
  if (read.entries.some(x => x.state === 'other')) return 'state-unlisted';
  if (read.entries.some(x => x.object > 1)) return 'key-objects';
  if (read.entries.length) {
    const connected = connectedOf(members), route = routeOf(decl, e.resource), settleMs = route?.settleMs ?? 0;
    const arrivals = connected.map(x => x.upstream.transport.arrivedWall), ends = connected.map(x => x.upstream.transport.wall);
    if (!connected.length || [...arrivals, ...ends].some(v => !Number.isSafeInteger(v))) return 'clock-missing';
    const lo = Math.min(...arrivals) - decl.maxSkewMs, hi = Math.max(...ends) + settleMs + decl.maxSkewMs;
    if (read.entries.some(x => x.at < lo || x.at > hi)) return 'entry-outside-interval';
  }
  return null;
}
// The refutation preconditions (ADDENDUM-R1 1.5, ADDENDUM-R2 section 5).
function refutable({ members, read, decl, route }) {
  if (decl.watermark !== true || read.watermark === null || route?.settleMs === null || route?.settleMs === undefined || read.headMono === null || read.headWall === null) return false;
  const settleMs = route.settleMs, offset = read.headWall - read.headMono, connected = connectedOf(members);
  if (read.entries.length < members.filter(x => x.upstream?.proven === true).length) return false;
  return connected.length > 0 && connected.every(x => {
    const t = x.upstream.transport;
    return Number.isSafeInteger(t.wall) && read.headMono >= t.mono + settleMs && read.watermark >= t.wall + settleMs + decl.maxSkewMs && Math.abs(offset - (t.wall - t.mono)) <= decl.maxSkewMs;
  });
}

// The observers whose R1 reads disagree on their feed-level part, over everything the run's resolver reads returned (items: { observer,
// records }). A recorder reads its feed once, so such reads are not one recorder's: the connector fails them all (src/in-doubt.mjs
// lateEntriesFor), and the validator refuses them (consistentRequestFeedRun below), so the two sides never disagree about a run.
export function requestFeedDisagreeing(items) {
  const parts = new Map();
  for (const x of Array.isArray(items) ? items : []) for (const r of Array.isArray(x?.records) ? x.records : []) {
    if (r?.resolver !== 'r1' || !plain(r.read)) continue;
    const part = stable({ clear: r.read.clear, headMono: r.read.headMono, headWall: r.read.headWall, watermark: r.read.watermark });
    parts.set(x.observer, (parts.get(x.observer) ?? new Set()).add(part));
  }
  return new Set([...parts].filter(([, set]) => set.size > 1).map(([observer]) => observer));
}
// Run checks (src/contracts.mjs): every R1 read of one recorder carries the same feed-level part (the recorder reads its feed once, at run
// end), and a read's run-wide counts are at least what the run's sealed windows show (sends under its key's fold; sends to its host whose
// key could not be read). rows: [{ resolutions, windows }] per effect row (its sealed entries and bound windows); sealedWindows: every
// sealed window of the run. A read edited in one row is caught against the others. Throws request-feed-run.
export function consistentRequestFeedRun(rows, sealedWindows) {
  const bad = () => { throw new Error('request-feed-run'); };
  const feedPart = new Map();
  for (const { resolutions, windows } of Array.isArray(rows) ? rows : []) for (const entry of Array.isArray(resolutions) ? resolutions : []) for (const r of entry.records) {
    if (r?.resolver !== 'r1' || !Object.hasOwn(r, 'read')) continue;
    const part = stable({ clear: r.read.clear, headMono: r.read.headMono, headWall: r.read.headWall, watermark: r.read.watermark });
    if (feedPart.has(entry.observer) && feedPart.get(entry.observer) !== part) bad();
    feedPart.set(entry.observer, part);
    const e = windows.find(w => w.instanceId === entry.observer)?.events.find(x => x.seq === entry.seq);
    if (!plain(e?.idempotency)) bad();
    const own = sealedWindows.filter(w => w.instanceId === entry.observer).flatMap(w => w.events).filter(x => x.operation === 'send' && x.name === e.name);
    if (r.read.keySends < own.filter(x => plain(x.idempotency) && x.idempotency.fold === e.idempotency.fold).length) bad();
    if (r.read.dirtySends < own.filter(x => !plain(x.idempotency) || DIRTY_STATUSES.includes(x.idempotency.status)).length) bad();
  }
}

// Profile checks. A feed endpoint served on the port of the target origin, an observer, a forward upstream or another feed would be
// answered by the app or a ScopeHaven sink, not by the provider. Returns a message, or null.
const LOOPBACK_ORIGIN = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/?$/;
const UPSTREAM = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/;
export function requestFeedClash(target) {
  const observers = Array.isArray(target?.observers) ? target.observers : [];
  const taken = new Map(observers.filter(o => Number.isInteger(o?.port)).map(o => [o.port, `observer "${o.id}"`]));
  const origin = typeof target?.origin === 'string' ? LOOPBACK_ORIGIN.exec(target.origin) : null;
  if (origin) taken.set(Number(origin[1]), 'the target origin');
  for (const o of observers) {
    if (o?.type === 'egress-recorder' && Array.isArray(o.destinations)) for (const d of o.destinations) { const m = typeof d?.forward?.upstream === 'string' ? UPSTREAM.exec(d.forward.upstream) : null; if (m) taken.set(Number(m[1]), `the forward upstream of "${d.host}"`); }
    if (o?.type === 'provider-feed' && Number.isInteger(o.feed?.endpoint?.port)) taken.set(o.feed.endpoint.port, `provider-feed observer "${o.id}"`);
  }
  // A feed host another egress recorder also declares: that recorder's sends are another writer the feed sees and the group never does
  // (PR363-REVIEW minor 2), so the profile is refused.
  for (const o of observers) {
    if (o?.type !== 'egress-recorder' || !Array.isArray(o.requestFeed?.hosts)) continue;
    for (const other of observers) {
      if (other === o || other?.type !== 'egress-recorder' || !Array.isArray(other.destinations)) continue;
      const shared = o.requestFeed.hosts.find(h => other.destinations.some(d => d?.host === h));
      if (shared !== undefined) return `the request feed of egress recorder "${o.id}" names host "${shared}", which egress recorder "${other.id}" also declares: a feed host is declared on one recorder only, so every send the feed lists is one the join can see`;
    }
  }
  for (const o of observers) {
    const port = o?.type === 'egress-recorder' ? o.requestFeed?.endpoint?.port : undefined;
    if (!Number.isInteger(port)) continue;
    if (taken.has(port)) return `the request feed of egress recorder "${o.id}" uses the port of ${taken.get(port)}: the feed must be served by the provider stub or adapter, not the app or a ScopeHaven observer`;
    taken.set(port, `the request feed of egress recorder "${o.id}"`);
  }
  return null;
}
// Whether any egress recorder of a profile (or of a run's observer records) declares a request feed (the timing plan's resolver read).
export const requestFeedsDeclared = observers => (Array.isArray(observers) ? observers : []).some(o => o?.type === 'egress-recorder' && plain(o.requestFeed));
