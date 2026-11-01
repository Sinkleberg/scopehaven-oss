// Request-feed reader (in-doubt resolution R1, IDR-4; contract and rules: src/request-feed-rules.mjs). It reads a provider's own signed
// record of the write requests it received, never the application's. An egress recorder that declares `requestFeed` builds one reader and
// gives it the digest functions its own key records use (the recorder's salt never leaves the recorder), so a provider key is compared with
// a send's key only as the same salted digest, and no key, object id or tenant is stored (ADDENDUM-R1 section 3; the returnedIds pattern).
//
// Custody. start() reads the whole feed from its genesis to a signed head before the run's first check: the epoch is pinned, and every
// entry read there is history (the key was used before the run). readToHead() at run end reads a fresh signed head and every entry up to
// it, seq lastSeq + 1 of the pinned epoch at a time, so no entry can be skipped, replaced or re-based:
//   - a bad signature (an unsigned entry, another key), a malformed entry or one with an unknown field, another feed or epoch, a rewritten
//     earlier seq, a time going backward, a second genesis, one event id carrying two different bodies (a redelivery is byte-identical in
//     its canonical signed body without seq, ADDENDUM-R2 m6, and is read once), an invalid signed head: a fault, and the feed is not clear
//   - a missing seq (a gap): nothing past it is read, and the feed is not clear
// The run-end read pairs the clocks just before its head request (performance.now in this process, which is the recorder's, and the wall
// clock): R1's refutation bound compares them with each send's connection end on the same two clocks (ADDENDUM-R2 section 5,
// PR342-REVIEW-R2 finding 7). The read is bounded by the caller's cap and each request by REQUEST_FEED_REQUEST_MS; a read cut short, or
// any failure, leaves the feed not clear, so every R1 record reads failed (in doubt). Loopback only: 127.0.0.1 on the declared port.
import { request, Agent } from 'node:http';
import { verify, randomUUID } from 'node:crypto';
import { requestFeedKey, REQUEST_FEED_SCHEMA, REQUEST_FEED_REQUEST_MS, REQUEST_FEED_READ_MS, REQUEST_FEED_BOUNDS } from '../../src/request-feed-rules.mjs';
import { stable } from '../../src/domain.mjs';

export const REQUEST_FEED_LIMITS = Object.freeze({ pageEntries: 500, responseBytes: 4 * 1024 * 1024, bodyBytes: 16 * 1024, startEntries: 20000, catchUpPages: 40, retainedKeys: 20000, requestTimeoutMs: REQUEST_FEED_REQUEST_MS });
const ENTRY_PREFIX = `${REQUEST_FEED_SCHEMA}\n`, HEAD_PREFIX = `${REQUEST_FEED_SCHEMA} head\n`;
const REQUEST_KEYS = Object.freeze(['feed', 'epoch', 'seq', 'id', 'at', 'type', 'host', 'route', 'key', 'object', 'state', 'tenant']);
const GENESIS_KEYS = Object.freeze(['feed', 'epoch', 'seq', 'id', 'at', 'type']);
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const KEY = /^[\x21-\x7e]{1,255}$/;
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const bounded = (value, max) => typeof value === 'string' && value.length >= 1 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
const timeOf = text => (typeof text === 'string' && ISO.test(text) && Number.isFinite(Date.parse(text)) ? Date.parse(text) : null);
const utf8 = new TextDecoder('utf-8', { fatal: true });
class FeedFault extends Error { constructor(code) { super(code); this.code = code; } }
const fault = code => { throw new FeedFault(code); };

// config: the normalized declaration (src/request-feed-rules.mjs validateRequestFeedConfig). digests: { key(host, key), fold(host, key),
// tenant(host, value), object(host, value) }, the recorder's salted digests (fold: of the key's case and quote fold, as its key records seal it).
// clocks: { mono(), wall() } (wall may return null).
export function createRequestFeedReader({ config, digests, clocks = { mono: () => performance.now(), wall: () => Date.now() } }) {
  const key = requestFeedKey(config.publicKey);
  if (!key) throw new Error('request feed: the public key is not an Ed25519 key');
  const routes = new Map(config.routes.map(r => [r.write, r]));
  // Feed state: the pinned epoch, the last seq read and its time, each read entry's digest (a byte-identical re-read is skipped), each event
  // id's canonical body without seq (a redelivery), whether the start read reached its head, a fault, a gap, and the start head's seq.
  let epoch = null, lastSeq = 0, lastAtMs = -Infinity, faulted = null, stuck = false, startClean = false, startHead = 0, closed = false;
  const seen = new Map(), ids = new Map();
  // Per key digest: history (entries in the start read), otherHosts (the same raw key on another feed host) and the entries read after start.
  const history = new Map(), otherHosts = new Map(), byKey = new Map();
  // Per fold digest, the exact key digests seen under it (start read and after), so a send can learn of a variant of its key.
  const foldKeys = new Map();
  const bump = (map, k) => map.set(k, (map.get(k) ?? 0) + 1);
  const agent = new Agent({ keepAlive: true, maxSockets: 1 });

  function signedBody(raw, prefix, code) {
    if (!plain(raw) || Object.keys(raw).sort().join(',') !== 'body,sig' || typeof raw.body !== 'string' || typeof raw.sig !== 'string') fault(`${code}-shape`);
    if (Buffer.byteLength(raw.body) > REQUEST_FEED_LIMITS.bodyBytes) fault(`${code}-too-large`);
    const sig = Buffer.from(raw.sig, 'base64');
    if (sig.length !== 64 || sig.toString('base64') !== raw.sig || !verify(null, Buffer.from(prefix + raw.body), key, sig)) fault(`${code}-signature`);
    let b;
    try { b = JSON.parse(raw.body); } catch { fault(`${code}-body`); }
    return plain(b) ? b : fault(`${code}-body`);
  }
  // One entry in feed order. initial: the start read. Returns 'read', 'skip' (a byte-identical re-read) or 'gap'.
  function ingest(raw, initial) {
    const b = signedBody(raw, ENTRY_PREFIX, 'entry'), at = timeOf(b.at);
    if (b.feed !== config.feedId || !bounded(b.epoch, 64) || !Number.isSafeInteger(b.seq) || b.seq < 1 || !bounded(b.id, 200) || !bounded(b.type, 64) || at === null) fault('entry-body');
    if (epoch === null) { if (b.seq !== 1 || b.type !== 'epoch-start') fault('genesis-missing'); epoch = b.epoch; }
    else if (b.epoch !== epoch) fault('epoch-changed');
    const digest = stable({ body: raw.body, sig: raw.sig });
    if (b.seq <= lastSeq) { if (seen.get(b.seq) !== digest) fault('entry-rewritten'); return 'skip'; }
    if (b.seq !== lastSeq + 1) return 'gap';
    if (at < lastAtMs) fault('time-backward');
    if (b.type === 'epoch-start') {
      if (b.seq !== 1 || Object.keys(b).some(k => !GENESIS_KEYS.includes(k))) fault('genesis-repeated');
    } else {
      // Every request entry names its host, route, key, object and state, and carries nothing else (tenant optional).
      if (Object.keys(b).some(k => !REQUEST_KEYS.includes(k)) || !bounded(b.host, 253) || !bounded(b.route, 210) || typeof b.key !== 'string' || !KEY.test(b.key) || !bounded(b.object, 200) || !bounded(b.state, 64)
        || (Object.hasOwn(b, 'tenant') && !bounded(b.tenant, 200))) fault('entry-body');
    }
    lastSeq = b.seq; lastAtMs = at;
    seen.set(b.seq, digest);
    if (seen.size > REQUEST_FEED_LIMITS.retainedKeys) seen.delete(seen.keys().next().value);
    // One event id, one canonical body (its seq aside): a second delivery is a redelivery, read once; another body under it is a fault.
    const { seq: _seq, ...rest } = b, canonical = stable(rest);
    if (ids.has(b.id)) { if (ids.get(b.id) !== canonical) fault('id-reused'); return 'read'; }
    ids.set(b.id, canonical);
    if (b.type === 'epoch-start') return 'read';
    const own = digests.key(b.host, b.key), fold = digests.fold(b.host, b.key);
    foldKeys.set(fold, (foldKeys.get(fold) ?? new Set()).add(own));
    if (initial) bump(history, own);
    else {
      const route = routes.get(b.route) ?? null;
      const list = byKey.get(own) ?? [];
      list.push({ at, route: b.route, type: route !== null && route.types.includes(b.type), state: route === null ? 'other' : route.applied.includes(b.state) ? 'applied' : route.notApplied.includes(b.state) ? 'not-applied' : 'other',
        // The entry's tenant as the send's is digested (src/request-feed-rules.mjs): absent is the default tenant (''), and a tenant on a
        // feed that declares no tenant header can match no send (null).
        object: digests.object(b.host, b.object), tenant: Object.hasOwn(b, 'tenant') ? (config.tenant === null ? null : digests.tenant(b.host, b.tenant)) : digests.tenant(b.host, '') });
      byKey.set(own, list);
    }
    // The same raw key on another feed host (a key on two hosts reads in doubt for the whole key group).
    for (const h of config.hosts) if (h !== b.host) bump(otherHosts, digests.key(h, b.key));
    if (byKey.size + history.size + otherHosts.size + foldKeys.size > 4 * REQUEST_FEED_LIMITS.retainedKeys) fault('too-many-keys');
    return 'read';
  }
  function ingestAll(list, initial) {
    for (const raw of list) if (ingest(raw, initial) === 'gap') { stuck = true; return false; }
    return true;
  }
  // One bounded GET on loopback: the parsed JSON, TOO_LARGE, or null.
  const TOO_LARGE = Symbol('too-large');
  function get(path) {
    return new Promise(resolve => {
      let deadline = null;
      const done = value => { clearTimeout(deadline); resolve(value); };
      const req = request({ host: '127.0.0.1', port: config.endpoint.port, method: 'GET', path, agent, headers: { host: `127.0.0.1:${config.endpoint.port}`, accept: 'application/json' }, timeout: REQUEST_FEED_LIMITS.requestTimeoutMs }, res => {
        if (res.statusCode !== 200) { res.resume(); done(null); return; }
        const chunks = []; let size = 0;
        res.on('data', chunk => { size += chunk.length; if (size > REQUEST_FEED_LIMITS.responseBytes) { req.destroy(); done(TOO_LARGE); } else chunks.push(chunk); });
        res.on('end', () => { try { done(JSON.parse(utf8.decode(Buffer.concat(chunks)))); } catch { done(null); } });
        res.on('error', () => done(null));
      });
      deadline = setTimeout(() => req.destroy(), REQUEST_FEED_LIMITS.requestTimeoutMs);
      req.on('timeout', () => req.destroy());
      req.on('error', () => done(null));
      req.end();
    });
  }
  // The signed head for a fresh nonce: { lastSeq, epoch, watermark } (watermark ms or null), or null when it could not be fetched. Anything
  // fetched that is not this feed's head for this nonce, in the pinned epoch, at or past what was read, is a fault.
  async function head() {
    const nonce = randomUUID(), raw = await get(`${config.endpoint.path}/head?nonce=${nonce}`);
    if (raw === null || raw === TOO_LARGE) return null;
    const b = signedBody(raw, HEAD_PREFIX, 'head'), keys = Object.keys(b).sort().join(',');
    if (!['epoch,feed,lastSeq,nonce', 'epoch,feed,lastSeq,nonce,watermark'].includes(keys) || b.feed !== config.feedId || b.nonce !== nonce || !bounded(b.epoch, 64) || !Number.isSafeInteger(b.lastSeq) || b.lastSeq < 1) fault('head-invalid');
    if (epoch !== null && (b.epoch !== epoch || b.lastSeq < lastSeq)) fault('head-invalid');
    const watermark = Object.hasOwn(b, 'watermark') ? timeOf(b.watermark) : null;
    if (Object.hasOwn(b, 'watermark') && watermark === null) fault('head-invalid');
    return { lastSeq: b.lastSeq, epoch: b.epoch, watermark };
  }
  // Pages up to target (or the end): true when the feed was read to it, false otherwise.
  async function readPages(initial, target) {
    let limit = REQUEST_FEED_LIMITS.pageEntries, read = 0;
    const pages = initial ? Math.ceil(REQUEST_FEED_LIMITS.startEntries / REQUEST_FEED_LIMITS.pageEntries) + 1 : REQUEST_FEED_LIMITS.catchUpPages;
    for (let n = 0; n < pages + 9 && lastSeq < target; n++) {
      if (closed && !initial) return false;
      const res = await get(`${config.endpoint.path}?after=${lastSeq}&limit=${limit}`);
      if (res === TOO_LARGE) { if (limit === 1) fault('entry-too-large'); limit = Math.max(1, Math.floor(limit / 2)); continue; }
      if (!plain(res) || res.schema !== REQUEST_FEED_SCHEMA || !Array.isArray(res.entries) || res.entries.length > limit || typeof res.more !== 'boolean') return false;
      read += res.entries.length;
      if (initial && read > REQUEST_FEED_LIMITS.startEntries) fault('start-too-long');
      if (!ingestAll(res.entries, initial)) return false;
      if (!res.more || !res.entries.length) break;
    }
    return lastSeq >= target;
  }
  const guarded = async (fn, fallback) => {
    if (faulted) return fallback;
    try { return await fn(); } catch (error) { if (!(error instanceof FeedFault)) return fallback; faulted = error.code; return fallback; }
  };
  const UNCLEAR = Object.freeze({ clear: false, headMono: null, headWall: null, watermark: null });
  const round = v => Math.round(v * 1000) / 1000;
  let final = null;
  return {
    // The start read: the history up to a signed head, within capMs (the recorder starts before the run's first check, so a slow feed never
    // holds the run longer than that). Never throws: a feed that cannot be read, or a read the cap cut, leaves every R1 record failed.
    async start({ capMs = REQUEST_FEED_READ_MS } = {}) {
      let timer;
      const read = guarded(async () => {
        const h = await head();
        if (!h) return false;
        const ok = await readPages(true, h.lastSeq);
        if (!ok || epoch !== h.epoch || lastSeq !== h.lastSeq) return false;
        startHead = h.lastSeq;
        return true;
      }, false);
      const cut = new Promise(resolve => { timer = setTimeout(() => resolve('cut'), capMs); });
      const got = await Promise.race([read, cut]).finally(() => clearTimeout(timer));
      startClean = got === true;
      if (got === 'cut') faulted ??= 'start-cut';
    },
    // The run-end read, once: the paired clocks, a fresh signed head and every entry up to it, within capMs. Returns the feed-level part
    // of every read: { clear, headMono, headWall, watermark }.
    async readToHead({ capMs = 0 } = {}) {
      if (final) return final;
      if (!startClean || !(capMs > 0)) { closed = true; final = UNCLEAR; return final; }
      let timer;
      const cut = new Promise(resolve => { timer = setTimeout(() => resolve(null), capMs); });
      const run = guarded(async () => {
        const headMono = round(clocks.mono()), wall = clocks.wall?.(), headWall = Number.isSafeInteger(wall) ? wall : null;
        const h = await head();
        if (!h) return null;
        const ok = await readPages(false, h.lastSeq);
        return ok && !stuck && lastSeq === h.lastSeq ? { clear: true, headMono, headWall, watermark: config.watermark ? h.watermark : null } : null;
      }, null);
      const got = await Promise.race([run, cut]).finally(() => clearTimeout(timer));
      closed = true;
      final = got && !faulted && !stuck ? Object.freeze(got) : UNCLEAR;
      return final;
    },
    // The key-level part of one send's read (src/request-feed-rules.mjs validRequestFeedRead): its key and fold digests, its resource and its
    // tenant digest (null when the send's tenant header could not be read).
    keyRead(keyDigest, { fold = null, resource, tenant }) {
      const list = byKey.get(keyDigest) ?? [], objects = [];
      const ordinal = d => { let i = objects.indexOf(d); if (i < 0) { objects.push(d); i = objects.length - 1; } return i + 1; };
      const entries = list.slice(0, REQUEST_FEED_BOUNDS.entriesPerKey).map(x => ({ at: x.at, route: x.route === resource, type: x.type, tenant: x.tenant !== null && tenant !== null && x.tenant === tenant, state: x.state, object: ordinal(x.object) }));
      const variants = [...(fold === null ? [] : foldKeys.get(fold) ?? [])].filter(k => k !== keyDigest).reduce((n, k) => n + (history.get(k) ?? 0) + (byKey.get(k)?.length ?? 0), 0);
      return { history: history.get(keyDigest) ?? 0, variants, otherHosts: otherHosts.get(keyDigest) ?? 0, entries, more: list.length > REQUEST_FEED_BOUNDS.entriesPerKey };
    },
    // For the recorder's tests: the read state, labels only.
    state() { return { clear: startClean && !faulted && !stuck, faulted, stuck, startHead, lastSeq }; },
    async stop() { closed = true; agent.destroy(); },
  };
}
