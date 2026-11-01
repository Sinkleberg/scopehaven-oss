// Provider-feed configuration (pure; shared by src/contracts.mjs, src/http-timing.mjs and the observer in
// integrations/observers/provider-feed.mjs).
//
// The observer reads an email provider's own record of what it accepted, never the application's record. The
// record is a feed of entries in the scopehaven-provider-feed/1 contract, each signed with Ed25519 by the
// provider stub (or an operator-run adapter) that implements the contract. ScopeHaven holds only the public key,
// declared here: no secret is read. Real provider APIs (Postmark, SendGrid, Mailgun, Stripe) are not read directly.
//
// feed: exactly one of
//   { endpoint: { port, path } } - route (i): GET http://127.0.0.1:<port><path>?after=<seq>&limit=<n> and the signed head
//     GET <path>/head?nonce=<nonce> (loopback only; the host cannot be set, and the port is never the target origin's,
//     another observer's or a forward upstream's)
//   { file: { path } }           - route (ii): an operator-supplied JSON-lines file of signed entries, bound at start. It is
//     presence-only in v1: it has no signed head, and an app that can write the file could remove a line not yet read.
// feedId: the "feed" every signed entry names. publicKey: base64 SPKI DER of the provider stub's Ed25519 key.
// domains: [{ domain, addresses? }] - the recipient domains checks name (effect name = recipient domain), as for the
//   SMTP sink; addresses are full recipient addresses that name an event's resource, any other recipient reads "*".
// routing: "provider" (the app's mail goes through this feed's provider) and witness: { actorId, method: "GET", path,
//   domain } - an app request (path) that makes the app send one email through the provider to "<nonce>@<domain>",
//   where <nonce> is the query parameter scopehaven_witness it was given. They go together, and only on an endpoint
//   feed: its silence counts as authoritative only with both; without them the observer is presence-only.
// pollMs: how often the feed is read; quietMs (at least 2 x pollMs): the quiet period after the witness;
// maxSkewMs: how far the stub's clock may differ from this one (0 when they share a clock).
// templates: optional, { <label>: <provider template id> } - the template vocabulary (src/body-fields.mjs TEMPLATE_POINTER). An
//   entry's signed contract field "template" (the provider's canonical id of the stored template it accepted the message with)
//   that is exactly a declared id gives each of its events to a declared domain the captured field /template with that label;
//   anything else reads unknown. Only labels reach a run: the run record's feed lists them, and no provider id is stored or digested.
// outcomes: optional, { waitMs? } - later outcomes (PROVIDER-LATER-OUTCOME design and ADDENDUM-R1): the feed reads signed "outcome" entries,
//   the provider's later word on a send it accepted (LATER_OUTCOMES), each bound to that send by the provider's own message id. Only on an
//   endpoint feed with a witness (its signed head bounds what was read). waitMs (0 to 30000, default 0): the later wait, after the final
//   mark and the run-end windows, for outcomes still due. The run record's feed carries { waitMs }; nothing else of it is stored.
// keySource: optional (FIX-06, provider-feed/7), where the public key came from, which nothing in a run can show: "provider" (the provider's
//   own export of the key it signs entries with), "adapter" (an operator-run adapter that implements the contract and signs with a key
//   the operator holds; adapterReads then says what it reads: "provider-api", the provider's own record, or "application-store", the
//   application's own store) or "stub" (a test stub). The run record's feed and every sealed window carry keySource ("undeclared" when
//   the profile names none) and adapterReads. Custody reads them (src/custody.mjs feedKeyCustody): an adapter that reads the
//   application's own store, or an undeclared source, is a key the application could hold, so the feed never supports a pass.
import { createPublicKey, createHash } from 'node:crypto';
import { smtpDomain } from './smtp-rules.mjs';
import { mailboxOf } from './mail-address.mjs';
import { TEMPLATE_POINTER, templateLabelValid } from './body-fields.mjs';

export const PROVIDER_FEED_SCHEMA = 'scopehaven-provider-feed/1';
// One feed or head request's deadline; the timing plan reserves three per witness close (the split's head, the end mark's head and a page).
export const PROVIDER_FEED_REQUEST_MS = 2000;
export const PROVIDER_FEED_BOUNDS = Object.freeze({ domains: 64, addresses: 64, quietMs: [100, 10000], witnessWaitMs: [0, 30000], pollMs: [25, 1000], maxSkewMs: [0, 2000], port: [1024, 65535], templates: 64, templateIdChars: 200, waitMs: [0, 30000] });
const KEYS = ['id', 'type', 'feedId', 'feed', 'publicKey', 'domains', 'routing', 'witness', 'witnessWaitMs', 'quietMs', 'pollMs', 'maxSkewMs', 'settleMs', 'templates', 'outcomes', 'keySource', 'adapterReads'];
// The key sources a profile may declare, and what an adapter may read (FIX-06). A record also says "undeclared".
export const FEED_KEY_SOURCES = Object.freeze(['provider', 'adapter', 'stub']);
export const FEED_ADAPTER_READS = Object.freeze(['provider-api', 'application-store']);
export const FEED_KEY_RECORD_SOURCES = Object.freeze([...FEED_KEY_SOURCES, 'undeclared']);
// A provider template id: printable ASCII without edge spaces. Two declared ids are distinct even with case and spaces folded,
// since a provider that matches loosely could render either for both.
const TEMPLATE_ID = /^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/;
const foldId = id => id.toLowerCase().replace(/\s+/g, '');
const WITNESS_KEYS = ['actorId', 'method', 'path', 'domain'];
const ADDRESS = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9.-]{1,253}$/;
const FEED_ID = /^[A-Za-z0-9_.-]{1,64}$/;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const intIn = (value, [lo, hi]) => Number.isInteger(value) && value >= lo && value <= hi;
const originPath = path => typeof path === 'string' && path.startsWith('/') && !path.startsWith('//') && path.length <= 200 && !/[?#\s\\]/.test(path);

// The Ed25519 public key a profile declares, or null when it is not exactly one (SPKI DER, base64).
export function providerFeedKey(text) {
  if (typeof text !== 'string' || text.length > 200 || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) return null;
  const der = Buffer.from(text, 'base64');
  if (der.toString('base64') !== text) return null;
  try {
    const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch { return null; }
}

// Throws with a profile-facing message; returns the normalized configuration.
export function validateProviderFeedConfig(o, actors) {
  if (!object(o) || Object.keys(o).some(key => !KEYS.includes(key))) throw new Error(`a provider-feed observer is { ${KEYS.join(', ')} } (feedId, feed, publicKey and domains required); it takes no credential`);
  if (typeof o.feedId !== 'string' || !FEED_ID.test(o.feedId)) throw new Error('"feedId" is the feed name every signed entry carries: 1 to 64 letters, digits, ".", "_" or "-"');
  if (!object(o.feed) || Object.keys(o.feed).length !== 1 || !['endpoint', 'file'].includes(Object.keys(o.feed)[0])) throw new Error('"feed" is { "endpoint": { port, path } } (a provider stub on 127.0.0.1) or { "file": { path } } (an export file of signed entries)');
  let feed;
  if (o.feed.endpoint !== undefined) {
    const e = o.feed.endpoint;
    if (!object(e) || Object.keys(e).some(key => !['port', 'path'].includes(key))) throw new Error('the feed "endpoint" is { port, path }: the host is always 127.0.0.1');
    if (!intIn(e.port, PROVIDER_FEED_BOUNDS.port)) throw new Error('the feed endpoint "port" must be an integer from 1024 to 65535 (the feed is read on 127.0.0.1 only)');
    if (!originPath(e.path) || e.path.endsWith('/')) throw new Error('the feed endpoint "path" must be an origin-form path without a query, a fragment or a trailing "/" (its signed head is <path>/head)');
    feed = { kind: 'endpoint', port: e.port, path: e.path };
  } else {
    const f = o.feed.file;
    if (!object(f) || Object.keys(f).some(key => key !== 'path')) throw new Error('the feed "file" is { path }');
    if (typeof f.path !== 'string' || !f.path.startsWith('/') || f.path.length > 1024 || /[\u0000-\u001f\u007f]/.test(f.path)) throw new Error('the feed file "path" must be an absolute path without control characters');
    feed = { kind: 'file', path: f.path };
  }
  if (!providerFeedKey(o.publicKey)) throw new Error('"publicKey" must be the provider stub\'s Ed25519 public key (SPKI DER, base64); a private key or any other key type is refused');
  if (o.keySource !== undefined && !FEED_KEY_SOURCES.includes(o.keySource)) throw new Error('"keySource" says where the public key came from: "provider" (the provider\'s own export), "adapter" (an operator-run adapter, with "adapterReads") or "stub" (a test stub)');
  if ((o.keySource === 'adapter') !== (o.adapterReads !== undefined)) throw new Error('"adapterReads" goes with "keySource": "adapter" and only with it: what the adapter reads, "provider-api" or "application-store"');
  if (o.adapterReads !== undefined && !FEED_ADAPTER_READS.includes(o.adapterReads)) throw new Error('"adapterReads" is "provider-api" (the provider\'s own record) or "application-store" (the application\'s own store, which the application can write)');
  if (!Array.isArray(o.domains) || !o.domains.length || o.domains.length > PROVIDER_FEED_BOUNDS.domains) throw new Error('"domains" lists 1 to 64 { domain, addresses? }');
  const domains = o.domains.map(d => {
    if (!object(d) || Object.keys(d).some(key => !['domain', 'addresses'].includes(key)) || !smtpDomain(d.domain)) throw new Error('each entry of "domains" is { domain, addresses? } with a lowercase domain name');
    if (d.addresses !== undefined && !(Array.isArray(d.addresses) && d.addresses.length <= PROVIDER_FEED_BOUNDS.addresses && d.addresses.every(a => typeof a === 'string' && ADDRESS.test(a) && a.endsWith(`@${d.domain}`) && mailboxOf(a)?.address === a) && new Set(d.addresses).size === d.addresses.length)) throw new Error('a domain\'s "addresses" lists up to 64 distinct lowercase addresses in that domain, each canonical (a plain dot-atom local part without % or !: src/mail-address.mjs)');
    return { domain: d.domain, addresses: [...(d.addresses ?? [])] };
  });
  if (new Set(domains.map(d => d.domain)).size !== domains.length) throw new Error('each domain is declared once');
  if ((o.routing === undefined) !== (o.witness === undefined)) throw new Error('"routing" and "witness" go together: absence is authoritative only on a declared route a witness proves');
  if (o.routing !== undefined && o.routing !== 'provider') throw new Error('"routing" must be "provider" (the app\'s mail goes through this feed\'s provider)');
  if (o.witness !== undefined && feed.kind === 'file') throw new Error('a file feed is presence-only in v1 (it has no signed head, and a file the app can write could lose a line not yet read): declare no "routing" or "witness"');
  let witness = null;
  if (o.witness !== undefined) {
    const w = o.witness;
    if (!object(w) || Object.keys(w).some(key => !WITNESS_KEYS.includes(key))) throw new Error('"witness" is { actorId, method: "GET", path, domain } and nothing else');
    if (w.method !== 'GET') throw new Error('the witness must be a GET to the app');
    // A string first: Object.hasOwn coerces its key (D-01's shape; src/audit-file-rules.mjs says why).
    if (!object(actors) || typeof w.actorId !== 'string' || !Object.hasOwn(actors, w.actorId)) throw new Error('the witness "actorId" must be a declared actor');
    if (typeof w.path !== 'string' || !w.path.startsWith('/') || w.path.startsWith('//') || w.path.length > 300 || /[#\s\\]/.test(w.path)) throw new Error('the witness "path" must be an origin-form path without a fragment');
    let decoded;
    try { decoded = decodeURIComponent(w.path); } catch { throw new Error('the witness "path" must be validly percent-encoded'); }
    if (/scopehaven_witness/i.test(decoded)) throw new Error('the witness "path" cannot carry its own witness parameter');
    if (!smtpDomain(w.domain) || domains.some(d => d.domain === w.domain)) throw new Error('the witness "domain" is a lowercase domain name that is not a destination (the witness is never an effect)');
    witness = { actorId: w.actorId, method: 'GET', path: w.path, domain: w.domain };
  }
  if (o.witnessWaitMs !== undefined && !intIn(o.witnessWaitMs, PROVIDER_FEED_BOUNDS.witnessWaitMs)) throw new Error('"witnessWaitMs" must be an integer from 0 to 30000');
  if (o.quietMs !== undefined && !intIn(o.quietMs, PROVIDER_FEED_BOUNDS.quietMs)) throw new Error('"quietMs" must be an integer from 100 to 10000');
  if (o.pollMs !== undefined && !intIn(o.pollMs, PROVIDER_FEED_BOUNDS.pollMs)) throw new Error('"pollMs" must be an integer from 25 to 1000');
  if (o.maxSkewMs !== undefined && !intIn(o.maxSkewMs, PROVIDER_FEED_BOUNDS.maxSkewMs)) throw new Error('"maxSkewMs" must be an integer from 0 to 2000');
  const quietMs = o.quietMs ?? 300, pollMs = o.pollMs ?? 100;
  if (quietMs < 2 * pollMs) throw new Error('"quietMs" must be at least twice "pollMs": the quiet period is measured between feed reads');
  let templates = null;
  if (o.templates !== undefined) {
    const t = o.templates, entries = object(t) && [Object.prototype, null].includes(Object.getPrototypeOf(t)) ? Object.entries(t) : null;
    if (!entries || entries.length < 1 || entries.length > PROVIDER_FEED_BOUNDS.templates) throw new Error('"templates" maps 1 to 64 labels to provider template ids: { "<label>": "<template id>" }');
    for (const [label, id] of entries) {
      if (!templateLabelValid(label)) throw new Error(`template label "${String(label).slice(0, 40)}" must be 1 to 31 characters of a-z, 0-9, "_", "." or "-", starting with a letter, and not shaped like a secret (only labels are stored in a run)`);
      if (typeof id !== 'string' || id.length > PROVIDER_FEED_BOUNDS.templateIdChars || !TEMPLATE_ID.test(id)) throw new Error(`the template id of "${label}" must be 1 to 200 printable ASCII characters without leading or trailing spaces`);
    }
    if (new Set(entries.map(([, id]) => foldId(id))).size !== entries.length) throw new Error('each template id is declared once, also with case and spaces ignored: a provider that matches ids loosely could render either for both labels');
    templates = Object.freeze(Object.fromEntries(entries));
  }
  let outcomes = null;
  if (o.outcomes !== undefined) {
    if (!object(o.outcomes) || Object.keys(o.outcomes).some(key => key !== 'waitMs')) throw new Error('"outcomes" is { waitMs? }: the feed reads the provider\'s later outcome of each send it accepted');
    if (o.outcomes.waitMs !== undefined && !intIn(o.outcomes.waitMs, PROVIDER_FEED_BOUNDS.waitMs)) throw new Error('"outcomes.waitMs" must be an integer from 0 to 30000');
    if (feed.kind !== 'endpoint' || witness === null) throw new Error('"outcomes" needs an endpoint feed with a witness: only its signed head shows every later outcome up to the final mark was read');
    outcomes = Object.freeze({ waitMs: o.outcomes.waitMs ?? 0 });
  }
  return { feedId: o.feedId, feed, publicKey: o.publicKey, keyDigest: providerFeedKeyDigest(o.publicKey), domains, witness, witnessWaitMs: o.witnessWaitMs ?? 3000, quietMs, pollMs, maxSkewMs: o.maxSkewMs ?? 0, templates, outcomes,
    keySource: o.keySource ?? 'undeclared', adapterReads: o.adapterReads ?? null };
}
// The sha256 of the public key's DER bytes: what a run record and every sealed window name the key by.
export const providerFeedKeyDigest = text => createHash('sha256').update(Buffer.from(text, 'base64')).digest('hex');
// The feed identity a run record and each sealed window carry: { feedId, keyDigest, route, keySource }, adapterReads for an adapter,
// templates (the sorted labels, never the provider ids) when the feed declares a template vocabulary, and outcomes ({ waitMs }) when it
// reads later outcomes. keySource is "undeclared" when the profile names none (provider-feed/7; earlier builds wrote no keySource).
export const providerFeedRecord = o => ({ feedId: o.feedId, keyDigest: providerFeedKeyDigest(o.publicKey), route: o.feed?.endpoint ? 'endpoint' : 'file',
  ...(object(o.templates) ? { templates: Object.keys(o.templates).sort() } : {}), ...(object(o.outcomes) ? { outcomes: { waitMs: o.outcomes.waitMs ?? 0 } } : {}),
  keySource: FEED_KEY_SOURCES.includes(o.keySource) ? o.keySource : 'undeclared', ...(o.keySource === 'adapter' ? { adapterReads: o.adapterReads } : {}) });
// Later outcomes. The words an outcome entry may carry (the stub or adapter maps the provider's own event types onto them; the observer
// never maps a provider type): succeeded (the provider completed it: delivered to the recipient's server, a payment or refund done),
// deferred (still trying), failed (it did not happen: a permanent bounce, a drop, a reject after accept), reversed (done, then undone),
// contested (left open: a dispute, a partial reversal, a type the adapter cannot map) and complained (the recipient reported spam).
export const LATER_OUTCOMES = Object.freeze(['succeeded', 'deferred', 'failed', 'reversed', 'contested', 'complained']);
// The words that end the later wait for a send.
export const LATER_TERMINAL = Object.freeze(['succeeded', 'failed', 'reversed']);
// A sealed record's word: one of LATER_OUTCOMES, or "ambiguous" (the observer could not bind the send's outcomes to it alone).
export const LATER_RECORD_WORDS = Object.freeze([...LATER_OUTCOMES, 'ambiguous']);
// records: per feed and run; perEvent: words per send.
export const LATER_LIMITS = Object.freeze({ records: 20000, perEvent: 16 });
// The provider feeds of a run's observer records whose later outcomes the run carries: a feed record that declares outcomes, under a
// collector label that reads them (labels: src/collector-identity.mjs OUTCOME_COLLECTOR_LABELS). In declaration order.
export const laterFeedsOf = (observers, labels) => (Array.isArray(observers) ? observers : []).filter(o => o?.type === 'provider-feed' && object(o.feed?.outcomes) && labels.includes(o.collector?.label));
// A settlement record's later list (one entry per later feed, in order): { instanceId, clear, waitedMs, records }, records
// [{ of, outcome }] by event seq (each send's words in feed order; an ambiguous send has exactly one record), at most
// LATER_LIMITS.records, waitedMs at most the feed's declared waitMs. Which sealed event each "of" names is checked by the caller.
const laterRecordsValid = records => {
  if (!Array.isArray(records) || records.length > LATER_LIMITS.records) return false;
  const counts = new Map(), ambiguous = new Set();
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (!object(r) || Object.keys(r).sort().join(',') !== 'of,outcome' || !Number.isSafeInteger(r.of) || r.of < 1 || !LATER_RECORD_WORDS.includes(r.outcome)) return false;
    if (i > 0 && records[i - 1].of > r.of) return false;
    counts.set(r.of, (counts.get(r.of) ?? 0) + 1);
    if (r.outcome === 'ambiguous') ambiguous.add(r.of);
  }
  return [...counts].every(([of, n]) => ambiguous.has(of) ? n === 1 : n <= LATER_LIMITS.perEvent);
};
export const validLater = (list, feeds) => Array.isArray(list) && Array.isArray(feeds) && list.length === feeds.length && list.length > 0 && list.every((e, k) => object(e)
  && Object.keys(e).sort().join(',') === 'clear,instanceId,records,waitedMs' && e.instanceId === `provider-feed-${feeds[k].id}` && typeof e.clear === 'boolean'
  && Number.isSafeInteger(e.waitedMs) && e.waitedMs >= 0 && e.waitedMs <= feeds[k].feed.outcomes.waitMs && laterRecordsValid(e.records));
const sortedLabels = list => Array.isArray(list) && list.length >= 1 && list.length <= PROVIDER_FEED_BOUNDS.templates && list.every(templateLabelValid) && list.every((l, i) => i === 0 || list[i - 1] < l);
const validOutcomesRecord = o => o !== null && typeof o === 'object' && !Array.isArray(o) && Object.keys(o).join(',') === 'waitMs' && intIn(o.waitMs, PROVIDER_FEED_BOUNDS.waitMs);
// keySource (provider-feed/7, FIX-06): one of FEED_KEY_RECORD_SOURCES, with adapterReads exactly for an adapter; a record an earlier
// build wrote carries neither (which labels must carry it is the run validator's: src/collector-identity.mjs KEY_SOURCE_LABELS).
const RECORD_KEYS = Object.freeze(['adapterReads', 'feedId', 'keyDigest', 'keySource', 'outcomes', 'route', 'templates']);
const validKeySource = r => !Object.hasOwn(r, 'keySource') ? !Object.hasOwn(r, 'adapterReads')
  : FEED_KEY_RECORD_SOURCES.includes(r.keySource) && (r.keySource === 'adapter') === Object.hasOwn(r, 'adapterReads') && (!Object.hasOwn(r, 'adapterReads') || FEED_ADAPTER_READS.includes(r.adapterReads));
export const validProviderFeedRecord = r => r !== null && typeof r === 'object' && !Array.isArray(r) && Object.keys(r).every(k => RECORD_KEYS.includes(k)) && ['feedId', 'keyDigest', 'route'].every(k => Object.hasOwn(r, k)) && validKeySource(r)
  && (!Object.hasOwn(r, 'outcomes') || (validOutcomesRecord(r.outcomes) && r.route === 'endpoint'))
  && typeof r.feedId === 'string' && FEED_ID.test(r.feedId) && typeof r.keyDigest === 'string' && /^[a-f0-9]{64}$/.test(r.keyDigest) && ['endpoint', 'file'].includes(r.route)
  && (!Object.hasOwn(r, 'templates') || sortedLabels(r.templates));
// The capture a feed with a template vocabulary publishes (its scope, and the run record's observer entry): { [domain]: ["/template"] }
// for every declared domain, in profile order; null without a vocabulary.
export const providerFeedCapture = o => object(o?.templates) && Array.isArray(o.domains) ? Object.fromEntries(o.domains.map(d => [d.domain, [TEMPLATE_POINTER]])) : null;
// A run record's provider-feed capture: exactly /template for each name, present exactly when its feed lists templates.
export const validProviderFeedCapture = (capture, feed) => (capture === undefined) === !Object.hasOwn(feed ?? {}, 'templates')
  && (capture === undefined || (object(capture) && Object.keys(capture).length >= 1 && Object.values(capture).every(list => Array.isArray(list) && list.length === 1 && list[0] === TEMPLATE_POINTER)));

const LOOPBACK_ORIGIN = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/?$/;
const UPSTREAM = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/;
// A feed endpoint served on the port of the target origin, another declared observer or a forward upstream would be
// answered by the app or a ScopeHaven sink, not by the provider. A feed file that is also an audit-file observer's log
// is the app's own record. Returns a message, or null.
export function providerFeedClash(target) {
  const observers = Array.isArray(target?.observers) ? target.observers : [];
  const taken = new Map(observers.filter(o => Number.isInteger(o?.port)).map(o => [o.port, `observer "${o.id}"`]));
  const origin = typeof target?.origin === 'string' ? LOOPBACK_ORIGIN.exec(target.origin) : null;
  if (origin) taken.set(Number(origin[1]), 'the target origin');
  for (const o of observers) if (o?.type === 'egress-recorder' && Array.isArray(o.destinations)) for (const d of o.destinations) {
    const m = typeof d?.forward?.upstream === 'string' ? UPSTREAM.exec(d.forward.upstream) : null;
    if (m) taken.set(Number(m[1]), `the forward upstream of "${d.host}"`);
  }
  const logs = new Set(observers.filter(o => o?.type === 'audit-file' && typeof o.path === 'string').map(o => o.path));
  for (const o of observers) {
    if (o?.type !== 'provider-feed' || !object(o.feed)) continue;
    const port = o.feed.endpoint?.port;
    if (Number.isInteger(port)) {
      if (taken.has(port)) return `the feed endpoint of provider-feed observer "${o.id}" uses the port of ${taken.get(port)}: the feed must be served by the provider stub, not the app or a ScopeHaven observer`;
      taken.set(port, `provider-feed observer "${o.id}"`);
    }
    if (typeof o.feed.file?.path === 'string' && logs.has(o.feed.file.path)) return `the feed file of provider-feed observer "${o.id}" is an audit-file observer's log: the feed must be the provider's record, not the app's`;
  }
  return null;
}

// A "/template" pin (src/body-fields.mjs TEMPLATE_POINTER) on a selector a provider feed sees (source provider-feed or none, and an
// exact name the feed declares) is read only against that feed's labels: a string the feed does not declare as a label (a typo, a
// provider id) reads "no" on every send and would let an absence pass vacuously, and a feed without a vocabulary reads every
// template unknown. Both are refused when the profile loads. Selectors are found in each check's effects and claims (any object
// with a "fields" list and a string "name"). Returns a message, or null.
export function providerFeedTemplatePins(target) {
  const feeds = (Array.isArray(target?.observers) ? target.observers : []).filter(o => o?.type === 'provider-feed' && Array.isArray(o.domains));
  if (!feeds.length) return null;
  const selectors = [];
  const walk = (value, depth) => {
    if (depth > 8 || value === null || typeof value !== 'object') return;
    if (Array.isArray(value)) { for (const v of value) walk(v, depth + 1); return; }
    if (Array.isArray(value.fields) && typeof value.name === 'string') selectors.push(value);
    for (const v of Object.values(value)) walk(v, depth + 1);
  };
  for (const check of Array.isArray(target?.checks) ? target.checks : []) if (object(check)) { walk(check.effects, 0); walk(check.claims, 0); }
  for (const select of selectors) {
    const pins = select.fields.filter(f => object(f) && f.pointer === TEMPLATE_POINTER);
    if (!pins.length || !(select.source === undefined || select.source === 'provider-feed')) continue;
    for (const o of feeds) {
      if (!o.domains.some(d => d?.domain === select.name)) continue;
      const labels = object(o.templates) ? Object.keys(o.templates) : null;
      if (!labels) return `a selector pins "${TEMPLATE_POINTER}" on "${select.name}", which provider-feed observer "${o.id}" reads, but that feed declares no "templates": declare its template vocabulary first`;
      for (const f of pins) {
        const operands = Object.hasOwn(f, 'in') && Array.isArray(f.in) ? f.in : Object.hasOwn(f, 'equals') ? [f.equals] : [];
        // A template is always a label: a member of another type would hold every send's template unknown (src/body-fields.mjs
        // crossState), so the pin could never decide.
        const other = operands.find(x => typeof x !== 'string');
        if (other !== undefined) return `a selector pins "${TEMPLATE_POINTER}" on "${select.name}" to ${JSON.stringify(other)}, which is not a label: pin only labels provider-feed observer "${o.id}" declares`;
        const stray = operands.find(x => typeof x === 'string' && !labels.includes(x));
        if (stray !== undefined) return `a selector pins "${TEMPLATE_POINTER}" on "${select.name}" to "${stray.slice(0, 40)}", which is not a label provider-feed observer "${o.id}" declares: pin the label, never a provider id (a template the feed does not name reads "no" on every send, so an absence would pass on it)`;
      }
    }
  }
  return null;
}
