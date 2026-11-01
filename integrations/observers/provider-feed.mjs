// Provider-feed observer (G2): reads an email provider's own record of the messages it accepted, never the
// application's record (configuration: src/provider-feed-rules.mjs). The record is a feed of entries in the
// scopehaven-provider-feed/1 contract that a provider stub, or an operator-run adapter, signs with Ed25519; ScopeHaven
// holds only the public key. Real provider APIs are not read directly.
//
// An entry is { body, sig }: sig is the Ed25519 signature of "scopehaven-provider-feed/1\n" + body, and body is the JSON
// text { feed, epoch, seq, id, type, at, messageId?, recipients?, template? }. Types are an allowlist:
//   epoch-start - seq 1 only, the genesis; the feed must begin with it
//   accepted    - the provider accepted a message: each recipient is one committed "send" effect named by its domain
//   rejected    - the provider refused a send: each recipient is one denied "send" effect
//   status      - a delivery update of an earlier accepted message: no effect (on a feed that reads later outcomes it is refused:
//                 an unread failure word must never pass silently)
//   outcome     - only on a feed that declares "outcomes": the provider's later word (LATER_OUTCOMES) on a message it accepted,
//                 bound to that send by the provider's own message id (below); no effect, no ledger record
// Anything else, a status of an unknown message, a repeated event id or message id, or a recipient that is repeated,
// cannot be parsed or carries a source route or an address literal, leaves the window partial. Other body fields
// (subject, stream, tags, metadata: the app writes those) are never read; only a digest of the whole body is kept.
// Template (feed v2): "template" is the provider's canonical id of the stored template it accepted the message with, signed
// like every contract field. It is read only on a feed that declares a template vocabulary (src/provider-feed-rules.mjs): each
// event to a declared domain then carries the captured field /template, the label of the declared id the entry names exactly,
// or absent (no template) or unusable "undeclared" (anything else), both of which read unknown (src/body-fields.mjs).
//
// Custody. At start() the observer reads the whole feed from its genesis, verifies every entry, pins the epoch, and from
// then on reads only seq lastSeq + 1 of that epoch, so no entry can be skipped, replaced or re-based by a stub reset:
//   - a bad signature, a malformed entry, another feed or epoch, a rewritten earlier seq, a time going backward, a
//     second genesis, an invalid signed head, a replaced or truncated file: an integrity fault, every later window fails
//   - a missing seq (a gap): nothing past it is read, and every window collected while it lasts is partial
// Once read, an entry is the observer's own copy: a later delete or edit at the provider changes nothing.
//
// The signed head (route i): GET <path>/head?nonce=<fresh nonce> answers { body, sig }, body { feed, epoch, lastSeq,
// nonce } signed over "scopehaven-provider-feed/1 head\n" + body. Every mark reads it and then the entries up to its
// lastSeq; a mark that could not is "behind", and every window it starts or ends is partial. The start mark's head fixes
// which entries were in the feed before the window. A look-alike server cannot sign a head for a fresh nonce.
// Route (ii), the export file, has no head and is presence-only in v1.
//
// Windows are the shared sink ledger's (sink-ledger.mjs): each verified entry is one record in feed order. A background
// poller reads the feed every pollMs between marks. The witness-request split uses no clock: called with
// { headSplit: true } (the HTTP connector awaits it before it sends the witness request), markWitnessRequest reads the
// signed head, and entries up to its lastSeq are before the request, later ones after it. Without the option the split
// falls at the last entry already read, which can only leave a window partial. The provider's time only tightens: an
// entry stamped outside a check window is kept with outcome "unknown" and leaves the window partial.
// Later outcomes (PROVIDER-LATER-OUTCOME design with ADDENDUM-R1; collector provider-feed/5). An outcome entry is
// { feed, epoch, seq, id, type: "outcome", at, messageId, recipients?, outcome, app? } and nothing else. It binds only to an accepted entry
// read after start (an in-run send), by its messageId, and to each named recipient by canonical address (src/mail-address.mjs); with no
// recipients it is for every recipient of that message. Each binding is a record { of: <the send's event seq>, outcome: <word> }: the
// observer's own seq, never a provider id. A message id seen more than once in the epoch (start read, accepted and rejected entries
// alike, before or after the send), or a named recipient that maps to no event or to two, makes every event of that message
// "ambiguous". An outcome for a message accepted before the run or for the witness message binds nothing. A refused outcome entry
// (an unknown word, a key outside the list, an orphan, a recipient that cannot be bound, a repeated event id, a cap) leaves the window
// partial and clears the feed's later horizon for the rest of the run ("clear" is false); so does a status entry, and a fault.
// laterWait({ capMs }) reads on for capMs after the final mark and the collect of every run-end window; laterRecords(laterMark) returns
// { clear, records } up to the signed head of a mark taken after it, clear only when that mark read up to its head with no gap and no
// fault. The records are sealed in the run's settlement record and decide nothing in this build.
// Late entries (feed v2, Part B): on a witnessed endpoint feed the connector collects check windows scoped. An entry after the
// witness request split then becomes a destination-scoped entry for its recipient domain and resource (src/effect-events.mjs)
// instead of making the whole window partial, unless anything else could hide a send (see collect). The follow rule and the
// run-end drain (drain, markClear) decide whether such an entry counts; the signed head, not a clock, says which entries are late
// and that nothing accepted is unread.
import { request, Agent } from 'node:http';
import { openSync, fstatSync, readSync, closeSync, constants as FS } from 'node:fs';
import { createHash, verify, randomUUID } from 'node:crypto';
import { makeEffect, FEED_LATE_CODE } from './events.mjs';
import { createSinkLedger } from './sink-ledger.mjs';
import { validateProviderFeedConfig, providerFeedKey, providerFeedRecord, providerFeedCapture, PROVIDER_FEED_SCHEMA, PROVIDER_FEED_REQUEST_MS, LATER_OUTCOMES, LATER_LIMITS } from '../../src/provider-feed-rules.mjs';
import { TEMPLATE_POINTER } from '../../src/body-fields.mjs';
// Recipients: the shared mail address rules (envelope normalization, dot-atom local parts, subaddress ambiguity).
import { recipientOf, addressResource } from '../../src/mail-address.mjs';

// A page asks for pageEntries and halves down to one entry when the answer is over responseBytes; bodyBytes bounds one
// entry's body (the stub must keep app-written values short enough). recipients: at most this many per entry become events.
export const PROVIDER_FEED_LIMITS = Object.freeze({ pageEntries: 500, responseBytes: 4 * 1024 * 1024, bodyBytes: 64 * 1024, startEntries: 20000, catchUpPages: 100,
  fileBytes: 64 * 1024 * 1024, readBytes: 1024 * 1024, fingerprintBytes: 4096, recipients: 100, requestTimeoutMs: PROVIDER_FEED_REQUEST_MS, eventsPerWindow: 5000, retained: 20000 });
// The body fields the contract defines; app-written values belong under "app". Any other top-level field leaves the window partial.
const BODY_KEYS = Object.freeze(['feed', 'epoch', 'seq', 'id', 'type', 'at', 'messageId', 'recipients', 'status', 'template', 'app']);
// An outcome entry's keys (later outcomes): its own list, so "outcome" is never a key another type may carry.
const OUTCOME_KEYS = Object.freeze(['feed', 'epoch', 'seq', 'id', 'type', 'at', 'messageId', 'recipients', 'outcome', 'app']);
const ENTRY_PREFIX = `${PROVIDER_FEED_SCHEMA}\n`, HEAD_PREFIX = `${PROVIDER_FEED_SCHEMA} head\n`;
const NONCE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const sha = value => createHash('sha256').update(value).digest('hex');
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const bounded = (value, max) => typeof value === 'string' && value.length >= 1 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
const utf8 = new TextDecoder('utf-8', { fatal: true });
// How often the top level of a JSON object text names a key (each string token at depth 1 followed by a colon, decoded): JSON.parse
// keeps the last of a repeated key, and another reader (the stub's own) may keep the first.
const KEY_COLON = /\s*:/y;
function topLevelKeys(text, name) {
  let depth = 0, n = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '{' || c === '[') depth++;
    else if (c === '}' || c === ']') depth--;
    else if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      KEY_COLON.lastIndex = j + 1;
      if (depth === 1 && KEY_COLON.test(text)) { try { if (JSON.parse(text.slice(i, j + 1)) === name) n++; } catch { n++; } }
      i = j;
    }
  }
  return n;
}

class FeedFault extends Error { constructor(code) { super(code); this.code = code; } }
const fault = code => { throw new FeedFault(code); };

export function createProviderFeedObserver({ instanceId = 'provider-feed-1', ...config }) {
  const cfg = validateProviderFeedConfig({ ...config, type: 'provider-feed' }, config.witness ? { [config.witness.actorId]: {} } : undefined);
  const key = providerFeedKey(cfg.publicKey), endpoint = cfg.feed.kind === 'endpoint';
  const observer = { kind: 'provider-feed-reader', instanceId };
  const declared = new Map(cfg.domains.map(d => [d.domain, new Set(d.addresses)]));
  const ledger = createSinkLedger({ prefix: 'provider-feed', unit: 'entry', retained: PROVIDER_FEED_LIMITS.retained });
  // The template vocabulary, by provider id (null when none is declared), and the capture it publishes.
  const templateLabels = cfg.templates ? new Map(Object.entries(cfg.templates).map(([label, id]) => [id, label])) : null;
  const capture = providerFeedCapture(cfg);
  // An entry's template as a captured value: only a string exactly equal to a declared id, named once in the signed body, is named
  // by its label; a repeated "template" key (readers disagree on which one counts) reads undeclared.
  const templateOf = (b, text) => !Object.hasOwn(b, 'template') ? { type: 'absent' } : topLevelKeys(text, 'template') !== 1 ? { type: 'unusable', reason: 'undeclared' }
    : typeof b.template === 'string' && templateLabels.has(b.template) ? { type: 'string', value: templateLabels.get(b.template) } : { type: 'unusable', reason: 'undeclared' };

  // Feed state: the pinned epoch, the last seq read and its time, a digest of each read entry (to tell a byte-identical
  // re-read from a rewrite), event ids and message ids seen. stuck: a gap stops reading.
  let epoch = null, lastSeq = 0, lastAtMs = -Infinity, faulted = null, gapNotedAt = null, stuck = false, started = false, running = false, timer = null;
  // Feed v2, Part B: the marks that read up to a signed head with no gap or fault, the seq gaps noted so far, and how many had been
  // noted when the first scoped collect left a late entry (null before that).
  const clearAtMark = new WeakMap();
  let gapsNoted = 0, lateSince = null;
  const lostAfterCollect = () => lateSince !== null && (faulted !== null || gapsNoted > lateSince);
  const seen = new Map(), ids = new Set(), messages = new Set(), accepted = new Set();
  // Later outcomes: in-run accepted messages by id (inRun: [{ ledgerSeq, byAddress: address -> [event index], indices }], more than one only
  // when the id repeats), the feed seq at which each message id was first seen again, the events made ambiguous (event seq -> feed
  // seq), every bound record in feed order ({ of, outcome, feedSeq }), records per event, the feed seq at which the later horizon
  // was first cleared.
  const inRun = new Map(), repeatedAt = new Map(), ambiguousAt = new Map(), laterLog = [], perEvent = new Map();
  let boundEvents = 0, unclearAt = null;
  const unclear = seq => { unclearAt ??= seq; };
  const eventsOf = entries => entries.flatMap(e => e.indices.map(i => e.ledgerSeq * 128 + i));
  const markAmbiguous = (entries, seq) => { for (const of of eventsOf(entries)) if (!ambiguousAt.has(of)) ambiguousAt.set(of, seq); };
  // The pending witness-request split ({ from, seq }) until an entry past seq is read or the window is collected; and the
  // start-mark nonces whose split could not be read to the head (those windows are partial).
  let split = null;
  const splitShort = new Set();
  const applySplit = () => { if (split) { ledger.markWitnessRequest(split.from); split = null; } };

  // One feed read at a time: the poller, every mark and every head read share this queue.
  let queue = Promise.resolve();
  const serial = fn => { const next = queue.then(fn, fn); queue = next.catch(() => {}); return next; };
  // Run a read; an integrity fault stops reading for good and takes the ledger down (every later window fails).
  const guarded = async (fn, fallback) => {
    if (faulted) return fallback;
    try { return await fn(); }
    catch (error) { if (!(error instanceof FeedFault)) throw error; faulted = error.code; ledger.down(); return fallback; }
  };

  // Verify one signed object ({ body, sig } under a prefix) and return its parsed body; any failure is a fault.
  function signedBody(raw, prefix, code) {
    if (!plain(raw) || Object.keys(raw).sort().join(',') !== 'body,sig' || typeof raw.body !== 'string' || typeof raw.sig !== 'string') fault(`${code}-shape`);
    if (Buffer.byteLength(raw.body) > PROVIDER_FEED_LIMITS.bodyBytes) fault(`${code}-too-large`);
    const sig = Buffer.from(raw.sig, 'base64');
    if (sig.length !== 64 || sig.toString('base64') !== raw.sig || !verify(null, Buffer.from(prefix + raw.body), key, sig)) fault(`${code}-signature`);
    try { const b = JSON.parse(raw.body); if (plain(b)) return b; } catch {}
    return fault(`${code}-body`);
  }
  function verified(raw) {
    const b = signedBody(raw, ENTRY_PREFIX, 'entry');
    if (b.feed !== cfg.feedId || !bounded(b.epoch, 64) || !Number.isSafeInteger(b.seq) || b.seq < 1 || !bounded(b.id, 200) || !bounded(b.type, 64)
      || typeof b.at !== 'string' || !ISO.test(b.at) || !Number.isFinite(Date.parse(b.at))) fault('entry-body');
    // What the app chose (how many recipients, how long, how written) only makes the window partial (ingest).
    if (['accepted', 'rejected'].includes(b.type) && (!bounded(b.messageId, 200) || !Array.isArray(b.recipients))) fault('entry-body');
    return b;
  }
  // Read one entry in feed order. initial: the start() read of the history before any mark (no ledger record).
  // Returns 'read', 'skip' (a byte-identical re-read) or 'gap' (a later seq: nothing past it is read).
  function ingest(raw, initial, offset = null) {
    const b = verified(raw), entryDigest = sha(`${raw.body}\n${raw.sig}`), atMs = Date.parse(b.at);
    if (epoch === null) { if (b.seq !== 1 || b.type !== 'epoch-start') fault('genesis-missing'); epoch = b.epoch; }
    else if (b.epoch !== epoch) fault('epoch-changed');
    if (b.seq <= lastSeq) { if (seen.get(b.seq) !== entryDigest) fault('entry-rewritten'); return 'skip'; }
    if (b.seq !== lastSeq + 1) return 'gap';
    if (b.type === 'epoch-start' && b.seq !== 1) fault('genesis-repeated');
    if (atMs < lastAtMs) fault('time-backward');
    lastSeq = b.seq; lastAtMs = atMs; gapNotedAt = null; stuck = false;
    seen.set(b.seq, entryDigest);
    if (seen.size > PROVIDER_FEED_LIMITS.retained) seen.delete(seen.keys().next().value);
    // The witness request was sent after the provider's head at split.seq: every later entry is after it.
    if (!initial && split && b.seq > split.seq) applySplit();
    const problem = kind => { if (!initial) ledger.record({ kind }); };
    if (b.type === 'outcome' && cfg.outcomes) return outcomeEntry(b, initial, problem);
    if (Object.keys(b).some(k => !BODY_KEYS.includes(k))) problem('field-unknown');
    if (b.type === 'epoch-start') return 'read';
    // On a feed that reads later outcomes a status entry is refused: its word is not one the contract defines.
    if (b.type === 'status') { if (cfg.outcomes) { problem('status-unmodelled'); if (!initial) unclear(b.seq); } else if (!accepted.has(b.messageId)) problem('status-orphan'); return 'read'; }
    if (!['accepted', 'rejected'].includes(b.type)) { problem('type-unknown'); return 'read'; }
    // Ids can come from the app's input, so a repeated event id or message id is never skipped as a redelivery.
    if (ids.has(b.id)) problem('duplicate-id');
    if (messages.has(b.messageId)) problem('duplicate-message');
    // Later outcomes: a message id seen again (start read, accepted and rejected alike) makes every in-run send under it ambiguous.
    if (messages.has(b.messageId) && !repeatedAt.has(b.messageId)) repeatedAt.set(b.messageId, b.seq);
    ids.add(b.id); messages.add(b.messageId);
    if (b.type === 'accepted') accepted.add(b.messageId);
    if (initial) return 'read';
    const recipients = [], nonces = [], addresses = new Set(), byAddress = new Map();
    let unusable = false, literal = false, repeated = false, ambiguous = false;
    if (!b.recipients.length) problem('recipients-empty');
    if (b.recipients.length > PROVIDER_FEED_LIMITS.recipients) problem('too-many-recipients');
    for (const text of b.recipients.slice(0, PROVIDER_FEED_LIMITS.recipients)) {
      // The shared recipient rules (as the SMTP sink): a recipient whose domain cannot be read is no event; one without a
      // canonical mailbox (another written form, a relay route, an odd host), or with a source route, stays a send to its
      // domain named "*"; either leaves the window partial.
      const rcpt = bounded(text, 320) ? recipientOf(text) : null;
      // A domain longer than an event name can hold (128) is unusable: shortened, it could read as another (declared) domain.
      if (!rcpt || rcpt.domain.length > 128) { unusable = true; continue; }
      const r = rcpt.mailbox, address = r ? r.address : text.toLowerCase();
      if (!r || rcpt.sourceRoute) unusable = true;
      if (rcpt.literal) literal = true;
      if (addresses.has(address)) repeated = true;
      addresses.add(address);
      // An alias form of a declared address (a subaddress, a dotted form) may be the same mailbox at the provider.
      const named = r ? addressResource(r, declared.get(rcpt.domain)) : { resource: '*', ambiguous: false };
      if (named.ambiguous) ambiguous = true;
      if (b.type === 'accepted' && cfg.witness && rcpt.domain === cfg.witness.domain) { nonces.push(r && NONCE.test(r.local) ? r.local : 'not-a-nonce'); continue; }
      byAddress.set(address, [...(byAddress.get(address) ?? []), recipients.length]);
      recipients.push({ domain: rcpt.domain, resource: named.resource, to: sha(address) });
    }
    // A witness message goes to the witness address only; one that also goes elsewhere is never a witness.
    const item = ledger.record({ kind: 'item', done: true, witnessNonces: nonces.length && !recipients.length && !unusable ? nonces : [], mixedWitness: nonces.length > 0 && (recipients.length > 0 || unusable),
      literal, unusable, repeated, ambiguous, recipients, feedSeq: b.seq, offset, atMs, outcome: b.type === 'accepted' ? 'committed' : 'denied', content: sha(raw.body),
      template: templateLabels ? templateOf(b, raw.body) : null });
    // Later outcomes: an in-run accepted message with events can be bound to; its events are seq x 128 + index, as collect names them.
    if (cfg.outcomes && b.type === 'accepted' && recipients.length) {
      if (boundEvents + recipients.length > LATER_LIMITS.records) unclear(b.seq);
      else {
        boundEvents += recipients.length;
        const entry = { ledgerSeq: item.seq, byAddress, indices: recipients.map((_, i) => i) };
        inRun.set(b.messageId, [...(inRun.get(b.messageId) ?? []), entry]);
      }
    }
    return 'read';
  }
  // Later outcomes: one outcome entry, read in feed order on a feed that declares outcomes. initial: the start read (no run send to bind).
  function outcomeEntry(b, initial, problem) {
    // A repeated event id is never skipped as a redelivery; the outcome's own id joins the others. Its message id never joins "messages".
    const repeatedId = ids.has(b.id);
    ids.add(b.id);
    if (initial) return 'read';
    const entries = typeof b.messageId === 'string' ? inRun.get(b.messageId) ?? null : null;
    // A refused entry leaves the window partial and clears the later horizon; when it names an in-run message, that message's events
    // are ambiguous too.
    const refuse = code => { problem(code); unclear(b.seq); if (entries) markAmbiguous(entries, b.seq); return 'read'; };
    if (Object.keys(b).some(k => !OUTCOME_KEYS.includes(k))) return refuse('outcome-field');
    if (!LATER_OUTCOMES.includes(b.outcome)) return refuse('outcome-word');
    if (repeatedId) return refuse('duplicate-id');
    // An orphan: no message the provider accepted under that id was read before this entry (a rejected one is not accepted).
    if (!bounded(b.messageId, 200) || !accepted.has(b.messageId)) return refuse('outcome-orphan');
    // A message accepted before the run, the witness message, or one with no event: nothing in the run to bind.
    if (!entries) return 'read';
    // A message id accepted twice: no outcome can name one send.
    if (entries.length !== 1) { markAmbiguous(entries, b.seq); return 'read'; }
    const [entry] = entries;
    let targets;
    if (b.recipients === undefined) targets = entry.indices;
    else {
      if (!Array.isArray(b.recipients) || !b.recipients.length || b.recipients.length > PROVIDER_FEED_LIMITS.recipients) return refuse('outcome-recipient');
      targets = [];
      for (const text of b.recipients) {
        const rcpt = bounded(text, 320) ? recipientOf(text) : null;
        const r = rcpt && !rcpt.sourceRoute && !rcpt.literal ? rcpt.mailbox : null;
        const list = r ? entry.byAddress.get(r.address) : undefined;
        // Exactly one event of this message: a name that maps to none, or to two (an address listed twice), binds nothing.
        if (!list || list.length !== 1) return refuse('outcome-recipient');
        targets.push(list[0]);
      }
      if (new Set(targets).size !== targets.length) return refuse('outcome-recipient');
    }
    for (const i of targets) {
      const of = entry.ledgerSeq * 128 + i, n = perEvent.get(of) ?? 0;
      if (n >= LATER_LIMITS.perEvent || laterLog.length >= LATER_LIMITS.records) { unclear(b.seq); continue; }
      perEvent.set(of, n + 1);
      laterLog.push({ of, outcome: b.outcome, feedSeq: b.seq });
    }
    return 'read';
  }
  // Read a batch of raw entries; stops at a gap (noted once per stuck position).
  function ingestAll(list, initial, offset = null) {
    for (const raw of list) {
      if (ingest(raw, initial, offset) === 'gap') { if (initial) fault('start-gap'); stuck = true; if (gapNotedAt !== lastSeq) { gapNotedAt = lastSeq; gapsNoted++; ledger.record({ kind: 'seq-gap' }); } return false; }
    }
    return true;
  }

  // Route (i): the stub's feed endpoint on loopback, through one keep-alive socket.
  const agent = endpoint ? new Agent({ keepAlive: true, maxSockets: 1 }) : null;
  // One bounded GET: the parsed JSON, TOO_LARGE when the answer is over responseBytes, or null. The whole exchange has
  // one deadline, so a server that trickles bytes cannot hold the read queue.
  const TOO_LARGE = Symbol('too-large');
  function get(path) {
    return new Promise(resolve => {
      let deadline = null;
      const done = value => { clearTimeout(deadline); resolve(value); };
      const req = request({ host: '127.0.0.1', port: cfg.feed.port, method: 'GET', path, agent, headers: { host: `127.0.0.1:${cfg.feed.port}`, accept: 'application/json' }, timeout: PROVIDER_FEED_LIMITS.requestTimeoutMs }, res => {
        if (res.statusCode !== 200) { res.resume(); done(null); return; }
        const chunks = []; let size = 0;
        res.on('data', chunk => { size += chunk.length; if (size > PROVIDER_FEED_LIMITS.responseBytes) { req.destroy(); done(TOO_LARGE); } else chunks.push(chunk); });
        res.on('end', () => { try { done(JSON.parse(utf8.decode(Buffer.concat(chunks)))); } catch { done(null); } });
        res.on('error', () => done(null));
      });
      deadline = setTimeout(() => req.destroy(), PROVIDER_FEED_LIMITS.requestTimeoutMs);
      req.on('timeout', () => req.destroy());
      req.on('error', () => done(null));
      req.end();
    });
  }
  // The signed head for a fresh nonce: { lastSeq }, or null when it could not be fetched. Anything fetched that is not
  // this feed's head for this nonce, in the pinned epoch, at or past what was read, is a fault.
  async function head() {
    const nonce = randomUUID(), raw = await get(`${cfg.feed.path}/head?nonce=${nonce}`);
    if (raw === null || raw === TOO_LARGE) return null;
    const b = signedBody(raw, HEAD_PREFIX, 'head');
    if (Object.keys(b).sort().join(',') !== 'epoch,feed,lastSeq,nonce' || b.feed !== cfg.feedId || b.nonce !== nonce || !bounded(b.epoch, 64)
      || !Number.isSafeInteger(b.lastSeq) || b.lastSeq < 1) fault('head-invalid');
    if (epoch !== null && (b.epoch !== epoch || b.lastSeq < lastSeq)) fault('head-invalid');
    return { lastSeq: b.lastSeq, epoch: b.epoch };
  }
  // Read the endpoint's pages to its end. Returns false when the feed could not be read (a transport failure).
  async function readEndpoint(initial) {
    let read = 0, limit = PROVIDER_FEED_LIMITS.pageEntries;
    for (let pages = 0; pages < (initial ? Math.ceil(PROVIDER_FEED_LIMITS.startEntries / PROVIDER_FEED_LIMITS.pageEntries) + 1 : PROVIDER_FEED_LIMITS.catchUpPages) + 9; pages++) {
      const res = await get(`${cfg.feed.path}?after=${lastSeq}&limit=${limit}`);
      // A page over the size cap is asked again smaller; one entry over it breaks the contract's body bound.
      if (res === TOO_LARGE) { if (limit === 1) fault('entry-too-large'); limit = Math.max(1, Math.floor(limit / 2)); continue; }
      if (!plain(res) || res.schema !== PROVIDER_FEED_SCHEMA || !Array.isArray(res.entries) || res.entries.length > limit || typeof res.more !== 'boolean') return false;
      read += res.entries.length;
      if (initial && read > PROVIDER_FEED_LIMITS.startEntries) fault('start-too-long');
      if (!ingestAll(res.entries, initial)) return true;
      if (!res.more || !res.entries.length) return true;
    }
    return false;
  }
  // The head, then the entries up to it: { headSeq, behind }, or null when the head could not be fetched.
  async function readToHead() {
    const h = await head();
    if (!h) return null;
    if (lastSeq < h.lastSeq) await readEndpoint(false);
    return { headSeq: h.lastSeq, behind: lastSeq < h.lastSeq };
  }

  // Route (ii): the export file, bound at start (device, inode, the digest of every complete line, the position) and
  // then read as appended complete lines, each checked against the 4 KiB before the bound position. Presence-only in v1.
  let bound = null;
  const readRange = (fd, start, end) => { const buf = Buffer.alloc(end - start); if (buf.length) readSync(fd, buf, 0, buf.length, start); return buf; };
  function readFile(initial) {
    let fd;
    try { fd = openSync(cfg.feed.path, FS.O_RDONLY | FS.O_NOFOLLOW | FS.O_NONBLOCK); } catch { if (initial) fault('file-unreadable'); return false; }
    try {
      const st = fstatSync(fd);
      if (!st.isFile()) fault('file-not-regular');
      if (!initial) {
        if (st.dev !== bound.dev || st.ino !== bound.ino || st.size < bound.pos) fault('file-replaced');
        if (sha(readRange(fd, bound.fpStart, bound.pos)) !== bound.fp) fault('file-rewritten');
      } else if (st.size > PROVIDER_FEED_LIMITS.fileBytes) fault('start-too-long');
      const from = initial ? 0 : bound.pos, to = initial ? st.size : Math.min(st.size, from + PROVIDER_FEED_LIMITS.readBytes);
      const bytes = readRange(fd, from, to), cut = bytes.lastIndexOf(0x0a);
      // A line that cannot end within one read is never an entry.
      if (cut < 0 && to - from >= PROVIDER_FEED_LIMITS.readBytes) fault('entry-too-large');
      let pos = from;
      if (cut >= 0) {
        let text;
        try { text = utf8.decode(bytes.subarray(0, cut)); } catch { fault('file-not-utf8'); }
        // Each entry keeps the byte offset its line starts at (the before-window rule of the file route).
        for (const line of text.split('\n')) {
          let raw;
          try { raw = JSON.parse(line); } catch { fault('entry-shape'); }
          if (!ingestAll([raw], initial, pos)) break;
          pos += Buffer.byteLength(line) + 1;
        }
      }
      const fpStart = Math.max(0, pos - PROVIDER_FEED_LIMITS.fingerprintBytes);
      bound = { dev: st.dev, ino: st.ino, pos, fpStart, fp: sha(readRange(fd, fpStart, pos)), size: st.size };
      // more: complete lines remain unread (past the read cap, or behind a gap).
      return { more: to < st.size || (cut >= 0 && pos < from + cut + 1) };
    } finally { closeSync(fd); }
  }

  // The file read to its end (or as far as a gap allows): { headSeq: null, behind, fileSize }, or null when unreadable.
  function readFileToEnd() {
    let r = null;
    for (let i = 0; i < 64; i++) {
      const pos = bound.pos;
      r = readFile(false);
      if (!r) return null;
      if (!r.more || bound.pos === pos) break;
    }
    return { headSeq: null, behind: r.more, fileSize: bound.size };
  }
  // One feed read on the shared queue, bounded by ms: CAP when the time ends first (a read still running finishes on the queue).
  const CAP = Symbol('cap');
  const boundedRead = (fn, ms) => {
    if (!(ms > 0)) return Promise.resolve(CAP);
    let timer;
    return Promise.race([serial(() => guarded(fn, null)), new Promise(resolve => { timer = setTimeout(() => resolve(CAP), ms); })]).finally(() => clearTimeout(timer));
  };
  const tick = async () => {
    if (!running) return;
    // A read that throws for any other reason is retried on the next tick; a mark that cannot read throws itself.
    try { await serial(() => guarded(() => endpoint ? readEndpoint(false) : readFile(false), true)); } catch {}
    if (running) timer = setTimeout(tick, cfg.pollMs);
  };

  return {
    kind: observer.kind, instanceId, source: 'provider-feed',
    // Feed v2, Part C (provider-feed/4): a window's only late entry, one signed send whose template is a declared label, may lift
    // effect.only through an allow it matches, template included (src/effect-events.mjs onlyCoverageFor).
    templateLift: true,
    // Later outcomes (provider-feed/5): this build reads outcome entries on a feed that declares them (laterRecords, laterWait).
    laterOutcomes: true,
    scope: Object.freeze({ operations: ['send'], names: cfg.domains.map(d => d.domain), actorAttribution: 'none', evidence: cfg.witness && endpoint ? 'authoritative' : 'presence-only',
      feed: Object.freeze(providerFeedRecord(config)), ...(capture ? { capture: Object.freeze(Object.fromEntries(Object.entries(capture).map(([name, list]) => [name, Object.freeze(list)]))) } : {}) }),
    ...(cfg.witness ? { witnessRequest: Object.freeze({ actorId: cfg.witness.actorId, method: 'GET', path: cfg.witness.path }) } : {}),
    // Called by the connector immediately before it sends this window's witness request. With { headSplit: true } the
    // caller awaits it, so the signed head read here precedes the request: entries up to its lastSeq are before it.
    // Without the option (a caller that does not wait) the split falls at the last entry already read.
    markWitnessRequest(from, { headSplit = false } = {}) {
      if (!from?.ok || typeof from.witnessNonce !== 'string') return undefined;
      if (!headSplit || !endpoint) { split = { from, seq: lastSeq }; return undefined; }
      split = { from, seq: Infinity };
      // Any failure leaves the split at the last entry read and the window partial (head-unread): never open.
      const fallback = () => { if (split?.from === from) { split.seq = lastSeq; splitShort.add(from.witnessNonce); applySplit(); } };
      return serial(async () => {
        try {
          await guarded(async () => {
            const h = await readToHead();
            if (split?.from !== from) return;
            if (!h || h.behind) splitShort.add(from.witnessNonce);
            // Everything read before this resolves was accepted before the request (the caller is waiting), and the head
            // says what else was: the split falls at the later of the two.
            split.seq = h ? Math.max(h.headSeq, lastSeq) : lastSeq;
            if (lastSeq >= split.seq) applySplit();
          }, undefined);
        } catch { fallback(); }
        if (faulted || split?.seq === Infinity) fallback();
      });
    },
    async start() {
      if (started) return;
      // The whole history from the genesis, and (route i) up to a signed head: the epoch is pinned before any window.
      const ok = await serial(() => guarded(async () => {
        if (!endpoint) return readFile(true);
        const h = await head();
        if (!h) return false;
        if (!(await readEndpoint(true))) return false;
        if (epoch !== h.epoch) fault('head-invalid');
        return lastSeq >= h.lastSeq;
      }, false));
      if (!ok || epoch === null) throw new Error(`provider-feed-${faulted ?? 'unreadable'}`);
      started = true; running = true; ledger.started();
      timer = setTimeout(tick, cfg.pollMs);
    },
    async mark() {
      const wallAt = Date.now();
      // Route (i): the signed head, then the entries up to it, so an entry the stub held before this mark is never taken
      // into the window. A mark that cannot read throws, so the window fails.
      // Route (ii): the file up to its end, and its size, which fixes which lines were there before the window.
      const r = await serial(() => guarded(async () => endpoint ? readToHead() : readFileToEnd(), { headSeq: null, behind: false }));
      if (!r) throw new Error('provider-feed-catch-up-failed');
      const mark = { ...ledger.position(), wallAt, headSeq: r.headSeq, behind: r.behind, ...(endpoint ? {} : { fileSize: r.fileSize ?? null }) };
      // Feed v2, Part B: clear when this mark read up to a signed head, with no gap and no fault (the run-end drain's final mark).
      clearAtMark.set(mark, endpoint && mark.ok === true && r.behind === false && Number.isSafeInteger(r.headSeq) && !stuck && !faulted);
      return mark;
    },
    // gap: a settlement gap window (sink-ledger.mjs), an exact range collected after the run.
    // scoped (feed v2, Part B; the HTTP connector's check windows on a witnessed endpoint feed only): entries after the witness
    // request become destination-scoped entries { name, resource, codes } where that is sound (below); every other window, and every
    // caller without it, is exactly as before.
    async collect(from, to, { gap = false, scoped = false } = {}) {
      const v2 = scoped && !gap && cfg.witness !== null && endpoint;
      if (!gap && split?.from === from) { if (split.seq === Infinity || lastSeq < split.seq) splitShort.add(from.witnessNonce); applySplit(); }
      const w = await ledger.window(from, to, { witness: cfg.witness !== null && endpoint, witnessWaitMs: cfg.witnessWaitMs, quietMs: cfg.quietMs, gap, scopedUnits: v2 });
      if (w.failed) return { events: [], coverage: 'failed', reason: faulted ? 'provider-feed-integrity' : w.failed };
      const { problems } = w, events = [];
      if (stuck) problems.add('provider-feed-entry-seq-gap');
      const short = !gap && splitShort.delete(from.witnessNonce);
      if (from.behind || to.behind || short) problems.add('provider-feed-head-unread');
      // The provider's time, the start mark's head (route i) and the file size at the start mark (route ii) only tighten:
      // such an entry stays an event with outcome unknown. A file entry stamped at or before the start mark is early, with
      // no skew allowed: an app that can write the file could hold a line back across the mark.
      const upper = Date.now() + cfg.maxSkewMs;
      const early = m => !gap && (endpoint ? m.atMs < from.wallAt - cfg.maxSkewMs : m.atMs <= from.wallAt);
      const before = m => !gap && (endpoint ? Number.isSafeInteger(from.headSeq) && m.feedSeq <= from.headSeq : Number.isSafeInteger(from.fileSize) && m.offset < from.fileSize);
      // The codes an entry's own record leaves on the window (an in-window item, or a late one under scoped); before and time tighten.
      const flags = m => {
        const own = [m.mixedWitness && 'provider-feed-witness-mixed', m.literal && 'provider-feed-address-literal', m.unusable && 'provider-feed-recipient-unusable',
          m.repeated && 'provider-feed-recipient-repeated', m.ambiguous && 'provider-feed-recipient-ambiguous'].filter(Boolean);
        const tighten = [before(m) && 'provider-feed-entry-before-window', (early(m) || !(m.atMs <= upper)) && 'provider-feed-time-outside-window'].filter(Boolean);
        return { own, tighten };
      };
      const recordOf = (m, r) => m.template && declared.has(r.domain) ? { status: 'captured', values: { [TEMPLATE_POINTER]: { ...m.template } } } : null;
      for (const m of w.items) {
        const { own, tighten } = flags(m);
        for (const c of [...own, ...tighten]) problems.add(c);
        const outcome = tighten.length ? 'unknown' : m.outcome;
        if (events.length + m.recipients.length > PROVIDER_FEED_LIMITS.eventsPerWindow) { problems.add('provider-feed-event-limit'); continue; }
        m.recipients.forEach((r, i) => { const captured = recordOf(m, r); events.push(makeEffect({ source: 'provider-feed', observer, seq: m.seq * 128 + i, observedAt: new Date(m.atMs).toISOString(), actor: null, operation: 'send',
          name: r.domain, resource: r.resource, outcome, correlation: {}, content: { entry: m.content, to: r.to },
          // The template record, on events to a declared domain only (the published capture names those).
          ...(captured ? { captured } : {}) })); });
      }
      if (!v2) {
        const reason = problems.size ? [...problems].sort().join(',').slice(0, 200) : null;
        return { events, coverage: reason ? 'partial' : 'complete', reason };
      }
      // Feed v2, Part B: each recipient of an entry after the witness request joins the entry for its (domain, resource), resource
      // being the declared address or "*" exactly as its event would carry. A unit whose own record leaves any code (a recipient
      // that is unusable, an address literal, repeated or ambiguous, a mixed witness, an entry before the window or stamped outside
      // it), or that names a domain the feed does not declare, keeps the whole window partial, as does any window-wide code. Feed
      // records are never pending; one that is, is a bug and reads window-wide too.
      if (w.pending.length) problems.add('provider-feed-entry-in-flight');
      const entries = new Map();
      for (const m of w.deferred) {
        const { own, tighten } = flags(m);
        if (own.length || tighten.length) { for (const c of [...own, ...tighten]) problems.add(c); continue; }
        m.recipients.forEach((r, i) => {
          if (!declared.has(r.domain)) { problems.add('provider-feed-scope-ineligible'); return; }
          const key = `${r.domain}\n${r.resource}`, entry = entries.get(key) ?? { name: r.domain, resource: r.resource, units: [] };
          entry.units.push({ m, i, r }); entries.set(key, entry);
        });
      }
      if (entries.size > 32) problems.add('provider-feed-scope-limit');
      if (problems.size) {
        if (w.deferred.length) problems.add(FEED_LATE_CODE);
        return { events, coverage: 'partial', reason: [...problems].sort().join(',').slice(0, 200) };
      }
      if (!entries.size) return { events, coverage: 'complete', reason: null };
      // An entry that is exactly one recipient of one entry carries that send's event seq and its template record (on a feed with a
      // template vocabulary); a second unit of any kind removes both.
      const list = [...entries.values()].map(e => { const u = e.units.length === 1 ? e.units[0] : null, captured = u ? recordOf(u.m, u.r) : null;
        return { name: e.name, resource: e.resource, codes: [FEED_LATE_CODE], ...(captured ? { seq: u.m.seq * 128 + u.i, captured } : {}) }; })
        .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.resource < b.resource ? -1 : a.resource > b.resource ? 1 : 0));
      lateSince ??= gapsNoted;
      return { events, coverage: 'partial', reason: FEED_LATE_CODE, scoped: list };
    },
    // Feed v2, Part B: the run-end drain (src/run-end-drain.mjs), on a witnessed endpoint feed. markClear: the final mark read up to
    // a signed head with no gap and no fault. drainCapMs: ten quiet periods and two feed requests. drain: read to a fresh signed head
    // until everything the head says the provider accepted is read, there is no gap or fault, and nothing new has been read for
    // quietMs (monotonic); then one more signed head must show nothing new. Anything else, or the cap, is not quiescent.
    // closedAfterCollect: the feed has no connection to lose bytes on; it reads true when a fault or a seq gap came after the first
    // scoped collect that left a late entry (entries may then be unseen), so the drain follows nothing.
    markClear(mark) { return clearAtMark.get(mark) === true; },
    drainCapMs() { return 10 * cfg.quietMs + 2 * PROVIDER_FEED_LIMITS.requestTimeoutMs; },
    async drain({ capMs }) {
      const began = performance.now(), elapsed = () => performance.now() - began, left = () => capMs - elapsed();
      // waitedMs is the time spent, at most the cap: every wait below ends by it.
      const result = quiescent => ({ quiescent, waitedMs: Math.min(elapsed(), capMs), closedAfterCollect: lostAfterCollect() });
      if (!(capMs > 0) || !endpoint || cfg.witness === null || !started) return result(false);
      // One feed read on the shared queue, bounded by the time left: at the cap the drain stops waiting (not quiescent), and a read
      // still running finishes on the queue before the final mark reads.
      const within = fn => boundedRead(fn, left());
      while (left() > 0) {
        if (faulted || !ledger.up()) return result(false);
        const h = await within(() => readToHead());
        if (h === CAP || faulted) return result(false);
        if (h && !h.behind && !stuck && lastSeq === h.headSeq && performance.now() - ledger.lastArrival() >= cfg.quietMs) {
          // The confirming head is compared with what was read at the quiet check, not with lastSeq: a background read between the two
          // may read on. (lastSeq cannot pass that head's lastSeq: head() faults when a head is behind what was read.)
          const seen = h.headSeq;
          const again = await within(() => head());
          if (again === CAP) return result(false);
          if (again && !faulted && !stuck && again.lastSeq === seen && left() >= 0) return result(true);
        }
        await new Promise(resolve => setTimeout(resolve, Math.max(1, Math.min(cfg.pollMs, left()))));
      }
      return result(false);
    },
    closedAfterCollect() { return lostAfterCollect(); },
    // Later outcomes: the records up to a mark's signed head (the later mark the connector takes after the later wait), and whether the
    // later horizon is clear there: that mark read up to its signed head with no gap and no fault (markClear), and no refused outcome or
    // status entry at or below it.
    // Events made ambiguous by then carry one "ambiguous" record instead of their words. Records come by event seq, each event's in
    // feed order, at most LATER_LIMITS.records (past it, not clear).
    laterRecords(mark) {
      if (!cfg.outcomes) return null;
      const cut = Number.isSafeInteger(mark?.headSeq) ? mark.headSeq : -Infinity;
      let clear = clearAtMark.get(mark) === true && faulted === null && cut > -Infinity && !(unclearAt !== null && unclearAt <= cut);
      const ambiguousEvents = new Set([...ambiguousAt].filter(([, at]) => at <= cut).map(([of]) => of));
      for (const [id, at] of repeatedAt) if (at <= cut) for (const of of eventsOf(inRun.get(id) ?? [])) ambiguousEvents.add(of);
      const words = new Map();
      for (const r of laterLog) if (r.feedSeq <= cut && !ambiguousEvents.has(r.of)) words.set(r.of, [...(words.get(r.of) ?? []), r.outcome]);
      let records = [...new Set([...words.keys(), ...ambiguousEvents])].sort((a, b) => a - b)
        .flatMap(of => ambiguousEvents.has(of) ? [{ of, outcome: 'ambiguous' }] : words.get(of).map(outcome => ({ of, outcome })));
      if (records.length > LATER_LIMITS.records) { records = records.slice(0, LATER_LIMITS.records); clear = false; }
      return { clear, records };
    },
    // Later outcomes: the later wait (ADDENDUM-R1 M3), run once by the connector after the final mark and the collect of every run-end
    // window, so nothing a window, a drain or a verdict reads can depend on it. It reads to fresh signed heads for the whole of capMs (the
    // review's first option for m2: a delayed bounce after a success is caught whenever it comes within the wait), and returns at once when
    // the run has no send an outcome could bind to. A fault ends it. Returns { waitedMs }.
    async laterWait({ capMs }) {
      const began = performance.now(), elapsed = () => performance.now() - began, left = () => capMs - elapsed();
      const result = () => ({ waitedMs: Math.max(0, Math.min(Math.round(elapsed()), capMs)) });
      if (!(capMs > 0) || !cfg.outcomes || !started || !endpoint || !inRun.size) return { waitedMs: 0 };
      while (left() > 0) {
        if (faulted) return result();
        const h = await boundedRead(() => readToHead(), left());
        if (h === CAP || faulted) return result();
        await new Promise(resolve => setTimeout(resolve, Math.max(1, Math.min(cfg.pollMs, left()))));
      }
      return result();
    },
    async stop() {
      running = false; clearTimeout(timer);
      await queue;
      ledger.stopped(); agent?.destroy();
    },
  };
}
