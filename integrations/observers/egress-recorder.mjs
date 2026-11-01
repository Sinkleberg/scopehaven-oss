// Egress recorder: a loopback sink for the application's outbound HTTP
// (configuration and routing modes: src/egress-rules.mjs). By default it answers every
// request itself and never forwards, so nothing the app sends during a test
// leaves this machine through it. Each request that reaches it is one "send"
// effect named by its destination host. A destination that declares `forward` (opt-in,
// readiness edge E1) has each recorded send forwarded to its declared loopback upstream
// (egress-forward.mjs) and the upstream's reply returned to the app; its event records the
// upstream outcome (src/effect-outcome.mjs). Forwarding stays on this machine.
//
// It is authoritative only with declared routing and a witness, and strict
// about what it could have missed. Windows, witnesses and the quiet period are
// kept by the shared sink ledger (sink-ledger.mjs). A window is partial when:
//   - this window's witness (the app's own outbound request carrying the start
//     mark's nonce) did not arrive within witnessWaitMs, arrived twice, or a
//     witness of another window arrived
//   - a request arrived after the witness request was sent (it may be the
//     witness route's own doing, or later than the check): never an effect
//   - a request was malformed, dropped at the connection limit, came from a
//     browser (Origin or Sec-Fetch-Site, or a base-url request whose Host names anything
//     but the sink: DNS rebinding), named no route (base-url), had a body
//     over maxBodyBytes, was aborted, or was still in flight at collect (its headers
//     included: the server's own parser was mid-message on that connection, also for
//     a request that follows a completed one in the same write)
//   - an HTTPS tunnel (CONNECT) was requested: the destination is recorded and
//     the tunnel refused, but its payload (method, path) is never seen
//   - a path's percent-decoding names a different declared path than the raw path
//   - a proxy request whose Host header names another host than its URL, or whose destination is an IP
//     literal that is not itself declared: a send to a declared host may be addressed under another name
//   - a connection had sent part of a request (headers not yet complete) when collect ran
//   - a request's host is longer than an event name (128 characters): it is no event, never shortened into another host
//   - a request's host has an empty label once its trailing dots are dropped (api-eu..pay.example; FIX-04): it is malformed, never
//     an event under a name no rule reads as a declared host or its sibling
// and failed when the listener was down at any point since the start mark, or
// the window's records were evicted (retainedRequests).
// Settle: collect() waits up to witnessWaitMs for the witness, then until no
// request has arrived for quietMs. A send the app makes later than that is not
// observed: that bound is the observer's declared limit.
// committed: the request reached the sink in full. The real destination never
// receives it; the effect recorded is the app's attempt to send. A forwarded send's record stays in flight
// until its forward settles (a collect before then reads egress-request-in-flight), and its event carries
// upstream { outcome, status, proven }: applied (a listed 2xx to a method that can change state), rejected (a listed
// 4xx) or unknown, and decided only when the reply carries a valid proof under the destination's proofEnv secret
// (egress-forward.mjs). Everything the record reads (digest, declared fields, correlation token, idempotency key) comes
// from the request as received; the upstream receives the same headers, less the fixed hop-by-hop set. A forwarded send's body is bounded by the smaller of
// maxBodyBytes and 1 MiB; one over it, aborted, or a CONNECT tunnel is never forwarded and reads unknown. A destination
// that also declares proofVersion 2 and ids records the salted digests of the declared string ids of each /2-proven reply
// body in upstream.minted and upstream.references (readiness edge E3, src/id-closure.mjs).
// egress-recorder/6 (in-doubt resolution IDR-0, IN-DOUBT-LEAD-RULING-IDR0 R-2): a settled forward's upstream record also carries
// target = { exact, query }: exact when the request path (raw and decoded agreeing) is exactly the declared path its resource names (a
// sub-path filed under it, or "*", is not), query when the request target carried a query string. Flags only: no path or query is kept.
// Only an exact, query-free send can be judged by its outcome (integrations/collateral/only.mjs outcomeJudged).
// egress-recorder/7 (in-doubt resolution R0, src/in-doubt.mjs): a settled forward's upstream record also carries transport = { connected, mono,
// wall }: whether the TCP connect to the upstream completed (egress-forward.mjs), and the settle moment on the monotonic clock and on the
// wall clock the factory passes (null without one). Times only: no body, id, key or address.
// egress-recorder/8 (in-doubt resolution R1, src/request-feed-rules.mjs): a recorder may declare a request feed (requestFeed), which its
// own reader (request-feed.mjs) reads on 127.0.0.1 at start and at run end, with this recorder's salt, so a provider's key is compared with
// a send's key only as the same salted digest. The scope publishes the feed's record. A forwarded send to a feed host also carries its
// arrival on both clocks in its transport record (arrivedMono, arrivedWall), and its tenant header (when declared) is kept only as a
// salted digest in memory. resolutionRecords (the connector's run-end resolver read, within its cap) returns, for each such send still in
// doubt that connected and carries a keyed record, the sealed read R1 derives its result from: counts, flags and times only.
// egress-recorder/9 (in-doubt resolution R2, src/read-back-rules.mjs): a destination may declare readBack (with credentialHeader and, on any
// forwarded destination, backend). Its reader (read-back.mjs), built with this recorder's seal, sees every forwarded send just before it is
// forwarded: a send that binds a read-back route waits for its group's pre-image (bounded by min(1000 ms, timeoutMs)), and its settled
// forward's upstream record also carries readBack { route, group, object, touches, credential, scopeUndeclared, authorInBody, preImage,
// preImageMs } (salted digests, flags and times; never a path, value or credential). The scope publishes the read-back record. At run end
// resolutionRecords also returns, for each send to a read-back route still in doubt that connected, the sealed read R2 derives its result from.
// egress-recorder/10 (FIX-02, SURPASS-BYPASS-01 A-21): the sink holds its port on both loopback addresses, 127.0.0.1 and [::1], each bound
// exclusively, and reads every connection to either as one server. A route written with a name (http://localhost:<port>) may resolve to
// ::1 first, so a listener another process held on [::1] at the sink's port would take the app's routed requests while it relayed only the
// witness to 127.0.0.1. If either bind fails, the recorder does not start and its windows fail; a listener that comes later cannot bind.
// egress-recorder/11 (FIX-04, SURPASS-BYPASS-01 A-32): another name of a declared provider. A destination may declare aliases (option 2): a
// proxy request or CONNECT tunnel to an alias is recorded under the destination's host (its Host header read the same way), and the scope
// publishes them. An undeclared host that shares its registrable domain with a destination or its aliases (src/egress-rules.mjs siblingsOf,
// src/public-suffix.mjs) may be that provider under another name (option 1): in a scoped check window each completed in-window send to one
// adds an entry { name: the destination, resource: the send's method and path read on the destination's declared paths, codes:
// [egress-undeclared-sibling-host] } beside its own event, so a clause that selects the destination reads missing; in every other window it
// adds that code window-wide. The send's own event keeps its own name, so the clause text names it (src/http-effects.mjs, option 3).
// egress-recorder/12: the run-end drain's last look, one turn after it found the recorder settled and quiet, checks quiet again: a request
// read, recorded and answered in that turn is an arrival, so the drain goes round again instead of reading quiescent just after it.
// egress-recorder/13 (FIX-08, SURPASS-BYPASS-01 M3 A-xrec): the run's other recorders. The factory passes crossDestinations, the destinations
// the profile's other egress recorders declare that this one does not (src/egress-rules.mjs crossDestinationsOf). A send to one of those
// hosts or its aliases is recorded under that host, its resource read on that host's declared paths (never captured, keyed or forwarded
// here), and siblingsOf reads the run's names, so a send to a sibling of another recorder's destination adds that destination an entry as
// above. The scope publishes them (cross: { [host]: [alias, ...] }), and a window holding such a send is one that can see that destination.
// Correlation (opt-in per destination, src/egress-rules.mjs): the token one well-formed value of the declared
// header carries goes into the event's correlation.settlementToken, a key no selector or pairing pin reads; a
// missing, repeated or malformed header records none. The app writes the value, and the recorder cannot tell
// whether it is the token the connector sent, so settlement reads it only to withhold a pass.
// Bodies: every body is kept only as a salted digest. A destination that declares
// `capture` (src/egress-rules.mjs, src/body-fields.mjs) also has the declared scalar
// fields of its JSON bodies on its declared paths read (a send on another path, or on a
// path whose raw and decoded forms disagree, records status "path-undeclared"): up to capture.maxBytes are buffered beside the digest,
// parsed once at the end of the request, and only the declared fields are stored on the
// event, with a status saying why nothing could be read. CONNECT tunnels and the witness
// request are never captured. The scope publishes the declaration (scope.capture). A destination that also
// declares capture.encodings ["json", "form"] has those fields read from form-encoded bodies too, only when the
// request is a POST whose target has no query or fragment (both are passed to captureBody); the scope lists such hosts
// (scope.captureForm).
import { createServer } from 'node:http';
import { isIP, createServer as createNetServer } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { makeEffect, credentialFrom } from './events.mjs';
import { createSinkLedger, SINK_LEDGER_LIMITS } from './sink-ledger.mjs';
import { validateEgressConfig, correlationTokenOf, siblingsOf, aliasRecordOf, validateCrossDestinations, crossRecordOf } from '../../src/egress-rules.mjs';
import { captureBody, formEnabled } from '../../src/body-fields.mjs';
import { readIdempotencyKey, readBodyKey, foldKey, headText, signedHead, publishIdempotency, createSigningCheck, signingHead, signingKeyOf, effectiveHmacKey, signingSecretValueClash,
  IDEMPOTENCY_TRANSPORT_HEADERS, IDEMPOTENCY_DIRTY, IDEMPOTENCY_BOUNDS, SIGNING_BOUNDS } from '../../src/idempotency.mjs';
import { upstreamRecord, forwardScopeOf, UNFORWARDED, FORWARD_BOUNDS, RETURNED_BOUNDS } from '../../src/effect-outcome.mjs';
import { transportRecord } from '../../src/in-doubt.mjs';
import { forwardRequest } from './egress-forward.mjs';
import { createRequestFeedReader } from './request-feed.mjs';
import { createReadBackReader } from './read-back.mjs';
import { readBackRecord } from '../../src/read-back-rules.mjs';
import { requestFeedRecord, REQUEST_FEED_READ_MS } from '../../src/request-feed-rules.mjs';
import { singleHeader } from '../../src/http.mjs';

// The Host a base-url request may name: the sink itself, as the app on this machine or a container (host.docker.internal) reaches it.
// A page that rebinds a name of its own to 127.0.0.1 (DNS rebinding) sends that name, and its same-origin requests carry no Origin or
// Sec-Fetch-Site. A repeated Host is never read; a request without one names no other host. The payments double keeps its own copy.
const SINK_HOSTS = Object.freeze(['127.0.0.1', 'localhost', 'host.docker.internal']);
const sinkHostAllowed = (req, port) => req.headers.host === undefined || SINK_HOSTS.some(h => String(singleHeader(req, 'host')).toLowerCase() === `${h}:${port}`);

export const EGRESS_LIMITS = Object.freeze({ retainedRequests: 20000, maxConnections: 256, headersTimeoutMs: 10000, requestTimeoutMs: 15000, maxHeaderSize: 16384 });
// The loopback addresses the sink holds its port on (egress-recorder/10), the first one by the HTTP server itself.
export const SINK_ADDRESSES = Object.freeze(['127.0.0.1', '::1']);
const listenExclusive = (server, port, host) => new Promise((resolve, reject) => { server.once('error', reject); server.listen({ port, host, exclusive: true }, () => { server.off('error', reject); resolve(); }); });

// retainedRequests: operator code only (a profile cannot set it). env: where a forwarded destination's proofEnv secret is read.
// idempotencyKeys: operator code only (a profile cannot set it); a new key past it records status "untracked".
// signingClock: operator code only (the factory passes the wall clock, which the recorder never reads itself), in milliseconds; a
// declared signature scheme's timestamp is checked against it (signedHead, createSigningCheck), and without it every such scheme
// reads unparsed and no send verifies. env: also where a destination's signing secrets (idempotency.signing.secretEnv) are read.
// wallClock: operator code only (the factory passes the wall clock), in milliseconds; a forward's transport record carries it at settle.
// drainTurn: operator and test code only (a profile cannot set it): the run-end drain's wait of one turn before its last look, a function
// returning a promise (default: setImmediate); a test passes its own to order an arrival inside that turn.
// crossDestinations: operator code only (the factory builds it from the profile's other egress recorders; a profile cannot set it).
export function createEgressRecorder({ instanceId = 'egress-recorder-1', retainedRequests = EGRESS_LIMITS.retainedRequests, idempotencyKeys = IDEMPOTENCY_BOUNDS.keysPerRecorder, env = process.env, signingClock = null, wallClock = null, drainTurn = null, crossDestinations = null, ...config }) {
  const cfg = validateEgressConfig({ ...config, type: 'egress-recorder' }, config.witness ? { [config.witness.actorId]: {} } : undefined);
  const observer = { kind: 'http-egress-recorder', instanceId };
  const byHost = new Map(cfg.destinations.map(d => [d.host, d]));
  // FIX-04 (egress-recorder/11): the declared names, the published aliases ({ [host]: [alias, ...] } or null) and the host an alias folds into.
  const names = cfg.destinations.map(d => d.host), aliasScope = aliasRecordOf({ type: 'egress-recorder', destinations: cfg.destinations });
  // FIX-08 (egress-recorder/13): the run's other recorders' destinations, their published record, and the names siblingsOf reads (the run's).
  const cross = validateCrossDestinations(crossDestinations, cfg), crossByHost = new Map((cross ?? []).map(d => [d.host, d])), crossScope = crossRecordOf(cross);
  const aliasOf = new Map([...cfg.destinations.flatMap(d => (d.aliases ?? []).map(a => [a, d.host])), ...(cross ?? []).flatMap(d => d.aliases.map(a => [a, d.host]))]), canonical = host => aliasOf.get(host) ?? host;
  const runNames = cross ? [...names, ...crossByHost.keys()] : names, runAliases = cross ? { ...(aliasScope ?? {}), ...crossScope } : aliasScope;
  // The declared capture, published on the scope: { [host]: [pointer, ...] }, only when some destination declares it.
  const captureScope = cfg.destinations.some(d => d.capture) ? Object.freeze(Object.fromEntries(cfg.destinations.filter(d => d.capture).map(d => [d.host, Object.freeze([...d.capture.pointers])]))) : null;
  // The hosts whose declared fields are also read from form bodies, in profile order, only when some destination declares it.
  const captureFormScope = cfg.destinations.some(d => formEnabled(d.capture)) ? Object.freeze(cfg.destinations.filter(d => formEnabled(d.capture)).map(d => d.host)) : null;
  // The forwarded hosts and their declared "not applied" statuses, published on the scope: { [host]: { rejected } }, or null.
  const forwardScope = forwardScopeOf(cfg.destinations);
  // Returned ids (readiness edge E3): the declared string ids (8 to 200 characters) of a /2-proven reply body, as salted
  // digests (sorted, distinct, at most 8 per list): minted (the ids the upstream created for this request), references (ids of
  // other objects it names) and echoed (a value at a minted pointer that the forwarded request carried: copied, re-cased, inside
  // a longer value, or behind JSON, form, percent or base64 encoding). An echoed value is never minted and contests the id
  // everywhere (src/id-closure.mjs). A value the body-field reader refuses is not an id.
  const requestTexts = request => {
    const texts = [request.body.toString('latin1'), request.path];
    try { texts.push(decodeURIComponent(request.path)); } catch {}
    // Whole request values (JSON strings, form values, header values) of 8 or more characters: a minted value containing one is derived.
    const values = [];
    const decoded = text => text.length >= RETURNED_BOUNDS.chars[0] ? ['base64', 'base64url'].map(encoding => Buffer.from(text, encoding).toString('latin1')) : [];
    const strings = value => { if (typeof value === 'string') { texts.push(value, ...decoded(value)); values.push(value); } else if (value !== null && typeof value === 'object') for (const v of Object.values(value)) strings(v); };
    try { strings(JSON.parse(request.body.toString('utf8'))); } catch {}
    try { for (const [key, value] of new URLSearchParams(request.body.toString('utf8'))) { texts.push(key, value); values.push(value); } } catch {}
    for (let i = 0; i < request.rawHeaders.length; i++) {
      const text = request.rawHeaders[i]; texts.push(text); if (i % 2) values.push(text);
      for (const token of text.split(/[\s,;=:.]+/)) if (token.length >= 8) for (const encoding of ['base64', 'base64url']) texts.push(Buffer.from(token, encoding).toString('latin1'));
    }
    const lower = texts.map(t => t.toLowerCase());
    return { lower, tokens: [...new Set([...lower.flatMap(t => t.split(/[^a-z0-9]+/)), ...values.map(v => v.toLowerCase())].filter(t => t.length >= RETURNED_BOUNDS.chars[0]))] };
  };
  const returnedIds = (forward, result, request) => {
    if (!forward.ids || forward.proofVersion !== 2 || !result.complete || !result.proven) return {};
    const read = captureBody({ rawHeaders: result.headers.flat(), buffer: result.body, bodyBytes: result.body.length, capture: forward.ids, search: '', method: 'POST' });
    if (read.status !== 'captured') return {};
    const [lo, hi] = RETURNED_BOUNDS.chars;
    const valueAt = pointer => { const v = read.values[pointer]; return v?.type === 'string' && v.value.length >= lo && v.value.length <= hi ? v.value : null; };
    const seen = requestTexts(request);
    const echoed = value => { const v = value.toLowerCase(); return seen.lower.some(t => t.includes(v)) || seen.tokens.some(t => v.includes(t)); };
    const digests = values => { const list = [...new Set(values.filter(v => v !== null).map(v => createHash('sha256').update(salt).update('scopehaven-returned-id/1\n').update(v).digest('hex')))].sort(); return list.length ? list.slice(0, RETURNED_BOUNDS.values) : undefined; };
    const mintedValues = forward.ids.minted.map(valueAt).filter(v => v !== null);
    return { minted: digests(mintedValues.filter(v => !echoed(v))), references: digests(forward.ids.references.map(valueAt)), echoed: digests(mintedValues.filter(echoed)) };
  };
  // Aborts every forward still in flight when the recorder stops.
  let stopForwards = new AbortController();
  // Each forwarded host's proof secret, read once from the dedicated namespace; a declared one that is missing or short fails here.
  const secrets = new Map(cfg.destinations.filter(d => d.forward?.proofEnv).map(d => {
    const secret = credentialFrom(env, d.forward.proofEnv, `forward proof of ${d.host}`);
    if (typeof secret !== 'string' || secret.length < FORWARD_BOUNDS.proofSecretChars) throw new Error(`forward proof of ${d.host}: ${d.forward.proofEnv} must hold a secret of at least ${FORWARD_BOUNDS.proofSecretChars} characters`);
    return [d.host, secret];
  }));
  // Verified signature headers (b', src/idempotency.mjs createSigningCheck): each destination that declares idempotency.signing has
  // its secrets read once, here, from the dedicated namespace, and held only as key bytes in this closure: never on the returned
  // object, the scope, a record or an event, and nothing derived from one is ever written. A missing or unusable secret leaves its
  // slot unusable (its sends' signature headers stay bound; the run's signing record and a limitation line say so). Two secrets of
  // one destination with the same effective HMAC key, a signing secret that is also a forward proof secret, and more than
  // SIGNING_BOUNDS.secretsPerRecorder secrets are refused. An unusable slot keeps a random dummy key, so the work a send costs
  // never depends on which secrets are usable. stop() zeroes the keys and closes signing for good (signingClosed).
  const signingDeclared = cfg.destinations.filter(d => d.idempotency?.signing);
  if (signingDeclared.reduce((n, d) => n + d.idempotency.signing.secretEnv.length, 0) > SIGNING_BOUNDS.secretsPerRecorder) throw new Error(`an egress recorder declares at most ${SIGNING_BOUNDS.secretsPerRecorder} signing secrets`);
  const signingClash = signingSecretValueClash([{ type: 'egress-recorder', destinations: cfg.destinations }], env);
  if (signingClash) throw new Error(signingClash);
  const signingSlots = new Map(signingDeclared.map(d => {
    const s = d.idempotency.signing;
    const slots = s.secretEnv.map((name, i) => { const key = signingKeyOf(s.scheme, credentialFrom(env, name, `signing secret ${i + 1} of ${d.host}`)); return key ? { key, usable: true } : { key: randomBytes(32), usable: false }; });
    const effective = slots.map(slot => (slot.usable ? effectiveHmacKey(slot.key) : null));
    for (let i = 0; i < slots.length; i++) for (let j = i + 1; j < slots.length; j++) if (effective[i] && effective[j] && effective[i].equals(effective[j])) throw new Error(`signing secrets ${i + 1} and ${j + 1} of ${d.host} are the same HMAC key: declare each signing secret once`);
    return [d.host, slots];
  }));
  let signingClosed = false;
  // Content digests are salted per recorder, so a bodiless request's digest does not reveal its target.
  const salt = randomBytes(16);
  // Keyed retries (src/idempotency.mjs), published on the scope: { [host]: published declaration }, only when some destination declares one.
  const idempotencyScope = cfg.destinations.some(d => d.idempotency) ? Object.freeze(Object.fromEntries(cfg.destinations.filter(d => d.idempotency).map(d => [d.host, publishIdempotency(d.idempotency)]))) : null;
  // Run-wide key state: the first seq of each key fold (capped, never evicted), the first seq of a send whose key could not be
  // read, per host, and the sends in flight per key fold (two at once mark each other "overlap"). Keys are sealed with the salt.
  // A body key (a declared pointer) is known only when the body ends: arrival and end ticks order such sends, and a send that ends
  // after another send of its fold arrived marks both "overlap" (lastEnded).
  const keyFirst = new Map(), dirtyFirst = new Map(), keysInFlight = new Map(), lastEnded = new Map();
  let tick = 0;
  // When the recorder started, in Unix seconds on the injected signing clock (null without one): a declared signature scheme's
  // timestamp is plausible from a margin before it (signedHead, createSigningCheck). The clock is read once, here; a send's second
  // (nowSec, and the signing item's arrival second at) counts from it on the monotonic clock, so a wall-clock step during the run
  // never stretches or shrinks a window or a dedupe bound.
  const signedSince = typeof signingClock === 'function' ? Math.floor(signingClock() / 1000) : null, signedSinceMono = performance.now();
  const signingSeconds = () => (Number.isSafeInteger(signedSince) ? signedSince + Math.floor((performance.now() - signedSinceMono) / 1000) : null);
  const seal = (label, text) => createHash('sha256').update(salt).update(label).update(text).digest('hex');
  // In-doubt resolution R1 (egress-recorder/8): the declared request feed and its reader, which digests a provider's key, tenant and object
  // with this recorder's salt (keys as the key records do). feedSends: the sends to feed hosts (each with its arrival and tenant digest);
  // foldSends: sends per key fold slot, run-wide; dirtySends: per host, the sends whose key could not be read (every markDirty), run-wide.
  const feedHosts = new Set(cfg.requestFeed?.hosts ?? []);
  const feed = cfg.requestFeed ? createRequestFeedReader({ config: cfg.requestFeed, digests: { key: (host, value) => seal('scopehaven-idempotency-key/1\n', `${host}\n${value}`),
    fold: (host, value) => seal('scopehaven-idempotency-fold/1\n', `${host}\n${foldKey(value)}`),
    tenant: (host, value) => seal('scopehaven-request-tenant/1\n', `${host}\n${value}`), object: (host, value) => seal('scopehaven-request-object/1\n', `${host}\n${value}`) },
    clocks: { mono: () => performance.now(), wall: () => (typeof wallClock === 'function' ? wallClock() : null) } }) : null;
  const feedSends = [], foldSends = new Map(), dirtySends = new Map();
  // In-doubt resolution R2 (egress-recorder/9): the read-back reader, only when some destination declares readBack, with this recorder's seal (ids
  // as the minted-id digests, keys as the key records seal them). It reads the read credential once; a missing one refuses the recorder.
  const readBackScope = readBackRecord(cfg.destinations);
  const readBack = readBackScope ? createReadBackReader({ destinations: cfg.destinations, env, seal, keyDigest: (host, value) => seal('scopehaven-idempotency-key/1\n', `${host}\n${value}`), secrets,
    clocks: { mono: () => performance.now(), wall: () => (typeof wallClock === 'function' ? wallClock() : null) }, signal: () => stopForwards.signal }) : null;
  // The send's tenant, as the request feed reads it: one value of the declared header (absent: the default tenant ''), null when repeated.
  const tenantOf = (host, rawHeaders) => {
    const header = cfg.requestFeed?.tenant ?? null, values = [];
    if (header !== null) for (let i = 0; i + 1 < rawHeaders.length; i += 2) if (rawHeaders[i].toLowerCase() === header) values.push(rawHeaders[i + 1]);
    return values.length > 1 ? null : seal('scopehaven-request-tenant/1\n', `${host}\n${values[0] ?? ''}`);
  };
  const markDirty = (host, seq) => {
    dirtyFirst.set(host, Math.min(dirtyFirst.get(host) ?? Infinity, seq));
    if (feedHosts.has(host)) { const set = dirtySends.get(host) ?? new Set(); set.add(seq); dirtySends.set(host, set); }
  };
  const unkeyed = (r, host, head, status) => { r.idem = { status, key: null, fold: null, head, firstSeq: null }; if (IDEMPOTENCY_DIRTY.includes(status)) markDirty(host, r.seq); };
  // A keyed send: its fold slot and first use, or untracked when the key store is full. Returns the slot, or null.
  function keyed(r, host, head, value) {
    const fold = seal('scopehaven-idempotency-fold/1\n', `${host}\n${foldKey(value)}`), slot = `${host}\n${fold}`;
    if (!keyFirst.has(slot) && keyFirst.size >= idempotencyKeys) { unkeyed(r, host, head, 'untracked'); return null; }
    keyFirst.set(slot, Math.min(keyFirst.get(slot) ?? Infinity, r.seq));
    if (feedHosts.has(host)) foldSends.set(slot, (foldSends.get(slot) ?? 0) + 1);
    r.idem = { status: 'keyed', key: seal('scopehaven-idempotency-key/1\n', `${host}\n${value}`), fold, head, firstSeq: null };
    r.idemSlot = slot;
    return slot;
  }
  // The key record of a send to a destination that declares idempotency: a header key read on arrival; a body key once the body
  // ends (finishBodyKey), with a placeholder until then (a window collected before the end is partial anyway).
  function startKey(r, host, method, rawTarget, rawHeaders) {
    const d = byHost.get(host), idem = d.idempotency, nowSec = signingSeconds();
    // The declared volatile names this send's head leaves out: a timestamped signature scheme's only when its values parse with a
    // timestamp inside the run window, and an untimed MAC's never. Each such scheme's signed item is sealed at once.
    const { exclude, marker, signed } = signedHead({ declaration: idem, rawHeaders, startSec: signedSince, nowSec });
    const headWith = (more = [], signingMarker = '') => seal('scopehaven-idempotency-head/1\n', headText({ method, rawTarget, rawHeaders, exclude: [...(idem.header ? [idem.header] : []), ...(d.correlation ? [d.correlation] : []), ...exclude, ...more, ...IDEMPOTENCY_TRANSPORT_HEADERS] }) + marker + signingMarker);
    let head;
    if (idem.signing) {
      // Verified signature headers: the raw body bytes feed the check as they arrive (r.idemSignCheck), and when the body ends
      // (r.idemSignEnd) the head is recomputed from the result. Until then the head keeps every header (unverified).
      const check = createSigningCheck({ signing: idem.signing, rawHeaders, slots: signingClosed ? null : signingSlots.get(host), startSec: signedSince, nowSec });
      head = headWith([], signingHead(idem.signing, { verified: false }).marker);
      r.idemSigning = { scheme: idem.signing.scheme, verified: false, t: null, at: Number.isSafeInteger(nowSec) ? nowSec : null };
      r.idemSignCheck = check;
      r.idemSignEnd = rawTrailers => {
        const result = check.finish(rawTrailers), h = signingHead(idem.signing, result, rawTrailers);
        r.idem.head = headWith(h.exclude, h.marker);
        r.idemSigning = { scheme: idem.signing.scheme, verified: result.verified, t: result.t, at: result.at };
      };
    } else head = headWith();
    if (signed !== null) r.idemSigned = Object.fromEntries(Object.entries(signed).map(([name, s]) => [name, s === null ? null : { t: s.t, mac: seal('scopehaven-idempotency-signed/1\n', `${host}\n${name}\n${s.mac}`) }]));
    if (idem.pointer !== null) { r.idem = { status: 'unreadable', key: null, fold: null, head, firstSeq: null }; r.idemBody = { arrivalTick: ++tick, chunks: [], bytes: 0, max: idem.maxBytes }; return; }
    const read = readIdempotencyKey({ declaration: idem, method, rawHeaders });
    if (read.status !== 'keyed') return unkeyed(r, host, head, read.status);
    const slot = keyed(r, host, head, read.value);
    if (slot === null) return;
    const flying = keysInFlight.get(slot) ?? new Set();
    if (flying.size) { r.idem.status = 'overlap'; for (const other of flying) other.idem.status = 'overlap'; }
    flying.add(r); keysInFlight.set(slot, flying);
  }
  // A send's stored key record. firstSeq, read at collect (a complete window has no request still arriving): the key's first
  // use, or an earlier send to the host whose key could not be read, whichever came first.
  const keyRecord = r => {
    const { status, key, fold, head } = r.idem, signed = r.idemSigned ? { signed: r.idemSigned } : r.idemSigning ? { signing: r.idemSigning } : {};
    if (key === null) return { status, key, fold, head, firstSeq: null, ...signed };
    const dirty = dirtyFirst.get(r.host) ?? Infinity;
    return { status, key, fold, head, firstSeq: Math.min(keyFirst.get(r.idemSlot), dirty < r.seq ? dirty : Infinity), ...signed };
  };
  const endKey = r => { if (r.idemSlot === undefined) return; const flying = keysInFlight.get(r.idemSlot); flying?.delete(r); if (flying && !flying.size) keysInFlight.delete(r.idemSlot); };
  // A send whose body or delivery was not seen whole: its key decides nothing, and later uses read earlier-use.
  // defer: a forwarded send, whose upstream is still applying it until the forward settles; its end tick waits (r.idemEnd).
  function finishBodyKey(r, host, method, rawHeaders, { defer = false } = {}) {
    const pending = r.idemBody, head = r.idem.head;
    delete r.idemBody;
    const read = readBodyKey({ declaration: byHost.get(host).idempotency, method, rawHeaders, buffer: pending.bytes <= pending.max ? Buffer.concat(pending.chunks) : null, bodyBytes: r.bodyBytes });
    if (read.status !== 'keyed') return unkeyed(r, host, head, read.status);
    const slot = keyed(r, host, head, read.value);
    if (slot === null) return;
    const end = (endTick = ++tick) => {
      const prior = lastEnded.get(slot);
      if (prior && prior.endTick > pending.arrivalTick) { r.idem.status = 'overlap'; if (prior.r.idem.key !== null) prior.r.idem.status = 'overlap'; }
      lastEnded.set(slot, { endTick, r });
    };
    if (defer) r.idemEnd = end; else end();
  }
  const spoilKey = (r, host) => { if (!r.idem) return; delete r.idemBody; delete r.idemSignCheck; delete r.idemSignEnd; endKey(r); r.idem = { status: 'unreadable', key: null, fold: null, head: r.idem.head, firstSeq: null }; markDirty(host, r.seq); };
  // Whether the server's own HTTP parser is mid-message on any connection: a request still arriving, headers included,
  // also one behind a completed request in the same write. Node keeps that parser state in the server's connections
  // list for its request timeouts; without it (another runtime) every window is partial. A connection cut off
  // mid-message is a client error, recorded as malformed.
  let requestArriving = null;
  // Per mark, whether a request was arriving when it was taken (read only by a run-end collection; unknown reads arriving).
  const arrivingAtMark = new WeakMap();
  const ledger = createSinkLedger({ prefix: 'egress', unit: 'request', retained: retainedRequests });
  // Coverage v2: every connection the recorder or its server closed first (a reply of 400 or more with Connection: close, a
  // destroyed socket, a refused tunnel, a timeout or keep-alive idle close), with the ledger seq at the close. Bytes a client
  // writes after such a close are lost unseen (COVERAGE-V2-PROBE.md), so a window in which one was logged is never scoped. Kept outside the ledger, so v1 windows do not change.
  // A close the client asked for (Connection: close, or HTTP/1.0 without keep-alive) is never logged: that client sends nothing more.
  // closesAtMark: the log's length at each mark, so a close counts by when it happened, never by whether a record followed it
  // (a pooled connection the idle timer closes before the window's first record is still in the window).
  const closeLog = [], closesAtMark = new WeakMap(), clientAskedClose = new WeakSet();
  // Coverage v2 Part D (the run-end drain): quiet is measured from the latest of the last arrival, the last forward settle and
  // the last reply written, since a settle records nothing and an app may send its next request only after reading a reply.
  // closedAfterCollect: once a scoped check collect has left a late entry (lateSince: the close log's length then), any close the
  // recorder or its server made later (a forward that failed at settle, a destroyed reply, a keep-alive idle close) may have
  // swallowed bytes of that check's late work, so the run-end drain follows nothing. Closes before that collect are the
  // window's own close rule (above). lastCloseAt: an abort or a close also moves the quiet baseline.
  // clearAtMark: per mark, whether the listener was up, no request was arriving (the parser state readable) and no record was pending.
  // Monotonic, as the ledger's arrival times are (sink-ledger.mjs): a wall-clock step never fakes quiet.
  const monotonicNow = () => performance.now();
  let lastSettleAt = 0, lastReplyAt = 0, lastCloseAt = 0, lateSince = null;
  const clearAtMark = new WeakMap();
  const closedAfterCollect = () => lateSince !== null && closeLog.length > lateSince;
  let server = null, server6 = null;
  // A request the recorder refuses, cannot read or files under another name (a host mismatch or an address literal) may have
  // carried any key to any keyed host: it marks them all, so a later use of that key reads as used before.
  const record = fields => {
    const r = ledger.record(fields);
    if (idempotencyScope && (fields.kind !== 'item' || fields.hostMismatch || fields.addressLiteral)) for (const host of Object.keys(idempotencyScope)) markDirty(host, r.seq);
    return r;
  };
  // The declared path prefix a path names ("POST /v1/charges"), or "*".
  const pathName = (host, path) => {
    const paths = byHost.get(host)?.paths ?? crossByHost.get(host)?.paths ?? [];
    const matchOf = value => paths.find(p => value === p || value.startsWith(p.endsWith('/') ? p : `${p}/`)) ?? null;
    let decoded = null;
    try { decoded = decodeURIComponent(path); } catch {}
    const raw = matchOf(path), dec = decoded === null ? null : matchOf(decoded);
    return { name: dec ?? raw ?? '*', ambiguous: decoded === null || raw !== dec };
  };
  // Every trailing dot is dropped (api.pay.example.. is api.pay.example; FIX-04 review), and a name left with an empty label is malformed.
  const normalHost = host => host.toLowerCase().replace(/^\[(.*)\]$/, '$1').replace(/\.+$/, '');
  const emptyLabel = host => host.split('.').some(label => !label.length);
  // A destination named by an IP literal that is not itself declared could be any declared host.
  const undeclaredLiteral = host => isIP(host) !== 0 && !byHost.has(host);
  // Where a request target points: { host, path, query } or a problem.
  function locate(target) {
    if (/^https?:\/\//i.test(target)) {
      let url;
      try { url = new URL(target); } catch { return { problem: 'malformed' }; }
      if (url.username || url.password || emptyLabel(normalHost(url.hostname))) return { problem: 'malformed' };
      return { host: canonical(normalHost(url.hostname)), path: url.pathname, query: url.searchParams, search: target.includes('#') ? '#' : url.search, forwardPath: `${url.pathname}${url.search}`, via: 'proxy' };
    }
    if (typeof target !== 'string' || !target.startsWith('/') || target.startsWith('//')) return { problem: 'malformed' };
    if (cfg.routing !== 'base-url') return { problem: 'unrouted' };
    const route = cfg.routes.find(r => target.startsWith(r.prefix));
    if (!route) return { problem: 'unrouted' };
    let url;
    try { url = new URL(`http://sink/${target.slice(route.prefix.length)}`); } catch { return { problem: 'malformed' }; }
    return { host: route.host, path: url.pathname, query: url.searchParams, search: target.includes('#') ? '#' : url.search, forwardPath: `${url.pathname}${url.search}`, via: 'route' };
  }
  // The run token a send to a correlated destination carries (every value of its one declared header, any case of the name).
  const tokenOf = (host, rawHeaders) => {
    const header = byHost.get(host)?.correlation ?? null;
    if (header === null) return null;
    const values = [];
    for (let i = 0; i + 1 < rawHeaders.length; i += 2) if (rawHeaders[i].toLowerCase() === header) values.push(rawHeaders[i + 1]);
    return correlationTokenOf(header, values);
  };
  function onRequest(req, res) {
    // An answered send keeps the connection open: a reused connection's next request is read and recorded too.
    const reply = (status, body = null) => { if (!res.headersSent) { res.writeHead(status, body === null ? { 'Content-Length': '0', ...(status >= 400 ? { Connection: 'close' } : {}) } : { 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(body)), ...(status >= 400 ? { Connection: 'close' } : {}) }); res.end(body ?? undefined); lastReplyAt = monotonicNow(); } };
    // A browser page could post here: never the app's own send.
    const site = req.headers['sec-fetch-site'];
    if (req.headers.origin !== undefined || (site !== undefined && site !== 'none')) { record({ kind: 'browser' }); req.resume(); return reply(403); }
    const where = locate(req.url);
    if (where.problem) { record({ kind: where.problem }); req.resume(); return reply(where.problem === 'unrouted' ? 404 : 400); }
    if (where.via === 'route' && !sinkHostAllowed(req, cfg.port)) { record({ kind: 'browser' }); req.resume(); return reply(403); }
    const named = pathName(where.host, where.path);
    // FIX-04 option 1: the declared destinations this undeclared host may be another name of, each with the resource the send names there.
    const siblingOf = siblingsOf(where.host, runNames, runAliases).map(host => { const n = pathName(host, where.path); return { host, resource: `${req.method} ${n.name}`.slice(0, 200), ambiguous: n.ambiguous }; });
    // A proxy request names its destination twice; when the Host header names another host, a send to a declared
    // host may be recorded under an undeclared name, and so may one addressed by an IP literal.
    let hostHeader = null;
    try { hostHeader = req.headers.host === undefined ? null : normalHost(new URL(`http://${req.headers.host}`).hostname); } catch { hostHeader = ''; }
    // A forwarded destination (never the witness host): the body is kept to forward and bounded by the smaller limit.
    const forward = where.host === cfg.witness?.host ? null : byHost.get(where.host)?.forward ?? null;
    const bodyLimit = forward ? Math.min(cfg.maxBodyBytes, FORWARD_BOUNDS.requestBytes) : cfg.maxBodyBytes;
    const r = record({ kind: 'item', done: false, method: req.method, host: where.host, resource: `${req.method} ${named.name}`.slice(0, 200), pathAmbiguous: named.ambiguous,
      hostMismatch: where.via === 'proxy' && hostHeader !== null && canonical(hostHeader) !== where.host, addressLiteral: undeclaredLiteral(where.host), ...(siblingOf.length ? { siblingOf } : {}),
      witnessNonces: where.host === cfg.witness?.host ? where.query.getAll('scopehaven_witness') : [], bodyBytes: 0, overLimit: false, outcome: 'unknown', token: tokenOf(where.host, req.rawHeaders),
      target: createHash('sha256').update(salt).update(`${where.host}\n${where.path}\n${where.query.toString()}`).digest('hex'), ...(forward ? { upstream: UNFORWARDED } : {}) });
    // R1: a forwarded send to a feed host keeps its arrival on both clocks and its tenant digest (egress-recorder/8).
    if (forward && feedHosts.has(where.host)) {
      r.arrived = { mono: monotonicNow(), wall: typeof wallClock === 'function' ? wallClock() : null };
      r.tenant = tenantOf(where.host, req.rawHeaders);
      if (feedSends.length < retainedRequests) feedSends.push(r);
    }
    const connection = String(req.headers.connection ?? '').toLowerCase();
    if (connection.split(',').map(t => t.trim()).includes('close') || (req.httpVersion === '1.0' && !connection.split(',').map(t => t.trim()).includes('keep-alive'))) clientAskedClose.add(req.socket);
    const hash = createHash('sha256').update(salt);
    if (where.host !== cfg.witness?.host && byHost.get(where.host)?.idempotency) startKey(r, where.host, req.method, req.url, req.rawHeaders);
    // Declared capture for this destination: buffer at most capture.maxBytes beside the digest (never for the witness host),
    // and only on one of its declared paths; any other path of the host records "path-undeclared" and buffers nothing.
    const capture = where.host === cfg.witness?.host ? null : byHost.get(where.host)?.capture ?? null;
    const captureHere = capture && named.name !== '*' && !named.ambiguous ? capture : null;
    if (capture && !captureHere) r.captured = { status: 'path-undeclared', values: {} };
    const kept = [], sent = forward ? [] : null;
    let keptBytes = 0;
    req.on('data', chunk => {
      if (r.overLimit) return;
      r.bodyBytes += chunk.length;
      if (r.bodyBytes > bodyLimit) { r.overLimit = true; r.done = true; spoilKey(r, where.host); reply(413); req.destroy(); return; }
      hash.update(chunk);
      r.idemSignCheck?.update(chunk);
      if (r.idemBody) { r.idemBody.bytes += chunk.length; if (r.idemBody.bytes <= r.idemBody.max) r.idemBody.chunks.push(chunk); else r.idemBody.chunks.length = 0; }
      if (sent) sent.push(chunk);
      if (captureHere && keptBytes + chunk.length <= captureHere.maxBytes) { kept.push(chunk); keptBytes += chunk.length; }
      else if (captureHere) keptBytes = captureHere.maxBytes + 1;
    });
    // A declared test-mode reply for this destination, method and path; otherwise the plain reply.
    const declaredReply = cfg.replies.find(x => x.host === where.host && (x.method === null || x.method === req.method) && (x.path === null || where.path === x.path || where.path.startsWith(x.path.endsWith('/') ? x.path : `${x.path}/`)));
    req.on('end', () => {
      if (r.overLimit) return;
      r.body = hash.digest('hex');
      if (captureHere) r.captured = captureBody({ rawHeaders: req.rawHeaders, buffer: keptBytes <= captureHere.maxBytes ? Buffer.concat(kept) : null, bodyBytes: r.bodyBytes, capture: captureHere, search: where.search, method: req.method });
      kept.length = 0;
      // The sink has the whole request now (both key sources are read from what it received, before any forward). Unless the
      // destination forwards, it answers now and a later send under the same key is sequential. A forwarded send's upstream is
      // still applying it: its key stays in flight until the forward settles (settleForward), so a same-key send meanwhile overlaps.
      // A declared signing scheme is decided on the whole body first: a body key's record is built with the head it gives.
      if (r.idemSignEnd) { r.idemSignEnd(req.rawTrailers); delete r.idemSignEnd; delete r.idemSignCheck; }
      if (r.idemBody) finishBodyKey(r, where.host, req.method, req.rawHeaders, { defer: Boolean(forward) });
      if (!forward) endKey(r);
      if (forward) {
        // The recorded bytes go to the upstream; the record is done, with its outcome, before the app gets any reply.
        r.outcome = 'committed'; r.forwarding = true;
        // The one settle point of a forwarded send (its reply read, timed out or failed): the outcome is recorded and the record done.
        // A forward that ends without a complete reply (a timeout, a cut or oversized reply, a failure, a stop) may still be applied
        // upstream: its key stays in flight for the rest of the run, so any later send under it reads overlap (and a body key's end never comes).
        const settleForward = upstream => {
          r.upstream = upstream; r.done = true; lastSettleAt = monotonicNow();
          if (upstream.status !== null) { endKey(r); r.idemEnd?.(); } else r.idemEnd?.(Infinity);
          delete r.idemEnd;
        };
        const requestBody = Buffer.concat(sent);
        // R2 (egress-recorder/9): the reader sees the send first; one bound to a read-back route waits for its group's pre-image.
        const rb = readBack ? readBack.admit(r, { host: where.host, method: req.method, path: where.path, rawHeaders: req.rawHeaders, body: requestBody, captured: r.captured, idem: r.idem }) : null;
        // Anything that goes wrong after the forward settles leaves the record done and unknown, and the app a 502.
        const settle = result => {
          settleForward({ ...upstreamRecord({ ...result, ...returnedIds(forward, result, { body: requestBody, path: where.forwardPath, rawHeaders: req.rawHeaders }) }, forward, req.method),
            target: { exact: !named.ambiguous && named.name !== '*' && where.path === named.name, query: typeof req.url === 'string' && req.url.includes('?') },
            transport: transportRecord(result, monotonicNow(), typeof wallClock === 'function' ? wallClock() : null, r.arrived ?? null), ...(rb?.record ? { readBack: { ...rb.record } } : {}) });
          readBack?.settled(rb?.entry);
          if (res.headersSent || res.destroyed) return;
          if (!result.complete) return reply(result.reason === 'timeout' ? 504 : 502);
          try { res.writeHead(result.status, [...result.headers.flat(), 'Content-Length', String(result.body.length)]); res.end(result.body); lastReplyAt = monotonicNow(); }
          catch { if (!res.headersSent) reply(502); else res.destroy(); }
        };
        const go = () => {
          readBack?.forwarding(rb?.entry);
          forwardRequest({ port: forward.port, host: where.host, method: req.method, path: where.forwardPath, rawHeaders: req.rawHeaders, body: requestBody, timeoutMs: forward.timeoutMs, maxReplyBytes: forward.maxReplyBytes,
            secret: secrets.get(where.host) ?? null, proofVersion: forward.proofVersion, signal: stopForwards.signal })
            .then(settle).catch(() => { settleForward(UNFORWARDED); readBack?.settled(rb?.entry); if (!res.headersSent && !res.destroyed) reply(502); });
        };
        if (rb?.ready) rb.ready.then(go, go); else go();
        sent.length = 0;
        return;
      }
      r.outcome = 'committed'; r.done = true; declaredReply ? reply(declaredReply.status, declaredReply.body) : reply(cfg.replyStatus);
    });
    // A forwarded send's request ends before its forward settles: only an unfinished request is aborted.
    req.on('close', () => { if (!r.done && !r.forwarding) { r.done = true; r.aborted = true; lastCloseAt = monotonicNow(); spoilKey(r, where.host); } else if (!r.forwarding) endKey(r); });
  }
  // HTTPS through the proxy: record the destination and refuse the tunnel.
  function onConnect(req, socket) {
    const m = /^\[?([^\]]+?)\]?:(\d{1,5})$/.exec(req.url ?? '');
    if (!m || emptyLabel(normalHost(m[1]))) record({ kind: 'malformed' });
    else {
      const host = canonical(normalHost(m[1]));
      const r = record({ kind: 'item', method: 'CONNECT', host, resource: `CONNECT :${Number(m[2])}`, tunnel: true, addressLiteral: undeclaredLiteral(host), witnessNonces: [], bodyBytes: 0, outcome: 'committed',
        target: createHash('sha256').update(salt).update(`${host}:${Number(m[2])}`).digest('hex'), ...(byHost.get(host)?.forward ? { upstream: UNFORWARDED } : {}) });
      // A tunnel's request, key included, is never seen.
      if (byHost.get(host)?.idempotency) { startKey(r, host, 'CONNECT', req.url, req.rawHeaders); spoilKey(r, host); }
    }
    socket.on('error', () => {});
    socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
  }
  return {
    kind: observer.kind, instanceId, source: 'http-egress', port: cfg.port,
    scope: Object.freeze({ operations: ['send'], names: cfg.destinations.map(d => d.host), actorAttribution: 'none', evidence: cfg.routing ? 'authoritative' : 'presence-only', ...(captureScope ? { capture: captureScope } : {}), ...(captureFormScope ? { captureForm: captureFormScope } : {}),
      ...(idempotencyScope ? { idempotency: idempotencyScope } : {}), ...(forwardScope ? { forward: forwardScope } : {}), ...(cfg.requestFeed ? { requestFeed: Object.freeze(requestFeedRecord(cfg.requestFeed)) } : {}),
      ...(readBackScope ? { readBack: Object.freeze(readBackScope) } : {}), ...(aliasScope ? { aliases: Object.freeze(aliasScope) } : {}), ...(crossScope ? { cross: Object.freeze(crossScope) } : {}) }),
    ...(cfg.witness ? { witnessRequest: Object.freeze({ actorId: cfg.witness.actorId, method: 'GET', path: cfg.witness.path }) } : {}),
    // Called by the connector immediately before it sends this window's witness request.
    markWitnessRequest(from) { ledger.markWitnessRequest(from); },
    async start() {
      if (server) return;
      stopForwards = new AbortController();
      const s = createServer({ headersTimeout: EGRESS_LIMITS.headersTimeoutMs, requestTimeout: EGRESS_LIMITS.requestTimeoutMs, maxHeaderSize: EGRESS_LIMITS.maxHeaderSize }, onRequest);
      s.maxConnections = EGRESS_LIMITS.maxConnections;
      s.on('connect', onConnect);
      // Which side ended first: our finish before the client's FIN, or a close with no FIN at all, is a close the server made.
      s.on('connection', socket => {
        let clientFirst = null;
        socket.on('end', () => { clientFirst ??= true; });
        socket.on('finish', () => { clientFirst ??= false; });
        socket.on('close', () => { lastCloseAt = monotonicNow(); if (clientFirst !== true && !clientAskedClose.has(socket)) closeLog.push({ seq: ledger.lastSeq() }); });
      });
      s.on('clientError', (_error, socket) => { record({ kind: 'malformed' }); socket.destroy(); });
      s.on('drop', () => { record({ kind: 'dropped' }); });
      // [::1] (egress-recorder/10): its own listener hands each connection to the HTTP server, so the parser, the connections list, the
      // timeouts and the close log treat it as one to 127.0.0.1. Its connection limit is its own, and a drop there is recorded the same way.
      const v6 = createNetServer(socket => s.emit('connection', socket));
      v6.maxConnections = EGRESS_LIMITS.maxConnections;
      v6.on('drop', () => { record({ kind: 'dropped' }); });
      await listenExclusive(s, cfg.port, SINK_ADDRESSES[0]);
      try { await listenExclusive(v6, cfg.port, SINK_ADDRESSES[1]); } catch (error) { await new Promise(resolve => s.close(() => resolve())); throw error; }
      // The server's connections list exists once it listens, before any connection is accepted.
      const connections = s[Object.getOwnPropertySymbols(s).find(k => k.description === 'http.server.connections')];
      requestArriving = typeof connections?.active === 'function' ? () => connections.active().length > 0 : null;
      for (const listener of [s, v6]) { listener.on('error', () => ledger.down()); listener.on('close', () => ledger.down()); }
      server = s; server6 = v6; ledger.started(); readBack?.started();
      // R1: the request feed's start read (its history, up to a signed head), before any check. A feed that cannot be read decides nothing.
      if (feed) await feed.start();
    },
    // Each mark also notes whether a request was arriving then, for a run-end (final) collection made after it.
    async mark() {
      const mark = ledger.position(), arriving = requestArriving ? requestArriving() : null;
      arrivingAtMark.set(mark, arriving); closesAtMark.set(mark, closeLog.length); clearAtMark.set(mark, mark.ok === true && arriving === false && ledger.notDone() === 0);
      return mark;
    },
    // Coverage v2 Part D. markClear: at this mark no request was arriving (the parser state readable) and no record was pending.
    markClear(mark) { return clearAtMark.get(mark) === true; },
    // The drain's own cap: the collect's witness wait and quiet cap, or the longest declared forward timeout and a margin.
    drainCapMs() { return Math.max(cfg.witnessWaitMs + 10 * cfg.quietMs, ...[...byHost.values()].map(d => (d?.forward?.timeoutMs ?? 0) + cfg.quietMs + 100)); },
    // Wait, at most capMs, until no request is arriving, no record is pending and quietMs has passed since the latest arrival,
    // forward settle or reply. An unreadable parser state is never quiescent. closedAfterCollect: see above.
    async drain({ capMs }) {
      const began = monotonicNow(), result = quiescent => ({ quiescent, waitedMs: monotonicNow() - began, closedAfterCollect: closedAfterCollect() });
      const settled = () => requestArriving() === false && ledger.notDone() === 0;
      const quiet = () => monotonicNow() - Math.max(ledger.lastArrival(), lastSettleAt, lastReplyAt, lastCloseAt) >= cfg.quietMs;
      if (!(capMs > 0) || requestArriving === null) return result(false);
      while (true) {
        if (!ledger.up()) return result(false);
        if (settled() && quiet()) {
          // Bytes already read off a socket but not yet parsed are handled in the next turn: look once more after it, quiet included
          // (egress-recorder/12: a request read, recorded and answered in that turn is an arrival, so the quiet period starts again).
          await (typeof drainTurn === 'function' ? drainTurn() : new Promise(resolve => setImmediate(resolve)));
          if (settled() && quiet() && ledger.up()) return result(true);
        }
        if (!(monotonicNow() - began < capMs)) return result(false);
        await new Promise(resolve => setTimeout(resolve, Math.min(SINK_LEDGER_LIMITS.pollMs, Math.max(1, capMs - (monotonicNow() - began)))));
      }
    },
    closedAfterCollect() { return closedAfterCollect(); },
    // In-doubt resolution R1 (egress-recorder/8): the connector's run-end resolver read, after the final mark, within capMs. The feed is read to a
    // fresh signed head, then each send to a feed host that is still in doubt, connected and carries a keyed record gets one { seq, records:
    // [{ resolver: 'r1', read }] } (src/request-feed-rules.mjs validRequestFeedRead); src/in-doubt.mjs keeps only those R1 applies to. No feed: [].
    // R2 (egress-recorder/9): with read-back declared, the reader's run-end reads within the same cap, beside the feed's.
    async resolutionRecords(_mark, { capMs = REQUEST_FEED_READ_MS } = {}) {
      const r1 = async () => {
        if (!feed) return [];
        const state = await feed.readToHead({ capMs });
        return feedSends.filter(r => r.done && r.upstream?.outcome === 'unknown' && r.upstream.transport?.connected === true && r.idem && ['keyed', 'overlap'].includes(r.idem.status) && r.idem.key !== null)
          .map(r => ({ seq: r.seq, records: [{ resolver: 'r1', read: { ...state, key: r.idem.key, ...feed.keyRead(r.idem.key, { fold: r.idem.fold, resource: r.resource, tenant: r.tenant }), keySends: foldSends.get(r.idemSlot) ?? 0, dirtySends: dirtySends.get(r.host)?.size ?? 0 } }] }));
      };
      const [one, two] = await Promise.all([r1(), readBack ? readBack.records({ capMs }) : []]);
      return [...one, ...two];
    },
    // Per declared signing destination, whether each secret slot was usable when the recorder was built: { [host]: { scheme, usable } }.
    // Booleans only; never a key or anything derived from one.
    signingRecord() { return Object.fromEntries([...signingSlots].map(([host, slots]) => [host, { scheme: byHost.get(host).idempotency.signing.scheme, usable: slots.map(slot => slot.usable) }])); },
    // gap: a settlement gap window (sink-ledger.mjs), an exact range collected after the run. final: the run-end window
    // (background attribution, src/http-attribution.mjs): nothing follows it, so a request arriving at its end mark, or
    // still arriving when it is collected, leaves it partial.
    // scoped (coverage v2, the HTTP connector's check windows only): problem units become destination-scoped entries where
    // that is sound (classify, below); gap, barrier and run-end windows, and every caller without it, are exactly v1.
    async collect(from, to, { gap = false, final = false, scoped = false } = {}) {
      const v2 = scoped && !gap;
      const w = await ledger.window(from, to, { witness: cfg.witness !== null, witnessWaitMs: cfg.witnessWaitMs, quietMs: cfg.quietMs, gap, scopedUnits: v2 });
      if (w.failed) return { events: [], coverage: 'failed', reason: w.failed };
      const { problems } = w, events = [];
      if ((!gap || final) && !requestArriving) problems.add('egress-parser-state-unavailable');
      else if ((!gap || final) && (requestArriving() || (final && arrivingAtMark.get(to) !== false))) problems.add(v2 ? 'egress-connection-mid-request' : 'egress-request-in-flight');
      for (const r of w.items) {
        if (r.hostMismatch) problems.add('egress-host-mismatch');
        if (r.addressLiteral) problems.add('egress-address-literal');
        if (r.tunnel) problems.add('egress-tunnel-payload-unseen');
        if (r.overLimit) problems.add('egress-body-over-limit');
        if (r.aborted) problems.add('egress-request-incomplete');
        if (r.pathAmbiguous && !v2) problems.add('egress-path-ambiguous');
        // FIX-04 option 1: outside a scoped check window, a send that may be a declared provider under another name leaves the window partial.
        if (r.siblingOf && !v2) problems.add('egress-undeclared-sibling-host');
        // A host longer than an event name can hold (128) is never an event: shortened, it could read as another (declared) host.
        if (r.host.length > 128) { problems.add('egress-host-over-limit'); continue; }
        if (events.length >= 5000) { problems.add('egress-event-limit'); continue; }
        events.push(makeEffect({ source: 'http-egress', observer, seq: r.seq, actor: null, operation: 'send', name: r.host, resource: r.resource,
          outcome: r.overLimit || r.aborted ? 'unknown' : r.outcome, correlation: r.token ? { settlementToken: r.token } : {}, content: { target: r.target, body: r.body ?? null, bodyBytes: r.bodyBytes }, ...(r.captured ? { captured: r.captured } : {}),
          ...(r.idem ? { idempotency: keyRecord(r) } : {}), ...(r.upstream ? { upstream: r.upstream } : {}) }));
      }
      if (!v2) {
        const reason = problems.size ? [...problems].sort().join(',').slice(0, 200) : null;
        return { events, coverage: reason ? 'partial' : 'complete', reason };
      }
      // Coverage v2 classification. A unit is a scoped entry { name, resource, codes } (plus seq and captured, below) only when its host is a declared
      // destination, it carries none of the flags that could hide another host's request (host mismatch, address literal,
      // tunnel, over-limit body, aborted), it is not a witness unit, the recorder read the whole request (a done unit, or a
      // pending forward whose request ended), and no close was logged since the window's start mark (a mark this recorder did not
      // make reads closed). Everything else adds a
      // window-wide code of its own, so scoped entries appear only on a window with no window-wide code.
      const closed = !closesAtMark.has(from) || closeLog.length > closesAtMark.get(from);
      const entries = new Map();
      const classify = (r, late) => {
        const own = [r.hostMismatch && 'egress-host-mismatch', r.addressLiteral && 'egress-address-literal', r.tunnel && 'egress-tunnel-payload-unseen', r.overLimit && 'egress-body-over-limit', r.aborted && 'egress-request-incomplete',
          late === 'pending' && !r.forwarding && 'egress-request-unfinished'].filter(Boolean);
        if (own.length || !byHost.has(r.host) || r.host === cfg.witness?.host || (r.witnessNonces?.length ?? 0) > 0 || closed) { for (const c of own.length ? own : ['egress-scope-ineligible']) problems.add(c); if (r.pathAmbiguous) problems.add('egress-path-ambiguous'); return; }
        const codes = [late === 'deferred' && 'egress-request-after-witness-request', late === 'pending' && 'egress-request-in-flight', r.pathAmbiguous && 'egress-path-ambiguous'].filter(Boolean);
        if (!codes.length) return;
        const resource = r.pathAmbiguous ? null : r.resource, key = `${r.host}\n${resource}`;
        const entry = entries.get(key) ?? { name: r.host.slice(0, 128), resource, codes: new Set(), units: [] };
        codes.forEach(c => entry.codes.add(c)); entry.units.push({ r, late }); entries.set(key, entry);
      };
      for (const r of w.items) if (r.pathAmbiguous) classify(r, null);
      // FIX-04 option 1: a completed in-window send to an undeclared sibling host is an entry for each declared destination it may be (its
      // resource read on that destination's paths, null when they disagree raw and decoded); its own event stays as recorded.
      for (const r of w.items) for (const s of r.siblingOf ?? []) {
        const resource = s.ambiguous ? null : s.resource, key = `${s.host}\n${resource}`;
        const entry = entries.get(key) ?? { name: s.host, resource, codes: new Set(), units: [] };
        entry.codes.add('egress-undeclared-sibling-host'); if (s.ambiguous) entry.codes.add('egress-path-ambiguous');
        entry.units.push({ r, late: null }); entries.set(key, entry);
      }
      for (const r of w.deferred) classify(r, 'deferred');
      for (const r of w.pending) classify(r, 'pending');
      if (entries.size > 32) problems.add('egress-scope-limit');
      if (problems.size) return { events, coverage: 'partial', reason: [...problems].sort().join(',').slice(0, 200) };
      if (!entries.size) return { events, coverage: 'complete', reason: null };
      // LATE-FIELDS (egress-recorder/4): an entry that is exactly one completed after-witness request, not path-ambiguous, on a host
      // that declares capture carries that record's ledger seq and captured fields (src/effect-events.mjs validScoped binds them).
      // An entry with a second unit of any kind carries neither.
      const lone = e => e.units.length === 1 && e.units[0].late === 'deferred' && !e.units[0].r.pathAmbiguous && e.units[0].r.captured ? e.units[0].r : null;
      const list = [...entries.values()].map(e => { const r = lone(e); return { name: e.name, resource: e.resource, codes: [...e.codes].sort(), ...(r ? { seq: r.seq, captured: r.captured } : {}) }; })
        .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : String(a.resource) < String(b.resource) ? -1 : String(a.resource) > String(b.resource) ? 1 : 0));
      if (list.some(e => e.codes.includes('egress-request-after-witness-request') || e.codes.includes('egress-request-in-flight'))) lateSince ??= closeLog.length;
      return { events, coverage: 'partial', reason: [...new Set(list.flatMap(e => e.codes))].sort().join(','), scoped: list };
    },
    async stop() {
      const s = server, v6 = server6; server = null; server6 = null; ledger.stopped(); stopForwards.abort();
      await feed?.stop(); readBack?.stop();
      // Signing keys are cleared for good: a restarted recorder verifies nothing (a zeroed key is the empty key, which anyone can use).
      signingClosed = true;
      for (const slots of signingSlots.values()) for (const slot of slots) slot.key.fill(0);
      // Every connection either listener accepted is in the HTTP server's list, so closeAllConnections ends them all.
      if (s) await Promise.all([new Promise(resolve => v6.close(() => resolve())), new Promise(resolve => { s.close(() => resolve()); s.closeAllConnections(); })]);
    },
  };
}
