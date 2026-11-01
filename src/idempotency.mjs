// Keyed retries (W6). Pure: no I/O.
//
// An egress destination may declare `idempotency`: the request header carrying the key its provider dedupes by
// (Idempotency-Key, PayPal-Request-Id, a webhook event id), or a JSON pointer to the event id in the request body (an outbox
// or webhook payload's id). The recorder never forwards, so an application is what
// the declared provider would do with the bytes the recorder received: a send whose exact key, content and headers
// repeat a send already made under that key is the same application, and anything else counts on its own.
//
// The recorder stores on each send to such a destination a record { status, key, fold, head, firstSeq, signed? }:
//   key      - a salted digest of the host and the exact key (never the key itself)
//   fold     - a salted digest of the host and the key with one pair of surrounding quotes removed and ASCII lowercased
//   head     - a salted digest of the method, the raw request target and every header except the key header, the
//              destination's correlation header, the declared volatile headers and the transport headers (a declared
//              signature or timestamp header only when its scheme's values parsed, signedHead)
//   firstSeq - the earliest seq at which the recorder saw the key's fold, or a send to the host whose key it could not
//              read, over the whole run (so a key used before this window is visible to it)
//   signed   - only on a destination that declares a timestamped signature scheme's header volatile: per such scheme,
//              { t, mac } (the signing timestamp and a salted digest of the MAC) when its values parsed, or null
//   signing  - only on a destination that declares verified signature headers (idempotency.signing, below): { scheme,
//              verified, t, at }, where verified is true only when the recorder verified the send under exactly one declared
//              secret (t the signing timestamp, at the arrival second), false when it did not, and null when the send carried no
//              signature header. No secret, MAC or anything derived from a secret is ever recorded.
// An effect.count clause opts in with countBy: "idempotency-key" (countApplications). Nothing else changes:
// effect.none, effect.exists, effect.only and claim rules still count every send.
//
// Allowlist for a decided count: a key group collapses to one application only when every send to the host in the
// window has a readable key or a definite absence, every member carries the same exact key, content, head and
// settlement token, no two members were in flight at once, and the key's first use is in this window. Every other
// group counts as an interval [low, high]; a pass needs low === high === expected, and a fail needs expected outside it.
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { digest } from './domain.mjs';
import { readJsonBody, pointerTokens } from './body-fields.mjs';
// In-doubt resolution (IDR-1): the fate a resolved clause reads (src/in-doubt.mjs fateOf).
import { fateOf, inDoubtAttempt } from './in-doubt.mjs';
// The key collapse's identity and retention rule (src/key-identity.mjs, shared with R1 in src/request-feed-rules.mjs), and the timestamped
// signature schemes it reads.
import { IDEMPOTENCY_SIGNATURE_SCHEMES, declaredSchemes, keyGroupIdentity } from './key-identity.mjs';
export { IDEMPOTENCY_SIGNATURE_SCHEMES };

export const IDEMPOTENCY_BOUNDS = Object.freeze({ keyChars: 255, headerChars: 64, methods: 4, volatile: 8, scopeHosts: 64, keysPerRecorder: 20000, maxBytes: Object.freeze([1024, 65536]), defaultMaxBytes: 16384 });
export const IDEMPOTENCY_METHODS = Object.freeze(['POST', 'PUT', 'PATCH', 'DELETE']);
// Names a key header may not take: identity, framing, routing, tracing and method override.
export const IDEMPOTENCY_RESERVED_HEADERS = Object.freeze(['host', 'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'content-type', 'content-length', 'content-encoding', 'transfer-encoding',
  'connection', 'keep-alive', 'proxy-connection', 'te', 'trailer', 'upgrade', 'expect', 'traceparent', 'tracestate', 'baggage', 'x-http-method-override', 'x-http-method', 'x-method-override']);
// The only names that may be declared volatile (left out of head): tracing, SDK retry counters and Date. No provider keys on them.
export const IDEMPOTENCY_VOLATILE_HEADERS = Object.freeze(['b3', 'baggage', 'date', 'sentry-trace', 'traceparent', 'tracestate', 'x-amzn-trace-id', 'x-b3-flags', 'x-b3-parentspanid', 'x-b3-sampled', 'x-b3-spanid', 'x-b3-traceid',
  'x-cloud-trace-context', 'x-datadog-origin', 'x-datadog-parent-id', 'x-datadog-sampling-priority', 'x-datadog-trace-id', 'x-stainless-retry-count', 'x-stainless-timeout', 'x-stripe-client-telemetry']);
// Webhook signature and timestamp headers a sender recomputes on every redelivery: each is a timestamp or a MAC over the body, which
// contentDigest binds on its own, so leaving one out of head never hides a changed payload or target. Also declarable as volatile,
// but none leaves head unconditionally: see the two lists below.
export const IDEMPOTENCY_SIGNATURE_HEADERS = Object.freeze(['stripe-signature', 'svix-signature', 'svix-timestamp', 'webhook-signature', 'webhook-timestamp', 'x-hub-signature', 'x-hub-signature-256',
  'x-shopify-hmac-sha256', 'x-slack-request-timestamp', 'x-slack-signature', 'x-twilio-signature', 'x-zm-request-timestamp', 'x-zm-signature']);
const DECLARABLE_VOLATILE = [...IDEMPOTENCY_VOLATILE_HEADERS, ...IDEMPOTENCY_SIGNATURE_HEADERS];
// MACs with no timestamp (GitHub, Shopify, Twilio): a redelivery under one secret of the same body (and URL) repeats the value
// exactly, so leaving one out of head could only ever merge two sends signed under different secrets. Still declarable, so
// profiles keep loading, but always kept in head; the idempotency limitation says so.
export const IDEMPOTENCY_UNTIMED_SIGNATURE_HEADERS = Object.freeze(['x-hub-signature', 'x-hub-signature-256', 'x-shopify-hmac-sha256', 'x-twilio-signature']);
// A signing timestamp is plausible from beforeStart seconds before the recorder started to afterArrival seconds after the send arrived.
export const IDEMPOTENCY_SIGNATURE_WINDOW = Object.freeze({ beforeStart: 300, afterArrival: 60 });
// Verified signature headers (b', HMAC-SIG-DESIGN.md and its addendum R1). A destination may declare
//   idempotency.signing: { scheme, signature, timestamp?, id?, dedupeSeconds?, secretEnv: [name, ...] }
// with one scheme from this menu, the header names the sender uses, and 1 to 4 SCOPEHAVEN_TARGET_ variables holding the secrets
// the destination verifies this URL with. The recorder reads them once and verifies each send (HMAC-SHA256) on the raw body bytes
// it received; the scheme's signature and timestamp headers leave head only when every signature entry matches exactly one
// usable declared secret, the timestamp is in the run window (IDEMPOTENCY_SIGNATURE_WINDOW, on the injected signing clock) and the
// request has no trailers. The head then names that secret's slot and the entry count, so sends verified under different secrets
// never compare equal, and anything that did not verify keeps its raw values bound. The menu:
//   stripe             one header: "t=" and a Unix time, then 1 to 4 ",v1=" and 64 lowercase hex (no v0); message "<t>.<body>";
//                      key: the secret's UTF-8 bytes as given
//   standard-webhooks  Standard Webhooks and Svix: id, timestamp and signature headers; the signature is 1 to 4 space-separated
//                      "v1," and base64 of 32 bytes; message "<id>.<t>.<body>"; key: the secret without an optional "whsec_" prefix,
//                      base64-decoded (16 to 64 bytes)
//   slack-v0           Slack and Zoom: timestamp and signature headers; "v0=" and 64 lowercase hex; message "v0:<t>:<body>"; key: the
//                      secret's UTF-8 bytes
// MACs with no timestamp (GitHub, Shopify, Twilio) are not offered: under one secret a redelivery repeats them exactly, so
// verifying could only ever merge sends signed under different secrets.
export const IDEMPOTENCY_SIGNING_SCHEMES = Object.freeze({
  stripe: Object.freeze({ timestamp: false, id: false }),
  'standard-webhooks': Object.freeze({ timestamp: true, id: true }),
  'slack-v0': Object.freeze({ timestamp: true, id: false }),
});
// secrets per destination and per recorder; key bytes after the scheme's decoding; how long the receiver keeps a key after the first
// delivery's signing timestamp (dedupeSeconds, the collapse bound); signature entries in one header.
export const SIGNING_BOUNDS = Object.freeze({ secrets: 4, secretsPerRecorder: 16, keyBytes: Object.freeze([16, 256]), standardKeyBytes: Object.freeze([16, 64]),
  dedupeSeconds: Object.freeze([1, 86400]), defaultDedupeSeconds: 300, entries: 4 });
// Always left out of head: connection-specific (RFC 9110 7.6.1) or framing the body digest already covers.
export const IDEMPOTENCY_TRANSPORT_HEADERS = Object.freeze(['connection', 'keep-alive', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length', 'expect']);
export const IDEMPOTENCY_STATUSES = Object.freeze(['keyed', 'overlap', 'absent', 'not-applicable', 'method-undeclared', 'repeated', 'malformed', 'over-cap', 'unreadable', 'untracked']);
// A send whose key could not be read: it may have used any key.
export const IDEMPOTENCY_DIRTY = Object.freeze(['method-undeclared', 'repeated', 'malformed', 'over-cap', 'unreadable', 'untracked']);
export const IDEMPOTENCY_REASONS = Object.freeze(['idempotency-key-unrecorded', 'idempotency-key-earlier-use', 'idempotency-key-content-differs', 'idempotency-key-variant', 'idempotency-key-concurrent',
  'idempotency-key-outcome-unknown', 'idempotency-key-method-undeclared', 'idempotency-key-repeated', 'idempotency-key-malformed', 'idempotency-key-over-cap', 'idempotency-key-unreadable', 'idempotency-key-untracked']);
export const IDEMPOTENCY_BASIS = Object.freeze({
  'idempotency-key-unrecorded': 'a send to the host carries no key record, or the observer does not record keys for it',
  'idempotency-key-earlier-use': 'a key, or a send whose key could not be read, was seen before this window, so a send here may repeat an earlier application',
  'idempotency-key-content-differs': 'sends under one key differ in content, target or headers, which a provider may apply, reject or replay',
  'idempotency-key-variant': 'keys differ only in letter case or quotes, which a provider may or may not treat as one key',
  'idempotency-key-concurrent': 'sends under one key were in flight at the same time',
  'idempotency-key-outcome-unknown': 'the forwarding upstream\'s outcome of a send is not proven applied or a declared rejection',
  'idempotency-key-method-undeclared': 'a send carried the key header on a method the declaration does not key, which the provider may key',
  'idempotency-key-repeated': 'a send carried the key header more than once',
  'idempotency-key-malformed': 'a send carried an empty key or one with spaces, controls or non-ASCII characters',
  'idempotency-key-over-cap': 'a send carried a key over 255 characters',
  'idempotency-key-unreadable': 'a send to the host was cut off, over the body limit or a tunnel, so its key was not read',
  'idempotency-key-untracked': 'the recorder\'s key store was full, so a key was not tracked',
});
export const COUNT_BY = Object.freeze(['idempotency-key']);
const DIRTY_REASON = Object.freeze({ 'method-undeclared': 'idempotency-key-method-undeclared', repeated: 'idempotency-key-repeated', malformed: 'idempotency-key-malformed', 'over-cap': 'idempotency-key-over-cap', unreadable: 'idempotency-key-unreadable', untracked: 'idempotency-key-untracked' });

const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const HEADER = /^[a-z0-9][a-z0-9-]{0,63}$/;
const HEX = /^[a-f0-9]{64}$/;
const KEY = /^[\x21-\x7e]{1,255}$/;
const distinctStrings = (list, max) => Array.isArray(list) && list.length <= max && list.every(x => typeof x === 'string') && new Set(list).size === list.length;

const SIGNING_KEYS = ['scheme', 'signature', 'timestamp', 'id', 'dedupeSeconds', 'secretEnv'];
// The dedicated credential namespace (the same rule as CREDENTIAL_ENV in src/effect-events.mjs).
const SIGNING_ENV = /^SCOPEHAVEN_TARGET_[A-Z0-9_]{1,110}$/;
// A destination's `idempotency.signing`, normalized: { scheme, signature, timestamp, id, dedupeSeconds, secretEnv } (timestamp and id
// null where the scheme has none; secretEnv in declared order, which numbers the slots). Header names are refused only to stop
// configuration mistakes; the safety argument never rests on a name.
function validateSigning(s, { header, correlationHeader, volatile }) {
  if (!plain(s) || Object.keys(s).some(key => !SIGNING_KEYS.includes(key))) throw new Error(`"idempotency.signing" is { ${SIGNING_KEYS.join(', ')} } (scheme, signature and secretEnv required)`);
  if (typeof s.scheme !== 'string' || !Object.hasOwn(IDEMPOTENCY_SIGNING_SCHEMES, s.scheme)) throw new Error(`"idempotency.signing.scheme" is one of ${Object.keys(IDEMPOTENCY_SIGNING_SCHEMES).join(', ')}`);
  const form = IDEMPOTENCY_SIGNING_SCHEMES[s.scheme];
  if (form.timestamp !== Object.hasOwn(s, 'timestamp')) throw new Error(form.timestamp ? `"idempotency.signing.timestamp" names the ${s.scheme} timestamp header` : `"idempotency.signing" for ${s.scheme} takes no "timestamp": the timestamp is inside the signature header`);
  if (form.id !== Object.hasOwn(s, 'id')) throw new Error(form.id ? `"idempotency.signing.id" names the ${s.scheme} message id header` : `"idempotency.signing" for ${s.scheme} takes no "id"`);
  const signed = [s.signature, ...(form.timestamp ? [s.timestamp] : [])], names = [...signed, ...(form.id ? [s.id] : [])];
  if (!names.every(n => typeof n === 'string' && HEADER.test(n))) throw new Error('"idempotency.signing" names its headers in lowercase: 1 to 64 letters, digits and hyphens');
  if (new Set(names).size !== names.length) throw new Error('"idempotency.signing" names its signature, timestamp and id headers once each');
  const correlation = typeof correlationHeader === 'string' ? correlationHeader.toLowerCase() : null;
  const misnamed = n => IDEMPOTENCY_RESERVED_HEADERS.includes(n) || IDEMPOTENCY_VOLATILE_HEADERS.includes(n) || IDEMPOTENCY_UNTIMED_SIGNATURE_HEADERS.includes(n) || n.includes('scopehaven') || n === correlation;
  if (signed.some(n => misnamed(n) || n === header) || (form.id && misnamed(s.id))) throw new Error('"idempotency.signing" cannot name the key, correlation, identity, framing, tracing, untimed MAC or scopehaven header as its signature or timestamp header, nor its id header as anything but the key');
  if (names.some(n => volatile.includes(n))) throw new Error('a header in "idempotency.signing" cannot also be "volatile"');
  if (declaredSchemes(volatile).length) throw new Error('a destination declares one signature route: "idempotency.signing" (recommended) or a timestamped signature header in "volatile", never both');
  const dedupeSeconds = Object.hasOwn(s, 'dedupeSeconds') ? s.dedupeSeconds : SIGNING_BOUNDS.defaultDedupeSeconds;
  if (!Number.isInteger(dedupeSeconds) || dedupeSeconds < SIGNING_BOUNDS.dedupeSeconds[0] || dedupeSeconds > SIGNING_BOUNDS.dedupeSeconds[1]) throw new Error('"idempotency.signing.dedupeSeconds" is an integer from 1 to 86400: how long the destination keeps a key after the first delivery\'s signing timestamp');
  if (!distinctStrings(s.secretEnv, SIGNING_BOUNDS.secrets) || !s.secretEnv.length || !s.secretEnv.every(n => SIGNING_ENV.test(n))) throw new Error('"idempotency.signing.secretEnv" lists 1 to 4 distinct SCOPEHAVEN_TARGET_ variables holding the secrets the destination verifies this URL with');
  return { scheme: s.scheme, signature: s.signature, timestamp: form.timestamp ? s.timestamp : null, id: form.id ? s.id : null, dedupeSeconds, secretEnv: [...s.secretEnv] };
}
// A destination's `idempotency`: { header | pointer, methods?, volatile?, maxBytes? (pointer only), signing? }. Returns the normalized
// declaration { header, pointer, methods, volatile, maxBytes }, with null for the source not declared, and signing only when declared.
export function validateIdempotencyDeclaration(decl, { correlationHeader = null, maxBodyBytes = Infinity } = {}) {
  if (!plain(decl) || Object.keys(decl).some(key => !['header', 'pointer', 'methods', 'volatile', 'maxBytes', 'signing'].includes(key))) throw new Error('a destination\'s "idempotency" is { header or pointer, methods?, volatile?, maxBytes?, signing? }');
  if (Object.hasOwn(decl, 'header') === Object.hasOwn(decl, 'pointer')) throw new Error('"idempotency" declares exactly one key source: "header" or "pointer" (a JSON pointer to the id in the request body)');
  if (Object.hasOwn(decl, 'header') ? typeof decl.header !== 'string' : typeof decl.pointer !== 'string') throw new Error('"idempotency.header" or "idempotency.pointer" names the key source as a string: a header name or a JSON pointer');
  const header = decl.header ?? null, pointer = decl.pointer ?? null;
  if (header !== null && (typeof header !== 'string' || !HEADER.test(header))) throw new Error('"idempotency.header" is a lowercase header name of 1 to 64 letters, digits and hyphens');
  if (header !== null && (IDEMPOTENCY_RESERVED_HEADERS.includes(header) || DECLARABLE_VOLATILE.includes(header) || header.includes('scopehaven') || header === correlationHeader)) throw new Error('"idempotency.header" cannot name an identity, framing, routing, tracing, signature, method-override, volatile, correlation or scopehaven header');
  if (pointer !== null) { try { pointerTokens(pointer); } catch (error) { throw new Error(`"idempotency.pointer": ${error.message}`); } }
  if (header !== null && Object.hasOwn(decl, 'maxBytes')) throw new Error('"idempotency.maxBytes" bounds a body key: declare it only with "pointer"');
  const maxBytes = pointer === null ? null : decl.maxBytes ?? Math.min(IDEMPOTENCY_BOUNDS.defaultMaxBytes, maxBodyBytes);
  if (maxBytes !== null && (!Number.isInteger(maxBytes) || maxBytes < IDEMPOTENCY_BOUNDS.maxBytes[0] || maxBytes > IDEMPOTENCY_BOUNDS.maxBytes[1] || maxBytes > maxBodyBytes)) throw new Error('"idempotency.maxBytes" is an integer from 1024 to 65536 and no more than the recorder\'s maxBodyBytes');
  const methods = decl.methods ?? ['POST'];
  if (!distinctStrings(methods, IDEMPOTENCY_BOUNDS.methods) || !methods.length || !methods.every(m => IDEMPOTENCY_METHODS.includes(m))) throw new Error('"idempotency.methods" lists 1 to 4 distinct of POST, PUT, PATCH, DELETE');
  const volatile = decl.volatile ?? [];
  if (!distinctStrings(volatile, IDEMPOTENCY_BOUNDS.volatile) || !volatile.every(v => DECLARABLE_VOLATILE.includes(v)) || volatile.includes(correlationHeader)) throw new Error(`"idempotency.volatile" lists up to 8 distinct of ${DECLARABLE_VOLATILE.join(', ')}`);
  // The correlation header always leaves head, so it may not be a signature or timestamp header: those leave only as signedHead
  // allows (an untimed MAC never).
  if (typeof correlationHeader === 'string' && IDEMPOTENCY_SIGNATURE_HEADERS.includes(correlationHeader.toLowerCase())) throw new Error('a destination that declares "idempotency" cannot name a webhook signature or timestamp header as its correlation header');
  const normalized = { header, pointer, methods: IDEMPOTENCY_METHODS.filter(m => methods.includes(m)), volatile: [...volatile].sort(), maxBytes };
  return decl.signing === undefined ? normalized : { ...normalized, signing: validateSigning(decl.signing, { header, correlationHeader, volatile }) };
}
// The published form of a normalized declaration (an observer scope, a run's declared observer record, the exported suite): the
// same, except that signing names how many secrets it declares (secrets), never their variables, as forward publishes only whether
// it has a proof (src/effect-outcome.mjs). A declaration without signing is returned as it is.
export function publishIdempotency(decl) {
  if (!plain(decl?.signing)) return decl;
  const { secretEnv, ...signing } = decl.signing;
  return { ...decl, signing: { ...signing, secrets: secretEnv.length } };
}
// A published map { [host]: published declaration } (an observer scope, or a run's declared observer record).
export function validIdempotencyMap(map) {
  if (!plain(map)) return false;
  const entries = Object.entries(map);
  if (entries.length < 1 || entries.length > IDEMPOTENCY_BOUNDS.scopeHosts) return false;
  return entries.every(([host, decl]) => {
    if (typeof host !== 'string' || !host.length || host.length > 253 || !plain(decl)) return false;
    const source = decl.header !== null ? { header: decl.header } : { pointer: decl.pointer, maxBytes: decl.maxBytes };
    let signing = {};
    if (Object.hasOwn(decl, 'signing')) {
      const s = decl.signing;
      if (!plain(s) || !Number.isInteger(s.secrets) || s.secrets < 1 || s.secrets > SIGNING_BOUNDS.secrets) return false;
      // The variables are not published: placeholders stand in for them, so only their number is checked.
      signing = { signing: { scheme: s.scheme, signature: s.signature, ...(s.timestamp !== null ? { timestamp: s.timestamp } : {}), ...(s.id !== null ? { id: s.id } : {}), dedupeSeconds: s.dedupeSeconds,
        secretEnv: Array.from({ length: s.secrets }, (_, i) => `SCOPEHAVEN_TARGET_SIGNING_SLOT_${i + 1}`) } };
    }
    try { return digest(publishIdempotency(validateIdempotencyDeclaration({ ...source, methods: decl.methods, volatile: decl.volatile, ...signing }))) === digest(decl); } catch { return false; }
  });
}
// The published map of a raw profile egress-recorder observer, or null when no destination declares idempotency.
export function idempotencyRecordOf(o) {
  const destinations = o?.type === 'egress-recorder' && Array.isArray(o.destinations) ? o.destinations.filter(d => d?.idempotency !== undefined) : [];
  if (!destinations.length) return null;
  return Object.fromEntries(destinations.map(d => [d.host, publishIdempotency(validateIdempotencyDeclaration(d.idempotency, { correlationHeader: d.correlation?.header ?? null, maxBodyBytes: o.maxBodyBytes ?? 1024 * 1024 }))]));
}

// The key a request carries: { status, value }. value is the raw key, which the recorder seals at once and never stores.
export function readIdempotencyKey({ declaration, method, rawHeaders }) {
  const values = [];
  const list = Array.isArray(rawHeaders) ? rawHeaders : [];
  for (let i = 0; i + 1 < list.length; i += 2) if (String(list[i]).toLowerCase() === declaration.header) values.push(String(list[i + 1]));
  // A method the declaration does not key: a definite application only without the key header (a read method never applies).
  if (!declaration.methods.includes(method)) return { status: values.length && !['GET', 'HEAD', 'OPTIONS'].includes(method) ? 'method-undeclared' : 'not-applicable', value: null };
  if (!values.length) return { status: 'absent', value: null };
  if (values.length > 1) return { status: 'repeated', value: null };
  if (values[0].length > IDEMPOTENCY_BOUNDS.keyChars) return { status: 'over-cap', value: null };
  if (!KEY.test(values[0])) return { status: 'malformed', value: null };
  return { status: 'keyed', value: values[0] };
}
// The key a request body carries at the declared pointer: { status, value }, read with the capture rules (readJsonBody). A body
// that cannot be read is unreadable, never absent; a value that is not a string of visible ASCII (a number included) is malformed.
export function readBodyKey({ declaration, method, rawHeaders, buffer, bodyBytes }) {
  const read = () => {
    // A leading byte-order mark: the UTF-8 decoder strips it, but strict receivers (Go, JSON.parse on the raw text) refuse the body.
    if (buffer && buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) return { status: 'unreadable', value: null };
    const body = readJsonBody({ rawHeaders, buffer, bodyBytes, maxBytes: declaration.maxBytes });
    if (body.status === 'no-body') return { status: 'absent', value: null };
    if (body.status !== 'parsed') return { status: 'unreadable', value: null };
    let value = body.root;
    for (const token of pointerTokens(declaration.pointer)) {
      if (Array.isArray(value)) { if (!/^(0|[1-9][0-9]{0,8})$/.test(token) || Number(token) >= value.length) return { status: 'absent', value: null }; value = value[Number(token)]; }
      else if (value !== null && typeof value === 'object') {
        // Receivers that match keys case-insensitively (Go encoding/json, ASP.NET Core) may bind a case or NFKC variant instead.
        const fold = k => k.normalize('NFKC').toLowerCase();
        if (Object.keys(value).some(k => k !== token && fold(k) === fold(token))) return { status: 'unreadable', value: null };
        if (!Object.hasOwn(value, token)) return { status: 'absent', value: null };
        value = value[token];
      } else return { status: 'absent', value: null };
    }
    if (typeof value !== 'string') return { status: 'malformed', value: null };
    if (value.length > IDEMPOTENCY_BOUNDS.keyChars) return { status: 'over-cap', value: null };
    return KEY.test(value) ? { status: 'keyed', value } : { status: 'malformed', value: null };
  };
  if (declaration.methods.includes(method)) return read();
  // A method the declaration does not key: a read method never applies; otherwise an id in the body may be keyed by the provider.
  if (['GET', 'HEAD', 'OPTIONS'].includes(method)) return { status: 'not-applicable', value: null };
  const r = read();
  return { status: r.status === 'absent' ? 'not-applicable' : r.status === 'keyed' ? 'method-undeclared' : r.status, value: null };
}
// A key's case and quote variants share one fold.
export const foldKey = value => (value.length >= 2 && value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value).replace(/[A-Z]/g, c => c.toLowerCase());
// The text head digests: method, raw target, then every header not excluded as [name, [values in arrival order]], sorted by name.
export function headText({ method, rawTarget, rawHeaders, exclude }) {
  const skip = new Set(exclude.map(name => String(name).toLowerCase()));
  const byName = new Map();
  const list = Array.isArray(rawHeaders) ? rawHeaders : [];
  for (let i = 0; i + 1 < list.length; i += 2) {
    const name = String(list[i]).toLowerCase();
    if (skip.has(name)) continue;
    if (!byName.has(name)) byName.set(name, []);
    byName.get(name).push(String(list[i + 1]));
  }
  return `${method}\n${rawTarget}\n${JSON.stringify([...byName.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))}`;
}

const UNIX = /^[1-9][0-9]{9}$/;
// "v1," and base64 of exactly 32 bytes: 43 characters, the last carrying two zero bits, then one "=".
const V1_BASE64 = /^v1,[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;
// A scheme's signature value as { t (stripe only, else null), entries, mac }, or null when it does not parse. Several signatures in one
// value (a secret rotation) parse only when every one does, up to four. Their labels and count enter head (signedHead), so two sends
// compare only with the same number and order of entries; a header with any other form stays bound.
function parseSignature(form, value) {
  if (form === 'v0') return /^v0=[0-9a-f]{64}$/.test(value) ? { t: null, entries: 'v0', mac: value } : null;
  if (form === 'v1-list') {
    const parts = value.split(' ');
    return parts.length <= 4 && parts.every(p => V1_BASE64.test(p)) ? { t: null, entries: parts.map(() => 'v1').join(' '), mac: value } : null;
  }
  const [first, ...rest] = value.split(',');
  const t = /^t=([1-9][0-9]{9})$/.exec(first);
  if (!t || !rest.length || rest.length > 4 || !rest.every(p => /^v[01]=[0-9a-f]{64}$/.test(p)) || !rest.some(p => p.startsWith('v1='))) return null;
  return { t: Number(t[1]), entries: rest.map(p => p.slice(0, 2)).join(','), mac: rest.join(',') };
}
// What a send's head leaves out for its declared volatile names: { exclude, marker, signed }. Tracing, retry-counter and Date names
// always leave; untimed MAC names never do. A timestamped scheme's declared headers leave only when the scheme parses: each of its
// headers appears exactly once, the signature parses and the timestamp (10 digits) is from IDEMPOTENCY_SIGNATURE_WINDOW.beforeStart
// seconds before the recorder started (startSec) to afterArrival seconds after the send arrived (nowSec). A scheme that does not
// parse keeps its declared headers in head with their values, and so does every scheme when startSec or nowSec is not an integer
// (a recorder without a signing clock). marker is a line the caller appends to the head text, naming each
// declared scheme with its parsed entries or null, so a send never compares equal to one whose scheme parsed differently or not at
// all; signed is { [scheme]: { t, mac } | null } with the raw MAC, which the recorder seals at once. With no timestamped scheme
// declared, marker is '' and signed is null, so the head text is the one headText alone gives.
export function signedHead({ declaration, rawHeaders, startSec, nowSec }) {
  const list = Array.isArray(rawHeaders) ? rawHeaders : [];
  const values = name => { const out = []; for (let i = 0; i + 1 < list.length; i += 2) if (String(list[i]).toLowerCase() === name) out.push(String(list[i + 1])); return out; };
  const exclude = declaration.volatile.filter(name => IDEMPOTENCY_VOLATILE_HEADERS.includes(name));
  const schemes = declaredSchemes(declaration.volatile);
  if (!schemes.length) return { exclude, marker: '', signed: null };
  const marker = [], signed = {}, clocked = Number.isSafeInteger(startSec) && Number.isSafeInteger(nowSec);
  for (const name of schemes) {
    const s = IDEMPOTENCY_SIGNATURE_SCHEMES[name], sig = values(s.signature), stamp = s.timestamp === null ? null : values(s.timestamp);
    const parsed = sig.length === 1 ? parseSignature(s.form, sig[0]) : null;
    const t = parsed === null ? null : stamp === null ? parsed.t : stamp.length === 1 && UNIX.test(stamp[0]) ? Number(stamp[0]) : null;
    const ok = t !== null && clocked && t >= startSec - IDEMPOTENCY_SIGNATURE_WINDOW.beforeStart && t <= nowSec + IDEMPOTENCY_SIGNATURE_WINDOW.afterArrival;
    marker.push([name, ok ? parsed.entries : null]);
    signed[name] = ok ? { t, mac: parsed.mac } : null;
    if (ok) exclude.push(...[s.signature, s.timestamp].filter(header => header !== null && declaration.volatile.includes(header)));
  }
  return { exclude, marker: `\nsigned ${JSON.stringify(marker)}`, signed };
}
const signedItem = s => s === null || (plain(s) && Object.keys(s).sort().join(',') === 'mac,t' && HEX.test(s.mac ?? '') && Number.isSafeInteger(s.t) && UNIX.test(String(s.t)));

// Verified signature headers (IDEMPOTENCY_SIGNING_SCHEMES). The parts of one send's signature: absent (no signature header),
// unverified (anything that is not exactly the scheme's form, each of its headers once), or parsed { t, prefix, entries }, where
// prefix is the message before the body and entries the decoded 32-byte MACs.
const STRIPE_SIGNATURE = /^t=([1-9][0-9]{9})((?:,v1=[0-9a-f]{64}){1,4})$/;
function signingParts(signing, rawHeaders) {
  const list = Array.isArray(rawHeaders) ? rawHeaders : [];
  const values = name => { const out = []; for (let i = 0; i + 1 < list.length; i += 2) if (String(list[i]).toLowerCase() === name) out.push(String(list[i + 1])); return out; };
  const sig = values(signing.signature), unverified = { status: 'unverified' };
  if (!sig.length) return { status: 'absent' };
  if (sig.length !== 1) return unverified;
  if (signing.scheme === 'stripe') {
    const m = STRIPE_SIGNATURE.exec(sig[0]);
    return m ? { status: 'parsed', t: Number(m[1]), prefix: `${m[1]}.`, entries: m[2].slice(1).split(',').map(p => Buffer.from(p.slice(3), 'hex')) } : unverified;
  }
  const stamp = values(signing.timestamp);
  if (stamp.length !== 1 || !UNIX.test(stamp[0])) return unverified;
  if (signing.scheme === 'slack-v0') return /^v0=[0-9a-f]{64}$/.test(sig[0]) ? { status: 'parsed', t: Number(stamp[0]), prefix: `v0:${stamp[0]}:`, entries: [Buffer.from(sig[0].slice(3), 'hex')] } : unverified;
  const id = values(signing.id), parts = sig[0].split(' ');
  if (id.length !== 1 || !KEY.test(id[0]) || parts.length > SIGNING_BOUNDS.entries || !parts.every(p => V1_BASE64.test(p))) return unverified;
  return { status: 'parsed', t: Number(stamp[0]), prefix: `${id[0]}.${stamp[0]}.`, entries: parts.map(p => Buffer.from(p.slice(3), 'base64')) };
}
// A declared secret's HMAC key bytes for its scheme, or null when it is unusable: unset, empty, outside the scheme's byte bounds, or
// (standard-webhooks) not canonical base64 after an optional "whsec_" prefix.
export function signingKeyOf(scheme, value) {
  if (typeof value !== 'string' || !value.length) return null;
  if (scheme === 'standard-webhooks') {
    const text = value.startsWith('whsec_') ? value.slice(6) : value;
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text) || text.length % 4 !== 0) return null;
    const key = Buffer.from(text, 'base64');
    return key.toString('base64') === text && key.length >= SIGNING_BOUNDS.standardKeyBytes[0] && key.length <= SIGNING_BOUNDS.standardKeyBytes[1] ? key : null;
  }
  const key = Buffer.from(value, 'utf8');
  return key.length >= SIGNING_BOUNDS.keyBytes[0] && key.length <= SIGNING_BOUNDS.keyBytes[1] ? key : null;
}
// The key HMAC-SHA256 actually uses (RFC 2104): a key over the 64-byte block is hashed first, then it is zero-padded to the block.
// Two secrets with the same effective key verify exactly the same MACs, so they are compared in this form.
export const effectiveHmacKey = key => { const out = Buffer.alloc(64); (key.length > 64 ? createHash('sha256').update(key).digest() : key).copy(out); return out; };
// One send's verification, started on arrival. slots: [{ key, usable }] in declared order (the recorder gives an unusable slot a
// random dummy key, so the work never depends on which secrets are usable), or null once the recorder stopped. Hashing starts only
// when the signature parses and the timestamp is in the run window on the signing clock, one HMAC per declared slot whether or not
// it is usable (so the work never shows how many secrets are usable, or whether any is); update(chunk) feeds
// the raw body bytes; finish(rawTrailers) compares every entry with every slot's MAC in constant time, with no early exit, and
// returns { verified, t, at, slot, count }: verified true only when exactly one usable slot matches every entry and the request had
// no trailers (t the signing timestamp); null for a send with no signature header; false otherwise. at, the arrival second on the
// signing clock, is given for every send when the recorder has a clock (the dedupe bound applies to every send, exact replays too).
export function createSigningCheck({ signing, rawHeaders, slots, startSec, nowSec }) {
  const parts = signingParts(signing, rawHeaders), clocked = Number.isSafeInteger(startSec) && Number.isSafeInteger(nowSec);
  const live = parts.status === 'parsed' && clocked && parts.t >= startSec - IDEMPOTENCY_SIGNATURE_WINDOW.beforeStart && parts.t <= nowSec + IDEMPOTENCY_SIGNATURE_WINDOW.afterArrival
    && Array.isArray(slots) && slots.length > 0;
  const macs = live ? slots.map(s => createHmac('sha256', s.key).update(parts.prefix, 'latin1')) : null;
  const unverified = { verified: parts.status === 'absent' ? null : false, t: null, at: clocked ? nowSec : null, slot: null, count: null };
  return {
    update(chunk) { if (macs) for (const mac of macs) mac.update(chunk); },
    finish(rawTrailers = []) {
      if (!macs) return unverified;
      const digests = macs.map(mac => mac.digest());
      let matching = 0, slot = null;
      for (let s = 0; s < digests.length; s++) {
        let all = 1;
        for (const entry of parts.entries) all &= timingSafeEqual(entry, digests[s]) ? 1 : 0;
        const hit = all & (slots[s].usable === true ? 1 : 0);
        matching += hit;
        if (hit) slot = s;
      }
      return matching === 1 && !(Array.isArray(rawTrailers) && rawTrailers.length) ? { verified: true, t: parts.t, at: nowSec, slot, count: parts.entries.length } : unverified;
    },
  };
}
// What a send's head leaves out for its signing declaration, and the marker line appended to its head text: a verified send leaves
// out the signature and timestamp headers (never the id header) and names the slot and entry count; any other keeps every header
// and says it was unverified or absent. The request's trailers are bound in the marker.
export function signingHead(signing, result, rawTrailers = []) {
  const trailers = Array.isArray(rawTrailers) ? rawTrailers.map(String) : [];
  if (result.verified === true) return { exclude: [signing.signature, ...(signing.timestamp ? [signing.timestamp] : [])], marker: `\nsigning ${JSON.stringify([signing.scheme, 'verified', result.slot, result.count, trailers])}` };
  return { exclude: [], marker: `\nsigning ${JSON.stringify([signing.scheme, result.verified === null ? 'absent' : 'unverified', null, null, trailers])}` };
}
// The stored item of a send's verification: { scheme, verified, t, at }: t only when verified (the window's upper edge bounds it by
// the arrival second); at, the arrival second, on every send of a recorder with a signing clock (required when verified).
const unixOrNull = v => v === null || (Number.isSafeInteger(v) && UNIX.test(String(v)));
const signingItem = s => plain(s) && Object.keys(s).sort().join(',') === 'at,scheme,t,verified' && typeof s.scheme === 'string' && Object.hasOwn(IDEMPOTENCY_SIGNING_SCHEMES, s.scheme)
  && (s.verified === true ? Number.isSafeInteger(s.t) && UNIX.test(String(s.t)) && Number.isSafeInteger(s.at) && UNIX.test(String(s.at)) && s.at + IDEMPOTENCY_SIGNATURE_WINDOW.afterArrival >= s.t
    : (s.verified === false || s.verified === null) && s.t === null && unixOrNull(s.at));
const egressDestinations = observers => (Array.isArray(observers) ? observers : []).filter(o => o?.type === 'egress-recorder' && Array.isArray(o.destinations)).flatMap(o => o.destinations);
// A profile's signing secretEnv that is also an actor's or an observer's credential, or a forward proofEnv: the connector sends
// credentials to the application, and the application must never hold a proof secret, while it holds its signing secrets by
// definition. Returns a message (names only), or null.
export function signingSecretClash(target) {
  const named = new Map();
  for (const [alias, actor] of Object.entries(plain(target?.actors) ? target.actors : {})) for (const [key, value] of Object.entries(plain(actor) ? actor : {})) if (/Env$/.test(key) && typeof value === 'string') named.set(value, `the credential of actor "${alias}"`);
  for (const o of Array.isArray(target?.observers) ? target.observers : []) for (const [key, value] of Object.entries(plain(o) ? o : {})) if (/Env$/.test(key) && typeof value === 'string') named.set(value, `the credential of observer "${o.id}"`);
  for (const d of egressDestinations(target?.observers)) if (typeof d?.forward?.proofEnv === 'string') named.set(d.forward.proofEnv, `the forward proofEnv of "${d.host}"`);
  for (const d of egressDestinations(target?.observers)) for (const name of Array.isArray(d?.idempotency?.signing?.secretEnv) ? d.idempotency.signing.secretEnv : []) {
    if (named.has(name)) return `a signing secretEnv of "${d.host}" is also ${named.get(name)}: a signing secret is the application's own, so it must be its own variable`;
  }
  return null;
}
// The same test on values: every declared signing secret against every forward proof secret of these observers, as raw strings
// (with an optional "whsec_" prefix removed from either), and as key bytes and effective HMAC keys under every reading either value
// has (its UTF-8 bytes, its scheme's key, and its canonical base64 decoding). It reads the variables only to compare them and keeps
// nothing. Returns a message (hosts and slot numbers only, never a value), or null.
export function signingSecretValueClash(observers, env) {
  const read = name => (typeof name === 'string' && SIGNING_ENV.test(name) && typeof env?.[name] === 'string' && env[name].length ? env[name] : null);
  const bare = value => (value.startsWith('whsec_') ? value.slice(6) : value);
  const readings = value => [Buffer.from(value, 'utf8'), signingKeyOf('standard-webhooks', value)].filter(k => k !== null);
  const destinations = egressDestinations(observers);
  for (const p of destinations) {
    const proof = read(p?.forward?.proofEnv);
    if (proof === null) continue;
    const proofKeys = readings(proof);
    for (const d of destinations) {
      const names = Array.isArray(d?.idempotency?.signing?.secretEnv) ? d.idempotency.signing.secretEnv : [];
      for (let i = 0; i < names.length; i++) {
        const value = read(names[i]);
        if (value === null) continue;
        const keys = [...readings(value), signingKeyOf(d.idempotency.signing.scheme, value)].filter(k => k !== null);
        if (bare(value) === bare(proof) || keys.some(k => proofKeys.some(p => k.equals(p) || effectiveHmacKey(k).equals(effectiveHmacKey(p))))) {
          return `signing secret ${i + 1} of "${d.host}" is the forward proof secret of "${p.host}": the application holds its signing secrets, so a proof secret must differ`;
        }
      }
    }
  }
  return null;
}
// The run's signing record: per declared signing destination (observers in run order, hosts sorted), { observer, host, scheme,
// usable }, where usable says for each declared secret slot whether the recorder could use it (records: per observer, the
// recorder's signingRecord(), or null to build the expected shape). null when no destination declares signing.
export function signingRunOf(declaredObservers, records) {
  const out = [];
  (Array.isArray(declaredObservers) ? declaredObservers : []).forEach((o, i) => {
    if (o?.type !== 'egress-recorder' || !plain(o.idempotency)) return;
    for (const host of Object.keys(o.idempotency).sort()) {
      const s = o.idempotency[host]?.signing;
      if (!plain(s)) continue;
      const rec = records?.[i]?.[host];
      out.push({ observer: o.id, host, scheme: s.scheme, usable: Array.from({ length: s.secrets }, (_, k) => rec?.usable?.[k] === true) });
    }
  });
  return out.length ? out : null;
}
// A run's signing record agrees with its declared observers: present exactly when some destination declares signing, one entry per
// such destination in order, with one boolean per declared secret.
export function validSigningRun(signing, declaredObservers) {
  const expected = signingRunOf(declaredObservers, null);
  if (expected === null) return signing === undefined;
  return Array.isArray(signing) && signing.length === expected.length && signing.every((e, i) => plain(e) && Object.keys(e).sort().join(',') === 'host,observer,scheme,usable'
    && e.observer === expected[i].observer && e.host === expected[i].host && e.scheme === expected[i].scheme && Array.isArray(e.usable) && e.usable.length === expected[i].usable.length && e.usable.every(u => typeof u === 'boolean'));
}
// Across every sealed window of a run: a send to a host whose published declaration has signing carries a signing item of that
// scheme, and no other send carries one; a verified item needs a usable secret on its host in the run's signing record. Throws a code.
export function consistentSigningRun(windows, signing) {
  const usable = new Set((Array.isArray(signing) ? signing : []).filter(e => e.usable.some(u => u === true)).map(e => `egress-recorder-${e.observer}\n${e.host}`));
  for (const w of windows) for (const e of w.events) {
    if (!plain(e.idempotency)) continue;
    const declared = w.scope?.idempotency?.[e.name]?.signing, s = e.idempotency.signing;
    if (!plain(declared)) { if (s !== undefined) throw new Error('idempotency-signing'); continue; }
    if (!plain(s) || s.scheme !== declared.scheme || (s.verified === true && !usable.has(`${w.instanceId}\n${e.name}`))) throw new Error('idempotency-signing');
  }
}

// A stored record on one event: the five keys, and signed only as signedHead gives it (sealed) or signing as a verification gives
// it, never both; key, fold and firstSeq only for a keyed or overlapping send. Throws a code.
export function validateIdempotencyRecord(rec, seq) {
  if (!plain(rec) || !['firstSeq,fold,head,key,status', 'firstSeq,fold,head,key,signed,status', 'firstSeq,fold,head,key,signing,status'].includes(Object.keys(rec).sort().join(',')) || !IDEMPOTENCY_STATUSES.includes(rec.status) || !HEX.test(rec.head ?? '')) throw new Error('idempotency-record');
  if (Object.hasOwn(rec, 'signed') && !(plain(rec.signed) && Object.keys(rec.signed).length >= 1 && Object.entries(rec.signed).every(([name, s]) => Object.hasOwn(IDEMPOTENCY_SIGNATURE_SCHEMES, name) && signedItem(s)))) throw new Error('idempotency-record');
  if (Object.hasOwn(rec, 'signing') && !signingItem(rec.signing)) throw new Error('idempotency-record');
  const keyed = rec.status === 'keyed' || rec.status === 'overlap';
  if (keyed ? !(HEX.test(rec.key ?? '') && HEX.test(rec.fold ?? '') && Number.isSafeInteger(rec.firstSeq) && rec.firstSeq >= 1 && rec.firstSeq <= seq)
    : !(rec.key === null && rec.fold === null && rec.firstSeq === null)) throw new Error('idempotency-record');
  return rec;
}
// The records of one window agree with each other. Throws a code.
export function consistentIdempotencyWindow(events) {
  const foldOfKey = new Map(), firstOfFold = new Map(), minSeqOfFold = new Map(), sameSend = new Map();
  const bySeq = new Map(events.map(e => [e.seq, e]));
  for (const e of events) {
    const r = e.idempotency;
    if (!r || r.key === null) continue;
    if (foldOfKey.has(r.key) && foldOfKey.get(r.key) !== r.fold) throw new Error('idempotency-window');
    foldOfKey.set(r.key, r.fold);
    if (firstOfFold.has(r.fold) && firstOfFold.get(r.fold) !== r.firstSeq) throw new Error('idempotency-window');
    firstOfFold.set(r.fold, r.firstSeq);
    minSeqOfFold.set(r.fold, Math.min(minSeqOfFold.get(r.fold) ?? Infinity, e.seq));
    const id = `${r.key}\n${e.contentDigest}\n${r.head}`, shape = digest([e.resource, e.captured ?? null]);
    if (sameSend.has(id) && sameSend.get(id) !== shape) throw new Error('idempotency-window');
    sameSend.set(id, shape);
  }
  for (const [fold, first] of firstOfFold) {
    if (first > minSeqOfFold.get(fold)) throw new Error('idempotency-window');
    const at = bySeq.get(first);
    // The first use is this fold's send, a send to its host whose key could not be read, or a send the recorder filed under
    // another name (a host mismatch or an address literal); never another key's send.
    if (at && at.idempotency && !(at.idempotency.fold === fold || (IDEMPOTENCY_DIRTY.includes(at.idempotency.status) && at.name === events.find(e => e.idempotency?.fold === fold).name))) throw new Error('idempotency-window');
  }
}
// Across every sealed window of a run (rows, settlement gaps and barriers): one observer's fold has one first use, at or before
// its earliest send in any of them. A first use edited in one row is caught against the others. Throws a code.
export function consistentIdempotencyRun(windows) {
  const first = new Map(), earliest = new Map();
  for (const w of windows) for (const e of w.events) {
    const r = e.idempotency;
    if (!r || r.fold === null) continue;
    const slot = `${w.instanceId}\n${r.fold}`;
    if (first.has(slot) && first.get(slot) !== r.firstSeq) throw new Error('idempotency-run');
    first.set(slot, r.firstSeq);
    earliest.set(slot, Math.min(earliest.get(slot) ?? Infinity, e.seq));
  }
  for (const [slot, seq] of first) if (seq > earliest.get(slot)) throw new Error('idempotency-run');
}

// The applications the counted sends stand for: { low, high, reason, replays }. window is the clause's single
// authoritative window, host its exact selector name and counted the committed sends the clause matched there.
// On a host the window forwards to a declared loopback upstream (src/effect-outcome.mjs, E1), each send's proven outcome narrows
// the count: a send whose proven status is in the destination's declared rejected list applied nothing and drops out, a proven
// applied one applied (or replayed an earlier application of its key), and any other is unknown, which only widens high. A
// rejection outside the declared list (the default list is empty) is unknown. A host the window does not forward keeps the
// rules above, where every committed send is the declared provider's attempt.
// The committed sends to host in one window, grouped as countApplications and keyedReplays read them: dirty (a send whose key was
// not recorded or could not be read, with its reasons), each send's forwarding fate, the keyed sends by fold, in window order, and
// the identity function each group compares by (src/key-identity.mjs keyGroupIdentity).
// resolved (an exactly-n clause pinned to upstream "resolved", or an effect.only clause with outcomeJudged; gate A): an in-doubt attempt its
// resolvers refuted (src/in-doubt.mjs fateOf: R0, or R1's request feed) drops out as a declared rejection does, and one they confirmed
// (R1: the provider's signed entry for its exact key) reads applied, as a proven applied reply does (IDR-4; the IDR-2 builder's note: a
// confirmation read unknown, so a keyed count read missing); a proven reply and every other undecided send read as before. R1 decides a
// key group as one application (src/request-feed-rules.mjs deriveRequestFeed confirms at most one member and refutes the rest), so the
// collapse below counts it once. Off, every fate is exactly the proven record's.
function keyedSends(window, host, { resolved = false } = {}) {
  const sends = window.events.filter(e => e.name === host && e.operation === 'send' && e.outcome === 'committed');
  const reasons = new Set();
  let dirty = false;
  for (const e of sends) {
    if (!e.idempotency) { dirty = true; reasons.add('idempotency-key-unrecorded'); }
    else if (IDEMPOTENCY_DIRTY.includes(e.idempotency.status)) { dirty = true; reasons.add(DIRTY_REASON[e.idempotency.status]); }
  }
  const forward = plain(window.scope?.forward?.[host]) ? window.scope.forward[host] : null;
  const fate = e => {
    if (!forward) return 'attempt';
    if (resolved === true && inDoubtAttempt(e)) { const f = fateOf(e); if (f === 'refuted') return 'rejected'; if (f === 'applied') return 'applied'; }
    const u = e.upstream;
    if (plain(u) && u.proven === true && u.outcome === 'applied') return 'applied';
    if (plain(u) && u.proven === true && u.outcome === 'rejected' && Array.isArray(forward.rejected) && forward.rejected.includes(u.status)) return 'rejected';
    return 'unknown';
  };
  const groups = new Map();
  for (const e of sends) {
    const r = e.idempotency;
    if (r && (r.status === 'keyed' || r.status === 'overlap')) { if (!groups.has(r.fold)) groups.set(r.fold, []); groups.get(r.fold).push(e); }
  }
  return { sends, dirty, reasons, forward, fate, groups, identityOf: keyGroupIdentity(window, host, sends), seqs: new Set(window.events.map(e => e.seq)) };
}
export function countApplications(window, host, counted, { resolved = false } = {}) {
  const { sends, dirty, reasons, forward, fate, groups, identityOf, seqs } = keyedSends(window, host, { resolved });
  const countedSet = new Set(counted);
  let low = 0, high = 0, replays = 0;
  for (const e of sends) {
    const r = e.idempotency;
    if (r && (r.status === 'keyed' || r.status === 'overlap')) continue;
    if (!countedSet.has(e)) continue;
    const f = fate(e);
    if (f === 'rejected') continue;
    // A definite absence (no key, or a method the provider does not key): every such send is its own application.
    if (r && (r.status === 'absent' || r.status === 'not-applicable') && f !== 'unknown') { low++; high++; }
    else { high++; if (f === 'unknown') reasons.add('idempotency-key-outcome-unknown'); }
  }
  for (const all of groups.values()) {
    const identity = identityOf(all);
    const members = all.filter(e => fate(e) !== 'rejected');
    const countedMembers = members.filter(e => countedSet.has(e));
    if (!countedMembers.length) continue;
    const earlier = !seqs.has(members[0].idempotency.firstSeq);
    const overlap = members.some(e => e.idempotency.status === 'overlap');
    const ids = new Set(members.map(identity)), countedIds = new Set(countedMembers.map(identity));
    const keys = new Set(members.map(e => e.idempotency.key));
    const applied = new Set(countedMembers.filter(e => fate(e) !== 'unknown').map(identity));
    if (!dirty && !earlier && !overlap && ids.size === 1 && applied.size === 1) { low++; high++; replays += countedMembers.length - 1; continue; }
    low += !dirty && !earlier && applied.size >= 1 && countedMembers.length === members.length ? 1 : 0;
    high += overlap ? countedMembers.length : countedIds.size;
    if (earlier) reasons.add('idempotency-key-earlier-use');
    if (keys.size > 1) reasons.add('idempotency-key-variant');
    if (overlap) reasons.add('idempotency-key-concurrent');
    if (applied.size < countedIds.size) reasons.add(forward ? 'idempotency-key-outcome-unknown' : 'idempotency-key-content-differs');
    if (keys.size === 1 && ids.size > 1) reasons.add('idempotency-key-content-differs');
  }
  return { low, high, replays, reason: low === high ? null : IDEMPOTENCY_REASONS.find(r => reasons.has(r)) ?? null };
}
// effect.only's keyed sends to host in one window (countBy "idempotency-key"): which sends are the same application as an earlier
// send, and which cannot be shown to be. A key group collapses exactly when countApplications counts it as one decided application
// (no dirty send to the host, the key's first use in this window, no concurrent sends, one identity and an applied or attempted
// one among the sends a proven declared rejection leaves): its first such send stands for the application, every other send
// with that same identity, rejected or not, is a replay, and a rejected send with another identity is judged on its own.
// Otherwise every send of the group after its first, a rejected one included, is unproven: it may or may not be a further
// application, so it can never pass. Every send not keyed is judged on its own. Returns { replay, unproven, reason }.
// outcomeJudged (an effect.only clause that declares it, in-doubt resolution gate A; IN-DOUBT-LEAD-RULING-IDR0 R-3): a collapsing group stands
// on its first proven-applied member when it has one, so the application is judged as applied and an earlier member whose outcome is
// unknown is its replay (otherwise that member would stand, read held, and hide the applied one). Under it the fates are the resolved ones
// too (keyedSends): an attempt R0 refuted reads rejected, so it can never stand for a group that has an applied member (PR342-REVIEW
// finding 1: a refused attempt standing hid the applied retry, which was then never judged). Without it, as before.
export function keyedReplays(window, host, { outcomeJudged = false } = {}) {
  const { dirty, reasons, forward, fate, groups, identityOf, seqs } = keyedSends(window, host, { resolved: outcomeJudged === true });
  const replay = new Set(), unproven = new Set();
  for (const all of groups.values()) {
    const identity = identityOf(all);
    const members = all.filter(e => fate(e) !== 'rejected');
    if (!members.length) continue;
    const earlier = !seqs.has(members[0].idempotency.firstSeq);
    const overlap = members.some(e => e.idempotency.status === 'overlap');
    const ids = new Set(members.map(identity)), keys = new Set(members.map(e => e.idempotency.key));
    const applied = new Set(members.filter(e => fate(e) !== 'unknown').map(identity));
    if (!dirty && !earlier && !overlap && ids.size === 1 && applied.size === 1) {
      const stands = (outcomeJudged === true && members.find(e => fate(e) === 'applied')) || members[0], standing = identity(stands);
      for (const e of all) if (e !== stands && identity(e) === standing) replay.add(e);
      continue;
    }
    for (const e of all.slice(1)) unproven.add(e);
    if (earlier) reasons.add('idempotency-key-earlier-use');
    if (keys.size > 1) reasons.add('idempotency-key-variant');
    if (overlap) reasons.add('idempotency-key-concurrent');
    if (applied.size < ids.size) reasons.add(forward ? 'idempotency-key-outcome-unknown' : 'idempotency-key-content-differs');
    if (keys.size === 1 && ids.size > 1) reasons.add('idempotency-key-content-differs');
  }
  return { replay, unproven, reason: unproven.size ? IDEMPOTENCY_REASONS.find(r => reasons.has(r)) ?? null : null };
}
// The verdict an application interval gives against an expected count.
export const applicationsVerdict = ({ low, high }, expected) => low === high ? (low === expected ? 'pass' : 'fail') : expected < low || expected > high ? 'fail' : 'missing';
export function applicationsBasis({ low, high, replays, reason }, matched, expected) {
  if (low === high) return `Observed ${matched} matching committed send(s): ${low} application(s) (${replays} exact keyed replay(s) of one application counted once); expected ${expected}.`;
  return `Observed ${matched} matching committed send(s): ${low} to ${high} application(s) (${reason ? IDEMPOTENCY_BASIS[reason] : 'ambiguous keys'}); expected ${expected}.`;
}
