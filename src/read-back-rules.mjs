// Read-back of the system of record: in-doubt resolution R2 (IDR-3; IN-DOUBT-DESIGN.md section 4, ADDENDUM-R1 sections 1.4, 1.5 and 4,
// ADDENDUM-R2 sections 1 to 5 and minors m1 to m5 and m8). Pure: no I/O. The declaration, its record, the per-send record, the sealed read and
// the derivation of an attempt's R2 result from that read. Shared by src/egress-rules.mjs (the declaration), src/in-doubt.mjs (applicability
// and the derivation), src/http-effects.mjs (the run record and the window binding), src/contracts.mjs (profile and run checks),
// src/http-timing.mjs and src/http-connector.mjs (the reads' reserve) and the reader in integrations/observers/read-back.mjs. It imports only
// src/domain.mjs, src/body-fields.mjs (pointer syntax) and src/key-identity.mjs, none of which imports src/in-doubt.mjs, so the core reads it
// without a cycle.
//
// What a read-back is. ScopeHaven's own read of the system of record a forwarded destination writes to: a GET of a declared collection, sent
// by the egress recorder straight to the destination's forward upstream on 127.0.0.1 (never through the app or the recorder's listener),
// under a read credential the application never holds, proven under forward proof /2 (the proof covers the reply body), at times
// ScopeHaven picks: a pre-image before a group's first write is forwarded, two reads after the declared settlement bound, and one at run end.
// Declared on a destination beside `forward` (which must declare proofVersion 2), with two destination keys of its own:
//   credentialHeader  the request header that carries the write credential (authorization, x-api-key); the recorder keeps a salted digest of
//                     its one value per send (egress-recorder/9), never the value (ADDENDUM-R2 m4). A rotating token never maps to a declared
//                     identity, so it fails closed: static keys are expected
//   backend           optional: a label shared by every forwarded destination that writes to one system of record. A forwarded destination
//                     without one is in every backend (its writes intervene with every group), the least permissive reading
//   readBack: {
//     credential   { env, header, scheme? }: the read credential, from the SCOPEHAVEN_TARGET_ namespace, sent as `scheme value` in `header`
//     timeoutMs    one read's bound (100 to 30000, default 2000); a pre-image is bounded by min(1000, timeoutMs) and is abandoned past it
//     scopeHeaders the request headers (possibly none, but declared) whose values are copied from the write onto its reads and enter the
//                  group key as salted digests; a write that carries a header of TENANT_HEADERS not declared here is never refuted
//     identities   { "<backend identity>": { env, scheme? } }: the write credentials whose items a read can attribute, by the salted digest of
//                  `scheme value` against the send's credential digest (ADDENDUM-R2 section 3); a credential no identity maps decides nothing
//     routes       [{ write, read, items, id, author, settleMs, complete?, match?, lifecycle?, guarantees?, view?, deferredFields, control?, touches? }]
//   }
//   route.write    "POST /tickets/{ticket}/notes": a method that can change state and a path template; {name} binds one segment of the
//                  forwarded path (A-Z a-z 0-9 . _ ~ -, 1 to 128 characters, never "." or ".."), raw and decoded forms agreeing
//   route.read     "GET /tickets/{ticket}/notes": a collection on the same host, origin form, no query (search and index endpoints are not
//                  declarable), filled only from the write's own bindings
//   items, id      JSON pointers: the array of items (at most 1000; "" for a top-level array) and each item's provider id (a string of 1 to
//                  200 characters or a safe integer). Ids are compared only as salted digests, the minted-id digest of forward ids (E3)
//   author         { pointer, serverAssigned: true }: the item's server-assigned author, whose value names a declared identity
//   settleMs       the route's settlement bound (1 to 120000): reads S1 and S2 are taken at or after the last member's connection end plus
//                  settleMs, at least settleMs apart, on the recorder's monotonic clock; never below guarantees.settleMs (C5)
//   complete       { pointer, equals }: the signal every read must carry; absent, the route never refutes or caps (one page in v1, m8)
//   match          { fields: { itemPointer: requestPointer } } (every request pointer captured) or { key: itemPointer, serverAssigned: true } (the
//                  item holds the send's idempotency key as the server recorded it, compared as its salted digest): which items belong to the
//                  write. Absent: no confirmation
//   lifecycle      { pointer, applied, notApplied?, nonFinal? }: final state words; every other word blocks a count (ADDENDUM-R2 2.3)
//   guarantees     { consistency, completeness, removal, settleMs, source }: the provider document for this endpoint. Refutation needs
//                  consistency "strong", completeness "exhaustive-pagination", removal "never" or "tombstoned" and a source other than
//                  "observed" (ADDENDUM-R2 C3, C4, m8). Absent: no refutation and no cap
//   view           { covers, items }: the identities whose items the read credential and copied scope headers see; items "all-items" is the
//                  operator's assertion that nothing is hidden. Refutation needs G's identity in covers
//   deferredFields captured request pointers that can schedule or hide an item (required, possibly []): a refutation needs each absent or
//                  null on every member (m1)
//   control        { bind, identities? }: a seeded object read at run end in each view key used; an item of G's identity there is control C2
//   touches        the read templates a write on this route can change (they include its own read). A write elsewhere on the backend, or on a
//                  route without touches, intervenes everywhere on it (ADDENDUM-R2 section 4)
// Every guarantee key, absent, reads the least permissive way (ADDENDUM-R2 m1): it can only remove a decision.
//
// A group G (ADDENDUM-R2 section 3) is the sends on one route of one host to one bound object, with one binding value (the exact key, or the
// matched request fields), one write-credential digest and one set of scope-header values: the recorder seals its digest on each member.
// In v1 a group is decided only within one window (every member in the window: groupSends); run-wide facts come from the recorder's counts.
// The sealed read (m2): per attempt, the group's reads as counts, flags and times only (no id, path, value, body, key or credential), plus the
// recorder's run-wide counts; deriveReadBack re-derives every interval and verdict from it on both sides. Strict combination (ADDENDUM-R2 2.4):
// R2 reads its own records and the sealed events only (P is the members proven applied by their own reply, never another resolver's verdict).
import { stable } from './domain.mjs';
import { pointerTokens } from './body-fields.mjs';
// The key collapse's identity and retention rule (IDR-4, PR363-REVIEW-FINAL): R2 never confirms two members the collapse would read as one
// application. key-identity.mjs imports nothing.
import { keyGroupIdentity } from './key-identity.mjs';

export const READ_BACK_BOUNDS = Object.freeze({ routes: 16, items: 1000, settleMs: Object.freeze([1, 120000]), timeoutMs: Object.freeze([100, 30000]), defaultTimeoutMs: 2000, preImageMs: 1000,
  identities: 16, scopeHeaders: 8, deferredFields: 8, touches: 8, words: 16, matchFields: 8, members: 16, groups: 256, counts: 1e6, segment: 128, offsetDriftMs: 1000 });
// The read outcomes a sealed read names. ok: a proven 200 with a JSON body whose items array is within the cap, every item with a valid, distinct
// id, and (when declared) the complete signal. Every other outcome is a failed read, and a group with one decides nothing.
export const READ_OUTCOMES = Object.freeze(['ok', 'status', 'unproven', 'not-json', 'shape', 'over-cap', 'ids', 'incomplete', 'timeout', 'failed', 'abandoned', 'not-run']);
export const READ_KINDS = Object.freeze(['pre', 's1', 's2', 's3']);
export const PRE_IMAGE_ROLES = Object.freeze(['first', 'member', 'none']);
// Request headers that name a tenant on common providers (ADDENDUM-R1 4.1): a write that carries one its destination does not declare in
// scopeHeaders is never refuted, since its read would not be in that tenant.
export const TENANT_HEADERS = Object.freeze(['stripe-account', 'stripe-context', 'openai-organization', 'openai-project', 'x-tenant', 'x-tenant-id', 'x-account', 'x-account-id', 'x-organization',
  'x-organization-id', 'x-org-id', 'x-workspace', 'x-workspace-id', 'x-team-id', 'x-company-id', 'x-merchant-id', 'x-site-id', 'x-shop-id', 'x-shopify-shop-domain', 'zendesk-subdomain', 'x-zendesk-subdomain']);
export const CONSISTENCY = Object.freeze(['strong', 'read-your-writes', 'eventual']);
export const COMPLETENESS = Object.freeze(['exhaustive-pagination', 'snapshot', 'single-object']);
export const REMOVAL = Object.freeze(['never', 'tombstoned', 'possible']);
export const VIEW_ITEMS = Object.freeze(['all-items', 'partial']);
// The digest labels the recorder seals with its salt (integrations/observers/read-back.mjs): the credential is backend-wide (no host).
export const READ_BACK_LABELS_TEXT = Object.freeze({ credential: 'scopehaven-readback-credential/1\n', object: 'scopehaven-readback-object/1\n', binding: 'scopehaven-readback-binding/1\n',
  scope: 'scopehaven-readback-scope/1\n', group: 'scopehaven-readback-group/1\n' });

const KEYS = Object.freeze(['credential', 'timeoutMs', 'scopeHeaders', 'identities', 'routes']);
const ROUTE_KEYS = Object.freeze(['write', 'read', 'items', 'id', 'author', 'settleMs', 'complete', 'match', 'lifecycle', 'guarantees', 'view', 'deferredFields', 'control', 'touches']);
const GUARANTEE_KEYS = Object.freeze(['consistency', 'completeness', 'removal', 'settleMs', 'source']);
// Headers never declarable as a credential or scope header: framing, hop-by-hop, routing, cookies and ScopeHaven's own.
const RESERVED = Object.freeze(['host', 'content-type', 'content-length', 'content-encoding', 'transfer-encoding', 'connection', 'keep-alive', 'proxy-connection', 'proxy-authorization', 'te', 'trailer', 'upgrade', 'expect',
  'cookie', 'set-cookie', 'traceparent', 'tracestate', 'accept', 'x-forwarded-for', 'x-forwarded-host', 'x-real-ip', 'forwarded']);
const HEADER = /^[a-z0-9][a-z0-9-]{0,63}$/;
const SCHEME = /^[A-Za-z][A-Za-z0-9._-]{0,31}$/;
const LABEL = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const WORD = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const ENV = /^SCOPEHAVEN_TARGET_[A-Z0-9_]{1,110}$/;
const SOURCE = /^[\x20-\x7e]{1,200}$/;
const LITERAL = /^[A-Za-z0-9._~-]{1,128}$/, PLACEHOLDER = /^\{([a-z][a-z0-9_]{0,31})\}$/, SEGMENT = /^[A-Za-z0-9._~-]{1,128}$/;
const HEX = /^[a-f0-9]{64}$/;
const WRITE_METHODS = Object.freeze(['POST', 'PUT', 'PATCH', 'DELETE']);
const SAFE = Object.freeze(['GET', 'HEAD', 'OPTIONS', 'TRACE']);
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const intIn = (value, [lo, hi]) => Number.isSafeInteger(value) && value >= lo && value <= hi;
const distinct = list => new Set(list).size === list.length;
const words = (list, { min = 1 } = {}) => Array.isArray(list) && list.length >= min && list.length <= READ_BACK_BOUNDS.words && list.every(w => typeof w === 'string' && WORD.test(w)) && distinct(list);
const fail = message => { throw new Error(message); };

// A JSON pointer a read reply is read at (syntax only: values are never stored), or "" for the whole document where allowed.
const replyPointer = (p, { root = false } = {}) => { if (root && p === '') return true; try { pointerTokens(p); return true; } catch { return false; } };
export const pointerTokensOf = p => (p === '' ? [] : pointerTokens(p));
// The raw value at a pointer in parsed JSON, or undefined (arrays by canonical index, objects by own key).
export function valueAt(root, pointer) {
  let value = root;
  for (const token of pointerTokensOf(pointer)) {
    if (Array.isArray(value)) { if (!/^(0|[1-9][0-9]{0,8})$/.test(token) || Number(token) >= value.length) return undefined; value = value[Number(token)]; }
    else if (value !== null && typeof value === 'object') { if (!Object.hasOwn(value, token)) return undefined; value = value[token]; }
    else return undefined;
  }
  return value;
}

// A route template: { method, segments: [{ literal } | { name }], names }, or null. kind: 'write' (a method that can change state) or 'read' (GET).
export function parseTemplate(text, kind) {
  if (typeof text !== 'string' || text.length > 220) return null;
  const m = /^([A-Z]+) (\/[^?#\s]*)$/.exec(text);
  if (!m || (kind === 'write' ? !WRITE_METHODS.includes(m[1]) : m[1] !== 'GET')) return null;
  const segments = m[2].slice(1).split('/').map(s => { const p = PLACEHOLDER.exec(s); return p ? { name: p[1] } : LITERAL.test(s) && s !== '.' && s !== '..' ? { literal: s } : null; });
  if (!segments.length || !segments.every(Boolean)) return null;
  const names = segments.filter(s => s.name).map(s => s.name);
  return distinct(names) ? { method: m[1], segments, names } : null;
}
// The bindings a forwarded path gives a template: { [name]: segment } or null. The path is the recorder's forwarded path (URL-normalized), its
// raw and decoded segments agreeing: a placeholder binds a segment of the charset alone (which holds no "%"), a literal must be equal.
export function bindTemplate(template, method, path) {
  if (!template || method !== template.method || typeof path !== 'string' || !path.startsWith('/') || path.includes('?') || path.includes('#')) return null;
  const raw = path.slice(1).split('/');
  if (raw.length !== template.segments.length) return null;
  const bindings = {};
  for (let i = 0; i < raw.length; i++) {
    const s = template.segments[i], v = raw[i];
    let decoded;
    try { decoded = decodeURIComponent(v); } catch { return null; }
    if (decoded !== v) return null;
    if (s.literal !== undefined) { if (v !== s.literal) return null; continue; }
    if (!SEGMENT.test(v) || v === '.' || v === '..') return null;
    bindings[s.name] = v;
  }
  return bindings;
}
// A template's path filled from bindings (every name bound), or null.
export const fillTemplate = (template, bindings) => template && template.names.every(n => typeof bindings?.[n] === 'string')
  ? `/${template.segments.map(s => (s.literal !== undefined ? s.literal : bindings[s.name])).join('/')}` : null;

const scalarLiteral = v => v === null || typeof v === 'boolean' || (typeof v === 'string' && v.length <= 200) || (Number.isSafeInteger(v));
function validRoute(r, { capture, idempotency, identityNames }) {
  if (!plain(r) || Object.keys(r).some(k => !ROUTE_KEYS.includes(k))) fail(`each read-back route is { ${ROUTE_KEYS.join(', ')} } (write, read, items, id, author, settleMs and deferredFields required)`);
  const write = parseTemplate(r.write, 'write'), read = parseTemplate(r.read, 'read');
  if (!write) fail('a read-back route\'s "write" is a method that can change state and a path template ("POST /tickets/{ticket}/notes"): literal segments of A-Z a-z 0-9 . _ ~ -, or {name} placeholders with distinct names');
  if (!read || !read.names.every(n => write.names.includes(n))) fail('a read-back route\'s "read" is "GET" and a path template on the same host with no query, every {name} bound by its write');
  if (typeof r.items !== 'string' || !replyPointer(r.items, { root: true })) fail('"items" is the JSON pointer of the read\'s item array ("" for a top-level array)');
  if (typeof r.id !== 'string' || r.id === '' || !replyPointer(r.id)) fail('"id" is the JSON pointer of each item\'s provider id');
  if (!plain(r.author) || Object.keys(r.author).length !== 2 || typeof r.author.pointer !== 'string' || r.author.pointer === '' || !replyPointer(r.author.pointer) || r.author.serverAssigned !== true) fail('"author" is { pointer, serverAssigned: true }: the item\'s server-assigned author, naming a declared identity');
  if (!intIn(r.settleMs, READ_BACK_BOUNDS.settleMs)) fail('a read-back route\'s "settleMs" is an integer from 1 to 120000: the provider\'s bound from the end of the forward connection to the last moment a received write can commit');
  let complete = null;
  if (r.complete !== undefined) {
    if (!plain(r.complete) || Object.keys(r.complete).length !== 2 || typeof r.complete.pointer !== 'string' || r.complete.pointer === '' || !replyPointer(r.complete.pointer) || !Object.hasOwn(r.complete, 'equals') || !scalarLiteral(r.complete.equals)) fail('"complete" is { pointer, equals }: the signal (a literal) every read must carry for the list to be complete');
    complete = { pointer: r.complete.pointer, equals: r.complete.equals };
  }
  let match = null;
  if (r.match !== undefined) {
    const shape = plain(r.match) ? Object.keys(r.match).sort().join(',') : '';
    if (shape !== 'fields' && shape !== 'key,serverAssigned') fail('"match" is { fields: { itemPointer: requestPointer } } or { key: itemPointer, serverAssigned: true }');
    if (r.match.fields !== undefined) {
      const entries = plain(r.match.fields) ? Object.entries(r.match.fields) : [];
      if (!entries.length || entries.length > READ_BACK_BOUNDS.matchFields || !entries.every(([item, req]) => item !== '' && replyPointer(item) && typeof req === 'string' && Array.isArray(capture?.pointers) && capture.pointers.includes(req))) fail('"match.fields" maps 1 to 8 item pointers to request pointers the destination captures');
      match = { fields: Object.fromEntries(entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) };
    } else {
      if (typeof r.match.key !== 'string' || r.match.key === '' || !replyPointer(r.match.key) || r.match.serverAssigned !== true || !idempotency) fail('"match.key" is the item pointer that holds the send\'s idempotency key as the server recorded it (serverAssigned: true), on a destination that declares "idempotency"');
      match = { key: r.match.key, serverAssigned: true };
    }
  }
  let lifecycle = null;
  if (r.lifecycle !== undefined) {
    const l = r.lifecycle;
    if (!plain(l) || Object.keys(l).some(k => !['pointer', 'applied', 'notApplied', 'nonFinal'].includes(k)) || typeof l.pointer !== 'string' || l.pointer === '' || !replyPointer(l.pointer) || !words(l.applied)
      || (l.notApplied !== undefined && !words(l.notApplied, { min: 0 })) || (l.nonFinal !== undefined && !words(l.nonFinal, { min: 0 }))) fail('"lifecycle" is { pointer, applied, notApplied?, nonFinal? }: lowercase state words, 1 to 16 applied');
    const all = [...l.applied, ...(l.notApplied ?? []), ...(l.nonFinal ?? [])];
    if (!distinct(all)) fail('"lifecycle" lists each state word once: applied, notApplied and nonFinal are disjoint');
    lifecycle = { pointer: l.pointer, applied: [...l.applied], notApplied: [...(l.notApplied ?? [])], nonFinal: [...(l.nonFinal ?? [])] };
  }
  let guarantees = null;
  if (r.guarantees !== undefined) {
    const g = r.guarantees;
    if (!plain(g) || Object.keys(g).length !== GUARANTEE_KEYS.length || !GUARANTEE_KEYS.every(k => Object.hasOwn(g, k)) || !CONSISTENCY.includes(g.consistency) || !COMPLETENESS.includes(g.completeness) || !REMOVAL.includes(g.removal)
      || !intIn(g.settleMs, READ_BACK_BOUNDS.settleMs) || typeof g.source !== 'string' || !SOURCE.test(g.source)) fail(`"guarantees" is { consistency (${CONSISTENCY.join(', ')}), completeness (${COMPLETENESS.join(', ')}), removal (${REMOVAL.join(', ')}), settleMs, source } as the provider documents the endpoint`);
    if (r.settleMs < g.settleMs) fail('a read-back route\'s "settleMs" is never below its documented "guarantees.settleMs"');
    guarantees = { consistency: g.consistency, completeness: g.completeness, removal: g.removal, settleMs: g.settleMs, source: g.source };
  }
  let view = null;
  if (r.view !== undefined) {
    if (!plain(r.view) || Object.keys(r.view).length !== 2 || !Array.isArray(r.view.covers) || !r.view.covers.length || !distinct(r.view.covers) || !r.view.covers.every(n => identityNames.includes(n)) || !VIEW_ITEMS.includes(r.view.items)) fail('"view" is { covers: [identity, ...], items: "all-items" or "partial" }, naming declared identities');
    view = { covers: [...r.view.covers].sort(), items: r.view.items };
  }
  if (!Array.isArray(r.deferredFields) || r.deferredFields.length > READ_BACK_BOUNDS.deferredFields || !distinct(r.deferredFields) || !r.deferredFields.every(p => Array.isArray(capture?.pointers) && capture.pointers.includes(p))) fail('"deferredFields" is required: the captured request pointers (possibly none) that can schedule or hide an item (send_at, publish_at)');
  let control = null;
  if (r.control !== undefined) {
    const c = r.control;
    if (!plain(c) || Object.keys(c).some(k => !['bind', 'identities'].includes(k)) || !plain(c.bind) || Object.keys(c.bind).length !== read.names.length || !read.names.every(n => typeof c.bind[n] === 'string' && SEGMENT.test(c.bind[n]) && c.bind[n] !== '.' && c.bind[n] !== '..')
      || (c.identities !== undefined && !(Array.isArray(c.identities) && c.identities.length && distinct(c.identities) && c.identities.every(n => identityNames.includes(n))))) fail('"control" is { bind, identities? }: a literal segment for every {name} of the read, naming a seeded object that holds an item of each declared identity');
    control = { bind: Object.fromEntries(Object.entries(c.bind).sort(([a], [b]) => (a < b ? -1 : 1))), ...(c.identities ? { identities: [...c.identities].sort() } : {}) };
  }
  let touches = null;
  if (r.touches !== undefined) {
    const list = Array.isArray(r.touches) ? r.touches : [];
    if (!list.length || list.length > READ_BACK_BOUNDS.touches || !distinct(list) || !list.every(t => { const p = parseTemplate(t, 'read'); return p && p.names.every(n => write.names.includes(n)); }) || !list.includes(r.read)) fail('"touches" lists 1 to 8 read templates ("GET /tickets/{ticket}/notes") a write on this route can change, bound by its write and including its own "read"');
    touches = [...list].sort();
  }
  return { write: r.write, read: r.read, items: r.items, id: r.id, author: { pointer: r.author.pointer, serverAssigned: true }, settleMs: r.settleMs, complete, match, lifecycle, guarantees, view, deferredFields: [...r.deferredFields].sort(), control, touches };
}

// A destination's read-back keys (src/egress-rules.mjs validateEgressConfig), given its other normalized keys: { readBack, credentialHeader,
// backend } normalized, or throws a profile-facing message. backend may stand alone on a forwarded destination.
export function validateReadBackDestination(d, { forward, capture, idempotency, correlationHeader }) {
  const backend = d.backend === undefined ? null : d.backend;
  if (backend !== null && !(typeof backend === 'string' && LABEL.test(backend) && forward)) fail('a destination\'s "backend" is a label (lowercase letters, digits, ".", "_" or "-") shared by the forwarded destinations that write to one system of record');
  if (d.readBack === undefined) {
    if (d.credentialHeader !== undefined) fail('"credentialHeader" is declared with "readBack": the header whose value the recorder digests per send');
    return { readBack: null, credentialHeader: null, backend };
  }
  if (!forward || forward.proofVersion !== 2) fail('"readBack" needs "forward" with "proofVersion": 2: a read\'s reply body is covered by the proof');
  const reserved = h => RESERVED.includes(h) || h.includes('scopehaven') || h === idempotency?.header || h === correlationHeader;
  const credentialHeader = d.credentialHeader;
  if (typeof credentialHeader !== 'string' || !HEADER.test(credentialHeader) || reserved(credentialHeader)) fail('"credentialHeader" is required with "readBack": the lowercase request header that carries the write credential (authorization, x-api-key)');
  const rb = d.readBack;
  if (!plain(rb) || Object.keys(rb).some(k => !KEYS.includes(k))) fail(`"readBack" is { ${KEYS.join(', ')} } (timeoutMs optional)`);
  const c = rb.credential;
  if (!plain(c) || Object.keys(c).some(k => !['env', 'header', 'scheme'].includes(k)) || typeof c.env !== 'string' || !ENV.test(c.env) || typeof c.header !== 'string' || !HEADER.test(c.header) || reserved(c.header)
    || (c.scheme !== undefined && !(typeof c.scheme === 'string' && SCHEME.test(c.scheme)))) fail('"readBack.credential" is { env, header, scheme? }: the read credential in the SCOPEHAVEN_TARGET_ namespace (never the application\'s), the header it is sent in and an optional scheme ("Bearer")');
  const timeoutMs = rb.timeoutMs ?? READ_BACK_BOUNDS.defaultTimeoutMs;
  if (!intIn(timeoutMs, READ_BACK_BOUNDS.timeoutMs)) fail('"readBack.timeoutMs" is an integer from 100 to 30000');
  if (!Array.isArray(rb.scopeHeaders) || rb.scopeHeaders.length > READ_BACK_BOUNDS.scopeHeaders || !distinct(rb.scopeHeaders) || !rb.scopeHeaders.every(h => typeof h === 'string' && HEADER.test(h) && !reserved(h) && h !== credentialHeader && h !== c.header)) fail('"readBack.scopeHeaders" is required: the lowercase request headers (possibly none) whose values name the tenant a write is in, copied onto its reads');
  const ids = plain(rb.identities) ? Object.entries(rb.identities) : [];
  if (!ids.length || ids.length > READ_BACK_BOUNDS.identities || !ids.every(([name, v]) => LABEL.test(name) && plain(v) && Object.keys(v).every(k => ['env', 'scheme'].includes(k)) && typeof v.env === 'string' && ENV.test(v.env) && v.env !== c.env
    && (v.scheme === undefined || (typeof v.scheme === 'string' && SCHEME.test(v.scheme)))) || !distinct(ids.map(([, v]) => v.env))) fail('"readBack.identities" maps 1 to 16 backend identities to { env, scheme? }: the write credential each one\'s items are authored under, each in its own SCOPEHAVEN_TARGET_ variable, never the read credential\'s');
  const identityNames = ids.map(([name]) => name).sort();
  if (!Array.isArray(rb.routes) || !rb.routes.length || rb.routes.length > READ_BACK_BOUNDS.routes) fail('"readBack.routes" lists 1 to 16 routes');
  const routes = rb.routes.map(r => validRoute(r, { capture, idempotency, identityNames }));
  if (!distinct(routes.map(r => r.write))) fail('each read-back route "write" is declared once');
  return { readBack: { credential: { env: c.env, header: c.header, ...(c.scheme ? { scheme: c.scheme } : {}) }, timeoutMs, scopeHeaders: [...rb.scopeHeaders].sort(),
    identities: Object.fromEntries(ids.sort(([a], [b]) => (a < b ? -1 : 1)).map(([name, v]) => [name, { env: v.env, ...(v.scheme ? { scheme: v.scheme } : {}) }])), routes }, credentialHeader, backend };
}

// The record a window's scope and a run's observer record carry for one recorder (no variable name or scheme): { hosts: { [host]: { credentialHeader,
// timeoutMs, scopeHeaders, identities: [name, ...], routes } }, backends: { [forwardedHost]: label | null } }, or null when no destination declares readBack.
const hostRecord = d => ({ credentialHeader: d.credentialHeader, timeoutMs: d.readBack.timeoutMs, scopeHeaders: [...d.readBack.scopeHeaders], identities: Object.keys(d.readBack.identities).sort(), routes: structuredClone(d.readBack.routes) });
export function readBackRecord(destinations) {
  const list = Array.isArray(destinations) ? destinations : [];
  if (!list.some(d => d?.readBack)) return null;
  return { hosts: Object.fromEntries(list.filter(d => d.readBack).map(d => [d.host, hostRecord(d)])), backends: Object.fromEntries(list.filter(d => d.forward).map(d => [d.host, d.backend ?? null])) };
}
const ROUTE_RECORD_KEYS = ROUTE_KEYS;
// A record, by shape and by re-validation of each route (a forged route is refused).
export function validReadBackRecord(rec) {
  if (!plain(rec) || Object.keys(rec).length !== 2 || !plain(rec.hosts) || !plain(rec.backends) || !Object.keys(rec.hosts).length) return false;
  if (!Object.entries(rec.backends).every(([h, b]) => typeof h === 'string' && h.length <= 253 && (b === null || (typeof b === 'string' && LABEL.test(b))))) return false;
  return Object.entries(rec.hosts).every(([host, h]) => {
    if (!Object.hasOwn(rec.backends, host) || !plain(h) || Object.keys(h).length !== 5 || typeof h.credentialHeader !== 'string' || !HEADER.test(h.credentialHeader) || !intIn(h.timeoutMs, READ_BACK_BOUNDS.timeoutMs)
      || !Array.isArray(h.scopeHeaders) || !Array.isArray(h.identities) || !h.identities.length || !h.identities.every(n => typeof n === 'string' && LABEL.test(n)) || !distinct(h.identities) || !Array.isArray(h.routes) || !h.routes.length) return false;
    // Re-validate the routes from their own record: capture and idempotency are not in the record, so request pointers and the key pointer are
    // checked for syntax only here (the profile loader checked them against the destination).
    const capture = { pointers: h.routes.flatMap(r => [...Object.values(r?.match?.fields ?? {}), ...(Array.isArray(r?.deferredFields) ? r.deferredFields : [])]) };
    try {
      const again = h.routes.map(r => {
        if (!plain(r) || Object.keys(r).length !== ROUTE_RECORD_KEYS.length) throw new Error('route');
        const raw = Object.fromEntries(Object.entries(r).filter(([, v]) => v !== null));
        return validRoute(raw, { capture, idempotency: r.match?.key !== undefined ? { header: null } : null, identityNames: h.identities });
      });
      return stable(again) === stable(h.routes) && distinct(h.routes.map(r => r.write)) && h.scopeHeaders.every(s => typeof s === 'string' && HEADER.test(s)) && distinct(h.scopeHeaders);
    } catch { return false; }
  });
}
// The record of a profile's raw (already validated) egress recorder (src/http-effects.mjs declaredObserverRecord): readBackRecord over its
// destinations normalized by the same function the loader uses, or null when none declares readBack.
export function readBackRecordOf(observer) {
  if (observer?.type !== 'egress-recorder' || !Array.isArray(observer.destinations) || !observer.destinations.some(d => d?.readBack !== undefined)) return null;
  return readBackRecord(observer.destinations.map(d => {
    const forward = plain(d?.forward) ? { proofVersion: d.forward.proofVersion ?? 1 } : null;
    return { host: d.host, forward, ...validateReadBackDestination(d, { forward, capture: plain(d.capture) ? { pointers: d.capture.pointers } : null, idempotency: plain(d.idempotency) ? { header: d.idempotency.header ?? null } : null,
      correlationHeader: d.correlation?.header ?? null }) };
  }).map(d => (d.backend === null ? (({ backend: _b, ...rest }) => rest)(d) : d)));
}

// The per-send record (egress-recorder/9) on a settled forward's upstream to a destination that declares readBack: { route, group, object,
// touches, credential, scopeUndeclared, authorInBody, preImage, preImageMs }. route: the index of the one route whose write binds the send, or
// null (then group, object and touches are null and preImage "none"); group: the salted digest of the group key, null when a part could not
// be read (no single credential value, an unreadable binding, a repeated scope header, the group cap); object: the bound read path's digest;
// touches: the bound touches paths' digests (sorted), or null when the route declares none; credential: the salted digest of the one
// credentialHeader value, or null; scopeUndeclared: the send carried a TENANT_HEADERS header its destination does not declare; authorInBody:
// the request body carries a value at the route's author or match.key pointer (an app-settable author or key decides nothing); preImage: the
// group's pre-image role (first: this send took it before any member was forwarded; member: it waited for the group's); preImageMs: how long
// its forward waited for the pre-image, or null; forwardMono: when its forward started on the recorder's monotonic clock (no later than its
// connection end, src/effect-outcome.mjs), so a saved run shows that the group's pre-image ended before every member was forwarded.
const SEND_KEYS = Object.freeze(['route', 'group', 'object', 'touches', 'credential', 'scopeUndeclared', 'authorInBody', 'preImage', 'preImageMs', 'forwardMono']);
const hexOrNull = v => v === null || (typeof v === 'string' && HEX.test(v));
export function validReadBackSend(rec, routes) {
  if (!plain(rec) || Object.keys(rec).length !== SEND_KEYS.length || !SEND_KEYS.every(k => Object.hasOwn(rec, k))) return false;
  if (!(rec.route === null || (Number.isSafeInteger(rec.route) && rec.route >= 0 && rec.route < (Array.isArray(routes) ? routes.length : READ_BACK_BOUNDS.routes)))) return false;
  if (![rec.group, rec.object, rec.credential].every(hexOrNull) || typeof rec.scopeUndeclared !== 'boolean' || typeof rec.authorInBody !== 'boolean' || !PRE_IMAGE_ROLES.includes(rec.preImage)) return false;
  if (!(rec.touches === null || (Array.isArray(rec.touches) && rec.touches.length >= 1 && rec.touches.length <= READ_BACK_BOUNDS.touches && rec.touches.every((t, i) => typeof t === 'string' && HEX.test(t) && (i === 0 || rec.touches[i - 1] < t))))) return false;
  if (!(rec.preImageMs === null || (typeof rec.preImageMs === 'number' && Number.isFinite(rec.preImageMs) && rec.preImageMs >= 0 && rec.preImageMs <= 1e7))) return false;
  if (!(rec.forwardMono === null || (typeof rec.forwardMono === 'number' && Number.isFinite(rec.forwardMono) && rec.forwardMono >= 0 && rec.forwardMono <= 1e13))) return false;
  if (rec.route === null) return rec.group === null && rec.object === null && rec.touches === null && rec.preImage === 'none';
  if (rec.object === null) return false;
  return rec.group === null ? rec.preImage === 'none' : rec.preImage !== 'none' && rec.credential !== null;
}

// The sealed read (m2): what the recorder read for one attempt's group, counts, flags and times only, from which deriveReadBack re-derives the
// result. Group-level: group (the group's digest, as each member's record carries it, so a read is bound to the group it was read for),
// credential (the members' credential digest), identity (the declared identity it maps to, or null), early (the pre-image was taken within the
// route's settleMs of the recorder's start, so a send before the recorder started could still commit: m5), the recorder's run-wide counts:
// groupSends (sends in the group), intervening (other forwarded state-changing sends to the backend that may touch the group's read and whose
// [forward start, connection end + settleMs] overlaps [pre-image, S2]), credOthers (other such sends under the group's credential, or an
// unknown one, anywhere on the backend: exclusivity), laterCred, laterRemovals and laterTouching (sends after S2 surely to the group's object:
// under its credential, non-POST ones, and any, which may explain what S3 shows); then pre, s1, s2, s3, control (the control object read at
// run end in G's view key, null when the route declares none) and controlStart (the same object read when the recorder started, null when the
// route declares none or declares scope headers, whose values are known only from a write). Per read: outcome, atMono and doneMono (the request's start and the reply's end on the recorder's monotonic clock, raw), atWall (the wall clock at
// the start, or null), complete (the declared signal held), total, and against the pre-image S0 and the proven members' minted ids M:
// missingPre (|S0 minus Sk|), newIds (|Sk minus S0|), newInM, mInRead (|M within Sk|), credItems (items authored by the identity), credNew (new
// items authored by the identity outside M: N), credApplied, credNotApplied, credOther (N by lifecycle class), credUnmatched (N items that do
// not match the group's binding), credChanged (S2: |N2 differs from N1|; S3: |N3 minus N2|; else 0), anonNew (new items outside M whose author is
// absent or not a string: they could be anyone's, so they block an exact count), lateNew (S3 only: new items outside M of any author that
// neither S1 nor S2 showed, a commit after the bound that S3 alarms on unless a later send to the object explains it).
const READ_KEYS = Object.freeze(['group', 'credential', 'identity', 'early', 'groupSends', 'intervening', 'credOthers', 'laterCred', 'laterRemovals', 'laterTouching', 'pre', 's1', 's2', 's3', 'control', 'controlStart']);
const ONE_KEYS = Object.freeze(['outcome', 'atMono', 'doneMono', 'atWall', 'complete', 'total', 'missingPre', 'newIds', 'newInM', 'mInRead', 'credItems', 'credNew', 'credApplied', 'credNotApplied', 'credOther', 'credUnmatched', 'credChanged', 'anonNew', 'lateNew']);
export const READ_COUNT_KEYS = Object.freeze(ONE_KEYS.slice(5));
const monoOk = v => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1e13;
const COUNT = [0, READ_BACK_BOUNDS.counts], ITEM_COUNT = [0, READ_BACK_BOUNDS.items];
export function validOneRead(x) {
  if (!plain(x) || Object.keys(x).length !== ONE_KEYS.length || !ONE_KEYS.every(k => Object.hasOwn(x, k)) || !READ_OUTCOMES.includes(x.outcome) || typeof x.complete !== 'boolean') return false;
  if (!READ_COUNT_KEYS.every(k => intIn(x[k], ITEM_COUNT))) return false;
  if (!(x.atWall === null || intIn(x.atWall, [0, 8.64e15]))) return false;
  // A read that was never sent has no times; one that was has a start no later than its end.
  if (x.outcome === 'not-run') return x.atMono === null && x.doneMono === null && x.atWall === null && !x.complete && READ_COUNT_KEYS.every(k => x[k] === 0);
  if (!monoOk(x.atMono) || !monoOk(x.doneMono) || x.atMono > x.doneMono) return false;
  if (x.outcome !== 'ok') return !x.complete && READ_COUNT_KEYS.every(k => x[k] === 0);
  return x.newInM <= x.newIds && x.newIds <= x.total && x.missingPre <= READ_BACK_BOUNDS.items && x.mInRead <= x.total && x.credItems <= x.total && x.credNew <= x.newIds - x.newInM
    && x.credApplied + x.credNotApplied + x.credOther === x.credNew && x.credUnmatched <= x.credNew && x.anonNew <= x.newIds - x.newInM - x.credNew && x.lateNew <= x.newIds - x.newInM && x.credChanged <= READ_BACK_BOUNDS.items;
}
export function validReadBackRead(read) {
  if (!plain(read) || Object.keys(read).length !== READ_KEYS.length || !READ_KEYS.every(k => Object.hasOwn(read, k))) return false;
  if (typeof read.group !== 'string' || !HEX.test(read.group) || typeof read.credential !== 'string' || !HEX.test(read.credential) || !(read.identity === null || (typeof read.identity === 'string' && LABEL.test(read.identity))) || typeof read.early !== 'boolean') return false;
  if (!['groupSends', 'intervening', 'credOthers', 'laterCred', 'laterRemovals', 'laterTouching'].every(k => intIn(read[k], COUNT)) || read.groupSends < 1) return false;
  if (!READ_KINDS.every(k => validOneRead(read[k])) || !['control', 'controlStart'].every(k => read[k] === null || validOneRead(read[k]))) return false;
  // The pre-image is the baseline: nothing in it is new relative to itself, and N is defined only after it.
  const p = read.pre;
  return ['missingPre', 'newIds', 'newInM', 'credNew', 'credApplied', 'credNotApplied', 'credOther', 'credUnmatched', 'credChanged', 'anonNew', 'lateNew'].every(k => p[k] === 0)
    && ['control', 'controlStart'].every(c => read[c] === null || ['missingPre', 'newIds', 'newInM', 'mInRead', 'credNew', 'credApplied', 'credNotApplied', 'credOther', 'credUnmatched', 'credChanged', 'anonNew', 'lateNew'].every(k => read[c][k] === 0))
    && read.s1.credChanged === 0 && read.s1.lateNew === 0 && read.s2.lateNew === 0;
}

// The scope record of the window an event sits in, for R2 (src/in-doubt.mjs admitInDoubt marks the events of a host the record declares).
// R2 applies to an in-doubt attempt (the core checks that) only when it connected and its recorder bound it to a read-back route.
export const readBackApplies = (e, rec) => plain(rec) && plain(rec.hosts) && Object.hasOwn(rec.hosts, e?.name) && e?.upstream?.transport?.connected === true
  && plain(e.upstream.readBack) && Number.isSafeInteger(e.upstream.readBack.route);

// Interval arithmetic on the recorder's monotonic clock: a send's settle is its route's settleMs on a read-back route, else unbounded (its
// commit time is undocumented, the least permissive reading).
const methodOf = e => (typeof e?.resource === 'string' ? e.resource.split(' ', 1)[0] : null);
const stateChanging = e => typeof methodOf(e) === 'string' && !SAFE.includes(methodOf(e));
const routeOfSend = (rec, e) => { const h = rec.hosts[e.name], i = e.upstream?.readBack?.route; return h && Number.isSafeInteger(i) ? h.routes[i] ?? null : null; };
const settleOf = (rec, e) => routeOfSend(rec, e)?.settleMs ?? Infinity;
const sameBackend = (rec, a, b) => { const x = rec.backends[a] ?? null, y = rec.backends[b] ?? null; return Object.hasOwn(rec.backends, a) && Object.hasOwn(rec.backends, b) && (x === null || y === null || x === y); };
const provenRejected = e => e?.upstream?.proven === true && e.upstream.outcome === 'rejected';
// A non-member send whose effect surely overlaps [t0, t2] (a lower bound from sealed events: it ended by t2, so it started by t2, and its
// connection end plus its settle reaches t0). Only a forward that connected reached the upstream.
const surelyOverlaps = (rec, x, t0, t2) => x?.upstream?.transport?.connected === true && x.upstream.transport.mono <= t2 && x.upstream.transport.mono + settleOf(rec, x) >= t0;
// The other sends among `sends` that a group's own reading must treat as intervening (they may touch its read) and as breaking exclusivity
// (they may carry its credential), counted from sealed events alone: the validator's lower bound on the recorder's run-wide counts.
export function localCounts(rec, group, sends, t0, t2) {
  const g = group.upstream.readBack, host = group.name;
  let intervening = 0, credOthers = 0;
  for (const x of sends) {
    if (x?.upstream?.readBack?.group === g.group && x.name === host) continue;
    if (x?.operation !== 'send' || x.outcome !== 'committed' || !stateChanging(x) || provenRejected(x) || !Object.hasOwn(rec.backends, x.name) || !sameBackend(rec, host, x.name) || !surelyOverlaps(rec, x, t0, t2)) continue;
    const xr = x.upstream.readBack;
    if (x.name !== host || !plain(xr) || xr.touches === null || xr.touches.includes(g.object)) intervening++;
    if (!plain(xr) || xr.credential === null || xr.credential === g.credential) credOthers++;
  }
  return { intervening, credOthers };
}
// A deferred field shows no schedule on a send: its body was captured in full and the field is absent or null.
const deferredClear = (e, fields) => fields.every(p => plain(e?.captured) && e.captured.status === 'captured' && plain(e.captured.values?.[p]) && ['absent', 'null'].includes(e.captured.values[p].type));
// The wall-to-monotonic offset at each read and at each member's connection end agrees within offsetDriftMs (ADDENDUM-R2 M6): a sleep or a
// clock step in between withholds the refutation and the cap (the monotonic bound itself errs safe).
const offsetsStable = (members, reads) => {
  const ends = members.map(x => x.upstream.transport);
  if (ends.some(t => !Number.isSafeInteger(t.wall)) || reads.some(r => r.atWall === null)) return false;
  const offsets = [...ends.map(t => t.wall - t.mono), ...reads.map(r => r.atWall - r.atMono)];
  return Math.max(...offsets) - Math.min(...offsets) <= READ_BACK_BOUNDS.offsetDriftMs;
};
// One identity among the standing members: equal content digests (path, query and body) and equal captured records, so no selector can tell
// one member from another and assigning the group's count to its members is verdict-safe (as R1's decision 5).
const identityOf = e => stable([e.contentDigest, e.captured ?? null]);

// The derivation (the connector's run-end stage and the validator both run it, src/in-doubt.mjs bindResolutions). window: one admitted window
// whose scope declares read-back; reads: Map(event -> sealed read) of the attempts R2 applies to that carry one; inDoubt and applies: the core's
// predicates. Returns Map(event -> { resolver: 'r2', status: 'succeeded', result } or { resolver: 'r2', status: 'failed', reason }).
// A group decides only when every in-doubt connected member carries an equal read bound to its group and credential, every member is in this
// window, exactly one member took the pre-image and every other waited for it, every member's forward settled and started only after the
// pre-image ended (its sealed forward start), every read is ok, S1 is at or past the last member's connection end plus the route's settleMs,
// S2 at least settleMs after S1, S3 after S2, and the pre-image held no minted id. With P the members proven applied by their own reply (never another resolver's verdict) and D the in-doubt connected ones, R2's
// interval is [low, high] within [P, P + D] (ADDENDUM-R2 2.2 and 2.3):
//   refutable (the cap): the route's write is a POST and its host declares forward ids.minted (PR373-REVIEW blocker 1: refutation reads a
//     missing new item, so it holds only for a write that creates exactly one new item per application; a PUT or PATCH that changes an item
//     in place adds none, so such a route confirms only); the route documents strong consistency, exhaustive one-page completeness with its
//     complete signal held on every read, removal never or tombstoned and a source; G's identity is in a view of all items; every member shows each deferred field absent
//     or null, carries no query and no undeclared tenant header; S1 and S2 are sighted (C1: every minted id of M visible, one minted id per
//     proven member; C2: an item of G's identity visible there or in the control read); no pre-image id is missing from S1, S2 or S3; and the
//     wall-to-monotonic offset is stable. Then high = P + min(D, n), n the new items outside M on S1 or S2, of any kind (unfiltered)
//   confirmable: a match is declared, G's credential maps to an identity, no other send under that credential (or an unknown one) overlaps
//     [pre-image, S2] (exclusivity: the recorder's count and the window's own), S1 and S2 miss no pre-image id, and N (the new items of G's
//     identity outside M) is equal on S1 and S2, every N item matches the group's binding and sits in a declared final state. Then low = P +
//     the N items in an applied state (every listed item without a lifecycle)
//   exact: both, and no new item outside M lacks an author: every one of G's items is visible and attributed, so high = low as well (a
//     declined item of G's identity then refutes, ADDENDUM-R2 2.3)
// Any intervening write, an early pre-image, an app-settable author or key, or a proven member without exactly one minted id leaves R2
// silent. S3 only blocks (ADDENDUM-R2 section 4): a pre-image or minted id missing there with no later non-POST write to the object, more late
// items of G's identity than later sends under its credential to the object explain, or more late items of any author than later sends to the
// object explain (stricter than the design, whose alarm reads G's identity only: an item whose author is missing could be G's late commit),
// fails the group, and so does an empty interval (a conflict). On a singleton [c, c]: with c = P every in-doubt member is refuted (beside one
// identity only, when P > 0: they are further applications of the P); otherwise, among one identity, the first c - P in-doubt members by seq
// are confirmed and the rest refuted, which no selector can tell apart (as R1's decision 5). Either way only when no two members R2 leaves
// applied (proven or confirmed) share the key collapse's identity (src/key-identity.mjs keyGroupIdentity, within their key fold), and no
// confirmed member shares it with a proven applied send to the host outside the group: the collapse would count those as one application
// where R2 counts two, for example two proven replies under one key with two minted ids (PR373-REVIEW major 1). Anything else is silent.
export function deriveReadBack({ window, reads, inDoubt, applies }) {
  const out = new Map(), failed = reason => ({ resolver: 'r2', status: 'failed', reason });
  const rec = window?.scope?.readBack, events = Array.isArray(window?.events) ? window.events : [];
  if (!validReadBackRecord(rec)) { for (const e of reads.keys()) out.set(e, failed('declaration-invalid')); return out; }
  const sends = events.filter(x => plain(x) && x.operation === 'send' && x.outcome === 'committed');
  const done = new Set();
  for (const e of reads.keys()) {
    if (done.has(e)) continue;
    const g = e.upstream.readBack;
    const members = g.group === null ? [] : sends.filter(x => x.name === e.name && x.upstream?.readBack?.group === g.group).sort((a, b) => a.seq - b.seq);
    if (!members.includes(e)) { done.add(e); out.set(e, failed('group-unreadable')); continue; }
    const needing = members.filter(x => inDoubt(x) && x.upstream?.transport?.connected === true);
    const group = needing.filter(x => reads.has(x));
    for (const x of group) done.add(x);
    const settle = result => { for (const x of group) out.set(x, typeof result === 'function' ? result(x) : result); };
    if (group.length !== needing.length || !needing.every(applies)) { settle(failed('group-unresolved')); continue; }
    const read = reads.get(group[0]);
    if (!group.every(x => stable(reads.get(x)) === stable(read))) { settle(failed('record-mismatch')); continue; }
    const verdict = decideGroup({ window, rec, route: rec.hosts[e.name].routes[g.route], e, members, needing, read, sends });
    settle(verdict.failed ? failed(verdict.failed) : x => ({ resolver: 'r2', status: 'succeeded', result: verdict.results.get(x) ?? 'silent' }));
  }
  return out;
}
const READ_REASON = { status: 'status', unproven: 'unproven', 'not-json': 'not-json', shape: 'shape', 'over-cap': 'over-cap', ids: 'ids', incomplete: 'incomplete', timeout: 'timeout', failed: 'failed', abandoned: 'abandoned', 'not-run': 'not-run' };
function decideGroup({ window, rec, route, e, members, needing, read, sends }) {
  const fail = reason => ({ failed: reason }), silent = { results: new Map() };
  const g = e.upstream.readBack;
  if (read.group !== g.group) return fail('group-mismatch');
  if (read.credential !== g.credential) return fail('credential-mismatch');
  if (members.length > READ_BACK_BOUNDS.members) return fail('group-too-large');
  if (read.groupSends !== members.length) return fail('group-other-window');
  if (members.filter(x => x.upstream.readBack.preImage === 'first').length !== 1 || members.some(x => !['first', 'member'].includes(x.upstream.readBack.preImage))) return fail('pre-image-order');
  if (members.some(x => !plain(x.upstream.transport))) return fail('member-unsettled');
  for (const k of READ_KINDS) if (read[k].outcome !== 'ok') return fail(k === 'pre' && read[k].outcome === 'abandoned' ? 'pre-image-abandoned' : `${k === 'pre' ? 'pre-image' : `read-${k}`}-${READ_REASON[read[k].outcome]}`);
  const lastEnd = Math.max(...members.map(x => x.upstream.transport.mono));
  // Every member's forward started after the pre-image ended (the recorder makes each wait for it; the forward start is sealed).
  if (members.some(x => x.upstream.readBack.forwardMono === null || read.pre.doneMono > x.upstream.readBack.forwardMono)) return fail('pre-image-late');
  if (read.s1.atMono < lastEnd + route.settleMs) return fail('read-before-bound');
  if (read.s2.atMono < read.s1.atMono + route.settleMs) return fail('reads-too-close');
  if (read.s3.atMono < read.s2.doneMono) return fail('read-order');
  // Preconditions for any decision: unmet, R2 is silent (a succeeded read with no information), never failed.
  if (read.early || members.some(x => x.upstream.readBack.authorInBody) || read.pre.mInRead > 0) return silent;
  const t0 = read.pre.atMono, t2 = read.s2.doneMono, local = localCounts(rec, e, sends, t0, t2);
  if (read.intervening > 0 || local.intervening > 0) return silent;
  const proven = members.filter(x => x.upstream.proven === true && x.upstream.outcome === 'applied'), P = proven.length, D = needing.length;
  const minted = proven.map(x => x.upstream.minted);
  if (P > 0 && !(minted.every(list => Array.isArray(list) && list.length === 1) && new Set(minted.map(list => list[0])).size === P)) return silent;
  // S3 only blocks: an unexplained removal, or more late items of G's identity than later sends under its credential to the object explain.
  if ((read.s3.missingPre > 0 || read.s3.mInRead < P) && read.laterRemovals === 0) return fail('read-late-removal');
  if (read.s3.credChanged > read.laterCred || read.s3.lateNew > read.laterTouching) return fail('read-late-item');
  const gu = route.guarantees, view = route.view;
  const controlShows = c => read[c] !== null && read[c].outcome === 'ok' && read[c].credItems >= 1;
  const sighted = k => read[k].mInRead === P && (read[k].credItems >= 1 || controlShows('control') || controlShows('controlStart'));
  // Refutation and the cap read a missing new item: only a POST on a host that declares the ids its replies mint (blocker 1).
  const creates = route.write.startsWith('POST ') && (window?.scope?.forward?.[e.name]?.ids?.minted?.length ?? 0) >= 1;
  const refutable = creates && gu !== null && gu.source !== 'observed' && gu.consistency === 'strong' && ['never', 'tombstoned'].includes(gu.removal) && gu.completeness === 'exhaustive-pagination' && route.complete !== null
    && READ_KINDS.every(k => read[k].complete === true) && view !== null && view.items === 'all-items' && read.identity !== null && view.covers.includes(read.identity)
    && members.every(x => deferredClear(x, route.deferredFields) && x.upstream.target?.query === false && x.upstream.readBack.scopeUndeclared === false)
    && sighted('s1') && sighted('s2') && ['s1', 's2', 's3'].every(k => read[k].missingPre === 0) && offsetsStable(members, [read.s1, read.s2, read.s3]);
  const confirmable = route.match !== null && read.identity !== null && read.credOthers === 0 && local.credOthers === 0 && read.s1.missingPre === 0 && read.s2.missingPre === 0
    && read.s2.credChanged === 0 && read.s1.credUnmatched === 0 && read.s1.credOther === 0;
  const n = Math.max(read.s1.newIds - read.s1.newInM, read.s2.newIds - read.s2.newInM);
  const low = confirmable ? P + read.s1.credApplied : P;
  let high = refutable ? P + Math.min(D, n) : P + D;
  if (refutable && confirmable && read.s1.anonNew === 0 && read.s2.anonNew === 0) high = Math.min(high, low);
  if (low > high) return fail('read-conflict');
  if (low !== high) return silent;
  const standing = members.filter(x => !provenRejected(x) && x.upstream.transport.connected !== false);
  const one = new Set(standing.map(identityOf)).size === 1, k = low - P;
  if (k === 0 ? !(P === 0 || one) : !one) return silent;
  if (collapses(window, e.name, sends, proven, needing.slice(0, k))) return silent;
  return { results: new Map(needing.map((x, i) => [x, i < k ? 'confirms' : 'refutes'])) };
}

// Whether R2's applications would reach the key collapse as fewer (PR373-REVIEW major 1): two applied members (proven, or about to be confirmed)
// with one key identity (the fold and src/key-identity.mjs keyGroupIdentity over the fold's sends in window order, as src/idempotency.mjs
// groups them), or a confirmed member with the key identity of a proven applied send to the host. A send without a readable key counts alone.
function collapses(window, host, sends, proven, confirmed) {
  const hostSends = sends.filter(x => x.name === host), folds = new Map();
  for (const x of hostSends) { const r = x.idempotency; if (plain(r) && ['keyed', 'overlap'].includes(r.status) && typeof r.fold === 'string') { if (!folds.has(r.fold)) folds.set(r.fold, []); folds.get(r.fold).push(x); } }
  const idOf = new Map();
  for (const [fold, all] of folds) { const identity = keyGroupIdentity(window, host, hostSends)(all); for (const x of all) idOf.set(x, `${fold}\n${identity(x)}`); }
  const outside = new Set(hostSends.filter(x => !proven.includes(x) && x.upstream?.proven === true && x.upstream.outcome === 'applied' && idOf.has(x)).map(x => idOf.get(x)));
  const seen = new Set();
  for (const x of [...proven, ...confirmed]) {
    if (!idOf.has(x)) continue;
    const id = idOf.get(x);
    if (seen.has(id) || (confirmed.includes(x) && outside.has(id))) return true;
    seen.add(id);
  }
  return false;
}

// The observers whose R2 reads disagree for one group (or name two identities for one credential), over everything the run's resolver reads
// returned (items: { observer, records }): a recorder reads a group once, so such reads are not one recorder's. The connector fails them all
// (src/in-doubt.mjs lateEntriesFor) and the validator refuses them (consistentReadBackRun), so the two sides never disagree about a run.
export function readBackDisagreeing(items) {
  const groups = new Map(), creds = new Map(), bad = new Set();
  for (const x of Array.isArray(items) ? items : []) for (const r of Array.isArray(x?.records) ? x.records : []) {
    if (r?.resolver !== 'r2' || !plain(r.read)) continue;
    const gk = `${x.observer}\n${r.read.group}`, ck = `${x.observer}\n${r.read.credential}`;
    if (groups.has(gk) && groups.get(gk) !== stable(r.read)) bad.add(x.observer);
    if (creds.has(ck) && creds.get(ck) !== r.read.identity) bad.add(x.observer);
    groups.set(gk, stable(r.read)); creds.set(ck, r.read.identity);
  }
  return bad;
}
// Run checks (src/contracts.mjs): one read per group and one identity per credential for each recorder, across every row, and the recorder's
// run-wide counts no lower than every sealed window of the run shows (the group's sends; sends that surely overlap [pre-image, S2] and may touch
// its read, or may carry its credential). rows: [{ resolutions, windows }] per effect row; sealedWindows: every sealed window of the run.
// Throws read-back-run.
export function consistentReadBackRun(rows, sealedWindows) {
  const bad = () => { throw new Error('read-back-run'); };
  const items = (Array.isArray(rows) ? rows : []).flatMap(({ resolutions }) => (Array.isArray(resolutions) ? resolutions : []).map(entry => ({ observer: entry.observer, records: entry.records })));
  if (readBackDisagreeing(items).size) bad();
  for (const { resolutions, windows } of Array.isArray(rows) ? rows : []) for (const entry of Array.isArray(resolutions) ? resolutions : []) for (const r of entry.records) {
    if (r?.resolver !== 'r2' || !Object.hasOwn(r, 'read')) continue;
    const w = windows.find(x => x.instanceId === entry.observer), e = w?.events.find(x => x.seq === entry.seq);
    if (!plain(e?.upstream?.readBack) || !validReadBackRecord(w.scope?.readBack)) bad();
    const own = sealedWindows.filter(x => x.instanceId === entry.observer).flatMap(x => x.events);
    if (r.read.groupSends < own.filter(x => x.name === e.name && x.upstream?.readBack?.group === r.read.group).length) bad();
    if (r.read.pre.atMono === null || r.read.s2.doneMono === null) continue;
    const local = localCounts(w.scope.readBack, e, own, r.read.pre.atMono, r.read.s2.doneMono);
    if (r.read.intervening < local.intervening || r.read.credOthers < local.credOthers) bad();
  }
}

// Profile checks (src/contracts.mjs). Names only: the read credential is never an actor's, an observer's, a forward proof's, a signing secret's or
// an identity's variable, and an identity is never a proof or signing secret; a read-back host is declared on one egress recorder only (another
// recorder's sends to it would be writes the reads see and the group never does). Returns a message, or null. Values are compared at run start
// (readBackSecretValueClash).
export function readBackClash(target) {
  const observers = Array.isArray(target?.observers) ? target.observers : [];
  const named = new Map();
  for (const [alias, actor] of Object.entries(plain(target?.actors) ? target.actors : {})) for (const [k, v] of Object.entries(plain(actor) ? actor : {})) if (/Env$/.test(k) && typeof v === 'string') named.set(v, `actor "${alias}"`);
  for (const o of observers) for (const [k, v] of Object.entries(plain(o) ? o : {})) if (/Env$/.test(k) && typeof v === 'string') named.set(v, `observer "${o.id}"`);
  const secrets = new Map();
  for (const o of observers) for (const d of o?.type === 'egress-recorder' && Array.isArray(o.destinations) ? o.destinations : []) {
    if (typeof d?.forward?.proofEnv === 'string') secrets.set(d.forward.proofEnv, `the forward proof of "${d.host}"`);
    for (const s of Array.isArray(d?.idempotency?.signing?.secretEnv) ? d.idempotency.signing.secretEnv : []) secrets.set(s, `a signing secret of "${d.host}"`);
  }
  const reads = new Map(), identities = new Map();
  for (const o of observers) for (const d of o?.type === 'egress-recorder' && Array.isArray(o.destinations) ? o.destinations : []) {
    if (!plain(d?.readBack)) continue;
    if (typeof d.readBack.credential?.env === 'string') reads.set(d.readBack.credential.env, d.host);
    for (const v of Object.values(plain(d.readBack.identities) ? d.readBack.identities : {})) if (typeof v?.env === 'string') identities.set(v.env, d.host);
  }
  for (const [env, host] of reads) {
    const clash = named.get(env) ?? secrets.get(env) ?? (identities.has(env) ? `an identity of "${identities.get(env)}"` : null);
    if (clash) return `the read-back credential of "${host}" is also ${clash.startsWith('the') || clash.startsWith('a') ? clash : `the credential of ${clash}`}: the read credential is ScopeHaven's alone, never one the application holds`;
  }
  for (const [env, host] of identities) if (secrets.has(env)) return `an identity of "${host}" names ${secrets.get(env)}: an identity is a write credential the application sends, never a proof or signing secret`;
  for (const o of observers) {
    if (o?.type !== 'egress-recorder' || !Array.isArray(o.destinations)) continue;
    for (const d of o.destinations) {
      if (!plain(d?.readBack)) continue;
      const other = observers.find(x => x !== o && x?.type === 'egress-recorder' && Array.isArray(x.destinations) && x.destinations.some(y => y?.host === d.host));
      if (other) return `the read-back host "${d.host}" of egress recorder "${o.id}" is also a destination of egress recorder "${other.id}": a read-back host is declared on one recorder only, so every write the reads can see is one the groups can see`;
    }
  }
  return null;
}
// Values (run start, before any observer starts; the connector calls it beside signingSecretValueClash): a read credential whose value is an
// actor's credential, an identity's, a forward proof secret or a signing secret is refused. Values are compared and dropped; nothing is kept.
export function readBackSecretValueClash(target, env) {
  const value = name => (typeof name === 'string' && ENV.test(name) && typeof env?.[name] === 'string' && env[name].length ? env[name] : null);
  const observers = Array.isArray(target?.observers) ? target.observers : [];
  const held = [];
  for (const actor of Object.values(plain(target?.actors) ? target.actors : {})) if (typeof actor?.credentialEnv === 'string') held.push(value(actor.credentialEnv));
  for (const o of observers) for (const d of o?.type === 'egress-recorder' && Array.isArray(o.destinations) ? o.destinations : []) {
    held.push(value(d?.forward?.proofEnv));
    for (const s of Array.isArray(d?.idempotency?.signing?.secretEnv) ? d.idempotency.signing.secretEnv : []) held.push(value(s));
    for (const v of Object.values(plain(d?.readBack?.identities) ? d.readBack.identities : {})) held.push(value(v?.env));
  }
  for (const o of observers) for (const d of o?.type === 'egress-recorder' && Array.isArray(o.destinations) ? o.destinations : []) {
    const mine = value(d?.readBack?.credential?.env);
    if (mine !== null && held.some(v => v !== null && v === mine)) return `the read-back credential of "${d.host}" holds the value of a credential the application or the forward holds: the read credential must be ScopeHaven's alone`;
  }
  return null;
}
// Whether a profile (or a run's observer records) declares read-back, and the run-end reserve its reads need (ADDENDUM-R2 m3): per route, two
// settle bounds and three read bounds after the last connection end, the largest over every declared route.
export const readBacksDeclared = observers => (Array.isArray(observers) ? observers : []).some(o => o?.type === 'egress-recorder' && Array.isArray(o.destinations) && o.destinations.some(d => plain(d?.readBack)));
export const readBackReserveMs = observers => Math.max(0, ...(Array.isArray(observers) ? observers : []).filter(o => o?.type === 'egress-recorder' && Array.isArray(o.destinations))
  .flatMap(o => o.destinations.filter(d => plain(d?.readBack) && Array.isArray(d.readBack.routes)).flatMap(d => d.readBack.routes.map(r => 2 * (Number.isSafeInteger(r?.settleMs) ? r.settleMs : 0) + 3 * (d.readBack.timeoutMs ?? READ_BACK_BOUNDS.defaultTimeoutMs)))));
// The largest declared route settleMs (src/contracts.mjs: never past the target's effect horizon).
export const readBackMaxSettleMs = observers => Math.max(0, ...(Array.isArray(observers) ? observers : []).filter(o => o?.type === 'egress-recorder' && Array.isArray(o.destinations))
  .flatMap(o => o.destinations.filter(d => plain(d?.readBack) && Array.isArray(d.readBack.routes)).flatMap(d => d.readBack.routes.map(r => (Number.isSafeInteger(r?.settleMs) ? r.settleMs : 0)))));
