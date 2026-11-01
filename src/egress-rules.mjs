// Egress recorder configuration (pure; shared by src/contracts.mjs and the
// observer in integrations/observers/egress-recorder.mjs).
//
// The recorder is a loopback sink for the application's outbound HTTP. By default it never
// forwards: every request is answered by the sink itself (a destination may opt in to forwarding,
// destinations[].forward below). Its silence counts
// as authoritative only when "routing" is declared (how the app's outbound
// calls reach the sink) and each window's witness proves the route was live:
//   routing: "proxy"    - the app's HTTP client uses the sink as its forward
//                         proxy (HTTP_PROXY): plain-HTTP requests arrive in
//                         absolute form; HTTPS arrives as CONNECT host:port,
//                         which is recorded and refused (no tunnel)
//   routing: "base-url" - the app's per-destination base URLs point at the
//                         sink, under one declared path prefix per destination
// Without "routing" (and "witness") the observer is presence-only: a recorded
// send shows it happened, and no record proves nothing.
//
// destinations: [{ host, paths?, capture? }] - the hosts checks name (effect name = host).
//   paths are literal path prefixes that name an event's resource
//   ("POST /v1/charges"); any other path reads "POST *". Raw paths and queries
//   are never stored (webhook URLs often carry their secret in the path).
//   capture: { pointers, maxBytes?, encodings? } - opt-in: up to 16 JSON pointers to scalar fields of
//   this destination's JSON request bodies on its declared paths, read and stored on each send event
//   (src/body-fields.mjs). A destination that declares capture must declare paths; a send on any other
//   path of the host records capture status "path-undeclared" and no values.
//   Off by default (bodies stay salted digests); a pointer naming a secret-like key is refused;
//   maxBytes (1024 to 65536, default 16384, at most maxBodyBytes) bounds the body read for parsing.
//   encodings ["json", "form"] also reads those fields from form-encoded bodies (src/body-fields.mjs).
//   idempotency: { header | pointer, methods?, volatile?, maxBytes? } - opt-in (src/idempotency.mjs): the request header, or the
//   JSON body pointer, carrying the key or event id this destination's provider or receiver dedupes by; each send records a salted key record, and an effect.count clause with
//   countBy "idempotency-key" counts an exact keyed replay of one application once.
// routes (base-url only): [{ prefix: "/pay/", host }] - the sink path prefix
//   each destination's base URL points at; prefixes never overlap.
// witness: { actorId, method: "GET", path, host } - an app request (path) that
//   makes the app send one outbound request to the witness host carrying the
//   query parameter scopehaven_witness=<nonce>. The witness host is never a
//   destination, and its request is never an effect.
// destinations[].correlation: { header } - opt-in (run settlement, src/http-settlement.mjs): read this one
//   request header on this destination's sends and record the token one well-formed value carries in the
//   event's correlation.settlementToken, a key no selector or pairing pin reads (src/effect-events.mjs). It must
//   name the target's declared correlation header (src/contracts.mjs). The app writes the value: any well-formed
//   one is recorded, whether or not the connector sent it. A missing, repeated or malformed header records no token. The witness host is never a destination, so
//   a witness send never carries a recorded token.
// destinations[].forward: { upstream: "http://127.0.0.1:<port>", rejected?, timeoutMs?, maxReplyBytes? } - opt-in
//   (readiness edge E1, src/effect-outcome.mjs): each send to this host is recorded as above, then its recorded bytes
//   are forwarded to the declared loopback upstream and the upstream's reply (bounded) goes back to the app; the send
//   event records the upstream outcome (applied, rejected or unknown). A forwarded host takes no static replies.
// destinations[].objectPaths / objectFields - opt-in (in-doubt resolution IDR-0, IN-DOUBT-LEAD-RULING-IDR0 R-1), forwarded destinations only:
//   which routes name one object and how, so an effect.only outcomeJudged selector (integrations/collateral/only.mjs) judges by outcome only
//   sends on the asked-for object. objectPaths: ["POST /tickets/{ticket}/close", ...], route templates with at least one {name} segment;
//   a selector binds each by a literal path segment. objectFields: { "POST /v1/refunds": ["/charge"], ... }, a declared path's route and
//   the captured body pointers that together identify its object; a selector pins each with equals. Methods that can change state only.
//   The declaration is the operator's trust: ScopeHaven refuses what it can detect (no {} segment, a route on an undeclared path, a pointer
//   not captured, one route in both forms), not a template that really names a collection.
// requestFeed: { feedId, endpoint, publicKey, hosts, routes, maxSkewMs, watermark?, tenant? } - opt-in (in-doubt resolution R1, IDR-4,
//   src/request-feed-rules.mjs): a provider-signed feed of the requests the provider received on some forwarded, keyed destinations of this
//   recorder, read on 127.0.0.1 at the recorder's start and at run end, joined to this recorder's own sends by their exact idempotency key.
// destinations[].readBack, credentialHeader, backend - opt-in (in-doubt resolution R2, IDR-3, src/read-back-rules.mjs), on a destination that
//   forwards under proof /2: ScopeHaven's own reads of the system of record the destination writes to, sent straight to its forward upstream
//   on 127.0.0.1 under a read credential the application never holds, before a group's first write and after a declared settlement bound.
//   credentialHeader names the header whose one value the recorder keeps per send as a salted digest; backend labels the forwarded
//   destinations that write to one system of record (a forwarded destination without one is in every backend).
// destinations[].aliases: [host, ...] - opt-in (FIX-04 option 2, egress-recorder/11): up to 8 other names the destination's provider
//   serves the same API under (a regional or legacy host). A send to an alias (proxy routing, a CONNECT tunnel included) is recorded
//   under the destination's host, read on its declared paths, captured, keyed and forwarded as a send to it. Its key record's head keeps
//   the target and Host header it was sent with, so a keyed retry under another name than the first send's is never read as an exact
//   replay (the cautious reading: a provider's regions need not share one key store). An alias is a lowercase host name that is not a
//   declared destination, the witness host, or another destination's alias. The scope publishes them.
// Undeclared sibling hosts (FIX-04 option 1, egress-recorder/11, siblingsOf below): an undeclared host that shares its registrable
//   domain (src/public-suffix.mjs) with a declared destination or one of its aliases may be another name of that provider. In a check
//   window a completed send to one is a scoped entry for each such destination (egress-undeclared-sibling-host), so a clause that
//   selects one reads missing; in every other window (a settlement gap, a barrier, the run's tail) it makes the window partial, so
//   settlement withholds every earlier absence pass that recorder decided. Declare the host, or declare it as an alias.
// The run's other recorders (FIX-08, egress-recorder/13, crossDestinationsOf below): operator input the factory builds from the profile (a
//   profile cannot set it). A recorder also reads the destinations the run's other egress recorders declare and it does not: a send to one
//   of those hosts or its aliases is recorded under that host, its resource read on that host's declared paths, and an undeclared host that
//   shares a registrable domain with one is its sibling as above. The scope and the run record publish them (scope.cross), and a window that
//   holds such a send or sibling is one that can see that destination (src/effect-events.mjs windowSees), so a clause on it reads the send
//   whichever recorder held it. A run with one egress recorder has none, and reads exactly as before.
// reply: { status } - what the sink answers (default 202, empty body).
// replies: [{ host, method?, path?, status, json }] - test-mode answers for SDKs and
//   webhook senders that read the response (for example a payment client that needs a
//   charge object). Static declared JSON only: a reply never echoes anything from the
//   request. The first matching entry wins (host, then method and path prefix when
//   given); anything else gets "reply". Replies change what the app sees, never what
//   is recorded.
import { validateCaptureDeclaration, CAPTURE_BOUNDS } from './body-fields.mjs';
import { validateIdempotencyDeclaration } from './idempotency.mjs';
import { validateForwardDeclaration } from './effect-outcome.mjs';
import { validateRequestFeedConfig } from './request-feed-rules.mjs';
import { validateReadBackDestination } from './read-back-rules.mjs';
import { registrableDomain } from './public-suffix.mjs';
export const EGRESS_BOUNDS = Object.freeze({ destinations: 64, paths: 128, routes: 64, replies: 32, replyBytes: 16384, quietMs: [100, 10000], witnessWaitMs: [0, 30000], maxBodyBytes: [1024, 16 * 1024 * 1024], port: [1024, 65535], aliases: 8 });
export const EGRESS_ROUTING = Object.freeze(['proxy', 'base-url']);
const KEYS = ['id', 'type', 'port', 'routing', 'destinations', 'routes', 'witness', 'witnessWaitMs', 'quietMs', 'maxBodyBytes', 'reply', 'replies', 'settleMs', 'requestFeed'];
const REPLY_KEYS = ['host', 'method', 'path', 'status', 'json'];
const REPLY_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
const WITNESS_KEYS = ['actorId', 'method', 'path', 'host'];
const HOST = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const PATH_PREFIX = /^\/[A-Za-z0-9._~\-/]{0,199}$/;
const ROUTE_PREFIX = /^\/[A-Za-z0-9._~-]{1,64}\/$/;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
// Object routes (objectPaths, objectFields): "METHOD /segment/..." with no empty segment; a template segment is {name}.
export const OBJECT_BOUNDS = Object.freeze({ routes: 16, pointers: 8 });
export const OBJECT_METHODS = Object.freeze(['POST', 'PUT', 'PATCH', 'DELETE']);
const LITERAL_SEGMENT = /^[A-Za-z0-9._~-]{1,128}$/, PLACEHOLDER = /^\{([a-z][a-z0-9_]{0,31})\}$/;
// A route as { method, segments: [{ literal } | { name }] }, or null. template: whether {name} segments are allowed.
export function parseObjectRoute(route, { template = false } = {}) {
  if (typeof route !== 'string' || route.length > 200) return null;
  const m = /^([A-Z]+) (\/.*)$/.exec(route);
  if (!m || !OBJECT_METHODS.includes(m[1])) return null;
  const segments = m[2].slice(1).split('/').map(text => { const p = template ? PLACEHOLDER.exec(text) : null; return p ? { name: p[1] } : LITERAL_SEGMENT.test(text) ? { literal: text } : null; });
  return segments.length && segments.every(Boolean) ? { method: m[1], path: m[2], segments } : null;
}
// The object route a resource ("METHOD /path") names on a normalized destination: { kind: 'path', template } when it binds an objectPaths
// template (every {name} by a literal segment), { kind: 'fields', pointers } when it is an objectFields route, or null.
export function objectRouteOf(destination, resource) {
  const r = parseObjectRoute(resource);
  if (!r || !object(destination)) return null;
  if (object(destination.objectFields) && Object.hasOwn(destination.objectFields, resource)) return { kind: 'fields', pointers: [...destination.objectFields[resource]] };
  for (const template of Array.isArray(destination.objectPaths) ? destination.objectPaths : []) {
    const t = parseObjectRoute(template, { template: true });
    if (t && t.method === r.method && t.segments.length === r.segments.length && t.segments.every((s, i) => s.literal !== undefined ? s.literal === r.segments[i].literal : true)) return { kind: 'path', template };
  }
  return null;
}
// A template names at least one object segment and at least one literal one ("POST /{a}" names nothing about what it addresses;
// PR341-REVIEW-R2 nit 5), with distinct names.
const templateShaped = r => r.segments.some(s => s.name !== undefined) && r.segments.some(s => s.literal !== undefined)
  && new Set(r.segments.filter(s => s.name).map(s => s.name)).size === r.segments.filter(s => s.name).length;
function validateObjects(d, paths, capture, forward) {
  if (d.objectPaths === undefined && d.objectFields === undefined) return {};
  if (!forward) throw new Error('a destination\'s "objectPaths" and "objectFields" need "forward": only a forwarded send is judged by its outcome');
  const objectPaths = d.objectPaths ?? [], objectFields = d.objectFields ?? {};
  if (!Array.isArray(objectPaths) || objectPaths.length > OBJECT_BOUNDS.routes || new Set(objectPaths).size !== objectPaths.length
    || !objectPaths.every(t => { const r = parseObjectRoute(t, { template: true }); return r && templateShaped(r); }))
    throw new Error(`a destination's "objectPaths" lists up to ${OBJECT_BOUNDS.routes} distinct route templates ("POST /tickets/{ticket}/close"), each with at least one {name} segment, at least one literal segment, distinct names, and a method that can change state`);
  if (!object(objectFields) || Object.keys(objectFields).length > OBJECT_BOUNDS.routes || !Object.entries(objectFields).every(([route, pointers]) => {
    const r = parseObjectRoute(route);
    return r && paths.includes(r.path) && Array.isArray(pointers) && pointers.length >= 1 && pointers.length <= OBJECT_BOUNDS.pointers && new Set(pointers).size === pointers.length && pointers.every(p => capture && capture.pointers.includes(p));
  })) throw new Error(`a destination's "objectFields" maps up to ${OBJECT_BOUNDS.routes} routes ("POST /v1/refunds", a method that can change state and one of its "paths") to 1 to ${OBJECT_BOUNDS.pointers} distinct captured body pointers that identify the object`);
  if (Object.keys(objectFields).some(route => objectRouteOf({ objectPaths }, route)?.kind === 'path')) throw new Error('a route is declared in "objectPaths" or in "objectFields", never both');
  return { ...(objectPaths.length ? { objectPaths: [...objectPaths] } : {}), ...(Object.keys(objectFields).length ? { objectFields: Object.fromEntries(Object.entries(objectFields).map(([k, v]) => [k, [...v]])) } : {}) };
}
// A run record's object declarations: { [host]: { paths?, fields? } }, by shape.
export const validObjectRecord = rec => object(rec) && Object.keys(rec).length >= 1 && Object.entries(rec).every(([host, o]) => egressHost(host) && object(o) && Object.keys(o).length >= 1
  && Object.keys(o).every(k => k === 'paths' || k === 'fields')
  && (o.paths === undefined || (Array.isArray(o.paths) && o.paths.length >= 1 && o.paths.length <= OBJECT_BOUNDS.routes && o.paths.every(t => { const r = parseObjectRoute(t, { template: true }); return r !== null && templateShaped(r); })))
  && (o.fields === undefined || (object(o.fields) && Object.keys(o.fields).length >= 1 && Object.entries(o.fields).every(([route, ps]) => parseObjectRoute(route) && Array.isArray(ps) && ps.length >= 1 && ps.length <= OBJECT_BOUNDS.pointers && ps.every(p => typeof p === 'string')))));
// The run record of an egress recorder's object declarations (validated), or null when no destination declares one.
export function objectRecordOf(observer) {
  const out = {};
  for (const d of observer?.type === 'egress-recorder' && Array.isArray(observer.destinations) ? observer.destinations : []) {
    if (d?.objectPaths === undefined && d?.objectFields === undefined) continue;
    out[d.host] = { ...(d.objectPaths?.length ? { paths: [...d.objectPaths] } : {}), ...(d.objectFields && Object.keys(d.objectFields).length ? { fields: Object.fromEntries(Object.entries(d.objectFields).map(([k, v]) => [k, [...v]])) } : {}) };
  }
  return Object.keys(out).length ? out : null;
}
// FIX-04 option 2: the run record and window scope of an egress recorder's declared aliases, { [host]: [alias, ...] } (each list sorted),
// or null when no destination declares one.
export function aliasRecordOf(observer) {
  const out = {};
  for (const d of observer?.type === 'egress-recorder' && Array.isArray(observer.destinations) ? observer.destinations : []) if (Array.isArray(d?.aliases) && d.aliases.length) out[d.host] = [...d.aliases].sort();
  return Object.keys(out).length ? out : null;
}
// A published alias map, by shape: declared names only, 1 to 8 distinct sorted host names each, none a declared name or another's alias.
export const validAliasRecord = (aliases, names) => object(aliases) && Array.isArray(names) && Object.keys(aliases).length >= 1 && Object.entries(aliases).every(([host, list]) => names.includes(host)
  && Array.isArray(list) && list.length >= 1 && list.length <= EGRESS_BOUNDS.aliases && list.every(a => egressHost(a) && !names.includes(a)) && list.join('\n') === [...new Set(list)].sort().join('\n'))
  && new Set(Object.values(aliases).flat()).size === Object.values(aliases).flat().length;
// FIX-04 option 1 (egress-recorder/11): the declared destinations an undeclared host may be another name of, in names' order: each one whose
// host or a declared alias shares the host's registrable domain (src/public-suffix.mjs). A declared host or alias, an IP literal and a name
// with no registrable domain have none. names: the declared destination hosts; aliases: { [host]: [alias, ...] } or null. The recorder
// writes its entries by it and the validator binds them by it (src/http-effects.mjs), from the window's own scope and events.
export function siblingsOf(host, names, aliases = null) {
  const namesOf = name => [name, ...(aliases?.[name] ?? [])];
  if (names.some(n => namesOf(n).includes(host))) return [];
  const domain = registrableDomain(host);
  return domain === null ? [] : names.filter(n => namesOf(n).some(x => registrableDomain(x) === domain));
}
// FIX-08 (egress-recorder/13, SURPASS-BYPASS-01 M3 A-xrec): the destinations the profile's other egress recorders declare that this one
// does not, [{ host, paths, aliases }] in profile order, or null when there are none. observers: the profile's observers, the recorder
// among them. A host two other recorders declare is listed once, its paths and aliases joined. A name this recorder declares (a host or an
// alias) or its witness host is never listed, and an alias that names one of those, a listed host, or an alias two listed hosts claim is
// dropped (such a name then reads as a sibling, never as one host's). Only the factory builds it; a profile cannot set it.
export function crossDestinationsOf(observer, observers) {
  if (observer?.type !== 'egress-recorder' || !Array.isArray(observer.destinations) || !Array.isArray(observers)) return null;
  const own = new Set([...observer.destinations.flatMap(d => [d?.host, ...(Array.isArray(d?.aliases) ? d.aliases : [])]), observer.witness?.host].filter(egressHost));
  const merged = new Map();
  for (const o of observers) if (o !== observer && o?.type === 'egress-recorder' && Array.isArray(o.destinations)) for (const d of o.destinations) {
    if (!egressHost(d?.host) || own.has(d.host)) continue;
    const m = merged.get(d.host) ?? { host: d.host, paths: new Set(), aliases: new Set() };
    for (const p of Array.isArray(d.paths) ? d.paths : []) if (typeof p === 'string' && PATH_PREFIX.test(p)) m.paths.add(p);
    for (const a of Array.isArray(d.aliases) ? d.aliases : []) if (egressHost(a)) m.aliases.add(a);
    merged.set(d.host, m);
  }
  const claims = new Map();
  for (const m of merged.values()) for (const a of m.aliases) claims.set(a, (claims.get(a) ?? 0) + 1);
  const keep = a => !own.has(a) && !merged.has(a) && claims.get(a) === 1;
  const list = [...merged.values()].map(m => ({ host: m.host, paths: [...m.paths].sort((a, b) => b.length - a.length), aliases: [...m.aliases].filter(keep).sort() }));
  return list.length ? list : null;
}
// The run record and window scope of those: { [host]: [alias, ...] } (each list sorted, possibly empty), or null.
export const crossRecordOf = destinations => (Array.isArray(destinations) && destinations.length ? Object.fromEntries(destinations.map(d => [d.host, [...d.aliases]])) : null);
// A published cross record, by shape: 1 to 1024 hosts none of the recorder's names, each with up to 8 distinct sorted aliases that are
// neither its names nor a listed host, no alias under two hosts. names: the recorder's declared hosts; aliases: its own alias map or null.
export const validCrossRecord = (cross, names, aliases = null) => object(cross) && Array.isArray(names) && Object.keys(cross).length >= 1 && Object.keys(cross).length <= 16 * EGRESS_BOUNDS.destinations
  && Object.entries(cross).every(([host, list]) => egressHost(host) && !names.includes(host) && !Object.values(aliases ?? {}).flat().includes(host)
    && Array.isArray(list) && list.length <= EGRESS_BOUNDS.aliases && list.every(a => egressHost(a) && !names.includes(a) && !Object.hasOwn(cross, a) && !Object.values(aliases ?? {}).flat().includes(a)) && list.join('\n') === [...new Set(list)].sort().join('\n'))
  && new Set(Object.values(cross).flat()).size === Object.values(cross).flat().length;
// Validates the factory's cross destinations against a normalized configuration (validateEgressConfig); throws, returns them normalized.
export function validateCrossDestinations(list, cfg) {
  if (list === null || list === undefined) return null;
  const own = new Set([...cfg.destinations.flatMap(d => [d.host, ...(d.aliases ?? [])]), cfg.witness?.host].filter(Boolean));
  if (!Array.isArray(list) || !list.length || list.length > 16 * EGRESS_BOUNDS.destinations || !list.every(d => object(d) && Object.keys(d).sort().join(',') === 'aliases,host,paths' && egressHost(d.host) && !own.has(d.host)
    && Array.isArray(d.paths) && d.paths.length <= 16 * EGRESS_BOUNDS.paths && d.paths.every(p => typeof p === 'string' && PATH_PREFIX.test(p)) && new Set(d.paths).size === d.paths.length
    && Array.isArray(d.aliases) && d.aliases.every(a => egressHost(a) && !own.has(a))) || new Set(list.map(d => d.host)).size !== list.length
    || !validCrossRecord(crossRecordOf(list), cfg.destinations.map(d => d.host), aliasRecordOf({ type: 'egress-recorder', destinations: cfg.destinations }))) throw new Error('crossDestinations lists the other recorders\' destinations this recorder does not declare: { host, paths, aliases }, each host once');
  return list.map(d => ({ host: d.host, paths: [...d.paths].sort((a, b) => b.length - a.length), aliases: [...d.aliases] }));
}
// The cross destinations a window holds a send to, or a send to a sibling of (siblingsOf over the run's names), in the record's order:
// the destinations it can see beside its own (src/effect-events.mjs windowSees). Read from the window's own scope, events and entries.
export function crossSeenOf(window) {
  const cross = window?.scope?.cross;
  if (!object(cross)) return [];
  const hosts = Object.keys(cross), names = [...(Array.isArray(window.scope.names) ? window.scope.names : []), ...hosts];
  const aliases = { ...(object(window.scope.aliases) ? window.scope.aliases : {}), ...cross };
  const events = Array.isArray(window.events) ? window.events : [], entries = Array.isArray(window.scoped) ? window.scoped : [];
  const seen = new Set([...events.map(e => e?.name), ...entries.map(e => e?.name)].filter(n => Object.hasOwn(cross, n)));
  for (const e of events) if (typeof e?.name === 'string' && !Object.hasOwn(cross, e.name)) for (const s of siblingsOf(e.name, names, aliases)) if (Object.hasOwn(cross, s)) seen.add(s);
  return hosts.filter(h => seen.has(h));
}
const intIn = (value, [lo, hi]) => Number.isInteger(value) && value >= lo && value <= hi;
export const egressHost = host => typeof host === 'string' && HOST.test(host);

// Throws with a profile-facing message; returns the normalized configuration.
export function validateEgressConfig(o, actors) {
  if (!object(o) || Object.keys(o).some(key => !KEYS.includes(key))) throw new Error(`an egress-recorder observer is { ${KEYS.join(', ')} } (all but id, type, port and destinations optional)`);
  if (!intIn(o.port, EGRESS_BOUNDS.port)) throw new Error('"port" must be an integer from 1024 to 65535 (the sink listens on 127.0.0.1 and [::1])');
  if (!Array.isArray(o.destinations) || !o.destinations.length || o.destinations.length > EGRESS_BOUNDS.destinations) throw new Error('"destinations" lists 1 to 64 { host, paths?, capture? }');
  if (o.maxBodyBytes !== undefined && !intIn(o.maxBodyBytes, EGRESS_BOUNDS.maxBodyBytes)) throw new Error('"maxBodyBytes" must be an integer from 1024 to 16777216');
  const destinations = o.destinations.map(d => {
    if (!object(d) || Object.keys(d).some(key => !['host', 'paths', 'correlation', 'capture', 'idempotency', 'forward', 'objectPaths', 'objectFields', 'readBack', 'credentialHeader', 'backend', 'aliases'].includes(key)) || !egressHost(d.host)) throw new Error('each destination is { host, paths?, correlation?, capture?, idempotency?, forward?, objectPaths?, objectFields?, readBack?, credentialHeader?, backend?, aliases? } with a lowercase host name (no scheme, port or path)');
    if (d.aliases !== undefined && !(Array.isArray(d.aliases) && d.aliases.length >= 1 && d.aliases.length <= EGRESS_BOUNDS.aliases && d.aliases.every(egressHost) && new Set(d.aliases).size === d.aliases.length && !d.aliases.includes(d.host))) throw new Error(`a destination's "aliases" lists 1 to ${EGRESS_BOUNDS.aliases} distinct lowercase host names other than its own: the other names its provider serves the same API under`);
    if (d.correlation !== undefined && !(object(d.correlation) && Object.keys(d.correlation).length === 1 && correlationHeaderValid(d.correlation.header))) throw new Error(`a destination's "correlation" is { header } naming the target's correlation header (${CORRELATION_HEADER_RULE})`);
    if (d.paths !== undefined && !(Array.isArray(d.paths) && d.paths.length <= EGRESS_BOUNDS.paths && d.paths.every(p => typeof p === 'string' && PATH_PREFIX.test(p)) && new Set(d.paths).size === d.paths.length)) throw new Error('a destination\'s "paths" lists up to 128 distinct literal path prefixes ("/v1/charges")');
    const capture = d.capture === undefined ? null : validateCaptureDeclaration(d.capture, o.maxBodyBytes ?? 1024 * 1024);
    if (capture && !(d.paths ?? []).length) throw new Error('a destination that declares "capture" declares "paths": body fields are read only on those paths');
    const idempotency = d.idempotency === undefined ? null : validateIdempotencyDeclaration(d.idempotency, { correlationHeader: d.correlation?.header ?? null, maxBodyBytes: o.maxBodyBytes ?? 1024 * 1024 });
    const forward = d.forward === undefined ? null : validateForwardDeclaration(d.forward, o.port);
    const objects = validateObjects(d, d.paths ?? [], capture, forward);
    // In-doubt resolution R2 (src/read-back-rules.mjs): absent, the destination is exactly as before.
    const read = validateReadBackDestination(d, { forward, capture, idempotency, correlationHeader: d.correlation?.header ?? null });
    return { host: d.host, paths: [...(d.paths ?? [])].sort((a, b) => b.length - a.length), correlation: d.correlation?.header ?? null, ...(capture ? { capture } : {}), ...(idempotency ? { idempotency } : {}), ...(forward ? { forward } : {}), ...objects,
      ...(read.readBack ? { readBack: read.readBack, credentialHeader: read.credentialHeader } : {}), ...(read.backend !== null ? { backend: read.backend } : {}), ...(d.aliases ? { aliases: [...d.aliases] } : {}) };
  });
  if (new Set(destinations.map(d => d.host)).size !== destinations.length) throw new Error('each destination host is declared once');
  const aliasNames = destinations.flatMap(d => d.aliases ?? []);
  if (new Set(aliasNames).size !== aliasNames.length || aliasNames.some(a => destinations.some(d => d.host === a))) throw new Error('an alias names one destination only, and is never itself a declared destination');
  if (destinations.reduce((n, d) => n + (d.capture?.pointers.length ?? 0), 0) > CAPTURE_BOUNDS.pointersPerRecorder) throw new Error('one egress recorder captures at most 64 body fields in total');
  if ((o.routing === undefined) !== (o.witness === undefined)) throw new Error('"routing" and "witness" go together: absence is authoritative only on a declared route a witness proves');
  if (o.routing !== undefined && !EGRESS_ROUTING.includes(o.routing)) throw new Error(`"routing" must be one of ${EGRESS_ROUTING.join(', ')}`);
  let witness = null;
  if (o.witness !== undefined) {
    const w = o.witness;
    if (!object(w) || Object.keys(w).some(key => !WITNESS_KEYS.includes(key))) throw new Error('"witness" is { actorId, method: "GET", path, host } and nothing else');
    if (w.method !== 'GET') throw new Error('the witness must be a GET to the app');
    // A string first: Object.hasOwn coerces its key (D-01's shape; src/audit-file-rules.mjs says why).
    if (!object(actors) || typeof w.actorId !== 'string' || !Object.hasOwn(actors, w.actorId)) throw new Error('the witness "actorId" must be a declared actor');
    if (typeof w.path !== 'string' || !w.path.startsWith('/') || w.path.startsWith('//') || w.path.length > 300 || /[#\s\\]/.test(w.path)) throw new Error('the witness "path" must be an origin-form path without a fragment');
    let decoded;
    try { decoded = decodeURIComponent(w.path); } catch { throw new Error('the witness "path" must be validly percent-encoded'); }
    if (/scopehaven_witness/i.test(decoded)) throw new Error('the witness "path" cannot carry its own witness parameter');
    if (!egressHost(w.host) || destinations.some(d => d.host === w.host)) throw new Error('the witness "host" is a lowercase host name that is not a destination (the witness is never an effect)');
    if (aliasNames.includes(w.host)) throw new Error('the witness "host" is never a destination\'s alias (the witness is never an effect)');
    witness = { actorId: w.actorId, method: 'GET', path: w.path, host: w.host };
  }
  let routes = [];
  if (o.routes !== undefined) {
    if (o.routing !== 'base-url') throw new Error('"routes" are declared only with routing "base-url"');
    if (!Array.isArray(o.routes) || !o.routes.length || o.routes.length > EGRESS_BOUNDS.routes || !o.routes.every(r => object(r) && Object.keys(r).length === 2 && ROUTE_PREFIX.test(r.prefix ?? '') && egressHost(r.host))) throw new Error('"routes" lists 1 to 64 { prefix: "/name/", host }');
    routes = o.routes.map(r => ({ prefix: r.prefix, host: r.host }));
    if (new Set(routes.map(r => r.prefix)).size !== routes.length || new Set(routes.map(r => r.host)).size !== routes.length) throw new Error('each route prefix and host is declared once');
    const known = new Set([...destinations.map(d => d.host), witness?.host]);
    if (!routes.every(r => known.has(r.host))) throw new Error('each route names a declared destination or the witness host');
  }
  if (o.routing === 'base-url' && !routes.some(r => r.host === witness.host)) throw new Error('with routing "base-url", the witness host needs a route');
  if (o.witnessWaitMs !== undefined && !intIn(o.witnessWaitMs, EGRESS_BOUNDS.witnessWaitMs)) throw new Error('"witnessWaitMs" must be an integer from 0 to 30000');
  if (o.quietMs !== undefined && !intIn(o.quietMs, EGRESS_BOUNDS.quietMs)) throw new Error('"quietMs" must be an integer from 100 to 10000');
  if (o.reply !== undefined && !(object(o.reply) && Object.keys(o.reply).length === 1 && intIn(o.reply.status, [200, 599]))) throw new Error('"reply" is { status } with an HTTP status from 200 to 599');
  let replies = [];
  if (o.replies !== undefined) {
    if (!Array.isArray(o.replies) || !o.replies.length || o.replies.length > EGRESS_BOUNDS.replies) throw new Error('"replies" lists 1 to 32 { host, method?, path?, status, json }');
    replies = o.replies.map(x => {
      if (!object(x) || Object.keys(x).some(key => !REPLY_KEYS.includes(key))) throw new Error('each reply is { host, method?, path?, status, json } and nothing else');
      if (!destinations.some(d => d.host === x.host)) throw new Error('each reply names a declared destination host');
      if (destinations.some(d => d.host === x.host && d.forward)) throw new Error('a forwarded destination is answered by its upstream: it takes no "replies"');
      if (x.method !== undefined && !REPLY_METHODS.includes(x.method)) throw new Error(`a reply's "method" is one of ${REPLY_METHODS.join(', ')}`);
      if (x.path !== undefined && !(typeof x.path === 'string' && PATH_PREFIX.test(x.path))) throw new Error('a reply\'s "path" is a literal path prefix ("/v1/charges")');
      if (!intIn(x.status, [200, 599])) throw new Error('a reply\'s "status" is an HTTP status from 200 to 599');
      let body;
      try { body = JSON.stringify(x.json); } catch { body = undefined; }
      if ((x.json === null || typeof x.json !== 'object') || typeof body !== 'string' || Buffer.byteLength(body) > EGRESS_BOUNDS.replyBytes) throw new Error('a reply\'s "json" is a JSON object or array of at most 16384 bytes');
      return { host: x.host, method: x.method ?? null, path: x.path ?? null, status: x.status, body };
    });
  }
  const requestFeed = o.requestFeed === undefined ? null : validateRequestFeedConfig(o.requestFeed, { destinations, witnessHost: witness?.host ?? null, port: o.port });
  return { port: o.port, routing: o.routing ?? null, destinations, routes, witness, witnessWaitMs: o.witnessWaitMs ?? 3000, quietMs: o.quietMs ?? 300,
    maxBodyBytes: o.maxBodyBytes ?? 1024 * 1024, replyStatus: o.reply?.status ?? 202, replies, requestFeed };
}

// Correlation (run settlement, src/http-settlement.mjs). Shared by the connector (which sets the header on
// every sent check request), src/contracts.mjs (which validates the declaration) and the egress recorder
// (which reads it). The token is the sent check's random requestId, dashes removed: 32 lowercase hex.
//   traceparent  W3C Trace Context Level 1: "00-<token>-<16 random hex>-01". An app with OpenTelemetry
//                propagation forwards the trace id on its outbound requests.
//   x-<name>     a custom header carrying the requestId as a UUID (1 to 40 of a-z, 0-9 and "-" after "x-").
// The app writes what it forwards, so a token is the subject's own account of causation: settlement lets a
// token only make attribution stricter; it never releases or fails a pass (src/http-settlement.mjs).
export const CORRELATION_HEADER_RULE = '"traceparent" or an "x-" header name of 1 to 40 lowercase letters, digits or "-" that is not reserved';
const CORRELATION_RESERVED = Object.freeze(['host', 'authorization', 'proxy-authorization', 'cookie', 'connection', 'accept', 'te', 'upgrade', 'transfer-encoding', 'keep-alive']);
const CUSTOM_CORRELATION = /^x-[a-z0-9-]{1,40}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TRACEPARENT = /^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$/;
const ALL_ZERO = /^0+$/;
export function correlationHeaderValid(name) {
  if (name === 'traceparent') return true;
  return typeof name === 'string' && CUSTOM_CORRELATION.test(name) && !CORRELATION_RESERVED.includes(name) && !name.startsWith('content-') && !name.includes('scopehaven');
}
// A sent check's token, from its requestId (a UUID); null for anything else.
export const correlationToken = requestId => typeof requestId === 'string' && UUID.test(requestId) && !ALL_ZERO.test(requestId.replace(/-/g, '')) ? requestId.replace(/-/g, '').toLowerCase() : null;
// The header value the connector sends. span: 16 hex characters (the traceparent parent id), not all zero.
export function correlationHeaderValue(header, requestId, span) {
  const token = correlationToken(requestId);
  if (token === null || !correlationHeaderValid(header)) throw new Error('correlation-header');
  if (header !== 'traceparent') return requestId.toLowerCase();
  if (typeof span !== 'string' || !/^[0-9a-f]{16}$/.test(span) || ALL_ZERO.test(span)) throw new Error('correlation-header');
  return `00-${token}-${span}-01`;
}
// The token one request carries: values are every value the request sent under that header name. Exactly
// one well-formed value gives a token: a traceparent "00-<32 lowercase hex>-<16 lowercase hex>-<2 lowercase hex>"
// (its trace id), or for a custom header a UUID written in lowercase (its 32 hex digits). None, several, an
// uppercase or malformed traceparent, an all-zero trace or parent id, or a custom value with any uppercase letter
// gives null (no token recorded): nothing is re-cased or trimmed, so normalization never makes two different values
// one token. This checks the format only. It cannot tell the connector's own token from a well-formed value the
// app chose, so a recorded token is the app's account and settlement reads it only to withhold a pass.
export function correlationTokenOf(header, values) {
  if (!correlationHeaderValid(header) || !Array.isArray(values) || values.length !== 1 || typeof values[0] !== 'string') return null;
  if (header !== 'traceparent') return values[0] === values[0].toLowerCase() ? correlationToken(values[0]) : null;
  const m = TRACEPARENT.exec(values[0]);
  return m && !ALL_ZERO.test(m[1]) && !ALL_ZERO.test(m[2]) ? m[1] : null;
}
// The (observer, destination host) pairs that record the token, from a profile's observers, in profile order:
// [{ observer: <observer id>, names: [host, ...] }]. Kept on the run's settlement record and the exported suite.
export const correlationRecorded = observers => (observers ?? []).filter(o => o?.type === 'egress-recorder' && Array.isArray(o.destinations))
  .map(o => ({ observer: o.id, names: o.destinations.filter(d => d?.correlation !== undefined).map(d => d.host) })).filter(r => r.names.length > 0);
