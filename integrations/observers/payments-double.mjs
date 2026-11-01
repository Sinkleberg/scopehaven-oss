// Payments double (SURPASS-LEDGER-01): a stateful test-mode payment provider on
// loopback whose ledger the observer holds, not the application.
//
// The app's payment client is pointed at it the way an egress recorder is
// reached (routing "proxy" or "base-url", src/egress-rules.mjs), and it takes the
// same configuration, so a profile declares it as an egress-recorder observer and
// the operator's observer factory (paymentsDoubleFactory) builds this double for
// that entry. Like the recorder it never forwards: it answers every request
// itself, so nothing reaches a real provider. Unlike the recorder it keeps
// provider state (charges and refunds, test mode only) and names each send to the
// paths it models by what the app asked it to do with money:
//   charge                   a charge
//   refund original-method   a refund to the charge's own payment method
//   refund new-destination   a refund sent anywhere else
//   refund unknown-charge    a refund naming no destination, of a charge the provider never made
//   payout                   money sent to a destination outside any charge
//   read                     a plain GET of a charge or a refund (no body, no method override)
// A send is classified from everything the request carries (its path, its query
// and every body parameter, once each) and never from provider state alone: a
// refund that names a destination for a charge the double does not hold cannot be
// compared with that charge's method, so it is unclassified. On the provider host,
// any other non-GET request (a transfer, a payment intent, a path that only looks
// like a modelled one) could move money the double does not model, so it is
// unclassified too, keeping the egress recorder's name "<METHOD> *"; another plain
// GET is "GET *". A GET that carries a body (or a Transfer-Encoding saying one
// follows) or a method override could be acted on as another method, so it is
// unclassified as well. A request to another declared host keeps "<METHOD> *" as for the
// recorder, and the witness host's request is never an effect. The recorder's
// "paths" and "replies" are refused: the double names provider sends itself and
// answers as the provider.
//
// The effect recorded is the app's attempt, as for the recorder: a refund the
// provider refuses (more than the charge left, a replayed key with another body)
// is still a committed send of its class. Whether money moved is the provider
// ledger's to say, not the effect's, so no verdict depends on what earlier
// checks did to a charge.
//
// What the double keeps: amounts, currencies, object ids and salted SHA-256
// digests of payment methods, destinations and idempotency keys. Raw card or
// account identifiers and request bodies are never stored; the salt is per sealed provider (below).
// Every request is an effect, including an idempotency replay: the provider
// returns the original object (one refund in its ledger) while the app made two
// sends, so the replay counts as two effects. A key reused with another body gets
// the provider's idempotency error, and the new attempt is recorded by what it asked
// for (the replay digest covers the query and the body). A request with a live-mode
// key (sk_, rk_ or pk_live_) in its URL or any header, a Basic user name included, is
// refused and leaves the window partial; replies always carry livemode: false.
// A refund, payout or charge with a parameter the double does not model (a nested
// or redirected destination, another currency, a query parameter, a repeated
// parameter) is unclassified, so the window is partial, never a refund to the
// original method.
// Its silence is authoritative only with declared routing and a witness, exactly
// as for the egress recorder (sink-ledger.mjs keeps the windows); anything it
// could not classify (an unreadable refund or payout body) leaves the window
// partial, never absent. Its records live in the observer's process: the app can
// add a send but never change or remove one (request-path lineage).
// collectPayments observes those same attempts and separately reports only NEW
// refunds committed in that window. A correct retry is two sends, one refund.
import { createServer, request } from 'node:http';
import { isIP, createServer as createNetServer } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { makeEffect } from './events.mjs';
import { createSinkLedger } from './sink-ledger.mjs';
import { buildObservers } from './factory.mjs';
import { validateEgressConfig, egressHost } from '../../src/egress-rules.mjs';
import { observerInstanceId, settleDeclared } from '../../src/http-effects.mjs';
import { singleHeader } from '../../src/http.mjs';

export const PAYMENTS_LIMITS = Object.freeze({ retainedRequests: 20000, maxConnections: 256, headersTimeoutMs: 10000, requestTimeoutMs: 15000, maxHeaderSize: 16384, seeds: 100 });
export const PAYMENT_RESOURCES = Object.freeze(['charge', 'refund original-method', 'refund new-destination', 'refund unknown-charge', 'payout', 'read']);
export const PAYMENTS_WINDOW_SCHEMA = 'scopehaven-payments-window/1';
// In-memory custody only: copying or deserializing a bundle cannot mint evidence.
const PAYMENT_WINDOWS = new WeakSet();
const ID = /^[A-Za-z0-9_-]{1,64}$/, CURRENCY = /^[a-z]{3}$/, GENERATED_ID = /^(ch|re|po)_test_\d{6}$/, READ = /^\/v1\/(charges|refunds)\/[A-Za-z0-9_-]{1,64}$/;
// The parameters the double models, per path. Anything else makes the request unclassified.
const FIELDS = Object.freeze({ '/v1/charges': ['amount', 'currency', 'payment_method', 'description'], '/v1/refunds': ['charge', 'amount', 'currency', 'destination', 'reason'], '/v1/payouts': ['amount', 'currency', 'destination', 'description'] });
const MODELLED = Object.freeze(Object.keys(FIELDS));
// Method overrides: the headers stacks honour (Express method-override, ASP.NET, OData, Rack) and the "_method"
// parameter (Rails, Laravel, Spring). A GET is read as a GET only when it is plain: it carries no body, no
// Transfer-Encoding saying one follows and no override. A Content-Length that says a body follows is a body by
// the time the request ends; one whose body never arrives leaves the request in flight or incomplete. A "_method" body
// parameter is a body. Any other GET could be acted on as the method it names (review R3-1).
const OVERRIDE_HEADERS = Object.freeze(['x-http-method-override', 'x-http-method', 'x-method-override']);
const plainGet = (req, query, raw) => raw.length === 0 && req.headers['transfer-encoding'] === undefined
  && !OVERRIDE_HEADERS.some(name => req.headers[name] !== undefined) && !query.has('_method');
const LIVE = /\b[srp]k_live_/i;
// A live-mode key anywhere the request carries one before its body: the URL (the whole of it, each
// query name and value as a provider decodes them, and each path segment decoded) or any header, a
// Basic user name in either base64 alphabet included. One malformed escape cannot hide the rest.
function urlParts(url) {
  const q = url.indexOf('?'), path = q >= 0 ? url.slice(0, q) : url;
  const segments = path.split('/').map(segment => { try { return decodeURIComponent(segment); } catch { return segment; } });
  return [url, ...segments, ...(q >= 0 ? [...new URLSearchParams(url.slice(q + 1))].flat() : [])];
}
function liveKey(req) {
  for (const value of [...urlParts(req.url ?? ''), ...req.rawHeaders.filter((_, i) => i % 2 === 1)]) {
    if (LIVE.test(value)) return true;
    const basic = /^Basic\s+([A-Za-z0-9+/=_-]+)\s*$/i.exec(value);
    if (basic && LIVE.test(Buffer.from(basic[1], 'base64').toString('utf8'))) return true;
  }
  return false;
}
// The number of keys a JSON text names at any depth: each string token followed by a colon. A
// repeated key is one JSON.parse keeps only the last of, and a provider may keep the first.
const COLON = /\s*:/y;
function keyTokens(text) {
  let keys = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== '"') continue;
    let j = i + 1;
    while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
    COLON.lastIndex = j + 1;
    if (COLON.test(text)) keys++;
    i = j;
  }
  return keys;
}
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function freezeTree(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freezeTree(child);
    Object.freeze(value);
  }
  return value;
}
const amountOk = value => Number.isSafeInteger(value) && value > 0 && value <= 100_000_000;
const digestWith = (salt, value) => createHash('sha256').update(salt).update(String(value)).digest('hex');
// Only synthetic business identifiers are hashed here. Existing provider-ledger
// identifiers remain salted; the canonical digest lets the independent expected
// instruction be compared without retaining its raw payment-method token.
const businessDigest = value => createHash('sha256').update(String(value)).digest('hex');
const TEMPORAL_HEADERS = Object.freeze({ runId: 'run', instructionId: 'instruction', attemptId: 'attempt', authorityId: 'authority',
  principalId: 'principal', tenantId: 'tenant', currency: 'currency' });
function temporalMetadata(req) {
  const metadata = {}, problems = [];
  for (const [field, suffix] of Object.entries(TEMPORAL_HEADERS)) {
    const name = `x-scopehaven-${suffix}`;
    const values = req.rawHeaders.filter((_, i) => i % 2 === 0).filter(key => key.toLowerCase() === name);
    const value = req.headers[name];
    if (values.length !== 1 || typeof value !== 'string' || !(field === 'currency' ? CURRENCY : /^[A-Za-z0-9_.:-]{1,128}$/).test(value)) {
      metadata[field] = null; problems.push(`invalid-${field}`);
    } else metadata[field] = value;
  }
  return { metadata: Object.freeze(metadata), problems: Object.freeze(problems) };
}

// provider: { host, seed?: [{ id, paymentMethod, amount, currency }] } - operator code only. Sealed
// at once: each payment method becomes a salted digest, so whoever holds the result (the double, or
// the operator's factory between runs) keeps a salt and digests, never a raw payment identifier.
const SEALED = Symbol('payments provider, sealed');
function sealProvider(provider) {
  if (object(provider) && provider[SEALED] === true) return provider;
  if (!object(provider) || Object.keys(provider).some(k => !['host', 'seed'].includes(k))) throw new Error('A payments double is { host, seed? }.');
  const seed = provider.seed ?? [];
  if (!Array.isArray(seed) || seed.length > PAYMENTS_LIMITS.seeds || !seed.every(s => object(s) && ID.test(s.id ?? '') && typeof s.paymentMethod === 'string' && s.paymentMethod.length >= 1 && s.paymentMethod.length <= 200 && amountOk(s.amount) && CURRENCY.test(s.currency ?? ''))
    || new Set(seed.map(s => s.id)).size !== seed.length) throw new Error('Each seeded charge is { id, paymentMethod, amount, currency } with a unique id.');
  // A seed id in the double's own generated form could be taken by the app's first charge.
  if (seed.some(s => GENERATED_ID.test(s.id))) throw new Error('A seeded charge id may not take the double\'s generated form (ch_test_000001).');
  const salt = randomBytes(16);
  return Object.freeze({ [SEALED]: true, host: provider.host, salt, seed: Object.freeze(seed.map(s => Object.freeze({ id: s.id, method: digestWith(salt, s.paymentMethod), methodDigest: businessDigest(s.paymentMethod), amount: s.amount, currency: s.currency }))) });
}
function validProvider(provider, cfg, raw) {
  const sealed = sealProvider(provider);
  if (!egressHost(sealed.host) || !cfg.destinations.some(d => d.host === sealed.host)) throw new Error('The payments host must be a declared destination of the observer.');
  // The recorder's resource paths and static replies would be accepted and ignored: refuse them.
  // Body-field capture is the egress recorder's (src/body-fields.mjs): the double classifies provider bodies itself.
  if ((Array.isArray(raw.destinations) && raw.destinations.some(d => object(d) && (Object.hasOwn(d, 'paths') || Object.hasOwn(d, 'capture')))) || Object.hasOwn(raw, 'replies')) throw new Error('A payments double names provider sends itself and answers as the provider: declare no "paths", no "capture" and no "replies".');
  // Keyed retries are the egress recorder's (src/idempotency.mjs): the double keeps its own provider ledger.
  if (Array.isArray(raw.destinations) && raw.destinations.some(d => object(d) && Object.hasOwn(d, 'idempotency'))) throw new Error('A payments double keeps its own provider ledger: declare no "idempotency".');
  return sealed;
}

// retainedRequests: operator code only, as for the egress recorder.
// The Host a base-url request may name: the double itself, as the app or a container (host.docker.internal) reaches it. Its own copy
// of egress-recorder.mjs's rule, so the refund identity (integrations/temporal-contracts/identity.mjs) covers it.
const DOUBLE_HOSTS = Object.freeze(['127.0.0.1', 'localhost', 'host.docker.internal']);
const doubleHostAllowed = (req, port) => req.headers.host === undefined || DOUBLE_HOSTS.some(h => String(singleHeader(req, 'host')).toLowerCase() === `${h}:${port}`);

export function createPaymentsDouble({ instanceId = 'egress-recorder-payments', retainedRequests = PAYMENTS_LIMITS.retainedRequests, provider, ...config }) {
  const cfg = validateEgressConfig({ ...config, type: 'egress-recorder' }, config.witness ? { [config.witness.actorId]: {} } : undefined);
  const { host: payHost, seed, salt } = validProvider(provider, cfg, config);
  // The observer kind and source of an egress recorder: the run declares this double as one.
  const observer = { kind: 'http-egress-recorder', instanceId };
  // resources: the double classifies every modelled send to the provider host into PAYMENT_RESOURCES, so that host alone
  // declares them (src/http-pairing.mjs vouches a class only for the name that lists it, and only while every committed
  // send to that name in the window carries a listed class). Another declared host, an unmodelled path ("<method> *")
  // and a tunnel ("CONNECT :port") are not classified.
  const scope = { operations: ['send'], names: cfg.destinations.map(d => d.host), actorAttribution: 'none', evidence: cfg.routing ? 'authoritative' : 'presence-only', resources: { [payHost]: [...PAYMENT_RESOURCES] } };
  const marks = new WeakMap();
  let markOrder = 0;
  function originalMark(mark) {
    const state = marks.get(mark);
    if (!state || Object.getPrototypeOf(mark) !== Object.prototype) return null;
    const fields = Object.getOwnPropertyDescriptors(mark), keys = Reflect.ownKeys(fields);
    return keys.length === Object.keys(state.snapshot).length && keys.every(key => Object.hasOwn(state.snapshot, key)
      && Object.hasOwn(fields[key], 'value') && fields[key].value === state.snapshot[key]) ? state : null;
  }
  function takeWindowMarks(from, to) {
    const start = originalMark(from), end = originalMark(to);
    if (!start || !end || start.used || end.used || start.order >= end.order || start.snapshot.seq > end.snapshot.seq
      || start.snapshot.at > end.snapshot.at || start.snapshot.epoch !== end.snapshot.epoch) {
      throw new Error('A payments window needs original, ordered, unused marks from this double.');
    }
    // Consume before awaiting: neither API can reuse or steal this cutoff.
    start.used = end.used = true;
    return { start, end };
  }
  // One salt per sealed provider: a double built directly has its own; the factory seals each provider entry
  // once, so every double it builds for that entry, in every run, shares that entry's salt.
  const seal = value => digestWith(salt, value);
  const ledger = createSinkLedger({ prefix: 'payments', unit: 'request', retained: retainedRequests });
  // Provider state. Charges and refunds carry digests, never raw payment identifiers.
  const charges = new Map(), refunds = [], payouts = [], idempotent = new Map();
  let serial = 0;
  // A new id is never one already taken.
  const nextId = prefix => { let id; do id = `${prefix}_test_${String(++serial).padStart(6, '0')}`; while (charges.has(id) || refunds.some(r => r.id === id) || payouts.some(p => p.id === id)); return id; };
  // The seed arrives sealed: digests only.
  for (const s of seed) charges.set(s.id, { object: 'charge', id: s.id, amount: s.amount, currency: s.currency, method: s.method, methodDigest: s.methodDigest, refunded: 0, seeded: true });
  let temporalRun = null;
  let server = null, server6 = null, requestArriving = null;
  const normalHost = host => host.toLowerCase().replace(/^\[(.*)\]$/, '$1').replace(/\.$/, '');
  const undeclaredLiteral = host => isIP(host) !== 0 && !cfg.destinations.some(d => d.host === host);
  function locate(target) {
    if (/^https?:\/\//i.test(target)) {
      let url;
      try { url = new URL(target); } catch { return { problem: 'malformed' }; }
      if (url.username || url.password) return { problem: 'malformed' };
      return { host: normalHost(url.hostname), path: url.pathname, query: url.searchParams, via: 'proxy' };
    }
    if (typeof target !== 'string' || !target.startsWith('/') || target.startsWith('//')) return { problem: 'malformed' };
    if (cfg.routing !== 'base-url') return { problem: 'unrouted' };
    const route = cfg.routes.find(r => target.startsWith(r.prefix));
    if (!route) return { problem: 'unrouted' };
    let url;
    try { url = new URL(`http://sink/${target.slice(route.prefix.length)}`); } catch { return { problem: 'malformed' }; }
    return { host: route.host, path: url.pathname, query: url.searchParams, via: 'route' };
  }
  const parseBody = (raw, type) => {
    if (!raw.length) return {};
    const text = raw.toString('utf8');
    // A repeated parameter is unclassified: the double cannot know which one the provider keeps.
    if (/^application\/x-www-form-urlencoded/i.test(type ?? '')) {
      // A raw ";" is a parameter separator to some form parsers: a second parameter could hide in a value.
      if (text.includes(';')) throw new Error('a ";" in a form body');
      const params = new URLSearchParams(text), names = [...params.keys()];
      if (new Set(names).size !== names.length) throw new Error('a repeated parameter');
      return Object.fromEntries(params);
    }
    const value = JSON.parse(text);
    if (!object(value)) throw new Error('not an object');
    if (keyTokens(text) !== Object.keys(value).length) throw new Error('a repeated or nested key');
    return value;
  };
  const toInt = value => typeof value === 'string' && /^\d{1,9}$/.test(value) ? Number(value) : value;
  const invalid = (code = undefined) => ({ error: { type: 'invalid_request_error', ...(code ? { code } : {}) } });
  // An unclassified request keeps the recorder's name and leaves the window partial.
  const unclassified = method => ({ unclassified: true, status: 400, body: invalid(), resource: `${method} *`, outcome: 'unknown' });
  // What a provider request asks for, from everything it carries and without changing provider
  // state: { resource } for a modelled request, { unclassified } for one the double cannot classify,
  // or null for a GET it does not model (a plain GET moves no money; onRequest leaves any other GET
  // unclassified before it gets here).
  function classify(method, path, query, fields) {
    if (method === 'GET') return READ.test(path) ? { resource: 'read' } : null;
    // Any other request the double does not model could move money it cannot see: a transfer, a
    // payment intent, or a path that only decodes, case-folds or normalizes into a modelled one.
    if (method !== 'POST' || !MODELLED.includes(path)) return { unclassified: true };
    if ([...query.keys()].length || fields === null || Object.keys(fields).some(key => !FIELDS[path].includes(key)) || Object.values(fields).some(v => v !== null && typeof v === 'object')) return { unclassified: true };
    const amount = toInt(fields.amount);
    if (fields.currency !== undefined && !CURRENCY.test(fields.currency)) return { unclassified: true };
    if (path === '/v1/charges') return amountOk(amount) && CURRENCY.test(fields.currency ?? '') && typeof fields.payment_method === 'string' && fields.payment_method ? { resource: 'charge' } : { unclassified: true };
    if (path === '/v1/payouts') return amountOk(amount) && typeof fields.destination === 'string' && fields.destination && CURRENCY.test(fields.currency ?? '') ? { resource: 'payout' } : { unclassified: true };
    if (typeof fields.charge !== 'string' || (fields.amount !== undefined && !amountOk(amount)) || (fields.destination !== undefined && (typeof fields.destination !== 'string' || !fields.destination))) return { unclassified: true };
    const charge = charges.get(fields.charge);
    // A destination named for a charge the double does not hold cannot be compared with that charge's
    // method: unclassified, so the class never turns on what the operator seeded.
    if (!charge) return fields.destination === undefined ? { resource: 'refund unknown-charge' } : { unclassified: true };
    // A refund in another currency than its charge is one the double does not model.
    if (fields.currency !== undefined && fields.currency !== charge.currency) return { unclassified: true };
    const destination = fields.destination === undefined ? charge.method : seal(fields.destination);
    return { resource: destination === charge.method ? 'refund original-method' : 'refund new-destination', charge, destination };
  }
  // One provider operation: { status, body, resource, outcome, unclassified? }. Every classified
  // request is a committed send of its class (the app's attempt), whatever the provider answered.
  function operate(method, path, query, fields, idem, requestRecord) {
    const asked = classify(method, path, query, fields);
    if (asked === null) return { status: 404, body: invalid(), resource: `${method} *`, outcome: 'committed' };
    if (asked.unclassified) return unclassified(method);
    const { resource } = asked;
    if (resource === 'read') {
      const [, kind, id] = /^\/v1\/(charges|refunds)\/(.+)$/.exec(path);
      const found = kind === 'charges' ? charges.get(id) : refunds.find(r => r.id === id);
      return found ? { status: 200, body: publicView(found), resource, outcome: 'committed' } : { status: 404, body: invalid('resource_missing'), resource, outcome: 'committed' };
    }
    const amount = toInt(fields.amount);
    if (resource === 'charge') {
      const charge = { object: 'charge', id: nextId('ch'), amount, currency: fields.currency, method: seal(fields.payment_method), methodDigest: businessDigest(fields.payment_method), refunded: 0, seeded: false, idem };
      charges.set(charge.id, charge);
      return { status: 200, body: publicView(charge), resource, outcome: 'committed' };
    }
    if (resource === 'payout') {
      const payout = { object: 'payout', id: nextId('po'), amount, currency: fields.currency, destination: seal(fields.destination), idem };
      payouts.push(payout);
      return { status: 200, body: publicView(payout), resource, outcome: 'committed' };
    }
    if (resource === 'refund unknown-charge') return { status: 404, body: invalid('resource_missing'), resource, outcome: 'committed' };
    const { charge, destination } = asked;
    const value = fields.amount === undefined ? charge.amount - charge.refunded : amount;
    // The provider refuses more than the charge left. The attempt is still a committed send of its
    // class; the provider ledger shows that no money moved.
    if (value <= 0 || charge.refunded + value > charge.amount) return { status: 400, body: invalid('amount_too_large'), resource, outcome: 'committed', refused: true };
    charge.refunded += value;
    const refund = { object: 'refund', id: nextId('re'), charge: charge.id, amount: value, currency: charge.currency, destination, toOriginalMethod: destination === charge.method, idem };
    refunds.push(refund);
    // Attach once, synchronously with the new provider refund. Replays and
    // refusals never call this branch; later collections do not scan global state.
    Object.defineProperty(requestRecord, 'refundCommit', { value: Object.freeze({ seq: requestRecord.seq, id: refund.id, charge: refund.charge,
      amount: refund.amount, currency: refund.currency, destination: refund.destination,
      destinationDigest: fields.destination === undefined ? charge.methodDigest : businessDigest(fields.destination),
      toOriginalMethod: refund.toOriginalMethod, idempotency: idem }) });
    return { status: 200, body: publicView(refund), resource, outcome: 'committed' };
  }
  // What the app sees: ids, amounts, status and livemode false; never a digest.
  function publicView(o) {
    if (o.object === 'charge') return { id: o.id, object: 'charge', amount: o.amount, currency: o.currency, amount_refunded: o.refunded, status: 'succeeded', livemode: false };
    if (o.object === 'refund') return { id: o.id, object: 'refund', charge: o.charge, amount: o.amount, currency: o.currency, status: 'succeeded', livemode: false };
    return { id: o.id, object: 'payout', amount: o.amount, currency: o.currency, status: 'paid', livemode: false };
  }
  function onRequest(req, res) {
    const reply = (status, body = null) => { if (!res.headersSent) { const text = body === null ? '' : JSON.stringify(body); res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(text)), ...(status >= 400 ? { Connection: 'close' } : {}) }); res.end(text); } };
    const site = req.headers['sec-fetch-site'];
    if (req.headers.origin !== undefined || (site !== undefined && site !== 'none')) { ledger.record({ kind: 'browser' }); req.resume(); return reply(403); }
    const where = locate(req.url);
    if (where.problem) { ledger.record({ kind: where.problem }); req.resume(); return reply(where.problem === 'unrouted' ? 404 : 400); }
    // DNS rebinding: a base-url request whose Host names anything but the double is a browser's (the egress recorder's rule).
    if (where.via === 'route' && !doubleHostAllowed(req, cfg.port)) { ledger.record({ kind: 'browser' }); req.resume(); return reply(403); }
    let hostHeader = null;
    try { hostHeader = req.headers.host === undefined ? null : normalHost(new URL(`http://${req.headers.host}`).hostname); } catch { hostHeader = ''; }
    const provider = where.host === payHost;
    // A live-mode key, in any auth scheme, never reaches provider state.
    if (provider && liveKey(req)) { ledger.record({ kind: 'live-key' }); req.resume(); return reply(403, { error: { type: 'livemode_refused' }, livemode: false }); }
    const r = ledger.record({ kind: 'item', done: false, method: req.method, host: where.host, resource: provider ? null : `${req.method} *`.slice(0, 200),
      hostMismatch: where.via === 'proxy' && hostHeader !== null && hostHeader !== where.host, addressLiteral: undeclaredLiteral(where.host),
      witnessNonces: where.host === cfg.witness?.host ? where.query.getAll('scopehaven_witness') : [], bodyBytes: 0, overLimit: false, outcome: 'unknown',
      target: seal(`${where.host}\n${where.path}\n${where.query.toString()}`), idem: null });
    const temporal = provider && req.method !== 'GET' ? temporalMetadata(req) : null;
    const chunks = [];
    req.on('data', chunk => {
      if (r.overLimit) return;
      r.bodyBytes += chunk.length;
      if (r.bodyBytes > cfg.maxBodyBytes) { r.overLimit = true; r.done = true; reply(413); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (r.overLimit) return;
      const raw = Buffer.concat(chunks); chunks.length = 0;
      r.body = seal(raw.toString('base64'));
      if (!provider) { r.outcome = 'committed'; r.done = true; return reply(cfg.replyStatus); }
      const key = req.headers['idempotency-key'];
      const idem = typeof key === 'string' && key.length >= 1 && key.length <= 255 ? seal(`${req.method} ${where.path}\n${key}`) : null;
      r.idem = idem;
      let fields;
      try { fields = parseBody(raw, req.headers['content-type']); } catch { fields = null; }
      // Capture the actual business payload BEFORE operate can mutate the charge.
      // Headers are only causal claims; independently expected authority and the
      // app's dispatch record are checked later by the temporal binding adapter.
      let attemptedBinding = null;
      if (temporal && req.method === 'POST' && where.path === '/v1/refunds' && fields !== null) {
        const charge = charges.get(fields.charge);
        attemptedBinding = freezeTree({ instructionId: temporal.metadata.instructionId, authorityId: temporal.metadata.authorityId,
          principalId: temporal.metadata.principalId, tenantId: temporal.metadata.tenantId, operation: 'refund', chargeId: typeof fields.charge === 'string' ? fields.charge : null,
          amount: fields.amount === undefined ? (charge ? charge.amount - charge.refunded : null) : toInt(fields.amount),
          currency: fields.currency ?? charge?.currency ?? null,
          destinationDigest: fields.destination === undefined ? charge?.methodDigest ?? null : typeof fields.destination === 'string' ? businessDigest(fields.destination) : null });
      }
      // A replayed key with the same body gets the original answer and changes nothing; the send
      // still counts. A key reused with another body gets the provider's idempotency error, and the
      // new attempt is recorded by what it asked for (the provider changed nothing).
      const bodyDigest = seal(`${where.query.toString()}\n${raw.toString('base64')}`);
      const replay = idem && idempotent.get(idem);
      let result;
      // A GET that is not plain is unclassified first, so a replayed key cannot return it as a read.
      if (req.method === 'GET' && !plainGet(req, where.query, raw)) result = unclassified(req.method);
      else if (replay && replay.bodyDigest === bodyDigest) result = { ...replay.result, replayed: true };
      else if (replay) {
        const asked = classify(req.method, where.path, where.query, fields);
        result = asked === null ? { status: 400, body: { error: { type: 'idempotency_error' } }, resource: `${req.method} *`, outcome: 'committed', replayed: true }
          : asked.unclassified ? { ...unclassified(req.method), body: { error: { type: 'idempotency_error' } }, replayed: true }
          : { status: 400, body: { error: { type: 'idempotency_error' } }, resource: asked.resource, outcome: 'committed', replayed: true };
      } else result = operate(req.method, where.path, where.query, fields, idem, r);
      if (idem && !replay) idempotent.set(idem, { bodyDigest, result: { status: result.status, body: result.body, resource: result.resource, outcome: result.outcome, unclassified: result.unclassified } });
      Object.assign(r, { resource: result.resource, outcome: result.outcome, unclassified: Boolean(result.unclassified), replayed: Boolean(result.replayed), done: true });
      if (temporal) Object.defineProperty(r, 'temporalObservation', { value: freezeTree({ seq: r.seq, ...temporal.metadata,
        binding: attemptedBinding, problems: [...temporal.problems], providerStatus: result.status, replayed: Boolean(result.replayed),
        created: Boolean(r.refundCommit), effectId: result.status === 200 && result.body?.object === 'refund' ? result.body.id : null }) });
      reply(result.status, result.body);
    });
    req.on('close', () => { if (!r.done) { r.done = true; r.aborted = true; } });
  }
  function onConnect(req, socket) {
    const m = /^\[?([^\]]+?)\]?:(\d{1,5})$/.exec(req.url ?? '');
    if (!m) ledger.record({ kind: 'malformed' });
    else ledger.record({ kind: 'item', method: 'CONNECT', host: normalHost(m[1]), resource: `CONNECT :${Number(m[2])}`, tunnel: true, addressLiteral: undeclaredLiteral(normalHost(m[1])), witnessNonces: [], bodyBytes: 0, outcome: 'committed', target: seal(`${normalHost(m[1])}:${Number(m[2])}`), idem: null });
    socket.on('error', () => {});
    socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
  }
  // One collection owns the witness cutoff. The legacy API projects exactly its
  // previous shape, while the payments API retains both kinds of observation.
  // gap: a settlement gap window (sink-ledger.mjs), an exact range with no witness, collected after the run. final: the
  // run-end window (background attribution): nothing follows it, so a request arriving at its end mark (arrivingAtEnd),
  // or still arriving when it is collected, leaves it partial.
  async function collectRecords(from, to, witnessRequested, { gap = false, final = false, arrivingAtEnd = null } = {}) {
    const w = await ledger.window(from, to, { witness: cfg.witness !== null, witnessWaitMs: cfg.witnessWaitMs, quietMs: cfg.quietMs, gap });
    if (w.failed) return { events: [], refunds: [], lineage: [], coverage: 'failed', reason: w.failed };
    const { problems } = w, events = [], committedRefunds = [], lineage = [];
    if (!gap && cfg.witness && !witnessRequested) problems.add('payments-witness-request-not-marked');
    if ((!gap || final) && !requestArriving) problems.add('payments-parser-state-unavailable');
    else if ((!gap || final) && (requestArriving() || (final && arrivingAtEnd !== false))) problems.add('payments-request-in-flight');
    for (const r of w.items) {
      if (r.hostMismatch) problems.add('payments-host-mismatch');
      if (r.addressLiteral) problems.add('payments-address-literal');
      if (r.tunnel) problems.add('payments-tunnel-payload-unseen');
      if (r.overLimit) problems.add('payments-body-over-limit');
      if (r.aborted) problems.add('payments-request-incomplete');
      if (r.unclassified) problems.add('payments-unclassified-request');
      // A host longer than an event name can hold (128) is never an event: shortened, it could read as another (declared) host.
      if (r.host.length > 128) { problems.add('payments-host-over-limit'); continue; }
      if (events.length >= 5000) { problems.add('payments-event-limit'); continue; }
      events.push(makeEffect({ source: 'http-egress', observer, seq: r.seq, actor: null, operation: 'send', name: r.host, resource: r.resource,
        outcome: r.overLimit || r.aborted ? 'unknown' : r.outcome, correlation: r.idem ? { requestId: `idem-${r.idem.slice(0, 32)}` } : {}, content: { target: r.target, body: r.body ?? null, bodyBytes: r.bodyBytes } }));
      if (r.refundCommit) committedRefunds.push(r.refundCommit);
      if (r.temporalObservation) lineage.push(r.temporalObservation);
    }
    const reason = problems.size ? [...problems].sort().join(',').slice(0, 200) : null;
    return { events, refunds: committedRefunds, lineage, coverage: reason ? 'partial' : 'complete', reason };
  }
  return {
    kind: observer.kind, instanceId, source: 'http-egress', port: cfg.port,
    scope: freezeTree(scope),
    ...(cfg.witness ? { witnessRequest: Object.freeze({ actorId: cfg.witness.actorId, method: 'GET', path: cfg.witness.path }) } : {}),
    markWitnessRequest(from) {
      const state = originalMark(from);
      if (!state || state.used) throw new Error('A payments witness needs an original, unused mark from this double.');
      // The first request cutoff wins; repeating this call cannot admit late sends.
      if (!state.witnessRequested) { state.witnessRequested = true; ledger.markWitnessRequest(state.snapshot); }
    },
    // Operator capability, inaccessible through HTTP. A provider lifetime belongs
    // to one temporal run; wrappers and concurrent collectors cannot reuse it.
    registerTemporalRun(identity) {
      if (temporalRun) throw new Error('The payments source already belongs to a temporal run.');
      const keys = ['runId', 'targetId', 'buildHash', 'horizonId'];
      if (!object(identity) || Object.keys(identity).length !== keys.length || keys.some(k => typeof identity[k] !== 'string' || !identity[k] || identity[k].length > 128)) throw new Error('A temporal source needs an exact run, target, build and horizon identity.');
      temporalRun = freezeTree({ ...identity });
      return temporalRun;
    },
    async dispatchWitness(from) {
      const state = originalMark(from);
      if (!state || state.used) throw new Error('A payments witness needs an original, unused mark from this double.');
      if (!cfg.witness) return;
      const route = cfg.routes.find(r => r.host === cfg.witness.host);
      if (cfg.routing !== 'base-url' || !route) throw new Error('Temporal witness dispatch requires its declared loopback base-url route.');
      // This proves recorder delivery, not that the application reached or
      // closed its boundary. Keep the origin even if delivery later fails.
      state.witnessSource = 'observer-dispatched';
      if (!state.witnessRequested) { state.witnessRequested = true; ledger.markWitnessRequest(state.snapshot); }
      await new Promise((resolve, reject) => {
        const req = request({ host: '127.0.0.1', port: cfg.port, method: 'GET', path: `${route.prefix}?scopehaven_witness=${encodeURIComponent(state.snapshot.witnessNonce)}` }, res => {
          res.resume(); res.on('end', () => res.statusCode === cfg.replyStatus ? resolve() : reject(new Error('The payments witness was refused.')));
          res.on('error', reject);
        });
        req.on('error', reject); req.setTimeout(PAYMENTS_LIMITS.requestTimeoutMs, () => req.destroy(new Error('The payments witness timed out.'))); req.end();
      });
    },
    // The provider ledger as the observer holds it: digests and amounts only.
    providerLedger() {
      return Object.freeze({ livemode: false,
        charges: Object.freeze([...charges.values()].map(c => Object.freeze({ id: c.id, amount: c.amount, currency: c.currency, refunded: c.refunded, method: c.method, seeded: c.seeded }))),
        refunds: Object.freeze(refunds.map(r => Object.freeze({ id: r.id, charge: r.charge, amount: r.amount, currency: r.currency, destination: r.destination, toOriginalMethod: r.toOriginalMethod, idempotency: r.idem }))),
        payouts: Object.freeze(payouts.map(p => Object.freeze({ id: p.id, amount: p.amount, currency: p.currency, destination: p.destination, idempotency: p.idem }))) });
    },
    // The digest a payment identifier would have in this double's ledger (operator-side comparison only).
    digestOf(value) { return seal(value); },
    async start() {
      if (server) return;
      const s = createServer({ headersTimeout: PAYMENTS_LIMITS.headersTimeoutMs, requestTimeout: PAYMENTS_LIMITS.requestTimeoutMs, maxHeaderSize: PAYMENTS_LIMITS.maxHeaderSize }, onRequest);
      s.maxConnections = PAYMENTS_LIMITS.maxConnections;
      s.on('connect', onConnect);
      s.on('clientError', (_error, socket) => { ledger.record({ kind: 'malformed' }); socket.destroy(); });
      s.on('drop', () => { ledger.record({ kind: 'dropped' }); });
      // Both loopback addresses, each bound exclusively, as for the egress recorder (FIX-02): a route written as localhost may resolve to
      // ::1 first, so a listener another process held there would answer as the provider. [::1]'s listener hands each connection to the
      // HTTP server. If either bind fails, the double does not start.
      const v6 = createNetServer(socket => s.emit('connection', socket));
      v6.maxConnections = PAYMENTS_LIMITS.maxConnections;
      v6.on('drop', () => { ledger.record({ kind: 'dropped' }); });
      await new Promise((resolve, reject) => { s.once('error', reject); s.listen({ port: cfg.port, host: '127.0.0.1', exclusive: true }, () => { s.off('error', reject); resolve(); }); });
      try { await new Promise((resolve, reject) => { v6.once('error', reject); v6.listen({ port: cfg.port, host: '::1', exclusive: true }, () => { v6.off('error', reject); resolve(); }); }); }
      catch (error) { await new Promise(resolve => s.close(() => resolve())); throw error; }
      const connections = s[Object.getOwnPropertySymbols(s).find(k => k.description === 'http.server.connections')];
      requestArriving = typeof connections?.active === 'function' ? () => connections.active().length > 0 : null;
      for (const listener of [s, v6]) { listener.on('error', () => ledger.down()); listener.on('close', () => ledger.down()); }
      server = s; server6 = v6; ledger.started();
    },
    async mark() {
      const mark = ledger.position();
      // arriving: whether a request was arriving when the mark was taken (read only by a run-end collection).
      marks.set(mark, { snapshot: Object.freeze({ ...mark }), order: ++markOrder, used: false, witnessRequested: false,
        witnessSource: cfg.witness ? 'external' : 'none', arriving: requestArriving ? requestArriving() : null });
      return mark;
    },
    // A settlement gap window reads between two original marks in order without owning either: it takes no
    // witness cutoff, so it never consumes the marks a check window owns.
    async collect(from, to, { gap = false, final = false } = {}) {
      if (gap) {
        const start = originalMark(from), end = originalMark(to);
        if (!start || !end || start.order >= end.order || start.snapshot.seq > end.snapshot.seq || start.snapshot.epoch !== end.snapshot.epoch) return { events: [], coverage: 'failed', reason: 'payments-marks-invalid-or-reused' };
        const { events, coverage, reason } = await collectRecords(start.snapshot, end.snapshot, true, { gap: true, final, arrivingAtEnd: end.arriving });
        return { events, coverage, reason };
      }
      let owned;
      try { owned = takeWindowMarks(from, to); }
      catch { return { events: [], coverage: 'failed', reason: 'payments-marks-invalid-or-reused' }; }
      const { start, end } = owned;
      const { events, coverage, reason } = await collectRecords(start.snapshot, end.snapshot, start.witnessRequested);
      return { events, coverage, reason };
    },
    async collectPayments(from, to) {
      const { start, end } = takeWindowMarks(from, to);
      const { events, refunds: committedRefunds, lineage, coverage, reason } = await collectRecords(start.snapshot, end.snapshot, start.witnessRequested);
      const bundle = freezeTree({ schema: PAYMENTS_WINDOW_SCHEMA, observer: { ...observer }, window: { from: start.snapshot, to: end.snapshot },
        witnessSource: start.witnessSource,
        scope: { operations: ['refund'], names: [payHost], actorAttribution: 'none', evidence: scope.evidence }, coverage, reason,
        attempts: { source: 'http-egress', instanceId, scope, events, coverage, reason }, refunds: committedRefunds, lineage, temporalRun });
      PAYMENT_WINDOWS.add(bundle);
      return bundle;
    },
    async stop() {
      const s = server, v6 = server6; server = null; server6 = null; ledger.stopped();
      if (s) await Promise.all([new Promise(resolve => v6.close(() => resolve())), new Promise(resolve => { s.close(() => resolve()); s.closeAllConnections(); })]);
    },
  };
}

// Verification only: there is deliberately no API that brands imported data.
export function isAuthenticPaymentsWindow(bundle) { return PAYMENT_WINDOWS.has(bundle) && Object.isFrozen(bundle); }

// Exact NEW-refund count for one observer-minted window, not a send-attempt
// count or a lifetime snapshot. Only complete, authoritative custody decides it.
export function evaluateRefundCount(assertion, bundle) {
  const keys = ['kind', 'charge', 'expected'];
  if (!object(assertion) || ![Object.prototype, null].includes(Object.getPrototypeOf(assertion))
    || Reflect.ownKeys(assertion).length !== keys.length || Reflect.ownKeys(assertion).some(key => !keys.includes(key))
    || keys.some(key => !Object.hasOwn(Object.getOwnPropertyDescriptor(assertion, key), 'value'))
    || assertion.kind !== 'payment.refund.count' || typeof assertion.charge !== 'string' || !ID.test(assertion.charge)
    || !Number.isSafeInteger(assertion.expected) || assertion.expected < 0) {
    throw new Error('A refund count is { kind: "payment.refund.count", charge: <exact charge id>, expected: <safe nonnegative integer> }.');
  }
  const result = (verdict, matched, basis) => ({ kind: assertion.kind, verdict, matched, expected: assertion.expected, basis });
  if (!PAYMENT_WINDOWS.has(bundle) || !Object.isFrozen(bundle)) {
    return result('inconclusive', null, 'Refund counts require the original in-memory observer-minted payments window.');
  }
  if (bundle.witnessSource === 'observer-dispatched') {
    return result('inconclusive', null, 'An observer-dispatched witness requires independent closure; the payment window alone cannot establish it.');
  }
  if (bundle.coverage !== 'complete' || bundle.scope.evidence !== 'authoritative') {
    return result('inconclusive', null, `Refund count needs complete authoritative coverage (${bundle.coverage}, ${bundle.scope.evidence}${bundle.reason ? `, ${bundle.reason}` : ''}).`);
  }
  const matched = bundle.refunds.filter(refund => refund.charge === assertion.charge).length;
  return result(matched === assertion.expected ? 'pass' : 'fail', matched, `Observed ${matched} newly committed refunds for ${assertion.charge}; expected ${assertion.expected}.`);
}

// Operator code: an observer factory for runHttpAssessment that builds this double
// for the profile's egress-recorder entries named in `providers` (by observer id)
// and every other entry as usual. A profile cannot choose the double itself.
export function paymentsDoubleFactory(providers, build = buildObservers) {
  if (!object(providers)) throw new Error('Name the payments doubles by observer id.');
  // Sealed now: the factory keeps each provider's host, a salt and digests, never the operator's
  // object or a raw payment method, and a later edit to that object changes nothing.
  const sealed = new Map(Object.entries(providers).map(([id, provider]) => [id, sealProvider(provider)]));
  const doubles = new Map();
  const factory = (configs, options) => {
    const built = build(configs, options);
    return configs.map((c, i) => {
      if (!sealed.has(c.id)) return built[i];
      if (c.type !== 'egress-recorder') throw new Error(`Observer "${c.id}" must be declared as an egress-recorder to be served by a payments double.`);
      const { id, type, settleMs, ...config } = c;
      // The operator's provider and the instance id are set last, so no profile field can replace them.
      const double = Object.assign(createPaymentsDouble({ ...config, instanceId: observerInstanceId(type, id), provider: sealed.get(id) }), { postResponseSettleMs: settleDeclared(settleMs) ? settleMs : null });
      doubles.set(id, double);
      return double;
    });
  };
  // The doubles built for the last run, so the operator can read the provider ledger afterwards.
  return Object.assign(factory, { doubles });
}
