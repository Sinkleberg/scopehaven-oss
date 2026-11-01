// Signed-webhook driver (lane WH). Pure: no I/O and no network. It builds a check's request the way a provider sends a
// webhook: the body bytes (form-encoded or JSON), the provider's documented headers, and the signature computed over the
// exact bytes sent, under a synthetic test secret the profile names by a SCOPEHAVEN_TARGET_ variable. The caller sends
// what it returns unchanged, to the profile's own origin: nothing here contacts a provider. The secret's value is never
// returned or recorded; a request records the variable's name and a salted digest of the key (docs/WEBHOOK-DRIVER.md).
//
// The schemes, each checked at the provider's own source on 2026-10-24 (only the documented algorithms, applied to
// synthetic keys):
//   twilio  X-Twilio-Signature: base64 HMAC-SHA1, keyed with the auth token, of the webhook URL followed by every POST
//           parameter sorted by name, each as its name then its value with no separator (a repeated name: once per
//           distinct value, values sorted). A JSON body instead puts bodySHA256=<hex SHA-256 of the raw body> on the URL,
//           and no parameters follow it. No timestamp: a redelivery of the same request repeats the signature exactly.
//           https://www.twilio.com/docs/usage/webhooks/webhooks-security; the concatenation as twilio-node
//           src/webhooks/webhooks.ts getExpectedTwilioSignature and toFormUrlEncodedParam; test vectors from twilio-python
//           tests/unit/test_request_validator.py. I-Twilio-Idempotency-Token (it distinguishes retry attempts):
//           https://www.twilio.com/docs/usage/webhooks/webhooks-connection-overrides
//   telnyx  telnyx-signature-ed25519: base64 Ed25519 signature of "<timestamp>|<raw JSON body>"; telnyx-timestamp: the
//           Unix seconds signed. The receiver verifies with the account's public key (telnyxPublicKey gives the public key
//           of a synthetic seed). https://developers.telnyx.com/docs/messaging/messages/receiving-webhooks
//   stripe  Stripe-Signature: "t=<Unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<raw body>" keyed with the endpoint secret as
//           given>". Stripe signs each delivery again, retries included, with a new timestamp; test mode's extra v0 entry
//           is not sent. https://docs.stripe.com/webhooks#verify-manually
// A check declares
//   "webhook": { "provider", "secretEnv"?, "signature"?, "encoding"?, "url"?, "timestampOffsetSeconds"?, "headers"? }
// beside its "body" (the parameters for a form, the event for JSON); validateWebhookDeclaration states each rule.
import { createHash, createHmac, createPrivateKey, createPublicKey, randomBytes, sign } from 'node:crypto';

export const WEBHOOK_SCHEMA = 'scopehaven-webhook/1';
export const WEBHOOK_DRIVER_SCHEMA = 'scopehaven-webhook-driver/1';
const KEY_DIGEST = 'scopehaven-webhook-key/1', PAYLOAD_DIGEST = 'scopehaven-webhook-payload/1';
// payloadBytes: the connector's request limit (HTTP_LIMITS.requestBytes in src/http-connector.mjs).
export const WEBHOOK_LIMITS = Object.freeze({ payloadBytes: 8192, urlChars: 2048, formNameChars: 128, formValues: 32, timestampOffsetSeconds: 86400 });
// Per provider: the encodings it sends (the first is the default), whether it signs a timestamp or the URL, the headers
// the driver computes, and the further headers a profile may declare (only those the provider documents for webhooks).
export const WEBHOOK_PROVIDERS = Object.freeze({
  twilio: Object.freeze({ encodings: Object.freeze(['form', 'json']), timestamped: false, signsUrl: true, signatureHeaders: Object.freeze(['X-Twilio-Signature']), extraHeaders: Object.freeze(['I-Twilio-Idempotency-Token']) }),
  telnyx: Object.freeze({ encodings: Object.freeze(['json']), timestamped: true, signsUrl: false, signatureHeaders: Object.freeze(['telnyx-signature-ed25519', 'telnyx-timestamp']), extraHeaders: Object.freeze([]) }),
  stripe: Object.freeze({ encodings: Object.freeze(['json']), timestamped: true, signsUrl: false, signatureHeaders: Object.freeze(['Stripe-Signature']), extraHeaders: Object.freeze([]) }),
});
// The secret each provider's scheme is keyed with, as a SCOPEHAVEN_TARGET_ variable holds it (synthetic test keys only).
const SECRET_FORMS = Object.freeze({ twilio: 'an auth token of 16 to 256 visible ASCII characters', telnyx: 'an Ed25519 private key seed, base64 of 32 bytes', stripe: 'an endpoint secret of 16 to 256 visible ASCII characters' });
const CONTENT_TYPE = Object.freeze({ form: 'application/x-www-form-urlencoded', json: 'application/json' });
const ENV = /^SCOPEHAVEN_TARGET_[A-Z0-9_]{1,110}$/, HMAC_SECRET = /^[\x21-\x7e]{16,256}$/, SEED = /^[A-Za-z0-9+/]{43}=$/;
const HEADER_VALUE = /^[\x21-\x7e](?:[\x20-\x7e]{0,253}[\x21-\x7e])?$/;
// PKCS #8 for an Ed25519 key (RFC 8410): this prefix, then the 32-byte seed.
const ED25519_PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const DECLARATION_KEYS = Object.freeze(['provider', 'secretEnv', 'signature', 'encoding', 'url', 'timestampOffsetSeconds', 'headers']);

export const WEBHOOK_REFUSALS = Object.freeze(['webhook-declaration', 'webhook-body', 'webhook-url', 'webhook-header', 'webhook-secret-unavailable', 'webhook-secret-clash', 'webhook-closed']);
// Every refusal is thrown before anything is sent. Messages name fields and variables, never a value.
export class WebhookDriverError extends Error {
  constructor(code, message) { super(message); this.name = 'WebhookDriverError'; this.code = code; }
}
const refuse = (code, message) => { throw new WebhookDriverError(code, message); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));

// A check's "webhook", normalized: { provider, signature, secretEnv, encoding, url, timestampOffsetSeconds, headers }.
//   provider                 twilio, telnyx or stripe; the check is a POST with a "body"
//   signature                "sign" (the default), or "omit": the request goes out without the provider's signature headers,
//                            as declared (an unsigned delivery test); a request is never sent unsigned for want of a key
//   secretEnv                the SCOPEHAVEN_TARGET_ variable holding the synthetic key (required to sign, refused when omitted)
//   encoding                 twilio: "form" (the default) or "json"; telnyx and stripe: "json"
//   url                      twilio only: the webhook URL as the provider is configured with it, which the signature covers;
//                            it must be its own origin followed by the check's path (default: the profile origin and path)
//   timestampOffsetSeconds   telnyx and stripe only: an integer within one day added to the signed time (default 0), so a
//                            check can send a stale or future signature
//   headers                  only headers the provider documents (twilio: I-Twilio-Idempotency-Token), literal values
export function validateWebhookDeclaration(webhook, check) {
  const fields = declarationFields(webhook);
  if (!plain(check) || check.method !== 'POST') refuse('webhook-declaration', 'a webhook check is a POST: each of these providers delivers its webhooks by POST');
  const url = Object.hasOwn(webhook, 'url') ? declaredUrl(webhook.url, check.path, fields.encoding) : null;
  if (!plain(check.body)) refuse('webhook-body', 'a webhook check declares its "body": the parameters for a form, the event for JSON');
  encodeBody(check.body, fields.encoding);
  return Object.freeze({ provider: fields.provider, signature: fields.signature, secretEnv: fields.secretEnv, encoding: fields.encoding, url, timestampOffsetSeconds: fields.timestampOffsetSeconds, headers: fields.headers });
}
// The rules that read the declaration alone (no method, path or body), which the evidence validator applies to suite checks too.
function declarationFields(webhook) {
  if (!plain(webhook) || Object.keys(webhook).some(key => !DECLARATION_KEYS.includes(key))) refuse('webhook-declaration', `"webhook" is { ${DECLARATION_KEYS.join(', ')} } (provider required)`);
  const { provider } = webhook;
  if (typeof provider !== 'string' || !Object.hasOwn(WEBHOOK_PROVIDERS, provider)) refuse('webhook-declaration', `"webhook.provider" is one of ${Object.keys(WEBHOOK_PROVIDERS).join(', ')}`);
  const form = WEBHOOK_PROVIDERS[provider];
  const signature = Object.hasOwn(webhook, 'signature') ? webhook.signature : 'sign';
  if (!['sign', 'omit'].includes(signature)) refuse('webhook-declaration', '"webhook.signature" is "sign" (the default) or "omit" (sent without the signature headers, as declared)');
  if (signature === 'sign' && !(typeof webhook.secretEnv === 'string' && ENV.test(webhook.secretEnv))) refuse('webhook-declaration', '"webhook.secretEnv" names the synthetic signing key in the dedicated SCOPEHAVEN_TARGET_ namespace');
  if (signature === 'omit' && Object.hasOwn(webhook, 'secretEnv')) refuse('webhook-declaration', 'a webhook whose signature is omitted names no "secretEnv"');
  const encoding = Object.hasOwn(webhook, 'encoding') ? webhook.encoding : form.encodings[0];
  if (!form.encodings.includes(encoding)) refuse('webhook-declaration', `"webhook.encoding" for ${provider} is ${form.encodings.map(e => `"${e}"`).join(' or ')}`);
  if (Object.hasOwn(webhook, 'timestampOffsetSeconds')) {
    if (!form.timestamped) refuse('webhook-declaration', `${provider} signs no timestamp: "webhook.timestampOffsetSeconds" does not apply`);
    const offset = webhook.timestampOffsetSeconds;
    if (!Number.isInteger(offset) || Math.abs(offset) > WEBHOOK_LIMITS.timestampOffsetSeconds) refuse('webhook-declaration', `"webhook.timestampOffsetSeconds" is an integer from -${WEBHOOK_LIMITS.timestampOffsetSeconds} to ${WEBHOOK_LIMITS.timestampOffsetSeconds}`);
  }
  if (Object.hasOwn(webhook, 'url') && !form.signsUrl) refuse('webhook-url', `${provider} does not sign the URL: "webhook.url" does not apply`);
  return { provider, signature, secretEnv: signature === 'sign' ? webhook.secretEnv : null, encoding, timestampOffsetSeconds: form.timestamped ? webhook.timestampOffsetSeconds ?? 0 : null,
    headers: declaredHeaders(webhook.headers, form, provider), url: Object.hasOwn(webhook, 'url') ? 'declared' : form.signsUrl ? 'origin' : null };
}
// The declared URL is signed as written (Twilio: decoding or re-encoding it fails validation) and the request is sent to the
// path a URL parser gives the check's path, so the URL must be written exactly as a URL parser writes it (percent-encoded,
// lower-case host, no default port), and be its own origin followed by the check's path and query; no user, password or fragment.
function declaredUrl(text, path, encoding) {
  let url = null;
  try { url = typeof text === 'string' && text.length <= WEBHOOK_LIMITS.urlChars ? new URL(text) : null; } catch { url = null; }
  if (!url || !['http:', 'https:'].includes(url.protocol) || url.username || url.password || text.includes('#')) refuse('webhook-url', `"webhook.url" is an absolute http or https URL of at most ${WEBHOOK_LIMITS.urlChars} characters, with no user, password or fragment`);
  if (url.href !== text) refuse('webhook-url', '"webhook.url" is written as a URL parser writes it (percent-encoded, lower-case host, no default port), because the signature covers the URL exactly as the request is sent');
  if (text !== `${url.origin}${path}`) refuse('webhook-url', '"webhook.url" is its origin followed by the check\'s own "path": the signature covers the URL the provider calls, so the request goes to that path');
  if (encoding === 'json' && url.searchParams.has('bodySHA256')) refuse('webhook-url', 'the driver adds bodySHA256 to a JSON webhook\'s URL itself');
  return text;
}
function declaredHeaders(declared, form, provider) {
  if (declared === undefined) return Object.freeze([]);
  if (!plain(declared)) refuse('webhook-header', '"webhook.headers" maps header names to literal values');
  const pairs = [];
  for (const [name, value] of Object.entries(declared)) {
    const canonical = form.extraHeaders.find(h => h.toLowerCase() === name.toLowerCase());
    if (!canonical) refuse('webhook-header', form.extraHeaders.length ? `a declared header is not one ${provider} documents for its webhooks (allowed: ${form.extraHeaders.join(', ')}); the driver sets Content-Type and the signature headers itself`
      : `${provider} documents no further webhook headers, so none may be declared; the driver sets Content-Type and the signature headers itself`);
    if (pairs.some(([n]) => n === canonical)) refuse('webhook-header', 'each header is declared once (names compare without case)');
    if (typeof value !== 'string' || !HEADER_VALUE.test(value)) refuse('webhook-header', 'a declared header value is 1 to 255 visible ASCII characters or inner spaces');
    pairs.push(Object.freeze([canonical, value]));
  }
  return Object.freeze(pairs);
}
// A form body maps each parameter name to a string, or to a list of strings (a repeated parameter), sent in the object's own
// key order (as JavaScript orders keys: integer-like names first). Twilio's signature sorts the names, so the order never matters to it.
function formEntries(body) {
  const entries = [];
  for (const [name, value] of Object.entries(body)) {
    if (!(name.length >= 1 && name.length <= WEBHOOK_LIMITS.formNameChars && name.isWellFormed())) refuse('webhook-body', `a form parameter name is 1 to ${WEBHOOK_LIMITS.formNameChars} characters`);
    const values = Array.isArray(value) ? value : [value];
    if (!values.length || values.length > WEBHOOK_LIMITS.formValues || !values.every(v => typeof v === 'string' && v.isWellFormed())) refuse('webhook-body', `a form parameter's value is a string, or a list of 1 to ${WEBHOOK_LIMITS.formValues} strings (a repeated parameter)`);
    for (const v of values) entries.push([name, v]);
  }
  if (!entries.length) refuse('webhook-body', 'a form webhook body has at least one parameter');
  return entries;
}
// { payload, entries }: the body bytes, and for a form the parameters they encode (null for JSON), from one read of the body.
function encodeBody(body, encoding) {
  const entries = encoding === 'form' ? formEntries(body) : null;
  const payload = Buffer.from(entries ? new URLSearchParams(entries).toString() : JSON.stringify(body), 'utf8');
  if (payload.length > WEBHOOK_LIMITS.payloadBytes) refuse('webhook-body', `the encoded webhook body exceeds ${WEBHOOK_LIMITS.payloadBytes} bytes`);
  return { payload, entries };
}

// The signing primitives. Each takes the key as its variable holds it (a string), so operator code and a fixture can use them.
// Twilio's signed text: the URL, then for each parameter name in sorted order, the name and each distinct value (sorted).
function twilioText(url, entries) {
  const byName = new Map();
  for (const [name, value] of entries) byName.set(name, [...(byName.get(name) ?? []), value]);
  return [...byName.keys()].sort().reduce((text, name) => text + [...new Set(byName.get(name))].sort().map(value => name + value).join(''), url);
}
const twilioMac = (key, url, entries) => createHmac('sha1', key).update(Buffer.from(twilioText(url, entries), 'utf8')).digest('base64');
const stripeHeader = (key, t, payload) => `t=${t},v1=${createHmac('sha256', key).update(`${t}.`).update(payload).digest('hex')}`;
const ed25519Key = seed => createPrivateKey({ key: Buffer.concat([ED25519_PKCS8, seed]), format: 'der', type: 'pkcs8' });
const telnyxMac = (seed, t, payload) => sign(null, Buffer.concat([Buffer.from(`${t}|`), payload]), ed25519Key(seed)).toString('base64');
// A key given to an exported primitive: a non-empty string, refused without echoing it.
const keyText = (value, what) => { if (typeof value !== 'string' || !value.length) refuse('webhook-secret-unavailable', `${what} is a non-empty string`); return value; };
// params: { name: value or [values] }, as twilio-node takes them.
export const twilioSignature = (authToken, url, params) => twilioMac(Buffer.from(keyText(authToken, 'a Twilio auth token'), 'utf8'), url, Object.entries(params).flatMap(([name, v]) => (Array.isArray(v) ? v : [v]).map(value => [name, value])));
export const twilioBodyHash = payload => createHash('sha256').update(payload).digest('hex');
export const stripeSignature = (secret, t, payload) => stripeHeader(Buffer.from(keyText(secret, 'a Stripe endpoint secret'), 'utf8'), t, Buffer.from(payload));
export const telnyxSignature = (seed, t, payload) => telnyxMac(seedOf(seed), t, Buffer.from(payload));
// The base64 raw 32-byte public key of a synthetic seed (not a secret), as Telnyx's Go, C# and PHP samples read the key; a receiver
// that parses the key as X.509 SubjectPublicKeyInfo (Telnyx's Java sample) needs the SPKI form instead.
export const telnyxPublicKey = seed => createPublicKey(ed25519Key(seedOf(seed))).export({ format: 'der', type: 'spki' }).subarray(12).toString('base64');
// A seed is canonical base64 of 32 bytes: the last character's two padding bits are zero, so no two strings name one seed.
function seedOf(text) {
  const seed = typeof text === 'string' && SEED.test(text) ? Buffer.from(text, 'base64') : null;
  if (!seed || seed.length !== 32 || seed.toString('base64') !== text) refuse('webhook-secret-unavailable', `a telnyx key is ${SECRET_FORMS.telnyx}`);
  return seed;
}
// Key bytes from a variable's value, or null when it does not hold the provider's key form.
function keyBytes(provider, value) {
  if (typeof value !== 'string') return null;
  if (provider === 'telnyx') { try { return seedOf(value); } catch { return null; } }
  return HMAC_SECRET.test(value) ? Buffer.from(value, 'utf8') : null;
}

// Every SCOPEHAVEN_TARGET_ variable name a config holds, under whatever field and at any depth: an actor's "credentialEnv", a
// signing "secretEnv" list, a forward "proofEnv", a read-back credential's or identity's "env".
function variableNames(config) {
  const names = [];
  for (const stack = [config]; stack.length;) {
    const value = stack.pop();
    if (typeof value === 'string') { if (ENV.test(value)) names.push(value); }
    else if (value !== null && typeof value === 'object') for (const child of Object.values(value)) stack.push(child);
  }
  return names;
}
const webhookChecks = target => (Array.isArray(target?.checks) ? target.checks : []).filter(c => plain(c) && Object.hasOwn(c, 'webhook') && c.applicability?.applies !== false);
// Every other credential variable the profile names: everywhere but its checks (whose only variables are the webhook keys).
const otherEnvs = target => (plain(target) ? variableNames(Object.entries(target).filter(([key]) => key !== 'checks').map(([, value]) => value)) : []);
// For the profile validator: null, or why a webhook key's variable is also another credential's: an actor's, or an observer's
// under any field (a read-back credential included). A signing key and a credential never share a variable, so the application
// is never handed the key as a token, nor a read credential ScopeHaven alone must hold, nor a recorder told it verifies the
// application's own signatures with the key the driver signs with.
export function webhookEnvClash(target) {
  const names = new Set(webhookChecks(target).map(c => c.webhook?.secretEnv).filter(n => typeof n === 'string'));
  const taken = otherEnvs(target).find(n => names.has(n));
  return taken ? `the webhook signing key variable ${taken} is also named elsewhere in the profile (as an actor's or an observer's credential variable, under any field): give each synthetic signing key its own SCOPEHAVEN_TARGET_ variable` : null;
}
// For the profile validator: null, or why a header the connector adds to a webhook check's request (the target's correlation
// header, or the check actor's "credentialHeader") has the name of one of that provider's headers, its signature or further
// headers, compared without case. Sent after the driver's headers, it would replace the signature, or add one to a request
// declared unsigned; sent before them, the driver's would replace the credential while the run still records it as sent.
// The connector also refuses, before writing, a request in which one of its own headers has the name of any of the provider's
// headers, signed or not (src/http-connector.mjs sendRequest).
export function webhookHeaderClash(target) {
  const correlation = plain(target?.correlation) && typeof target.correlation.header === 'string' ? target.correlation.header : null;
  for (const c of webhookChecks(target)) {
    const provider = c.webhook?.provider;
    if (typeof provider !== 'string' || !Object.hasOwn(WEBHOOK_PROVIDERS, provider)) continue;
    const actor = plain(target.actors) && Object.hasOwn(target.actors, c.actorId) ? target.actors[c.actorId] : null;
    const credential = plain(actor) && typeof actor.credentialHeader === 'string' ? actor.credentialHeader : null;
    for (const name of [...WEBHOOK_PROVIDERS[provider].signatureHeaders, ...WEBHOOK_PROVIDERS[provider].extraHeaders]) {
      if (correlation?.toLowerCase() === name.toLowerCase()) return `the target's correlation header is ${name}, a ${provider} webhook header of check "${c.id}": a correlation header would replace that check's signature or add one to an unsigned request, so name it otherwise`;
      if (credential?.toLowerCase() === name.toLowerCase()) return `actor "${c.actorId}" sends its key in ${name}, a ${provider} webhook header of its check "${c.id}": the key would replace that check's signature or be replaced by it, so give the actor another "credentialHeader"`;
    }
  }
  return null;
}

// The driver for one run: every declared key is read once, here, and held only as key bytes in this closure. A key that is
// missing or not in its provider's form, one variable declared for two providers, a key whose value is another webhook
// key's (a wrong-key check would then be signed validly) or another credential's the run reads, and a header the connector adds
// under one of a provider's header names (webhookHeaderClash), all refuse the run before any request. salt: the run's own
// (random by default), recorded, so a holder of a synthetic key can recompute its digest.
// now: the clock the signed timestamps read (default the wall clock, which receivers compare them to).
// build(check, { origin }) returns { path, headers, payload, record } for a declared check: the path to send (a JSON
// Twilio webhook's carries bodySHA256), the headers to add, the exact body bytes, and the evidence record. The caller sends
// the payload as given, with these headers and its own framing (Content-Length). record() is the run's key record.
export function createWebhookDriver({ target, env = process.env, now = Date.now, salt = randomBytes(16) } = {}) {
  if (!Buffer.isBuffer(salt) || salt.length < 16 || salt.length > 64) refuse('webhook-declaration', 'the driver salt is 16 to 64 random bytes');
  const declared = new Map(webhookChecks(target).map(c => [c.id, validateWebhookDeclaration(c.webhook, c)]));
  const providerOf = new Map();
  for (const d of declared.values()) {
    if (d.secretEnv === null) continue;
    if (providerOf.has(d.secretEnv) && providerOf.get(d.secretEnv) !== d.provider) refuse('webhook-declaration', `${d.secretEnv} is declared for two providers: each signing key variable serves one provider`);
    providerOf.set(d.secretEnv, d.provider);
  }
  const clash = webhookEnvClash(target);
  if (clash) refuse('webhook-secret-clash', clash);
  const headerClash = webhookHeaderClash(target);
  if (headerClash) refuse('webhook-header', headerClash);
  // Every variable the rules below compare, read once: every rule and every key comes from these values.
  const values = new Map([...new Set([...providerOf.keys(), ...otherEnvs(target)])].map(name => [name, env[name]]));
  const unusable = [...providerOf].filter(([name, provider]) => keyBytes(provider, values.get(name)) === null).map(([name, provider]) => `${name} (${provider}: ${SECRET_FORMS[provider]})`);
  if (unusable.length) refuse('webhook-secret-unavailable', `webhook signing keys missing or unusable: ${unusable.join('; ')}. Set each to a synthetic test key; nothing was sent`);
  const names = [...providerOf.keys()].sort();
  const keys = new Map(names.map(name => {
    const provider = providerOf.get(name), key = keyBytes(provider, values.get(name));
    return [name, { provider, key, digest: createHash('sha256').update(`${KEY_DIGEST}\n`).update(salt).update(`${name}\n`).update(key).digest('hex') }];
  }));
  for (const [i, name] of names.entries()) {
    // Two webhook variables are compared by value and by key bytes (a seed's decoded bytes), other credentials by value.
    const same = names.slice(i + 1).find(other => values.get(other) === values.get(name) || keys.get(other).key.equals(keys.get(name).key))
      ?? otherEnvs(target).find(other => other !== name && values.get(other) === values.get(name));
    if (same) refuse('webhook-secret-clash', `${name} and ${same} hold the same key: a webhook signing key is its own synthetic key, distinct from every other key and credential of the run`);
  }
  let closed = false;
  const build = (check, { origin } = {}) => {
    if (closed) refuse('webhook-closed', 'the webhook driver is closed: a new run creates a new one');
    const d = declared.get(check?.id);
    if (!d) refuse('webhook-declaration', 'the check declares no webhook in the profile this driver was created for');
    // The check as sent (captures filled in) must still carry the same declaration, and its body is encoded again.
    if (JSON.stringify(validateWebhookDeclaration(check.webhook, check)) !== JSON.stringify(d)) refuse('webhook-declaration', 'the check\'s webhook declaration changed after the driver read it');
    const { payload, entries } = encodeBody(check.body, d.encoding), signed = d.signature === 'sign', key = signed ? keys.get(d.secretEnv).key : null;
    const t = d.timestampOffsetSeconds === null || !signed ? null : Math.floor(now() / 1000) + d.timestampOffsetSeconds;
    const headers = { 'Content-Type': CONTENT_TYPE[d.encoding] };
    for (const [name, value] of d.headers) headers[name] = value;
    let path = check.path;
    if (d.provider === 'twilio') {
      // The URL as the request is sent: a URL parser's form of the declared URL (already written that way) or of the origin and
      // path, so a path with characters the parser percent-encodes is signed and sent the same way.
      const sent = new URL(d.url ?? `${originOf(origin)}${check.path}`);
      if (sent.hash) refuse('webhook-url', 'a Twilio webhook path has no fragment');
      let url = sent.href;
      path = url.slice(sent.origin.length);
      if (d.encoding === 'json') { const suffix = `${!url.includes('?') ? '?' : url.endsWith('?') ? '' : '&'}bodySHA256=${twilioBodyHash(payload)}`; url += suffix; path += suffix; }
      if (signed) headers['X-Twilio-Signature'] = twilioMac(key, url, entries ?? []);
    } else if (d.provider === 'stripe') {
      if (signed) headers['Stripe-Signature'] = stripeHeader(key, t, payload);
    } else if (signed) { headers['telnyx-signature-ed25519'] = telnyxMac(key, t, payload); headers['telnyx-timestamp'] = String(t); }
    const record = Object.freeze({ schema: WEBHOOK_SCHEMA, provider: d.provider, encoding: d.encoding, signature: signed ? 'signed' : 'omitted', secretEnv: d.secretEnv, keyDigest: signed ? keys.get(d.secretEnv).digest : null,
      headers: Object.freeze(Object.keys(headers).map(h => h.toLowerCase()).sort()), signedAt: t, timestampOffsetSeconds: d.timestampOffsetSeconds, url: d.provider === 'twilio' ? (d.url ? 'declared' : 'origin') : null,
      payloadDigest: createHash('sha256').update(`${PAYLOAD_DIGEST}\n`).update(salt).update(payload).digest('hex') });
    return Object.freeze({ path, headers: Object.freeze(headers), payload, record });
  };
  return Object.freeze({
    build,
    declares: id => declared.has(id),
    record: () => Object.freeze({ schema: WEBHOOK_DRIVER_SCHEMA, salt: salt.toString('hex'), keys: Object.freeze(names.map(name => Object.freeze({ secretEnv: name, provider: keys.get(name).provider, keyDigest: keys.get(name).digest }))) }),
    // Zeroes the key bytes; every later build refuses.
    close: () => { closed = true; for (const { key } of keys.values()) key.fill(0); },
  });
}
// The profile origin without its trailing slash: Twilio signs the URL the request goes to when no "url" is declared.
function originOf(origin) {
  let url = null;
  try { url = typeof origin === 'string' ? new URL(origin) : null; } catch { url = null; }
  if (!url || origin.replace(/\/$/, '') !== url.origin) refuse('webhook-url', 'the driver needs the target origin (scheme, host and port only) to sign a Twilio webhook without a declared "url"');
  return url.origin;
}

// For the run evidence validator (src/contracts.mjs validateHttpRunEvidence): null, or why a run's webhook records are
// not what a run of this driver writes. Each sent row of a check that declares "webhook" carries the record its declaration
// gives (provider, encoding, signature, key, offset, which URL was signed, header names), every signed record names a key of
// the run's driver record under the same digest, and no other row carries one. checks: the profile's checks, or an exported
// suite's (whose "webhook" is webhookSuiteViews' view: the key as a slot, never its variable); only id, applicability and
// "webhook" are read. Without checks each record is checked alone and against the driver record. Form and agreement only:
// a key digest can be recomputed only by whoever holds the synthetic key.
const HEX64 = /^[0-9a-f]{64}$/, SALT = /^(?:[0-9a-f]{2}){16,64}$/;
const RECORD_KEYS = Object.freeze(['schema', 'provider', 'encoding', 'signature', 'secretEnv', 'keyDigest', 'headers', 'signedAt', 'timestampOffsetSeconds', 'url', 'payloadDigest']);
const VIEW_KEYS = Object.freeze(['provider', 'signature', 'encoding', 'url', 'timestampOffsetSeconds', 'headers', 'key']);
const headerNamesOf = f => [...new Set(['content-type', ...f.headers.map(([name]) => name.toLowerCase()), ...(f.signature === 'sign' ? WEBHOOK_PROVIDERS[f.provider].signatureHeaders.map(h => h.toLowerCase()) : [])])].sort();
// The suite form of a profile's webhook declarations (for src/registry.mjs exportSuite), by check id: everything the evidence
// validator compares except the key's variable, which an exported suite never names. key is the variable's slot, its place among
// the profile's webhook key variables in sorted order (null when the signature is omitted), so a suite still says which checks
// share a key and which use another.
export function webhookSuiteViews(target) {
  const fields = webhookChecks(target).map(c => [c.id, declarationFields(c.webhook)]);
  const names = [...new Set(fields.map(([, f]) => f.secretEnv).filter(n => n !== null))].sort();
  return new Map(fields.map(([id, f]) => [id, Object.freeze({ provider: f.provider, signature: f.signature, encoding: f.encoding, url: f.url, timestampOffsetSeconds: f.timestampOffsetSeconds,
    headers: Object.freeze(headerNamesOf(f)), key: f.secretEnv === null ? null : names.indexOf(f.secretEnv) })]));
}
// What a check's record must show: from a profile declaration (with its variable) or a suite view (with its slot).
function expectationOf(webhook) {
  if (plain(webhook) && Object.hasOwn(webhook, 'key')) {
    // A provider is looked up only as a string: a lookup coerces its key, so ["twilio"] would read as twilio (D-01's shape, #502).
    const v = webhook, form = typeof v.provider === 'string' && Object.hasOwn(WEBHOOK_PROVIDERS, v.provider) ? WEBHOOK_PROVIDERS[v.provider] : null;
    const allowed = form ? ['content-type', ...form.extraHeaders, ...form.signatureHeaders].map(h => h.toLowerCase()) : [];
    if (Object.keys(v).length !== VIEW_KEYS.length || !VIEW_KEYS.every(k => Object.hasOwn(v, k)) || !form || !['sign', 'omit'].includes(v.signature) || !form.encodings.includes(v.encoding)
      || !(v.signature === 'omit' ? v.key === null : Number.isInteger(v.key) && v.key >= 0) || !(form.signsUrl ? ['declared', 'origin'].includes(v.url) : v.url === null)
      || !(form.timestamped ? Number.isInteger(v.timestampOffsetSeconds) && Math.abs(v.timestampOffsetSeconds) <= WEBHOOK_LIMITS.timestampOffsetSeconds : v.timestampOffsetSeconds === null)
      || !Array.isArray(v.headers) || !v.headers.every((h, i) => typeof h === 'string' && allowed.includes(h) && (i === 0 || v.headers[i - 1] < h)) || !v.headers.includes('content-type')
      || !form.signatureHeaders.every(h => v.headers.includes(h.toLowerCase()) === (v.signature === 'sign'))) refuse('webhook-declaration', 'a suite webhook view is not one webhookSuiteViews writes');
    return { ...v, headers: [...v.headers], secretEnv: undefined };
  }
  const f = declarationFields(webhook);
  return { provider: f.provider, signature: f.signature, encoding: f.encoding, url: f.url, timestampOffsetSeconds: f.timestampOffsetSeconds, headers: headerNamesOf(f), secretEnv: f.secretEnv, key: undefined };
}
const validDriverRecord = d => plain(d) && Object.keys(d).length === 3 && d.schema === WEBHOOK_DRIVER_SCHEMA && typeof d.salt === 'string' && SALT.test(d.salt) && Array.isArray(d.keys)
  && d.keys.every((k, i) => plain(k) && Object.keys(k).length === 3 && typeof k.secretEnv === 'string' && ENV.test(k.secretEnv) && typeof k.provider === 'string' && Object.hasOwn(WEBHOOK_PROVIDERS, k.provider) && typeof k.keyDigest === 'string' && HEX64.test(k.keyDigest)
    && (i === 0 || d.keys[i - 1].secretEnv < k.secretEnv));
function validRecord(r, keyOf) {
  if (!plain(r) || Object.keys(r).length !== RECORD_KEYS.length || !RECORD_KEYS.every(k => Object.hasOwn(r, k)) || r.schema !== WEBHOOK_SCHEMA || typeof r.provider !== 'string' || !Object.hasOwn(WEBHOOK_PROVIDERS, r.provider)) return false;
  const form = WEBHOOK_PROVIDERS[r.provider], signed = r.signature === 'signed', key = signed ? keyOf.get(r.secretEnv) : null;
  if (!form.encodings.includes(r.encoding) || !['signed', 'omitted'].includes(r.signature)) return false;
  if (signed ? !(key && key.provider === r.provider && key.keyDigest === r.keyDigest) : !(r.secretEnv === null && r.keyDigest === null)) return false;
  const allowed = ['content-type', ...form.extraHeaders, ...form.signatureHeaders].map(h => h.toLowerCase());
  if (!Array.isArray(r.headers) || !r.headers.every((h, i) => typeof h === 'string' && allowed.includes(h) && (i === 0 || r.headers[i - 1] < h)) || !r.headers.includes('content-type')
    || !form.signatureHeaders.every(h => r.headers.includes(h.toLowerCase()) === signed)) return false;
  const offsetOk = form.timestamped ? Number.isInteger(r.timestampOffsetSeconds) && Math.abs(r.timestampOffsetSeconds) <= WEBHOOK_LIMITS.timestampOffsetSeconds : r.timestampOffsetSeconds === null;
  const signedAtOk = form.timestamped && signed ? Number.isSafeInteger(r.signedAt) && r.signedAt >= 0 : r.signedAt === null;
  return offsetOk && signedAtOk && (form.signsUrl ? ['declared', 'origin'].includes(r.url) : r.url === null) && typeof r.payloadDigest === 'string' && HEX64.test(r.payloadDigest);
}
// slotOf: a variable's place in the driver record's sorted keys (the slot a suite view names).
const recordMatches = (r, e, slotOf) => r.provider === e.provider && r.encoding === e.encoding && r.signature === (e.signature === 'sign' ? 'signed' : 'omitted')
  && (e.key === undefined ? r.secretEnv === e.secretEnv : e.key === null ? r.secretEnv === null : slotOf(r.secretEnv) === e.key)
  && r.timestampOffsetSeconds === e.timestampOffsetSeconds && r.url === e.url && JSON.stringify(r.headers) === JSON.stringify(e.headers);
export function webhookEvidenceProblem(run, { checks = null } = {}) {
  const rows = Array.isArray(run?.results) ? run.results : [];
  let expected = null;
  if (checks !== null) {
    try { expected = new Map(webhookChecks({ checks }).map(c => [c.id, expectationOf(c.webhook)])); } catch { return 'webhook-declaration'; }
    if (new Set([...expected.values()].map(e => e.key === undefined)).size > 1) return 'webhook-declaration';
  }
  const recordOf = row => { const evidence = row?.trace?.[0]?.data; return plain(evidence) && Object.hasOwn(evidence, 'webhook') ? evidence.webhook : undefined; };
  const driver = plain(run) && Object.hasOwn(run, 'webhookDriver') ? run.webhookDriver : undefined;
  // The keys the checks declare, each with its provider: variable names (profile checks, in sorted order) or slots 0 to n - 1
  // (suite views, in numeric order). The driver record must list exactly these, in that order, under the same providers.
  const declaredKeys = expected === null ? null : [...new Map([...expected.values()].filter(e => (e.key === undefined ? e.secretEnv : e.key) !== null)
    .map(e => [e.key === undefined ? e.secretEnv : e.key, e.provider])).entries()].sort(([a], [b]) => (typeof a === 'number' ? a - b : a < b ? -1 : a > b ? 1 : 0));
  const keysAgree = () => declaredKeys === null || (declaredKeys.length === driver.keys.length && declaredKeys.every(([k, provider], i) => driver.keys[i].provider === provider && (typeof k === 'number' ? k === i : driver.keys[i].secretEnv === k)));
  if (driver === undefined ? declaredKeys?.length || rows.some(row => recordOf(row)?.signature === 'signed') : !validDriverRecord(driver) || !keysAgree()) return 'webhook-driver-record';
  const keyOf = new Map((driver?.keys ?? []).map(k => [k.secretEnv, k])), slotOf = name => (driver?.keys ?? []).findIndex(k => k.secretEnv === name);
  for (const row of rows) {
    const record = recordOf(row), e = expected?.get(row?.id);
    if (expected !== null && (e !== undefined && row?.trace?.[0]?.data?.requestAttempted === true) !== (record !== undefined)) return 'webhook-record';
    if (record === undefined) continue;
    if (!validRecord(record, keyOf)) return 'webhook-record';
    if (e !== undefined && !recordMatches(record, e, slotOf)) return 'webhook-record-declaration';
  }
  return null;
}
