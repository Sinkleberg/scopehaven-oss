// The signed-webhook driver (src/webhook-driver.mjs) over real loopback HTTP. Each scheme is checked against the provider's
// published test vectors where one exists and by an independent verifier written here from the provider's documentation
// (never the driver's own code); receivers come as a fixed twin and defective twins, one per property; the egress
// recorder's own idempotency.signing check verifies the HMAC-SHA256 scheme (Stripe), and its keyed-retry rules collapse a
// redelivery only where docs/KNOWN-LIMITS.md says they do. Every request goes to 127.0.0.1; every provider host is a name
// only and is never resolved or contacted. Every key is synthetic and built at run time.
//   SCOPEHAVEN_WEBHOOK_MUTATIONS=1 runs the mutation sweep (one mutation per property, each must make this file fail).
//   SCOPEHAVEN_WEBHOOK_EXAMPLE_OUT=<file> writes the worked example's results there.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { createHash, createHmac, createPrivateKey, createPublicKey, timingSafeEqual, verify } from 'node:crypto';
import { inspect } from 'node:util';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createWebhookDriver, validateWebhookDeclaration, webhookEnvClash, webhookEvidenceProblem, webhookSuiteViews, twilioSignature, twilioBodyHash, stripeSignature, telnyxSignature, telnyxPublicKey,
  WebhookDriverError, WEBHOOK_PROVIDERS, WEBHOOK_SCHEMA, WEBHOOK_DRIVER_SCHEMA, WEBHOOK_LIMITS } from '../src/webhook-driver.mjs';
import { createEgressRecorder } from '../integrations/observers/egress-recorder.mjs';
import { onFreePorts, watchingBinds } from '../integrations/observers/fixtures/free-port.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';
import { collectWindow, evaluateEffectAssertion } from '../integrations/observers/events.mjs';
import { observeHttp, runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';

// Synthetic keys, built from parts at run time so no literal looks like a credential.
const synthetic = (...parts) => ['synthetic', 'webhook', ...parts, 'k7'].join('-');
const seedFrom = label => createHash('sha256').update(synthetic(label)).digest().toString('base64');
const ENV = Object.freeze({ twilio: 'SCOPEHAVEN_TARGET_TWILIO_AUTH_TOKEN', twilioForged: 'SCOPEHAVEN_TARGET_FORGED_TWILIO_TOKEN', stripe: 'SCOPEHAVEN_TARGET_STRIPE_WHSEC',
  stripeForged: 'SCOPEHAVEN_TARGET_FORGED_STRIPE_WHSEC', telnyx: 'SCOPEHAVEN_TARGET_TELNYX_SEED', telnyxForged: 'SCOPEHAVEN_TARGET_FORGED_TELNYX_SEED', billing: 'SCOPEHAVEN_TARGET_BILLING_WHSEC', ops: 'SCOPEHAVEN_TARGET_OPS' });
const KEY = Object.freeze({ [ENV.twilio]: synthetic('twilio', 'one'), [ENV.twilioForged]: synthetic('twilio', 'forged'), [ENV.stripe]: ['wh', 'sec_', synthetic('stripe', 'one')].join(''),
  [ENV.stripeForged]: ['wh', 'sec_', synthetic('stripe', 'forged')].join(''), [ENV.telnyx]: seedFrom('telnyx-one'), [ENV.telnyxForged]: seedFrom('telnyx-forged'),
  [ENV.billing]: ['wh', 'sec_', synthetic('billing')].join(''), [ENV.ops]: synthetic('ops', 'bearer') });
const T = 1791800000;
const refusal = code => error => error instanceof WebhookDriverError && error.code === code;

// Independent verifiers, written from each provider's documentation.
// Twilio (webhooks-security): HMAC-SHA1 under the auth token of the URL and the sorted POST parameters, base64.
function twilioValid(token, url, params, header) {
  let text = url;
  for (const name of [...new Set(params.keys())].sort()) for (const value of [...new Set(params.getAll(name))].sort()) text += name + value;
  const expected = createHmac('sha1', token).update(text, 'utf8').digest(), got = Buffer.from(String(header ?? ''), 'base64');
  return typeof header === 'string' && got.length === expected.length && timingSafeEqual(got, expected);
}
// Twilio, a JSON body (webhooks-security; twilio-node validateRequestWithBody): the URL's bodySHA256 is the body's hex SHA-256, and
// the signature covers the URL alone.
function twilioJsonValid(token, url, raw, header) {
  const hash = new URL(url).searchParams.get('bodySHA256');
  return hash === createHash('sha256').update(raw).digest('hex') && twilioValid(token, url, new URLSearchParams(), header);
}
// Stripe (webhooks#verify-manually): split on ",", then "="; t and every v1; HMAC-SHA256 of "<t>.<body>"; constant-time compare; tolerance.
function stripeValid(secret, header, raw, nowSeconds, tolerance = 300) {
  let t = null; const v1 = [];
  for (const element of String(header ?? '').split(',')) { const at = element.indexOf('='); const [prefix, value] = [element.slice(0, at), element.slice(at + 1)]; if (prefix === 't') t = /^\d+$/.test(value) ? Number(value) : null; if (prefix === 'v1') v1.push(value); }
  if (t === null || !v1.length) return false;
  const expected = Buffer.from(createHmac('sha256', secret).update(Buffer.concat([Buffer.from(`${t}.`), raw])).digest('hex'));
  return v1.some(s => s.length === expected.length && timingSafeEqual(Buffer.from(s), expected)) && Math.abs(nowSeconds - t) <= tolerance;
}
// Telnyx (receiving-webhooks): Ed25519 over "<telnyx-timestamp>|<raw body>", the signature base64, the public key raw 32 bytes base64.
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const publicKeyOf = seedBase64 => createPublicKey(createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedBase64, 'base64')]), format: 'der', type: 'pkcs8' }))
  .export({ format: 'der', type: 'spki' }).subarray(SPKI.length).toString('base64');
function telnyxValid(publicKey, signature, timestamp, raw, nowSeconds, tolerance = 300) {
  if (typeof signature !== 'string' || typeof timestamp !== 'string' || !/^\d+$/.test(timestamp)) return false;
  const key = createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(publicKey, 'base64')]), format: 'der', type: 'spki' });
  return verify(null, Buffer.concat([Buffer.from(`${timestamp}|`), raw]), key, Buffer.from(signature, 'base64')) && Math.abs(nowSeconds - Number(timestamp)) <= tolerance;
}

// A profile-shaped target for the driver: one check per declaration.
const check = (id, webhook, body, path) => ({ id, title: id, category: 'webhooks', severity: 'high', actorId: 'provider', method: 'POST', path, body, webhook, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] });
const targetOf = (...checks) => ({ actors: { provider: { principalId: 'provider' } }, checks });
const SMS = Object.freeze({ MessageSid: 'SM0000000000000000000000000000001', AccountSid: 'AC0000000000000000000000000000001', From: '+15550100001', To: '+15550100002', Body: 'Call me back & soon, please' });
const EVENT = Object.freeze({ id: 'evt_0001', type: 'invoice.paid', data: { object: { id: 'in_0001', amount_paid: 2500 } } });
const TELNYX_EVENT = Object.freeze({ data: { event_type: 'message.received', id: 'b301ed3f-0000-4000-8000-000000000001', payload: { direction: 'inbound', text: 'call me back' } }, meta: { attempt: 1 } });
const twilioCheck = (id, extra = {}) => check(id, { provider: 'twilio', secretEnv: ENV.twilio, ...extra }, { ...SMS }, '/twilio/sms');
const stripeCheck = (id, extra = {}) => check(id, { provider: 'stripe', secretEnv: ENV.stripe, ...extra }, structuredClone(EVENT), '/stripe/events');
const telnyxCheck = (id, extra = {}) => check(id, { provider: 'telnyx', secretEnv: ENV.telnyx, ...extra }, structuredClone(TELNYX_EVENT), '/telnyx/messages');
const driverFor = (checks, options = {}) => createWebhookDriver({ target: targetOf(...checks), env: { ...KEY }, now: () => T * 1000, ...options });

test('published vectors: Twilio (twilio-python test_request_validator.py) for a form and a JSON body; RFC 8032 test 1 for the Ed25519 public key', () => {
  const uri = 'https://mycompany.com/myapp.php?foo=1&bar=2', params = { CallSid: 'CA1234567890ABCDE', Digits: '1234', From: '+14158675309', To: '+18005551212', Caller: '+14158675309' };
  assert.equal(twilioSignature('12345', uri, params), 'RSOYDt4T1cUTdK1PDd93/VVr8B8=');
  const body = '{"property": "value", "boolean": true}';
  assert.equal(twilioBodyHash(Buffer.from(body)), '0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620');
  assert.equal(twilioSignature('12345', `${uri}&bodySHA256=${twilioBodyHash(Buffer.from(body))}`, {}), 'a9nBmqA0ju/hNViExpshrM61xv4=');
  // The same vectors through a driver-built request: the URL declared, the token in its variable.
  const token = 'SCOPEHAVEN_TARGET_VECTOR_TOKEN', env = { [token]: '1234512345123451' };
  const target = { actors: { provider: { principalId: 'provider' } }, checks: [check('V-FORM', { provider: 'twilio', secretEnv: token, url: uri.replace('/myapp.php', '/v') }, params, '/v?foo=1&bar=2'),
    check('V-JSON', { provider: 'twilio', secretEnv: token, encoding: 'json' }, JSON.parse(body), '/j')] };
  const driver = createWebhookDriver({ target, env });
  const form = driver.build(target.checks[0]), json = driver.build(target.checks[1], { origin: 'http://127.0.0.1:47001' });
  assert.ok(twilioValid(env[token], 'https://mycompany.com/v?foo=1&bar=2', new URLSearchParams(form.payload.toString()), form.headers['X-Twilio-Signature']));
  assert.equal(json.path, `/j?bodySHA256=${createHash('sha256').update(json.payload).digest('hex')}`);
  assert.ok(twilioValid(env[token], `http://127.0.0.1:47001${json.path}`, new URLSearchParams(), json.headers['X-Twilio-Signature']), 'a JSON body: the URL with bodySHA256, no parameters');
  // RFC 8032 section 7.1, test 1: the seed's public key (the driver's key derivation).
  const seed = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex').toString('base64');
  assert.equal(Buffer.from(telnyxPublicKey(seed), 'base64').toString('hex'), 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
  assert.equal(telnyxPublicKey(seed), publicKeyOf(seed));
});

test('each scheme verifies under the independent verifier, over the exact bytes; a changed body, URL, time or key does not', () => {
  const twilio = twilioCheck('TW', { url: 'https://sms-app.example.test/twilio/sms', headers: { 'i-twilio-idempotency-token': 'idem-0001' } }), stripe = stripeCheck('ST'), telnyx = telnyxCheck('TX');
  const driver = driverFor([twilio, stripe, telnyx]);
  const tw = driver.build(twilio), st = driver.build(stripe), tx = driver.build(telnyx);
  assert.deepEqual(Object.keys(tw.headers), ['Content-Type', 'I-Twilio-Idempotency-Token', 'X-Twilio-Signature']);
  assert.equal(tw.headers['Content-Type'], 'application/x-www-form-urlencoded');
  assert.equal(tw.payload.toString(), 'MessageSid=SM0000000000000000000000000000001&AccountSid=AC0000000000000000000000000000001&From=%2B15550100001&To=%2B15550100002&Body=Call+me+back+%26+soon%2C+please');
  assert.equal(tw.path, '/twilio/sms');
  const params = new URLSearchParams(tw.payload.toString());
  assert.ok(twilioValid(KEY[ENV.twilio], 'https://sms-app.example.test/twilio/sms', params, tw.headers['X-Twilio-Signature']));
  assert.ok(!twilioValid(KEY[ENV.twilio], 'https://sms-app.example.test/twilio/other', params, tw.headers['X-Twilio-Signature']), 'another URL');
  const changed = new URLSearchParams(params); changed.set('Body', 'refund everything');
  assert.ok(!twilioValid(KEY[ENV.twilio], 'https://sms-app.example.test/twilio/sms', changed, tw.headers['X-Twilio-Signature']), 'a changed body (a replay under another body)');
  assert.ok(!twilioValid(KEY[ENV.twilioForged], 'https://sms-app.example.test/twilio/sms', params, tw.headers['X-Twilio-Signature']), 'another key');
  assert.deepEqual(Object.keys(st.headers), ['Content-Type', 'Stripe-Signature']);
  assert.equal(st.payload.toString(), JSON.stringify(EVENT));
  assert.match(st.headers['Stripe-Signature'], new RegExp(`^t=${T},v1=[0-9a-f]{64}$`));
  assert.ok(stripeValid(KEY[ENV.stripe], st.headers['Stripe-Signature'], st.payload, T));
  assert.ok(!stripeValid(KEY[ENV.stripe], st.headers['Stripe-Signature'], Buffer.from(JSON.stringify({ ...EVENT, type: 'charge.refunded' })), T), 'a changed body');
  assert.ok(!stripeValid(KEY[ENV.stripeForged], st.headers['Stripe-Signature'], st.payload, T), 'another key');
  assert.ok(!stripeValid(KEY[ENV.stripe], st.headers['Stripe-Signature'], st.payload, T + 301), 'outside the five-minute tolerance');
  assert.deepEqual(Object.keys(tx.headers), ['Content-Type', 'telnyx-signature-ed25519', 'telnyx-timestamp']);
  assert.equal(tx.headers['telnyx-timestamp'], String(T));
  const pub = publicKeyOf(KEY[ENV.telnyx]);
  assert.ok(telnyxValid(pub, tx.headers['telnyx-signature-ed25519'], tx.headers['telnyx-timestamp'], tx.payload, T));
  assert.ok(!telnyxValid(pub, tx.headers['telnyx-signature-ed25519'], String(T + 1), tx.payload, T), 'another timestamp');
  assert.ok(!telnyxValid(pub, tx.headers['telnyx-signature-ed25519'], tx.headers['telnyx-timestamp'], Buffer.from(tx.payload.toString().replace('call me back', 'stop')), T), 'a changed body');
  assert.ok(!telnyxValid(publicKeyOf(KEY[ENV.telnyxForged]), tx.headers['telnyx-signature-ed25519'], tx.headers['telnyx-timestamp'], tx.payload, T), 'another key');
  // The exported primitives agree with the built requests.
  assert.equal(stripeSignature(KEY[ENV.stripe], T, st.payload), st.headers['Stripe-Signature']);
  assert.equal(telnyxSignature(KEY[ENV.telnyx], T, tx.payload), tx.headers['telnyx-signature-ed25519']);
});

test('repeated form parameters, a declared URL with a query, offsets and an omitted signature', () => {
  const repeated = check('REP', { provider: 'twilio', secretEnv: ENV.twilio }, { MediaUrl: ['b', 'a', 'b'], From: '+15550100001' }, '/twilio/mms?tenant=t1');
  const stale = stripeCheck('STALE', { timestampOffsetSeconds: -3600 }), future = telnyxCheck('FUTURE', { timestampOffsetSeconds: 600 });
  const omitted = [check('OM-T', { provider: 'twilio', signature: 'omit' }, { ...SMS }, '/twilio/sms'), check('OM-S', { provider: 'stripe', signature: 'omit' }, structuredClone(EVENT), '/stripe/events'),
    check('OM-X', { provider: 'telnyx', signature: 'omit' }, structuredClone(TELNYX_EVENT), '/telnyx/messages')];
  const driver = driverFor([repeated, stale, future, ...omitted]);
  const rep = driver.build(repeated, { origin: 'http://127.0.0.1:47002/' });
  assert.equal(rep.payload.toString(), 'MediaUrl=b&MediaUrl=a&MediaUrl=b&From=%2B15550100001', 'sent as declared, in order');
  assert.ok(twilioValid(KEY[ENV.twilio], 'http://127.0.0.1:47002/twilio/mms?tenant=t1', new URLSearchParams(rep.payload.toString()), rep.headers['X-Twilio-Signature']), 'signed over distinct sorted values, the query in the URL');
  const s = driver.build(stale);
  assert.match(s.headers['Stripe-Signature'], new RegExp(`^t=${T - 3600},`));
  assert.ok(stripeValid(KEY[ENV.stripe], s.headers['Stripe-Signature'], s.payload, T, Infinity) && !stripeValid(KEY[ENV.stripe], s.headers['Stripe-Signature'], s.payload, T), 'a valid MAC over a stale time');
  assert.equal(s.record.signedAt, T - 3600);
  const f = driver.build(future);
  assert.equal(f.headers['telnyx-timestamp'], String(T + 600));
  assert.ok(telnyxValid(publicKeyOf(KEY[ENV.telnyx]), f.headers['telnyx-signature-ed25519'], f.headers['telnyx-timestamp'], f.payload, T, Infinity), 'the header carries the time it signed');
  const [ot, os, ox] = omitted.map(c => driver.build(c, { origin: 'http://127.0.0.1:47002' }));
  assert.deepEqual([Object.keys(ot.headers), Object.keys(os.headers), Object.keys(ox.headers)], [['Content-Type'], ['Content-Type'], ['Content-Type']]);
  assert.deepEqual([ot.record.signature, ot.record.secretEnv, ot.record.keyDigest, os.record.signedAt], ['omitted', null, null, null]);
});

test('declarations: every rule refuses before anything is built, and no message echoes a value', () => {
  const ok = { provider: 'twilio', secretEnv: ENV.twilio };
  const refused = (webhook, code, extra = {}) => assert.throws(() => validateWebhookDeclaration(webhook, { method: 'POST', path: '/twilio/sms', body: { ...SMS }, ...extra }), error => {
    assert.ok(refusal(code)(error), `${JSON.stringify(webhook)}: ${error.code} ${error.message}`);
    for (const value of Object.values(SMS)) assert.ok(!error.message.includes(value), 'no body value in the message');
    return true;
  });
  refused({ ...ok, provider: 'vonage' }, 'webhook-declaration');
  refused({ ...ok, extra: 1 }, 'webhook-declaration');
  refused(ok, 'webhook-declaration', { method: 'PUT' });
  refused({ ...ok, secretEnv: 'TWILIO_AUTH_TOKEN' }, 'webhook-declaration');
  refused({ provider: 'twilio' }, 'webhook-declaration');
  refused({ ...ok, signature: 'omit' }, 'webhook-declaration');
  refused({ ...ok, signature: 'forge' }, 'webhook-declaration');
  refused({ ...ok, timestampOffsetSeconds: -60 }, 'webhook-declaration');
  refused({ provider: 'stripe', secretEnv: ENV.stripe, timestampOffsetSeconds: 86401 }, 'webhook-declaration');
  refused({ provider: 'stripe', secretEnv: ENV.stripe, timestampOffsetSeconds: 1.5 }, 'webhook-declaration');
  refused({ provider: 'stripe', secretEnv: ENV.stripe, encoding: 'form' }, 'webhook-declaration');
  refused({ provider: 'telnyx', secretEnv: ENV.telnyx, encoding: 'form' }, 'webhook-declaration');
  refused({ ...ok, encoding: 'xml' }, 'webhook-declaration');
  refused({ provider: 'stripe', secretEnv: ENV.stripe, url: 'https://a.example.test/twilio/sms' }, 'webhook-url');
  refused({ ...ok, url: 'https://a.example.test/twilio/other' }, 'webhook-url');
  refused({ ...ok, url: 'https://A.example.test/twilio/sms' }, 'webhook-url');
  refused({ ...ok, url: 'https://a.example.test:443/twilio/sms' }, 'webhook-url');
  refused({ ...ok, url: 'https://user:pw@a.example.test/twilio/sms' }, 'webhook-url');
  refused({ ...ok, url: 'https://a.example.test/twilio/sms#x' }, 'webhook-url');
  refused({ ...ok, url: 'ftp://a.example.test/twilio/sms' }, 'webhook-url');
  refused({ ...ok, url: 'not a url' }, 'webhook-url');
  refused({ ...ok, url: "https://a.example.test/twilio/sms?name=O'Brien" }, 'webhook-url', { path: "/twilio/sms?name=O'Brien" });
  refused({ ...ok, url: 'https://a.example.test/twilio/caf\u00e9' }, 'webhook-url', { path: '/twilio/caf\u00e9' });
  assert.equal(validateWebhookDeclaration({ ...ok, url: 'https://a.example.test/twilio/sms?name=O%27Brien' }, { method: 'POST', path: '/twilio/sms?name=O%27Brien', body: { ...SMS } }).url, 'https://a.example.test/twilio/sms?name=O%27Brien', 'written as a URL parser writes it');
  refused({ ...ok, encoding: 'json', url: 'https://a.example.test/j?bodySHA256=0' }, 'webhook-url', { path: '/j?bodySHA256=0' });
  for (const name of ['Host', 'Content-Length', 'Content-Type', 'X-Twilio-Signature', 'Authorization', 'Cookie', 'Transfer-Encoding', 'X-Forwarded-Host']) refused({ ...ok, headers: { [name]: 'v' } }, 'webhook-header');
  refused({ provider: 'stripe', secretEnv: ENV.stripe, headers: { 'Stripe-Signature': 't=1,v1=00' } }, 'webhook-header');
  refused({ ...ok, headers: { 'I-Twilio-Idempotency-Token': 'a', 'i-twilio-idempotency-token': 'b' } }, 'webhook-header');
  for (const value of ['', ' lead', 'trail ', 'a\r\nInjected: 1', 'tab\there', 'x'.repeat(256), 7]) refused({ ...ok, headers: { 'I-Twilio-Idempotency-Token': value } }, 'webhook-header');
  refused(ok, 'webhook-body', { body: undefined });
  refused(ok, 'webhook-body', { body: {} });
  refused(ok, 'webhook-body', { body: { From: 1 } });
  refused(ok, 'webhook-body', { body: { From: { nested: 'x' } } });
  refused(ok, 'webhook-body', { body: { From: [] } });
  refused(ok, 'webhook-body', { body: { From: Array(33).fill('x') } });
  refused(ok, 'webhook-body', { body: { From: 'a\uD800' } });
  refused(ok, 'webhook-body', { body: { ['n'.repeat(129)]: 'x' } });
  refused(ok, 'webhook-body', { body: { ['a\uD800']: 'x' } });
  refused(ok, 'webhook-body', { body: { Body: 'x'.repeat(WEBHOOK_LIMITS.payloadBytes) } });
  refused({ provider: 'stripe', secretEnv: ENV.stripe }, 'webhook-body', { body: { pad: 'x'.repeat(WEBHOOK_LIMITS.payloadBytes) } });
  // Accepted: the documented header (any case), an offset within a day, a JSON Twilio body.
  assert.deepEqual(validateWebhookDeclaration({ ...ok, headers: { 'i-twilio-idempotency-token': 'idem-1' } }, { method: 'POST', path: '/twilio/sms', body: { ...SMS } }).headers, [['I-Twilio-Idempotency-Token', 'idem-1']]);
  assert.equal(validateWebhookDeclaration({ provider: 'telnyx', secretEnv: ENV.telnyx, timestampOffsetSeconds: -86400 }, { method: 'POST', path: '/t', body: {} }).timestampOffsetSeconds, -86400);
  assert.equal(validateWebhookDeclaration({ ...ok, encoding: 'json' }, { method: 'POST', path: '/j', body: { a: { b: true } } }).encoding, 'json');
  assert.deepEqual(Object.keys(WEBHOOK_PROVIDERS), ['twilio', 'telnyx', 'stripe']);
});

test('keys: a missing, short or malformed key, a key shared with another key or credential, and a reused variable refuse the run before any build', () => {
  const tw = twilioCheck('TW'), st = stripeCheck('ST'), tx = telnyxCheck('TX');
  const create = (env, checks = [tw, st, tx], target = targetOf(...checks)) => createWebhookDriver({ target, env, now: () => T * 1000 });
  const noValue = error => !Object.values(KEY).some(v => error.message.includes(v));
  assert.throws(() => create({}), error => refusal('webhook-secret-unavailable')(error) && [ENV.twilio, ENV.stripe, ENV.telnyx].every(n => error.message.includes(n)) && noValue(error));
  assert.throws(() => create({ ...KEY, [ENV.twilio]: 'short' }), error => refusal('webhook-secret-unavailable')(error) && error.message.includes(ENV.twilio) && !error.message.includes(ENV.stripe));
  assert.throws(() => create({ ...KEY, [ENV.stripe]: 'has a space in it 1234' }), refusal('webhook-secret-unavailable'));
  assert.throws(() => create({ ...KEY, [ENV.telnyx]: Buffer.alloc(31, 1).toString('base64') }), refusal('webhook-secret-unavailable'), 'a seed is 32 bytes');
  assert.throws(() => create({ ...KEY, [ENV.telnyx]: KEY[ENV.stripe] }), refusal('webhook-secret-unavailable'));
  assert.throws(() => telnyxPublicKey('not-a-seed'), refusal('webhook-secret-unavailable'));
  // A seed's last base64 character carries two padding bits: a non-canonical spelling of the same 32 bytes is refused, so a
  // "forged" seed cannot be the real one spelled another way.
  const real = KEY[ENV.telnyx], alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', last = alphabet.indexOf(real[42]);
  const respelled = real.slice(0, 42) + alphabet[last ^ 1] + '=';
  assert.deepEqual(Buffer.from(respelled, 'base64'), Buffer.from(real, 'base64'), 'the same 32 bytes');
  assert.throws(() => create({ ...KEY, [ENV.telnyxForged]: respelled }, [tx, telnyxCheck('TX-F', { secretEnv: ENV.telnyxForged })]), error => refusal('webhook-secret-unavailable')(error) && error.message.includes(ENV.telnyxForged));
  // Every variable is read once: the value every rule saw is the value that signs.
  const reads = new Map(), counting = new Proxy({ ...KEY }, { get: (o, name) => { reads.set(name, (reads.get(name) ?? 0) + 1); return o[name]; } });
  create(counting, null, { ...targetOf(tw), observers: [{ id: 'sink', type: 'egress-recorder', destinations: [{ host: 'h.example.test', idempotency: { header: 'x-id', signing: { scheme: 'stripe', signature: 'x-sig', secretEnv: [ENV.billing] } } }] }] });
  assert.deepEqual([...reads].filter(([name]) => typeof name === 'string' && name.startsWith('SCOPEHAVEN_')).sort(), [[ENV.billing, 1], [ENV.twilio, 1]]);
  // The exported primitives refuse a key that is not a string, without echoing it.
  for (const call of [() => twilioSignature(987654321987, 'https://a.example.test/x', {}), () => stripeSignature(987654321987, T, '{}'), () => stripeSignature('', T, '{}')])
    assert.throws(call, error => refusal('webhook-secret-unavailable')(error) && !error.message.includes('987654321987'));
  // A wrong-key check must not be signed validly: two webhook variables with one value are refused.
  const forged = twilioCheck('TW-F', { secretEnv: ENV.twilioForged });
  assert.throws(() => create({ ...KEY, [ENV.twilioForged]: KEY[ENV.twilio] }, [tw, forged]), error => refusal('webhook-secret-clash')(error) && noValue(error));
  // Nor is a key that is also a credential the run reads, under another variable.
  const withActor = { ...targetOf(tw), actors: { provider: { principalId: 'provider' }, ops: { principalId: 'ops', credentialEnv: ENV.ops } } };
  assert.throws(() => create({ ...KEY, [ENV.ops]: KEY[ENV.twilio] }, null, withActor), refusal('webhook-secret-clash'));
  const withRecorder = { ...targetOf(tw), observers: [{ id: 'sink', type: 'egress-recorder', destinations: [{ host: 'h.example.test', idempotency: { header: 'x-id', signing: { scheme: 'stripe', signature: 'x-sig', secretEnv: [ENV.billing] } } }] }] };
  assert.throws(() => create({ ...KEY, [ENV.billing]: KEY[ENV.twilio] }, null, withRecorder), refusal('webhook-secret-clash'));
  assert.doesNotThrow(() => create({ ...KEY }, null, withRecorder));
  // The same variable as an actor's or an observer's credential (by name).
  assert.match(webhookEnvClash({ ...targetOf(twilioCheck('X', { secretEnv: ENV.ops })), actors: { ops: { principalId: 'ops', credentialEnv: ENV.ops } } }), /is also named elsewhere in the profile/);
  assert.match(webhookEnvClash({ ...targetOf(twilioCheck('X', { secretEnv: ENV.billing })), observers: withRecorder.observers }), /SCOPEHAVEN_TARGET_BILLING_WHSEC/);
  assert.throws(() => create({ ...KEY }, null, { ...targetOf(twilioCheck('X', { secretEnv: ENV.billing })), observers: withRecorder.observers }), refusal('webhook-secret-clash'));
  assert.equal(webhookEnvClash(withRecorder), null);
  // One variable serves one provider.
  assert.throws(() => create({ ...KEY }, [tw, stripeCheck('S2', { secretEnv: ENV.twilio })]), refusal('webhook-declaration'));
  // A check not applicable is not read.
  assert.doesNotThrow(() => create({}, [{ ...tw, applicability: { applies: false, reason: 'no SMS here' } }]));
});

test('build: only declared checks, the declaration as read, and nothing after close', () => {
  const tw = twilioCheck('TW'), st = stripeCheck('ST');
  const driver = driverFor([tw, st]);
  assert.throws(() => driver.build({ ...tw, id: 'OTHER' }, { origin: 'http://127.0.0.1:47003' }), refusal('webhook-declaration'));
  assert.throws(() => driver.build({ ...tw, webhook: { ...tw.webhook, secretEnv: ENV.twilioForged } }, { origin: 'http://127.0.0.1:47003' }), refusal('webhook-declaration'), 'the sent check changed its declaration');
  assert.throws(() => driver.build(tw, {}), refusal('webhook-url'), 'a Twilio check without a declared URL needs the origin');
  assert.throws(() => driver.build(tw, { origin: 'http://127.0.0.1:47003/base' }), refusal('webhook-url'));
  const filled = driver.build({ ...tw, body: { ...SMS, Body: 'captured value' } }, { origin: 'http://127.0.0.1:47003' });
  assert.ok(filled.payload.toString().includes('Body=captured+value'), 'a body with captures filled is encoded again');
  assert.equal(driver.declares('TW'), true); assert.equal(driver.declares('NOPE'), false);
  driver.close();
  assert.throws(() => driver.build(st), refusal('webhook-closed'));
});

test('records: the variable name and salted digests only; no key, no MAC, in any form, anywhere the driver returns', () => {
  const tw = twilioCheck('TW', { url: 'https://sms-app.example.test/twilio/sms' }), st = stripeCheck('ST'), tx = telnyxCheck('TX'), st2 = stripeCheck('ST2');
  const salt = Buffer.alloc(16, 3), driver = driverFor([tw, st, tx, st2], { salt });
  const built = [tw, st, tx, st2].map(c => driver.build(c));
  const records = built.map(b => b.record);
  assert.deepEqual(records[1], { schema: WEBHOOK_SCHEMA, provider: 'stripe', encoding: 'json', signature: 'signed', secretEnv: ENV.stripe, keyDigest: records[1].keyDigest, headers: ['content-type', 'stripe-signature'],
    signedAt: T, timestampOffsetSeconds: 0, url: null, payloadDigest: records[1].payloadDigest });
  assert.deepEqual([records[0].url, records[0].signedAt, records[0].timestampOffsetSeconds, records[2].headers], ['declared', null, null, ['content-type', 'telnyx-signature-ed25519', 'telnyx-timestamp']]);
  // The key digest, recomputed from the recorded salt: SHA-256 of the domain, the salt, the variable name and the key bytes.
  const keyDigest = (name, bytes) => createHash('sha256').update('scopehaven-webhook-key/1\n').update(salt).update(`${name}\n`).update(bytes).digest('hex');
  assert.equal(records[1].keyDigest, keyDigest(ENV.stripe, Buffer.from(KEY[ENV.stripe])));
  assert.equal(records[2].keyDigest, keyDigest(ENV.telnyx, Buffer.from(KEY[ENV.telnyx], 'base64')));
  assert.equal(records[1].keyDigest, records[3].keyDigest, 'one key, one digest within a run');
  assert.equal(records[1].payloadDigest, createHash('sha256').update('scopehaven-webhook-payload/1\n').update(salt).update(built[1].payload).digest('hex'));
  const run = driver.record();
  assert.deepEqual(run, { schema: WEBHOOK_DRIVER_SCHEMA, salt: salt.toString('hex'), keys: [ENV.stripe, ENV.telnyx, ENV.twilio].map(n => ({ secretEnv: n, provider: { [ENV.stripe]: 'stripe', [ENV.telnyx]: 'telnyx', [ENV.twilio]: 'twilio' }[n], keyDigest: records.find(r => r.secretEnv === n).keyDigest })) });
  const other = driverFor([st], { salt: Buffer.alloc(16, 4) }).build(st).record;
  assert.notEqual(other.keyDigest, records[1].keyDigest, 'another run\'s salt gives another digest');
  // No form of any key or any signature value in a record, the run record, or the inspected driver.
  const text = JSON.stringify([records, run]) + inspect(driver, { showHidden: true, depth: Infinity });
  const forms = Object.values(KEY).flatMap(v => [v, Buffer.from(v).toString('hex'), Buffer.from(v).toString('base64'), Buffer.from(v, 'base64').toString('hex')]);
  const macs = built.flatMap(b => Object.entries(b.headers).filter(([name]) => /signature/i.test(name)).map(([, v]) => v));
  for (const value of [...forms, ...macs]) assert.ok(!text.includes(value), 'no key or MAC is recorded');
  assert.throws(() => createWebhookDriver({ target: targetOf(st), env: { ...KEY }, salt: Buffer.alloc(8) }), refusal('webhook-declaration'));
});

test('evidence: the validator helper accepts what a run of the driver writes and refuses each edit', () => {
  const tw = twilioCheck('TW', { url: 'https://sms-app.example.test/twilio/sms', headers: { 'I-Twilio-Idempotency-Token': 'idem-1' } }), st = stripeCheck('ST', { timestampOffsetSeconds: -60 });
  const om = { ...telnyxCheck('OM'), webhook: { provider: 'telnyx', signature: 'omit' } }, plainCheck = { ...stripeCheck('PLAIN'), webhook: undefined }, unsent = stripeCheck('UNSENT');
  delete plainCheck.webhook;
  const checks = [tw, st, om, plainCheck, unsent], driver = driverFor(checks);
  const row = (c, attempted = true) => ({ id: c.id, trace: [{ type: 'http-observation', data: { requestAttempted: attempted, ...(attempted && c.webhook ? { webhook: driver.build(c, { origin: 'http://127.0.0.1:47004' }).record } : {}) } }] });
  const run = { results: [row(tw), row(st), row(om), row(plainCheck), row(unsent, false)], webhookDriver: driver.record() };
  assert.equal(webhookEvidenceProblem(run, { checks }), null);
  assert.equal(webhookEvidenceProblem(run), null, 'without the checks, each record alone');
  assert.equal(webhookEvidenceProblem({ results: [] }), null, 'a run with no webhook checks');
  const edited = edit => { const x = structuredClone(run); edit(x); return x; };
  const at = (x, id) => x.results.find(r => r.id === id).trace[0].data;
  const cases = [
    ['webhook-driver-record', x => { delete x.webhookDriver; }],
    ['webhook-driver-record', x => { x.webhookDriver.keys.pop(); }],
    ['webhook-driver-record', x => { x.webhookDriver.salt = 'short'; }],
    ['webhook-driver-record', x => { x.webhookDriver.keys.reverse(); }],
    ['webhook-record', x => { at(x, 'TW').webhook.keyDigest = '0'.repeat(64); }],
    ['webhook-record', x => { at(x, 'OM').webhook.secretEnv = ENV.telnyx; }],
    ['webhook-record', x => { at(x, 'ST').webhook.headers = ['content-type']; }],
    ['webhook-record', x => { at(x, 'ST').webhook.signedAt = null; }],
    ['webhook-record', x => { at(x, 'TW').webhook.signedAt = T; }],
    ['webhook-record', x => { at(x, 'TW').webhook.url = null; }],
    ['webhook-record', x => { at(x, 'ST').webhook.extra = 1; }],
    ['webhook-record', x => { at(x, 'ST').webhook.encoding = 'form'; }],
    ['webhook-record', x => { delete at(x, 'TW').webhook; }],
    ['webhook-record', x => { at(x, 'PLAIN').webhook = structuredClone(at(x, 'ST').webhook); }],
    ['webhook-record', x => { at(x, 'UNSENT').webhook = structuredClone(at(x, 'ST').webhook); }],
    ['webhook-record-declaration', x => { at(x, 'ST').webhook.timestampOffsetSeconds = 0; }],
    ['webhook-record-declaration', x => { at(x, 'TW').webhook.headers = ['content-type', 'x-twilio-signature']; }],
    ['webhook-record-declaration', x => { at(x, 'TW').webhook.url = 'origin'; }],
  ];
  for (const [reason, edit] of cases) assert.equal(webhookEvidenceProblem(edited(edit), { checks }), reason, `${reason}: ${edit}`);
  // A record moved to a check declaring another key reads against that declaration.
  const swapped = { ...stripeCheck('ST', { timestampOffsetSeconds: -60, secretEnv: ENV.stripeForged }) };
  assert.equal(webhookEvidenceProblem(run, { checks: [tw, swapped, om, plainCheck, unsent] }), 'webhook-driver-record', 'the driver record names other keys');
  assert.equal(webhookEvidenceProblem(run, { checks: [{ id: 'X', webhook: { provider: 'vonage' } }] }), 'webhook-declaration');
  // An exported suite carries the suite views: the key as a slot, never its variable; the run validates against them alike.
  const forged = twilioCheck('TW-F', { secretEnv: ENV.twilioForged, url: 'https://sms-app.example.test/twilio/sms' });
  const all = [tw, forged, st, om], two = driverFor(all), views = webhookSuiteViews(targetOf(...all));
  assert.ok(!JSON.stringify([...views]).includes('SCOPEHAVEN_'), 'no variable name in a suite view');
  assert.deepEqual([...views].map(([id, v]) => [id, v.key]), [['TW', 2], ['TW-F', 0], ['ST', 1], ['OM', null]], 'slots: the variables in sorted order');
  assert.deepEqual(views.get('TW').headers, ['content-type', 'i-twilio-idempotency-token', 'x-twilio-signature']);
  const suiteChecks = all.map(c => ({ id: c.id, webhook: views.get(c.id) }));
  const rowFor = (d, c) => ({ id: c.id, trace: [{ data: { requestAttempted: true, webhook: d.build(c, { origin: 'http://127.0.0.1:47004' }).record } }] }), rowOf = c => rowFor(two, c);
  const suiteRun = { results: all.map(rowOf), webhookDriver: two.record() };
  assert.equal(webhookEvidenceProblem(suiteRun, { checks: suiteChecks }), null);
  // The forged check's record moved onto the real key (a consistent record, the wrong slot).
  const moved = structuredClone(suiteRun), real = moved.results[0].trace[0].data.webhook;
  Object.assign(moved.results[1].trace[0].data.webhook, { secretEnv: real.secretEnv, keyDigest: real.keyDigest });
  assert.equal(webhookEvidenceProblem(moved, { checks: suiteChecks }), 'webhook-record-declaration', 'a suite still tells one key from another');
  assert.equal(webhookEvidenceProblem(suiteRun, { checks: suiteChecks.map(c => (c.id === 'TW' ? { ...c, webhook: { ...c.webhook, key: 3 } } : c)) }), 'webhook-driver-record');
  assert.equal(webhookEvidenceProblem(suiteRun, { checks: [...suiteChecks.slice(1), tw] }), 'webhook-declaration', 'suite views and profile declarations are not mixed');
  assert.equal(webhookEvidenceProblem(suiteRun, { checks: suiteChecks.map(c => (c.id === 'OM' ? { ...c, webhook: { ...c.webhook, key: 0 } } : c)) }), 'webhook-declaration', 'an omitted signature has no slot');
  for (const bad of [{ url: null }, { url: 'elsewhere' }, { timestampOffsetSeconds: 0 }, { headers: ['content-type'] }, { headers: ['x-twilio-signature', 'content-type'] }, { headers: [...views.get('TW').headers, 'host'] }])
    assert.equal(webhookEvidenceProblem({ results: [] }, { checks: [{ id: 'TW', webhook: { ...views.get('TW'), ...bad } }] }), 'webhook-declaration', `a malformed suite view: ${JSON.stringify(bad)}`);
  // A driver key listed under another provider than the checks declare.
  const wrongProvider = structuredClone(suiteRun); wrongProvider.webhookDriver.keys[0].provider = 'stripe';
  assert.equal(webhookEvidenceProblem(wrongProvider, { checks: suiteChecks }), 'webhook-driver-record');
  // Every signature omitted: the driver's record lists no key, and a run that keeps it validates as one that leaves it out.
  const quiet = driverFor([om]), quietRun = { results: [rowFor(quiet, om)], webhookDriver: quiet.record() };
  assert.deepEqual(quiet.record().keys, []);
  assert.deepEqual([webhookEvidenceProblem(quietRun, { checks: [om] }), webhookEvidenceProblem({ results: quietRun.results }, { checks: [om] })], [null, null]);
  // Eleven keys: slots are numbers and are compared in numeric order (0, 1, 2, ..., 10).
  const many = Array.from({ length: 11 }, (_, i) => stripeCheck(`S${i}`, { secretEnv: `SCOPEHAVEN_TARGET_STRIPE_${String.fromCharCode(65 + i)}` }));
  const manyEnv = Object.fromEntries(many.map((c, i) => [c.webhook.secretEnv, ['wh', 'sec_', synthetic('many', String(i))].join('')]));
  const manyDriver = createWebhookDriver({ target: targetOf(...many), env: manyEnv, now: () => T * 1000 }), manyViews = webhookSuiteViews(targetOf(...many));
  const manyRun = { results: many.map(c => rowFor(manyDriver, c)), webhookDriver: manyDriver.record() };
  assert.deepEqual([webhookEvidenceProblem(manyRun, { checks: many }), webhookEvidenceProblem(manyRun, { checks: many.map(c => ({ id: c.id, webhook: manyViews.get(c.id) })) })], [null, null]);
  assert.throws(() => createWebhookDriver({ target: targetOf(st), env: { ...KEY }, salt: Buffer.alloc(65, 1) }), refusal('webhook-declaration'), 'the salt is 16 to 64 bytes, as the validator reads it');
});

// A receiver over real loopback HTTP, as a fixed twin or one defective twin per property:
//   none             verifies nothing
//   header-optional  verifies a signature only when the request carries one
//   no-tolerance     verifies the MAC but not the signed time (Stripe and Telnyx)
async function receiver(t, { defect = null, now = () => Date.now() } = {}) {
  const writes = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks), url = new URL(req.url, 'http://127.0.0.1'), nowSeconds = Math.floor(now() / 1000), tolerance = defect === 'no-tolerance' ? Infinity : 300;
      const provider = /^\/(twilio|stripe|telnyx)\//.exec(url.pathname)?.[1] ?? null, json = String(req.headers['content-type']).startsWith('application/json');
      const signatureHeader = { twilio: 'x-twilio-signature', stripe: 'stripe-signature', telnyx: 'telnyx-signature-ed25519' }[provider];
      const signedIn = { twilio: () => (json ? twilioJsonValid(KEY[ENV.twilio], `${origin}${req.url}`, raw, req.headers['x-twilio-signature']) : twilioValid(KEY[ENV.twilio], `${origin}${req.url}`, new URLSearchParams(raw.toString()), req.headers['x-twilio-signature'])),
        stripe: () => stripeValid(KEY[ENV.stripe], req.headers['stripe-signature'], raw, nowSeconds, tolerance),
        telnyx: () => telnyxValid(publicKeyOf(KEY[ENV.telnyx]), req.headers['telnyx-signature-ed25519'], req.headers['telnyx-timestamp'], raw, nowSeconds, tolerance) }[provider];
      const accepted = signedIn && (defect === 'none' || (defect === 'header-optional' && req.headers[signatureHeader] === undefined) || signedIn());
      if (accepted) writes.push(req.url);
      res.writeHead(accepted ? 200 : signedIn ? 403 : 404, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify({ accepted: Boolean(accepted) }));
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return { origin, writes };
}
// Sends a built request the way the connector will: the path, headers and payload as built, and its own framing.
const send = (origin, built, { payload = built.payload } = {}) => new Promise(resolve => {
  const req = request(new URL(built.path, origin), { method: 'POST', agent: false, headers: { Accept: 'application/json', Connection: 'close', ...built.headers, 'Content-Length': payload.length } }, res => {
    const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve(res.statusCode));
  });
  req.on('error', () => resolve(null)); req.end(payload);
});

test('fixed and defective receiver twins: the fixed twin accepts only the signed request; each defect is caught by the check for its property', async t => {
  const providers = { twilio: twilioCheck, stripe: stripeCheck, telnyx: telnyxCheck };
  const forgedEnv = { twilio: ENV.twilioForged, stripe: ENV.stripeForged, telnyx: ENV.telnyxForged };
  const results = {};
  for (const defect of [null, 'none', 'header-optional', 'no-tolerance']) {
    const r = await receiver(t, { defect });
    for (const [provider, make] of Object.entries(providers)) {
      const checks = { valid: make('VALID'), forged: make('FORGED', { secretEnv: forgedEnv[provider] }), omitted: { ...make('OMITTED'), webhook: { provider, signature: 'omit' } },
        ...(WEBHOOK_PROVIDERS[provider].timestamped ? { stale: make('STALE', { timestampOffsetSeconds: -3600 }) } : {}) };
      const driver = createWebhookDriver({ target: targetOf(...Object.values(checks)), env: { ...KEY } });
      const valid = driver.build(checks.valid, { origin: r.origin });
      // A replay of the valid request's signature over a changed body.
      const changed = Buffer.from(valid.payload.toString().replace(provider === 'twilio' ? 'Call+me+back' : provider === 'stripe' ? 'invoice.paid' : 'call me back', provider === 'twilio' ? 'Refund+all' : provider === 'stripe' ? 'invoice.void' : 'refund all'));
      assert.notDeepEqual(changed, valid.payload);
      const statuses = { valid: await send(r.origin, valid), replay: await send(r.origin, valid, { payload: changed }) };
      for (const name of Object.keys(checks).filter(n => n !== 'valid')) statuses[name] = await send(r.origin, driver.build(checks[name], { origin: r.origin }));
      results[`${defect ?? 'fixed'}/${provider}`] = Object.fromEntries(Object.entries(statuses).map(([name, status]) => [name, status === 200 ? 'accepted' : status === 403 ? 'refused' : String(status)]));
    }
  }
  const refusedAll = timestamped => ({ valid: 'accepted', replay: 'refused', forged: 'refused', omitted: 'refused', ...(timestamped ? { stale: 'refused' } : {}) });
  for (const provider of Object.keys(providers)) {
    const ts = WEBHOOK_PROVIDERS[provider].timestamped;
    assert.deepEqual(results[`fixed/${provider}`], refusedAll(ts), `fixed twin, ${provider}`);
    assert.deepEqual(results[`none/${provider}`], Object.fromEntries(Object.keys(refusedAll(ts)).map(k => [k, 'accepted'])), `no verification, ${provider}: every negative check catches it`);
    assert.deepEqual(results[`header-optional/${provider}`], { ...refusedAll(ts), omitted: 'accepted' }, `optional header, ${provider}: caught by the omitted signature only`);
    assert.deepEqual(results[`no-tolerance/${provider}`], ts ? { ...refusedAll(ts), stale: 'accepted' } : refusedAll(ts), `no tolerance, ${provider}: caught by the stale signature only (Twilio signs no time)`);
  }
});

test('Twilio paths a URL parser percent-encodes are signed as sent; a JSON body joins an existing query with "&"', async t => {
  const fixed = await receiver(t), loose = await receiver(t, { defect: 'none' });
  const paths = ["/twilio/sms?name=O'Brien", '/twilio/{tenant}/sms', '/twilio/café?q=a b'];
  const checks = [...paths.map((path, i) => check(`ENC-${i}`, { provider: 'twilio', secretEnv: ENV.twilio }, { ...SMS }, path)),
    check('JSON-Q', { provider: 'twilio', secretEnv: ENV.twilio, encoding: 'json' }, { CallSid: 'CA0001', CallStatus: 'ringing' }, '/twilio/voice?tenant=t1'),
    check('JSON-BARE', { provider: 'twilio', secretEnv: ENV.twilio, encoding: 'json' }, { CallSid: 'CA0002' }, '/twilio/voice')];
  const driver = createWebhookDriver({ target: targetOf(...checks), env: { ...KEY } });
  const built = checks.map(c => driver.build(c, { origin: fixed.origin }));
  assert.deepEqual(built.slice(0, 3).map(b => b.path), ['/twilio/sms?name=O%27Brien', '/twilio/%7Btenant%7D/sms', '/twilio/caf%C3%A9?q=a%20b'], 'the path as a URL parser sends it');
  assert.match(built[3].path, /^\/twilio\/voice\?tenant=t1&bodySHA256=[0-9a-f]{64}$/);
  assert.match(built[4].path, /^\/twilio\/voice\?bodySHA256=[0-9a-f]{64}$/);
  assert.deepEqual(await Promise.all(built.map(b => send(fixed.origin, b))), [200, 200, 200, 200, 200], 'each verifies at a receiver that follows the documented scheme');
  // The JSON receiver checks the body against bodySHA256: the same signed URL over another body is refused.
  assert.equal(await send(fixed.origin, built[3], { payload: Buffer.from('{"CallSid":"CA0001","CallStatus":"completed"}') }), 403);
  assert.equal(await send(loose.origin, built[3], { payload: Buffer.from('{"CallSid":"CA0001","CallStatus":"completed"}') }), 200, 'a receiver that verifies nothing takes it');
  // A declared URL in the parser's own form signs the same way.
  const declared = check('ENC-D', { provider: 'twilio', secretEnv: ENV.twilio, url: 'https://sms-app.example.test/twilio/sms?name=O%27Brien' }, { ...SMS }, '/twilio/sms?name=O%27Brien');
  const d = createWebhookDriver({ target: targetOf(declared), env: { ...KEY } }).build(declared);
  assert.equal(d.path, '/twilio/sms?name=O%27Brien');
  assert.ok(twilioValid(KEY[ENV.twilio], 'https://sms-app.example.test/twilio/sms?name=O%27Brien', new URLSearchParams(d.payload.toString()), d.headers['X-Twilio-Signature']));
});

// The egress recorder (proxy routing), as in integrations/observers/egress-signing.test.mjs: its own verification and keyed retries.
const HOOKS = 'hooks.example.test', WITNESS = 'witness.scopehaven.invalid';
const sink = (t, destinations, { env = { ...KEY }, signingClock = () => T * 1000 } = {}) => onFreePorts(1, async port => {
  const o = createEgressRecorder({ instanceId: 'egress-recorder-webhooks', port, routing: 'proxy', destinations, witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150, env, signingClock });
  await o.start(); t.after(() => o.stop()); return o;
});
// A built request through the recorder, to the destination host, with the payload as built unless changed.
const viaSink = (port, built, { payload = built.payload } = {}) => new Promise(resolve => {
  const req = request({ host: '127.0.0.1', port, method: 'POST', path: `http://${HOOKS}${built.path}`, agent: false, headers: { host: HOOKS, ...built.headers, 'content-length': String(payload.length) } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
  req.on('error', () => resolve(null)); req.end(payload);
});
async function windowOf(o, between) {
  const from = await o.mark(); await between(); o.markWitnessRequest(from);
  await new Promise(resolve => { const req = request({ host: '127.0.0.1', port: o.port, method: 'GET', path: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, headers: { host: WITNESS } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(); });
  return collectWindow(o, from, await o.mark());
}
const verdict = w => { const d = evaluateEffectAssertion({ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: HOOKS }, expected: 1, countBy: 'idempotency-key' }, [w], { countBy: true }); return [d.verdict, d.applications && [d.applications.low, d.applications.high]]; };
const at = (checks, seconds) => createWebhookDriver({ target: targetOf(...checks), env: { ...KEY }, now: () => seconds * 1000 });

test('the recorder verifies the driver\'s Stripe signature (HMAC-SHA256) and collapses a re-signed redelivery only under one declared secret', async t => {
  const st = stripeCheck('ST'), forged = stripeCheck('ST-F', { secretEnv: ENV.stripeForged });
  const signing = { pointer: '/id', signing: { scheme: 'stripe', signature: 'stripe-signature', secretEnv: [ENV.stripe] } };
  const o = await sink(t, [{ host: HOOKS, paths: ['/stripe/events'], idempotency: signing }]);
  // Each window keys its own event: a key first used in an earlier window reads earlier use (KNOWN-LIMITS, keyed retries).
  const event = id => ({ ...st, body: { ...structuredClone(EVENT), id } });
  const first = at([st], T).build(st), redelivery = at([st], T + 30).build(st);
  assert.notEqual(first.headers['Stripe-Signature'], redelivery.headers['Stripe-Signature'], 'a redelivery is signed again with a new timestamp');
  const resign = await windowOf(o, async () => { await viaSink(o.port, first); await viaSink(o.port, redelivery); });
  assert.deepEqual(resign.events.map(e => [e.idempotency.status, e.idempotency.signing.scheme, e.idempotency.signing.verified, e.idempotency.signing.t]), [['keyed', 'stripe', true, T], ['keyed', 'stripe', true, T + 30]]);
  assert.deepEqual(verdict(resign), ['pass', [1, 1]], 'two verified deliveries of one event under one secret: one application');
  const second = at([st], T).build(event('evt_0002'));
  const tampered = await windowOf(o, async () => { await viaSink(o.port, second); await viaSink(o.port, second, { payload: Buffer.from(second.payload.toString().replace('2500', '9900')) }); });
  assert.deepEqual([tampered.events[1].idempotency.signing.verified, verdict(tampered)], [false, ['missing', [1, 2]]], 'a replay under a changed body fails verification');
  const wrongKey = await windowOf(o, async () => { await viaSink(o.port, at([st], T).build(event('evt_0003'))); await viaSink(o.port, at([forged], T + 5).build({ ...forged, body: { ...structuredClone(EVENT), id: 'evt_0003' } })); });
  assert.deepEqual([wrongKey.events[1].idempotency.signing.verified, verdict(wrongKey)], [false, ['missing', [1, 2]]], 'another key does not verify');
  const omitted = { ...st, id: 'ST-O', webhook: { provider: 'stripe', signature: 'omit' } };
  const unsigned = await windowOf(o, async () => { await viaSink(o.port, at([omitted], T).build(omitted)); });
  assert.equal(unsigned.events[0].idempotency.signing.verified, null, 'no signature header: nothing to verify');
  const stale = stripeCheck('ST-S', { timestampOffsetSeconds: -3600 });
  const old = await windowOf(o, async () => { await viaSink(o.port, at([stale], T).build(stale)); });
  assert.equal(old.events[0].idempotency.signing.verified, false, 'a signing time outside the run window does not verify');
  // KNOWN-LIMITS, keyed retries: without signing, a re-sign is a changed request unless the header is declared volatile.
  const plain = await sink(t, [{ host: HOOKS, paths: ['/stripe/events'], idempotency: { pointer: '/id' } }]);
  assert.deepEqual(verdict(await windowOf(plain, async () => { await viaSink(plain.port, first); await viaSink(plain.port, redelivery); })), ['missing', [1, 2]]);
  const volatile = await sink(t, [{ host: HOOKS, paths: ['/stripe/events'], idempotency: { pointer: '/id', volatile: ['stripe-signature'] } }]);
  assert.deepEqual(verdict(await windowOf(volatile, async () => { await viaSink(volatile.port, first); await viaSink(volatile.port, redelivery); })), ['pass', [1, 1]]);
});

test('the recorder on Telnyx and Twilio: exact redeliveries collapse; a Telnyx re-sign and a Twilio signature under another key stay bound, as KNOWN-LIMITS says', async t => {
  const tx = telnyxCheck('TX'), tw = twilioCheck('TW', { url: `http://${HOOKS}/twilio/sms`, headers: { 'I-Twilio-Idempotency-Token': 'idem-0001' } });
  const twSecond = twilioCheck('TW-2', { url: `http://${HOOKS}/twilio/sms`, headers: { 'I-Twilio-Idempotency-Token': 'idem-0002' } });
  const twForged = twilioCheck('TW-F', { secretEnv: ENV.twilioForged, url: `http://${HOOKS}/twilio/sms`, headers: { 'I-Twilio-Idempotency-Token': 'idem-0002' } });
  const telnyx = await sink(t, [{ host: HOOKS, paths: ['/telnyx/messages'], idempotency: { pointer: '/data/id' } }]);
  const first = at([tx], T).build(tx);
  assert.deepEqual(verdict(await windowOf(telnyx, async () => { await viaSink(telnyx.port, first); await viaSink(telnyx.port, first); })), ['pass', [1, 1]], 'an exact redelivery (Ed25519 is deterministic)');
  const other = { ...tx, body: { ...structuredClone(TELNYX_EVENT), data: { ...structuredClone(TELNYX_EVENT.data), id: 'b301ed3f-0000-4000-8000-000000000002' } } };
  assert.deepEqual(verdict(await windowOf(telnyx, async () => { await viaSink(telnyx.port, at([tx], T).build(other)); await viaSink(telnyx.port, at([tx], T + 30).build(other)); })), ['missing', [1, 2]],
    'a re-sign under a new telnyx-timestamp reads as a changed request: neither header is on the declarable signature list');
  await assert.rejects(sink(t, [{ host: HOOKS, paths: ['/telnyx/messages'], idempotency: { pointer: '/data/id', volatile: ['telnyx-timestamp'] } }]), /volatile/);
  const twilio = await sink(t, [{ host: HOOKS, paths: ['/twilio/sms'], idempotency: { header: 'i-twilio-idempotency-token', volatile: ['x-twilio-signature'] } }]);
  const twilioDriver = at([tw, twSecond, twForged], T), sms = twilioDriver.build(tw);
  const exact = await windowOf(twilio, async () => { await viaSink(twilio.port, sms); await viaSink(twilio.port, sms); });
  assert.deepEqual([exact.events.map(e => e.idempotency.status), verdict(exact)], [['keyed', 'keyed'], ['pass', [1, 1]]], 'Twilio signs no time: a redelivery repeats the signature exactly');
  const otherKey = await windowOf(twilio, async () => { await viaSink(twilio.port, twilioDriver.build(twSecond)); await viaSink(twilio.port, twilioDriver.build(twForged)); });
  assert.deepEqual(verdict(otherKey), ['missing', [1, 2]], 'x-twilio-signature declared volatile has no effect: it stays bound');
  assert.equal(exact.events[0].idempotency.signing, undefined, 'the recorder verifies no Twilio scheme (an untimed MAC)');
});

// The worked example: an inbound Twilio-style SMS into an owned fixture app, whose write path sends one Stripe-style event
// to billing through the egress recorder, signed with the app's own synthetic billing secret; a connector run drives it.
// This example drives the driver through the connector's transport option (operator code) on purpose, with the declarations
// beside the profile, keyed by check id; test/webhook-wiring.test.mjs runs the wired path, where the checks declare "webhook".
const PUBLIC_URL = 'https://sms-app.example.test', BILLING = 'billing.example.test';
async function smsApp(t, sinkPort, { defect = null } = {}) {
  const leads = [];
  const relay = (host, path, headers = {}, body = null) => new Promise(resolve => {
    const r = request({ host: '127.0.0.1', port: sinkPort, method: body === null ? 'GET' : 'POST', path: `http://${host}${path}`, agent: false, headers: { host, ...headers, ...(body === null ? {} : { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) }) } },
      x => { x.resume(); x.on('end', resolve); });
    r.on('error', resolve); r.end(body ?? undefined);
  });
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', async () => {
      const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
      const raw = Buffer.concat(chunks), url = new URL(req.url, 'http://127.0.0.1');
      if (url.pathname === '/me') return req.headers.authorization === `Bearer ${KEY[ENV.ops]}` ? reply(200, { user: 'ops' }) : reply(401, {});
      if (url.pathname === '/ping') { await relay(WITNESS, `/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
      if (url.pathname !== '/twilio/sms' || req.method !== 'POST') return reply(404, {});
      const params = new URLSearchParams(raw.toString()), header = req.headers['x-twilio-signature'];
      const valid = defect === 'none' || (defect === 'header-optional' && header === undefined) || twilioValid(KEY[ENV.twilio], `${PUBLIC_URL}${req.url}`, params, header);
      if (!valid) return reply(403, { error: 'signature' });
      leads.push(params.get('From'));
      const event = JSON.stringify({ id: `evt_${params.get('MessageSid')}`, type: 'usage.recorded', data: { sms: 1 } });
      await relay(BILLING, '/hooks/usage', { 'stripe-signature': stripeSignature(KEY[ENV.billing], Math.floor(Date.now() / 1000), event) }, event);
      reply(200, { ok: true });
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return { origin: `http://127.0.0.1:${server.address().port}`, leads };
}
// The prohibitions' selectors name the billing host only. Pinning each to its own event id (a declared field) would need an
// allowed-use twin carrying the same field value (src/http-pairing.mjs), which a refused request never has.
const billingSends = [{ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: BILLING, resource: 'POST /hooks/usage' }, expected: 1, countBy: 'idempotency-key' }];
const noBilling = [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: BILLING } }];
const smsCheck = (id, severity, status, effects, sid) => ({ id, title: id, category: 'webhooks', severity, actorId: 'provider', method: 'POST', path: '/twilio/sms',
  body: { ...SMS, MessageSid: sid }, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: status }], effects });
const EXAMPLE_WEBHOOKS = Object.freeze({
  'SMS-SIGNED': { provider: 'twilio', secretEnv: ENV.twilio, url: `${PUBLIC_URL}/twilio/sms`, headers: { 'I-Twilio-Idempotency-Token': 'idem-signed' } },
  'SMS-FORGED': { provider: 'twilio', secretEnv: ENV.twilioForged, url: `${PUBLIC_URL}/twilio/sms` },
  'SMS-UNSIGNED': { provider: 'twilio', signature: 'omit', url: `${PUBLIC_URL}/twilio/sms` },
});
const exampleProfile = (origin, port) => ({ id: 'webhook-worked-example', name: 'Signed webhook worked example', applicationId: 'sms-fixture', origin, buildLabel: 'b1', contextId: 'synthetic-webhooks',
  actors: { ops: { principalId: 'ops', credentialEnv: ENV.ops, identityValue: 'ops' }, provider: { principalId: 'sms-provider' } }, requiredControlIds: ['WHOAMI'],
  observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [{ host: BILLING, paths: ['/hooks/usage'], idempotency: { pointer: '/id', signing: { scheme: 'stripe', signature: 'stripe-signature', secretEnv: [ENV.billing] } } }],
    witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250 }],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
    smsCheck('SMS-SIGNED', 'control', 200, billingSends, 'SM-signed'), smsCheck('SMS-FORGED', 'critical', 403, noBilling, 'SM-forged'), smsCheck('SMS-UNSIGNED', 'critical', 403, noBilling, 'SM-unsigned')] });
// The transport: a declared webhook check goes out as the driver built it (as the proposed connector wiring sends it); every
// other request (identity probes, witnesses) through the connector's own loopback transport.
const webhookTransport = driver => (origin, sent, options) => {
  if (!driver.declares(sent.id)) return observeHttp(origin, sent, options);
  const built = driver.build({ ...sent, webhook: EXAMPLE_WEBHOOKS[sent.id] }, { origin });
  return new Promise(resolve => {
    const req = request(new URL(built.path, origin), { method: 'POST', agent: false, headers: { Accept: 'application/json', Connection: 'close', ...built.headers, 'Content-Length': built.payload.length } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c));
      res.on('end', () => { const bytes = Buffer.concat(chunks); let json; try { json = JSON.parse(bytes.toString()); } catch { json = undefined; } resolve({ status: res.statusCode, complete: true, jsonParsed: json !== undefined, json, bytes: bytes.length, repeatedKeys: 0 }); });
    });
    req.on('error', () => resolve({ status: null, complete: false, jsonParsed: false, json: undefined, bytes: 0, error: 'network' }));
    req.end(built.payload);
  });
};
const runExample = (t, defect) => onFreePorts(1, async port => {
  const app = await smsApp(t, port, { defect }), p = exampleProfile(app.origin, port), watch = watchingBinds(buildObservers);
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  const env = { ...KEY };
  const driver = createWebhookDriver({ target: { ...p, checks: p.checks.map(c => (EXAMPLE_WEBHOOKS[c.id] ? { ...c, webhook: EXAMPLE_WEBHOOKS[c.id] } : c)) }, env });
  try { return { app, run: await runHttpAssessment(p, { env, transport: webhookTransport(driver), observerFactory: watch.factory }), driverRecord: driver.record(), lostBind: watch.state.lostBind }; }
  finally { driver.close(); }
}, r => r.lostBind);
const billingEvents = row => row.trace[1].data.windows.flatMap(w => w.events).filter(e => e.name === BILLING || e.host === BILLING);

test('worked example: a signed SMS reaches the write path and its Stripe-style event verifies in the window; a forged or unsigned one is refused', async t => {
  const summary = {};
  for (const defect of [null, 'none', 'header-optional']) {
    const { app, run, driverRecord } = await runExample(t, defect);
    const row = id => run.results.find(r => r.id === id);
    validateHttpRunEvidence(run);
    summary[defect ?? 'fixed'] = { statuses: Object.fromEntries(['WHOAMI', 'SMS-SIGNED', 'SMS-FORGED', 'SMS-UNSIGNED'].map(id => [id, row(id).status])),
      httpStatus: Object.fromEntries(['SMS-SIGNED', 'SMS-FORGED', 'SMS-UNSIGNED'].map(id => [id, row(id).trace[0].data.httpStatus])),
      billing: Object.fromEntries(['SMS-SIGNED', 'SMS-FORGED', 'SMS-UNSIGNED'].map(id => [id, billingEvents(row(id)).map(e => ({ status: e.idempotency.status, scheme: e.idempotency.signing.scheme, verified: e.idempotency.signing.verified }))])),
      unsettled: Object.fromEntries(run.results.filter(r => r.status !== 'pass').map(r => [r.id, r.assertions.filter(a => a.status !== 'pass').map(a => `${a.name}: ${a.actual}`)])),
      signing: run.signing, leads: app.leads.length, driverKeys: driverRecord.keys.map(k => ({ secretEnv: k.secretEnv, provider: k.provider })) };
  }
  const fixed = summary.fixed;
  assert.deepEqual(fixed.statuses, { WHOAMI: 'pass', 'SMS-SIGNED': 'pass', 'SMS-FORGED': 'pass', 'SMS-UNSIGNED': 'pass' }, JSON.stringify(summary));
  assert.deepEqual(fixed.httpStatus, { 'SMS-SIGNED': 200, 'SMS-FORGED': 403, 'SMS-UNSIGNED': 403 });
  assert.deepEqual(fixed.billing, { 'SMS-SIGNED': [{ status: 'keyed', scheme: 'stripe', verified: true }], 'SMS-FORGED': [], 'SMS-UNSIGNED': [] }, 'the outbound Stripe-style event verified under the declared billing secret, in the signed check\'s window');
  assert.deepEqual([fixed.signing, fixed.leads], [[{ observer: 'sink', host: BILLING, scheme: 'stripe', usable: [true] }], 1]);
  assert.deepEqual(fixed.driverKeys, [{ secretEnv: ENV.twilioForged, provider: 'twilio' }, { secretEnv: ENV.twilio, provider: 'twilio' }]);
  assert.deepEqual(summary.none.statuses, { WHOAMI: 'pass', 'SMS-SIGNED': 'pass', 'SMS-FORGED': 'fail', 'SMS-UNSIGNED': 'fail' }, 'an app that verifies nothing: both prohibitions fail');
  assert.deepEqual(summary.none.billing['SMS-FORGED'].map(e => e.verified), [true], 'the forged SMS reached the write path: its billing event is in the window');
  // An app that verifies only a present header: the unsigned SMS catches it. Its billing send lands after the forged check's
  // window and fits that check's selector, so the forged check's absence pass is withheld (settlement, effect-outside-window).
  assert.deepEqual(summary['header-optional'].statuses, { WHOAMI: 'pass', 'SMS-SIGNED': 'pass', 'SMS-FORGED': 'inconclusive', 'SMS-UNSIGNED': 'fail' });
  assert.match(summary['header-optional'].unsettled['SMS-FORGED'].join(' '), /effect-outside-window/);
  assert.deepEqual(summary['header-optional'].httpStatus, { 'SMS-SIGNED': 200, 'SMS-FORGED': 403, 'SMS-UNSIGNED': 200 });
  if (process.env.SCOPEHAVEN_WEBHOOK_EXAMPLE_OUT) writeFileSync(process.env.SCOPEHAVEN_WEBHOOK_EXAMPLE_OUT, `${JSON.stringify(summary, null, 1)}\n`);
});

// The mutation sweep: one mutation per property of src/webhook-driver.mjs, each applied alone to a copy of the tree (never the
// checkout) in a folder whose name has a space; this file must pass unmutated there and fail under every mutation.
const D = 'src/webhook-driver.mjs';
export const MUTATIONS = Object.freeze([
  ['W1', 'Twilio sorts parameters by name', 'return [...byName.keys()].sort().reduce(', 'return [...byName.keys()].reduce('],
  ['W2', 'Twilio signs the URL', ".join(''), url);", ".join(''), '');"],
  ['W3', 'Twilio signs a repeated parameter once per distinct value, sorted', '[...new Set(byName.get(name))].sort().map(', 'byName.get(name).map('],
  ['W4', 'Twilio uses HMAC-SHA1', "createHmac('sha1', key)", "createHmac('sha256', key)"],
  ['W5', 'a JSON Twilio webhook signs the URL with bodySHA256', 'url += suffix; path += suffix;', 'path += suffix;'],
  ['W6', 'a JSON Twilio webhook appends no parameters', 'twilioMac(key, url, entries ?? [])', 'twilioMac(key, url, formEntries(check.body))'],
  ['W7', 'Stripe signs "<t>." and the body', '.update(`${t}.`).update(payload)', '.update(payload)'],
  ['W8', 'Stripe sends hex', "digest('hex')}`;", "digest('base64')}`;"],
  ['W9', 'Stripe sends the v1 scheme', '`t=${t},v1=${', '`t=${t},v0=${'],
  ['W10', 'Telnyx signs "<t>|" and the body', 'Buffer.from(`${t}|`)', 'Buffer.from(`${t}.`)'],
  ['W11', 'Telnyx sends the time it signed', "headers['telnyx-timestamp'] = String(t);", "headers['telnyx-timestamp'] = String(Math.floor(now() / 1000));"],
  ['W12', 'the declared offset moves the signed time', 'Math.floor(now() / 1000) + d.timestampOffsetSeconds', 'Math.floor(now() / 1000)'],
  ['W13', 'the Ed25519 public key is the raw 32 bytes', ".subarray(12).toString('base64')", ".subarray(0).toString('base64')"],
  ['W14', 'a form body is form-encoded', 'entries ? new URLSearchParams(entries).toString() : JSON.stringify(body)', 'JSON.stringify(body)'],
  ['W15', 'Content-Type follows the encoding', "form: 'application/x-www-form-urlencoded'", "form: 'application/json'"],
  ['W16', 'a missing or unusable key refuses the run', 'if (unusable.length) refuse(', 'if (false) refuse('],
  ['W17', 'an omitted signature sends no signature header', "if (signed) headers['Stripe-Signature']", "headers['Stripe-Signature']"],
  ['W18', 'only documented headers may be declared', 'const canonical = form.extraHeaders.find(h => h.toLowerCase() === name.toLowerCase());', 'const canonical = form.extraHeaders.find(h => h.toLowerCase() === name.toLowerCase()) ?? name;'],
  ['W19', 'a header value is visible ASCII', "if (typeof value !== 'string' || !HEADER_VALUE.test(value)) refuse(", "if (typeof value !== 'string') refuse("],
  ['W20', 'the declared URL ends in the check path', "if (text !== `${url.origin}${path}`) refuse(", 'if (false) refuse('],
  ['W21', 'an omitted signature names no key', "if (signature === 'omit' && Object.hasOwn(webhook, 'secretEnv')) refuse(", 'if (false) refuse('],
  ['W22', 'Twilio signs no timestamp, so takes no offset', "if (!form.timestamped) refuse('webhook-declaration', `${provider} signs no timestamp", "if (false) refuse('webhook-declaration', `${provider} signs no timestamp"],
  ['W23', 'Stripe and Telnyx send JSON only', "stripe: Object.freeze({ encodings: Object.freeze(['json'])", "stripe: Object.freeze({ encodings: Object.freeze(['json', 'form'])"],
  ['W24', 'the encoded body is bounded', 'if (payload.length > WEBHOOK_LIMITS.payloadBytes) refuse(', 'if (false) refuse('],
  ['W25', 'two webhook keys never share a value', 'names.slice(i + 1).find(other => values.get(other) === values.get(name) || keys.get(other).key.equals(keys.get(name).key))\n      ?? ', ''],
  ['W26', 'a webhook key is never another credential\'s value', '\n      ?? otherEnvs(target).find(other => other !== name && values.get(other) === values.get(name))', ''],
  ['W27', 'a webhook key variable is never an actor\'s or observer\'s', 'const taken = otherEnvs(target).find(n => names.has(n));', 'const taken = undefined;'],
  ['W28', 'the key digest is salted', '.update(salt).update(`${name}\\n`)', '.update(`${name}\\n`)'],
  ['W29', 'a record holds a digest, never the key', 'keyDigest: signed ? keys.get(d.secretEnv).digest : null', "keyDigest: signed ? keys.get(d.secretEnv).key.toString('hex') : null"],
  ['W30', 'a closed driver builds nothing', 'close: () => { closed = true; ', 'close: () => { '],
  ['W31', 'the sent check keeps the declaration read', 'if (JSON.stringify(validateWebhookDeclaration(check.webhook, check)) !== JSON.stringify(d)) refuse(', 'if (false) refuse('],
  ['W32', 'one variable serves one provider', 'if (providerOf.has(d.secretEnv) && providerOf.get(d.secretEnv) !== d.provider) refuse(', 'if (false) refuse('],
  ['W33', 'a declared URL is written as a URL parser writes it', 'if (url.href !== text) refuse(', 'if (false) refuse('],
  ['W34', 'a default Twilio URL is signed as the request is sent', 'let url = sent.href;', 'let url = d.url ?? `${originOf(origin)}${check.path}`;'],
  ['W35', 'a JSON body hash joins an existing query with "&"', "url.endsWith('?') ? '' : '&'", "url.endsWith('?') ? '' : '?'"],
  ['W36', 'a Telnyx seed is canonical base64', " || seed.toString('base64') !== text", ''],
  ['W37', 'each variable is read once', 'keyBytes(provider, values.get(name)) === null', 'keyBytes(provider, env[name]) === null'],
  ['W38', 'a form parameter name is well formed', ' && name.isWellFormed()', ''],
  ['W39', 'an exported primitive refuses a key that is not a string', "if (typeof value !== 'string' || !value.length) refuse(", 'if (false) refuse('],
  ['W40', 'evidence: a signed record names a driver key under its digest', 'key.keyDigest === r.keyDigest', 'true'],
  ['W41', 'evidence: each sent webhook row carries its record, and no other row does', "if (expected !== null && (e !== undefined && row?.trace?.[0]?.data?.requestAttempted === true) !== (record !== undefined)) return 'webhook-record';", ''],
  ['W42', 'evidence: a record matches its declaration', "if (e !== undefined && !recordMatches(record, e, slotOf)) return 'webhook-record-declaration';", ''],
  ['W43', 'evidence: the driver record names exactly the declared keys', ' || !keysAgree()) return', ') return'],
  ['W45', 'evidence: a suite view\'s slot names the record\'s key', 'slotOf(r.secretEnv) === e.key', 'true'],
  ['W46', 'a suite view names no variable', 'key: f.secretEnv === null ? null : names.indexOf(f.secretEnv)', 'key: f.secretEnv'],
  ['W47', 'evidence: slots compare in numeric order, not as text', ".sort(([a], [b]) => (typeof a === 'number' ? a - b : a < b ? -1 : a > b ? 1 : 0))", '.sort()'],
  ['W48', 'evidence: each driver key is listed under its declared provider', 'driver.keys[i].provider === provider && ', ''],
  ['W49', 'evidence: a suite view is validated in full', "|| !(form.signsUrl ? ['declared', 'origin'].includes(v.url) : v.url === null)", ''],
  ['W44', 'evidence: signature headers are recorded exactly when signed', "\n    || !form.signatureHeaders.every(h => r.headers.includes(h.toLowerCase()) === signed)) return false;", ') return false;'],
]);
test('mutation sweep: every mutation of the driver makes this file fail', { skip: process.env.SCOPEHAVEN_WEBHOOK_MUTATIONS !== '1' && 'set SCOPEHAVEN_WEBHOOK_MUTATIONS=1 to run it', timeout: 3600000 }, () => {
  const root = fileURLToPath(new URL('../', import.meta.url)), tmp = mkdtempSync(join(tmpdir(), 'scopehaven webhook mutations '));
  const only = process.env.SCOPEHAVEN_WEBHOOK_MUTATIONS_ONLY?.split(',') ?? null, outFile = process.env.SCOPEHAVEN_WEBHOOK_MUTATIONS_OUT ?? null;
  // The child is a test run of its own: without NODE_TEST_CONTEXT it would report to this runner and run nothing.
  const { SCOPEHAVEN_WEBHOOK_MUTATIONS: _sweep, SCOPEHAVEN_WEBHOOK_MUTATIONS_ONLY: _only, SCOPEHAVEN_WEBHOOK_MUTATIONS_OUT: _out, SCOPEHAVEN_WEBHOOK_EXAMPLE_OUT: _example, NODE_TEST_CONTEXT: _context, ...childEnv } = process.env;
  const run = () => {
    const r = spawnSync(process.execPath, ['--test', '--test-concurrency=1', '--test-reporter=spec', 'test/webhook-driver.test.mjs'], { cwd: tmp, encoding: 'utf8', timeout: 600000, env: childEnv });
    const count = name => Number(/^ℹ (\w+) (\d+)$/m.test(r.stdout) ? (r.stdout.match(new RegExp(`^ℹ ${name} (\\d+)$`, 'm'))?.[1] ?? NaN) : NaN);
    return { status: r.status, pass: count('pass'), fail: count('fail'), failed: [...new Set(r.stdout.split('\n').filter(l => /^✖ /.test(l)).map(l => l.slice(2).replace(/ \([\d.]+ms\)$/, '')))].filter(n => n !== 'failing tests:') };
  };
  try {
    for (const dir of ['src', 'integrations']) cpSync(join(root, dir), join(tmp, dir), { recursive: true });
    cpSync(join(root, 'test', 'webhook-driver.test.mjs'), join(tmp, 'test', 'webhook-driver.test.mjs'));
    cpSync(join(root, 'package.json'), join(tmp, 'package.json'));
    const base = run();
    // The unmutated file must really run there: every test but this one passes.
    assert.deepEqual([base.status, base.fail, base.pass >= 13], [0, 0, true], `unmutated: ${JSON.stringify(base)}`);
    const path = join(tmp, D), original = readFileSync(path, 'utf8'), results = [];
    for (const [id, property, find, replace] of MUTATIONS.filter(([id]) => !only || only.includes(id))) {
      assert.equal(original.split(find).length - 1, 1, `${id}: the edit matches once`);
      writeFileSync(path, original.replace(find, () => replace));
      let r;
      try { r = run(); } finally { writeFileSync(path, original); }
      results.push({ id, property, status: r.status === 0 ? 'SURVIVED' : 'killed', fail: r.fail, killedBy: r.failed.slice(0, 3) });
      process.stderr.write(`${id} ${results.at(-1).status} ${r.failed.slice(0, 2).join(' | ')}\n`);
    }
    if (outFile) writeFileSync(outFile, `${JSON.stringify({ schema: 'scopehaven-webhook-mutations/1', at: new Date().toISOString(), node: process.version, base, total: results.length, killed: results.filter(r => r.status === 'killed').length, results }, null, 1)}\n`);
    assert.deepEqual(results.filter(r => r.status !== 'killed').map(r => `${r.id} ${r.property}`), []);
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});
