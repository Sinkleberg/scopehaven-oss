// Loopback-only HTTP transport for sequence steps that use PUT, PATCH or
// DELETE, which many admin APIs use to change access. It mirrors the
// connector's observeHttp (src/http-connector.mjs) rule for rule: a literal
// 127.0.0.1 origin, a same-origin path, no redirects, no proxy or DNS, no
// retries, the same credential and cookie checks, request and response size
// caps and a timeout. GET and POST steps keep using observeHttp itself, so
// existing runs and the connector's identity are unchanged.
// observeWebsocket (below) opens a sequence's websocket steps under the same rules.
import { request } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { HTTP_LIMITS, observeHttp } from '../../src/http-connector.mjs';
import { COOKIE_NAME_PATTERN } from '../../src/contracts.mjs';
import { CREDENTIAL_ENV } from '../observers/events.mjs';

export const EXTRA_METHODS = Object.freeze(['PUT', 'PATCH', 'DELETE']);
export const SEQUENCE_METHODS = Object.freeze(['GET', 'POST', ...EXTRA_METHODS]);
const BEARER_VALUE = /^[\x21-\x7e]{1,8192}$/, COOKIE_VALUE = /^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]{1,8192}$/;
const credentialFormatValid = (value, cookieName) => typeof value === 'string' && (cookieName === undefined ? BEARER_VALUE : COOKIE_VALUE).test(value);

// csrf ({ header, cookie, value }, from actorCsrf only): the actor's CSRF pair, sent as that header and as that cookie beside its
// credential on every request, GET and POST included (they come here only for such an actor; see withActorCsrf).
export function observeHttpMethod(origin, check, { credential, credentialCookie, csrf, timeoutMs = HTTP_LIMITS.requestTimeoutMs, maxResponseBytes = HTTP_LIMITS.responseBytes } = {}) {
  const literal = typeof origin === 'string' && /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/?$/.exec(origin);
  if (!literal || Number(literal[1]) > 65535) throw new Error('Target connection is outside the configured local origin.');
  if (typeof check.path !== 'string' || !check.path.startsWith('/') || check.path.startsWith('//')) throw new Error('Target connection is outside the configured local origin.');
  const base = new URL(origin), url = new URL(check.path, origin);
  if (url.origin !== base.origin || url.username || url.password || url.hash) throw new Error('Target connection is outside the configured local origin.');
  if (!(csrf === undefined ? EXTRA_METHODS : SEQUENCE_METHODS).includes(check.method)) throw new Error('Unsupported request method.');
  if (csrf !== undefined && (csrfProblem(csrf, credentialCookie) !== null || credential === undefined)) throw new Error('CSRF pair is unsupported or has no credential beside it.');
  if (check.method === 'GET' && check.body !== undefined) throw new Error('A GET request carries no body.');
  if (credentialCookie !== undefined && (typeof credentialCookie !== 'string' || !COOKIE_NAME_PATTERN.test(credentialCookie) || credential === undefined)) throw new Error('Credential cookie is missing or has an unsupported name.');
  if (credential !== undefined && !credentialFormatValid(credential, credentialCookie)) throw new Error('Credential is missing or has an unsupported format.');
  const payload = check.body === undefined ? null : JSON.stringify(check.body);
  if (payload && Buffer.byteLength(payload) > HTTP_LIMITS.requestBytes) throw new Error('Request exceeds the local connector limit.');
  return new Promise(resolve => {
    let done = false, status = null, bytes = 0, timer;
    const chunks = [];
    const finish = result => { if (done) return; done = true; clearTimeout(timer); resolve({ status, complete: false, jsonParsed: false, json: undefined, bytes, ...result }); };
    const req = request(url, { method: check.method, agent: false, maxHeaderSize: 8192, headers: {
      Accept: 'application/json', Connection: 'close',
      ...(credential === undefined ? {} : credentialCookie === undefined ? { Authorization: `Bearer ${credential}` } : {}),
      ...(credentialCookie === undefined && csrf === undefined ? {} : { Cookie: [...(credential !== undefined && credentialCookie !== undefined ? [`${credentialCookie}=${credential}`] : []), ...(csrf ? [`${csrf.cookie}=${csrf.value}`] : [])].join('; ') }),
      ...(csrf === undefined ? {} : { [csrf.header]: csrf.value }),
      ...(payload === null ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }),
    } }, res => {
      status = res.statusCode;
      // A redirect is itself a response. Never follow its Location header.
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > maxResponseBytes) { finish({ error: 'too-large' }); res.destroy(); req.destroy(); return; }
        chunks.push(chunk);
      });
      res.on('end', () => {
        if (!res.complete) return finish({ error: 'network' });
        const raw = Buffer.concat(chunks);
        // A 204 or other empty body is a complete response without JSON.
        if (!raw.length) return finish({ complete: true, error: 'invalid-json' });
        let value;
        try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)); }
        catch { return finish({ complete: true, error: 'invalid-json' }); }
        finish({ complete: true, jsonParsed: true, json: value });
      });
      res.on('aborted', () => finish({ error: 'network' }));
      res.on('error', () => finish({ error: 'network' }));
    });
    req.on('error', () => finish({ error: 'network' }));
    timer = setTimeout(() => { finish({ error: 'timeout' }); req.destroy(); }, timeoutMs);
    req.end(payload);
  });
}

// observeHttp for GET and POST (unchanged), observeHttpMethod for the rest.
export const sequenceTransport = (origin, check, options) => (EXTRA_METHODS.includes(check.method) ? observeHttpMethod : observeHttp)(origin, check, options);

// Per-actor CSRF pair (L8 fix 6a). An app that checks a CSRF token on every signed-in route (a header that must equal a cookie,
// as one practice stack's console does) refuses a sequence that sends only the session credential. An actor may declare
//   "csrf": { "env": "SCOPEHAVEN_TARGET_...", "header": "X-CSRF-Token", "cookie": "csrf_token" }
// and its requests then carry that header and that cookie, both holding the env value, beside its credential. The value is a
// secret read as the credential is (the SCOPEHAVEN_TARGET_ namespace) and never written to a run. The declaration is read here
// and in the CLI only, never by sequence.mjs, so the sequence and evaluator identities are unchanged: it changes how a request
// is presented, not what is sent or how a run is judged.
// The header may not be one the transport sets itself or one a framework reads as another method; the cookie may not be the
// credential's cookie. Values follow the cookie-value rule (no space, quote, comma, semicolon or backslash).
const CSRF_KEYS = ['cookie', 'env', 'header'];
const RESERVED_HEADERS = new Set(['accept', 'authorization', 'connection', 'content-length', 'content-type', 'cookie', 'host', 'transfer-encoding', 'x-http-method-override', 'x-http-method', 'x-method-override']);
function csrfProblem(csrf, credentialCookie) {
  if (!csrf || typeof csrf !== 'object' || Array.isArray(csrf)) return 'csrf must be an object';
  if (typeof csrf.header !== 'string' || !COOKIE_NAME_PATTERN.test(csrf.header) || RESERVED_HEADERS.has(csrf.header.toLowerCase())) return 'csrf.header must be a header name the transport does not set';
  if (typeof csrf.cookie !== 'string' || !COOKIE_NAME_PATTERN.test(csrf.cookie) || csrf.cookie === credentialCookie) return 'csrf.cookie must be a cookie name other than the credential cookie';
  if (Object.hasOwn(csrf, 'value') && !COOKIE_VALUE.test(csrf.value)) return 'the CSRF value has an unsupported format';
  return null;
}
// actorCsrf(seq, env): one pair per actor that declares csrf, keyed by how its credential is presented, or null when none does.
// Refused (thrown) before any request: a malformed declaration, an unset or malformed value, an actor with no credential, and
// two actors presenting the same credential with different pairs (the transport could not tell them apart).
export function actorCsrf(seq, env) {
  const pairs = new Map();
  for (const [alias, actor] of Object.entries(seq?.actors ?? {})) {
    if (actor?.csrf === undefined) continue;
    const where = `Actor "${alias.slice(0, 40)}"`, csrf = actor.csrf;
    if (!csrf || typeof csrf !== 'object' || Array.isArray(csrf) || Object.keys(csrf).sort().join(',') !== CSRF_KEYS.join(',')) throw new Error(`${where}: csrf needs exactly env, header and cookie.`);
    if (typeof csrf.env !== 'string' || !CREDENTIAL_ENV.test(csrf.env)) throw new Error(`${where}: csrf.env must use the dedicated SCOPEHAVEN_TARGET_ namespace.`);
    if (typeof actor.credentialEnv !== 'string') throw new Error(`${where}: a CSRF pair rides a session, so the actor needs a credentialEnv.`);
    const problem = csrfProblem(csrf, actor.credentialCookie);
    if (problem) throw new Error(`${where}: ${problem}.`);
    const value = env[csrf.env], credential = env[actor.credentialEnv];
    if (typeof value !== 'string' || !COOKIE_VALUE.test(value)) throw new Error(`${where}: the CSRF value reference is not set or has an unsupported format.`);
    if (typeof credential !== 'string') continue; // the runner refuses the unset credential itself, naming the actor
    const key = `${actor.credentialCookie ?? ''}\n${credential}`, pair = Object.freeze({ header: csrf.header, cookie: csrf.cookie, value });
    const had = pairs.get(key);
    if (had && (had.header !== pair.header || had.cookie !== pair.cookie || had.value !== pair.value)) throw new Error(`${where}: another actor presents the same credential with a different CSRF pair.`);
    pairs.set(key, pair);
  }
  return pairs.size ? pairs : null;
}
// The transport for a sequence whose actors may declare csrf: a request presenting a credential that a pair is keyed by goes
// through observeHttpMethod with that pair (every method); every other request goes to `base` unchanged.
export function withActorCsrf(pairs, base = sequenceTransport) {
  if (!pairs) return base;
  return (origin, check, options = {}) => {
    const pair = options.credential === undefined ? undefined : pairs.get(`${options.credentialCookie ?? ''}\n${options.credential}`);
    return pair === undefined ? base(origin, check, options) : observeHttpMethod(origin, check, { ...options, csrf: pair });
  };
}

// Websocket steps (L8 fix 4). A minimal RFC 6455 client over node:http, under the HTTP transport's rules: a literal
// 127.0.0.1 origin and a same-origin path, no proxy, no redirect, no retry, the same credential, cookie and CSRF checks.
// It offers no extension (no permessage-deflate), so every frame carries the bytes the server sent. Bounds: 1 MiB per
// message, 8 MiB per step, at most 1000 messages. It returns what a run seals: the handshake status (101, the status of a
// refusal, or null), how the step ended, the number of data messages, the close code, the bytes received and one sha256
// digest per message. Message content is never returned.
//   transport: complete (the declared message count was reached, or the server closed), timeout, network (the connection
//   ended without a close frame), refused (the handshake was answered without 101), too-large, protocol (a frame no
//   server may send, or a handshake answer that is not a websocket's)
export const WEBSOCKET_LIMITS = Object.freeze({ messageBytes: 1024 * 1024, stepBytes: 8 * 1024 * 1024, messages: 1000, send: 16, sendBytes: HTTP_LIMITS.requestBytes, timeoutMs: 600000 });
const WEBSOCKET_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
// One masked client frame (RFC 6455 5.3: a client masks every frame).
function clientFrame(opcode, payload) {
  const mask = randomBytes(4), length = payload.length;
  let head;
  if (length < 126) head = Buffer.from([0x80 | opcode, 0x80 | length]);
  else if (length < 65536) head = Buffer.from([0x80 | opcode, 0x80 | 126, length >> 8, length & 255]);
  else { head = Buffer.alloc(10); head[0] = 0x80 | opcode; head[1] = 0x80 | 127; head.writeBigUInt64BE(BigInt(length), 2); }
  const body = Buffer.from(payload);
  for (let i = 0; i < body.length; i++) body[i] ^= mask[i & 3];
  return Buffer.concat([head, mask, body]);
}

// step: { path, send?: [JSON values], until?: { messages: n } | { close: true } }
export function observeWebsocket(origin, step, { credential, credentialCookie, csrf, timeoutMs = 60000 } = {}) {
  const literal = typeof origin === 'string' && /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/?$/.exec(origin);
  if (!literal || Number(literal[1]) > 65535) throw new Error('Target connection is outside the configured local origin.');
  if (typeof step?.path !== 'string' || !step.path.startsWith('/') || step.path.startsWith('//')) throw new Error('Target connection is outside the configured local origin.');
  const base = new URL(origin), url = new URL(step.path, origin);
  if (url.origin !== base.origin || url.username || url.password || url.hash) throw new Error('Target connection is outside the configured local origin.');
  if (csrf !== undefined && (csrfProblem(csrf, credentialCookie) !== null || credential === undefined)) throw new Error('CSRF pair is unsupported or has no credential beside it.');
  if (credentialCookie !== undefined && (typeof credentialCookie !== 'string' || !COOKIE_NAME_PATTERN.test(credentialCookie) || credential === undefined)) throw new Error('Credential cookie is missing or has an unsupported name.');
  if (credential !== undefined && !credentialFormatValid(credential, credentialCookie)) throw new Error('Credential is missing or has an unsupported format.');
  const sends = (step.send ?? []).map(value => Buffer.from(JSON.stringify(value)));
  if (sends.length > WEBSOCKET_LIMITS.send || sends.some(b => b.length > WEBSOCKET_LIMITS.sendBytes)) throw new Error('Websocket messages exceed the local connector limit.');
  const wanted = Number.isInteger(step.until?.messages) ? step.until.messages : Infinity;
  const key = randomBytes(16).toString('base64');
  return new Promise(resolve => {
    let done = false, status = null, socket = null, timer, buffer = Buffer.alloc(0), bytes = 0, closeCode = null, fragments = [], fragmentBytes = 0;
    const digests = [];
    const finish = transport => {
      if (done) return;
      done = true; clearTimeout(timer);
      if (socket) {
        // Answer or start the closing handshake, then drop the connection whatever the server does.
        try { if (!socket.destroyed && transport !== 'network') socket.end(clientFrame(0x8, Buffer.from([0x03, 0xe8]))); } catch {}
        setTimeout(() => socket.destroy(), 50).unref();
      } else req.destroy();
      resolve({ status, transport, messages: digests.length, closeCode, bytes, digests });
    };
    // Frames from the server: unmasked; data (text, binary, continuation), close, ping and pong.
    const read = () => {
      while (!done) {
        if (buffer.length < 2) return;
        const fin = buffer[0] & 0x80, rsv = buffer[0] & 0x70, opcode = buffer[0] & 0x0f, masked = buffer[1] & 0x80;
        let length = buffer[1] & 0x7f, offset = 2;
        if (rsv || masked) return finish('protocol');
        if (length === 126) { if (buffer.length < 4) return; length = buffer.readUInt16BE(2); offset = 4; }
        else if (length === 127) {
          if (buffer.length < 10) return;
          const big = buffer.readBigUInt64BE(2);
          if (big > BigInt(WEBSOCKET_LIMITS.messageBytes)) return finish('too-large');
          length = Number(big); offset = 10;
        }
        const control = opcode >= 0x8;
        if (control && (!fin || length > 125)) return finish('protocol');
        if (!control && fragmentBytes + length > WEBSOCKET_LIMITS.messageBytes) return finish('too-large');
        if (!control && bytes + length > WEBSOCKET_LIMITS.stepBytes) return finish('too-large');
        if (buffer.length < offset + length) return;
        const payload = buffer.subarray(offset, offset + length);
        buffer = buffer.subarray(offset + length);
        if (opcode === 0x8) { closeCode = payload.length >= 2 ? payload.readUInt16BE(0) : null; return finish('complete'); }
        if (opcode === 0x9) { socket.write(clientFrame(0xa, payload)); continue; }
        if (opcode === 0xa) continue;
        if (![0x0, 0x1, 0x2].includes(opcode) || (opcode === 0x0) !== (fragments.length > 0)) return finish('protocol');
        bytes += length;
        fragments.push(Buffer.from(payload)); fragmentBytes += length;
        if (!fin) continue;
        digests.push(sha256(Buffer.concat(fragments))); fragments = []; fragmentBytes = 0;
        if (digests.length >= wanted) return finish('complete');
        if (digests.length >= WEBSOCKET_LIMITS.messages) return finish('too-large');
      }
    };
    const req = request(url, { method: 'GET', agent: false, maxHeaderSize: 8192, headers: {
      Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': key,
      ...(credential === undefined ? {} : credentialCookie === undefined ? { Authorization: `Bearer ${credential}` } : {}),
      ...(credentialCookie === undefined && csrf === undefined ? {} : { Cookie: [...(credential !== undefined && credentialCookie !== undefined ? [`${credentialCookie}=${credential}`] : []), ...(csrf ? [`${csrf.cookie}=${csrf.value}`] : [])].join('; ') }),
      ...(csrf === undefined ? {} : { [csrf.header]: csrf.value }),
    } });
    // A handshake answered without 101 is a refusal; its body is never read, and a redirect is not followed.
    req.on('response', res => { status = res.statusCode; res.resume(); finish('refused'); });
    req.on('upgrade', (res, upgraded, head) => {
      socket = upgraded; status = res.statusCode;
      const accept = createHash('sha1').update(key + WEBSOCKET_GUID).digest('base64');
      if (res.headers['sec-websocket-accept'] !== accept || res.headers['sec-websocket-extensions'] !== undefined || String(res.headers.upgrade).toLowerCase() !== 'websocket') return finish('protocol');
      socket.on('data', chunk => { buffer = Buffer.concat([buffer, chunk]); read(); });
      for (const event of ['end', 'close', 'error']) socket.on(event, () => finish('network'));
      for (const message of sends) socket.write(clientFrame(0x1, message));
      if (head?.length) { buffer = Buffer.concat([buffer, head]); read(); }
    });
    req.on('error', () => finish('network'));
    timer = setTimeout(() => finish('timeout'), Math.max(1, Math.min(timeoutMs, WEBSOCKET_LIMITS.timeoutMs)));
    req.end();
  });
}
// The websocket transport for a sequence whose actors may declare csrf: an actor's pair rides its handshake too.
export function websocketWithActorCsrf(pairs, base = observeWebsocket) {
  if (!pairs) return base;
  return (origin, step, options = {}) => {
    const pair = options.credential === undefined ? undefined : pairs.get(`${options.credentialCookie ?? ''}\n${options.credential}`);
    return base(origin, step, pair === undefined ? options : { ...options, csrf: pair });
  };
}
