// A minimal PostgreSQL wire-protocol client for read-only observers. No npm
// dependency: node:net and node:crypto only. It speaks protocol 3.0 startup,
// SCRAM-SHA-256 authentication (verifying the server's signature, requiring at
// least 4096 iterations and a server nonce that extends the client's), and the
// simple-query protocol with text results. A server that accepts the login
// without a challenge (trust), or asks for md5 or a cleartext password, is
// refused: a process squatting on the loopback port could otherwise feed
// fabricated rows, or collect an offline-crackable md5 response. (md5 is
// available only with allowMd5: true, for operator code.) It connects only to
// the literal loopback address 127.0.0.1, sets client_encoding to UTF8 at startup
// (a database or role default cannot change how text is decoded), and never keeps the password: it is
// used during the handshake and then dropped. Error frames surface only a
// validated SQLSTATE code, never server message text.
import { connect as tcpConnect } from 'node:net';
import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from 'node:crypto';

export const PG_LIMITS = Object.freeze({ messageBytes: 64 * 1024 * 1024, rows: 250000, connectTimeoutMs: 5000, queryTimeoutMs: 30000 });
export class PgError extends Error {
  constructor(code, sqlState = null) { super(`postgres: ${code}${sqlState ? ` (${sqlState})` : ''}`); this.name = 'PgError'; this.code = code; this.sqlState = sqlState; }
}

const int32 = n => { const b = Buffer.alloc(4); b.writeInt32BE(n); return b; };
const cstr = s => Buffer.concat([Buffer.from(s, 'utf8'), Buffer.from([0])]);
const frame = (type, body) => Buffer.concat([type ? Buffer.from(type) : Buffer.alloc(0), int32(body.length + 4), body]);
const xor = (a, b) => Buffer.from(a.map((byte, i) => byte ^ b[i]));
const hmac = (key, data) => createHmac('sha256', key).update(data).digest();

// Incremental reader of backend messages: [type:1][length:4][body].
function messageReader(socket) {
  let buffered = Buffer.alloc(0), waiting = null, failure = null;
  const queue = [];
  const drain = () => {
    while (buffered.length >= 5) {
      const length = buffered.readInt32BE(1);
      if (length < 4 || length > PG_LIMITS.messageBytes) { failure = new PgError('protocol-message-too-large'); break; }
      if (buffered.length < 1 + length) break;
      queue.push({ type: String.fromCharCode(buffered[0]), body: buffered.subarray(5, 1 + length) });
      buffered = buffered.subarray(1 + length);
    }
    if (waiting && (queue.length || failure)) { const w = waiting; waiting = null; failure ? w.reject(failure) : w.resolve(queue.shift()); }
  };
  socket.on('data', chunk => { buffered = Buffer.concat([buffered, chunk]); drain(); });
  socket.on('error', () => { failure ??= new PgError('connection-error'); drain(); });
  socket.on('close', () => { failure ??= new PgError('connection-closed'); drain(); });
  return () => new Promise((resolve, reject) => {
    if (queue.length) return resolve(queue.shift());
    if (failure) return reject(failure);
    waiting = { resolve, reject };
  });
}
// An ErrorResponse: keep only the SQLSTATE ('C'), validated, never the message text.
// A field without its NUL terminator ends the scan (a malformed frame never loops).
const SQLSTATE = /^[0-9A-Z]{5}$/;
const sqlStateOf = body => {
  for (let i = 0; i < body.length && body[i] !== 0;) {
    const field = String.fromCharCode(body[i]), end = body.indexOf(0, i + 1);
    if (end < 0) break;
    if (field === 'C') { const code = body.toString('utf8', i + 1, end); return SQLSTATE.test(code) ? code : null; }
    i = end + 1;
  }
  return null;
};

// connect({ host: '127.0.0.1', port, database, user, password }) -> { query(sql), close() }
export async function pgConnect({ host, port, database, user, password, connectTimeoutMs = PG_LIMITS.connectTimeoutMs, allowMd5 = false, connector = tcpConnect }) {
  if (host !== '127.0.0.1') throw new PgError('host-must-be-literal-loopback');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new PgError('invalid-port');
  if (typeof user !== 'string' || !user || typeof database !== 'string' || !database || typeof password !== 'string') throw new PgError('invalid-credential');
  const socket = connector({ host, port });
  socket.setNoDelay?.(true);
  const read = messageReader(socket);
  const send = buf => socket.write(buf);
  const timer = setTimeout(() => socket.destroy(), connectTimeoutMs);
  try {
    // Settles on connect, error or close: the connect timer's destroy() emits only 'close'.
    await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', () => reject(new PgError('connect-failed'))); socket.once('close', () => reject(new PgError('connect-failed'))); });
    send(frame(null, Buffer.concat([int32(196608), cstr('user'), cstr(user), cstr('database'), cstr(database), cstr('application_name'), cstr('scopehaven-observer'), cstr('client_encoding'), cstr('UTF8'), Buffer.from([0])])));
    await authenticate(read, send, user, password, { allowMd5 });
    password = null; // never kept past the handshake
    for (;;) { const m = await read(); if (m.type === 'E') throw new PgError('startup-failed', sqlStateOf(m.body)); if (m.type === 'Z') break; }
  } catch (error) { socket.destroy(); throw error instanceof PgError ? error : new PgError('startup-failed'); }
  finally { clearTimeout(timer); }

  let busy = false;
  return {
    // Simple query; returns [{ rows: [[text|null, ...]], command }] per statement. Errors carry the SQLSTATE only.
    async query(sql, { queryTimeoutMs = PG_LIMITS.queryTimeoutMs, maxRows = PG_LIMITS.rows } = {}) {
      if (busy) throw new PgError('query-in-progress');
      busy = true;
      const timeout = setTimeout(() => socket.destroy(), queryTimeoutMs);
      try {
        send(frame('Q', cstr(sql)));
        const results = []; let current = { rows: [] }, error = null, total = 0;
        for (;;) {
          const m = await read();
          if (m.type === 'T') current = { rows: [] };
          else if (m.type === 'D') {
            if (++total > maxRows) error ??= new PgError('row-limit');
            else {
              const n = m.body.readInt16BE(0), row = []; let at = 2;
              for (let i = 0; i < n; i++) { const len = m.body.readInt32BE(at); at += 4; if (len === -1) row.push(null); else { row.push(m.body.toString('utf8', at, at + len)); at += len; } }
              current.rows.push(row);
            }
          } else if (m.type === 'C') { results.push({ ...current, command: m.body.toString('utf8', 0, m.body.length - 1) }); current = { rows: [] }; }
          else if (m.type === 'E') error ??= new PgError('query-failed', sqlStateOf(m.body));
          else if (m.type === 'Z') break;
        }
        if (error) throw error;
        return results;
      } finally { clearTimeout(timeout); busy = false; }
    },
    close() { try { socket.end(frame('X', Buffer.alloc(0))); } catch {} socket.destroy(); },
  };
}

async function authenticate(read, send, user, password, { allowMd5 }) {
  let challenged = false;
  for (;;) {
    const m = await read();
    if (m.type === 'E') throw new PgError('authentication-failed', sqlStateOf(m.body));
    if (m.type !== 'R') throw new PgError('unexpected-message');
    const code = m.body.readInt32BE(0);
    // Ok before any challenge is "trust": anyone listening on the port could be answering.
    if (code === 0) { if (!challenged) throw new PgError('authentication-not-challenged'); return; }
    challenged = true;
    if (code === 5) { // md5(md5(password + user) + salt): only when operator code allows it
      if (!allowMd5) throw new PgError('md5-authentication-refused');
      const inner = createHash('md5').update(password + user).digest('hex');
      send(frame('p', cstr(`md5${createHash('md5').update(Buffer.concat([Buffer.from(inner), m.body.subarray(4, 8)])).digest('hex')}`)));
      continue;
    }
    if (code === 10) { await scram(read, send, m.body.subarray(4), password); continue; }
    // 3 (cleartext) and anything else: refuse rather than send a password in the clear.
    throw new PgError(code === 3 ? 'cleartext-password-refused' : 'unsupported-authentication');
  }
}

// SCRAM-SHA-256 (RFC 5802 / 7677), no channel binding ("n,,"). The server's final
// signature is verified, so a server that does not know the password cannot pass.
async function scram(read, send, mechanismList, password) {
  const mechanisms = mechanismList.toString('utf8').split('\0').filter(Boolean);
  if (!mechanisms.includes('SCRAM-SHA-256')) throw new PgError('unsupported-authentication');
  const clientNonce = randomBytes(18).toString('base64');
  const clientFirstBare = `n=,r=${clientNonce}`;
  const first = Buffer.from(`n,,${clientFirstBare}`);
  send(frame('p', Buffer.concat([cstr('SCRAM-SHA-256'), int32(first.length), first])));
  const continueMsg = await read();
  if (continueMsg.type !== 'R' || continueMsg.body.readInt32BE(0) !== 11) throw new PgError('authentication-failed', continueMsg.type === 'E' ? sqlStateOf(continueMsg.body) : null);
  const serverFirst = continueMsg.body.subarray(4).toString('utf8');
  const attrs = Object.fromEntries(serverFirst.split(',').map(kv => [kv[0], kv.slice(2)]));
  const iterations = Number(attrs.i);
  // The server must extend our nonce (never echo it) and use a real iteration count.
  if (!attrs.r?.startsWith(clientNonce) || attrs.r.length <= clientNonce.length || !attrs.s || !Number.isInteger(iterations) || iterations < 4096 || iterations > 1e7) throw new PgError('authentication-failed');
  let salted = pbkdf2Sync(password.normalize('NFKC'), Buffer.from(attrs.s, 'base64'), iterations, 32, 'sha256');
  const clientKey = hmac(salted, 'Client Key'), serverKey = hmac(salted, 'Server Key');
  salted.fill(0); salted = null;
  const clientFinalNoProof = `c=biws,r=${attrs.r}`;
  const authMessage = `${clientFirstBare},${serverFirst},${clientFinalNoProof}`;
  const proof = xor(clientKey, hmac(createHash('sha256').update(clientKey).digest(), authMessage)).toString('base64');
  clientKey.fill(0);
  send(frame('p', Buffer.from(`${clientFinalNoProof},p=${proof}`)));
  const final = await read();
  if (final.type === 'E') throw new PgError('authentication-failed', sqlStateOf(final.body));
  if (final.type !== 'R' || final.body.readInt32BE(0) !== 12) throw new PgError('authentication-failed');
  const v = /(?:^|,)v=([^,]+)/.exec(final.body.subarray(4).toString('utf8'))?.[1];
  const expected = hmac(serverKey, authMessage); serverKey.fill(0);
  const got = v ? Buffer.from(v, 'base64') : Buffer.alloc(0);
  if (got.length !== expected.length || !timingSafeEqual(got, expected)) throw new PgError('server-signature-mismatch');
}
