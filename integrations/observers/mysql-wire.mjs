// A minimal MySQL client/server-protocol client for read-only observers. No npm
// dependency: node:net and node:crypto only. It speaks HandshakeV10 with
// protocol 4.1, the caching_sha2_password plugin (fast path, and full
// authentication by encrypting the password to the server's RSA public key,
// which the operator pins; the server's default since 8.0) and mysql_native_password, and COM_QUERY with
// text results, one statement per query (multi-statements are never enabled).
// It refuses mysql_clear_password and any other plugin, and an empty password.
// It connects only to the literal loopback address 127.0.0.1, and never keeps
// the password: it is used during the handshake and then dropped. Error
// packets surface only a validated SQLSTATE, never server message text.
// Unlike SCRAM, these plugins never prove the server to the client: a process
// that took the loopback port first could answer. Declared as a limitation.
// For the same reason a public key the server offers is never asked for or used:
// that process could offer its own and decrypt the password. Full authentication
// encrypts only to serverPublicKey (PEM, pinned by the operator) and is refused
// without one ("server-key-not-pinned"), before any password byte is sent.
import { connect as tcpConnect } from 'node:net';
import { createHash, createPublicKey, publicEncrypt, constants, randomBytes } from 'node:crypto';

export const MYSQL_LIMITS = Object.freeze({ packetBytes: 16 * 1024 * 1024, messageBytes: 64 * 1024 * 1024, rows: 250000, connectTimeoutMs: 5000, queryTimeoutMs: 30000 });
export class MysqlError extends Error {
  constructor(code, sqlState = null) { super(`mysql: ${code}${sqlState ? ` (${sqlState})` : ''}`); this.name = 'MysqlError'; this.code = code; this.sqlState = sqlState; }
}

// Capability flags (protocol 4.1).
const CAP = Object.freeze({ LONG_PASSWORD: 0x1, CONNECT_WITH_DB: 0x8, PROTOCOL_41: 0x200, TRANSACTIONS: 0x2000, SECURE_CONNECTION: 0x8000, PLUGIN_AUTH: 0x80000, PLUGIN_AUTH_LENENC: 0x200000, DEPRECATE_EOF: 0x1000000 });
const CLIENT_CAPS = CAP.LONG_PASSWORD | CAP.CONNECT_WITH_DB | CAP.PROTOCOL_41 | CAP.TRANSACTIONS | CAP.SECURE_CONNECTION | CAP.PLUGIN_AUTH | CAP.PLUGIN_AUTH_LENENC | CAP.DEPRECATE_EOF;
const sha1 = (...parts) => { const h = createHash('sha1'); for (const p of parts) h.update(p); return h.digest(); };
const sha256 = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
const xor = (a, b) => Buffer.from(a.map((byte, i) => byte ^ b[i % b.length]));
const lenenc = n => n < 251 ? Buffer.from([n]) : n < 0x10000 ? Buffer.from([0xfc, n & 0xff, n >> 8]) : Buffer.from([0xfd, n & 0xff, (n >> 8) & 0xff, n >> 16]);
// Length-encoded integer at `at`: [value, next]; null for the NULL marker (0xfb).
function readLenenc(buf, at) {
  const first = buf[at];
  if (first < 0xfb) return [first, at + 1];
  if (first === 0xfb) return [null, at + 1];
  if (first === 0xfc) return [buf.readUInt16LE(at + 1), at + 3];
  if (first === 0xfd) return [buf.readUIntLE(at + 1, 3), at + 4];
  if (first === 0xfe) { const v = Number(buf.readBigUInt64LE(at + 1)); if (!Number.isSafeInteger(v)) throw new MysqlError('protocol-error'); return [v, at + 9]; }
  throw new MysqlError('protocol-error');
}
// caching_sha2_password scramble: SHA256(p) XOR SHA256(SHA256(SHA256(p)), nonce).
export const cachingSha2Scramble = (password, nonce) => { const p1 = sha256(password); return xor(p1, sha256(sha256(p1), nonce)); };
// mysql_native_password scramble: SHA1(p) XOR SHA1(nonce, SHA1(SHA1(p))).
export const nativeScramble = (password, nonce) => { const p1 = sha1(password); return xor(p1, sha1(nonce, sha1(p1))); };

// Incremental packet reader: [length:3 LE][sequence:1][payload]; a 0xffffff payload continues in the next packet.
function packetReader(socket) {
  let buffered = Buffer.alloc(0), waiting = null, failure = null, parts = [];
  const queue = [];
  const drain = () => {
    while (buffered.length >= 4) {
      const length = buffered.readUIntLE(0, 3);
      if (buffered.length < 4 + length) break;
      parts.push(buffered.subarray(4, 4 + length)); buffered = buffered.subarray(4 + length);
      if (parts.reduce((n, p) => n + p.length, 0) > MYSQL_LIMITS.messageBytes) { failure = new MysqlError('protocol-message-too-large'); break; }
      if (length === 0xffffff) continue;
      queue.push(parts.length === 1 ? parts[0] : Buffer.concat(parts)); parts = [];
    }
    if (waiting && (queue.length || failure)) { const w = waiting; waiting = null; failure ? w.reject(failure) : w.resolve(queue.shift()); }
  };
  socket.on('data', chunk => { buffered = Buffer.concat([buffered, chunk]); drain(); });
  socket.on('error', () => { failure ??= new MysqlError('connection-error'); drain(); });
  socket.on('close', () => { failure ??= new MysqlError('connection-closed'); drain(); });
  return () => new Promise((resolve, reject) => {
    if (queue.length) return resolve(queue.shift());
    if (failure) return reject(failure);
    waiting = { resolve, reject };
  });
}
const SQLSTATE = /^[0-9A-Z]{5}$/;
// An ERR packet: 0xff, code:2, '#', SQLSTATE:5, message. Keep only a valid SQLSTATE.
const sqlStateOf = p => p.length >= 9 && p[3] === 0x23 && SQLSTATE.test(p.toString('latin1', 4, 9)) ? p.toString('latin1', 4, 9) : null;

// connect({ host: '127.0.0.1', port, database, user, password, serverPublicKey? }) -> { query(sql), close() }
export async function mysqlConnect({ host, port, database, user, password, serverPublicKey = null, connectTimeoutMs = MYSQL_LIMITS.connectTimeoutMs, connector = tcpConnect }) {
  if (host !== '127.0.0.1') throw new MysqlError('host-must-be-literal-loopback');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new MysqlError('invalid-port');
  if (typeof user !== 'string' || !user || typeof database !== 'string' || !database || typeof password !== 'string') throw new MysqlError('invalid-credential');
  if (!password) throw new MysqlError('empty-password-refused');
  let pinned = null;
  if (serverPublicKey !== null && serverPublicKey !== undefined) {
    try { pinned = createPublicKey(serverPublicKey); } catch { throw new MysqlError('invalid-server-key'); }
    if (pinned.asymmetricKeyType !== 'rsa') throw new MysqlError('invalid-server-key');
  }
  const socket = connector({ host, port });
  socket.setNoDelay?.(true);
  const read = packetReader(socket);
  let seq = 0;
  const send = payload => { const header = Buffer.alloc(4); header.writeUIntLE(payload.length, 0, 3); header[3] = seq++ & 0xff; socket.write(Buffer.concat([header, payload])); };
  const timer = setTimeout(() => socket.destroy(), connectTimeoutMs);
  try {
    await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', () => reject(new MysqlError('connect-failed'))); socket.once('close', () => reject(new MysqlError('connect-failed'))); });
    const greeting = await read();
    if (greeting[0] === 0xff) throw new MysqlError('startup-failed', sqlStateOf(greeting));
    if (greeting[0] !== 10) throw new MysqlError('unsupported-protocol');
    let at = greeting.indexOf(0, 1) + 1; // server version
    at += 4; // connection id
    const nonce1 = greeting.subarray(at, at + 8); at += 9; // auth data part 1, filler
    const capsLow = greeting.readUInt16LE(at); at += 2;
    at += 3; // charset, status
    const caps = capsLow | (greeting.readUInt16LE(at) << 16); at += 2;
    const authLength = greeting[at]; at += 11; // auth data length, reserved
    // DEPRECATE_EOF is required: without it an EOF after the column definitions would read as an empty result.
    if (!(caps & CAP.PROTOCOL_41) || !(caps & CAP.SECURE_CONNECTION) || !(caps & CAP.PLUGIN_AUTH) || !(caps & CAP.DEPRECATE_EOF)) throw new MysqlError('unsupported-protocol');
    const part2 = Math.max(13, authLength - 8);
    const nonce = Buffer.concat([nonce1, greeting.subarray(at, at + part2 - 1)]); at += part2; // the last byte is a NUL
    let plugin = greeting.toString('latin1', at, greeting.indexOf(0, at) < 0 ? greeting.length : greeting.indexOf(0, at));
    seq = 1;
    const scramble = (name, salt) => name === 'caching_sha2_password' ? cachingSha2Scramble(password, salt) : name === 'mysql_native_password' ? nativeScramble(password, salt) : null;
    let response = scramble(plugin, nonce);
    if (!response) throw new MysqlError(plugin === 'mysql_clear_password' ? 'cleartext-password-refused' : 'unsupported-authentication');
    send(Buffer.concat([(() => { const b = Buffer.alloc(32); b.writeUInt32LE(CLIENT_CAPS >>> 0, 0); b.writeUInt32LE(MYSQL_LIMITS.packetBytes, 4); b[8] = 255; return b; })(),
      Buffer.from(`${user}\0`, 'utf8'), lenenc(response.length), response, Buffer.from(`${database}\0`, 'utf8'), Buffer.from(`${plugin}\0`, 'latin1')]));
    let salt = nonce;
    for (;;) {
      const p = await read(); seq = (seq + 1) & 0xff;
      if (p[0] === 0x00) break; // OK: authenticated
      if (p[0] === 0xff) throw new MysqlError('authentication-failed', sqlStateOf(p));
      if (p[0] === 0xfe) { // AuthSwitchRequest: plugin name, then a new salt
        const end = p.indexOf(0, 1); plugin = p.toString('latin1', 1, end); salt = p.subarray(end + 1, p.length - (p[p.length - 1] === 0 ? 1 : 0));
        response = scramble(plugin, salt);
        if (!response) throw new MysqlError(plugin === 'mysql_clear_password' ? 'cleartext-password-refused' : 'unsupported-authentication');
        send(response); continue;
      }
      if (p[0] === 0x01 && plugin === 'caching_sha2_password') { // AuthMoreData
        if (p[1] === 0x03 && p.length === 2) continue; // fast path accepted; OK follows
        if (!(p[1] === 0x04 && p.length === 2)) throw new MysqlError('protocol-error'); // never a key the server offers
        // Full authentication: the password goes only to the pinned key.
        if (pinned === null) throw new MysqlError('server-key-not-pinned');
        send(publicEncrypt({ key: pinned, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, xor(Buffer.from(`${password}\0`, 'utf8'), salt)));
        continue;
      }
      throw new MysqlError('unexpected-message');
    }
    password = null; response.fill(0); // never kept past the handshake
  } catch (error) { socket.destroy(); throw error instanceof MysqlError ? error : new MysqlError('startup-failed'); }
  finally { clearTimeout(timer); }

  let busy = false;
  return {
    // One statement; returns { rows: [[text|null, ...]], columns } or { rows: [], columns: 0 } for a statement without results.
    async query(sql, { queryTimeoutMs = MYSQL_LIMITS.queryTimeoutMs, maxRows = MYSQL_LIMITS.rows } = {}) {
      if (busy) throw new MysqlError('query-in-progress');
      if (typeof sql !== 'string' || sql.includes(';')) throw new MysqlError('one-statement-only');
      busy = true;
      const timeout = setTimeout(() => socket.destroy(), queryTimeoutMs);
      try {
        seq = 0; send(Buffer.concat([Buffer.from([0x03]), Buffer.from(sql, 'utf8')]));
        const head = await read();
        if (head[0] === 0xff) throw new MysqlError('query-failed', sqlStateOf(head));
        if (head[0] === 0x00) return { rows: [], columns: 0 };
        const [columns] = readLenenc(head, 0);
        if (!Number.isInteger(columns) || columns < 1 || columns > 4096) throw new MysqlError('protocol-error');
        for (let i = 0; i < columns; i++) await read(); // column definitions (names are the query's own)
        const rows = []; let error = null;
        for (;;) {
          const p = await read();
          if (p[0] === 0xfe && p.length < 0xffffff && p.length < 16) break; // OK packet ending the result set (DEPRECATE_EOF)
          if (p[0] === 0xff) { error ??= new MysqlError('query-failed', sqlStateOf(p)); break; }
          if (rows.length >= maxRows) { error ??= new MysqlError('row-limit'); continue; }
          const row = []; let at = 0;
          for (let i = 0; i < columns; i++) {
            const [len, next] = readLenenc(p, at);
            if (len === null) { row.push(null); at = next; }
            else { if (next + len > p.length) throw new MysqlError('protocol-error'); row.push(p.toString('utf8', next, next + len)); at = next + len; }
          }
          if (at !== p.length) throw new MysqlError('protocol-error');
          rows.push(row);
        }
        if (error) throw error;
        return { rows, columns };
      } catch (error) { if (!(error instanceof MysqlError)) { socket.destroy(); throw new MysqlError('protocol-error'); } throw error; }
      finally { clearTimeout(timeout); busy = false; }
    },
    close() { try { seq = 0; send(Buffer.from([0x01])); } catch {} socket.destroy(); },
  };
}

// Exported for the fixture server only.
export const MYSQL_PROTOCOL = Object.freeze({ CAP, CLIENT_CAPS, lenenc, readLenenc });
export const mysqlRandomNonce = () => { const b = randomBytes(20); for (let i = 0; i < b.length; i++) if (b[i] === 0) b[i] = 1; return b; };
