// A scripted MySQL server for tests only (loopback, port 0). It speaks the
// server side of HandshakeV10 and COM_QUERY with text results, and verifies
// the client's credentials for each auth mode:
//   'caching-fast'  caching_sha2_password, fast path (0x01 0x03)
//   'caching-full'  caching_sha2_password, full authentication with an RSA key pair (MYSQL_SERVER_KEY is its public half)
//   'offer-key'     full authentication, but pushes its own public key instead of asking (a port squatter)
//   'native'        mysql_native_password
//   'switch-native' starts as caching_sha2_password, switches to mysql_native_password
//   'clear'         switches to mysql_clear_password (the client must refuse)
//   'no-deprecate-eof' a greeting without CLIENT_DEPRECATE_EOF (the client must refuse)
// onQuery(sql) -> { rows, columns } | { ok: true } | { error: sqlstate } | { stall: true }.
import { createServer } from 'node:net';
import { generateKeyPairSync, privateDecrypt, constants, timingSafeEqual } from 'node:crypto';
import { MYSQL_PROTOCOL, cachingSha2Scramble, nativeScramble, mysqlRandomNonce } from '../mysql-wire.mjs';

export const MYSQL_USER = 'reader', MYSQL_PASSWORD = 'synthetic-mysql-password';
const { CAP, lenenc } = MYSQL_PROTOCOL;
const SERVER_CAPS = CAP.LONG_PASSWORD | CAP.CONNECT_WITH_DB | CAP.PROTOCOL_41 | CAP.TRANSACTIONS | CAP.SECURE_CONNECTION | CAP.PLUGIN_AUTH | CAP.PLUGIN_AUTH_LENENC | CAP.DEPRECATE_EOF;
let keys = null;
const rsa = () => (keys ??= generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } }));
const same = (a, b) => a.length === b.length && timingSafeEqual(a, b);
export const MYSQL_SERVER_KEY = () => rsa().publicKey;

// received: every packet the client sent after the handshake response, before authentication finished.
export async function fakeMysql(t, { onQuery, auth = 'caching-fast', password = MYSQL_PASSWORD, received = [] }) {
  const sockets = new Set();
  const server = createServer(socket => {
    sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.on('error', () => {});
    let buffered = Buffer.alloc(0), state = 'handshake', seq = 0, nonce = mysqlRandomNonce(), plugin = auth === 'native' ? 'mysql_native_password' : 'caching_sha2_password';
    const send = payload => { const h = Buffer.alloc(4); h.writeUIntLE(payload.length, 0, 3); h[3] = seq++ & 0xff; socket.write(Buffer.concat([h, payload])); };
    const ok = (header = 0x00) => send(Buffer.from([header, 0, 0, 0x02, 0x00, 0, 0]));
    const err = sqlState => send(Buffer.concat([Buffer.from([0xff, 0x15, 0x04, 0x23]), Buffer.from(sqlState, 'latin1'), Buffer.from('fake error', 'latin1')]));
    const caps = auth === 'no-deprecate-eof' ? SERVER_CAPS & ~CAP.DEPRECATE_EOF : SERVER_CAPS;
    const greeting = Buffer.concat([Buffer.from([10]), Buffer.from('8.4.0-fake\0', 'latin1'), Buffer.from([1, 0, 0, 0]), nonce.subarray(0, 8), Buffer.from([0]),
      Buffer.from([caps & 0xff, (caps >> 8) & 0xff, 255, 0x02, 0x00, (caps >> 16) & 0xff, (caps >> 24) & 0xff, 21]), Buffer.alloc(10), nonce.subarray(8), Buffer.from([0]), Buffer.from(`${plugin}\0`, 'latin1')]);
    send(greeting);
    const authenticated = () => { state = 'command'; ok(); };
    const onPacket = p => {
      if (state === 'handshake') {
        let at = 32; const userEnd = p.indexOf(0, at); const user = p.toString('utf8', at, userEnd); at = userEnd + 1;
        const len = p[at]; const response = p.subarray(at + 1, at + 1 + len);
        if (user !== MYSQL_USER) return err('28000');
        if (auth === 'clear') { state = 'switch'; nonce = mysqlRandomNonce(); return send(Buffer.concat([Buffer.from([0xfe]), Buffer.from('mysql_clear_password\0', 'latin1')])); }
        if (auth === 'switch-native') { state = 'switch'; plugin = 'mysql_native_password'; nonce = mysqlRandomNonce(); return send(Buffer.concat([Buffer.from([0xfe]), Buffer.from('mysql_native_password\0', 'latin1'), nonce, Buffer.from([0])])); }
        if (auth === 'native') return same(response, nativeScramble(password, nonce)) ? authenticated() : err('28000');
        if (!same(response, cachingSha2Scramble(password, nonce))) return err('28000');
        if (auth === 'caching-full') { state = 'full'; return send(Buffer.from([0x01, 0x04])); }
        if (auth === 'offer-key') { state = 'full'; return send(Buffer.concat([Buffer.from([0x01]), Buffer.from(rsa().publicKey, 'latin1')])); }
        send(Buffer.from([0x01, 0x03])); return authenticated();
      }
      if (state !== 'command') received.push(Buffer.from(p));
      if (state === 'switch') { if (auth === 'clear') return err('28000'); return same(p, nativeScramble(password, nonce)) ? authenticated() : err('28000'); }
      if (state === 'full') {
        if (p.length === 1 && p[0] === 0x02) return send(Buffer.concat([Buffer.from([0x01]), Buffer.from(rsa().publicKey, 'latin1')]));
        let plain; try { plain = privateDecrypt({ key: rsa().privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, p); } catch { return err('28000'); }
        const clear = Buffer.from(plain.map((b, i) => b ^ nonce[i % nonce.length]));
        return clear.toString('utf8') === `${password}\0` ? authenticated() : err('28000');
      }
      // Commands.
      seq = 1;
      if (p[0] === 0x01) { socket.end(); return; }
      if (p[0] !== 0x03) return err('08S01');
      const out = onQuery(p.toString('utf8', 1));
      if (out?.stall) return;
      if (out?.error) return err(out.error);
      if (out?.ok || !out?.rows) return ok();
      const columns = out.columns ?? (out.rows[0]?.length ?? 1);
      send(lenenc(columns));
      for (let i = 0; i < columns; i++) send(Buffer.concat([lenenc(3), Buffer.from('def'), lenenc(0), lenenc(0), lenenc(0), lenenc(1), Buffer.from('c'), lenenc(0), Buffer.from([0x0c, 255, 0, 0, 0, 0, 0, 0xfd, 0, 0, 0, 0, 0])]));
      for (const row of out.rows) send(Buffer.concat(row.map(v => v === null ? Buffer.from([0xfb]) : (b => Buffer.concat([lenenc(b.length), b]))(Buffer.from(String(v), 'utf8')))));
      ok(0xfe);
    };
    socket.on('data', chunk => {
      buffered = Buffer.concat([buffered, chunk]);
      while (buffered.length >= 4) {
        const length = buffered.readUIntLE(0, 3);
        if (buffered.length < 4 + length) break;
        seq = (buffered[3] + 1) & 0xff;
        const p = buffered.subarray(4, 4 + length); buffered = buffered.subarray(4 + length);
        onPacket(p);
      }
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { for (const s of sockets) s.destroy(); server.close(r); }));
  return { port: server.address().port };
}

// A scripted database: states[mark] = { now, readOnly?, tables: { name: rows | { error } }, meta: { name: { engine, type, created, options?, columns } }, ids? }.
// rows: [[key, change|null, hash]]. columns: [[name, extra, dataType, precision, default]]. Each mark's first statement
// (SET SESSION TRANSACTION ISOLATION LEVEL) begins the next state.
export const COLUMNS = [['id', '', 'varchar', null, null], ['updated_at', 'DEFAULT_GENERATED on update CURRENT_TIMESTAMP(6)', 'timestamp', '6', 'CURRENT_TIMESTAMP(6)'], ['v', '', 'text', null, null]];
export function scriptedMysql(t, states, log = [], { auth } = {}) {
  let mark = -1;
  const onQuery = sql => {
    log.push(sql);
    if (/^SET SESSION TRANSACTION ISOLATION LEVEL/.test(sql)) { mark++; return { ok: true }; }
    const st = states[Math.max(0, mark)];
    if (/^(SET|START TRANSACTION|COMMIT)/.test(sql)) return { ok: true };
    if (/NOW\(6\)/.test(sql)) return { rows: [[st.now, st.readOnly ?? '0']] };
    const table = /TABLE_NAME = '(\w+)'/.exec(sql)?.[1] ?? /FROM `\w+`\.`(\w+)`/.exec(sql)?.[1];
    const meta = st.meta?.[table] ?? { engine: 'InnoDB', type: 'BASE TABLE', created: '2026-10-01 00:00:00', columns: COLUMNS };
    if (/information_schema\.TABLES/.test(sql)) return meta === 'missing' ? { rows: [], columns: 4 } : { rows: [[meta.engine, meta.type, meta.created, meta.options ?? '']] };
    if (/information_schema\.COLUMNS/.test(sql)) return { rows: meta.columns };
    // ids: { name: [tableId, space] | [[tableId, space], ...] | { error } }, the INNODB_TABLES rows a reader with PROCESS sees.
    if (/information_schema\.INNODB_TABLES/.test(sql)) { const ids = st.ids?.[/NAME = '\w+\/([\w@]+)'/.exec(sql)?.[1]]; return ids?.error ? ids : { rows: !ids ? [] : Array.isArray(ids[0]) ? ids : [ids], columns: 2 }; }
    const rows = st.tables[table];
    if (rows && !Array.isArray(rows)) return rows;
    return { rows: rows ?? [], columns: 3 };
  };
  return fakeMysql(t, { onQuery, auth });
}
