// Owned synthetic agent desk for websocket-step tests (L8 fix 4): a chat route whose JSON reply names an invocation, and
// a websocket at a path built from it, as some agents run. Listens on 127.0.0.1 at an OS-assigned port
// and makes no outbound connection. A minimal RFC 6455 server: handshake, text frames, ping and close.
//   POST /api/chat                          200 { websocketUUID } for the token, else 401
//   GET  /whoami                            200 for the token, else 401
//   GET  /api/agent-invocation/<id> (upgrade) 101 for the token and a known id; 403 for another credential, 404 for another id
// After the client's first message the desk sends `messages` text frames, then closes (1000). mode changes that on purpose:
// 'big' sends one message over 1 MiB, 'split' one over 1 MiB in two frames, 'flood' nine messages of 1,000,000 bytes (over the
// 8 MiB step bound), 'masked' a masked frame, 'silent' nothing, 'ping' a ping first, 'drop' ends the
// connection without a close frame, 'deflate' answers the handshake with an extension the client never offered.
import { createServer } from 'node:http';
import { createHash, randomUUID } from 'node:crypto';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const frame = (opcode, payload, masked = false, fin = true) => {
  const body = Buffer.from(payload), length = body.length, first = (fin ? 0x80 : 0) | opcode;
  let head;
  if (length < 126) head = Buffer.from([first, (masked ? 0x80 : 0) | length]);
  else if (length < 65536) head = Buffer.from([first, (masked ? 0x80 : 0) | 126, length >> 8, length & 255]);
  else { head = Buffer.alloc(10); head[0] = first; head[1] = (masked ? 0x80 : 0) | 127; head.writeBigUInt64BE(BigInt(length), 2); }
  return Buffer.concat([head, masked ? Buffer.alloc(4) : Buffer.alloc(0), body]);
};
// Client frames, unmasked: [{ opcode, payload }] and the bytes left over.
function frames(buffer) {
  const out = [];
  while (buffer.length >= 2) {
    let length = buffer[1] & 0x7f, offset = 2;
    if (length === 126) { if (buffer.length < 4) break; length = buffer.readUInt16BE(2); offset = 4; }
    else if (length === 127) { if (buffer.length < 10) break; length = Number(buffer.readBigUInt64BE(2)); offset = 10; }
    const masked = buffer[1] & 0x80, mask = masked ? buffer.subarray(offset, offset + 4) : null;
    if (masked) offset += 4;
    if (buffer.length < offset + length) break;
    const payload = Buffer.from(buffer.subarray(offset, offset + length));
    if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
    out.push({ opcode: buffer[0] & 0x0f, masked: Boolean(masked), payload });
    buffer = buffer.subarray(offset + length);
  }
  return { out, rest: buffer };
}

export async function startWsDesk({ token = 'desk-token', cookie = null, csrf = null, messages = 3, mode = 'normal' } = {}) {
  const invocations = new Set(), handshakes = [], received = [];
  const authorized = headers => {
    const cookies = Object.fromEntries(String(headers.cookie ?? '').split(';').map(c => c.trim().split('=')).filter(p => p.length === 2));
    const signedIn = cookie ? cookies[cookie] === token : headers.authorization === `Bearer ${token}`;
    return signedIn && (!csrf || (headers[csrf.header.toLowerCase()] === csrf.value && cookies[csrf.cookie] === csrf.value));
  };
  const server = createServer((req, res) => {
    const json = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
    req.resume();
    req.on('end', () => {
      if (!authorized(req.headers)) return json(401, { error: 'unauthorized' });
      if (req.method === 'GET' && req.url === '/whoami') return json(200, { ok: true });
      if (req.method === 'POST' && req.url === '/api/chat') { const id = randomUUID(); invocations.add(id); return json(200, { websocketUUID: id, nested: { odd: '../x', dots: '..' } }); }
      json(404, { error: 'not found' });
    });
  });
  server.on('upgrade', (req, socket) => {
    handshakes.push({ url: req.url, headers: { ...req.headers } });
    const id = /^\/api\/agent-invocation\/([^/?]+)$/.exec(req.url)?.[1];
    if (!authorized(req.headers)) { socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'); return; }
    if (!id || !invocations.has(id)) { socket.end('HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n'); return; }
    const accept = createHash('sha1').update(req.headers['sec-websocket-key'] + GUID).digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n${mode === 'deflate' ? 'Sec-WebSocket-Extensions: permessage-deflate\r\n' : ''}\r\n`);
    let buffer = Buffer.alloc(0), started = false;
    socket.on('error', () => {});
    socket.on('data', chunk => {
      const parsed = frames(Buffer.concat([buffer, chunk]));
      buffer = parsed.rest;
      for (const f of parsed.out) {
        received.push({ opcode: f.opcode, masked: f.masked, text: f.opcode === 0x1 ? f.payload.toString('utf8') : null });
        if (f.opcode === 0x8) { socket.end(); return; }
        if (f.opcode !== 0x1 || started) continue;
        started = true;
        if (mode === 'silent') continue;
        if (mode === 'drop') { socket.write(frame(0x1, '{"step":1}')); socket.destroy(); return; }
        if (mode === 'big') { socket.write(frame(0x1, Buffer.alloc(1024 * 1024 + 1, 0x61))); continue; }
        if (mode === 'split') { socket.write(frame(0x1, Buffer.alloc(600000, 0x61), false, false)); socket.write(frame(0x0, Buffer.alloc(600000, 0x61))); continue; }
        if (mode === 'flood') { for (let i = 0; i < 9; i++) socket.write(frame(0x1, Buffer.alloc(1000000, 0x61))); continue; }
        if (mode === 'masked') { socket.write(frame(0x1, '{"step":1}', true)); continue; }
        if (mode === 'ping') socket.write(frame(0x9, 'are you there'));
        for (let i = 1; i <= messages; i++) socket.write(frame(0x1, JSON.stringify({ step: i, invocation: id })));
        socket.write(frame(0x8, Buffer.from([0x03, 0xe8])));
      }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return { origin, invocations, handshakes, received, stop: () => new Promise(resolve => { server.closeAllConnections(); server.close(() => resolve()); }) };
}
