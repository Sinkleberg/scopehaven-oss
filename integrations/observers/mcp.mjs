// MCP observer: records tools/call traffic between an MCP client and server
// and turns each call into an effect event. Two transports, one frame format:
//   stdio           - `node integrations/observers/mcp.mjs record --log F --actor A -- cmd args...`
//                     sits in the client's server command, tees newline-delimited
//                     JSON-RPC in both directions and appends frames to F.
//   Streamable HTTP - createMcpHttpProxy() forwards a loopback MCP endpoint and
//                     maps each request's Authorization value to a declared actor
//                     by digest; the credential itself is never kept.
// A result is paired with its call only inside the same connection (one stdio
// recorder process) or the same HTTP exchange, and only when it comes after the
// call: JSON-RPC ids are per session, so they are never matched across them.
// Anything the recorder could not read (an oversized line, an unparsable or
// oversized response, a frame over the limit) is written to the log as a gap,
// and a window containing a gap, or a call without a result, is partial.
// Frames keep the method, id, tool name, error flag and argument digest only.
import { createServer, request } from 'node:http';
import { spawn } from 'node:child_process';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { appendFileSync, readFileSync, existsSync, statSync } from 'node:fs';
import { digest } from '../../src/domain.mjs';
import { makeEffect, wallNs, loopbackRequestAllowed, credentialFrom, originForm } from './events.mjs';

export const MCP_LIMITS = Object.freeze({ lineBytes: 1024 * 1024, bodyBytes: 4 * 1024 * 1024, frames: 50000 });
const nowNs = () => String(wallNs());
const LOOPBACK = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})(\/[^#]*)?$/;

// Parse one JSON-RPC message (or batch) into frames for one connection.
export function framesOf(message, direction, { conn, actor = null, httpStatus } = {}) {
  const list = Array.isArray(message) ? message : [message];
  const frames = [];
  for (const m of list) {
    if (!m || typeof m !== 'object' || m.jsonrpc !== '2.0') continue;
    const id = m.id === undefined || m.id === null ? undefined : String(m.id).slice(0, 128);
    if (direction === 'c2s' && m.method === 'tools/call' && id !== undefined) {
      const tool = typeof m.params?.name === 'string' ? m.params.name.slice(0, 128) : null;
      if (tool) frames.push({ kind: 'call', conn, id, tool, actor, argsDigest: m.params.arguments === undefined ? null : digest(m.params.arguments) });
      else frames.push({ kind: 'gap', conn, reason: 'tools-call-without-name' });
    } else if (direction === 's2c' && id !== undefined && (Object.hasOwn(m, 'result') || Object.hasOwn(m, 'error'))) {
      frames.push({ kind: 'result', conn, id, isError: Object.hasOwn(m, 'error') || m.result?.isError === true, rpcErrorCode: Number.isInteger(m.error?.code) ? m.error.code : null, httpStatus: httpStatus ?? null });
    }
  }
  return frames;
}

export class FrameLog {
  constructor({ path = null, maxFrames = MCP_LIMITS.frames } = {}) { this.path = path; this.maxFrames = maxFrames; this.frames = []; this.seq = 0; this.overflow = false; }
  push(frame) {
    if (this.overflow) return;
    // The last slot records the overflow itself, so a file reader sees it too.
    const record = this.frames.length >= this.maxFrames - 1 ? { v: 1, seq: ++this.seq, t: nowNs(), kind: 'overflow' } : { v: 1, seq: ++this.seq, t: nowNs(), ...frame };
    if (record.kind === 'overflow') this.overflow = true;
    this.frames.push(record);
    if (this.path) appendFileSync(this.path, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  }
}
// Frames with their log position: the byte offset after the line for a file,
// the 1-based index for an in-memory log. Windows are position ranges, so
// marks never compare the recorder's clock with the evaluator's.
function readLog(path) {
  if (!existsSync(path)) return null;
  const frames = [], raw = readFileSync(path);
  let offset = 0;
  for (const line of raw.toString('utf8').split('\n')) {
    offset += Buffer.byteLength(line) + 1;
    if (!line) continue;
    try { frames.push({ ...JSON.parse(line), pos: offset }); } catch { frames.push({ kind: 'gap', reason: 'unreadable-log-line', pos: offset }); }
  }
  return frames;
}

// Observer over a FrameLog (in-process proxy) or a log file (stdio recorder).
// tools: the tool names it can vouch for in name-specific checks.
export function createMcpObserver({ instanceId = 'mcp-1', log, path, deniedRpcCodes = [], tools = null }) {
  const observer = { kind: path ? 'mcp-stdio-recorder' : 'mcp-http-proxy', instanceId };
  const frames = () => path ? readLog(path) : log.frames.map((f, i) => ({ ...f, pos: i + 1 }));
  return {
    kind: observer.kind, instanceId, source: 'mcp-jsonrpc',
    scope: Object.freeze({ operations: ['tool-call'], names: tools, actorAttribution: 'principal', evidence: 'presence-only' }),
    async start() {},
    async mark() { return { pos: path ? (existsSync(path) ? statSync(path).size : 0) : log.frames.length }; },
    async collect(from, to) {
      const all = frames();
      if (!all) return { events: [], coverage: 'failed', reason: 'log-missing' };
      // A log that shrank (truncated or rotated) no longer holds the window.
      const size = path ? statSync(path).size : log.frames.length;
      if (to.pos < from.pos || size < to.pos) return { events: [], coverage: 'failed', reason: 'log-truncated-or-rotated' };
      const upTo = all.filter(f => f.pos <= to.pos), inWindow = f => f.pos > from.pos && f.pos <= to.pos;
      const opened = upTo.some(f => f.kind === 'open' && f.pos <= from.pos);
      const closed = upTo.some(f => f.kind === 'close');
      const gap = upTo.some(f => (f.kind === 'gap' && (inWindow(f) || f.reason === 'unreadable-log-line')) || f.kind === 'overflow');
      const resultOf = call => {
        // The first result for this id on the same connection after the call,
        // and before any later call that reuses the id.
        const reuse = upTo.find(f => f.kind === 'call' && f.conn === call.conn && f.id === call.id && f.pos > call.pos);
        return upTo.find(f => f.kind === 'result' && f.conn === call.conn && f.id === call.id && f.pos > call.pos && (!reuse || f.pos < reuse.pos));
      };
      // Calls made in the window, and earlier calls whose result landed in it.
      const calls = upTo.filter(f => f.kind === 'call').map(call => ({ call, result: resultOf(call) }))
        .filter(({ call, result }) => inWindow(call) || (result && inWindow(result)));
      const events = calls.map(({ call, result }) => {
        const denied = result && (deniedRpcCodes.includes(result.rpcErrorCode) || [401, 403].includes(result.httpStatus));
        return makeEffect({ source: 'mcp-jsonrpc', observer, seq: call.pos, observedAt: new Date(Number(BigInt((result ?? call).t ?? '0') / 1000000n)).toISOString(), actor: call.actor ?? null,
          operation: 'tool-call', name: call.tool, outcome: !result ? 'started' : denied ? 'denied' : result.isError ? 'error' : 'committed', correlation: { rpcId: call.id, requestId: call.conn }, content: call.argsDigest ?? undefined });
      });
      // A result whose call was never recorded (dropped, oversized, before the log) is a lost call.
      const orphan = upTo.some(r => r.kind === 'result' && inWindow(r) && !upTo.some(c => c.kind === 'call' && c.conn === r.conn && c.id === r.id && c.pos < r.pos));
      const reason = !opened ? 'recorder-not-open-before-window' : closed ? 'recorder-closed' : gap ? 'recorder-gap-in-window' : orphan ? 'result-without-call' : null;
      return { events, coverage: reason ? 'partial' : 'complete', reason };
    },
    async stop() {},
  };
}

// Streamable HTTP proxy. actors: [{ actorId, credentialEnv }] - the
// Authorization header value of each request is matched by digest only.
export function createMcpHttpProxy({ upstream, port = 0, actors = [], env = process.env, log = new FrameLog() }) {
  const match = LOOPBACK.exec(upstream || '');
  if (!match || Number(match[1]) > 65535) throw new Error('MCP upstream must be literal loopback HTTP.');
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('MCP proxy port must be an integer from 0 to 65535; the listener always binds 127.0.0.1.');
  const upstreamUrl = new URL(upstream);
  // An Authorization value that names no declared actor is kept only as a digest keyed with a secret this proxy never
  // stores: an unkeyed hash of a credential is confirmed by hashing guesses.
  const actorKey = randomBytes(32);
  const byDigest = new Map(actors.map(a => [a, credentialFrom(env, a.credentialEnv, `MCP actor "${a.actorId}"`)]).filter(([, value]) => value).map(([a, value]) => [digest(`Bearer ${value}`), a.actorId]));
  let server = null, listening = null;
  const handle = (req, res) => {
    if (!loopbackRequestAllowed(req, listening)) { req.resume(); res.writeHead(403).end(); return; }
    // Streamable HTTP uses POST (messages), GET (server stream) and DELETE (end session).
    if (!['POST', 'GET', 'DELETE'].includes(req.method)) { req.resume(); res.writeHead(405, { Allow: 'POST, GET, DELETE' }).end(); return; }
    // Origin-form targets only: an absolute or authority-form target could move the forward off the upstream.
    if (!originForm(req.url)) { req.resume(); res.writeHead(400).end(); return; }
    if (req.method !== 'POST' && (Number(req.headers['content-length'] || 0) > 0 || req.headers['transfer-encoding'] !== undefined)) { req.resume(); res.writeHead(400).end(); return; }
    if (req.method !== 'POST') log.push({ kind: 'meta', method: req.method });
    // One HTTP exchange is one pairing scope: its call and its result.
    const conn = `x-${randomUUID()}`;
    const chunks = []; let bytes = 0;
    req.on('data', chunk => { bytes += chunk.length; if (bytes <= MCP_LIMITS.bodyBytes) chunks.push(chunk); });
    req.on('end', () => {
      if (bytes > MCP_LIMITS.bodyBytes) { log.push({ kind: 'gap', conn, reason: 'request-too-large' }); res.writeHead(413).end(); return; }
      const body = Buffer.concat(chunks);
      const auth = req.headers.authorization;
      const actor = auth ? byDigest.get(digest(auth)) ?? `unlisted:${createHmac('sha256', actorKey).update(auth).digest('hex').slice(0, 16)}` : null;
      if (req.method === 'POST') { try { for (const f of framesOf(JSON.parse(body.toString('utf8')), 'c2s', { conn, actor })) log.push(f); } catch { log.push({ kind: 'gap', conn, reason: 'unparsable-request' }); } }
      const headers = { ...req.headers, host: upstreamUrl.host };
      const target = new URL(req.url, upstreamUrl);
      if (target.origin !== upstreamUrl.origin) { res.writeHead(400).end(); return; }
      const up = request(target, { method: req.method, headers, agent: false }, upRes => {
        res.writeHead(upRes.statusCode, upRes.headers);
        const type = String(upRes.headers['content-type'] || '');
        const parse = req.method === 'POST' && (type.includes('text/event-stream') || type.includes('application/json'));
        let buffer = '', seen = 0, overLimit = false, held = [];
        const parseFailed = () => log.push({ kind: 'gap', conn, reason: 'unparsable-response' });
        const json = parse && type.includes('application/json');
        upRes.on('data', chunk => {
          if (!parse || overLimit) { res.write(chunk); return; }
          if ((seen += chunk.length) > MCP_LIMITS.bodyBytes) {
            overLimit = true; buffer = ''; log.push({ kind: 'gap', conn, reason: 'response-too-large' });
            for (const h of held) res.write(h); held = []; res.write(chunk); return;
          }
          buffer += chunk.toString('utf8');
          // A JSON reply is held until it is parsed and recorded; the client gets it after.
          if (json) { held.push(chunk); return; }
          // SSE: record each complete event before forwarding the chunk that ends it.
          let cut;
          while ((cut = buffer.indexOf('\n\n')) >= 0) {
            const block = buffer.slice(0, cut); buffer = buffer.slice(cut + 2);
            const data = block.split('\n').filter(l => l.startsWith('data:')).map(l => l.slice(5).trimStart()).join('\n');
            if (data) { try { for (const f of framesOf(JSON.parse(data), 's2c', { conn, httpStatus: upRes.statusCode })) log.push(f); } catch { parseFailed(); } }
          }
          res.write(chunk);
        });
        upRes.on('end', () => {
          if (json && !overLimit && buffer) { try { for (const f of framesOf(JSON.parse(buffer), 's2c', { conn, httpStatus: upRes.statusCode })) log.push(f); } catch { parseFailed(); } }
          for (const h of held) res.write(h);
          res.end();
        });
      });
      up.on('error', () => { log.push({ kind: 'gap', conn, reason: 'upstream-error' }); if (!res.headersSent) res.writeHead(502); res.end(); });
      up.end(body);
    });
  };
  return {
    log,
    get url() { return listening ? `http://127.0.0.1:${listening}${upstreamUrl.pathname}` : null; },
    async start() { server = createServer(handle); await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); }); listening = server.address().port; log.push({ kind: 'open' }); },
    async stop() { log.push({ kind: 'close' }); if (server) await new Promise(resolve => server.close(resolve)); server = null; },
  };
}

// stdio recorder CLI. The MCP client launches this instead of the server.
function lineTee(input, output, direction, log, conn, actor) {
  let pending = '', dropping = false;
  // Record complete lines before forwarding the chunk, so the other side can
  // never act on a message (or a reply) that is not yet in the log.
  input.on('data', chunk => {
    let text = chunk.toString('utf8');
    while (text.length) {
      const cut = text.indexOf('\n');
      const piece = cut < 0 ? text : text.slice(0, cut);
      text = cut < 0 ? '' : text.slice(cut + 1);
      if (!dropping) pending += piece;
      if (!dropping && pending.length > MCP_LIMITS.lineBytes) { dropping = true; pending = ''; log.push({ kind: 'gap', conn, reason: `${direction}-line-too-large` }); }
      if (cut < 0) break;
      const line = pending.trim(); pending = ''; dropping = false;
      if (line) { try { for (const f of framesOf(JSON.parse(line), direction, { conn, actor })) log.push(f); } catch { log.push({ kind: 'gap', conn, reason: `${direction}-unparsable-line` }); } }
    }
    output.write(chunk);
  });
}
export function recordStdio({ logPath, actor = null, command, args = [] }) {
  const log = new FrameLog({ path: logPath }), conn = `stdio-${randomUUID()}`;
  log.push({ kind: 'open', conn, actor });
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'inherit'], shell: false });
  lineTee(process.stdin, child.stdin, 'c2s', log, conn, actor);
  lineTee(child.stdout, process.stdout, 's2c', log, conn, actor);
  process.stdin.on('end', () => child.stdin.end());
  // If the client goes away, do not leave the server running.
  for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.on(signal, () => { child.kill(signal); });
  child.on('exit', code => { log.push({ kind: 'close', conn, exitCode: code }); process.exit(code ?? 1); });
  return child;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href && process.argv[2] === 'record') {
  const argv = process.argv.slice(3), split = argv.indexOf('--');
  const opts = argv.slice(0, split < 0 ? argv.length : split), cmd = split < 0 ? [] : argv.slice(split + 1);
  const opt = name => { const i = opts.indexOf(name); return i >= 0 ? opts[i + 1] : undefined; };
  // The actor is required: an MCP stdio session carries no user identity of its own.
  if (!opt('--log') || !opt('--actor') || !/^[A-Za-z0-9_-]{1,80}$/.test(opt('--actor')) || !cmd.length) { process.stderr.write('Usage: mcp.mjs record --log <file> --actor <actorId> -- <server command> [args...]\n'); process.exit(2); }
  recordStdio({ logPath: opt('--log'), actor: opt('--actor'), command: cmd[0], args: cmd.slice(1) });
}
