// Model tap: a loopback forwarding proxy between an application and its model
// server. It records which model each call asked for and which model the
// server says answered it, so a run's model identity comes from traffic the
// tap saw, not from the application's configuration or its own report.
//
// Per call it keeps: the API shape, the requested model, the served model(s)
// and system_fingerprint(s) read from the response, the HTTP status, and the
// sha256 and size of the request and response bodies. Prompt and response
// content are never written. For a local Ollama upstream it also lists the
// server's models (name -> weights digest) at start, at every mark and at stop.
// A model replaced under the same name between two lists is visible; one
// swapped and restored between two lists is not.
//
// Anything the tap cannot vouch for is written as a gap: an unrecognised route,
// a model-management call (pull, create, copy, delete, push, blobs), a redirect,
// an unparsable, unreadable or encoded response, an oversized body, an upstream
// error or an aborted stream. The tap never changes a forwarded body. It sets
// Accept-Encoding: identity on the forwarded request so it can read the response.
//
// The log is append-only JSON lines. Each line carries its sequence number and a
// hash chained to the previous line (h), so a removed, reordered, duplicated or
// edited line is visible to a reader that recomputes the chain. Anyone who can
// rewrite the whole file can rewrite the chain: anchor the head (identity.head)
// in signed evidence (integrations/attest, the W1 ledger) to fix it in time.
import { createServer, request } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { randomUUID, createHash } from 'node:crypto';
import { openSync, writeSync, closeSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { loopbackRequestAllowed, originForm, wallNs } from '../observers/events.mjs';

export const TAP_SCHEMA = 'scopehaven-model-tap/2';
export const TAP_LIMITS = Object.freeze({ requestBytes: 64 * 1024 * 1024, parseBytes: 16 * 1024 * 1024, lineBytes: 4 * 1024 * 1024, valuesPerCall: 8, frames: 200000, nameChars: 200, tagsBytes: 4 * 1024 * 1024, tagsTimeoutMs: 5000 });
export const CHAIN_START = '0'.repeat(64);

// Generation routes the tap understands. streamDefault: how to read a request
// that omits "stream" (Ollama streams unless told not to).
export const ROUTES = Object.freeze({
  '/v1/chat/completions': { api: 'openai-chat', streamDefault: false },
  '/v1/completions': { api: 'openai-completions', streamDefault: false },
  '/v1/responses': { api: 'openai-responses', streamDefault: false },
  '/v1/embeddings': { api: 'openai-embeddings', streamDefault: false },
  '/v1/messages': { api: 'anthropic-messages', streamDefault: false },
  '/api/chat': { api: 'ollama-chat', streamDefault: true },
  '/api/generate': { api: 'ollama-generate', streamDefault: true },
  '/api/embed': { api: 'ollama-embed', streamDefault: false },
  '/api/embeddings': { api: 'ollama-embeddings', streamDefault: false },
});
// Read-only metadata routes: forwarded and logged as meta, never identity.
export const META_ROUTES = Object.freeze(['GET /', 'HEAD /', 'GET /v1/models', 'GET /api/tags', 'POST /api/show', 'GET /api/version', 'GET /api/ps']);
// Routes that change which weights a name points to.
export const ADMIN_ROUTES = Object.freeze(['/api/pull', '/api/create', '/api/copy', '/api/delete', '/api/push', '/api/blobs']);

const LOOPBACK_ORIGIN = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/;
// Hosted vendor origins the tap may forward to, exactly as written (https, default port, no
// path). The operator's application already sends its prompts there with its own key; the tap
// passes the key through and stores none of it. The vendor's model string and fingerprint are the
// vendor's readings: a hosted upstream never yields a weights digest.
export const HOSTED_ORIGINS = Object.freeze(['https://api.openai.com', 'https://api.anthropic.com']);
// 'loopback', 'hosted', or null for anything the tap must not forward to.
export function upstreamKind(upstream) {
  if (typeof upstream !== 'string') return null;
  const match = LOOPBACK_ORIGIN.exec(upstream);
  const kind = match ? (Number(match[1]) <= 65535 ? 'loopback' : null) : HOSTED_ORIGINS.includes(upstream) ? 'hosted' : null;
  // The declared string must already be its own origin, so the log records exactly what was
  // declared (http://127.0.0.1:80 would be logged as http://127.0.0.1, so it is refused).
  return kind && new URL(upstream).origin === upstream ? kind : null;
}
const DIGEST = /^[0-9a-f]{64}$/;
const sha256 = buf => createHash('sha256').update(buf).digest('hex');
const nowNs = () => String(wallNs());
const name = v => typeof v === 'string' && v.length > 0 && v.length <= TAP_LIMITS.nameChars ? v : null;

// Ollama treats "llama3" as "llama3:latest".
export const ollamaName = n => typeof n === 'string' && n.length ? (n.includes(':') ? n : `${n}:latest`) : null;
// The chained hash of one line: the previous hash and the line without its own hash.
export const chainHash = (previous, record) => sha256(`${previous}\n${JSON.stringify(record)}`);

// One append-only JSON-lines log. The file must not exist yet: one log per tap
// session, so two runs never share (or reuse) a log by accident. A write that
// fails (a full disk, a closed file) stops all later disk writes, so the file
// never holds a later line after a missing one; the failure is kept in memory
// and the file ends early, which a reader sees as an unclosed log.
export class TapLog {
  constructor({ path = null, maxFrames = TAP_LIMITS.frames } = {}) {
    if (path !== null && (typeof path !== 'string' || !isAbsolute(path))) throw new Error('The tap log path must be absolute.');
    this.path = path; this.maxFrames = maxFrames; this.frames = []; this.seq = 0; this.overflow = false; this.head = CHAIN_START; this.writeError = null;
    this.session = randomUUID();
    this.fd = path ? openSync(path, 'wx', 0o600) : null;
  }
  push(frame) {
    if (this.overflow) return null;
    const body = this.frames.length >= this.maxFrames - 1 ? { v: 1, seq: this.seq + 1, t: nowNs(), kind: 'overflow' } : { v: 1, seq: this.seq + 1, t: nowNs(), ...frame };
    const record = { ...body, h: chainHash(this.head, body) };
    this.seq = record.seq; this.head = record.h;
    if (record.kind === 'overflow') this.overflow = true;
    this.frames.push(record);
    if (this.fd !== null && !this.writeError) {
      const line = Buffer.from(`${JSON.stringify(record)}\n`);
      let failure = null;
      try { if (writeSync(this.fd, line) !== line.length) failure = 'short-write'; } catch (error) { failure = error?.code ?? 'write-failed'; }
      if (failure) { this.writeError = failure; this.frames.push({ v: 1, seq: null, kind: 'gap', reason: 'log-write-failed', code: failure }); }
    }
    return record;
  }
  close() { if (this.fd !== null) { try { closeSync(this.fd); } catch {} this.fd = null; } }
}

// Served model and fingerprint fields of one parsed response object, by API. A
// model field that is present but not a readable name is counted as invalid.
export function servedFields(api, obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return { served: [], fingerprints: [], invalid: 0 };
  const served = [], fingerprints = [];
  let invalid = 0;
  const add = (list, v) => { if (v === undefined || v === null) return; const n = name(v); if (n) list.push(n); else invalid++; };
  if (api === 'anthropic-messages') { add(served, obj.model); if (obj.type === 'message_start') add(served, obj.message?.model); }
  else if (api === 'openai-responses') { add(served, obj.model); add(served, obj.response?.model); }
  else { add(served, obj.model); add(fingerprints, obj.system_fingerprint); }
  return { served, fingerprints, invalid };
}

// Token counts a reply reports about itself (numbers only, never content): what the call cost.
// OpenAI chat and completions: usage.prompt_tokens / completion_tokens (a stream's final chunk);
// OpenAI Responses: usage or response.usage input_tokens / output_tokens (response.completed);
// Anthropic: usage, message_start.message.usage and message_delta.usage input_tokens / output_tokens;
// Ollama: prompt_eval_count / eval_count. Streams report cumulative counts, so the largest is kept.
const COUNT = v => Number.isInteger(v) && v >= 0 && v <= 1e9 ? v : null;
export function usageFields(api, obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
  let input = null, output = null;
  const take = (i, o) => { if (COUNT(i) !== null) input = Math.max(input ?? 0, i); if (COUNT(o) !== null) output = Math.max(output ?? 0, o); };
  if (api.startsWith('ollama-')) take(obj.prompt_eval_count, obj.eval_count);
  // Anthropic bills prompt-cache reads and writes as input too, reported beside input_tokens.
  else if (api === 'anthropic-messages') for (const u of [obj.usage, obj.message?.usage]) take(COUNT(u?.input_tokens) === null ? null : u.input_tokens + (COUNT(u.cache_creation_input_tokens) ?? 0) + (COUNT(u.cache_read_input_tokens) ?? 0), u?.output_tokens);
  else if (api === 'openai-responses') for (const u of [obj.usage, obj.response?.usage]) take(u?.input_tokens, u?.output_tokens);
  else take(obj.usage?.prompt_tokens, obj.usage?.completion_tokens);
  return input === null && output === null ? null : { input, output };
}

// Incremental reader for one response body. SSE events (blank-line separated,
// "data:" lines) or NDJSON lines are parsed as they complete; a JSON body is
// parsed at the end. Bytes are decoded as one UTF-8 stream, so a character split
// across chunks is read whole. Returns the distinct served models and fingerprints.
export function createResponseReader(api, contentType) {
  const type = String(contentType || '').toLowerCase();
  const mode = type.includes('text/event-stream') ? 'sse' : type.includes('ndjson') || (api.startsWith('ollama-') && !type.includes('application/json') && type !== '') ? 'ndjson' : type.includes('json') ? 'json' : 'other';
  const served = new Set(), fingerprints = new Set();
  const decoder = new StringDecoder('utf8');
  let buffer = '', bytes = 0, unparsable = 0, parsed = 0, invalid = 0, overLimit = false, started = false;
  let usage = null;
  const take = obj => {
    parsed++;
    const u = usageFields(api, obj);
    // A side the reply never reported stays null (priced at the worst case downstream), never 0.
    if (u) usage = { input: u.input === null ? usage?.input ?? null : Math.max(usage?.input ?? 0, u.input), output: u.output === null ? usage?.output ?? null : Math.max(usage?.output ?? 0, u.output) };
    const f = servedFields(api, obj);
    invalid += f.invalid;
    for (const s of f.served) if (served.size < TAP_LIMITS.valuesPerCall || served.has(s)) served.add(s); else overLimit = true;
    for (const p of f.fingerprints) if (fingerprints.size < TAP_LIMITS.valuesPerCall || fingerprints.has(p)) fingerprints.add(p); else overLimit = true;
  };
  const parseText = text => { try { take(JSON.parse(text)); } catch { unparsable++; } };
  const dataOf = block => block.split(/\r\n|\r|\n/).filter(l => l.startsWith('data:')).map(l => l.slice(5).replace(/^ /, '')).join('\n');
  const drain = final => {
    if (mode === 'sse') {
      let cut;
      while ((cut = buffer.search(/(\r\n|\r|\n)(\r\n|\r|\n)/)) >= 0) {
        const block = buffer.slice(0, cut); buffer = buffer.slice(cut).replace(/^(\r\n|\r|\n)(\r\n|\r|\n)/, '');
        const data = dataOf(block);
        if (data && data !== '[DONE]') parseText(data);
      }
      if (final && buffer.trim()) { const data = dataOf(buffer); buffer = ''; if (data && data !== '[DONE]') parseText(data); }
    } else if (mode === 'ndjson') {
      let cut;
      while ((cut = buffer.indexOf('\n')) >= 0) { const line = buffer.slice(0, cut).trim(); buffer = buffer.slice(cut + 1); if (line) parseText(line); }
      if (final && buffer.trim()) { parseText(buffer.trim()); buffer = ''; }
    } else if (mode === 'json' && final) { if (buffer.trim()) parseText(buffer); buffer = ''; }
    if (buffer.length > TAP_LIMITS.lineBytes && mode !== 'json') { overLimit = true; buffer = ''; }
  };
  const append = text => { if (!started && text.length) { started = true; if (text.charCodeAt(0) === 0xfeff) text = text.slice(1); } buffer += text; };
  return {
    mode,
    push(chunk) {
      bytes += chunk.length;
      if (mode === 'other' || overLimit) return;
      if (mode === 'json' && bytes > TAP_LIMITS.parseBytes) { overLimit = true; buffer = ''; return; }
      append(decoder.write(chunk)); drain(false);
    },
    end() {
      if (mode !== 'other' && !overLimit) { append(decoder.end()); drain(true); }
      return { served: [...served], fingerprints: [...fingerprints], usage, parsed, unparsable, invalid, overLimit, mode, bytes };
    },
  };
}

// GET /api/tags on the upstream: { available, models: [{ name, digest }] }.
// The deadline covers the whole exchange, so a reply that trickles is cut off.
export function fetchOllamaTags(upstreamUrl, timeoutMs = TAP_LIMITS.tagsTimeoutMs) {
  return new Promise(resolve => {
    let settled = false;
    const done = value => { if (settled) return; settled = true; clearTimeout(deadline); resolve(value); };
    const req = request(new URL('/api/tags', upstreamUrl), { method: 'GET', agent: false, headers: { accept: 'application/json', 'accept-encoding': 'identity' } }, res => {
      const chunks = []; let size = 0;
      res.on('data', c => { size += c.length; if (size <= TAP_LIMITS.tagsBytes) chunks.push(c); });
      res.on('end', () => {
        if (res.statusCode !== 200 || size > TAP_LIMITS.tagsBytes) { done({ available: false, reason: `tags-status-${res.statusCode}` }); return; }
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (!Array.isArray(body?.models)) { done({ available: false, reason: 'tags-shape' }); return; }
          const models = [];
          for (const m of body.models) {
            // A digest that is not 64 lowercase hex characters names nothing; the model is left out of the list.
            const n = name(m?.name) ?? name(m?.model), d = typeof m?.digest === 'string' && DIGEST.test(m.digest) ? m.digest : null;
            if (n && d) models.push({ name: ollamaName(n), digest: d });
          }
          done({ available: true, models });
        } catch { done({ available: false, reason: 'tags-unparsable' }); }
      });
      res.on('error', () => done({ available: false, reason: 'tags-error' }));
    });
    const deadline = setTimeout(() => { req.destroy(); done({ available: false, reason: 'tags-timeout' }); }, timeoutMs);
    req.on('error', () => done({ available: false, reason: 'tags-unreachable' }));
    req.end();
  });
}

const HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'proxy-authorization', 'proxy-authenticate']);
// Hop-by-hop names for one message: the fixed set plus any header its Connection header names.
const hopNames = raw => { const names = new Set(HOP); for (let i = 0; i < raw.length; i += 2) if (raw[i].toLowerCase() === 'connection') for (const n of String(raw[i + 1]).split(',')) if (n.trim()) names.add(n.trim().toLowerCase()); return names; };
// Headers as a flat raw list, keeping duplicates and order, without hop-by-hop headers
// (Node sets this connection's own framing). keep: hop-by-hop names to pass anyway.
const forwardHeaders = (raw, keep = []) => { const hop = hopNames(raw), out = []; for (let i = 0; i < raw.length; i += 2) { const n = raw[i].toLowerCase(); if (!hop.has(n) || keep.includes(n)) out.push(raw[i], raw[i + 1]); } return out; };

// upstream: a literal loopback origin (for example http://127.0.0.1:11434) or one of HOSTED_ORIGINS.
// ollamaTags: list a loopback upstream's models at start, marks and stop (default true for
//   loopback; a hosted vendor has no model list, so it is never asked for one).
// testPinToLoopback: { port, ca }, for tests only: connect a hosted upstream to 127.0.0.1:port
//   instead, verifying the certificate for the vendor's host name against ca. It can only ever
//   reach loopback, so no test sends anything to a vendor.
export function createModelTap({ upstream, port = 0, log = new TapLog(), ollamaTags, tagsTimeoutMs = TAP_LIMITS.tagsTimeoutMs, testPinToLoopback } = {}) {
  const kind = upstreamKind(upstream);
  if (!kind) throw new Error(`The model upstream must be a literal loopback origin such as http://127.0.0.1:11434, or one of ${HOSTED_ORIGINS.join(', ')}, exactly as written (no path, no trailing slash).`);
  if (kind === 'hosted' && ollamaTags === true) throw new Error('A hosted vendor has no model list; ollamaTags applies to a loopback Ollama upstream only.');
  if (ollamaTags !== undefined && typeof ollamaTags !== 'boolean') throw new Error('ollamaTags must be true or false.');
  ollamaTags = kind === 'loopback' && ollamaTags !== false;
  if (testPinToLoopback !== undefined) {
    if (kind !== 'hosted') throw new Error('testPinToLoopback applies to a hosted upstream only.');
    const pin = testPinToLoopback;
    if (!pin || !Number.isInteger(pin.port) || pin.port < 1 || pin.port > 65535 || !(typeof pin.ca === 'string' || Buffer.isBuffer(pin.ca)) || !pin.ca.length) throw new Error('testPinToLoopback needs { port: 1-65535, ca: the test CA certificate }.');
  }
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('The tap port must be an integer from 0 to 65535; the listener always binds 127.0.0.1.');
  if (!Number.isInteger(tagsTimeoutMs) || tagsTimeoutMs < 1 || tagsTimeoutMs > 60000) throw new Error('tagsTimeoutMs must be an integer from 1 to 60000.');
  const upstreamUrl = new URL(upstream);
  let server = null, listening = null, inflight = 0;
  const sockets = new Set();

  const snapshot = async phase => {
    if (!ollamaTags) return log.push({ kind: 'models', phase, available: false, reason: 'not-requested' });
    const tags = await fetchOllamaTags(upstreamUrl, tagsTimeoutMs);
    return log.push({ kind: 'models', phase, ...tags });
  };

  const handle = (req, res) => {
    if (!loopbackRequestAllowed(req, listening)) { req.resume(); res.writeHead(403).end(); return; }
    if (!originForm(req.url)) { req.resume(); res.writeHead(400).end(); return; }
    const target = new URL(req.url, upstreamUrl);
    if (target.origin !== upstreamUrl.origin) { req.resume(); res.writeHead(400).end(); return; }
    const path = target.pathname;
    const route = req.method === 'POST' ? ROUTES[path] : undefined;
    const conn = `c-${randomUUID()}`;
    if (!route) {
      if (META_ROUTES.includes(`${req.method} ${path}`)) log.push({ kind: 'meta', conn, method: req.method, path });
      else if (ADMIN_ROUTES.some(p => path === p || path.startsWith(`${p}/`))) log.push({ kind: 'gap', conn, reason: 'model-admin-call', method: req.method, path: path.slice(0, 200) });
      else log.push({ kind: 'gap', conn, reason: 'unrecognized-route', method: req.method, path: path.slice(0, 200) });
    }
    const chunks = []; let bytes = 0, tooLarge = false;
    req.on('data', chunk => { bytes += chunk.length; if (bytes > TAP_LIMITS.requestBytes) tooLarge = true; else chunks.push(chunk); });
    req.on('end', () => {
      if (tooLarge) { log.push({ kind: 'gap', conn, reason: 'request-too-large' }); res.writeHead(413).end(); return; }
      const body = Buffer.concat(chunks);
      let api = null, stream = false;
      if (route) {
        api = route.api; stream = route.streamDefault;
        let requested = null, parsedRequest = false;
        if (body.length <= TAP_LIMITS.parseBytes) {
          try { const j = JSON.parse(body.toString('utf8')); if (j && typeof j === 'object' && !Array.isArray(j)) { parsedRequest = true; requested = name(j.model); if (typeof j.stream === 'boolean') stream = j.stream; } } catch {}
        }
        log.push({ kind: 'call', conn, api, requested, stream, reqSha256: sha256(body), reqBytes: body.length, ...(parsedRequest ? {} : { requestUnparsed: true }) });
      }
      // Request headers as sent, duplicates included, minus hop-by-hop ones; the tap sets
      // Host, Accept-Encoding and Content-Length itself.
      const headers = forwardHeaders(req.rawHeaders), own = [];
      for (let i = 0; i < headers.length; i += 2) if (!['host', 'accept-encoding', 'content-length'].includes(headers[i].toLowerCase())) own.push(headers[i], headers[i + 1]);
      own.push('Host', upstreamUrl.host, 'Accept-Encoding', 'identity');
      if (body.length || req.method === 'POST' || req.method === 'PUT') own.push('Content-Length', String(body.length));
      inflight++;
      // Body bytes the application has actually received: a call it abandoned before any
      // arrived (a cancelled parallel request) carried no model output into the run.
      let finished = false, delivered = 0;
      const deliver = chunk => { delivered += chunk.length; res.write(chunk); };
      const finish = frame => { if (finished) return; finished = true; inflight--; if (frame) log.push(frame); };
      // Hosted: TLS, certificate verified for the vendor's host name (never disabled).
      const send = kind === 'hosted' ? httpsRequest : request;
      // rejectUnauthorized is set explicitly, so no environment (NODE_TLS_REJECT_UNAUTHORIZED=0) can turn checking off.
      const connect = kind !== 'hosted' ? {} : { rejectUnauthorized: true, ...(testPinToLoopback ? { hostname: '127.0.0.1', port: testPinToLoopback.port, servername: upstreamUrl.hostname, ca: testPinToLoopback.ca } : {}) };
      const up = send(target, { method: req.method, headers: own, agent: false, ...connect }, upRes => {
        const encoding = String(upRes.headers['content-encoding'] || 'identity').toLowerCase();
        const reader = api && encoding === 'identity' ? createResponseReader(api, upRes.headers['content-type']) : null;
        const hash = createHash('sha256'); let respBytes = 0;
        res.writeHead(upRes.statusCode, forwardHeaders(upRes.rawHeaders, upRes.rawTrailers?.length || upRes.headers.trailer ? ['trailer'] : []));
        // A non-streaming JSON reply is held until it is recorded, so the application
        // can never act on an answer the log does not yet hold. A stream the request
        // asked for passes through as it arrives, whatever its content type; its
        // result frame can land after a window ends, which reads as a call without a
        // result (partial), never as a wrong identity.
        const hold = reader?.mode === 'json' && !stream ? [] : null;
        upRes.on('data', chunk => { respBytes += chunk.length; hash.update(chunk); if (reader) reader.push(chunk); if (hold && respBytes <= TAP_LIMITS.parseBytes) hold.push(chunk); else { if (hold?.length) { for (const h of hold.splice(0)) deliver(h); } deliver(chunk); } });
        upRes.on('end', () => {
          if (api) {
            const r = reader ? reader.end() : null;
            const gaps = [];
            if (upRes.statusCode >= 300 && upRes.statusCode <= 399) gaps.push('redirect');
            else if (!reader) gaps.push('encoded-response');
            else if (r.overLimit) gaps.push('response-too-large');
            else if (r.mode === 'other') gaps.push('unrecognized-response-type');
            else if (r.unparsable) gaps.push('unparsable-response');
            else if (r.invalid) gaps.push('served-model-unreadable');
            else if ((r.mode === 'sse' || r.mode === 'ndjson') && r.parsed === 0 && r.bytes > 0) gaps.push('no-events-parsed');
            finish({ kind: 'result', conn, status: upRes.statusCode, served: r?.served ?? [], fingerprints: r?.fingerprints ?? [], ...(r?.usage ? { usage: r.usage } : {}), respSha256: hash.digest('hex'), respBytes, ...(gaps.length ? { gap: gaps[0] } : {}) });
          } else finish(null);
          if (hold) for (const h of hold.splice(0)) deliver(h);
          const trailers = forwardHeaders(upRes.rawTrailers ?? []), pairs = [];
          for (let i = 0; i < trailers.length; i += 2) pairs.push([trailers[i], trailers[i + 1]]);
          if (pairs.length) res.addTrailers(pairs);
          res.end();
        });
        upRes.on('close', () => { if (!upRes.complete) { finish(api ? { kind: 'gap', conn, reason: 'response-aborted' } : null); res.destroy(); } });
      });
      up.on('information', info => {
        if (info.statusCode !== 103 || typeof res.writeEarlyHints !== 'function') return;
        const kept = forwardHeaders(info.rawHeaders ?? []), hints = {};
        for (let i = 0; i < kept.length; i += 2) hints[kept[i].toLowerCase()] = hints[kept[i].toLowerCase()] ? [].concat(hints[kept[i].toLowerCase()], kept[i + 1]) : kept[i + 1];
        try { res.writeEarlyHints(hints); } catch {}
      });
      // After the headers went out, an upstream failure must reach the application as an
      // aborted response, never as a clean (possibly empty) one.
      up.on('error', () => { finish({ kind: 'gap', conn, reason: 'upstream-error' }); if (!res.headersSent) { res.writeHead(502); res.end(); } else res.destroy(); });
      res.on('close', () => { if (!res.writableFinished) { finish(api ? { kind: 'gap', conn, reason: 'client-closed', delivered } : null); up.destroy(); } });
      up.end(body);
    });
  };

  return {
    log,
    get url() { return listening ? `http://127.0.0.1:${listening}` : null; },
    get inflight() { return inflight; },
    // The first model list is written before the listener accepts a call, so every
    // call in the log comes after a list it can be checked against.
    async start() {
      log.push({ kind: 'open', schema: TAP_SCHEMA, session: log.session, upstream: upstreamUrl.origin, ollamaTags });
      await snapshot('start');
      server = createServer(handle);
      server.on('connection', s => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
      listening = server.address().port;
    },
    // A window boundary: lists the models again and returns the log position after it.
    async mark() { await snapshot('mark'); return { seq: log.seq }; },
    async stop() {
      if (!server) return;
      await snapshot('stop');
      log.push({ kind: 'close', inflight });
      await new Promise(resolve => { server.close(resolve); for (const s of sockets) s.destroy(); });
      server = null;
      log.close();
    },
  };
}
