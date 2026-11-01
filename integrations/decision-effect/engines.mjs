// The policy engines a decision-effect run can use, both on loopback only.
//   startOpa       the real Open Policy Agent binary (SCOPEHAVEN_OPA_BIN), with its decision-log
//                  plugin uploading to the sink; telemetry and the version check are off.
//   startStandIn   a small stand-in that answers the data API with a JS policy and uploads its
//                  decisions in OPA's format (gzip batches to POST /logs) and counts them in OPA's
//                  metric, so the tests run without OPA. Its faults (dropEvery, flushDelayMs, noLog)
//                  exercise the late and missing log readings.
//   startGateFault the gate-outage drill's fault gate (DE-03): it sits between the application and
//                  either engine, fails every decision about one resource, and forwards the rest.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { gzipSync, gunzipSync } from 'node:zlib';
import { writeFileSync, existsSync, chmodSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { digest } from '../../src/domain.mjs';
import { loopbackRequestAllowed } from '../observers/events.mjs';

const loopbackOrigin = url => { const u = new URL(url); if (u.protocol !== 'http:' || u.hostname !== '127.0.0.1' || u.pathname !== '/') throw new Error('Engines run on, and log to, loopback HTTP only.'); return u.origin; };
async function freePort() {
  const s = createServer(); await new Promise(resolve => s.listen(0, '127.0.0.1', resolve));
  const { port } = s.address(); await new Promise(resolve => s.close(resolve)); return port;
}
async function waitHealthy(origin, ms = 15000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    try { const res = await fetch(`${origin}/health`, { redirect: 'error', signal: AbortSignal.timeout(1000) }); await res.arrayBuffer(); if (res.ok) return; } catch { /* starting */ }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('The policy engine did not become healthy.');
}

// The OPA config, holding the sink's bearer token as the service's credentials, written to its own
// directory (0700) as a 0600 file. File modes keep out other users, not other processes of this user.
export function writeOpaConfig({ dir, sinkUrl, sinkToken, minDelaySeconds = 1, maxDelaySeconds = 1 }) {
  if (typeof sinkToken !== 'string' || !sinkToken) throw new Error('Give OPA the sink\'s bearer token.');
  const sink = loopbackOrigin(sinkUrl), confDir = mkdtempSync(join(dir, 'opa-config-'));
  chmodSync(confDir, 0o700);
  const config = join(confDir, 'opa-config.json');
  writeFileSync(config, JSON.stringify({ services: { sink: { url: sink, credentials: { bearer: { token: sinkToken } } } }, decision_logs: { service: 'sink', reporting: { min_delay_seconds: minDelaySeconds, max_delay_seconds: maxDelaySeconds } } }), { mode: 0o600 });
  chmodSync(config, 0o600);
  return config;
}
// policyFiles: the .rego and data.json files to load; dir: a scratch directory for the config.
export async function startOpa({ bin, policyFiles, sinkUrl, sinkToken, dir, minDelaySeconds = 1, maxDelaySeconds = 1 }) {
  if (typeof bin !== 'string' || !existsSync(bin)) throw new Error('Set SCOPEHAVEN_OPA_BIN to an installed OPA binary.');
  const config = writeOpaConfig({ dir, sinkUrl, sinkToken, minDelaySeconds, maxDelaySeconds });
  const port = await freePort(), origin = `http://127.0.0.1:${port}`;
  const child = spawn(bin, ['run', '--server', '--addr', `127.0.0.1:${port}`, '--config-file', config, '--disable-telemetry', '--skip-version-check', '--log-level', 'error', ...policyFiles], { env: {}, stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = ''; child.stderr.on('data', d => { if (stderr.length < 4000) stderr += d; });
  const exited = new Promise(resolve => child.once('exit', resolve));
  try { await waitHealthy(origin); } catch (e) { child.kill('SIGKILL'); throw new Error(`${e.message} ${stderr.slice(0, 300)}`); }
  return { kind: 'opa', origin, async stop() { child.kill('SIGTERM'); await Promise.race([exited, new Promise(resolve => setTimeout(resolve, 5000))]); if (child.exitCode === null) child.kill('SIGKILL'); } };
}

// policy: (path, input) => boolean result. Faults: dropEvery n drops every n-th decision from the
// log (still served and counted); flushDelayMs delays every upload; noLog never uploads.
export async function startStandIn({ policy, sinkUrl, sinkToken, flushMs = 100, dropEvery = 0, flushDelayMs = 0, noLog = false }) {
  const sink = sinkUrl === null ? null : loopbackOrigin(sinkUrl), labels = { id: randomUUID(), version: 'stand-in' };
  const counts = new Map(), buffer = []; let served = 0, port = null;
  const count = handler => counts.set(handler, (counts.get(handler) ?? 0) + 1);
  const server = createServer((req, res) => {
    if (!loopbackRequestAllowed(req, port)) { req.resume(); res.writeHead(403).end(); return; }
    if (req.method === 'GET' && req.url === '/health') { req.resume(); res.writeHead(200).end('{}'); return; }
    if (req.method === 'GET' && req.url === '/metrics') {
      req.resume(); res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(['# TYPE http_request_duration_seconds histogram', ...[...counts].map(([h, n]) => `http_request_duration_seconds_count{code="200",handler="${h}",method="post"} ${n}`)].join('\n') + '\n'); return;
    }
    // Like OPA, the data API also answers with a trailing slash or a query string (?pretty=true).
    const m = /^\/v1\/data\/([A-Za-z0-9_/]+?)\/?(?:\?[^#]*)?$/.exec(req.url ?? '');
    if (req.method !== 'POST' || !m) { req.resume(); res.writeHead(404).end(); return; }
    const chunks = []; req.on('data', d => chunks.push(d));
    req.on('end', () => {
      let input = {};
      try { input = JSON.parse(Buffer.concat(chunks).toString() || '{}').input ?? {}; } catch { res.writeHead(400).end(); return; }
      const result = policy(m[1], input) === true, decision_id = randomUUID();
      count('v1/data'); served++;
      if (!(dropEvery && served % dropEvery === 0)) buffer.push({ labels, decision_id, path: m[1], input, result, timestamp: new Date().toISOString() });
      res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ decision_id, result }));
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); port = server.address().port;
  const upload = async () => {
    if (noLog || sink === null || !buffer.length) return;
    const batch = buffer.splice(0);
    if (flushDelayMs) await new Promise(resolve => setTimeout(resolve, flushDelayMs));
    try { const res = await fetch(`${sink}/logs`, { method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip', ...(sinkToken ? { Authorization: `Bearer ${sinkToken}` } : {}) }, body: gzipSync(JSON.stringify(batch)) }); await res.arrayBuffer(); } catch { /* a lost batch reads as decisions not logged */ }
  };
  let busy = false;
  const timer = setInterval(() => { if (!busy) { busy = true; upload().finally(() => { busy = false; }); } }, flushMs);
  return { kind: 'stand-in', origin: `http://127.0.0.1:${port}`, get served() { return served; },
    async stop() { clearInterval(timer); await new Promise(resolve => { server.close(resolve); server.closeAllConnections?.(); }); } };
}

// The gate-outage drill's fault gate (DE-03). The application is pointed at it as if it were the
// engine. Every request that names faultResource fails in the given mode and never reaches the engine:
// any method and path (the data API with or without a query string or trailing slash, its v0 and GET
// forms, the default decision at /), wherever the name appears (the path or query, percent-decoded;
// the body raw, gunzipped when marked gzip, and every string in it when it is JSON), case-insensitive
// and not as part of a longer name. A request it cannot read (a gzip body that does not inflate, JSON
// with more than GATE_JSON_DEPTH levels of arrays or objects) fails too, logged as unreadable-request.
// The name match is best-effort; the guarantee is the judge's leak check (gate-outage.mjs). Every
// other request is forwarded to the engine with its reply. The
// gate's log is the harness's record, which the application never writes: each failed call with its
// method, path, the input's identifiers and an input digest, and how many calls it forwarded (health
// and metrics excepted, with any subpath, as the engine's own count excepts them).
//   unreachable   the connection is closed without a reply
//   timeout       no reply: the request is held until the application gives up or the gate stops
//   error         503
//   rate-limited  429 with Retry-After
//   malformed     200 with a body that holds no result
// Only the Content-Type, Content-Encoding and Accept headers are forwarded.
export const GATE_FAULT_SCHEMA = 'scopehaven-gate-fault/2';
export const GATE_FAULT_MODES = Object.freeze(['unreachable', 'timeout', 'error', 'rate-limited', 'malformed']);
export const GATE_ERRORS = Object.freeze(['body-too-large', 'unreadable-request', 'forward-failed']);
const GATE_BODY_BYTES = 64 * 1024, GATE_FORWARDED_HEADERS = Object.freeze(['content-type', 'content-encoding', 'accept']);
const idField = value => (typeof value === 'string' ? value.slice(0, 200) : null);
const plainObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const parseJson = text => { try { return { ok: true, value: JSON.parse(text) }; } catch { return { ok: false }; } };

// What a request says, as the gate reads it: every text an engine could read the resource from, the
// decision input (the body's input, the query's input, or the body itself), and whether the gate could
// read all of it. A body marked gzip that does not inflate, or JSON with more than GATE_JSON_DEPTH levels
// of arrays or objects, is unreadable: the gate fails it (fail closed) and logs unreadable-request.
export const GATE_JSON_DEPTH = 64;
export function readGateRequest(url, headers, body) {
  const texts = [url];
  let readable = true;
  // Iterative, depth-capped: a nested body cannot exhaust the stack.
  const walk = value => {
    const stack = [[value, 0]];
    while (stack.length) {
      const [v, depth] = stack.pop();
      if (typeof v === 'string') { texts.push(v); continue; }
      if (v === null || typeof v !== 'object') continue;
      if (depth >= GATE_JSON_DEPTH) { readable = false; return; }
      for (const [k, x] of Object.entries(v)) { texts.push(k); stack.push([x, depth + 1]); }
    }
  };
  try { texts.push(decodeURIComponent(url)); } catch { /* the raw form is kept */ }
  const q = url.indexOf('?'), query = new URLSearchParams(q < 0 ? '' : url.slice(q + 1));
  for (const [k, v] of query) { texts.push(k, v); const j = parseJson(v); if (j.ok) walk(j.value); }
  let raw = body;
  if (/gzip/i.test(String(headers['content-encoding'] ?? ''))) { try { raw = gunzipSync(body, { maxOutputLength: GATE_BODY_BYTES }); } catch { return { texts, input: {}, readable: false }; } }
  const text = raw.toString('utf8');
  texts.push(text);
  const bodyJson = parseJson(text || '{}');
  if (bodyJson.ok) walk(bodyJson.value);
  const fromQuery = query.has('input') ? parseJson(query.get('input')) : { ok: false };
  const input = bodyJson.ok && plainObject(bodyJson.value?.input) ? bodyJson.value.input : fromQuery.ok && plainObject(fromQuery.value) ? fromQuery.value : bodyJson.ok && plainObject(bodyJson.value) ? bodyJson.value : {};
  return { texts, input, readable };
}
export const namesResource = (texts, resource) => {
  const needle = new RegExp(`(?<![A-Za-z0-9])${resource.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![A-Za-z0-9])`, 'i');
  return texts.some(t => needle.test(t));
};

export async function startGateFault({ engineOrigin, faultResource, mode }) {
  const engine = loopbackOrigin(engineOrigin);
  if (!GATE_FAULT_MODES.includes(mode)) throw new Error(`mode is ${GATE_FAULT_MODES.join(', ')}.`);
  if (typeof faultResource !== 'string' || !faultResource) throw new Error('Name the resource whose decisions the gate fails.');
  const faults = [], errors = [], held = new Set();
  let forwarded = 0, port = null;
  const fail = (req, res, input) => {
    faults.push({ seq: faults.length + 1, method: idField(req.method), path: idField((req.url ?? '/').split('?')[0]), principal: idField(input.principal), action: idField(input.action), resource: faultResource, inputDigest: digest(input) });
    if (mode === 'unreachable') { res.socket?.destroy(); return; }
    if (mode === 'timeout') { held.add(res); res.once('close', () => held.delete(res)); return; }
    if (mode === 'error') { res.writeHead(503, { 'Content-Type': 'application/json' }).end('{"code":"unavailable"}'); return; }
    if (mode === 'rate-limited') { res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '1' }).end('{"code":"rate_limited"}'); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ decision_id: randomUUID() }));
  };
  const server = createServer((req, res) => {
    if (!loopbackRequestAllowed(req, port)) { req.resume(); res.writeHead(403).end(); return; }
    const chunks = []; let size = 0, over = false;
    req.on('data', d => { size += d.length; if (size > GATE_BODY_BYTES) over = true; else chunks.push(d); });
    req.on('end', async () => {
      if (over) { errors.push('body-too-large'); res.writeHead(413).end(); return; }
      const body = Buffer.concat(chunks), url = req.url ?? '/';
      let read;
      try { read = readGateRequest(url, req.headers, body); } catch { read = { texts: [], input: {}, readable: false }; }
      // A request the gate cannot read might name the resource: it is failed, and the log reads partial,
      // so DE-03 never passes.
      if (!read.readable) errors.push('unreadable-request');
      if (!read.readable || namesResource(read.texts, faultResource)) { fail(req, res, read.input); return; }
      try {
        const headers = Object.fromEntries(GATE_FORWARDED_HEADERS.filter(h => req.headers[h] !== undefined).map(h => [h, String(req.headers[h])]));
        const reply = await fetch(`${engine}${url}`, { method: req.method, redirect: 'error', headers, ...(['GET', 'HEAD'].includes(req.method) ? {} : { body }), signal: AbortSignal.timeout(5000) });
        const text = Buffer.from(await reply.arrayBuffer());
        if (!/^\/(health|metrics)(\/|\?|$)/.test(url)) forwarded++;
        res.writeHead(reply.status, { 'Content-Type': reply.headers.get('content-type') ?? 'application/json' }); res.end(text);
      } catch { errors.push('forward-failed'); if (!res.headersSent) res.writeHead(502).end(); }
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  port = server.address().port;
  return { kind: 'gate-fault', origin: `http://127.0.0.1:${port}`, mode, faultResource,
    mark: () => ({ faults: faults.length, forwarded, errors: errors.length }),
    // The gate's log since a mark, as a drill record stores it.
    since: m => ({ schema: GATE_FAULT_SCHEMA, mode, faultResource, forwarded: forwarded - m.forwarded, faulted: faults.length - m.faults, errors: [...new Set(errors.slice(m.errors))], faults: faults.slice(m.faults) }),
    async stop() { for (const res of held) res.socket?.destroy(); await new Promise(resolve => { server.close(resolve); server.closeAllConnections?.(); }); } };
}
