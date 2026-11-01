// Decision-log sink (DECISION-EFFECT-01): a loopback receiver for an external policy engine's
// decision log, so what the engine decided is recorded outside the application under test.
// OPA's decision-log plugin uploads batches of decisions (a JSON array, usually gzip) with
// POST /logs to a configured service; this sink is that service. Each decision is reduced to
// identifiers (principal, action, resource), its result and the engine's timestamp; the input
// itself is kept only as a digest.
//
// Custody: the engine writes the log, never the application. The application can still call
// the engine any way it likes, so a window is complete only when the engine's own request
// counter agrees with what it logged (decisionWindow below). The sink takes uploads only with
// the window's bearer token, which the engine gets through its service credentials, so another
// process on the machine cannot add decisions; and every decision in a window must carry the
// engine label of that window's sentinel.
import { createServer } from 'node:http';
import { gunzipSync } from 'node:zlib';
import { randomUUID, randomBytes, timingSafeEqual } from 'node:crypto';
import { digest } from '../../src/domain.mjs';
import { loopbackRequestAllowed, wallNs } from '../observers/events.mjs';

export const DECISION_LOG_SCHEMA = 'scopehaven-decision-log/1';
export const DECISION_LOG_LIMITS = Object.freeze({ events: 5000, bodyBytes: 4 * 1024 * 1024, field: 200 });
export const SENTINEL = Object.freeze({ principal: 'scopehaven-sentinel', action: 'sentinel' });
const field = value => (typeof value === 'string' ? value.slice(0, DECISION_LOG_LIMITS.field) : null);

// One logged decision, reduced. result: 'allow' when the engine's result is true (or { allow: true }),
// 'deny' when it is false (or { allow: false }), 'other' for anything else (never read as an allow).
export function normalizeDecision(raw, seq) {
  const input = raw?.input !== null && typeof raw?.input === 'object' && !Array.isArray(raw.input) ? raw.input : {};
  const r = raw?.result, allow = typeof r === 'boolean' ? r : (r !== null && typeof r === 'object' && typeof r.allow === 'boolean' ? r.allow : null);
  return { seq, decisionId: field(raw?.decision_id), path: field(raw?.path), principal: field(input.principal), action: field(input.action), resource: field(input.resource),
    result: allow === true ? 'allow' : allow === false ? 'deny' : 'other', at: field(raw?.timestamp), engine: { id: field(raw?.labels?.id), version: field(raw?.labels?.version) }, inputDigest: digest(input) };
}

// token: the bearer token uploads must carry (a fresh random one by default; give it to the engine).
export function createDecisionLogSink({ limits = DECISION_LOG_LIMITS, token = randomBytes(24).toString('hex') } = {}) {
  const events = [], errors = [];
  const expected = Buffer.from(`Bearer ${token}`);
  const authorized = header => { const got = Buffer.from(String(header ?? '')); return got.length === expected.length && timingSafeEqual(got, expected); };
  let server = null, port = null, seq = 0;
  const handle = (req, res) => {
    if (!loopbackRequestAllowed(req, port)) { req.resume(); res.writeHead(403).end(); return; }
    if (req.method !== 'POST' || req.url !== '/logs') { req.resume(); res.writeHead(404).end(); return; }
    if (!authorized(req.headers.authorization)) { req.resume(); errors.push('unauthenticated'); res.writeHead(401).end(); return; }
    const chunks = []; let size = 0, over = false;
    req.on('data', d => { size += d.length; if (size > limits.bodyBytes) over = true; else chunks.push(d); });
    req.on('end', () => {
      if (over) { errors.push('body-too-large'); res.writeHead(413).end(); return; }
      let batch;
      try {
        const body = Buffer.concat(chunks);
        batch = JSON.parse((req.headers['content-encoding'] === 'gzip' ? gunzipSync(body, { maxOutputLength: limits.bodyBytes }) : body).toString('utf8'));
      } catch { errors.push('unreadable-batch'); res.writeHead(400).end(); return; }
      if (!Array.isArray(batch)) { errors.push('not-a-batch'); res.writeHead(400).end(); return; }
      const arrivedAt = String(wallNs());
      for (const raw of batch) {
        if (events.length >= limits.events) { errors.push('overflow'); break; }
        events.push({ ...normalizeDecision(raw, ++seq), arrivedAt });
      }
      res.writeHead(200).end();
    });
  };
  return {
    events, errors, token,
    get url() { return `http://127.0.0.1:${port}`; },
    mark: () => seq,
    async start() { server = createServer(handle); await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); }); port = server.address().port; },
    async stop() { if (server) { const s = server; server = null; await new Promise(resolve => { s.close(resolve); s.closeAllConnections?.(); }); } },
  };
}

// The engine's own count of the decisions it served: OPA's Prometheus metrics, every
// http_request_duration_seconds_count series except /health and /metrics. 0 for a metrics document
// with no such series yet (no call served); null when the text is not a metrics document.
export function servedFromMetrics(text) {
  if (typeof text !== 'string') return null;
  let total = 0, seen = false;
  for (const line of text.split('\n')) {
    const m = /^http_request_duration_seconds_count\{([^}]*)\}\s+(\d+)$/.exec(line.trim());
    if (!m) continue;
    const handler = /(?:^|,)handler="([^"]*)"/.exec(m[1])?.[1];
    if (handler === 'health' || handler === 'metrics') continue;
    total += Number(m[2]); seen = true;
  }
  return seen ? total : /^# TYPE /m.test(text) ? 0 : null;
}
export async function engineServed(origin) {
  try { const res = await fetch(`${origin}/metrics`, { redirect: 'error', signal: AbortSignal.timeout(3000) }); return res.ok ? servedFromMetrics(await res.text()) : null; } catch { return null; }
}

// A window's coverage from its own counts (the validator recomputes it from the same fields).
export const SINK_REASONS = Object.freeze(['body-too-large', 'unreadable-batch', 'not-a-batch', 'overflow', 'unauthenticated']);
export function coverageOf(d) {
  const reasons = [];
  if (!d.sentinelAnswered) reasons.push('sentinel-not-answered');
  if (d.served === null) reasons.push('engine-count-unreadable');
  if (d.sentinelAnswered && d.served !== null && !d.sentinel.logged) reasons.push('decision-log-late');
  if (d.served !== null && d.logged < d.served) reasons.push(`decisions-not-logged:${d.served - d.logged}`);
  if (d.served !== null && d.logged > d.served) reasons.push(`decisions-not-served:${d.logged - d.served}`);
  // Every decision must come from the engine that answered the sentinel.
  const foreign = d.sentinel.logged ? d.events.filter(e => e.engine?.id !== d.sentinel.engineId).length : 0;
  if (foreign) reasons.push(`foreign-engine:${foreign}`);
  reasons.push(...d.sinkErrors);
  return { reasons, coverage: !d.sentinelAnswered || d.served === null ? 'failed' : reasons.length ? 'partial' : 'complete' };
}

// A window of the decision log: `begin` before the scenario, `end` after it. end() asks the engine one
// sentinel question, then waits (up to flushTimeoutMs) until the sentinel is logged and the log holds
// as many decisions as the engine says it served since begin. The window's coverage:
//   complete  every decision the engine served in the window is in the log
//   partial   the log is late (no sentinel in time), short of the engine's count, or the sink refused a batch
//   failed    the engine's count could not be read, or the sentinel question failed
// Only a complete window can support a pass.
export function decisionWindow({ sink, engineOrigin, decisionPath, flushTimeoutMs = 5000, pollMs = 50 }) {
  let start = null;
  return {
    async begin() { start = { seq: sink.mark(), served: await engineServed(engineOrigin), errors: sink.errors.length }; },
    async end() {
      const nonce = randomUUID();
      let asked = false;
      try {
        const res = await fetch(`${engineOrigin}/v1/data/${decisionPath}`, { method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ input: { ...SENTINEL, resource: nonce } }), signal: AbortSignal.timeout(3000) });
        asked = res.ok; await res.arrayBuffer();
      } catch { asked = false; }
      const served = asked ? await engineServed(engineOrigin) : null;
      const inWindow = () => sink.events.filter(e => e.seq > start.seq);
      const deadline = Date.now() + flushTimeoutMs;
      let sentinel = false;
      const isSentinel = e => e.principal === SENTINEL.principal && e.action === SENTINEL.action && e.resource === nonce;
      while (asked && served !== null && start.served !== null) {
        sentinel = inWindow().some(isSentinel);
        if (sentinel && inWindow().length >= served - start.served) break;
        if (Date.now() >= deadline) break;
        await new Promise(resolve => setTimeout(resolve, pollMs));
      }
      const events = inWindow(), expected = served !== null && start.served !== null ? served - start.served : null;
      // Only this window's sentinel is set aside; a late sentinel from another window stays a logged decision.
      const own = events.find(isSentinel);
      const counts = { served: expected, logged: events.length, sentinel: { resource: nonce, logged: sentinel, engineId: own?.engine.id ?? null }, sentinelAnswered: asked, sinkErrors: [...new Set(sink.errors.slice(start.errors))],
        events: events.filter(e => e !== own).map(({ arrivedAt: _a, ...e }) => e) };
      const { coverage, reasons } = coverageOf(counts);
      return { schema: DECISION_LOG_SCHEMA, coverage, reasons, ...counts };
    },
  };
}
