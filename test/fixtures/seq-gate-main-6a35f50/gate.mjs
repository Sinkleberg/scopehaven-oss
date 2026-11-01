// Frozen copy of scopehaven/integrations/sequences/gate.mjs at main 6a35f50 (before the rules[].rejected declaration; imports
// re-pointed to the live src/ and integrations/observers/). For integrations/sequences/gate-rejected.test.mjs differentials only.
// Not in any identity list.
// Hold gate: a loopback reverse proxy that can pause matching requests at an
// execution boundary and release them on command. Put it in front of the
// app's model provider (an OpenAI-compatible or Ollama base URL) to pause any
// agent framework between "the model chose the next step" and "the tool ran",
// or in front of a tool service to pause the tool call itself. Ordering comes
// from events (held, then the access change, then release), not from timers,
// so a timed sequence replays deterministically.
import { createServer, request } from 'node:http';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { digest } from '../../../src/domain.mjs';
import { makeEffect, wallNs, loopbackRequestAllowed, originForm } from '../../../integrations/observers/events.mjs';

export const GATE_LIMITS = Object.freeze({ bodyBytes: 4 * 1024 * 1024, held: 64, timeline: 10000 });
const LOOPBACK = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/?$/;

// rules: [{ id, method?, pathPrefix, holds? }] - `holds` limits how many
// matching requests are held (default 1); later matches pass through.
export function createHoldGate({ upstream, port = 0, rules = [], instanceId = 'gate-1', timelineLimit = GATE_LIMITS.timeline }) {
  const m = LOOPBACK.exec(upstream || '');
  if (!m || Number(m[1]) > 65535) throw new Error('Gate upstream must be literal loopback HTTP.');
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Gate port must be an integer from 0 to 65535; the listener always binds 127.0.0.1.');
  for (const rule of rules) if (!/^[A-Za-z0-9_-]{1,80}$/.test(rule.id || '') || typeof rule.pathPrefix !== 'string' || !rule.pathPrefix.startsWith('/')) throw new Error('Each gate rule needs an id and a pathPrefix starting with "/".');
  const upstreamUrl = new URL(upstream), emitter = new EventEmitter(), held = new Map(), timeline = [], heldCount = new Map();
  let server = null, listening = null, seq = 0, overflowAtSeq = null;
  // The timeline is bounded; once full, gated traffic is no longer recorded, so
  // every later window is partial (see observer()).
  const note = entry => { seq++; if (timeline.length < timelineLimit) timeline.push({ seq, t: String(wallNs()), ...entry }); else if (overflowAtSeq === null) overflowAtSeq = seq; };
  // Rules match the normalized path (percent-decoded, case-folded), so an
  // encoded or differently cased path cannot slip past a rule. The matching
  // rule names the request even when it is not held (budget or capacity used
  // up, or another method on the same path), so it is never "ungated".
  const normalized = url => { try { return decodeURIComponent(new URL(url, 'http://127.0.0.1').pathname).toLowerCase(); } catch { return null; } };
  const ruleFor = path => rules.find(rule => path.startsWith(rule.pathPrefix.toLowerCase()));
  function forward(req, res, body, meta) {
    const target = new URL(req.url, upstreamUrl);
    if (target.origin !== upstreamUrl.origin) { res.writeHead(400).end(); return; }
    const up = request(target, { method: req.method, headers: { ...req.headers, host: upstreamUrl.host }, agent: false }, upRes => {
      note({ type: 'response', reqId: meta.reqId, ruleId: meta.ruleId, holdId: meta.holdId, status: upRes.statusCode, pathDigest: meta.pathDigest });
      res.writeHead(upRes.statusCode, upRes.headers);
      upRes.pipe(res);
    });
    up.on('error', () => { note({ type: 'upstream-error', reqId: meta.reqId, ruleId: meta.ruleId, holdId: meta.holdId, pathDigest: meta.pathDigest }); if (!res.headersSent) res.writeHead(502); res.end(); });
    note({ type: 'forwarded', reqId: meta.reqId, ruleId: meta.ruleId, holdId: meta.holdId, pathDigest: meta.pathDigest });
    up.end(body);
  }
  const handle = (req, res) => {
    if (!loopbackRequestAllowed(req, listening)) { req.resume(); res.writeHead(403).end(); return; }
    const path = originForm(req.url) ? normalized(req.url) : null;
    if (path === null) { req.resume(); res.writeHead(400).end(); return; }
    const chunks = []; let bytes = 0;
    req.on('data', chunk => { bytes += chunk.length; if (bytes <= GATE_LIMITS.bodyBytes) chunks.push(chunk); });
    req.on('end', () => {
      if (bytes > GATE_LIMITS.bodyBytes) { res.writeHead(413).end(); return; }
      const body = Buffer.concat(chunks), rule = ruleFor(path), pathDigest = digest(req.url), reqId = randomUUID();
      const budgetLeft = rule && (!rule.method || rule.method === req.method) && (heldCount.get(rule.id) ?? 0) < (rule.holds ?? 1);
      if (budgetLeft && held.size >= GATE_LIMITS.held) note({ type: 'hold-capacity-exceeded', ruleId: rule.id, pathDigest });
      if (!rule || !budgetLeft || held.size >= GATE_LIMITS.held) return forward(req, res, body, { reqId, ruleId: rule?.id ?? null, holdId: null, pathDigest });
      heldCount.set(rule.id, (heldCount.get(rule.id) ?? 0) + 1);
      const holdId = randomUUID();
      held.set(holdId, { ruleId: rule.id, release: () => forward(req, res, body, { reqId, ruleId: rule.id, holdId, pathDigest }), drop: () => { note({ type: 'dropped', ruleId: rule.id, holdId }); res.writeHead(503).end(); } });
      note({ type: 'held', reqId, ruleId: rule.id, holdId, pathDigest, bodyDigest: digest(body.toString('base64')) });
      // If the client gives up while held, record it: the request never reached upstream.
      res.on('close', () => { if (held.has(holdId) && !res.writableEnded) { held.delete(holdId); note({ type: 'client-closed-while-held', ruleId: rule.id, holdId }); } });
      emitter.emit('held', { ruleId: rule.id, holdId });
    });
  };
  return {
    instanceId, timeline,
    get url() { return listening ? `http://127.0.0.1:${listening}` : null; },
    async start() { server = createServer(handle); await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); }); listening = server.address().port; note({ type: 'open' }); },
    // Resolve with the hold id of the next request held by `ruleId` (or one already held).
    awaitHold(ruleId, timeoutMs = 30000) {
      for (const [holdId, h] of held) if (h.ruleId === ruleId && !h.claimed) { h.claimed = true; return Promise.resolve(holdId); }
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { emitter.off('held', on); reject(Object.assign(new Error(`No request matched gate rule "${ruleId}" within ${timeoutMs} ms.`), { code: 'hold-timeout' })); }, timeoutMs);
        const on = event => { if (event.ruleId !== ruleId) return; const h = held.get(event.holdId); if (!h || h.claimed) return; h.claimed = true; clearTimeout(timer); emitter.off('held', on); resolve(event.holdId); };
        emitter.on('held', on);
      });
    },
    release(holdId) { const h = held.get(holdId); if (!h) throw new Error('Unknown or already released hold.'); held.delete(holdId); note({ type: 'released', ruleId: h.ruleId, holdId }); h.release(); },
    drop(holdId) { const h = held.get(holdId); if (!h) throw new Error('Unknown or already released hold.'); held.delete(holdId); h.drop(); },
    heldIds() { return [...held.keys()]; },
    // The gate is also an observer: each gated request is a tool-call effect
    // that committed when upstream answered 2xx.
    // The gate is also an observer: each gated or forwarded request is one
    // tool-call effect, committed when upstream answered 2xx, still in flight
    // when it was held or forwarded but has no response by the window end.
    observer() {
      const observer = { kind: 'hold-gate', instanceId };
      return { kind: observer.kind, instanceId, source: 'hold-proxy',
        scope: Object.freeze({ operations: ['tool-call'], names: [...rules.map(r => r.id), 'ungated'], actorAttribution: 'none', evidence: 'authoritative' }),
        async start() {}, async stop() {},
        async mark() { return { seq }; },
        async collect(from, to) {
          if (!listening) return { events: [], coverage: 'failed', reason: 'gate-not-running' };
          const inWindow = timeline.filter(e => e.seq > from.seq && e.seq <= to.seq);
          // The gate proves only what it never forwarded. A forwarded request is
          // committed when upstream answered 2xx; any other end (a denial, a 5xx, an
          // upstream error, a reset, no answer yet) is unknown, because upstream may
          // have acted before failing, and an unknown event keeps the window partial.
          // A held request that was dropped or abandoned never reached upstream.
          const ended = new Map(inWindow.filter(e => e.type === 'response' || e.type === 'upstream-error').map(e => [e.reqId, e]));
          const neverForwarded = new Set(inWindow.filter(e => e.type === 'dropped' || e.type === 'client-closed-while-held').map(e => e.holdId));
          const firstSeen = new Map();
          for (const e of inWindow) if ((e.type === 'held' || e.type === 'forwarded') && !firstSeen.has(e.reqId)) firstSeen.set(e.reqId, e);
          const outcomeOf = e => e.type === 'upstream-error' ? 'unknown' : e.status >= 200 && e.status < 300 ? 'committed' : 'unknown';
          const events = [...firstSeen.values()].filter(e => !(e.type === 'held' && neverForwarded.has(e.holdId) && !ended.has(e.reqId))).map(e => {
            const end = ended.get(e.reqId);
            return makeEffect({ source: 'hold-proxy', observer, seq: e.seq, observedAt: new Date(Number(BigInt((end ?? e).t) / 1000000n)).toISOString(), operation: 'tool-call', name: e.ruleId ?? 'ungated',
              outcome: end ? outcomeOf(end) : 'started', correlation: { requestId: e.holdId ?? undefined }, content: e.pathDigest });
          });
          // Answers in this window for requests sent before it are effects of this window too.
          for (const [reqId, end] of ended) if (!firstSeen.has(reqId)) events.push(makeEffect({ source: 'hold-proxy', observer, seq: end.seq, observedAt: new Date(Number(BigInt(end.t) / 1000000n)).toISOString(),
            operation: 'tool-call', name: end.ruleId ?? 'ungated', outcome: outcomeOf(end), correlation: { requestId: end.holdId ?? undefined }, content: end.pathDigest }));
          events.sort((a, b) => a.seq - b.seq);
          const overflowed = overflowAtSeq !== null && overflowAtSeq <= to.seq;
          return { events, coverage: overflowed ? 'partial' : 'complete', reason: overflowed ? 'gate-timeline-full' : null };
        } };
    },
    async stop() { for (const id of [...held.keys()]) this.drop(id); note({ type: 'close' }); if (server) await new Promise(resolve => server.close(resolve)); server = null; listening = null; },
  };
}
