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
import { digest } from '../../src/domain.mjs';
import { makeEffect, wallNs, loopbackRequestAllowed, originForm } from '../observers/events.mjs';
import { UNREJECTABLE, FORWARD_BOUNDS } from '../../src/effect-outcome.mjs';
import { singleHeader } from '../../src/http.mjs';

export const GATE_LIMITS = Object.freeze({ bodyBytes: 4 * 1024 * 1024, held: 64, timeline: 10000 });
const LOOPBACK = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/?$/;
// The Host a gated request may name besides 127.0.0.1: the gate as an app in a container reaches it (Docker Desktop relays
// host.docker.internal to the host's loopback), as the egress recorder admits. Only the Host is widened: a repeated Host, more
// than 40 headers, an Origin other than the gate's 127.0.0.1 origin and a cross-site Sec-Fetch-Site still read 403, so a page
// that rebinds a name of its own to 127.0.0.1 is refused as before.
export const GATE_CONTAINER_HOST = 'host.docker.internal';
export function gateRequestAllowed(req, port) {
  if (loopbackRequestAllowed(req, port)) return true;
  if (req.rawHeaders && req.rawHeaders.length > 80) return false;
  if (String(singleHeader(req, 'host') ?? '').toLowerCase() !== `${GATE_CONTAINER_HOST}:${port}`) return false;
  if (req.headers.origin !== undefined && singleHeader(req, 'origin') !== `http://127.0.0.1:${port}`) return false;
  const site = req.headers['sec-fetch-site'];
  return site === undefined || site === 'same-origin' || site === 'none';
}

// A request can ask for another method than its request line's, by a header or by a `_method` parameter, as Rack (the
// header and a form body), Symfony (also the query), Laravel (also a JSON body) and Express's method-override honour.
// methodOverridesOf lists each value a request carries, as sent: the three headers, then `_method` in the query, in a
// form body (or one with no content type, which Rack reads as a form) and at the top of a JSON body. It reads them as
// the frameworks do:
// - a header named with `_` for `-` (a CGI server gives both spellings the same name);
// - a query or form key in the spellings Rack 2 and PHP fold into `_method` (overrideOfKey);
// - the media type up to its first `;`, `,` or whitespace, as Rack and PHP cut it, and any type with `/json` or `+json`
//   in it as JSON, as Laravel does.
// What the gate cannot read gives '': a body with a Content-Encoding other than identity (Express's body-parser inflates
// gzip and deflate), a JSON body that does not parse, and any other body (multipart included) that names `_method` or
// `.method`. At most 8 values are kept, each cut to 32 characters, and '' stands for the rest.
export const METHOD_OVERRIDE_HEADERS = Object.freeze(['x-http-method-override', 'x-http-method', 'x-method-override']);
export function methodOverridesOf(req, body) {
  const headers = Object.entries(req.headers);
  const found = METHOD_OVERRIDE_HEADERS.flatMap(h => headers.filter(([name]) => name.replaceAll('_', '-') === h).map(([, v]) => String(v)));
  const fromKeys = params => { for (const [key, value] of params) { const v = overrideOfKey(key, value); if (v !== null) found.push(v); } };
  fromKeys(new URL(req.url, 'http://127.0.0.1').searchParams);
  const header = String(req.headers['content-type'] ?? '').toLowerCase(), type = header.trim().split(/[;,\s]/)[0];
  const encoding = String(req.headers['content-encoding'] ?? '').trim().toLowerCase();
  if (body.length && encoding !== '' && encoding !== 'identity') found.push('');
  else {
    const text = body.toString('utf8'), form = type === '' || type === 'application/x-www-form-urlencoded', json = header.includes('/json') || header.includes('+json');
    if (form) fromKeys(new URLSearchParams(text));
    if (json && text.trim() !== '') {
      let parsed; try { parsed = JSON.parse(text); } catch { found.push(''); }
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && Object.hasOwn(parsed, '_method')) found.push(typeof parsed._method === 'string' ? parsed._method : '');
    }
    if (!form && !json && /_method|\.method/.test(text)) found.push('');
  }
  return [...found.slice(0, 8).map(v => v.slice(0, 32)), ...(found.length > 8 ? [''] : [])];
}

// What a query or form key gives the override: its value when a framework reads the key as `_method`, '' when it nests
// under `_method` (an array or a hash, never a method), and null otherwise. Rack 2 drops leading `[` and `]` and trailing
// `]`, so `[_method]` and `_method]` are `_method` (Rack 3 reads keys as sent). PHP, so Symfony and Laravel, ends a key at
// its first NUL (it decodes `%00` in place, then reads the name as a C string), drops leading spaces and reads `.` and ` `
// as `_`, so `_method%00x` and `.method` are `_method`. The gate also reads a key with its leading spaces kept, so
// ` method` is `_method` too: that only errs toward a write.
export function overrideOfKey(key, value) {
  const rack = /^[[\]]*([^[\]]+)\]*/.exec(key);
  if (rack?.[1] === '_method') {
    const after = key.slice(rack[0].length);
    if (after === '') return value;
    if (after !== '[') return '';
  }
  const php = key.split('\0')[0];
  for (const name of [php.replace(/^ +/, ''), php]) {
    const open = name.indexOf('['), base = (open === -1 ? name : name.slice(0, open)).replace(/[ .]/g, '_');
    if (base !== '_method') continue;
    if (open === -1) return value;
    if (name.includes(']', open + 1)) return '';
  }
  return null;
}

// rules: [{ id, method?, pathPrefix, holds?, rejected? }] - `holds` limits how many
// matching requests are held (default 1); later matches pass through.
// `rejected` (opt-in, default none) lists up to 16 distinct 4xx statuses the upstream answers to this rule's
// calls only when it did not apply them, from the statuses an egress destination's forward.rejected allows
// (src/effect-outcome.mjs: never 408, 425, 429 or 499, which may be answered while the upstream still applies
// the call). It covers every call the rule names: any method, held or passed through, on any path its prefix
// matches. A call under the rule answered one of them in full, with no upstream error, reads denied, so it
// leaves its window complete; every other answer, a listed status cut off included, reads as without the
// declaration. The gate cannot check the claim: the operator asserts that the upstream never answers a listed
// status after applying the call. A declaring rule's id is its own (no other rule uses it, and it is never
// "ungated", the name of calls no rule matches), and the observer's scope carries the declarations
// (scope.rejected), so a run seals them.
const rejectable = status => Number.isInteger(status) && status >= 400 && status <= 499 && !UNREJECTABLE.includes(status);
function rejectedOf(rule, rules) {
  if (rule.rejected === undefined) return null;
  const list = rule.rejected;
  if (!Array.isArray(list) || list.length > FORWARD_BOUNDS.statuses || ![...list].every(rejectable) || new Set(list).size !== list.length)
    throw new Error(`Gate rule "${rule.id}": "rejected" lists up to ${FORWARD_BOUNDS.statuses} distinct 4xx statuses the upstream answers only when it did not apply the call (2xx, 3xx and 5xx are never "not applied", nor ${UNREJECTABLE.join(', ')}, which may be answered while the upstream still applies it).`);
  if (!list.length) return null;
  if (rule.id === 'ungated') throw new Error('Gate rule "ungated" declares "rejected", but "ungated" names the calls no rule matches: give the rule another id.');
  if (rules.filter(other => other.id === rule.id).length > 1) throw new Error(`Gate rule "${rule.id}" declares "rejected", so no other rule may use its id.`);
  return Object.freeze([...list].sort((a, b) => a - b));
}
export function createHoldGate({ upstream, port = 0, rules = [], instanceId = 'gate-1', timelineLimit = GATE_LIMITS.timeline }) {
  const m = LOOPBACK.exec(upstream || '');
  if (!m || Number(m[1]) > 65535) throw new Error('Gate upstream must be literal loopback HTTP.');
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Gate port must be an integer from 0 to 65535; the listener always binds 127.0.0.1.');
  for (const rule of rules) if (!/^[A-Za-z0-9_-]{1,80}$/.test(rule.id || '') || typeof rule.pathPrefix !== 'string' || !rule.pathPrefix.startsWith('/')) throw new Error('Each gate rule needs an id and a pathPrefix starting with "/".');
  // The declared refusals, by rule id: only rules that list at least one status.
  const rejectedBy = new Map();
  for (const rule of rules) { const list = rejectedOf(rule, rules); if (list) rejectedBy.set(rule.id, list); }
  const upstreamUrl = new URL(upstream), emitter = new EventEmitter(), held = new Map(), timeline = [], heldCount = new Map();
  let server = null, listening = null, seq = 0, overflowAtSeq = null;
  // The timeline is bounded; once full, gated traffic is no longer recorded, so
  // every later window is partial (see observer()). Each held and forwarded entry
  // records the request's method and its method overrides (methodOverridesOf); the
  // observer's events carry neither, so the windows it collects are unchanged.
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
    // An upstream fault is noted once per request: the connection failed before any answer, or it cut a reply off after the
    // status line (a reset, or a close before the declared length or the last chunk). A cut reply is not a whole round trip,
    // even after a 2xx, so it ends unknown (collect below) as a reset does. The client's reply is then cut off too: ending it
    // would give a chunked reply a clean last chunk, so a truncated body would read complete, and one with a length never ends.
    let faulted = false;
    const fault = () => { if (!faulted) { faulted = true; note({ type: 'upstream-error', reqId: meta.reqId, ruleId: meta.ruleId, holdId: meta.holdId, pathDigest: meta.pathDigest }); } };
    const up = request(target, { method: req.method, headers: { ...req.headers, host: upstreamUrl.host }, agent: false }, upRes => {
      note({ type: 'response', reqId: meta.reqId, ruleId: meta.ruleId, holdId: meta.holdId, status: upRes.statusCode, pathDigest: meta.pathDigest });
      // A declared refusal can decide only once its reply has ended (as forward.rejected reads only a complete reply), so its end
      // is noted; one cut off after its status line has no response-end and stays unknown. A response-end alone does not mean the
      // reply arrived in full: a reply without a length also ends when its connection is reset, and the upstream-error noted for
      // that request still decides unknown (collect below). Noted only for a declared status, so an undeclared gate records as before.
      if (rejectedBy.get(meta.ruleId)?.includes(upRes.statusCode)) upRes.on('end', () => { if (upRes.complete) note({ type: 'response-end', reqId: meta.reqId, ruleId: meta.ruleId, holdId: meta.holdId, pathDigest: meta.pathDigest }); });
      upRes.on('close', () => { if (!upRes.complete) { fault(); res.destroy(); } });
      res.writeHead(upRes.statusCode, upRes.headers);
      upRes.pipe(res);
    });
    up.on('error', () => { fault(); if (res.headersSent) res.destroy(); else res.writeHead(502).end(); });
    note({ type: 'forwarded', reqId: meta.reqId, ruleId: meta.ruleId, holdId: meta.holdId, method: req.method, methodOverrides: meta.methodOverrides, pathDigest: meta.pathDigest });
    up.end(body);
  }
  const handle = (req, res) => {
    if (!gateRequestAllowed(req, listening)) { req.resume(); res.writeHead(403).end(); return; }
    const path = originForm(req.url) ? normalized(req.url) : null;
    if (path === null) { req.resume(); res.writeHead(400).end(); return; }
    const chunks = []; let bytes = 0;
    req.on('data', chunk => { bytes += chunk.length; if (bytes <= GATE_LIMITS.bodyBytes) chunks.push(chunk); });
    req.on('end', () => {
      if (bytes > GATE_LIMITS.bodyBytes) { res.writeHead(413).end(); return; }
      const body = Buffer.concat(chunks), rule = ruleFor(path), pathDigest = digest(req.url), reqId = randomUUID(), methodOverrides = methodOverridesOf(req, body);
      const budgetLeft = rule && (!rule.method || rule.method === req.method) && (heldCount.get(rule.id) ?? 0) < (rule.holds ?? 1);
      if (budgetLeft && held.size >= GATE_LIMITS.held) note({ type: 'hold-capacity-exceeded', ruleId: rule.id, pathDigest });
      if (!rule || !budgetLeft || held.size >= GATE_LIMITS.held) return forward(req, res, body, { reqId, ruleId: rule?.id ?? null, holdId: null, methodOverrides, pathDigest });
      heldCount.set(rule.id, (heldCount.get(rule.id) ?? 0) + 1);
      const holdId = randomUUID();
      held.set(holdId, { ruleId: rule.id, release: () => forward(req, res, body, { reqId, ruleId: rule.id, holdId, methodOverrides, pathDigest }), drop: () => { note({ type: 'dropped', ruleId: rule.id, holdId }); res.writeHead(503).end(); } });
      note({ type: 'held', reqId, ruleId: rule.id, holdId, method: req.method, methodOverrides, pathDigest, bodyDigest: digest(body.toString('base64')) });
      // If the client gives up while held, record it: the request never reached upstream.
      res.on('close', () => { if (held.has(holdId) && !res.writableEnded) { held.delete(holdId); note({ type: 'client-closed-while-held', ruleId: rule.id, holdId }); } });
      emitter.emit('held', { ruleId: rule.id, holdId });
    });
  };
  return {
    instanceId, timeline,
    get url() { return listening ? `http://127.0.0.1:${listening}` : null; },
    // The base URL an app in a container points at (GATE_CONTAINER_HOST); the listener is the same 127.0.0.1 one.
    get containerUrl() { return listening ? `http://${GATE_CONTAINER_HOST}:${listening}` : null; },
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
    // The gate is also an observer: each gated or forwarded request is one
    // tool-call effect, committed when upstream answered 2xx, denied when its
    // rule declares the status answered as a refusal and the reply ended with no
    // upstream error, still in flight when it was held or forwarded but has no
    // response by the window end, and unknown otherwise.
    observer() {
      const observer = { kind: 'hold-gate', instanceId };
      return { kind: observer.kind, instanceId, source: 'hold-proxy',
        scope: Object.freeze({ operations: ['tool-call'], names: [...rules.map(r => r.id), 'ungated'], actorAttribution: 'none', evidence: 'authoritative',
          ...(rejectedBy.size ? { rejected: Object.fromEntries(rejectedBy) } : {}) }),
        async start() {}, async stop() {},
        async mark() { return { seq }; },
        async collect(from, to) {
          if (!listening) return { events: [], coverage: 'failed', reason: 'gate-not-running' };
          const inWindow = timeline.filter(e => e.seq > from.seq && e.seq <= to.seq);
          // The gate proves only what it never forwarded. A forwarded request is
          // committed when upstream answered 2xx, and denied when its rule declares the
          // status it answered as a refusal (rules[].rejected), that reply ended within
          // the window (response-end) and no upstream error was noted for it there. The
          // last response or upstream-error noted for a request in the window is its
          // end, and an upstream error reads unknown even beside a response-end: a reply
          // without a length also ends when its connection is reset. Any other end (an
          // undeclared denial, a declared one cut off, a 5xx, an upstream error, a reset,
          // a reply of any status cut off after its status line, which notes an upstream
          // error after its response, no answer yet) is unknown, because upstream may
          // have acted before failing, and an unknown event keeps the window partial.
          // A held request that was dropped or abandoned never reached upstream.
          const ended = new Map(inWindow.filter(e => e.type === 'response' || e.type === 'upstream-error').map(e => [e.reqId, e]));
          const neverForwarded = new Set(inWindow.filter(e => e.type === 'dropped' || e.type === 'client-closed-while-held').map(e => e.holdId));
          const firstSeen = new Map();
          for (const e of inWindow) if ((e.type === 'held' || e.type === 'forwarded') && !firstSeen.has(e.reqId)) firstSeen.set(e.reqId, e);
          const fullReplies = new Set(inWindow.filter(e => e.type === 'response-end').map(e => e.reqId));
          const outcomeOf = e => e.type === 'upstream-error' ? 'unknown' : e.status >= 200 && e.status < 300 ? 'committed'
            : rejectedBy.get(e.ruleId)?.includes(e.status) && fullReplies.has(e.reqId) ? 'denied' : 'unknown';
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
