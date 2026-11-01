// OpenTelemetry trace observer: a loopback OTLP/HTTP receiver (JSON encoding)
// that turns agent tool spans into effect events. One receiver covers every
// framework that exports OTLP: OTel GenAI semantic conventions (gen_ai.*),
// OpenInference (tool.name, user.id), the Vercel AI SDK legacy names
// (ai.toolCall.*) and MCP spans (mcp.method.name). Spec: OTLP 1.x (traces
// stable); GenAI conventions are Development status, so names are matched by
// an alias table rather than trusted to stay fixed.
//
// Evidence lineage: spans are reported by the target's own instrumentation,
// so they are self-reported. A check gets independent evidence only when a
// backend observer (sql-*, http-audit-log) corroborates the effect.
import { createServer } from 'node:http';
import { gunzipSync } from 'node:zlib';
import { makeEffect, wallNs, loopbackRequestAllowed } from './events.mjs';
import { createHmac, randomBytes } from 'node:crypto';

export const OTEL_LIMITS = Object.freeze({ bodyBytes: 4 * 1024 * 1024, inflatedBytes: 16 * 1024 * 1024, spans: 50000, settleMs: 1500 });
// Raw tool-span values (arguments, name, actor, resource, call id) are kept until collect(); past
// this many characters in total, later tool spans are dropped and windows report span-limit-reached.
export const OTEL_RETAINED_CHARS = 64 * 1024 * 1024;
const retainedSize = value => value === undefined || value === null ? 0 : typeof value === 'string' ? value.length : (JSON.stringify(value) ?? '').length;
// First present attribute wins. Arguments are digested, never stored.
export const TOOL_NAME_KEYS = Object.freeze(['gen_ai.tool.name', 'tool.name', 'tool_call.function.name', 'ai.toolCall.name', 'function.name']);
export const TOOL_ARGS_KEYS = Object.freeze(['gen_ai.tool.call.arguments', 'tool.parameters', 'tool_call.function.arguments', 'ai.toolCall.args', 'input.value']);
export const TOOL_CALL_ID_KEYS = Object.freeze(['gen_ai.tool.call.id', 'tool_call.id', 'ai.toolCall.id', 'jsonrpc.request.id']);
// enduser.id is the OTel standard; user.id is OpenInference's; scopehaven.actor lets an app say it directly.
export const ACTOR_KEYS = Object.freeze(['scopehaven.actor', 'enduser.id', 'user.id']);
export const RESOURCE_KEYS = Object.freeze(['scopehaven.resource']);

// OTLP JSON AnyValue -> plain value (int64 arrives as a decimal string).
function anyValue(value) {
  if (value === null || typeof value !== 'object') return undefined;
  if ('stringValue' in value) return value.stringValue;
  if ('boolValue' in value) return value.boolValue;
  if ('intValue' in value) return String(value.intValue);
  if ('doubleValue' in value) return value.doubleValue;
  if ('arrayValue' in value) return (value.arrayValue?.values || []).map(anyValue);
  if ('kvlistValue' in value) return attributes(value.kvlistValue?.values);
  return undefined;
}
function attributes(list) {
  const out = Object.create(null);
  if (Array.isArray(list)) for (const kv of list.slice(0, 256)) if (kv && typeof kv.key === 'string') out[kv.key] = anyValue(kv.value);
  return out;
}
const first = (attrs, keys) => { for (const key of keys) if (attrs[key] !== undefined && attrs[key] !== null && attrs[key] !== '') return attrs[key]; return undefined; };
// OTLP/JSON uses hex ids; some exporters send base64 (promptfoo's convertId idea).
export function normalizeId(id, bytes) {
  if (typeof id !== 'string' || !id) return undefined;
  if (new RegExp(`^[0-9a-fA-F]{${bytes * 2}}$`).test(id)) return id.toLowerCase();
  const raw = Buffer.from(id, 'base64');
  return raw.length === bytes ? raw.toString('hex') : undefined;
}
const nanos = value => { try { return BigInt(value); } catch { return null; } };

// Classify one span. Returns null for spans that are not tool executions.
export function toolSpan(span, resourceAttrs) {
  const attrs = { ...resourceAttrs, ...attributes(span.attributes) };
  const operation = attrs['gen_ai.operation.name'];
  const kind = attrs['openinference.span.kind'];
  const isTool = operation === 'execute_tool' || kind === 'TOOL' || attrs['mcp.method.name'] === 'tools/call' || attrs['ai.toolCall.name'] !== undefined;
  if (!isTool) return null;
  // Without a tool-name attribute, fall back to the span name (GenAI spans are
  // named "execute_tool {tool}") rather than dropping a real tool execution.
  const attrName = first(attrs, TOOL_NAME_KEYS);
  const spanName = typeof span.name === 'string' ? span.name.replace(/^execute_tool\s+/, '').trim() : '';
  const name = typeof attrName === 'string' && attrName ? attrName : spanName || 'unnamed-tool';
  const start = nanos(span.startTimeUnixNano), end = nanos(span.endTimeUnixNano);
  if (start === null || end === null || end < start) return null;
  // Status code 2 is ERROR; 0 (unset) and 1 (ok) mean the tool ran to completion.
  const outcome = span.status?.code === 2 || span.status?.code === 'STATUS_CODE_ERROR' ? 'error' : 'committed';
  const actor = first(attrs, ACTOR_KEYS), resource = first(attrs, RESOURCE_KEYS), args = first(attrs, TOOL_ARGS_KEYS), callId = first(attrs, TOOL_CALL_ID_KEYS);
  return { name, start, end, outcome, actor: typeof actor === 'string' ? actor : null, resource: typeof resource === 'string' ? resource : null, args,
    traceId: normalizeId(span.traceId, 16), spanId: normalizeId(span.spanId, 8), parentSpanId: normalizeId(span.parentSpanId, 8), callId: callId === undefined ? undefined : String(callId) };
}

// Coverage. A trace receiver cannot see a span that has not ended, so the end
// of a window is proven only by a quiescence marker: a span carrying
// `scopehaven.quiescent = true`, started at or after the window end, sent by
// the target's exporter at a moment it had no other span open (the reference
// span processor in the README counts open spans and emits it at zero). Every
// span that started before the window end then ended before the marker, and a
// batch exporter sends spans in end order, so it was sent first.
//   services: ['name'] or [{ name, instanceIds: [...] }] - the target's exporters.
//     With instanceIds, each declared instance must send a marker, and a span
//     from that service with any other (or no) service.instance.id is a gap.
//     Without, every instance seen must send one; an instance that never
//     exported is invisible, so declare instanceIds when a service runs more than one process.
//   tools: the tool names this observer can vouch for (name-specific checks).
//   principals: declared actor principals; any other actor value is "unlisted:".
// Evidence is presence-only: a matching span proves the tool ran; no span proves nothing.
// Coverage still says when the window may be incomplete (no marker, a rejected export).
// A span dated more than maxSkewMs after it was received is rejected and
// cannot carry a marker; a malformed span from a declared service makes every
// later window partial; a duplicate (traceId, spanId) is ignored.
export const QUIESCENT_ATTRIBUTE = 'scopehaven.quiescent';
export function createOtelObserver({ instanceId = 'otel-1', port = 0, services, tools = null, principals = [], settleMs = OTEL_LIMITS.settleMs, maxSkewMs = 250, maxSpans = OTEL_LIMITS.spans, maxRetainedChars = OTEL_RETAINED_CHARS, now = wallNs } = {}) {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('OTel collector port must be an integer from 0 to 65535; the listener always binds 127.0.0.1.');
  const declared = (Array.isArray(services) ? services : []).map(s => typeof s === 'string' ? { name: s, instanceIds: null } : { name: s?.name, instanceIds: s?.instanceIds ?? null });
  if (!declared.length || !declared.every(d => typeof d.name === 'string' && d.name.length > 0 && d.name.length <= 128 && (d.instanceIds === null || (Array.isArray(d.instanceIds) && d.instanceIds.length && d.instanceIds.every(i => typeof i === 'string' && i.length <= 128)))))
    throw new Error('Declare the target exporters to observe ("services": names, or { name, instanceIds }).');
  if (tools !== null && !(Array.isArray(tools) && tools.every(t => typeof t === 'string' && t.length > 0 && t.length <= 128))) throw new Error('"tools" must list tool names.');
  const spans = [], seen = new Set(), quiescent = new Map(), exporters = new Set();
  // An actor that is not a declared principal is kept only as a digest keyed with a secret this observer never stores:
  // an unkeyed hash of a guessable value (an email, a user id) is confirmed by hashing guesses.
  const actorKey = randomBytes(32);
  let server = null, seq = 0, overflow = false, rejected = 0, skewed = 0, duplicates = 0, malformed = 0, taint = null, listening = null, retained = 0;
  const observer = { kind: 'otlp-http-json-receiver', instanceId };
  function ingest(body) {
    if (!body || !Array.isArray(body.resourceSpans)) throw new Error('not-otlp');
    const received = now(), limit = received + BigInt(maxSkewMs) * 1000000n;
    for (const rs of body.resourceSpans) {
      const resourceAttrs = attributes(rs?.resource?.attributes);
      const service = declared.find(d => d.name === resourceAttrs['service.name']);
      const instance = resourceAttrs['service.instance.id'];
      for (const ss of rs?.scopeSpans || []) for (const span of ss?.spans || []) {
        if (!service) continue; // other services never move coverage or produce events
        const end = nanos(span?.endTimeUnixNano), start = nanos(span?.startTimeUnixNano);
        const traceId = normalizeId(span?.traceId, 16), spanId = normalizeId(span?.spanId, 8);
        if (end === null || start === null || end < start || !traceId || !spanId) { malformed++; taint ??= 'malformed-span-from-target'; continue; }
        if (end > limit) { skewed++; continue; }
        if (service.instanceIds && !service.instanceIds.includes(instance)) { taint ??= 'span-from-undeclared-instance'; continue; }
        const key = `${traceId}:${spanId}`;
        if (seen.has(key)) { duplicates++; continue; }
        if (seen.size >= maxSpans * 4) { overflow = true; continue; }
        seen.add(key);
        const exporter = `${service.name}|${instance ?? ''}`;
        exporters.add(exporter);
        if (attributes(span.attributes)[QUIESCENT_ATTRIBUTE] === true && start > (quiescent.get(exporter) ?? -1n)) quiescent.set(exporter, start);
        const tool = toolSpan(span, resourceAttrs);
        if (!tool) continue;
        if (spans.length >= maxSpans) { overflow = true; continue; }
        const size = retainedSize(tool.args) + retainedSize(tool.name) + retainedSize(tool.actor) + retainedSize(tool.resource) + retainedSize(tool.callId);
        if (retained + size > maxRetainedChars) { overflow = true; continue; }
        retained += size;
        spans.push({ ...tool, seq: ++seq, receivedAt: received });
      }
    }
  }
  const quiescentAfter = at => declared.every(d => {
    const keys = d.instanceIds ? d.instanceIds.map(i => `${d.name}|${i}`) : [...exporters].filter(k => k.startsWith(`${d.name}|`));
    return keys.length > 0 && keys.every(k => (quiescent.get(k) ?? -1n) >= at);
  });
  return {
    kind: observer.kind, instanceId, source: 'otel-genai',
    scope: Object.freeze({ operations: ['tool-call'], names: tools, actorAttribution: 'principal', evidence: 'presence-only' }),
    get endpoint() { return listening ? `http://127.0.0.1:${listening}/v1/traces` : null; },
    async start() {
      if (server) return; // idempotent: the target may need the endpoint before a run starts
      server = createServer((req, res) => {
        const reply = (status, body = '{}') => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(body); };
        if (!loopbackRequestAllowed(req, listening)) { rejected++; req.resume(); return reply(403); }
        // The path is compared as text, never parsed: a target such as "//%zz" is no URL, and a throw here would end the process.
        if (req.method !== 'POST' || req.url.split('?')[0] !== '/v1/traces') return reply(404);
        const type = String(req.headers['content-type'] || '').split(';')[0].trim();
        // v1 accepts http/json only; configure exporters with OTEL_EXPORTER_OTLP_PROTOCOL=http/json.
        // A rejected export may have carried target spans: later windows may be incomplete.
        if (type !== 'application/json') { rejected++; taint ??= 'rejected-trace-export'; return reply(415, JSON.stringify({ message: 'Use OTLP http/json.' })); }
        const chunks = []; let bytes = 0, aborted = false;
        req.on('data', chunk => { bytes += chunk.length; if (bytes > OTEL_LIMITS.bodyBytes) { aborted = true; rejected++; taint ??= 'rejected-trace-export'; reply(413); req.destroy(); } else chunks.push(chunk); });
        req.on('end', () => {
          if (aborted) return;
          try {
            let raw = Buffer.concat(chunks);
            if (String(req.headers['content-encoding'] || '').toLowerCase() === 'gzip') raw = gunzipSync(raw, { maxOutputLength: OTEL_LIMITS.inflatedBytes });
            ingest(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)));
            reply(200, JSON.stringify({ partialSuccess: {} }));
          } catch { rejected++; taint ??= 'rejected-trace-export'; reply(400); }
        });
      });
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
      listening = server.address().port;
    },
    // A cursor is a wall-clock instant in Unix nanoseconds. Spans carry the
    // same clock because receiver and app share this machine (loopback only).
    async mark() { return { at: now(), seq }; },
    async collect(from, to) {
      // Wait up to the settle time for every exporter's quiescence marker.
      const deadline = to.at + BigInt(settleMs) * 1000000n;
      while (now() < deadline && !quiescentAfter(to.at)) await new Promise(resolve => setTimeout(resolve, 50));
      const events = spans.filter(s => s.end > from.at && s.start <= to.at).sort((a, b) => a.seq - b.seq).map(s => makeEffect({
        source: 'otel-genai', observer, seq: s.seq, observedAt: new Date(Number(s.end / 1000000n)).toISOString(), actor: s.actor === null ? null : principals.includes(s.actor) ? s.actor : `unlisted:${createHmac('sha256', actorKey).update(s.actor).digest('hex').slice(0, 16)}`, operation: 'tool-call', name: s.name, resource: s.resource,
        // A span still open at the window end is in flight, not yet an effect.
        outcome: s.end > to.at ? 'started' : s.outcome, correlation: { traceId: s.traceId, spanId: s.spanId, parentSpanId: s.parentSpanId, rpcId: s.callId }, content: s.args }));
      const reason = overflow ? 'span-limit-reached' : taint ?? (!quiescentAfter(to.at) ? 'no-quiescence-marker-after-window' : null);
      return { events, coverage: reason ? 'partial' : 'complete', reason };
    },
    stats() { return { toolSpans: spans.length, rejectedRequests: rejected, skewedSpans: skewed, duplicateSpans: duplicates, malformedSpans: malformed, overflow }; },
    async stop() { if (server) await new Promise(resolve => server.close(resolve)); server = null; listening = null; },
  };
}
