// Scripted model stand-in: a loopback, OpenAI-compatible chat-completions
// endpoint that replays a declared script of tool calls and a final message.
// With the hold gate (integrations/sequences/gate.mjs) in front of it, an agent
// turn can be paused at a model call: the app has asked for its next step, and
// the answer (and any tool call in it) waits until release. A kill-switch run
// therefore tests the app's own behaviour, not a model's.
// Deterministic: no weights, no network egress, no provider.
import { createServer } from 'node:http';
import { loopbackRequestAllowed } from '../observers/events.mjs';

export const STUB_LIMITS = Object.freeze({ steps: 32, bodyBytes: 256 * 1024 });
// script: [{ toolCalls: [{ name, arguments }] } | { content }]. The last step repeats.
export function validateScript(script) {
  const ok = Array.isArray(script) && script.length >= 1 && script.length <= STUB_LIMITS.steps && script.every(step =>
    (Array.isArray(step?.toolCalls) && !('content' in step) && step.toolCalls.length >= 1 && step.toolCalls.every(c => /^[a-z_]{1,64}$/.test(c?.name ?? '') && c.arguments !== null && typeof c.arguments === 'object'))
    || (typeof step?.content === 'string' && step.content.length <= 2000 && !('toolCalls' in step)));
  if (!ok) throw new Error('A model script needs 1 to 32 steps, each a list of tool calls or a final message.');
  return script;
}

export async function startModelStub({ script, stepDelayMs = 0 }) {
  validateScript(script);
  let calls = 0;
  const served = [];
  const server = createServer((req, res) => {
    if (!loopbackRequestAllowed(req, server.address().port)) { res.writeHead(403).end(); return; }
    const chunks = []; let size = 0;
    req.on('data', d => { size += d.length; if (size <= STUB_LIMITS.bodyBytes) chunks.push(d); });
    req.on('end', async () => {
      if (req.method !== 'POST' || !req.url.startsWith('/v1/chat/completions') || size > STUB_LIMITS.bodyBytes) { res.writeHead(404, { 'Content-Type': 'application/json' }).end('{}'); return; }
      const index = calls++, step = script[Math.min(index, script.length - 1)];
      if (stepDelayMs > 0) await new Promise(done => setTimeout(done, stepDelayMs));
      const message = step.toolCalls
        ? { role: 'assistant', content: '', tool_calls: step.toolCalls.map((c, j) => ({ id: `call_${index}_${j}`, type: 'function', function: { name: c.name, arguments: JSON.stringify(c.arguments) } })) }
        : { role: 'assistant', content: step.content };
      served.push({ index, kind: step.toolCalls ? 'tool_calls' : 'content' });
      res.writeHead(200, { 'Content-Type': 'application/json', Connection: 'close' });
      res.end(JSON.stringify({ id: `chatcmpl-stub-${index}`, object: 'chat.completion', model: 'scripted-stub', choices: [{ index: 0, message, finish_reason: step.toolCalls ? 'tool_calls' : 'stop' }] }));
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return { url: `http://127.0.0.1:${server.address().port}`, served, async stop() { await new Promise(done => server.close(done)); server.closeAllConnections?.(); } };
}
