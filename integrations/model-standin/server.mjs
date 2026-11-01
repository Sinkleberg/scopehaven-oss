// Model stand-in: an OpenAI-shaped model server on loopback that answers from a scripted plan, tool calls included,
// so a first run of an application needs no provider key and no spend. It serves
//   GET  /v1/models                 the plan's model
//   POST /v1/chat/completions       Chat Completions, JSON or SSE when the request streams
//   POST /v1/responses              the Responses API, JSON or SSE when the request streams
//   GET  /_standin/requests         what the application sent: endpoint, step chosen, tool names offered, roles, digests (never text)
// Any Authorization header is accepted and never read beyond its presence; message text is never logged (a digest is).
// The plan picks a reply per request: the first step whose "when" matches the request (a text the last user message contains,
// a tool result the last message carries, or no condition), or the plan's default. A step marked "once" is used one time.
// Binds 127.0.0.1 only; a request to bind anything else is refused.
import { createServer } from 'node:http';
import { createHash, randomUUID } from 'node:crypto';

export const PLAN_SCHEMA = 'scopehaven-model-standin-plan/1';
export const STANDIN_LIMITS = Object.freeze({ bodyBytes: 4 * 1024 * 1024, requests: 10000, steps: 200 });
const fail = message => { throw new Error(`model stand-in: ${message}`); };
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const sha = s => createHash('sha256').update(s).digest('hex');

export function validatePlan(plan) {
  if (plan?.schema !== PLAN_SCHEMA) fail(`a plan needs schema "${PLAN_SCHEMA}"`);
  if (typeof plan.model !== 'string' || !/^[A-Za-z0-9._:-]{1,80}$/.test(plan.model)) fail('model is the model id the stand-in answers as');
  if (!Array.isArray(plan.steps) || plan.steps.length > STANDIN_LIMITS.steps) fail(`steps is a list of at most ${STANDIN_LIMITS.steps}`);
  const reply = (r, where) => {
    if (!plain(r)) fail(`${where}.reply is { text } or { toolCalls: [{ name, arguments }] }`);
    if (typeof r.text === 'string') return;
    if (!Array.isArray(r.toolCalls) || !r.toolCalls.length || r.toolCalls.some(c => !plain(c) || typeof c.name !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(c.name) || !plain(c.arguments))) fail(`${where}.reply.toolCalls is a non-empty list of { name, arguments: object }`);
  };
  plan.steps.forEach((s, i) => {
    if (!plain(s)) fail(`steps[${i}] is an object`);
    if (s.id !== undefined && (typeof s.id !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(s.id))) fail(`steps[${i}].id is a short identifier`);
    if (s.when !== undefined) {
      if (!plain(s.when)) fail(`steps[${i}].when is an object`);
      for (const k of Object.keys(s.when)) if (!['contains', 'toolResult', 'tools'].includes(k)) fail(`steps[${i}].when.${k} is not a condition (contains, toolResult, tools)`);
      if (s.when.contains !== undefined && (typeof s.when.contains !== 'string' || !s.when.contains.length)) fail(`steps[${i}].when.contains is a non-empty text`);
      if (s.when.toolResult !== undefined && (typeof s.when.toolResult !== 'string' || !s.when.toolResult.length)) fail(`steps[${i}].when.toolResult is a tool name, or "any"`);
      if (s.when.tools !== undefined && (!Array.isArray(s.when.tools) || s.when.tools.some(t => typeof t !== 'string'))) fail(`steps[${i}].when.tools lists tool names the request must offer`);
    }
    if (s.once !== undefined && typeof s.once !== 'boolean') fail(`steps[${i}].once is a boolean`);
    reply(s.reply, `steps[${i}]`);
  });
  if (plan.default !== undefined) reply(plan.default, 'default');
  if (plan.requireAuthHeader !== undefined && typeof plan.requireAuthHeader !== 'boolean') fail('requireAuthHeader is a boolean');
  return plan;
}

// The conversation as the stand-in reads it, from either API: roles in order, the last user text, the last tool result's name.
function readChat(body) {
  const messages = Array.isArray(body?.messages) ? body.messages : [];
  const text = m => typeof m?.content === 'string' ? m.content : Array.isArray(m?.content) ? m.content.map(p => (typeof p?.text === 'string' ? p.text : '')).join(' ') : '';
  const roles = messages.map(m => String(m?.role ?? '?'));
  const lastUser = [...messages].reverse().find(m => m?.role === 'user');
  const last = messages.at(-1);
  const toolResult = last?.role === 'tool' ? (messages.find(m => Array.isArray(m?.tool_calls) && m.tool_calls.some(c => c?.id === last.tool_call_id))?.tool_calls.find(c => c.id === last.tool_call_id)?.function?.name ?? 'any') : null;
  const tools = (Array.isArray(body?.tools) ? body.tools : []).map(t => t?.function?.name ?? t?.name).filter(n => typeof n === 'string');
  return { roles, lastUserText: text(lastUser), toolResult, tools, messageCount: messages.length };
}
function readResponses(body) {
  const input = typeof body?.input === 'string' ? [{ role: 'user', content: body.input }] : Array.isArray(body?.input) ? body.input : [];
  const text = m => typeof m?.content === 'string' ? m.content : Array.isArray(m?.content) ? m.content.map(p => (typeof p?.text === 'string' ? p.text : '')).join(' ') : '';
  const roles = input.map(m => String(m?.type === 'function_call_output' ? 'tool' : m?.type === 'function_call' ? 'assistant' : m?.role ?? '?'));
  const lastUser = [...input].reverse().find(m => m?.role === 'user');
  const last = input.at(-1);
  const toolResult = last?.type === 'function_call_output' ? (input.find(m => m?.type === 'function_call' && m.call_id === last.call_id)?.name ?? 'any') : null;
  const tools = (Array.isArray(body?.tools) ? body.tools : []).map(t => t?.name ?? t?.function?.name).filter(n => typeof n === 'string');
  return { roles, lastUserText: text(lastUser), toolResult, tools, messageCount: input.length };
}

export function createPlanner(plan) {
  validatePlan(plan);
  const used = new Set();
  return {
    pick(read) {
      for (const [i, step] of plan.steps.entries()) {
        if (step.once && used.has(i)) continue;
        const w = step.when ?? {};
        if (w.contains !== undefined && !read.lastUserText.toLowerCase().includes(w.contains.toLowerCase())) continue;
        if (w.toolResult !== undefined && (read.toolResult === null || (w.toolResult !== 'any' && read.toolResult !== w.toolResult))) continue;
        if (w.tools !== undefined && !w.tools.every(t => read.tools.includes(t))) continue;
        if (step.once) used.add(i);
        return { step: step.id ?? `step-${i}`, reply: step.reply };
      }
      return { step: 'default', reply: plan.default ?? { text: 'Done.' } };
    },
  };
}

const readBody = (req, limit) => new Promise((resolve, reject) => {
  const chunks = []; let bytes = 0;
  req.on('data', d => { bytes += d.length; if (bytes > limit) { req.destroy(); reject(new Error('body too large')); } else chunks.push(d); });
  req.on('end', () => { try { resolve(Buffer.concat(chunks).length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch { reject(new Error('body is not JSON')); } });
  req.on('error', reject);
});
const json = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
const usage = { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 };

function chatPayload(reply, model, id) {
  const calls = reply.toolCalls?.map((c, i) => ({ id: `call_${id.slice(-8)}_${i}`, type: 'function', function: { name: c.name, arguments: JSON.stringify(c.arguments) } }));
  const message = calls ? { role: 'assistant', content: null, tool_calls: calls } : { role: 'assistant', content: reply.text };
  return { id: `chatcmpl-${id}`, object: 'chat.completion', created: Math.floor(Date.now() / 1000), model, choices: [{ index: 0, message, finish_reason: calls ? 'tool_calls' : 'stop', logprobs: null }], usage };
}
function responsesPayload(reply, model, id) {
  const output = reply.toolCalls
    ? reply.toolCalls.map((c, i) => ({ type: 'function_call', id: `fc_${id.slice(-8)}_${i}`, call_id: `call_${id.slice(-8)}_${i}`, name: c.name, arguments: JSON.stringify(c.arguments), status: 'completed' }))
    : [{ type: 'message', id: `msg_${id.slice(-8)}`, role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: reply.text, annotations: [] }] }];
  return { id: `resp_${id}`, object: 'response', created_at: Math.floor(Date.now() / 1000), status: 'completed', model, output, usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 }, ...(reply.text !== undefined ? { output_text: reply.text } : {}) };
}
function streamChat(res, payload) {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'close' });
  const base = { id: payload.id, object: 'chat.completion.chunk', created: payload.created, model: payload.model };
  const chunk = (delta, finish) => res.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta, finish_reason: finish, logprobs: null }] })}\n\n`);
  const m = payload.choices[0].message;
  chunk({ role: 'assistant', content: m.tool_calls ? null : '' }, null);
  if (m.tool_calls) m.tool_calls.forEach((c, index) => chunk({ tool_calls: [{ index, id: c.id, type: 'function', function: { name: c.function.name, arguments: c.function.arguments } }] }, null));
  else for (const piece of m.content.match(/.{1,24}/gs) ?? ['']) chunk({ content: piece }, null);
  chunk({}, payload.choices[0].finish_reason);
  res.write(`data: ${JSON.stringify({ ...base, choices: [], usage })}\n\n`);
  res.end('data: [DONE]\n\n');
}
function streamResponses(res, payload) {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'close' });
  let seq = 0;
  const event = (type, data) => res.write(`event: ${type}\ndata: ${JSON.stringify({ type, sequence_number: seq++, ...data })}\n\n`);
  const shell = { ...payload, status: 'in_progress', output: [] };
  event('response.created', { response: shell });
  event('response.in_progress', { response: shell });
  payload.output.forEach((item, output_index) => {
    event('response.output_item.added', { output_index, item: item.type === 'message' ? { ...item, status: 'in_progress', content: [] } : { ...item, status: 'in_progress', arguments: '' } });
    if (item.type === 'message') {
      event('response.content_part.added', { item_id: item.id, output_index, content_index: 0, part: { type: 'output_text', text: '', annotations: [] } });
      for (const piece of item.content[0].text.match(/.{1,24}/gs) ?? ['']) event('response.output_text.delta', { item_id: item.id, output_index, content_index: 0, delta: piece });
      event('response.output_text.done', { item_id: item.id, output_index, content_index: 0, text: item.content[0].text });
      event('response.content_part.done', { item_id: item.id, output_index, content_index: 0, part: item.content[0] });
    } else {
      event('response.function_call_arguments.delta', { item_id: item.id, output_index, delta: item.arguments });
      event('response.function_call_arguments.done', { item_id: item.id, output_index, arguments: item.arguments });
    }
    event('response.output_item.done', { output_index, item });
  });
  event('response.completed', { response: payload });
  res.end();
}

export async function startStandIn({ plan, port = 0, host = '127.0.0.1', log = null } = {}) {
  if (!['127.0.0.1', '::1'].includes(host)) fail('the stand-in binds loopback only (127.0.0.1 or ::1)');
  const planner = createPlanner(plan);
  const requests = [];
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://127.0.0.1');
      if (req.method === 'GET' && url.pathname === '/_standin/requests') return json(res, 200, { count: requests.length, requests: requests.slice(-500) });
      if (req.method === 'GET' && url.pathname === '/v1/models') { req.resume(); return json(res, 200, { object: 'list', data: [{ id: plan.model, object: 'model', created: 0, owned_by: 'scopehaven-standin' }] }); }
      const endpoint = url.pathname === '/v1/chat/completions' ? 'chat' : url.pathname === '/v1/responses' ? 'responses' : null;
      if (req.method !== 'POST' || !endpoint) { req.resume(); return json(res, 404, { error: { message: `no route ${req.method} ${url.pathname}`, type: 'invalid_request_error' } }); }
      if (plan.requireAuthHeader && req.headers.authorization === undefined) { req.resume(); return json(res, 401, { error: { message: 'missing Authorization header', type: 'invalid_request_error' } }); }
      let body;
      try { body = await readBody(req, STANDIN_LIMITS.bodyBytes); } catch (error) { return json(res, 400, { error: { message: error.message, type: 'invalid_request_error' } }); }
      const read = endpoint === 'chat' ? readChat(body) : readResponses(body);
      const { step, reply } = planner.pick(read);
      const id = randomUUID().replaceAll('-', '');
      const entry = { at: new Date().toISOString(), endpoint, model: typeof body?.model === 'string' ? body.model : null, stream: body?.stream === true, step, reply: reply.toolCalls ? { toolCalls: reply.toolCalls.map(c => c.name) } : { text: true },
        roles: read.roles, messageCount: read.messageCount, toolsOffered: read.tools, lastUserDigest: sha(read.lastUserText).slice(0, 16), lastUserChars: read.lastUserText.length, toolResult: read.toolResult, authHeader: req.headers.authorization !== undefined };
      if (requests.length < STANDIN_LIMITS.requests) requests.push(entry);
      if (typeof log === 'function') log(entry);
      const payload = endpoint === 'chat' ? chatPayload(reply, plan.model, id) : responsesPayload(reply, plan.model, id);
      if (body?.stream === true) return endpoint === 'chat' ? streamChat(res, payload) : streamResponses(res, payload);
      return json(res, 200, payload);
    } catch (error) { try { if (!res.headersSent) json(res, 500, { error: { message: 'stand-in error', type: 'server_error' } }); else res.end(); } catch { res.destroy(); } }
  });
  server.requestTimeout = 30000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, () => { server.off('error', reject); resolve(); }); });
  const origin = `http://${host === '::1' ? '[::1]' : host}:${server.address().port}`;
  return { origin, baseUrl: `${origin}/v1`, model: plan.model, requests: () => [...requests], stop: () => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }) };
}

export const EXAMPLE_PLAN = Object.freeze({
  schema: PLAN_SCHEMA, model: 'scopehaven-standin', requireAuthHeader: false,
  // Steps are tried in order: the tool-result step comes first, or the second turn (whose last user text still says "refund") would call the tool again.
  steps: [
    { id: 'after-tool', when: { toolResult: 'any' }, reply: { text: 'Done: the tool ran and I have recorded the result.' } },
    { id: 'refund-tool', when: { contains: 'refund', tools: ['issue_refund'] }, reply: { toolCalls: [{ name: 'issue_refund', arguments: { orderId: 'A-1', reason: 'customer asked' } }] } },
    { id: 'lookup', when: { contains: 'order' }, reply: { text: 'Order A-1 belongs to the Acme account.' } },
  ],
  default: { text: 'I can help with orders and refunds.' },
});
