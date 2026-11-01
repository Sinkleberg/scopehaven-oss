// Always-attempt stand-in: a loopback, OpenAI-compatible model (chat completions and the
// Responses API) that asks for one declared action, after the check's declared route if it
// has one, and then ends the turn.
// It is the actor that tries the forbidden action, so a check can show whether the
// application refuses it rather than relying on a real model's restraint.
//
// It records what it issued (call id, tool, canonical sha256 of the arguments) and
// whether the application acknowledged each call: a later request carrying a
// role "tool" message (chat completions) or a function_call_output item (Responses)
// with that call id shows the application received the call and ran its tool step. What that tool message says is the application's own
// reply and is never used as evidence of a refusal or an effect.
// Deterministic: no weights, no network egress, no provider.
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { loopbackRequestAllowed } from '../observers/events.mjs';
import { digest } from '../../src/domain.mjs';

export const STAND_IN_MODEL = 'always-attempt-stand-in';
const BODY_BYTES = 1024 * 1024;
const TOOL = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;

// The script an always-attempt stand-in serves for one action, and its canonical hash. A route is
// the check's declared way to the action in a multi-agent application (for example a handoff to the
// agent that holds the tool): each route step is one call, issued in order before the action. It is
// part of the check, so the stand-in has no choice in it; with no route the script is unchanged.
export function attemptScript(action, finalMessage = 'Done.', route = []) {
  if (!action || typeof action !== 'object' || !TOOL.test(action.tool ?? '') || action.arguments === null || typeof action.arguments !== 'object' || Array.isArray(action.arguments)) throw new Error('An action needs a tool name and an arguments object.');
  if (typeof finalMessage !== 'string' || finalMessage.length > 2000) throw new Error('The final message must be a string of at most 2000 characters.');
  if (!Array.isArray(route) || route.length > MAX_ROUTE) throw new Error(`A route is a list of at most ${MAX_ROUTE} calls.`);
  for (const step of route) {
    if (!step || typeof step !== 'object' || !TOOL.test(step.tool ?? '') || step.arguments === null || typeof step.arguments !== 'object' || Array.isArray(step.arguments)) throw new Error('A route step needs a tool name and an arguments object.');
    // A route never calls the action's tool: that would be an attempt with other arguments.
    if (step.tool === action.tool) throw new Error('A route step cannot call the action\'s own tool.');
  }
  return [...route.map(step => ({ toolCalls: [{ name: step.tool, arguments: step.arguments }] })), { toolCalls: [{ name: action.tool, arguments: action.arguments }] }, { content: finalMessage }];
}
export const scriptSha256 = script => digest(script);
export const actionSha256 = action => digest({ tool: action.tool, arguments: action.arguments });

// fixedReplies: { [model]: content } answers every request for that model name with one fixed final
// message and does not advance the script. It is for a model the application calls beside the agent,
// such as an LLM guardrail, so the attempt is not stopped by a model's judgement before it reaches the
// application. The stand-in cannot check that a reply is a pass for whatever reads it: a fixed reply
// can itself be the hold. So the replies are part of the check (pinned by fixedRepliesSha256 and
// compared by the locus), and each one served is logged with whether the action was then pending
// (issued, not yet acknowledged); the locus never reads a run whose action path held a fixed reply.
export const fixedRepliesSha256 = (fixedReplies = {}) => {
  if (!fixedReplies || typeof fixedReplies !== 'object' || Array.isArray(fixedReplies) || !Object.entries(fixedReplies).every(([model, content]) => MODEL_NAME.test(model) && model !== STAND_IN_MODEL && typeof content === 'string' && content.length <= 2000)) throw new Error('fixedReplies maps model names to reply text.');
  return digest(fixedReplies);
};
// Serves OpenAI chat completions and the Responses API (plain JSON or streamed events). Call ids carry
// a random tag of this instance, so history replayed from another run can never acknowledge them, and
// an acknowledgement counts only for a call already issued when the request arrives.
export async function startAlwaysAttempt({ action, finalMessage = 'Done.', delayMs = 0, route = [], fixedReplies = {} }) {
  const script = attemptScript(action, finalMessage, route);
  if (!Number.isInteger(delayMs) || delayMs < 0 || delayMs > 60000) throw new Error('delayMs must be an integer from 0 to 60000.');
  const repliesSha256 = fixedRepliesSha256(fixedReplies), tag = randomBytes(6).toString('hex');
  const issued = [], acknowledged = new Set(), fixedLog = [], offered = [];
  let calls = 0, server = null;
  const actionPending = () => issued.some(i => !i.route && !acknowledged.has(i.id));
  // The next scripted step: route calls in order, then the action, then the final message for every later request.
  const nextStep = () => {
    const index = calls++, step = script[Math.min(index, script.length - 1)];
    if (!step.toolCalls) return { content: step.content, index };
    const call = step.toolCalls[0], isAction = index === route.length;
    const id = isAction ? `call_attempt_${tag}_${index}` : `call_route_${tag}_${index}`;
    issued.push({ id, tool: call.name, argumentsSha256: digest(call.arguments), ...(isAction ? {} : { route: true }) });
    return { call: { id, name: call.name, arguments: JSON.stringify(call.arguments) }, index };
  };
  server = createServer((req, res) => {
    if (!loopbackRequestAllowed(req, server.address().port)) { req.resume(); res.writeHead(403).end(); return; }
    const chunks = []; let size = 0;
    req.on('data', d => { size += d.length; if (size <= BODY_BYTES) chunks.push(d); });
    req.on('end', async () => {
      if (delayMs) await new Promise(done => setTimeout(done, delayMs));
      if (res.destroyed) return;
      const path = new URL(req.url, 'http://127.0.0.1').pathname;
      if (req.method !== 'POST' || !['/v1/chat/completions', '/v1/responses'].includes(path) || size > BODY_BYTES) { res.writeHead(404, { 'content-type': 'application/json' }).end('{}'); return; }
      let body = null; try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch {}
      const model = typeof body?.model === 'string' ? body.model : '';
      const acks = path === '/v1/chat/completions' ? (Array.isArray(body?.messages) ? body.messages : []).filter(m => m?.role === 'tool').map(m => m.tool_call_id)
        : (Array.isArray(body?.input) ? body.input : []).filter(item => item?.type === 'function_call_output').map(item => item.call_id);
      for (const id of acks) if (typeof id === 'string' && issued.some(i => i.id === id)) acknowledged.add(id);
      let step;
      if (Object.hasOwn(fixedReplies, model)) { fixedLog.push({ model, contentSha256: digest(fixedReplies[model]), actionPending: actionPending() }); step = { content: fixedReplies[model], index: -1 }; }
      else {
        step = nextStep();
        // Whether the application offered the tool the stand-in is about to call (it may not, before a route step).
        if (step.call) offered.push({ id: step.call.id, offered: toolNames(body).includes(step.call.name) });
      }
      if (path === '/v1/chat/completions') return chatReply(res, step);
      return body?.stream === true ? responsesStream(res, step) : responsesReply(res, step);
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return {
    url: `http://127.0.0.1:${server.address().port}`, script, scriptSha256: scriptSha256(script), fixedRepliesSha256: repliesSha256,
    // The attempt reached the application: it issued the declared action and a later request acknowledged that call.
    record: () => ({ issued: issued.map(i => ({ ...i })), delivered: issued.some(i => !i.route && acknowledged.has(i.id) && i.tool === action.tool && i.argumentsSha256 === digest(action.arguments)),
      offered: offered.map(o => ({ ...o })), fixedReplies: fixedLog.map(f => ({ ...f })) }),
    async stop() { await new Promise(done => server.close(done)); server.closeAllConnections?.(); },
  };
}

const MAX_ROUTE = 5;
const MODEL_NAME = /^[A-Za-z0-9_.:/-]{1,100}$/;
// Tool names a request offers: chat completions { function: { name } } or Responses { name }.
const toolNames = body => (Array.isArray(body?.tools) ? body.tools : []).map(t => t?.function?.name ?? t?.name).filter(n => typeof n === 'string');
function chatReply(res, { call, content, index }) {
  const message = call ? { role: 'assistant', content: '', tool_calls: [{ id: call.id, type: 'function', function: { name: call.name, arguments: call.arguments } }] } : { role: 'assistant', content };
  res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
  res.end(JSON.stringify({ id: `chatcmpl-stand-in-${index}`, object: 'chat.completion', model: STAND_IN_MODEL, choices: [{ index: 0, message, finish_reason: call ? 'tool_calls' : 'stop' }] }));
}
const USAGE = Object.freeze({ input_tokens: 0, input_tokens_details: { cached_tokens: 0 }, output_tokens: 0, output_tokens_details: { reasoning_tokens: 0 }, total_tokens: 0 });
function responseItem({ call, content, index }) {
  return call ? { type: 'function_call', id: `fc_stand_in_${index}`, call_id: call.id, name: call.name, arguments: call.arguments, status: 'completed' }
    : { type: 'message', id: `msg_stand_in_${index}`, role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: content, annotations: [] }] };
}
const responseObject = (step, output, status) => ({ id: `resp_stand_in_${step.index}`, object: 'response', created_at: 0, model: STAND_IN_MODEL, status, output, parallel_tool_calls: false, tool_choice: 'auto', tools: [], usage: status === 'completed' ? USAGE : null, error: null, incomplete_details: null });
function responsesReply(res, step) {
  res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
  res.end(JSON.stringify(responseObject(step, [responseItem(step)], 'completed')));
}
// The streamed form: the events an Agents SDK runner reads (output item done, then response completed).
function responsesStream(res, step) {
  const item = responseItem(step);
  const opened = step.call ? { ...item, arguments: '', status: 'in_progress' } : { ...item, status: 'in_progress', content: [] };
  let sequence = 0;
  const events = [
    { type: 'response.created', response: responseObject(step, [], 'in_progress') },
    { type: 'response.output_item.added', output_index: 0, item: opened },
    ...(step.call ? [{ type: 'response.function_call_arguments.delta', output_index: 0, item_id: item.id, delta: item.arguments }, { type: 'response.function_call_arguments.done', output_index: 0, item_id: item.id, arguments: item.arguments }]
      : [{ type: 'response.content_part.added', output_index: 0, item_id: item.id, content_index: 0, part: { type: 'output_text', text: '', annotations: [] } },
        { type: 'response.output_text.delta', output_index: 0, item_id: item.id, content_index: 0, delta: step.content, logprobs: [] },
        { type: 'response.output_text.done', output_index: 0, item_id: item.id, content_index: 0, text: step.content, logprobs: [] },
        { type: 'response.content_part.done', output_index: 0, item_id: item.id, content_index: 0, part: item.content[0] }]),
    { type: 'response.output_item.done', output_index: 0, item },
    { type: 'response.completed', response: responseObject(step, [item], 'completed') },
  ];
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'close' });
  res.end(events.map(e => `event: ${e.type}\ndata: ${JSON.stringify({ ...e, sequence_number: sequence++ })}\n\n`).join(''));
}
