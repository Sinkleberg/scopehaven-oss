import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EXAMPLE_PLAN, PLAN_SCHEMA, createPlanner, startStandIn, validatePlan } from './server.mjs';
import { envLines, main } from './cli.mjs';

const post = async (origin, path, body, headers = {}) => {
  const res = await fetch(`${origin}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer standin-no-key-SECRET', ...headers }, body: JSON.stringify(body) });
  const text = await res.text();
  return { status: res.status, type: res.headers.get('content-type'), text, json: res.headers.get('content-type')?.includes('json') ? JSON.parse(text) : null };
};
const tools = [{ type: 'function', function: { name: 'issue_refund', parameters: { type: 'object', properties: { orderId: { type: 'string' } } } } }];
const scratch = async t => { const dir = await mkdtemp(join(tmpdir(), 'scopehaven standin ')); t.after(() => rm(dir, { recursive: true, force: true })); return dir; };

test('chat completions: a scripted tool call, then text after the tool result; streaming has the same content as SSE chunks', async t => {
  const server = await startStandIn({ plan: EXAMPLE_PLAN });
  t.after(() => server.stop());
  const first = await post(server.origin, '/v1/chat/completions', { model: 'gpt-x', messages: [{ role: 'system', content: 'You are support.' }, { role: 'user', content: 'Please refund order A-1' }], tools });
  assert.equal(first.status, 200);
  const choice = first.json.choices[0];
  assert.equal(choice.finish_reason, 'tool_calls');
  assert.equal(choice.message.content, null);
  assert.equal(choice.message.tool_calls[0].function.name, 'issue_refund');
  assert.deepEqual(JSON.parse(choice.message.tool_calls[0].function.arguments), { orderId: 'A-1', reason: 'customer asked' });
  assert.equal(first.json.model, 'scopehaven-standin');
  assert.equal(first.json.object, 'chat.completion');
  const callId = choice.message.tool_calls[0].id;
  const second = await post(server.origin, '/v1/chat/completions', { model: 'gpt-x', messages: [{ role: 'user', content: 'Please refund order A-1' }, choice.message, { role: 'tool', tool_call_id: callId, content: '{"ok":true}' }], tools });
  assert.equal(second.json.choices[0].finish_reason, 'stop');
  assert.match(second.json.choices[0].message.content, /^Done/);
  const other = await post(server.origin, '/v1/chat/completions', { model: 'gpt-x', messages: [{ role: 'user', content: 'hello' }] });
  assert.equal(other.json.choices[0].message.content, 'I can help with orders and refunds.');
  // Streaming: chunks, a usage chunk, [DONE].
  const stream = await post(server.origin, '/v1/chat/completions', { model: 'gpt-x', stream: true, messages: [{ role: 'user', content: 'Where is my order?' }] });
  assert.match(stream.type, /text\/event-stream/);
  const chunks = stream.text.split('\n\n').filter(l => l.startsWith('data: ')).map(l => l.slice(6));
  assert.equal(chunks.at(-1), '[DONE]');
  const parsed = chunks.slice(0, -1).map(c => JSON.parse(c));
  assert.ok(parsed.every(c => c.object === 'chat.completion.chunk'));
  assert.equal(parsed.filter(c => c.choices.length).map(c => c.choices[0].delta.content ?? '').join(''), 'Order A-1 belongs to the Acme account.');
  assert.equal(parsed.filter(c => c.choices.length).at(-1).choices[0].finish_reason, 'stop');
  const streamedTool = await post(server.origin, '/v1/chat/completions', { model: 'gpt-x', stream: true, messages: [{ role: 'user', content: 'refund A-1' }], tools });
  const toolChunks = streamedTool.text.split('\n\n').filter(l => l.startsWith('data: {')).map(l => JSON.parse(l.slice(6)));
  assert.equal(toolChunks.find(c => c.choices[0]?.delta.tool_calls)?.choices[0].delta.tool_calls[0].function.name, 'issue_refund');
  assert.equal(toolChunks.filter(c => c.choices.length).at(-1).choices[0].finish_reason, 'tool_calls');
  // Models, and the request log: what was sent, never the text or the credential.
  const models = await (await fetch(`${server.origin}/v1/models`)).json();
  assert.deepEqual(models.data.map(m => m.id), ['scopehaven-standin']);
  const log = await (await fetch(`${server.origin}/_standin/requests`)).json();
  assert.equal(log.count, 5);
  assert.deepEqual(log.requests[0], { ...log.requests[0], endpoint: 'chat', step: 'refund-tool', toolsOffered: ['issue_refund'], roles: ['system', 'user'], reply: { toolCalls: ['issue_refund'] }, authHeader: true, toolResult: null });
  assert.equal(log.requests[1].toolResult, 'issue_refund');
  assert.equal(log.requests[1].step, 'after-tool');
  assert.equal(JSON.stringify(log).includes('SECRET'), false);
  assert.equal(JSON.stringify(log).includes('refund order A-1'), false);
  assert.equal(server.requests().length, 5);
  const bad = await fetch(`${server.origin}/v1/embeddings`, { method: 'POST', body: '{}' });
  assert.equal(bad.status, 404);
  const notJson = await fetch(`${server.origin}/v1/chat/completions`, { method: 'POST', body: 'x' });
  assert.equal(notJson.status, 400);
});

test('responses API: function_call output items, text after a function_call_output, and the streamed event sequence', async t => {
  const server = await startStandIn({ plan: EXAMPLE_PLAN });
  t.after(() => server.stop());
  const first = await post(server.origin, '/v1/responses', { model: 'gpt-x', input: 'refund order A-1 please', tools: [{ type: 'function', name: 'issue_refund', parameters: {} }] });
  assert.equal(first.json.object, 'response');
  assert.equal(first.json.status, 'completed');
  assert.equal(first.json.output[0].type, 'function_call');
  assert.equal(first.json.output[0].name, 'issue_refund');
  assert.deepEqual(JSON.parse(first.json.output[0].arguments), { orderId: 'A-1', reason: 'customer asked' });
  const second = await post(server.origin, '/v1/responses', { model: 'gpt-x', input: [{ role: 'user', content: 'refund order A-1 please' }, first.json.output[0], { type: 'function_call_output', call_id: first.json.output[0].call_id, output: '{"ok":true}' }] });
  assert.equal(second.json.output[0].type, 'message');
  assert.match(second.json.output[0].content[0].text, /^Done/);
  assert.match(second.json.output_text, /^Done/);
  const stream = await post(server.origin, '/v1/responses', { model: 'gpt-x', stream: true, input: [{ role: 'user', content: [{ type: 'input_text', text: 'what about my order' }] }] });
  const events = stream.text.split('\n\n').filter(Boolean).map(block => { const [e, d] = block.split('\n'); return { type: e.slice(7), data: JSON.parse(d.slice(6)) }; });
  assert.deepEqual([events[0].type, events.at(-1).type], ['response.created', 'response.completed']);
  assert.equal(events.filter(e => e.type === 'response.output_text.delta').map(e => e.data.delta).join(''), 'Order A-1 belongs to the Acme account.');
  assert.ok(events.every((e, i) => e.data.sequence_number === i));
  assert.equal(events.at(-1).data.response.output[0].content[0].text, 'Order A-1 belongs to the Acme account.');
  const streamedTool = await post(server.origin, '/v1/responses', { model: 'gpt-x', stream: true, input: 'refund A-1', tools: [{ type: 'function', name: 'issue_refund' }] });
  const types = streamedTool.text.split('\n\n').filter(Boolean).map(b => b.split('\n')[0].slice(7));
  assert.ok(types.includes('response.function_call_arguments.done') && types.includes('response.output_item.done'));
});

test('the planner: once-steps, tool conditions, the default; the plan is validated; the server binds loopback only', async () => {
  const plan = { schema: PLAN_SCHEMA, model: 'm', steps: [{ id: 'one', once: true, reply: { text: 'first' } }, { id: 'tooled', when: { tools: ['a', 'b'] }, reply: { text: 'has tools' } }], default: { text: 'd' } };
  const planner = createPlanner(plan);
  const read = (tools = []) => ({ roles: ['user'], lastUserText: 'x', toolResult: null, tools, messageCount: 1 });
  assert.equal(planner.pick(read()).step, 'one');
  assert.equal(planner.pick(read()).step, 'default');
  assert.equal(planner.pick(read(['a', 'b', 'c'])).step, 'tooled');
  assert.equal(planner.pick(read(['a'])).step, 'default');
  assert.throws(() => validatePlan({ ...plan, schema: 'x' }), /schema/);
  assert.throws(() => validatePlan({ ...plan, steps: [{ reply: { toolCalls: [{ name: 'bad name', arguments: {} }] } }] }), /toolCalls/);
  assert.throws(() => validatePlan({ ...plan, steps: [{ when: { turn: 1 }, reply: { text: 'x' } }] }), /not a condition/);
  assert.throws(() => validatePlan({ ...plan, steps: [{ reply: 'text' }] }), /reply is/);
  await assert.rejects(startStandIn({ plan, host: '0.0.0.0' }), /loopback only/);
  const strict = await startStandIn({ plan: { ...plan, requireAuthHeader: true } });
  try {
    const res = await fetch(`${strict.origin}/v1/chat/completions`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"messages":[]}' });
    assert.equal(res.status, 401);
    const ok = await fetch(`${strict.origin}/v1/chat/completions`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer anything' }, body: '{"messages":[]}' });
    assert.equal(ok.status, 200);
  } finally { await strict.stop(); }
});

test('CLI: example-plan writes a plan, check validates it, serve prints the origin and the env lines, logs requests and stops', async t => {
  const dir = await scratch(t), out = [];
  assert.equal(await main(['example-plan', '--out', join(dir, 'plan.json')], { out: s => out.push(s) }), 0);
  assert.equal(await main(['check', '--plan', join(dir, 'plan.json')], { out: s => out.push(s) }), 0);
  assert.match(out.at(-1), /"steps":3/);
  let server;
  let release;
  const wait = new Promise(resolve => { release = resolve; });
  const done = main(['serve', '--plan', join(dir, 'plan.json'), '--log', join(dir, 'requests.jsonl')], { out: s => out.push(s), wait, onStart: s => { server = s; } });
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.ok(server, 'serve started');
  assert.ok(out.some(l => l.startsWith(`model stand-in listening on ${server.origin}`)));
  assert.deepEqual(envLines(server.origin), [`OPENAI_BASE_URL=${server.origin}/v1`, `OPENAI_API_BASE=${server.origin}/v1`, 'OPENAI_API_KEY=standin-no-key']);
  assert.ok(out.includes(`OPENAI_BASE_URL=${server.origin}/v1`));
  await post(server.origin, '/v1/chat/completions', { messages: [{ role: 'user', content: 'refund' }], tools });
  release();
  assert.equal(await done, 0);
  const lines = (await readFile(join(dir, 'requests.jsonl'), 'utf8')).trim().split('\n').map(l => JSON.parse(l));
  assert.equal(lines.length, 1);
  assert.equal(lines[0].step, 'refund-tool');
  assert.equal(out.at(-1), 'stopped after 1 request(s)');
  await assert.rejects(main(['serve', '--plan', join(dir, 'missing.json')]), /ENOENT|no such/);
  await writeFile(join(dir, 'bad.json'), '{"schema":"x"}');
  await assert.rejects(main(['check', '--plan', join(dir, 'bad.json')]), /schema/);
  assert.equal(await main([], { out: s => out.push(s) }), 0);
});
