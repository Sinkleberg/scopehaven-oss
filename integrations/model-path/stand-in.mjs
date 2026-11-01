// Owned stand-ins for the model path's own tests, on loopback only.
//
// startStubModel: an OpenAI-compatible chat server (and an Ollama-style /api/tags list)
// that answers its first chat call with one tool call (toolName, toolArgs) and every later
// call with a short text, as JSON or, when the request asks to stream, as SSE chunks.
// mode 'redirect' answers 302 on every route but the model list; mode 'no-tool' never calls a tool.
//
// startStandInAgent: a small agent app with its own SQLite store. POST /task (as the
// user) asks the model what to do and runs the tool call the model returns; the tool
// writes a note and an audit row. POST /admin/suspend (as the admin) removes the
// user's access. build 'start-only' authorizes the user when the task starts and never
// again; build 'recheck' re-checks access when the tool commits; build 'refuse-all' refuses
// every write (a "fix" that blocks allowed use too). This is the defect
// MIDTASK-ANY looks for, in a few lines of code, not a framework. writeFirst commits the
// write before the model call (a hold that lands too late to test anything). The
// degenerate builds the review asked about: build 'refuse-at-entry' refuses every task
// before calling the model; commitDelayMs commits that long after the tool ran, inside
// the request; deferMs answers first and commits that long after; toolCrash records the
// tool running and then fails without writing or refusing; attemptEarly records the tool
// running before the model call, and with recheckFirst a re-check build refuses before
// recording it. POST /admin/noop answers 200 and changes nothing.
import { createServer, request } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';

const json = (res, status, body) => { if (res.headersSent) return; res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
const readBody = req => new Promise((resolve, reject) => { const c = []; req.on('data', d => c.push(d)); req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(c).toString() || '{}')); } catch { resolve(null); } }); req.on('error', reject); });
const listen = async server => { await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); }); return `http://127.0.0.1:${server.address().port}`; };

export const STUB_MODEL = 'stub-model:1b';
export const STUB_DIGEST = 'a'.repeat(64);
export async function startStubModel({ mode = 'tool-call', toolName = 'write_note', toolArgs = { text: 'held turn' } } = {}) {
  let calls = 0;
  const server = createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/api/tags') return json(res, 200, { models: [{ name: STUB_MODEL, model: STUB_MODEL, digest: STUB_DIGEST }] });
    // A redirect answers 302, or the 3xx a ?status= query names.
    if (mode === 'redirect') { req.resume(); const asked = Number(new URL(req.url, 'http://127.0.0.1').searchParams.get('status')); res.writeHead(asked >= 300 && asked <= 399 ? asked : 302, { Location: `http://127.0.0.1:9${req.url}`, Connection: 'close' }); res.end(); return; }
    if (req.method !== 'POST' || req.url !== '/v1/chat/completions') return json(res, 404, {});
    const body = await readBody(req);
    const toolTurn = mode === 'tool-call' && calls++ === 0;
    const id = `chatcmpl-${randomUUID()}`, call = { id: 'call-1', type: 'function', function: { name: toolName, arguments: JSON.stringify(toolArgs) } };
    if (body?.stream === true) {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', Connection: 'close' });
      const chunk = (delta, finish) => res.write(`data: ${JSON.stringify({ id, object: 'chat.completion.chunk', created: 0, model: STUB_MODEL, choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`);
      chunk(toolTurn ? { role: 'assistant', tool_calls: [{ index: 0, ...call }] } : { role: 'assistant', content: 'Done.' }, null);
      chunk({}, toolTurn ? 'tool_calls' : 'stop');
      res.end('data: [DONE]\n\n');
      return;
    }
    return json(res, 200, { id, object: 'chat.completion', model: STUB_MODEL, choices: [{ index: 0, finish_reason: toolTurn ? 'tool_calls' : 'stop',
      message: toolTurn ? { role: 'assistant', content: null, tool_calls: [call] } : { role: 'assistant', content: 'Done.' } }] });
  });
  const origin = await listen(server);
  return { origin, stop: () => new Promise(done => { server.close(done); server.closeAllConnections(); }) };
}

// tokens: { user, admin }; modelBaseUrl: the base the agent calls (the gate's URL).
export async function startStandInAgent({ dbPath, tokens, modelBaseUrl, build, writeFirst = false, replyPadding = 0, commitDelayMs = 0, deferMs = 0, toolCrash = false, attemptEarly = false, recheckFirst = false }) {
  if (!['start-only', 'recheck', 'refuse-all', 'refuse-at-entry'].includes(build)) throw new Error('build is start-only, recheck, refuse-all or refuse-at-entry.');
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const db = new DatabaseSync(dbPath);
  db.exec(`CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, text TEXT);
    CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT, resource TEXT);`);
  const suspended = new Set();
  const callModel = body => new Promise((resolve, reject) => {
    const url = new URL('/v1/chat/completions', modelBaseUrl), payload = Buffer.from(JSON.stringify(body));
    const r = request(url, { method: 'POST', agent: false, timeout: 120000, headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length } }, res => {
      const c = []; res.on('data', d => c.push(d)); res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(c).toString()) }); } catch { resolve({ status: res.statusCode, body: null }); } });
    });
    r.on('timeout', () => r.destroy(new Error('timeout'))); r.on('error', reject); r.end(payload);
  });
  const server = createServer(async (req, res) => {
    try {
      const who = req.headers.authorization === `Bearer ${tokens.user}` ? 'user-1' : req.headers.authorization === `Bearer ${tokens.admin}` ? 'admin-1' : null;
      if (!who) return json(res, 401, { error: 'auth' });
      if (req.method === 'GET' && req.url === '/me') return json(res, 200, { user: who });
      if (req.method === 'POST' && req.url === '/admin/suspend') {
        if (who !== 'admin-1') return json(res, 403, { error: 'admin only' });
        suspended.add('user-1'); db.prepare('INSERT INTO audit (actor, action, resource) VALUES (?, ?, ?)').run('admin-1', 'user.suspend', 'users/user-1');
        return json(res, 200, { suspended: true });
      }
      if (req.method === 'POST' && req.url === '/admin/noop') return json(res, who === 'admin-1' ? 200 : 403, {});
      if (req.method === 'POST' && req.url === '/task') {
        if (who !== 'user-1') return json(res, 403, { error: 'user only' });
        await readBody(req);
        // Authorized when the task starts.
        if (build === 'refuse-at-entry' || suspended.has('user-1')) return json(res, 403, { error: 'refused' });
        const write = () => { const id = db.prepare('INSERT INTO notes (owner, text) VALUES (?, ?)').run('user-1', 'held turn').lastInsertRowid; db.prepare('INSERT INTO audit (actor, action, resource) VALUES (?, ?, ?)').run('user-1', 'note.write', `notes/${id}`); return Number(id); };
        const audit = action => db.prepare('INSERT INTO audit (actor, action, resource) VALUES (?, ?, ?)').run('user-1', action, 'notes/new');
        if (writeFirst) { audit('tool.invoked'); write(); }
        if (attemptEarly) audit('tool.invoked');
        const answer = await callModel({ model: STUB_MODEL, messages: [{ role: 'user', content: 'Write the note.' }], tools: [{ type: 'function', function: { name: 'write_note', parameters: { type: 'object' } } }] });
        const call = answer.body?.choices?.[0]?.message?.tool_calls?.[0];
        if (answer.status !== 200 || call?.function?.name !== 'write_note') return json(res, 502, { error: 'no tool call' });
        if (writeFirst) return json(res, 200, { wrote: 'before the model call' });
        // The tool runs here and commits. Only the recheck build asks again.
        const refuse = () => { audit('note.denied'); return json(res, 403, { error: 'access changed before the write' }); };
        if (recheckFirst && build === 'recheck' && suspended.has('user-1')) return refuse();
        audit('tool.invoked');
        if (toolCrash) return json(res, 500, { error: 'tool raised' });
        if (build === 'refuse-all' || (build === 'recheck' && suspended.has('user-1'))) return refuse();
        if (commitDelayMs) await sleep(commitDelayMs);
        if (deferMs) { json(res, 200, { queued: true }); await sleep(deferMs); write(); return; }
        return json(res, 200, { wrote: write(), ...(replyPadding ? { padding: 'x'.repeat(replyPadding) } : {}) });
      }
      return json(res, 404, {});
    } catch { return json(res, 500, { error: 'failed' }); }
  });
  const origin = await listen(server);
  return { origin, stop: async () => { await new Promise(done => { server.close(done); server.closeAllConnections(); }); db.close(); } };
}
