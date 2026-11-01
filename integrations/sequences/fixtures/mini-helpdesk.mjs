// Owned synthetic target for observer and sequence tests: a tiny helpdesk
// with an "assistant" that asks a model what to do, then writes a ticket note
// and a refund request. Loopback only, synthetic data, no real model.
//   recheckAtCommit: false reproduces the mid-task defect (authorization is
//   checked when the task starts, not when it commits); true is the repair.
// It stores its data in SQLite, keeps an audit_log table, and exports OTLP/JSON
// tool spans when given an endpoint.
import { createServer, request } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';

const json = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
const readBody = req => new Promise(resolve => { const c = []; req.on('data', d => c.push(d)); req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(c).toString() || '{}')); } catch { resolve({}); } }); });
function post(url, body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const r = request(url, { method: 'POST', agent: false, headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, res => {
      const c = []; res.on('data', d => c.push(d)); res.on('end', () => { try { resolve({ status: res.statusCode, json: JSON.parse(Buffer.concat(c).toString() || '{}') }); } catch { resolve({ status: res.statusCode, json: null }); } });
    });
    r.on('error', reject); r.end(payload);
  });
}
const hex = n => randomBytes(n).toString('hex');
const ns = () => String(BigInt(Math.round((performance.timeOrigin + performance.now()) * 1e3)) * 1000n);

export async function startMiniHelpdesk({ dbPath, modelUrl, otlpUrl = null, recheckAtCommit = false, tokens }) {
  const db = new DatabaseSync(dbPath);
  db.exec(`PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT, role TEXT, suspended INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket TEXT, author TEXT, body TEXT);
    CREATE TABLE IF NOT EXISTS refunds (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket TEXT, requested_by TEXT, amount INTEGER);
    CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT, resource TEXT);`);
  const upsert = db.prepare('INSERT OR REPLACE INTO users (id, email, role, suspended) VALUES (?, ?, ?, 0)');
  upsert.run('agent-sam', 'sam@synthetic.test', 'agent'); upsert.run('owner-olga', 'olga@synthetic.test', 'owner');
  const audit = db.prepare('INSERT INTO audit_log (actor, action, resource) VALUES (?, ?, ?)');
  const userByToken = token => { const id = Object.entries(tokens).find(([, t]) => t === token)?.[0]; return id ? db.prepare('SELECT * FROM users WHERE id = ?').get(id) : undefined; };
  const authed = req => { const m = /^Bearer (.+)$/.exec(req.headers.authorization || ''); const u = m && userByToken(m[1]); return u && !u.suspended ? u : null; };
  const span = async (traceId, name, user, start, error = false) => {
    if (!otlpUrl) return;
    await post(otlpUrl, { resourceSpans: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: 'mini-helpdesk' } }] }, scopeSpans: [{ scope: { name: 'mini-helpdesk' }, spans: [{
      traceId, spanId: hex(8), name: `execute_tool ${name}`, kind: 1, startTimeUnixNano: start, endTimeUnixNano: ns(), status: { code: error ? 2 : 1 },
      attributes: [{ key: 'gen_ai.operation.name', value: { stringValue: 'execute_tool' } }, { key: 'gen_ai.tool.name', value: { stringValue: name } }, { key: 'enduser.id', value: { stringValue: user } }, { key: 'gen_ai.tool.call.arguments', value: { stringValue: '{"ticket":"T-1"}' } }] }] }] }] }).catch(() => {});
  };
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/api/heartbeat') {
      // This fixture posts every span before answering, so nothing is open here:
      // send the quiescence marker the trace observer needs to close a window.
      if (otlpUrl) { const t = ns(); await post(otlpUrl, { resourceSpans: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: 'mini-helpdesk' } }] }, scopeSpans: [{ scope: { name: 'mini-helpdesk' }, spans: [{
        traceId: hex(16), spanId: hex(8), name: 'scopehaven.quiescent', kind: 1, startTimeUnixNano: t, endTimeUnixNano: t, status: { code: 1 }, attributes: [{ key: 'scopehaven.quiescent', value: { boolValue: true } }] }] }] }] }).catch(() => {}); }
      return json(res, 200, { ok: true });
    }
    const user = authed(req);
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    if (url.pathname === '/api/whoami') return json(res, 200, { email: user.email });
    if (url.pathname === '/api/admin/suspend' && req.method === 'POST') {
      if (user.role !== 'owner') return json(res, 403, { error: 'forbidden' });
      const { userId } = await readBody(req);
      db.prepare('UPDATE users SET suspended = 1 WHERE id = ?').run(userId); audit.run(user.id, 'user.suspend', `users/${userId}`);
      return json(res, 200, { suspended: userId });
    }
    // The same access change as /api/admin/suspend, in the PATCH shape many admin APIs use.
    const patchUser = /^\/api\/users\/([A-Za-z0-9_-]+)$/.exec(url.pathname);
    if (patchUser && req.method === 'PATCH') {
      if (user.role !== 'owner') return json(res, 403, { error: 'forbidden' });
      const { suspended } = await readBody(req);
      if (suspended !== true) return json(res, 400, { error: 'unsupported change' });
      db.prepare('UPDATE users SET suspended = 1 WHERE id = ?').run(patchUser[1]); audit.run(user.id, 'user.suspend', `users/${patchUser[1]}`);
      return json(res, 200, { id: patchUser[1], suspended: true });
    }
    if (url.pathname === '/api/assistant/run' && req.method === 'POST') {
      const traceId = hex(16);
      // The assistant asks the model what to do. This is the boundary a hold gate pauses.
      const plan = await post(modelUrl, { messages: [{ role: 'user', content: 'Add a note to T-1 and request a 20 refund.' }] }).catch(() => null);
      if (!plan || plan.status !== 200) return json(res, 502, { error: 'model unavailable' });
      const stillAllowed = () => { const u = db.prepare('SELECT suspended FROM users WHERE id = ?').get(user.id); return !u.suspended; };
      const done = [];
      for (const tool of plan.json.tools || []) {
        const start = ns();
        if (recheckAtCommit && !stillAllowed()) { audit.run(user.id, `${tool}.denied`, 'tickets/T-1'); await span(traceId, tool, user.id, start, true); continue; }
        if (tool === 'add_note') { db.prepare('INSERT INTO notes (ticket, author, body) VALUES (?, ?, ?)').run('T-1', user.id, 'synthetic note'); audit.run(user.id, 'note.create', 'tickets/T-1'); }
        if (tool === 'request_refund') { db.prepare('INSERT INTO refunds (ticket, requested_by, amount) VALUES (?, ?, ?)').run('T-1', user.id, 20); audit.run(user.id, 'refund.request', 'tickets/T-1'); }
        await span(traceId, tool, user.id, start);
        done.push(tool);
      }
      return json(res, 200, { reply: done.length ? 'All steps completed successfully.' : 'I could not complete the steps.', completed: done });
    }
    return json(res, 404, { error: 'not found' });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { origin: `http://127.0.0.1:${server.address().port}`, db, async stop() { await new Promise(resolve => server.close(resolve)); db.close(); } };
}

// A fake model endpoint that always plans the same two tool calls.
export async function startFakeModel() {
  const server = createServer((req, res) => { req.resume(); req.on('end', () => json(res, 200, { tools: ['add_note', 'request_refund'] })); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, async stop() { await new Promise(resolve => server.close(resolve)); } };
}
