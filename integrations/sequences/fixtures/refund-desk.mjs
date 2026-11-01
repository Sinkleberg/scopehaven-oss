// Owned synthetic target for in-flight lifecycle sequences: a refund desk whose agents request refunds.
// Each refund first asks an approval service (POST <upstream>/v1/approve), then commits through a refund
// tool (POST <upstream>/tool/refund), and only then records it. Put the hold gate (../gate.mjs) in front of
// <upstream>: it can hold the approval while the agent is suspended, and it records every tool call on the
// request path, a record the desk cannot write.
//   build 'unchecked-at-commit' (the defect): permission is checked when the refund starts, not when it
//     commits, so a refund held while its agent is suspended still commits through the tool on release.
//   build 'recheck-at-commit' (the repair): after approval, re-reads the agent's status and refuses (403) a
//     suspended agent before the tool call.
//   build 'halt-all' (over-blocking): once anyone is suspended, refuses every refund, so another agent's
//     allowed refund fails its control.
// Loopback only, synthetic users and data, no model. Every committed refund and every refusal is an audit
// row (actor, action, resource) in SQLite, the record the app itself keeps.
import { createServer, request } from 'node:http';
import { DatabaseSync } from 'node:sqlite';

export const REFUND_DESK_BUILDS = Object.freeze(['unchecked-at-commit', 'recheck-at-commit', 'halt-all']);
export const REFUND_DESK_USERS = Object.freeze({ 'agent-amy': 'agent', 'agent-ben': 'agent', 'owner-olga': 'owner' });
const LOOPBACK = /^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/;
const json = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
const readBody = req => new Promise(resolve => { const chunks = []; req.on('data', d => chunks.push(d)); req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch { resolve(null); } }); });
// One upstream call; any failure resolves null (the desk then answers 502 and commits nothing).
const post = (url, body) => new Promise(resolve => {
  const payload = JSON.stringify(body);
  const out = request(url, { method: 'POST', agent: false, headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, res => {
    res.resume(); res.on('end', () => resolve({ status: res.statusCode })); res.on('error', () => resolve(null));
  });
  out.on('error', () => resolve(null)); out.setTimeout(30000, () => out.destroy());
  out.end(payload);
});

export async function startRefundDesk({ dbPath, upstream, build, tokens }) {
  if (!REFUND_DESK_BUILDS.includes(build)) throw new Error(`build is one of ${REFUND_DESK_BUILDS.join(', ')}.`);
  if (!LOOPBACK.test(upstream ?? '')) throw new Error('upstream is a loopback base URL, http://127.0.0.1:<port>.');
  const db = new DatabaseSync(dbPath);
  db.exec(`PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, role TEXT, suspended INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS refunds (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket TEXT, requested_by TEXT, amount INTEGER);
    CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT, resource TEXT);`);
  for (const [id, role] of Object.entries(REFUND_DESK_USERS)) db.prepare('INSERT OR REPLACE INTO users (id, role, suspended) VALUES (?, ?, 0)').run(id, role);
  const audit = (actor, action, resource) => db.prepare('INSERT INTO audit_log (actor, action, resource) VALUES (?, ?, ?)').run(actor, action, resource);
  const userOf = req => {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || ''), id = m && Object.entries(tokens).find(([, t]) => t === m[1])?.[0];
    return id ? db.prepare('SELECT * FROM users WHERE id = ?').get(id) : undefined;
  };
  const suspended = id => db.prepare('SELECT suspended FROM users WHERE id = ?').get(id)?.suspended === 1;
  const anySuspended = () => db.prepare('SELECT COUNT(*) AS n FROM users WHERE suspended = 1').get().n > 0;
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    // The request-level check: an unknown or suspended user is refused when a request starts, in every build.
    const user = userOf(req);
    if (!user || user.suspended) { req.resume(); return json(res, 401, { error: 'unauthenticated' }); }
    if (url.pathname === '/api/whoami' && req.method === 'GET') return json(res, 200, { id: user.id });
    if (url.pathname === '/api/admin/suspend' && req.method === 'POST') {
      const body = await readBody(req);
      if (user.role !== 'owner') return json(res, 403, { error: 'forbidden' });
      if (!body || !Object.hasOwn(REFUND_DESK_USERS, body.userId)) return json(res, 400, { error: 'unknown user' });
      db.prepare('UPDATE users SET suspended = 1 WHERE id = ?').run(body.userId); audit(user.id, 'user.suspend', `users/${body.userId}`);
      return json(res, 200, { suspended: body.userId });
    }
    if (url.pathname === '/api/refunds' && req.method === 'POST') {
      const body = await readBody(req);
      if (user.role !== 'agent') return json(res, 403, { error: 'forbidden' });
      if (!body || typeof body.ticket !== 'string' || !/^T-[0-9]{1,6}$/.test(body.ticket) || !Number.isInteger(body.amount) || body.amount < 1 || body.amount > 500) return json(res, 400, { error: 'invalid refund' });
      const resource = `tickets/${body.ticket}`;
      const refuse = () => { audit(user.id, 'refund.denied', resource); return json(res, 403, { error: 'refund refused' }); };
      if (build === 'halt-all' && anySuspended()) return refuse();
      // The approval: the boundary the hold gate pauses.
      const approval = await post(`${upstream}/v1/approve`, { ticket: body.ticket, amount: body.amount });
      if (approval?.status !== 200) return json(res, 502, { error: 'approval unavailable' });
      // The commit point. Only the repair re-reads the agent's status here; halt-all stops every refund.
      if (build === 'recheck-at-commit' && suspended(user.id)) return refuse();
      if (build === 'halt-all' && anySuspended()) return refuse();
      const tool = await post(`${upstream}/tool/refund`, { ticket: body.ticket, amount: body.amount });
      if (tool?.status !== 200) return json(res, 502, { error: 'refund tool unavailable' });
      db.prepare('INSERT INTO refunds (ticket, requested_by, amount) VALUES (?, ?, ?)').run(body.ticket, user.id, body.amount);
      audit(user.id, 'refund.request', resource);
      return json(res, 200, { ok: true });
    }
    req.resume();
    return json(res, 404, { error: 'not found' });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { origin: `http://127.0.0.1:${server.address().port}`, db, async stop() { await new Promise(resolve => server.close(resolve)); db.close(); } };
}

// The approval service and the refund tool behind the gate: both answer 200 and count calls (for test
// diagnostics only; no verdict reads these counts).
export async function startRefundTools() {
  const calls = { approve: 0, refund: 0 };
  const server = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      if (req.method === 'POST' && req.url === '/v1/approve') { calls.approve++; return json(res, 200, { approved: true }); }
      if (req.method === 'POST' && req.url === '/tool/refund') { calls.refund++; return json(res, 200, { refunded: true }); }
      return json(res, 404, { error: 'not found' });
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, calls, async stop() { await new Promise(resolve => server.close(resolve)); } };
}
