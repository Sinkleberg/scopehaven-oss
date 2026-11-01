// Owned synthetic target for access-change cases: a helpdesk whose assistant
// issues refunds under an owner's approval, either directly (through a payment
// step a hold gate can pause) or through a queued worker. Loopback only,
// synthetic data, no real model or payment provider.
//   Request-level checks (a suspended caller is refused; an approval belongs to
//   one user) work in every build. repairs toggles each server-side guard, so a
//   test can remove one guard and show which cases it protects:
//     commitRecheck        access, grants version and approval re-checked at
//                          commit (after the payment step, and when the worker
//                          drains a job)
//     approvalBinding      an approval covers only its ticket, amount and recipient
//     grantsVersionBinding an approval dies when the user's grants change
//     idempotentRetry      a retried job never commits a second refund
//   recheckAtCommit: true turns all four on (the repair); false turns all off.
// Test-only hooks, each showing that a check catches a specific wrong result:
//   failAfterCommitOnce   the worker's first drain commits, then fails before marking the job done
//   failBeforeCommitOnce  the worker's first drain fails before committing (the retry must commit)
//   failMidCommitOnce     the worker's first drain writes the refund and its audit row, then fails
//                         before the approval is marked used or the job done (the mark is lost)
//   overBlock             every commit is refused (a "repair" that blocks everything)
//   auditCommits: false   refunds commit without an audit row
//   insertRefunds: false  the audit row is written but no refund lands
//   parkRevokedJobs       the worker parks a suspended user's job as 'retry' instead of settling it
//   requestLevelChecks: false  a suspended caller is served and approvals are not owner-checked
import { createServer, request } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import { loopbackRequestAllowed, originForm } from '../observers/events.mjs';

export const REPAIRS = Object.freeze(['commitRecheck', 'approvalBinding', 'grantsVersionBinding', 'idempotentRetry']);
// A job in any other status is still a carrier: queued, retrying or parked work can commit later.
export const TERMINAL_JOB_STATUSES = Object.freeze(['done', 'denied']);
export const REVOKE_ACTION = 'user.suspend', REGRANT_ACTION = 'user.regrant';
const TERMINAL_LIST = TERMINAL_JOB_STATUSES.map(s => `'${s}'`).join(', ');
const BODY_BYTES = 16384, ID = /^[A-Za-z0-9_-]{1,40}$/, LOOPBACK_URL = /^http:\/\/127\.0\.0\.1:\d{1,5}$/;
const json = (res, status, body) => { if (res.headersSent) return; res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
const readBody = req => new Promise((resolve, reject) => {
  const chunks = []; let size = 0;
  // Stop buffering past the cap, but read to the end so the 413 reaches the client.
  req.on('data', d => { size += d.length; if (size <= BODY_BYTES) chunks.push(d); });
  req.on('end', () => {
    if (size > BODY_BYTES) return reject(Object.assign(new Error('too large'), { status: 413 }));
    try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch { reject(Object.assign(new Error('invalid json'), { status: 400 })); }
  });
  req.on('error', reject);
});
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
function post(url, body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const r = request(url, { method: 'POST', agent: false, headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, res => { res.resume(); res.on('end', () => resolve({ status: res.statusCode })); });
    r.on('error', reject); r.end(payload);
  });
}

export async function startAccessDesk({ dbPath, paymentsUrl, tokens, recheckAtCommit = false, repairs = {}, failAfterCommitOnce = false, failBeforeCommitOnce = false, failMidCommitOnce = false, overBlock = false, auditCommits = true, insertRefunds = true, parkRevokedJobs = false, requestLevelChecks = true }) {
  if (!LOOPBACK_URL.test(String(paymentsUrl))) throw new Error('The payment step must be a literal 127.0.0.1 origin.');
  const on = Object.fromEntries(REPAIRS.map(r => [r, Object.hasOwn(repairs, r) ? Boolean(repairs[r]) : recheckAtCommit]));
  const db = new DatabaseSync(dbPath);
  db.exec(`PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, role TEXT, suspended INTEGER DEFAULT 0, grants_version INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, user_id TEXT, ticket TEXT, amount INTEGER, recipient TEXT, grants_version INTEGER, used INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, ticket TEXT, amount INTEGER, recipient TEXT, approval_id TEXT, grants_version INTEGER, idempotency_key TEXT, status TEXT);
    CREATE TABLE IF NOT EXISTS refunds (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket TEXT, requested_by TEXT, amount INTEGER, recipient TEXT, idempotency_key TEXT);
    CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT, resource TEXT);`);
  const addUser = db.prepare('INSERT OR REPLACE INTO users (id, role, suspended, grants_version) VALUES (?, ?, 0, 1)');
  for (const [id, role] of [['agent-sam', 'agent'], ['agent-tia', 'agent'], ['owner-olga', 'owner'], ['worker-svc', 'worker']]) addUser.run(id, role);
  const audit = db.prepare('INSERT INTO audit_log (actor, action, resource) VALUES (?, ?, ?)');
  const userById = id => db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  const userByToken = token => { const id = Object.entries(tokens).find(([, t]) => t === token)?.[0]; return id ? userById(id) : undefined; };
  const authed = req => { const m = /^Bearer (.+)$/.exec(req.headers.authorization || ''); const u = m && userByToken(m[1]); return u && (!u.suspended || !requestLevelChecks) ? u : null; };
  let failedOnce = false, failedBeforeOnce = false, failedMidOnce = false;

  // Approval check. Every build asks "is this an unused approval of mine?";
  // the binding repairs also tie it to its exact target and grants version.
  const approvalProblem = (user, input) => {
    const a = typeof input.approvalId === 'string' && db.prepare('SELECT * FROM approvals WHERE id = ?').get(input.approvalId);
    if (!a || (requestLevelChecks && a.user_id !== user.id) || a.used) return 'approval-missing-or-used';
    if (on.approvalBinding && (a.ticket !== input.ticket || a.amount !== input.amount || a.recipient !== input.recipient)) return 'approval-target-mismatch';
    if (on.grantsVersionBinding && a.grants_version !== userById(user.id).grants_version) return 'approval-stale-grants';
    return null;
  };
  // Commit-time recheck: access, grants version and approval must all still
  // hold for the exact action being committed.
  const commitProblem = (userId, grantsAtStart, input) => {
    if (overBlock) return 'blocked';
    if (!on.commitRecheck) return null;
    const u = userById(userId);
    if (!u || u.suspended || u.grants_version !== grantsAtStart) return 'access-changed-before-commit';
    return approvalProblem(u, input);
  };
  const commitRefund = (userId, input, key, { markApproval = true } = {}) => {
    if (insertRefunds) db.prepare('INSERT INTO refunds (ticket, requested_by, amount, recipient, idempotency_key) VALUES (?, ?, ?, ?, ?)').run(input.ticket, userId, input.amount, input.recipient, key);
    if (markApproval) db.prepare('UPDATE approvals SET used = 1 WHERE id = ?').run(input.approvalId);
    if (auditCommits) audit.run(userId, 'refund.commit', `tickets/${input.ticket}`);
  };
  const refundInput = body => ({ ticket: String(body.ticket ?? ''), amount: Number(body.amount), recipient: String(body.recipient ?? ''), approvalId: body.approvalId });
  const validInput = input => ID.test(input.ticket) && Number.isSafeInteger(input.amount) && input.amount > 0 && input.amount <= 1000 && ID.test(input.recipient);

  const handle = async (req, res) => {
    if (!loopbackRequestAllowed(req, server.address().port) || !originForm(req.url)) return json(res, 403, { error: 'forbidden origin' });
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/api/heartbeat') return json(res, 200, { ok: true });
    const user = authed(req);
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    if (req.method !== 'POST') return json(res, 404, { error: 'not found' });
    const body = await readBody(req);
    if (!plain(body)) return json(res, 400, { error: 'body must be an object' });

    if (url.pathname.startsWith('/api/admin/')) {
      if (user.role !== 'owner') return json(res, 403, { error: 'forbidden' });
      const target = typeof body.userId === 'string' && userById(body.userId);
      if (!target) return json(res, 400, { error: 'unknown user' });
      if (url.pathname === '/api/admin/suspend' || url.pathname === '/api/admin/regrant') {
        const suspend = url.pathname === '/api/admin/suspend';
        db.prepare('UPDATE users SET suspended = ?, grants_version = grants_version + 1 WHERE id = ?').run(suspend ? 1 : 0, target.id);
        audit.run(user.id, suspend ? 'user.suspend' : 'user.regrant', `users/${target.id}`);
        return json(res, 200, { userId: target.id, suspended: suspend, grantsVersion: userById(target.id).grants_version });
      }
      if (url.pathname === '/api/admin/approve') {
        // The owner names the approval id, so a declared sequence can refer to it.
        const input = refundInput(body);
        if (!ID.test(String(body.approvalId ?? '')) || !validInput(input) || db.prepare('SELECT 1 FROM approvals WHERE id = ?').get(body.approvalId)) return json(res, 400, { error: 'invalid approval' });
        db.prepare('INSERT INTO approvals (id, user_id, ticket, amount, recipient, grants_version) VALUES (?, ?, ?, ?, ?, ?)').run(body.approvalId, target.id, input.ticket, input.amount, input.recipient, target.grants_version);
        audit.run(user.id, 'approval.create', `approvals/${body.approvalId}`);
        return json(res, 200, { approvalId: body.approvalId });
      }
      return json(res, 404, { error: 'not found' });
    }

    if (url.pathname === '/api/assistant/refund' || url.pathname === '/api/assistant/queue-refund') {
      if (user.role !== 'agent') return json(res, 403, { error: 'forbidden' });
      const input = refundInput(body);
      if (!validInput(input)) return json(res, 400, { error: 'invalid refund' });
      const problem = approvalProblem(user, input);
      if (problem) { audit.run(user.id, 'refund.denied', `tickets/${input.ticket}`); return json(res, 403, { error: problem }); }
      const grantsAtStart = user.grants_version;
      if (url.pathname === '/api/assistant/queue-refund') {
        db.prepare('INSERT INTO jobs (user_id, ticket, amount, recipient, approval_id, grants_version, idempotency_key, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
          .run(user.id, input.ticket, input.amount, input.recipient, input.approvalId, grantsAtStart, randomBytes(8).toString('hex'), 'queued');
        audit.run(user.id, 'refund.queue', `tickets/${input.ticket}`);
        return json(res, 202, { queued: true });
      }
      // The payment step is the boundary a hold gate pauses: inside the tool, before commit.
      const payment = await post(`${paymentsUrl}/v1/payments/authorize`, { amount: input.amount }).catch(() => null);
      if (!payment || payment.status !== 200) return json(res, 502, { error: 'payments unavailable' });
      const late = commitProblem(user.id, grantsAtStart, input);
      if (late) { audit.run(user.id, 'refund.denied', `tickets/${input.ticket}`); return json(res, 409, { committed: false, error: late }); }
      commitRefund(user.id, input, null);
      return json(res, 200, { committed: true });
    }

    if (url.pathname === '/api/worker/drain') {
      if (user.role !== 'worker') return json(res, 403, { error: 'forbidden' });
      const jobs = db.prepare("SELECT * FROM jobs WHERE status = 'queued' ORDER BY id").all();
      let committed = 0;
      for (const job of jobs) {
        const input = { ticket: job.ticket, amount: job.amount, recipient: job.recipient, approvalId: job.approval_id };
        if (on.idempotentRetry && db.prepare('SELECT 1 FROM refunds WHERE idempotency_key = ?').get(job.idempotency_key)) {
          db.prepare("UPDATE jobs SET status = 'done' WHERE id = ?").run(job.id); audit.run(job.user_id, 'refund.dedupe', `tickets/${job.ticket}`); continue;
        }
        if (parkRevokedJobs && userById(job.user_id).suspended) { db.prepare("UPDATE jobs SET status = 'retry' WHERE id = ?").run(job.id); continue; }
        if (failBeforeCommitOnce && !failedBeforeOnce) { failedBeforeOnce = true; return json(res, 500, { error: 'worker failed before commit' }); }
        // A drained job re-checks the original authorization, not just "the job exists".
        const problem = commitProblem(job.user_id, job.grants_version, input);
        if (problem) { db.prepare("UPDATE jobs SET status = 'denied' WHERE id = ?").run(job.id); audit.run(job.user_id, 'refund.denied', `tickets/${job.ticket}`); continue; }
        // The approval is still unused after this, so the commit-time recheck passes the retry
        // and only the job's idempotency key can stop a second refund.
        if (failMidCommitOnce && !failedMidOnce) {
          failedMidOnce = true; commitRefund(job.user_id, input, job.idempotency_key, { markApproval: false });
          return json(res, 500, { error: 'worker failed before marking the approval used' });
        }
        commitRefund(job.user_id, input, job.idempotency_key);
        committed++;
        if (failAfterCommitOnce && !failedOnce) { failedOnce = true; return json(res, 500, { error: 'worker failed after commit' }); }
        db.prepare("UPDATE jobs SET status = 'done' WHERE id = ?").run(job.id);
      }
      return json(res, 200, { drained: jobs.length, committed });
    }
    return json(res, 404, { error: 'not found' });
  };
  const server = createServer((req, res) => { handle(req, res).catch(error => json(res, error.status || 500, { error: error.status ? error.message : 'request failed' })); });
  try { await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); }); }
  catch (error) { db.close(); throw error; }
  // R3 REVOKE-CLOSE-01 needs the ROWS, not the count pendingJobs gives: which principal each
  // open job belongs to, and which grants version it carries. Each table is read on its own, so
  // one unreadable table leaves the others usable and is NAMED rather than read as emptiness -
  // the distinction between "closed" and "we could not see" is the whole point of the row.
  const closureReading = () => {
    const read = (name, sql) => { try { return db.prepare(sql).all(); } catch { unread.push(name); return null; } };
    const unread = [];
    const users = read('users', 'SELECT id, suspended, grants_version FROM users');
    const openJobs = read('jobs', `SELECT id, user_id, grants_version, status FROM jobs WHERE status NOT IN (${TERMINAL_LIST}) ORDER BY id`);
    const revocations = read('audit_log', `SELECT actor, action, resource FROM audit_log WHERE action IN ('${REVOKE_ACTION}', '${REGRANT_ACTION}') ORDER BY id`);
    return {
      users: users === null ? null : users.map(u => ({ id: String(u.id), suspended: Number(u.suspended) === 1, grantsVersion: Number(u.grants_version) })),
      openJobs: openJobs === null ? null : openJobs.map(j => ({ id: Number(j.id), userId: String(j.user_id), grantsVersion: Number(j.grants_version), status: String(j.status) })),
      revocations: revocations === null ? null : revocations.map(r => ({ actor: String(r.actor), action: String(r.action), resource: String(r.resource) })),
      unreadTables: unread,
    };
  };
  return {
    origin: `http://127.0.0.1:${server.address().port}`, address: server.address().address, repairs: { ...on },
    // The app's own final state, read after a run: refunds per ticket and jobs still waiting.
    finalState() {
      const refunds = Object.fromEntries(db.prepare('SELECT ticket, COUNT(*) AS n FROM refunds GROUP BY ticket').all().map(r => [r.ticket, Number(r.n)]));
      // Any job not in a terminal state (claimed, parked, retrying) is unsettled work.
      const pendingJobs = Number(db.prepare(`SELECT COUNT(*) AS n FROM jobs WHERE status NOT IN (${TERMINAL_LIST})`).get().n);
      return { refunds, pendingJobs, closure: closureReading() };
    },
    async stop() { await new Promise(resolve => server.close(resolve)); db.close(); },
  };
}

// A fake payment step that always authorizes. Put a hold gate in front of it.
export async function startFakePayments() {
  const server = createServer((req, res) => {
    if (!loopbackRequestAllowed(req, server.address().port)) { res.writeHead(403); res.end(); return; }
    req.resume(); req.on('end', () => json(res, 200, { authorized: true }));
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return { url: `http://127.0.0.1:${server.address().port}`, async stop() { await new Promise(resolve => server.close(resolve)); } };
}
