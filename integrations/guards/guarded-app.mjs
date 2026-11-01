// Owned synthetic app that installs integrations/guards, so the library can be
// shown doing its job on real loopback HTTP rather than in isolation.
//
// One task runs three effects for a signed-in agent (two notes, then a refund
// request) and then replies. A control hold pauses the task after authorization
// and before its first commit, which is the window MIDTASK-01 is about: the owner
// can suspend the agent while the task is in flight.
//
//   guards: false  the app checks access once when the request starts and composes
//                  its reply from the request. This reproduces both defects.
//   guards: true   the same app with createAccessGuard at each commit and
//                  createClaimGuard on the reply path. Nothing else differs.
//
// Loopback only, synthetic users, no model and no provider.
import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { loopbackRequestAllowed } from '../observers/events.mjs';
import { createAccessGuard, createClaimGuard, guardCommits, GuardDenied } from './guards.mjs';

export const TASK_EFFECTS = Object.freeze(['note.added', 'note.added', 'refund.requested']);
const BODY_BYTES = 8192, TICKET = /^T-[0-9]{1,6}$/;
const json = (res, status, body) => { if (res.headersSent) return; res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
const readBody = req => new Promise((resolve, reject) => {
  const chunks = []; let size = 0;
  req.on('data', d => { size += d.length; if (size <= BODY_BYTES) chunks.push(d); });
  req.on('end', () => { if (size > BODY_BYTES) return reject(Object.assign(new Error('too large'), { status: 413 })); try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch { reject(Object.assign(new Error('invalid json'), { status: 400 })); } });
  req.on('error', reject);
});

// Test-only hooks:
//   stepDelayMs       time between effects, so a suspension can land mid-task
//   failCommitAfter   the store refuses commits from this step on (the app's own
//                     effect fails), to show the claim guard on a partial outcome
//   unreadableOutcome the app cannot read back what it recorded
export async function startGuardedApp({ dbPath, tokens, guards = false, stepDelayMs = 0, failCommitAfter = null, unreadableOutcome = false }) {
  const db = new DatabaseSync(dbPath);
  db.exec(`PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, role TEXT, status TEXT DEFAULT 'active', grants_version INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket TEXT, author TEXT);
    CREATE TABLE IF NOT EXISTS refunds (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket TEXT, requested_by TEXT, amount INTEGER);
    CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT, resource TEXT);
    CREATE TABLE IF NOT EXISTS guard_log (id INTEGER PRIMARY KEY AUTOINCREMENT, entry TEXT);`);
  for (const [id, role] of [['agent-sam', 'agent'], ['agent-tia', 'agent'], ['owner-olga', 'owner']]) db.prepare('INSERT OR REPLACE INTO users (id, role) VALUES (?, ?)').run(id, role);
  const audit = db.prepare('INSERT INTO audit_log (actor, action, resource) VALUES (?, ?, ?)');
  const userById = id => db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  const caller = req => { const m = /^Bearer (.+)$/.exec(req.headers.authorization || ''); const id = m && Object.entries(tokens).find(([, t]) => t === m[1])?.[0]; return id ? userById(id) : undefined; };
  const decisions = [];
  const onDecision = entry => { decisions.push(entry); db.prepare('INSERT INTO guard_log (entry) VALUES (?)').run(JSON.stringify(entry)); };

  // The app's own live view of a principal. Read fresh from the store every call.
  const currentAccess = principalId => {
    const row = userById(principalId);
    if (!row) return null;
    return { active: row.status === 'active', grantsVersion: row.grants_version, allows: action => TASK_EFFECTS.includes(action) && row.role === 'agent' };
  };
  const accessGuard = createAccessGuard({ currentAccess, onDecision });
  const claimGuard = createClaimGuard({ onDecision });

  // A hold pauses one task between authorization and its first commit.
  const holds = new Map();
  const createHold = () => {
    let arrive, release;
    const onArrival = new Promise(done => { arrive = done; }), onRelease = new Promise(done => { release = done; });
    const hold = { arrived: false, released: false, onArrival, onRelease, arrive() { hold.arrived = true; arrive(); }, release() { hold.released = true; release(); } };
    setTimeout(() => hold.release(), 15000).unref();
    return hold;
  };

  const wait = ms => new Promise(done => setTimeout(done, ms));
  // The app's own effects. Each one writes its row and its audit line. The step counter
  // belongs to one task, so concurrent tasks never share it.
  const effectsFor = (user, step) => ({
    'note.added': ticket => { if (failCommitAfter !== null && step.n >= failCommitAfter) return false;
      db.prepare('INSERT INTO notes (ticket, author) VALUES (?, ?)').run(ticket, user.id); audit.run(user.id, 'note.added', `tickets/${ticket}`); return true; },
    'refund.requested': ticket => { if (failCommitAfter !== null && step.n >= failCommitAfter) return false;
      db.prepare('INSERT INTO refunds (ticket, requested_by, amount) VALUES (?, ?, ?)').run(ticket, user.id, 20); audit.run(user.id, 'refund.requested', `tickets/${ticket}`); return true; },
  });

  async function runTask(user, ticket, holdId) {
    const step = { n: 0 };
    const raw = effectsFor(user, step);
    // With guards on, every commit goes through beforeCommit first.
    let turn = null, run = raw;
    if (guards) {
      turn = await accessGuard.beginTurn(user.id);
      run = guardCommits({ guard: accessGuard, turn, effects: raw, resourceOf: (_action, t) => `tickets/${t}` });
    }
    const hold = holdId ? holds.get(holdId) : null;
    if (hold) { hold.arrive(); await hold.onRelease; }
    let committed = 0, stopped = null;
    try {
      for (const action of TASK_EFFECTS) {
        if (step.n > 0 && stepDelayMs > 0) await wait(stepDelayMs);
        const ok = await run[action](ticket);
        step.n += 1;
        if (ok) committed += 1;
      }
    } catch (error) {
      if (!(error instanceof GuardDenied)) throw error;
      stopped = error.reason;
      audit.run(user.id, 'task.halted', `tickets/${ticket}`);
    }
    // What the app recorded for this task, read back from its own store.
    const outcome = unreadableOutcome ? { committed: null }
      : { committed: committed === TASK_EFFECTS.length, effects: committed, expected: TASK_EFFECTS.length };
    // The baseline composes its reply from the request, which is the TRUTH-01 defect.
    let reply = `All ${TASK_EFFECTS.length} steps completed successfully for ticket ${ticket}.`;
    let claim = { status: 'done', ticket, effects: TASK_EFFECTS.length };
    let review = null;
    if (guards) {
      review = claimGuard.review({ claim, reply, record: outcome, identifiers: [ticket] });
      reply = review.reply;
      if (review.verdict !== 'supported') claim = { status: review.verdict === 'unverifiable' ? 'unknown' : 'failed', ticket };
    }
    return { reply, claim, committed, stopped, outcome, ...(review ? { review: { verdict: review.verdict, reason: review.reason, replaced: review.replaced } } : {}) };
  }

  const server = createServer(async (req, res) => {
    try {
      if (!loopbackRequestAllowed(req, server.address().port)) return json(res, 403, { error: 'Loopback only.' });
      const url = new URL(req.url, 'http://127.0.0.1');
      if (req.method === 'POST' && url.pathname === '/control/hold') {
        if (holds.size >= 8) return json(res, 400, { error: 'Too many holds.' });
        const holdId = `hold-${holds.size + 1}`; holds.set(holdId, createHold()); return json(res, 200, { holdId });
      }
      if (req.method === 'POST' && ['/control/hold-wait', '/control/hold-release'].includes(url.pathname)) {
        const data = await readBody(req); const hold = holds.get(data.holdId);
        if (!hold) return json(res, 400, { error: 'Unknown hold.' });
        if (url.pathname === '/control/hold-release') { hold.release(); return json(res, 200, { released: true }); }
        await Promise.race([hold.onArrival, new Promise(done => setTimeout(done, 5000).unref())]);
        return json(res, 200, { arrived: hold.arrived });
      }
      const user = caller(req);
      if (!user || user.status !== 'active') return json(res, 401, { error: 'Authentication required.' });
      if (req.method === 'POST' && url.pathname === '/api/task') {
        const input = await readBody(req);
        if (user.role !== 'agent' || !TICKET.test(input.ticket ?? '')) return json(res, 400, { error: 'Invalid task.' });
        if (input.holdId !== undefined && !holds.has(input.holdId)) return json(res, 400, { error: 'Unknown hold.' });
        try { return json(res, 200, await runTask(user, input.ticket, input.holdId)); }
        catch (error) { if (error instanceof GuardDenied) return json(res, 403, { error: 'Access changed.', reason: error.reason }); throw error; }
      }
      const target = /^\/api\/admin\/users\/([a-z-]{1,40})$/.exec(url.pathname);
      if (req.method === 'PATCH' && target) {
        const input = await readBody(req);
        if (user.role !== 'owner') return json(res, 403, { error: 'Owners only.' });
        if (!userById(target[1]) || !['active', 'suspended'].includes(input.status)) return json(res, 400, { error: 'Invalid change.' });
        db.prepare('UPDATE users SET status = ?, grants_version = grants_version + 1 WHERE id = ?').run(input.status, target[1]);
        audit.run(user.id, input.status === 'suspended' ? 'user.suspend' : 'user.reactivate', `users/${target[1]}`);
        return json(res, 200, { id: target[1], status: input.status });
      }
      return json(res, 404, { error: 'Unknown route.' });
    } catch (error) { return json(res, error.status ?? 500, { error: 'Request failed.' }); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  let stopped = false;
  return {
    origin: `http://127.0.0.1:${server.address().port}`, guards, decisions,
    finalState: () => ({ notes: db.prepare('SELECT ticket, author FROM notes ORDER BY id').all().map(r => ({ ...r })),
      refunds: db.prepare('SELECT ticket, requested_by, amount FROM refunds ORDER BY id').all().map(r => ({ ...r })),
      audit: db.prepare('SELECT actor, action FROM audit_log ORDER BY id').all().map(r => ({ ...r })),
      guardLog: db.prepare('SELECT entry FROM guard_log ORDER BY id').all().map(r => JSON.parse(r.entry)) }),
    async stop() { if (stopped) return; stopped = true; const closed = new Promise(done => server.close(done)); server.closeAllConnections?.(); await closed; db.close(); },
  };
}
