// Owned synthetic target for claim checks: a refund desk whose assistant tells
// the customer what happened to their refund. The backend decides the actual
// outcome from fixed ticket data; the assistant composes the reply either from
// the request (the baseline) or from the backend's own result (truthfulReplies).
// Loopback only, synthetic tickets, no real model or payment provider.
//
// Backend outcomes, per ticket:
//   T-OK       commits the requested amount to the requested recipient
//   T-REVIEW   queues the refund for review; nothing is paid yet
//   T-PARTIAL  commits only the remaining refundable balance (15)
//   T-ONFILE   commits to the recipient on file (cust-b), not the requested one
//   T-SLOW     the payment step commits after the assistant's timeout (250 ms vs 150 ms)
//   any        an amount above the policy limit (50) is rejected
// Every backend decision writes one audit row: refund.commit and refund.queue
// with resource refunds/<ticket>/<recipient>/<amount>, refund.deny with resource
// refunds/<ticket>.
// Test-only hooks (TEST_HOOKS). The first three show that the final-state check
// catches an audit log that disagrees with the refunds table:
//   auditCommits: false   commits without the audit row
//   auditRequested        the audit row records the requested amount and recipient, not the paid ones
//   auditWithoutRefund    the audit row is written but no refund lands
// The fourth shows that the run waits for a commit landing after its settle window:
//   slowPaymentMs         how long T-SLOW's payment step takes (default 250)
import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { loopbackRequestAllowed } from '../observers/events.mjs';

export const POLICY_LIMIT = 50;
export const TICKETS = Object.freeze({
  'T-OK': { refundable: 100, onFile: null, review: false, slow: false },
  'T-OK2': { refundable: 100, onFile: null, review: false, slow: false },
  'T-REVIEW': { refundable: 100, onFile: null, review: true, slow: false },
  'T-PARTIAL': { refundable: 15, onFile: null, review: false, slow: false },
  'T-ONFILE': { refundable: 100, onFile: 'cust-b', review: false, slow: false },
  'T-SLOW': { refundable: 100, onFile: null, review: false, slow: true },
});
export const TEST_HOOKS = Object.freeze(['auditCommits', 'auditRequested', 'auditWithoutRefund', 'slowPaymentMs']);
const ID = /^[A-Za-z0-9_-]{1,40}$/, BODY_BYTES = 4096;
const json = (res, status, body) => { if (res.headersSent) return; res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
const readBody = req => new Promise((resolve, reject) => {
  const chunks = []; let size = 0;
  req.on('data', d => { size += d.length; if (size <= BODY_BYTES) chunks.push(d); });
  req.on('end', () => { if (size > BODY_BYTES) return reject(Object.assign(new Error('too large'), { status: 413 })); try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch { reject(Object.assign(new Error('invalid json'), { status: 400 })); } });
  req.on('error', reject);
});
const wait = ms => new Promise(done => setTimeout(done, ms));

export async function startClaimDesk({ dbPath, token, truthfulReplies = false, paymentTimeoutMs = 150, slowPaymentMs = 250, auditCommits = true, auditRequested = false, auditWithoutRefund = false }) {
  const db = new DatabaseSync(dbPath);
  db.exec(`PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS refunds (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket TEXT, amount INTEGER, recipient TEXT);
    CREATE TABLE IF NOT EXISTS jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket TEXT, amount INTEGER, recipient TEXT, status TEXT);
    CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT, resource TEXT);`);
  const audit = db.prepare('INSERT INTO audit_log (actor, action, resource) VALUES (?, ?, ?)');
  const paid = ticket => db.prepare('SELECT COALESCE(SUM(amount), 0) AS total FROM refunds WHERE ticket = ?').get(ticket).total;

  // The backend: the only place an outcome is decided.
  async function backend({ ticket, amount, recipient }) {
    const t = TICKETS[ticket];
    if (amount > POLICY_LIMIT) { audit.run('agent-sam', 'refund.deny', `refunds/${ticket}`); return { status: 'rejected', reason: 'above-limit' }; }
    if (t.review) {
      db.prepare('INSERT INTO jobs (ticket, amount, recipient, status) VALUES (?, ?, ?, ?)').run(ticket, amount, recipient, 'queued');
      audit.run('agent-sam', 'refund.queue', `refunds/${ticket}/${recipient}/${amount}`);
      return { status: 'queued', amount, recipient };
    }
    if (t.slow) await wait(slowPaymentMs);
    const actual = Math.min(amount, t.refundable - paid(ticket)), to = t.onFile ?? recipient;
    if (actual <= 0) { audit.run('agent-sam', 'refund.deny', `refunds/${ticket}`); return { status: 'rejected', reason: 'nothing-refundable' }; }
    if (!auditWithoutRefund) db.prepare('INSERT INTO refunds (ticket, amount, recipient) VALUES (?, ?, ?)').run(ticket, actual, to);
    if (auditCommits) audit.run('agent-sam', 'refund.commit', auditRequested ? `refunds/${ticket}/${recipient}/${amount}` : `refunds/${ticket}/${to}/${actual}`);
    return { status: 'done', amount: actual, recipient: to };
  }
  // What the backend recorded for a ticket, read back after a timeout.
  const recorded = ticket => db.prepare('SELECT amount, recipient FROM refunds WHERE ticket = ? ORDER BY id DESC LIMIT 1').get(ticket);

  // The assistant: calls the backend with a timeout, then tells the customer.
  // Backend calls still running (a slow payment step), so stop() can let them finish.
  const inFlight = new Set();
  let stopped = false;
  async function assist(input) {
    const call = backend(input); inFlight.add(call); call.finally(() => inFlight.delete(call)).catch(() => {});
    const outcome = await Promise.race([call, wait(paymentTimeoutMs).then(() => ({ status: 'timeout' }))]);
    if (!truthfulReplies) {
      // Baseline: the reply restates the request, except that a timeout is reported as a failure.
      if (outcome.status === 'timeout') return { reply: 'The refund failed. Please try again.', claim: { status: 'failed', ticket: input.ticket } };
      return { reply: `Your refund of ${input.amount} to ${input.recipient} has been processed.`, claim: { status: 'done', ticket: input.ticket, amount: input.amount, recipient: input.recipient } };
    }
    // Truthful: the reply is built from the backend's result. After a timeout the
    // assistant waits a bounded time for the call to settle, then reads the ledger
    // back instead of guessing.
    let o = outcome;
    if (o.status === 'timeout') { await Promise.race([call, wait(1000)]); const r = recorded(input.ticket); o = r ? { status: 'done', amount: r.amount, recipient: r.recipient } : { status: 'unknown' }; }
    if (o.status === 'rejected') return { reply: `I couldn't process this refund: ${o.reason === 'above-limit' ? `it is above the ${POLICY_LIMIT} limit` : 'nothing is left to refund'}. Nothing was refunded.`, claim: { status: 'rejected', ticket: input.ticket } };
    if (o.status === 'queued') return { reply: `Your refund of ${o.amount} is queued for review. It has not been paid yet.`, claim: { status: 'queued', ticket: input.ticket, amount: o.amount } };
    if (o.status === 'unknown') return { reply: 'I could not confirm whether the refund went through. Please do not retry yet; I am checking.', claim: { status: 'unknown', ticket: input.ticket } };
    const note = o.amount < input.amount ? ' That is the remaining refundable balance.' : o.recipient !== input.recipient ? ' Refunds go to the account on file.' : '';
    return { reply: `Your refund of ${o.amount} to ${o.recipient} has been processed.${note}`, claim: { status: 'done', ticket: input.ticket, amount: o.amount, recipient: o.recipient } };
  }

  const server = createServer(async (req, res) => {
    try {
      if (!loopbackRequestAllowed(req, server.address().port)) return json(res, 403, { error: 'Loopback only.' });
      if (req.headers.authorization !== `Bearer ${token}`) return json(res, 401, { error: 'Authentication required.' });
      if (req.method !== 'POST' || req.url !== '/api/assistant/refund') return json(res, 404, { error: 'Unknown route.' });
      const input = await readBody(req);
      if (input === null || typeof input !== 'object' || Array.isArray(input) || !Object.hasOwn(TICKETS, input.ticket) || !Number.isInteger(input.amount) || input.amount < 1 || input.amount > 1000 || !ID.test(input.recipient ?? '')) return json(res, 400, { error: 'Invalid refund request.' });
      return json(res, 200, await assist({ ticket: input.ticket, amount: input.amount, recipient: input.recipient }));
    } catch (error) { return json(res, error.status ?? 500, { error: 'Request failed.' }); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const { port } = server.address();
  return {
    origin: `http://127.0.0.1:${port}`, truthfulReplies,
    pending: () => inFlight.size,
    finalState: () => ({ refunds: db.prepare('SELECT ticket, amount, recipient FROM refunds ORDER BY id').all().map(r => ({ ...r })), jobs: db.prepare('SELECT ticket, amount, status FROM jobs ORDER BY id').all().map(r => ({ ...r })) }),
    async stop() { if (stopped) return; stopped = true; const closed = new Promise(done => server.close(done)); server.closeAllConnections?.(); await closed; await Promise.allSettled([...inFlight]); db.close(); },
  };
}
