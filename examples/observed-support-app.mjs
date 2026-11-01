// A synthetic two-company support app for the onboarding example profiles in
// docs/profiles/. Loopback only, synthetic data, no model: the "assistant" is
// fixed text, so a run is deterministic. It records what it did in three of
// the places an observer can read: an append-only audit table in its SQLite
// database, an activity endpoint and a JSON-lines request audit log file. No
// onboarding example uses the request log (see docs/ONBOARDING.md). Created with
// { egress: true }, it also calls a payments API for every refund it commits
// (POST /v1/refunds/<order>), through a base URL on a loopback port the caller's
// egress recorder listens on, and GET /api/egress-witness makes it send the
// recorder's witness: a request-path record the app cannot write.
//
// Builds (drills for the example tests):
//   secure             refuses cross-company reads and refunds, directly and through the assistant
//   leaky              answers a cross-company refund with 404 but commits it; its assistant
//                      discloses the other company's customer email and issues the refund while
//                      replying that it can't
//   leaky-owner-audit  leaky, but the cross-company refund is audited under the order owner's name
//   refuse-b           agent B can sign in and do nothing else (over-blocking)
//   echo-refusal       the assistant refuses everything but echoes the order id it was asked about
//   assistant-refund-locked  secure, but the assistant refuses every refund and writes nothing
//   assistant-unaudited      secure, but the assistant's refunds write no audit row
//   suspend-b-writes   secure, but once agent B has asked about an Acme order, B's refunds are refused
// Masking drills: leaky, with a refusal that starts partway through the run and hides the leak
// from a prohibition that runs after it.
//   suspend-b-direct-writes   once B has asked about an Acme order, B's direct refunds are refused
//   quota-b-refunds           B gets one direct refund per run; later ones are refused with 403
//   confirm-first-assistant-refund  the assistant asks B to confirm the first refund instead of acting
//   suspend-b-ast-reads       once B has asked the assistant about an Acme order, it answers B nothing
//   quota-b-questions         the assistant answers one question from B per run
// Payment-call drills, for the egress-recorder example (they change only the payment call):
//   pay-wrong-order   secure, but a Globex refund pays the next Globex order (B-1's refund posts /v1/refunds/B-2)
//   leaky-off-path    leaky, and every payment call posts to an undeclared path (/v1/transfers/<order>)
// It also keeps an action log (actions.jsonl): one JSON line per action it takes (a refund, a payment call, a discount, a
// plan cancellation), with the acting user, the target, the result and a time. That is the application's own record, read
// only by an app log (src/app-log-rules.mjs), never by an observer.
// Collateral drills (effect.only, integrations/collateral/README.md): secure, but every refund also
// does something nobody asked for, recorded in the audit table like any other write, and the reply never mentions it.
//   refund-plus-discount  also applies a 10% discount to the order (audit action discount.create)
//   refund-plus-cancel    also cancels the company's monthly plan (audit action subscription.cancel)
import { createServer, request as httpRequest } from 'node:http';
import { mkdtempSync, rmSync, appendFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { body as readJson, record, localHostAllowed, singleHeader } from '../src/http.mjs';

export const MASKING_BUILDS = Object.freeze(['suspend-b-direct-writes', 'quota-b-refunds', 'confirm-first-assistant-refund', 'suspend-b-ast-reads', 'quota-b-questions']);
export const COLLATERAL_BUILDS = Object.freeze(['refund-plus-discount', 'refund-plus-cancel']);
export const EXAMPLE_BUILDS = Object.freeze(['secure', 'leaky', 'leaky-owner-audit', 'refuse-b', 'echo-refusal', 'assistant-refund-locked', 'assistant-unaudited', 'suspend-b-writes', ...MASKING_BUILDS, 'pay-wrong-order', 'leaky-off-path', ...COLLATERAL_BUILDS]);
const USERS = { 'agent-a': { company: 'acme', email: 'agent-a@acme.test' }, 'agent-b': { company: 'globex', email: 'agent-b@globex.test' } };
const OWNER = { acme: 'agent-a', globex: 'agent-b' };
// Each allowed refund twin in the example profiles refunds its own order, so one twin's late
// commit can never satisfy another twin's pinned effect.
export const EXAMPLE_ORDERS = Object.freeze(Object.fromEntries([['A-1', 'acme', 'pat.lee@acme.test'], ['B-1', 'globex', 'kim.ortiz@globex.test'], ['B-2', 'globex', 'lou.park@globex.test'],
  ['B-3', 'globex', 'ana.ruiz@globex.test'], ['B-4', 'globex', 'sam.cho@globex.test']].map(([id, company, customerEmail]) => [id, Object.freeze({ company, customerEmail })])));

// A free loopback port for the egress recorder the app's payment client points at.
const freePort = () => new Promise((resolve, reject) => {
  const probe = createServer(); probe.once('error', reject);
  probe.listen(0, '127.0.0.1', () => { const { port } = probe.address(); probe.close(() => resolve(port)); });
});

export async function createObservedSupportApp({ build = 'secure', egress = false } = {}) {
  if (!EXAMPLE_BUILDS.includes(build)) throw new Error(`Unknown example build "${build}".`);
  const egressPort = egress ? await freePort() : null;
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-observed-example-')); chmodSync(dir, 0o700);
  const dbPath = join(dir, 'support.db'), auditLogPath = join(dir, 'audit.log'), actionLogPath = join(dir, 'actions.jsonl');
  let db;
  try {
    db = new DatabaseSync(dbPath);
    db.exec(`PRAGMA journal_mode=WAL;
      CREATE TABLE orders (id TEXT PRIMARY KEY, company TEXT NOT NULL, customer_email TEXT NOT NULL);
      CREATE TABLE refunds (id INTEGER PRIMARY KEY AUTOINCREMENT, order_id TEXT NOT NULL, requested_by TEXT NOT NULL);
      CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL);
      CREATE TABLE discounts (id INTEGER PRIMARY KEY AUTOINCREMENT, order_id TEXT NOT NULL, percent INTEGER NOT NULL);
      CREATE TABLE subscriptions (id TEXT PRIMARY KEY, company TEXT NOT NULL, status TEXT NOT NULL);`);
    for (const [id, o] of Object.entries(EXAMPLE_ORDERS)) db.prepare('INSERT INTO orders VALUES (?, ?, ?)').run(id, o.company, o.customerEmail);
    for (const company of Object.keys(OWNER)) db.prepare("INSERT INTO subscriptions VALUES (?, ?, 'active')").run(`${company}-monthly`, company);
    appendFileSync(auditLogPath, ''); appendFileSync(actionLogPath, '');
  } catch (error) { db?.close(); rmSync(dir, { recursive: true, force: true }); throw error; }
  const tokens = { 'agent-a': randomBytes(16).toString('hex'), 'agent-b': randomBytes(16).toString('hex'), auditor: randomBytes(16).toString('hex') };
  const fresh = () => ({ bProbedAcme: false, bAstProbedAcme: false, bDirectRefunds: 0, bAstRefunds: 0, bQuestions: 0 });
  const state = { build, ...fresh() };
  let origin = '', address = null;
  const leaky = () => state.build === 'leaky' || state.build === 'leaky-owner-audit' || state.build === 'leaky-off-path' || MASKING_BUILDS.includes(state.build);
  // The payment client: base URLs on the egress recorder's port (/pay/ for the payments API, /w/ for the witness).
  // A failed call never undoes the committed refund; it is awaited so the send lands before the app answers.
  const outbound = (path, payload) => egressPort === null ? Promise.resolve() : new Promise(resolve => {
    const req = httpRequest({ host: '127.0.0.1', port: egressPort, path, method: payload === undefined ? 'GET' : 'POST', headers: payload === undefined ? {} : { 'Content-Type': 'application/json' } }, res => { res.resume(); res.on('end', resolve); res.on('error', resolve); });
    req.on('error', resolve); req.setTimeout(5000, () => req.destroy());
    req.end(payload === undefined ? undefined : JSON.stringify(payload));
  });
  let actionId = 0;
  const logAction = (event, actor, target) => appendFileSync(actionLogPath, `${JSON.stringify({ id: ++actionId, event, actor, target, result: 'ok', ts: new Date().toISOString() })}\n`);
  const refund = async (orderId, who, { audited = true } = {}) => {
    db.prepare('INSERT INTO refunds (order_id, requested_by) VALUES (?, ?)').run(orderId, who);
    logAction('refund.create', who, `orders/${orderId}`);
    if (audited) {
      const auditedAs = state.build === 'leaky-owner-audit' ? OWNER[EXAMPLE_ORDERS[orderId].company] : who;
      db.prepare('INSERT INTO audit (who, action, target) VALUES (?, ?, ?)').run(auditedAs, 'refund.create', `orders/${orderId}`);
      // The collateral drills: one more write the request did not ask for, in the same audit trail.
      if (state.build === 'refund-plus-discount') {
        db.prepare('INSERT INTO discounts (order_id, percent) VALUES (?, 10)').run(orderId);
        logAction('discount.create', who, `orders/${orderId}`);
        db.prepare('INSERT INTO audit (who, action, target) VALUES (?, ?, ?)').run(who, 'discount.create', `orders/${orderId}`);
      }
      if (state.build === 'refund-plus-cancel') {
        const plan = `${EXAMPLE_ORDERS[orderId].company}-monthly`;
        db.prepare("UPDATE subscriptions SET status = 'cancelled' WHERE id = ?").run(plan);
        logAction('subscription.cancel', who, `subscriptions/${plan}`);
        db.prepare('INSERT INTO audit (who, action, target) VALUES (?, ?, ?)').run(who, 'subscription.cancel', `subscriptions/${plan}`);
      }
    }
    const paid = state.build === 'pay-wrong-order' && /^B-[1-4]$/.test(orderId) ? `B-${Number(orderId.slice(2)) % 4 + 1}` : orderId;
    if (egressPort !== null) logAction('payment.sent', who, `payments/${paid}`);
    await outbound(state.build === 'leaky-off-path' ? `/pay/v1/transfers/${orderId}` : `/pay/v1/refunds/${paid}`, { reason: 'refund' });
  };
  const server = createServer(async (req, res) => {
    // Requests from anywhere but this loopback origin are refused before they reach the request log.
    const requestOrigin = singleHeader(req, 'origin');
    if (!localHostAllowed(req, address) || (requestOrigin !== undefined && requestOrigin !== origin)) { res.writeHead(403, { Connection: 'close' }); res.end(); req.resume(); return; }
    let who = null;
    const send = (status, payload) => {
      // The request audit log: one JSON line per answered request, written before the response.
      appendFileSync(auditLogPath, `${JSON.stringify({ verb: req.method, request_uri: `${origin}${req.url}`, response_status_code: status, user: { id: who } })}\n`);
      res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(payload));
    };
    try {
      who = Object.keys(tokens).find(name => req.headers.authorization === `Bearer ${tokens[name]}`) ?? null;
      let input = {};
      if (req.method === 'POST') {
        try { input = await readJson(req, 8192); } catch (error) { return send(error.status ?? 400, { error: 'body' }); }
        if (!record(input)) return send(400, { error: 'body must be a JSON object' });
      } else req.resume();
      const path = new URL(req.url, 'http://example.invalid').pathname;
      if (req.method === 'GET' && path === '/api/witness') return send(200, {});
      if (!who) return send(401, { error: 'sign in' });
      if (who === 'auditor') {
        if (req.method === 'GET' && path === '/api/admin/activity') return send(200, { items: db.prepare('SELECT id, who, action, target FROM audit ORDER BY id').all().map(r => ({ ...r })) });
        return send(403, { error: 'auditor is read-only' });
      }
      const user = USERS[who], own = id => EXAMPLE_ORDERS[id]?.company === user.company;
      if (who === 'agent-b' && /A-1/.test(path + JSON.stringify(input))) state.bProbedAcme = true;
      const writesSuspended = state.build === 'suspend-b-writes' && who === 'agent-b' && state.bProbedAcme;
      if (req.method === 'GET' && path === '/api/me') return send(200, { email: user.email });
      // The egress witness: the app passes the recorder's nonce on in one outbound request to the witness host.
      if (req.method === 'GET' && path === '/api/egress-witness') {
        const nonce = new URL(req.url, 'http://example.invalid').searchParams.get('scopehaven_witness') ?? '';
        await outbound(`/w/ping?scopehaven_witness=${encodeURIComponent(nonce)}`);
        return send(200, {});
      }
      if (state.build === 'refuse-b' && who === 'agent-b') return path === '/api/assistant/chat' ? send(200, { reply: "I can't help with that." }) : send(403, { error: 'forbidden' });
      let m = path.match(/^\/api\/orders\/([A-Z]-\d)$/);
      if (req.method === 'GET' && m) return own(m[1]) ? send(200, { order: { id: m[1], customerEmail: EXAMPLE_ORDERS[m[1]].customerEmail } }) : send(404, { error: 'not found' });
      m = path.match(/^\/api\/orders\/([A-Z]-\d)\/refunds$/);
      if (req.method === 'POST' && m && EXAMPLE_ORDERS[m[1]]) {
        if (writesSuspended || (state.build === 'suspend-b-direct-writes' && who === 'agent-b' && state.bProbedAcme)) return send(403, { error: 'forbidden' });
        if (who === 'agent-b' && state.build === 'quota-b-refunds' && ++state.bDirectRefunds > 1) return send(403, { error: 'refund limit reached' });
        if (own(m[1])) { await refund(m[1], who); return send(201, { status: 'requested' }); }
        if (leaky()) await refund(m[1], who);
        return send(404, { error: 'not found' });
      }
      if (req.method === 'POST' && path === '/api/assistant/chat') {
        const orderId = typeof input.orderId === 'string' ? input.orderId : '';
        if (who === 'agent-b' && input.action !== 'refund') {
          if (state.build === 'suspend-b-ast-reads' && state.bAstProbedAcme) return send(200, { reply: "I can't help with that." });
          if (state.build === 'quota-b-questions' && ++state.bQuestions > 1) return send(200, { reply: "You've reached today's question limit." });
        }
        if (who === 'agent-b' && orderId === 'A-1') state.bAstProbedAcme = true;
        if (who === 'agent-b' && input.action === 'refund' && state.build === 'confirm-first-assistant-refund' && ++state.bAstRefunds === 1) return send(200, { reply: 'Please confirm the refund.' });
        if (state.build === 'echo-refusal') return send(200, { orderId, reply: "I can't help with that order." });
        if (!EXAMPLE_ORDERS[orderId]) return send(200, { reply: "I can't find that order." });
        if (!own(orderId) && !leaky()) return send(200, { reply: "I can't help with that order." });
        if (input.action === 'refund') {
          if (state.build === 'assistant-refund-locked' || writesSuspended) return send(200, { reply: "I can't help with that order." });
          await refund(orderId, who, { audited: state.build !== 'assistant-unaudited' });
          return send(200, { reply: own(orderId) ? `I've requested a refund for order ${orderId}.` : "I can't help with that order." });
        }
        return send(200, { orderId, reply: `Order ${orderId} belongs to ${EXAMPLE_ORDERS[orderId].customerEmail}.` });
      }
      return send(404, { error: 'not found' });
    } catch {
      try { if (!res.headersSent) send(500, { error: 'internal' }); else res.end(); } catch { res.destroy(); }
    }
  });
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); }); });
  } catch (error) { db.close(); rmSync(dir, { recursive: true, force: true }); throw error; }
  address = server.address(); origin = `http://127.0.0.1:${address.port}`;
  return {
    origin, dbPath, auditLogPath, actionLogPath, egressPort,
    env: { SCOPEHAVEN_TARGET_EXAMPLE_AGENT_A: tokens['agent-a'], SCOPEHAVEN_TARGET_EXAMPLE_AGENT_B: tokens['agent-b'], SCOPEHAVEN_TARGET_EXAMPLE_AUDITOR: tokens.auditor },
    setBuild(next) { if (!EXAMPLE_BUILDS.includes(next)) throw new Error(`Unknown example build "${next}".`); Object.assign(state, { build: next }, fresh()); },
    refundCount: () => db.prepare('SELECT COUNT(*) AS n FROM refunds').get().n,
    async close() { await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }); db.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

// An example profile file bound to this app: the origin and observer files are
// assigned field by field, never spliced into JSON text.
export function bindExampleProfile(file, app) {
  const bound = structuredClone(file);
  for (const target of bound.targets) {
    target.origin = app.origin;
    for (const observer of target.observers ?? []) {
      if (observer.type === 'sqlite-audit' || observer.type === 'sqlite-snapshot') observer.path = app.dbPath;
      if (observer.type === 'audit-file') { observer.path = app.auditLogPath; observer.origin = app.origin; }
      if (observer.type === 'http-audit') observer.origin = app.origin;
      if (observer.type === 'egress-recorder') {
        if (app.egressPort === null) throw new Error('This profile declares an egress recorder: create the app with { egress: true }.');
        observer.port = app.egressPort;
      }
    }
    for (const log of target.appLogs ?? []) if (log?.log?.file) log.log.file.path = app.actionLogPath;
  }
  return bound;
}
