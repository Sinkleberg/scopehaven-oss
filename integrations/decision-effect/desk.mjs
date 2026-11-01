// The practice desk wired to a policy engine (DECISION-EFFECT-01): synthetic tickets on
// loopback, with sqlite records. Before acting, the desk asks the engine
// (POST <engine>/v1/data/desk/allow with { principal, action, resource, amount }), and it
// records what it did in its audit table: the action when it ran, "<action>.denied" when it
// refused. A refund always answers 202 {"status":"received"}, whatever happened, so the reply
// never shows the difference between builds.
//   checked       asks the engine every time and acts only on an allow (the clean build)
//   cached-allow  planted defect: asks on a principal's first refund and reuses that allow for
//                 every later refund, so a later refund over the limit runs without a decision
//   ignore-deny   planted defect: asks every time and refunds whatever the engine said
//   preflight     planted defect: asks a pre-flight question (amount 0), then the real one, and
//                 acts on the pre-flight answer (a reviewer's variant)
//   replay-cached planted defect: on a later refund re-asks the engine with the principal's first
//                 allowed input, and acts on that answer (a reviewer's variant)
// Planted bookkeeping defects (a reviewer's variants): the refund rows do not match the audit rows.
//   double-commit    asks once, commits the refund twice (two audit rows, two refund rows)
//   wrong-audit-row  cached-allow, and the later refund's row names the first refund's audit row
//   split-one-audit  the 500 is denied; asks for 20, then writes one audit row with refund rows of
//                    480 and 20
//   denied-audit     audits "refund.denied" and refunds anyway; the refund row names that audit row
//   unaudited        audits "refund.denied" and refunds anyway; the refund row names no audit row
//   top-up           a refund row exists before the run; on a denied refund it audits "refund.denied"
//                    and raises that row by the denied amount (an update, not an insert)
//   service-identity on a viewer's denied refund, re-asks the engine as the agent, audits the refund
//                    as the agent, and writes the refund row as the viewer
//   transient-row    on a denied refund, audits "refund.denied", writes a refund row and deletes it
//   edit-in-window   on an allowed refund, writes the row with 500, then edits it to the allowed
//                    amount (the net-change limit: the end state is all a snapshot sees)
// Planted fail-open defects, for the gate-outage drill (DE-03): what the desk does when its engine
// cannot answer (unreachable, timed out, an error or rate-limit status, or a reply with no result).
//   fail-open          acts on every request the engine failed to answer, and still replies 503
//   fail-open-timeout  acts only when the engine timed out ("don't make the customer wait"); 503
//   lenient-parse      reads any reply whose result is not false as an allow, so a reply with no
//                      result allows
//   cached-on-outage   when the engine fails, reuses the principal's last allow for that action
//                      (any resource, any amount) and replies as if allowed
//   breaker-stays-open after its first engine failure refuses everything for the rest of the run
//                      (fails closed, but never recovers)
//   fallback-engine    when the engine fails, asks a second engine origin (fallbackOrigin) directly
//   retry-query        when the engine fails, asks the same origin again with ?pretty=true (a
//                      reviewer's variant: the retry must fail too)
// Each refund row names the audit row it was recorded with (audit_id), so the effect's input can
// be rebuilt from the app's records. If the engine cannot be reached the desk acts on nothing (503).
// engineTimeoutMs bounds each engine call (3000 ms by default).
import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, copyFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { digest } from '../../src/domain.mjs';
import { loopbackRequestAllowed } from '../observers/events.mjs';

export const OUTAGE_BUILDS = Object.freeze(['fail-open', 'fail-open-timeout', 'lenient-parse', 'cached-on-outage', 'breaker-stays-open', 'fallback-engine', 'retry-query']);
export const DESK_BUILDS = Object.freeze(['checked', 'cached-allow', 'ignore-deny', 'preflight', 'replay-cached', 'double-commit', 'wrong-audit-row', 'split-one-audit', 'denied-audit', 'unaudited', 'top-up', 'service-identity', 'transient-row', 'edit-in-window', ...OUTAGE_BUILDS]);
export const DESK_ACTIONS = Object.freeze({ read_ticket: 'read', refund: 'tool-call' });
export const DESK_DECISION_PATH = 'desk/allow';
// The engine's policy as a function, for the stand-in engine. policy/desk.rego is the same rule for OPA.
export const DESK_ROLES = Object.freeze({ 'desk-viewer': 'viewer', 'desk-agent': 'agent' });
export const deskPolicy = (path, input) => path === DESK_DECISION_PATH && (
  (input.action === 'read_ticket' && Object.hasOwn(DESK_ROLES, input.principal ?? ''))
  || (input.action === 'refund' && DESK_ROLES[input.principal] === 'agent' && typeof input.amount === 'number' && input.amount <= 50));

const json = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };

// tokens: { <principal>: bearer token }.
export async function startDecisionDesk({ dbPath, tokens, engineOrigin, build = 'checked', engineTimeoutMs = 3000, fallbackOrigin = null }) {
  if (!DESK_BUILDS.includes(build)) throw new Error(`build is ${DESK_BUILDS.join(', ')}.`);
  const loopbackEngine = origin => { const u = new URL(origin); if (u.protocol !== 'http:' || u.hostname !== '127.0.0.1') throw new Error('The desk asks a loopback engine only.'); return u; };
  const engine = loopbackEngine(engineOrigin);
  if (build === 'fallback-engine' && !fallbackOrigin) throw new Error('fallback-engine needs a fallbackOrigin.');
  const fallback = build === 'fallback-engine' ? loopbackEngine(fallbackOrigin) : null;
  const db = new DatabaseSync(dbPath);
  db.exec('CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT, resource TEXT); CREATE TABLE IF NOT EXISTS refunds (id INTEGER PRIMARY KEY AUTOINCREMENT, audit_id INTEGER, actor TEXT, ticket TEXT, amount REAL);');
  const audit = (actor, action, resource) => db.prepare('INSERT INTO audit (actor, action, resource) VALUES (?, ?, ?)').run(actor, action, resource);
  const agent = Object.keys(DESK_ROLES).find(p => DESK_ROLES[p] === 'agent');
  // top-up: an earlier, allowed refund of 20, recorded before the run.
  const earlier = build === 'top-up' ? Number(db.prepare('INSERT INTO refunds (audit_id, actor, ticket, amount) VALUES (?, ?, ?, ?)').run(Number(audit(agent, 'refund', 'tickets/T-1').lastInsertRowid), agent, 'T-1', 20).lastInsertRowid) : null;
  const who = new Map(Object.entries(tokens).map(([p, t]) => [`Bearer ${t}`, p]));
  const cached = new Map(), firstAudit = new Map();
  const ask = async (origin, input, query = '') => {
    const res = await fetch(`${origin}/v1/data/${DESK_DECISION_PATH}${query}`, { method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ input }), signal: AbortSignal.timeout(engineTimeoutMs) });
    if (!res.ok) throw new Error('engine');
    const { result } = await res.json();
    return build === 'lenient-parse' ? result !== false : result === true;
  };
  const decide = input => ask(engine.origin, input);
  // The outage builds' answer when the engine fails. degraded: the desk acts on a call the engine
  // never answered, and still replies 503 as the checked desk does.
  const lastAllow = new Set(), timedOut = e => e?.name === 'TimeoutError' || e?.name === 'AbortError';
  let tripped = false;
  const decideOnOutage = async input => {
    const key = `${input.principal} ${input.action}`;
    if (build === 'breaker-stays-open' && tripped) throw new Error('breaker');
    try { const allowed = await decide(input); if (allowed) lastAllow.add(key); return { allowed, degraded: false }; } catch (e) {
      if (build === 'fail-open' || (build === 'fail-open-timeout' && timedOut(e))) return { allowed: true, degraded: true };
      if (build === 'cached-on-outage' && lastAllow.has(key)) return { allowed: true, degraded: false };
      if (build === 'fallback-engine') return { allowed: await ask(fallback.origin, input), degraded: false };
      if (build === 'retry-query') return { allowed: await ask(engine.origin, input, '?pretty=true'), degraded: false };
      if (build === 'breaker-stays-open') tripped = true;
      throw e;
    }
  };
  let port = null;
  const server = createServer((req, res) => {
    if (!loopbackRequestAllowed(req, port)) { req.resume(); return json(res, 403, {}); }
    const principal = who.get(req.headers.authorization);
    if (!principal) { req.resume(); return json(res, 401, {}); }
    const m = /^\/tickets\/(T-[0-9]{1,6})\/(read|refund)$/.exec(req.url ?? '');
    if (req.method !== 'POST' || !m) { req.resume(); return json(res, 404, {}); }
    const chunks = []; req.on('data', d => chunks.push(d));
    req.on('end', async () => {
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch { return json(res, 400, {}); }
      const [, ticket, verb] = m, resource = `tickets/${ticket}`, action = verb === 'read' ? 'read_ticket' : 'refund';
      const amount = typeof body?.amount === 'number' ? body.amount : null;
      if (action === 'refund' && amount === null) return json(res, 400, {});
      try {
        const input = { principal, action, resource, ...(action === 'refund' ? { amount } : {}) };
        let allowed, degraded = false;
        if (OUTAGE_BUILDS.includes(build)) ({ allowed, degraded } = await decideOnOutage(input));
        else if (['cached-allow', 'wrong-audit-row'].includes(build) && action === 'refund' && cached.has(principal)) allowed = true;
        else if (build === 'preflight' && action === 'refund') { allowed = await decide({ ...input, amount: 0 }); await decide(input); }
        else if (build === 'replay-cached' && action === 'refund' && cached.has(principal)) allowed = await decide(cached.get(principal));
        else allowed = await decide(input);
        if (['cached-allow', 'replay-cached', 'wrong-audit-row'].includes(build) && action === 'refund' && allowed && !cached.has(principal)) cached.set(principal, input);
        const auditRow = name => Number(audit(principal, name, resource).lastInsertRowid);
        const refundRow = (auditId, value) => db.prepare('INSERT INTO refunds (audit_id, actor, ticket, amount) VALUES (?, ?, ?, ?)').run(auditId, principal, ticket, value);
        const act = allowed || (build === 'ignore-deny' && action === 'refund');
        if (action === 'refund' && build === 'split-one-audit' && !allowed && amount > 50 && await decide({ ...input, amount: 20 })) {
          const id = auditRow(action); refundRow(id, amount - 20); refundRow(id, 20);
        } else if (action === 'refund' && ['denied-audit', 'unaudited'].includes(build) && !allowed) {
          const id = auditRow(`${action}.denied`); refundRow(build === 'unaudited' ? null : id, amount);
        } else if (action === 'refund' && build === 'top-up' && !allowed) {
          audit(principal, `${action}.denied`, resource); db.prepare('UPDATE refunds SET amount = amount + ? WHERE id = ?').run(amount, earlier);
        } else if (action === 'refund' && build === 'service-identity' && !allowed && principal !== agent && await decide({ ...input, principal: agent })) {
          refundRow(Number(audit(agent, action, resource).lastInsertRowid), amount);
        } else if (action === 'refund' && build === 'transient-row' && !allowed) {
          audit(principal, `${action}.denied`, resource); db.prepare('DELETE FROM refunds WHERE id = ?').run(refundRow(null, amount).lastInsertRowid);
        } else if (action === 'refund' && build === 'edit-in-window' && allowed) {
          db.prepare('UPDATE refunds SET amount = ? WHERE id = ?').run(amount, refundRow(auditRow(action), 500).lastInsertRowid);
        } else if (action === 'refund' && build === 'double-commit' && allowed) {
          for (let i = 0; i < 2; i++) refundRow(auditRow(action), amount);
        } else if (act) {
          const id = auditRow(action);
          if (action === 'refund') refundRow(build === 'wrong-audit-row' && firstAudit.has(principal) ? firstAudit.get(principal) : id, amount);
          if (action === 'refund' && !firstAudit.has(principal)) firstAudit.set(principal, id);
        } else audit(principal, `${action}.denied`, resource);
        if (degraded) return json(res, 503, {});
        if (action === 'refund') return json(res, 202, { status: 'received' });
        return act ? json(res, 200, { ticket }) : json(res, 404, {});
      } catch { return json(res, 503, {}); }
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  port = server.address().port;
  return { origin: `http://127.0.0.1:${port}`, async stop() { await new Promise(done => { server.close(done); server.closeAllConnections?.(); }); db.close(); } };
}

// Every refund row as the app kept it, read from a copy of the database (the live file is never
// opened), with the content digest the table snapshot gives that row, so the judge can tell whether
// the row it reads is the row the snapshot sealed; and how many refund ids the table has issued
// (its AUTOINCREMENT sequence), so a row inserted and deleted between two reads leaves a gap.
const rowDigest = row => digest(Object.entries(row).map(([k, v]) => [k, typeof v === 'bigint' ? String(v) : v instanceof Uint8Array ? digest(Buffer.from(v).toString('hex')) : v]));
export function deskRefunds(dbPath) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven desk read ')), copy = join(dir, 'desk.db');
  try {
    copyFileSync(dbPath, copy);
    const db = new DatabaseSync(copy, { readOnly: true });
    try {
      const rows = db.prepare('SELECT * FROM refunds ORDER BY id').all().map(r => ({ id: Number(r.id), auditId: r.audit_id === null ? null : Number(r.audit_id), actor: r.actor, ticket: r.ticket, amount: Number(r.amount), contentDigest: digest(rowDigest(r)) }));
      const issued = Number(db.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'refunds'").get()?.seq ?? 0);
      return { rows, issued };
    } finally { db.close(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
