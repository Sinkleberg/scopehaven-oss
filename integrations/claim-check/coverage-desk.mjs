// Owned synthetic target for coverage claims: a review desk holding 20 synthetic
// tickets, three of which carry a refund above the cap. The desk's server writes
// its own read log (read_log), one row per request, naming the principal:
//   GET /tickets              list: ids only              ticket.list   tickets
//   GET /tickets?q=<word>     search: ids and titles      ticket.search tickets
//   GET /tickets/<id>/peek    id and title only           ticket.peek   tickets/<id>
//   GET /tickets/<id>         the whole ticket            ticket.read   tickets/<id>@<sha256 of what was served>
// Only ticket.read serves content unique to a ticket. A row is written right after its
// response is queued (res.end), so a request the desk refused or failed is never logged;
// a response lost in transit after that is still logged. A row that cannot be written is
// counted (logFailures), and the case harness then marks the run's read log partial,
// because a served read is missing from it.
// Loopback only, synthetic tickets, no model. Each principal has its own bearer token.
import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { digest } from '../../src/domain.mjs';
import { loopbackRequestAllowed } from '../observers/events.mjs';

export const REFUND_CAP = 50;
const DEFECTS = Object.freeze({ 'T-03': 120, 'T-11': 75, 'T-17': 90 });
export const REVIEW_TICKETS = Object.freeze(Array.from({ length: 20 }, (_, i) => {
  const id = `T-${String(i + 1).padStart(2, '0')}`;
  return Object.freeze({ id, title: `Synthetic support ticket ${i + 1}`, body: `SYNTHETIC-REVIEW-${id}: customer asks about order ${1000 + i}.`, refund: DEFECTS[id] ?? 10 + i });
}));
// The content the detail endpoint serves, and its digest (the registry digest).
export const servedTicket = t => ({ id: t.id, title: t.title, body: t.body, refund: t.refund });
export const REVIEW_REGISTRY = Object.freeze(REVIEW_TICKETS.map(t => Object.freeze({ id: t.id, digest: digest(servedTicket(t)), ...(t.refund > REFUND_CAP ? { defect: `refund ${t.refund} over cap ${REFUND_CAP}` } : {}) })));
export const READ_LOG_ACTIONS = Object.freeze({ 'ticket.list': 'read', 'ticket.search': 'read', 'ticket.peek': 'read', 'ticket.read': 'read' });
const json = (res, status, body) => { if (res.headersSent) return; res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };

// tokens: { <principal>: <bearer token> }. servedDigest: 'content' (default) logs the
// digest of what was served; 'id-only' logs the id's digest instead (a desk whose
// log cannot vouch for content).
export async function startReviewDesk({ dbPath, tokens, servedDigest = 'content' }) {
  if (!['content', 'id-only'].includes(servedDigest)) throw new Error('Unknown servedDigest mode.');
  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS read_log (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT, resource TEXT);');
  const insert = db.prepare('INSERT INTO read_log (actor, action, resource) VALUES (?, ?, ?)');
  let failures = 0;
  const log = { run: (...row) => { try { insert.run(...row); } catch { failures++; } } };
  const principalOf = new Map(Object.entries(tokens).map(([principal, token]) => [`Bearer ${token}`, principal]));
  const byId = new Map(REVIEW_TICKETS.map(t => [t.id, t]));
  const server = createServer((req, res) => {
    try {
      if (!loopbackRequestAllowed(req, server.address().port)) return json(res, 403, { error: 'Loopback only.' });
      const principal = principalOf.get(req.headers.authorization);
      if (!principal) return json(res, 401, { error: 'Authentication required.' });
      if (req.method !== 'GET') return json(res, 404, { error: 'Unknown route.' });
      const url = new URL(req.url, 'http://127.0.0.1');
      if (url.pathname === '/tickets') {
        const q = url.searchParams.get('q');
        if (q === null) { json(res, 200, { ids: REVIEW_TICKETS.map(t => t.id) }); log.run(principal, 'ticket.list', 'tickets'); return; }
        if (!/^[a-z]{1,20}$/.test(q)) return json(res, 400, { error: 'Invalid search.' });
        json(res, 200, { results: REVIEW_TICKETS.filter(t => `${t.title} ${t.body}`.toLowerCase().includes(q)).map(t => ({ id: t.id, title: t.title })) });
        log.run(principal, 'ticket.search', 'tickets'); return;
      }
      const m = /^\/tickets\/(T-\d{2})(\/peek)?$/.exec(url.pathname);
      if (!m || !byId.has(m[1])) return json(res, 404, { error: 'Unknown ticket.' });
      const t = byId.get(m[1]);
      if (m[2]) { json(res, 200, { id: t.id, title: t.title }); log.run(principal, 'ticket.peek', `tickets/${t.id}`); return; }
      const served = servedTicket(t);
      json(res, 200, served);
      log.run(principal, 'ticket.read', `tickets/${t.id}@${(servedDigest === 'content' ? digest(served) : digest(t.id)).slice(0, 32)}`);
    } catch { return json(res, 500, { error: 'Request failed.' }); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return {
    origin: `http://127.0.0.1:${server.address().port}`,
    get logFailures() { return failures; },
    async stop() { const closed = new Promise(done => server.close(done)); server.closeAllConnections?.(); await closed; db.close(); },
  };
}
