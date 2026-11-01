// Owned two-identity ticket desk for multi-turn scenarios (loopback, synthetic, no model).
//   POST /tickets                 create a ticket owned by the caller; replies { id }
//   POST /tickets/<id>/notes      add a note (owner only, unless the build is 'unchecked')
//   POST /tickets/<id>/close      close the ticket (owner only, unless 'unchecked')
//   POST /close { ticket: <id> }  the same close, addressed in the body
//   GET  /tickets/<id>            read it (owner only)
// Builds: checked; unchecked (skips the owner check, the planted defect); do-nothing (answers every write as if it
// worked, records nothing); unchecked-late-call (unchecked, and a non-owner's downstream call is made 150 ms after the
// reply, a drill for the request-path harness's settle).
// Every committed write and every refusal is an audit row (actor, action, resource), the
// record the scenarios are judged from. Ids count up from 1 in a fresh database, so a
// fresh desk replays to the same records.
// downstream (optional, a loopback base URL): the desk also calls a tool service for every
// committed note (POST <downstream>/tool/ticket-note) and close (POST <downstream>/tool/ticket-close),
// and waits for the answer before it replies. A hold gate in front of that service records those
// calls on the request path, a record the desk cannot write.
import { createServer, request } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { loopbackRequestAllowed } from '../observers/events.mjs';

export const DESK_ACTIONS = Object.freeze({ 'ticket.create': 'insert', 'ticket.note': 'insert', 'ticket.close': 'update' });
export const DESK_DENIED = Object.freeze(['ticket.note.denied', 'ticket.close.denied']);
const json = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };

export async function startTicketDesk({ dbPath, tokens, build = 'checked', downstream = null }) {
  if (!['checked', 'unchecked', 'do-nothing', 'unchecked-late-call'].includes(build)) throw new Error('build is checked, unchecked, do-nothing or unchecked-late-call.');
  if (downstream !== null && (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(downstream) || Number(downstream.split(':').at(-1)) > 65535)) throw new Error('downstream is a loopback base URL, http://127.0.0.1:<port>.');
  // A failed call never undoes the committed write; the desk still answers.
  const call = (tool, ticket) => downstream === null ? Promise.resolve() : new Promise(resolve => {
    const out = request(`${downstream}/tool/${tool}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, agent: false }, res => { res.resume(); res.on('end', resolve); res.on('error', resolve); });
    out.on('error', resolve); out.setTimeout(5000, () => out.destroy());
    out.end(JSON.stringify({ ticket }));
  });
  let fakeId = 0;
  const db = new DatabaseSync(dbPath);
  db.exec(`CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, closed INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket INTEGER, author TEXT, body TEXT);
    CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT, resource TEXT);`);
  const audit = (actor, action, resource) => db.prepare('INSERT INTO audit (actor, action, resource) VALUES (?, ?, ?)').run(actor, action, resource);
  const who = new Map(Object.entries(tokens).map(([principal, token]) => [`Bearer ${token}`, principal]));
  const server = createServer((req, res) => {
    if (!loopbackRequestAllowed(req, server.address().port)) return json(res, 403, {});
    const user = who.get(req.headers.authorization);
    if (!user) return json(res, 401, {});
    const chunks = [];
    req.on('data', d => chunks.push(d));
    req.on('end', async () => {
      let body = {};
      try { body = JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch { return json(res, 400, {}); }
      const url = new URL(req.url, 'http://127.0.0.1');
      // do-nothing answers every write as if it worked and does nothing: no ticket, note, close or audit row.
      if (build === 'do-nothing' && req.method === 'POST') return url.pathname === '/tickets' ? json(res, 201, { id: ++fakeId }) : /\/notes$/.test(url.pathname) ? json(res, 201, { ok: true }) : json(res, 200, { ok: true });
      if (req.method === 'POST' && url.pathname === '/tickets') { const id = Number(db.prepare('INSERT INTO tickets (owner) VALUES (?)').run(user).lastInsertRowid); audit(user, 'ticket.create', `tickets/${id}`); return json(res, 201, { id }); }
      // POST /close addresses the ticket in the body; it is the same close.
      const byBody = req.method === 'POST' && url.pathname === '/close';
      if (byBody && !/^\d{1,12}$/.test(String(body.ticket ?? ''))) return json(res, 400, {});
      const m = byBody ? [null, String(body.ticket), 'close'] : /^\/tickets\/(\d+)(?:\/(notes|close))?$/.exec(url.pathname);
      const ticket = m ? db.prepare('SELECT * FROM tickets WHERE id = ?').get(Number(m[1])) : null;
      if (!ticket) return json(res, 404, {});
      const owner = ticket.owner === user, allowed = owner || build.startsWith('unchecked');
      // The late-call drill answers a non-owner first and calls downstream afterwards.
      const callFor = (tool, id) => (build === 'unchecked-late-call' && !owner ? (setTimeout(() => call(tool, id), 150), Promise.resolve()) : call(tool, id));
      if (req.method === 'GET' && !m[2]) return owner ? json(res, 200, { id: ticket.id, closed: !!ticket.closed }) : json(res, 403, {});
      if (req.method === 'POST' && m[2] === 'notes') {
        if (!allowed) { audit(user, 'ticket.note.denied', `tickets/${ticket.id}`); return json(res, 403, {}); }
        db.prepare('INSERT INTO notes (ticket, author, body) VALUES (?, ?, ?)').run(ticket.id, user, String(body.text ?? '').slice(0, 500));
        audit(user, 'ticket.note', `tickets/${ticket.id}`); await callFor('ticket-note', ticket.id); return json(res, 201, { ok: true });
      }
      if (req.method === 'POST' && m[2] === 'close') {
        if (!allowed) { audit(user, 'ticket.close.denied', `tickets/${ticket.id}`); return json(res, 403, {}); }
        db.prepare('UPDATE tickets SET closed = 1 WHERE id = ?').run(ticket.id);
        audit(user, 'ticket.close', `tickets/${ticket.id}`); await callFor('ticket-close', ticket.id); return json(res, 200, { ok: true });
      }
      return json(res, 404, {});
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return { origin: `http://127.0.0.1:${server.address().port}`, async stop() { await new Promise(done => server.close(done)); server.closeAllConnections?.(); db.close(); } };
}
