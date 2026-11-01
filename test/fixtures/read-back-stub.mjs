// A loopback system of record for in-doubt resolution R2 tests (IDR-3): a ticket-notes service on 127.0.0.1 that a forwarded egress destination
// writes to and ScopeHaven's read-back reads. It answers under ScopeHaven's forward proof /2 with a secret the test passes in (a dummy), names
// each write's author by the bearer token it carries, and takes a plan per write and a hook per read, so a test can inject every fault the
// design lists: a reset before or after applying, a commit later than the settlement bound, a hidden item, a pre-existing or another
// credential's identical note, a deletion between the send and the read, a missing author, an incomplete list, a 5xx, an unproven or non-JSON
// reply, a list over the cap, a slow read. Owned synthetic data and dummy secrets only. For tests only; not in any identity list.
import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { forwardProofV2, NONCE_HEADER, PROOF_HEADER } from '../../integrations/observers/egress-forward.mjs';

const sha = buf => createHash('sha256').update(buf).digest('hex');
// A fresh note id of letters only. A hex id holds a run of exactly nine digits about one time in forty, which the capture rules redact as a
// possible personal identifier (src/body-fields.mjs secretShaped), so the recorder would record no minted id for that write and R2 would
// rightly decide nothing (every proven member must mint one recorded id): a case that needs a proven id would then read in doubt at random.
const freshId = () => `note_${randomBytes(8).toString('hex').replace(/[0-9]/g, d => 'ghijklmnop'[d])}`;
const NOTES = /^\/tickets\/([A-Za-z0-9._~-]{1,128})\/notes$/;

// secret: the forward proof secret (the destination's proofEnv value). tokens: { [bearer token]: identity }; readToken: the read credential's
// token. A write is applied, answered or cut per plan({ ticket, text, identity, key, n }) -> { apply = true, reply = 'proven' | 'reset' |
// 'reset-before' | 'hang' | 'status', status, commitAfterMs, hidden, author, keyed }; a read per readHook({ ticket, n }) -> { status, unproven,
// raw, delayMs, complete, extra, cap, after }.
export async function createReadBackStub({ secret, tokens, readToken }) {
  const tickets = new Map(), keys = new Map(), log = { writes: [], reads: [] };
  let plan = () => ({}), readHook = () => ({});
  const notesOf = t => { if (!tickets.has(t)) tickets.set(t, []); return tickets.get(t); };
  const proofOf = (req, body, status, reply) => forwardProofV2(secret, { nonce: req.headers[NONCE_HEADER] ?? '', method: req.method, path: req.url, bodySha256: sha(body), contentType: req.headers['content-type'] ?? '', status, replyBodySha256: sha(reply) });
  const answer = (req, res, body, status, payload, { unproven = false } = {}) => {
    const reply = Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload));
    const headers = { 'Content-Type': 'application/json', 'Content-Length': String(reply.length) };
    if (req.headers[NONCE_HEADER]) headers[PROOF_HEADER] = unproven ? '0'.repeat(64) : proofOf(req, body, status, reply);
    res.writeHead(status, headers); res.end(reply);
  };
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', async () => {
      const body = Buffer.concat(chunks), m = NOTES.exec(new URL(req.url, 'http://x').pathname), bearer = String(req.headers.authorization ?? '').replace(/^Bearer /, '');
      if (!m) { res.writeHead(404); res.end(); return; }
      const ticket = m[1];
      if (req.method === 'GET') {
        const n = log.reads.push({ ticket, at: performance.now(), token: bearer === readToken ? 'read' : 'other', tenant: req.headers['x-tenant'] ?? null });
        if (bearer !== readToken) return answer(req, res, body, 401, { error: 'read token required' });
        const hook = readHook({ ticket, n }) ?? {};
        if (hook.delayMs) await new Promise(resolve => setTimeout(resolve, hook.delayMs));
        if (hook.raw !== undefined) return answer(req, res, body, hook.status ?? 200, hook.raw, { unproven: hook.unproven === true });
        const listed = notesOf(ticket).filter(x => !x.hidden && x.committed).map(x => ({ id: x.id, text: x.text, ...(x.author === null ? {} : { author: x.author }), ...(x.state ? { state: x.state } : {}) }));
        const items = [...listed, ...(hook.extra ?? [])];
        answer(req, res, body, hook.status ?? 200, { notes: hook.cap ? Array.from({ length: hook.cap }, (_, i) => ({ id: `pad_${i}`, text: 'pad', author: 'other' })) : items, complete: hook.complete ?? true }, { unproven: hook.unproven === true });
        // after: a change to the backend made once this reply is built, so the next read sees it and this one does not.
        hook.after?.();
        return;
      }
      if (req.method !== 'POST') { res.writeHead(405); res.end(); return; }
      const identity = tokens[bearer] ?? null;
      let text = null;
      try { text = JSON.parse(body.toString('utf8')).body ?? null; } catch {}
      const key = req.headers['idempotency-key'] ?? null, n = log.writes.length + 1;
      const p = { apply: true, reply: 'proven', ...(plan({ ticket, text, identity, key, n }) ?? {}) };
      log.writes.push({ ticket, text, identity, key, n, plan: p, at: performance.now() });
      if (identity === null) return answer(req, res, body, 401, { error: 'write token required' });
      if (p.reply === 'reset-before') { req.socket.destroy(); return; }
      if (p.reply === 'hang') return;
      let item = null;
      if (p.keyed && key !== null && keys.has(key)) item = keys.get(key);
      else if (p.apply) {
        item = { id: freshId(), text, author: Object.hasOwn(p, 'author') ? p.author : identity, state: p.state ?? null, hidden: p.hidden === true, committed: !p.commitAfterMs };
        notesOf(ticket).push(item);
        if (p.commitAfterMs && Number.isFinite(p.commitAfterMs)) setTimeout(() => { item.committed = true; }, p.commitAfterMs);
        if (key !== null) keys.set(key, item);
      }
      if (p.reply === 'reset') { req.socket.destroy(); return; }
      if (p.reply === 'status') return answer(req, res, body, p.status ?? 503, { error: 'unavailable' });
      return answer(req, res, body, item ? 201 : 409, item ? { id: item.id, text: item.text } : { error: 'not applied' });
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {
    port: server.address().port, log,
    plan(fn) { plan = fn; }, readHook(fn) { readHook = fn; },
    // A note present before the run (committed and listed).
    seed(ticket, { id = freshId(), text, author, state = null } = {}) { const x = { id, text, author, state, hidden: false, committed: true }; notesOf(ticket).push(x); return x; },
    remove(ticket, id) { const list = notesOf(ticket), i = list.findIndex(x => x.id === id); if (i >= 0) list.splice(i, 1); },
    // Commit every note a plan held back (commitAfterMs: Infinity): a commit at a moment the test picks, such as after S2.
    commit(ticket) { for (const x of notesOf(ticket)) x.committed = true; },
    // A note another credential wrote, committed now (outside the recorder: no send of the run carries it).
    inject(ticket, { text, author }) { const x = { id: freshId(), text, author, state: null, hidden: false, committed: true }; notesOf(ticket).push(x); return x; },
    notes: ticket => notesOf(ticket).map(x => ({ ...x })),
    close: () => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }),
  };
}
