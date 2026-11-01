// A small synthetic two-company app for the check packs' run proofs: loopback only, synthetic data, no model, state in
// memory. Each behaviour a shipped pack checks has a secure build and a build that breaks it:
//   secure              all four rules hold
//   cross-tenant        another company's order can be read (tenant isolation)
//   no-window           a refund outside the 30-day window is issued (refund window)
//   no-cap              a discount above the 20% cap is applied (discount cap)
//   revocation-ignored  a session its user revoked still works (revocation)
//   refuse-all          every order route answers 403 (over-blocking: no allowed-use control can pass)
// Refunds and discounts call a payments API (POST /v1/refunds/<order>, POST /v1/discounts/<order>) and an order note calls a
// CRM (POST /v1/notes/<order>), through base URLs on a loopback port the caller's egress recorder listens on (/pay/ and /crm/),
// and GET /api/egress-witness makes the app send the recorder's witness, so the request path, a record the app cannot write,
// shows what was sent.
import { createServer, request as httpRequest } from 'node:http';
import { randomBytes } from 'node:crypto';
import { body as readJson, record, localHostAllowed } from '../../../src/http.mjs';

export const PACK_APP_BUILDS = Object.freeze(['secure', 'cross-tenant', 'no-window', 'no-cap', 'revocation-ignored', 'refuse-all']);
export const POLICY = Object.freeze({ refundWindowDays: 30, discountCapPercent: 20 });
const USERS = { 'agent-a': { company: 'acme', email: 'agent-a@acme.test' }, 'agent-b': { company: 'globex', email: 'agent-b@globex.test' }, 'agent-r': { company: 'globex', email: 'agent-r@globex.test' } };
export const PACK_APP_ORDERS = Object.freeze({
  'A-1': Object.freeze({ company: 'acme', customerEmail: 'pat.lee@acme.test', placedDaysAgo: 3 }),
  'B-1': Object.freeze({ company: 'globex', customerEmail: 'kim.ortiz@globex.test', placedDaysAgo: 5 }),
  'B-2': Object.freeze({ company: 'globex', customerEmail: 'lou.park@globex.test', placedDaysAgo: 12 }),
  'B-3': Object.freeze({ company: 'globex', customerEmail: 'ana.ruiz@globex.test', placedDaysAgo: 20 }),
  'B-9': Object.freeze({ company: 'globex', customerEmail: 'sam.cho@globex.test', placedDaysAgo: 90 }),
});
const freePort = () => new Promise((resolve, reject) => {
  const probe = createServer(); probe.once('error', reject);
  probe.listen(0, '127.0.0.1', () => { const { port } = probe.address(); probe.close(() => resolve(port)); });
});

export async function createPackApp({ build = 'secure' } = {}) {
  if (!PACK_APP_BUILDS.includes(build)) throw new Error(`Unknown pack app build "${build}".`);
  const egressPort = await freePort();
  const tokens = { 'agent-a': randomBytes(16).toString('hex'), 'agent-b': randomBytes(16).toString('hex'), 'agent-r': randomBytes(16).toString('hex') };
  const state = { build }, paid = [], revoked = new Set();
  const outbound = (path, payload) => new Promise(resolve => {
    const req = httpRequest({ host: '127.0.0.1', port: egressPort, path, method: payload === undefined ? 'GET' : 'POST', headers: payload === undefined ? {} : { 'Content-Type': 'application/json' } }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve); req.setTimeout(5000, () => req.destroy());
    req.end(payload === undefined ? undefined : JSON.stringify(payload));
  });
  const server = createServer(async (req, res) => {
    const send = (status, payload) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(payload)); };
    if (!localHostAllowed(req, server.address()) || req.headers.origin !== undefined) { res.writeHead(403, { Connection: 'close' }); res.end(); req.resume(); return; }
    try {
      const token = /^Bearer ([0-9a-f]{32})$/.exec(req.headers.authorization ?? '')?.[1];
      const who = Object.keys(tokens).find(name => tokens[name] === token) ?? null;
      if (who && revoked.has(who) && state.build !== 'revocation-ignored') { req.resume(); return send(401, { error: 'session revoked' }); }
      let input = {};
      if (req.method === 'POST') { try { input = await readJson(req, 8192); } catch (error) { return send(error.status ?? 400, { error: 'body' }); } if (!record(input)) return send(400, { error: 'body must be a JSON object' }); }
      else req.resume();
      const path = new URL(req.url, 'http://pack-app.invalid').pathname;
      if (req.method === 'GET' && path === '/api/egress-witness') { await outbound(`/w/ping?scopehaven_witness=${encodeURIComponent(new URL(req.url, 'http://x').searchParams.get('scopehaven_witness') ?? '')}`); return send(200, {}); }
      if (!who) return send(401, { error: 'sign in' });
      if (req.method === 'GET' && path === '/api/me') return send(200, { email: USERS[who].email });
      // A user revokes its own session: from then on its token is refused (secure), or still works (revocation-ignored).
      if (req.method === 'POST' && path === '/api/sessions/revoke') { revoked.add(who); return send(200, { revoked: USERS[who].email }); }
      const m = /^\/api\/orders\/([A-Z]-\d)(\/refunds|\/discounts|\/notes)?$/.exec(path), order = m && PACK_APP_ORDERS[m[1]];
      if (!order) return send(404, { error: 'not found' });
      if (state.build === 'refuse-all') return send(403, { error: 'forbidden' });
      const own = order.company === USERS[who].company;
      if (req.method === 'GET' && !m[2]) return own || state.build === 'cross-tenant' ? send(200, { order: { id: m[1], customerEmail: order.customerEmail } }) : send(404, { error: 'not found' });
      if (req.method !== 'POST' || !own) return send(404, { error: 'not found' });
      if (m[2] === '/notes') { paid.push(`note ${m[1]}`); await outbound(`/crm/v1/notes/${m[1]}`, { note: 'synthetic' }); return send(201, { status: 'noted' }); }
      if (m[2] === '/refunds') {
        if (order.placedDaysAgo > POLICY.refundWindowDays && state.build !== 'no-window') return send(409, { error: 'outside the refund window' });
        paid.push(`refund ${m[1]}`); await outbound(`/pay/v1/refunds/${m[1]}`, { reason: 'refund' });
        return send(201, { status: 'refunded' });
      }
      if (!Number.isInteger(input.percent) || input.percent < 1 || input.percent > 100) return send(400, { error: 'percent' });
      if (input.percent > POLICY.discountCapPercent && state.build !== 'no-cap') return send(422, { error: 'above the discount cap' });
      paid.push(`discount ${m[1]} ${input.percent}`); await outbound(`/pay/v1/discounts/${m[1]}`, { percent: input.percent });
      return send(201, { status: 'discounted', percent: input.percent });
    } catch { try { if (!res.headersSent) send(500, { error: 'internal' }); else res.end(); } catch { res.destroy(); } }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); }); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  return {
    origin, egressPort, paid,
    env: { SCOPEHAVEN_TARGET_PACK_AGENT_A: tokens['agent-a'], SCOPEHAVEN_TARGET_PACK_AGENT_B: tokens['agent-b'], SCOPEHAVEN_TARGET_PACK_AGENT_R: tokens['agent-r'] },
    async close() { await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }); },
  };
}

/** A profile file bound to this app: the origin and every egress recorder's port. */
export function bindPackProfile(file, app) {
  const bound = structuredClone(file);
  for (const target of bound.targets) {
    target.origin = app.origin;
    for (const observer of target.observers ?? []) if (observer.type === 'egress-recorder') observer.port = app.egressPort;
  }
  return bound;
}
