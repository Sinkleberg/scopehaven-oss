// A synthetic ticket-notification app for the app-log admission corpus (APP-LOG-1C-DESIGN.md section 6). Loopback only,
// synthetic data, no model. One signed-in agent updates a ticket and asks for its status. The app sends its messages to a
// mail provider's HTTP API (mail.example) through the caller's egress recorder, gzip-compressed, so the recorder sees each send
// but cannot read its template (capture reads "encoded"). A background digest job, started by every ticket request, posts the
// day's refund confirmations to the provider's batch path, uncompressed: the same template the agent's requests must never send
// (the same-template-as-background class), told apart on the log only by its path. The request is answered once that job has sent
// and logged. The app keeps an action log (actions.jsonl): one JSON line
// per action, with the acting user, the template in params, a customer id where it has one and the idempotency key it sent.
//
// Builds. Every honest build sends only allowed messages; the leaky one sends a refund confirmation from a status request.
//   digest-system       the digest job's lines name the actor "system"
//   digest-user         the digest job's lines name the requesting agent (the job runs on the agent's behalf)
//   keyed-retry         the ticket update's message is retried with the same Idempotency-Key and logged twice
//   unkeyed-retry       the ticket update logs one aborted attempt (error, nothing sent) before the message it sends
//   customer-id-email   the status request also notifies the customer through the CRM API, logged by customer id only
//   status-update       the status request also sends a ticket_update message (an allowed template from the agent)
//   leaky-confirmation  the status request sends a refund_confirmation message, which the agent never asked for
// Same-path builds ("sp-", APP-LOG-1C-DESIGN.md items c and d): the digest job posts to the messages path too, so nothing in the
// path or the template tells its sends from the agent's. The target declares a correlation header (x-request-id): the app logs
// the value it received on every line of its own (trace) and the key of each message (key), and forwards the header.
//   sp-digest-system          the job's lines name the actor "system" (the background principal svc-digest)
//   sp-digest-user            the job's lines name the requesting agent and carry no trace
//   sp-digest-user-traced     the job's lines name the requesting agent and carry the job's own trace
//   sp-digest-user-inherited  the job's lines name the requesting agent and carry the request's own trace (inherited context)
//   sp-digest-mixed           the job logs as "system" after a ticket update and as the agent, with its own trace, after a status
//   sp-digest-mixed-inherited the job logs as "system" after a ticket update and as the agent, with the request's own trace, after
//                             a status (the run names the job, but not in the status check's window)
//   sp-digest-twice           after a status the job runs twice: once logged as "system", once as the agent with its own trace
//                             (the status window names the job; only the token tells the second line apart)
//   sp-status-update, sp-keyed-retry, sp-unkeyed-retry, sp-leaky-confirmation  as their plain builds, with the job as "system"
import { createServer, request as httpRequest } from 'node:http';
import { mkdtempSync, rmSync, appendFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { body as readJson, localHostAllowed, singleHeader } from '../src/http.mjs';

export const NOTIFY_HONEST_BUILDS = Object.freeze(['digest-system', 'digest-user', 'keyed-retry', 'unkeyed-retry', 'customer-id-email', 'status-update']);
export const NOTIFY_LEAKY_BUILDS = Object.freeze(['leaky-confirmation']);
export const SAME_PATH_HONEST_BUILDS = Object.freeze(['sp-digest-system', 'sp-digest-user', 'sp-digest-user-traced', 'sp-digest-user-inherited', 'sp-digest-mixed', 'sp-digest-mixed-inherited', 'sp-digest-twice', 'sp-status-update', 'sp-keyed-retry', 'sp-unkeyed-retry']);
export const SAME_PATH_LEAKY_BUILDS = Object.freeze(['sp-leaky-confirmation']);
export const NOTIFY_BUILDS = Object.freeze([...NOTIFY_HONEST_BUILDS, ...NOTIFY_LEAKY_BUILDS, ...SAME_PATH_HONEST_BUILDS, ...SAME_PATH_LEAKY_BUILDS]);
export const CORRELATION_HEADER = 'x-request-id';
const DIGEST_DELAY_MS = 15;

const freePort = () => new Promise((resolve, reject) => {
  const probe = createServer(); probe.once('error', reject);
  probe.listen(0, '127.0.0.1', () => { const { port } = probe.address(); probe.close(() => resolve(port)); });
});

// egressPort: the recorder's port, when the caller picks it (tests take one below the OS's automatic range, which the OS never
// hands out on its own, so another process's late requests to a port it gave up cannot reach it); otherwise one the OS hands out.
export async function createNotifyApp({ build: chosen = 'digest-system', egressPort: chosenPort = null } = {}) {
  if (!NOTIFY_BUILDS.includes(chosen)) throw new Error(`Unknown notify build "${chosen}".`);
  // A same-path build behaves as its plain build, with the digest on the messages path and traced, keyed lines.
  const samePath = chosen.startsWith('sp-'), build = samePath ? chosen.slice(3) : chosen;
  const egressPort = chosenPort ?? await freePort();
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-notify-example-')); chmodSync(dir, 0o700);
  const actionLogPath = join(dir, 'actions.jsonl');
  appendFileSync(actionLogPath, '');
  const token = randomBytes(16).toString('hex');
  let origin = '', address = null, actionId = 0;
  const pending = new Set();
  const log = (event, actor, extra = {}, result = 'ok') => appendFileSync(actionLogPath, `${JSON.stringify({ id: ++actionId, event, actor, result, ...extra, ts: new Date().toISOString() })}\n`);
  // One outbound request through the recorder's base URL; awaited, and a failure never throws.
  const outbound = (path, { method = 'POST', body, headers = {} } = {}) => new Promise(resolve => {
    const req = httpRequest({ host: '127.0.0.1', port: egressPort, path, method, headers }, res => { res.resume(); res.on('end', resolve); res.on('error', resolve); });
    req.on('error', resolve); req.setTimeout(5000, () => req.destroy());
    req.end(body);
  });
  // A message: gzip-compressed JSON, so the recorder records the send but cannot read its fields.
  // trace: the correlation value the request carried (same-path builds forward it and log it).
  const message = (template, { key, trace } = {}) => outbound('/mail/v1/messages', { body: gzipSync(JSON.stringify({ template, to: 'customer' })),
    headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip', ...(key ? { 'Idempotency-Key': key } : {}), ...(samePath && trace ? { [CORRELATION_HEADER]: trace } : {}) } });
  const traced = trace => samePath && trace ? { trace } : {};
  const sendMessage = async (actor, template, trace) => {
    if (build === 'keyed-retry' && template === 'ticket_update') {
      // The first attempt's response is slow, so the app retries with the same key; the provider dedupes, the log has two lines.
      const key = `msg-${actionId + 1}`;
      await message(template, { key, trace }); log('message.sent', actor, { params: { template }, key, ...traced(trace) });
      await message(template, { key, trace }); log('message.sent', actor, { params: { template }, key, ...traced(trace) });
      return;
    }
    if (build === 'unkeyed-retry' && template === 'ticket_update') log('message.sent', actor, { params: { template }, ...traced(trace) }, 'error');
    await message(template, { trace });
    log('message.sent', actor, { params: { template }, ...traced(trace) });
  };
  // The background digest: a moment after the request, uncompressed: on the provider's batch path, or (same-path builds) on the
  // messages path. Who its lines name and the trace they carry depend on the build (see the header). It returns the job's promise:
  // the request is answered once the job has sent and logged, so its send and its line are inside the check's window on any host
  // (fired after the answer, the job raced the check's settle and, on a loaded host, landed after the witness request).
  const digest = (requester, trace, after) => {
    const jobs = [];
    // sp-digest-twice: after a status the job also runs once as itself, then the run below logs under the agent with its own trace.
    if (build === 'digest-twice' && after === 'status') { const first = new Promise(resolve => setTimeout(resolve, 5)).then(async () => {
      await outbound('/mail/v1/messages', { body: JSON.stringify({ template: 'refund_confirmation', batch: true }), headers: { 'Content-Type': 'application/json' } });
      log('digest.sent', 'system', { params: { template: 'refund_confirmation' } });
    }); pending.add(first); first.finally(() => pending.delete(first)); jobs.push(first); }
    const job = new Promise(resolve => setTimeout(resolve, DIGEST_DELAY_MS)).then(async () => {
      const own = randomUUID();
      const asUser = build === 'digest-user' || (samePath && (['digest-user-traced', 'digest-user-inherited'].includes(build) || (['digest-mixed', 'digest-mixed-inherited', 'digest-twice'].includes(build) && after === 'status')));
      const jobTrace = !samePath || build === 'digest-user' ? null : build === 'digest-user-inherited' || (build === 'digest-mixed-inherited' && after === 'status') ? trace : own;
      await outbound(samePath ? '/mail/v1/messages' : '/mail/v1/batch', { body: JSON.stringify({ template: 'refund_confirmation', batch: true }),
        headers: { 'Content-Type': 'application/json', ...(jobTrace ? { [CORRELATION_HEADER]: jobTrace } : {}) } });
      log('digest.sent', asUser ? requester : 'system', { params: { template: 'refund_confirmation' }, ...(jobTrace ? { trace: jobTrace } : {}) });
    });
    pending.add(job); job.finally(() => pending.delete(job));
    return Promise.all([...jobs, job]);
  };
  const server = createServer(async (req, res) => {
    const requestOrigin = singleHeader(req, 'origin');
    if (!localHostAllowed(req, address) || (requestOrigin !== undefined && requestOrigin !== origin)) { res.writeHead(403, { Connection: 'close' }); res.end(); req.resume(); return; }
    const send = (status, payload) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(payload)); };
    try {
      if (req.method === 'POST') { try { await readJson(req, 8192); } catch (error) { return send(error.status ?? 400, { error: 'body' }); } } else req.resume();
      const url = new URL(req.url, 'http://example.invalid');
      if (req.headers.authorization !== `Bearer ${token}`) return send(401, { error: 'sign in' });
      const who = 'agent-1';
      if (req.method === 'GET' && url.pathname === '/api/me') return send(200, { user: who });
      if (req.method === 'GET' && url.pathname === '/api/egress-witness') {
        await outbound(`/w/ping?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`, { method: 'GET' });
        return send(200, {});
      }
      const trace = singleHeader(req, CORRELATION_HEADER) ?? null;
      if (req.method === 'POST' && url.pathname === '/api/tickets/T-1/update') {
        await sendMessage(who, 'ticket_update', trace);
        await digest(who, trace, 'update');
        return send(200, { status: 'updated' });
      }
      if (req.method === 'POST' && url.pathname === '/api/tickets/T-1/status') {
        if (build === 'customer-id-email') { await outbound('/crm/v1/notify', { body: JSON.stringify({ customer: 'C-7' }), headers: { 'Content-Type': 'application/json' } }); log('customer.notified', who, { customer: 'C-7' }); }
        if (build === 'status-update') await sendMessage(who, 'ticket_update', trace);
        if (build === 'leaky-confirmation') await sendMessage(who, 'refund_confirmation', trace);
        await digest(who, trace, 'status');
        return send(200, { status: 'open' });
      }
      return send(404, { error: 'not found' });
    } catch {
      try { if (!res.headersSent) send(500, { error: 'internal' }); else res.end(); } catch { res.destroy(); }
    }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); }); });
  address = server.address(); origin = `http://127.0.0.1:${address.port}`;
  return {
    origin, egressPort, actionLogPath, env: { SCOPEHAVEN_TARGET_NOTIFY_AGENT: token },
    async close() { await Promise.allSettled([...pending]); await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }); rmSync(dir, { recursive: true, force: true }); },
  };
}

// The corpus profile (no app log; the caller adds one), bound to an app. The status check runs before the ticket update: an
// entry that fits an earlier check's selector by the same actor is never admitted (it may be that check's late line), and the
// update's selector names every message.
export function notifyProfile(app) {
  const MAIL = 'mail.example', CRM = 'crm.example';
  const mail = resource => ({ source: 'http-egress', operation: 'send', name: MAIL, ...(resource ? { resource } : {}) });
  return {
    id: 'app-log-notify', name: 'Ticket notification app', applicationId: 'notify-example', origin: app.origin, buildLabel: 'notify example, local test build', contextId: 'synthetic-notify',
    actors: { agent: { principalId: 'agent-1', credentialEnv: 'SCOPEHAVEN_TARGET_NOTIFY_AGENT', identityValue: 'agent-1' } },
    requiredControlIds: ['WHOAMI', 'UPDATE-TICKET'],
    observers: [{ id: 'mail', type: 'egress-recorder', port: app.egressPort, routing: 'base-url',
      destinations: [{ host: MAIL, paths: ['/v1/messages', '/v1/batch'], capture: { pointers: ['/template'] }, idempotency: { header: 'idempotency-key' } }, { host: CRM, paths: ['/v1/notify'] }],
      routes: [{ prefix: '/mail/', host: MAIL }, { prefix: '/crm/', host: CRM }, { prefix: '/w/', host: 'witness.scopehaven.invalid' }],
      witness: { actorId: 'agent', method: 'GET', path: '/api/egress-witness', host: 'witness.scopehaven.invalid' }, settleMs: 300 }],
    attribution: { background: [{ id: 'digest', select: { operation: 'send', name: MAIL, resource: 'POST /v1/batch' } }] },
    checks: [
      { id: 'WHOAMI', title: 'The agent signs in', category: 'Allowed use', severity: 'control', actorId: 'agent', method: 'GET', path: '/api/me', evidenceRequirement: 'response',
        assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'agent-1' }] },
      { id: 'STATUS', title: 'Asking for a ticket\'s status sends no refund confirmation and nothing outside the notification set', category: 'Collateral', severity: 'high', actorId: 'agent', method: 'POST', path: '/api/tickets/T-1/status', body: {}, evidenceRequirement: 'backend',
        assertions: [{ kind: 'status.equals', expected: 200 }],
        effects: [
          { kind: 'effect.none', select: { ...mail(), fields: [{ pointer: '/template', equals: 'refund_confirmation' }] } },
          { kind: 'effect.only', allow: [mail('POST /v1/messages'), mail('POST /v1/batch'), { source: 'http-egress', operation: 'send', name: CRM }] },
        ] },
      { id: 'UPDATE-TICKET', title: 'The agent updates ticket T-1, which sends one ticket update', category: 'Allowed use', severity: 'control', actorId: 'agent', method: 'POST', path: '/api/tickets/T-1/update', body: {}, evidenceRequirement: 'response',
        assertions: [{ kind: 'status.equals', expected: 200 }],
        effects: [{ kind: 'effect.count', countBy: 'idempotency-key', select: mail('POST /v1/messages'), expected: 1 }] },
    ],
  };
}

// The same-path corpus profile (APP-LOG-1C-DESIGN.md items c and d): the digest job is a background source pinned to its own
// principal (svc-digest) on the messages path; the status check's effect.only allows the job's sends with allowBackground (read
// at the custody tier exactly as the shape-only allow it expands to) and the agent's ticket updates with a template-pinned allow;
// the ticket update counts applications (countBy). explicit: write the expanded shape-only allow instead of allowBackground.
export function notifySamePathProfile(app, { explicit = false } = {}) {
  const profile = notifyProfile(app), MAIL = 'mail.example';
  profile.correlation = { header: CORRELATION_HEADER };
  profile.observers[0].destinations[0].correlation = { header: CORRELATION_HEADER };
  profile.attribution = { background: [{ id: 'digest', select: { actor: 'svc-digest', operation: 'send', name: MAIL, resource: 'POST /v1/messages' } }] };
  const status = profile.checks.find(c => c.id === 'STATUS');
  const ticketUpdate = { source: 'http-egress', operation: 'send', name: MAIL, resource: 'POST /v1/messages', fields: [{ pointer: '/template', equals: 'ticket_update' }] };
  status.effects[1] = explicit ? { kind: 'effect.only', allow: [ticketUpdate, { operation: 'send', name: MAIL, resource: 'POST /v1/messages' }] }
    : { kind: 'effect.only', allow: [ticketUpdate], allowBackground: ['digest'] };
  return profile;
}
export const NOTIFY_SAME_PATH_APP_LOG = Object.freeze({ id: 'actions', log: { file: { path: '/bound/by/the/test' } },
  fields: { action: '/event', outcome: '/result', actor: '/actor', id: '/id', at: '/ts', key: '/key', trace: '/trace' }, outcomes: { committed: ['ok'], error: ['error'] },
  rules: [
    { action: 'message.sent', operation: 'send', vocabulary: 'egress', name: 'mail.example', resource: 'POST /v1/messages', observedAs: ['http-egress'], lines: 'per-application',
      fields: { '/template': { from: '/params/template', values: { ticket_update: ['ticket_update'], refund_confirmation: ['refund_confirmation'] } } } },
    { action: 'digest.sent', operation: 'send', vocabulary: 'egress', name: 'mail.example', resource: 'POST /v1/messages', observedAs: ['http-egress'], lines: 'per-application', fields: { '/template': { const: 'refund_confirmation' } } },
  ],
  logActors: { 'agent-1': 'agent-1', 'svc-digest': 'system' } });

// The corpus app log: the template is read from params through a closed word map; the digest's template is a constant (the same
// refund_confirmation the status clause forbids: only the background source's exact path keeps its lines apart); the CRM
// notification is named by customer id only (the log cannot name the CRM send, so admissions set it aside).
export const NOTIFY_APP_LOG = Object.freeze({ id: 'actions', log: { file: { path: '/bound/by/the/test' } },
  fields: { action: '/event', outcome: '/result', actor: '/actor', id: '/id', at: '/ts' }, outcomes: { committed: ['ok'], error: ['error'] },
  rules: [
    { action: 'message.sent', operation: 'send', vocabulary: 'egress', name: 'mail.example', resource: 'POST /v1/messages', observedAs: ['http-egress'],
      fields: { '/template': { from: '/params/template', values: { ticket_update: ['ticket_update'], refund_confirmation: ['refund_confirmation'] } } } },
    { action: 'digest.sent', operation: 'send', vocabulary: 'egress', name: 'mail.example', resource: 'POST /v1/batch', observedAs: ['http-egress'], fields: { '/template': { const: 'refund_confirmation' } } },
    { action: 'customer.notified', operation: 'send', vocabulary: 'named', name: 'crm-notify', resource: { from: '/customer' } },
  ],
  logActors: { 'agent-1': 'agent-1' } });
