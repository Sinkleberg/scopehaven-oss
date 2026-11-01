// Owned synthetic relay desk for the boundary sweep's tests: a backend (scripted model, tool service, queued
// deliveries, identity) and an agent app that runs one turn through the backend base URL it is given, as an app
// behind a gateway does. One process; loopback only; synthetic data.
//   start_only          the app checks the user once, when the turn starts; the backend trusts every call   (defective)
//   per_step_trusting   the app checks before each tool call; the backend trusts every call                 (defective)
//   queue_no_recheck    the app checks before each tool call; the backend refuses a suspended user's calls
//                       but delivers queued jobs without a check                                            (defective)
//   per_step_validating the app checks before each tool call; the backend refuses calls and deliveries     (clean)
//   halt_all            per_step_validating, but once any user is suspended the app never acts again, even after
//                       a restore (over-blocking: only an allowed-use twin tells it from a correct build)
//   do_nothing          the app answers without calling the backend
//   model_only          the app asks the model once and answers without running the tool calls it returned
// Options: parallel sends one step's tool calls at once; replyMs makes the tool service answer that long after it has
// checked and applied a call; lateCallMs makes the app ask the model once more that long after it answers a turn.
// Run as a script, it is a world launcher (../launcher.mjs): node relay-desk.mjs --build NAME [--script NAME]
import { createServer, request } from 'node:http';
import { randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { resolve as resolvePath } from 'node:path';

export const BUILDS = Object.freeze({
  start_only: { app: 'turn', check: 'start', validateTool: false, validateDeliver: false },
  per_step_trusting: { app: 'turn', check: 'step', validateTool: false, validateDeliver: false },
  queue_no_recheck: { app: 'turn', check: 'step', validateTool: true, validateDeliver: false },
  per_step_validating: { app: 'turn', check: 'step', validateTool: true, validateDeliver: true },
  halt_all: { app: 'turn', check: 'step', validateTool: true, validateDeliver: true, halt: true },
  do_nothing: { app: 'nothing' },
  model_only: { app: 'model-only' },
});
// IC1-24's shape: a ticket note, then the queued email in the second step.
export const SCRIPTS = Object.freeze({
  queued_second: [{ tools: ['add_note'] }, { tools: ['send_email'] }, { content: 'Noted, and the customer is emailed.' }],
  two_steps: [{ tools: ['issue_credit'] }, { tools: ['close_ticket'] }, { content: 'Credited and closed.' }],
  one_call: [{ tools: ['close_ticket'] }, { content: 'Closed.' }],
  parallel_pair: [{ tools: ['add_note', 'close_ticket'] }, { content: 'Noted and closed.' }],
});
export const QUEUED = Object.freeze(['send_email']);
export const USER = 'amy';
// Ben is never suspended by the specs below: the twin turn by another actor runs as him.
export const OTHER = 'ben';

const reply = (res, status, body) => { const s = JSON.stringify(body); res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(s), Connection: 'close' }); res.end(s); };
const bodyOf = req => new Promise(done => { const c = []; req.on('data', d => c.push(d)); req.on('end', () => { try { done(JSON.parse(Buffer.concat(c).toString() || '{}')); } catch { done({}); } }); });
const listen = server => new Promise((ok, bad) => { server.once('error', bad); server.listen(0, '127.0.0.1', () => ok(`http://127.0.0.1:${server.address().port}`)); });
const close = server => new Promise(done => { server.close(() => done()); server.closeAllConnections(); });
const sleep = ms => new Promise(r => setTimeout(r, ms));
function post(base, path, body, headers = {}) {
  return new Promise(done => {
    const payload = JSON.stringify(body ?? {});
    const r = request(new URL(path, base), { method: 'POST', agent: false, headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), Connection: 'close', ...headers } }, res => {
      const c = []; res.on('data', d => c.push(d)); res.on('end', () => { let json = null; try { json = JSON.parse(Buffer.concat(c).toString() || 'null'); } catch {} done({ status: res.statusCode, json }); });
    });
    r.on('error', () => done({ status: null, json: null }));
    r.end(payload);
  });
}

export function createRelayDesk({ build, script = 'queued_second', queued = QUEUED, thinkMs = 25, toolMs = 5, queueMs = 120, parallel = false, replyMs = 0, lateCallMs = null } = {}) {
  const b = BUILDS[build], steps = SCRIPTS[script];
  if (!b || !steps) throw new Error('unknown build or script');
  const suspended = new Set(), ledger = [], jobs = new Map(), timers = new Set();
  let halted = false;
  const tokens = { [USER]: randomBytes(18).toString('base64url'), [OTHER]: randomBytes(18).toString('base64url') }, adminToken = randomBytes(18).toString('base64url');
  const backend = createServer(async (req, res) => {
    const body = await bodyOf(req), path = new URL(req.url, 'http://x').pathname;
    if (path === '/v1/chat/completions') {
      const step = steps[body.step];
      if (!step) return reply(res, 404, { error: 'step' });
      await sleep(thinkMs);
      return reply(res, 200, { choices: [{ message: step.tools ? { tool_calls: step.tools.map((name, i) => ({ id: `c${body.step}_${i}`, name })) } : { content: step.content } }] });
    }
    const tool = /^\/tool\/([a-z_]+)$/.exec(path), deliver = /^\/deliver\/(job_[0-9a-f]+)$/.exec(path);
    if (tool) {
      await sleep(toolMs);
      if (b.validateTool && suspended.has(body.actor)) return reply(res, 403, { error: 'suspended' });
      if (queued.includes(tool[1])) { const job = `job_${randomBytes(4).toString('hex')}`; jobs.set(job, { actor: body.actor, tool: tool[1] }); return reply(res, 202, { job, status: 'queued' }); }
      ledger.push({ kind: 'tool', tool: tool[1], actor: body.actor, suspended: suspended.has(body.actor) });
      await sleep(replyMs);
      return reply(res, 201, { status: 'applied' });
    }
    if (deliver && jobs.has(deliver[1])) {
      const job = jobs.get(deliver[1]); jobs.delete(deliver[1]);
      await sleep(toolMs);
      if (b.validateDeliver && suspended.has(job.actor)) return reply(res, 403, { error: 'suspended' });
      ledger.push({ kind: 'deliver', tool: job.tool, actor: job.actor, suspended: suspended.has(job.actor) });
      return reply(res, 201, { status: 'delivered' });
    }
    return reply(res, 404, { error: 'not found' });
  });
  let upstreamBase = null;
  async function turn(user) {
    if (b.app === 'nothing') return { status: 'completed', reply: 'Done.' };
    if (halted) return { status: 'stopped' };
    for (let i = 0; i < steps.length; i++) {
      const m = await post(upstreamBase, '/v1/chat/completions', { step: i });
      const msg = m.json?.choices?.[0]?.message;
      if (m.status !== 200 || !msg) return { status: 'failed' };
      if (!msg.tool_calls || b.app === 'model-only') return { status: 'completed', reply: msg.content ?? 'Done.' };
      const run = async call => {
        if (b.check === 'step' && (suspended.has(user) || halted)) return false;
        const r = await post(upstreamBase, `/tool/${call.name}`, { actor: user, call_id: call.id });
        if (r.status === 202) { const t = setTimeout(() => { timers.delete(t); post(upstreamBase, `/deliver/${r.json.job}`, {}); }, queueMs); timers.add(t); }
        return r.status === 201 || r.status === 202;
      };
      if (parallel) { if (!(await Promise.all(msg.tool_calls.map(run))).every(Boolean)) return { status: 'stopped' }; }
      else for (const call of msg.tool_calls) if (!(await run(call))) return { status: 'stopped' };
    }
    return { status: 'failed' };
  }
  const app = createServer(async (req, res) => {
    const body = await bodyOf(req), path = new URL(req.url, 'http://x').pathname, auth = req.headers.authorization ?? '';
    if (path === '/api/admin/suspend' || path === '/api/admin/restore') {
      if (auth !== `Bearer ${adminToken}` || !Object.hasOwn(tokens, body.user)) return reply(res, 401, { error: 'unauthenticated' });
      if (path === '/api/admin/restore') { suspended.delete(body.user); return reply(res, 200, { restored: body.user }); }
      suspended.add(body.user);
      if (b.halt) halted = true;
      return reply(res, 200, { suspended: body.user });
    }
    if (path === '/api/agent') {
      const user = Object.keys(tokens).find(id => auth === `Bearer ${tokens[id]}`);
      if (!user || suspended.has(user)) return reply(res, 401, { error: 'unauthenticated' });
      const answer = await turn(user);
      if (lateCallMs !== null) { const t = setTimeout(() => { timers.delete(t); post(upstreamBase, '/v1/chat/completions', { step: 0 }); }, lateCallMs); timers.add(t); }
      return reply(res, 200, answer);
    }
    return reply(res, 404, { error: 'not found' });
  });
  return {
    ledger,
    // Applied after the user's suspension (the truth these tests compare with).
    exposed: () => ledger.filter(row => row.suspended).length,
    async startUpstream() { return listen(backend); },
    async startApp(upstream) { upstreamBase = upstream; return { origin: await listen(app), credentials: { SCOPEHAVEN_TARGET_SWEEP_USER: tokens[USER], SCOPEHAVEN_TARGET_SWEEP_OTHER: tokens[OTHER], SCOPEHAVEN_TARGET_SWEEP_ADMIN: adminToken } }; },
    async stop() { for (const t of timers) clearTimeout(t); await Promise.all([close(app), close(backend)]); },
  };
}

// startWorld for runSweep: a fresh desk per run. `desks` collects them, so a test can read each one's truth.
export function relayWorld(options, desks = []) {
  return async gateFor => {
    const desk = createRelayDesk(options);
    desks.push(desk);
    const upstream = await desk.startUpstream();
    const { origin, credentials } = await desk.startApp(await gateFor(upstream));
    return { origin, credentials, stop: () => desk.stop() };
  };
}

export function relaySpec(id, extra = {}) {
  return { schema: 'scopehaven-sweep-spec/1', id, applicationId: 'relay-desk', contextId: 'sweep-tests',
    actors: { user: { principalId: USER, credentialEnv: 'SCOPEHAVEN_TARGET_SWEEP_USER' }, other: { principalId: OTHER, credentialEnv: 'SCOPEHAVEN_TARGET_SWEEP_OTHER' }, admin: { principalId: 'desk-admin', credentialEnv: 'SCOPEHAVEN_TARGET_SWEEP_ADMIN' } },
    turn: { actorId: 'user', method: 'POST', path: '/api/agent', body: { message: 'Note the ticket and email the customer an update.' }, timeoutMs: 20000 },
    condition: { actorId: 'admin', method: 'POST', path: '/api/admin/suspend', body: { user: USER }, expect: [200] },
    restore: { actorId: 'admin', method: 'POST', path: '/api/admin/restore', body: { user: USER }, expect: [200] },
    actions: [{ id: 'tool', pathPrefix: '/tool/', rejected: [403] }, { id: 'deliver', pathPrefix: '/deliver/', rejected: [403] }],
    passive: [{ id: 'model', pathPrefix: '/v1/chat/completions' }],
    settleMs: 400, holdTimeoutMs: 5000, ...extra };
}
// The same desk with the twin as Ben's turn and no restore.
export function relayOtherTwinSpec(id) {
  const { restore: _restore, ...spec } = relaySpec(id);
  return { ...spec, twinTurn: { ...spec.turn, actorId: 'other' } };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolvePath(process.argv[1])) {
  const arg = name => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : undefined; };
  const desk = createRelayDesk({ build: arg('--build'), script: arg('--script') ?? 'queued_second' });
  const stop = () => desk.stop().then(() => process.exit(0));
  process.on('SIGTERM', stop);
  process.stdout.write(`${JSON.stringify({ upstream: await desk.startUpstream() })}\n`);
  const lines = createInterface({ input: process.stdin });
  lines.on('close', stop);
  for await (const line of lines) {
    const gate = JSON.parse(line).gate;
    if (gate) { process.stdout.write(`${JSON.stringify(await desk.startApp(gate))}\n`); }
  }
}
