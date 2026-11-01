// Owned practice app for the core HTTP path: lifecycle (an account suspended mid-run, or a user who signs out),
// typed captures (an actor acting on a resource another actor created) and settlement
// (an effect committed after its check's window). Loopback only, synthetic users and
// notes in memory, no model, no provider, no network beyond 127.0.0.1.
//
// Its one external effect is a webhook per committed note deletion, sent through the
// loopback egress recorder the profile declares (proxy routing), to
//   http://hooks.desk.example/hooks/<deleter>/<creator role>
// so each (actor, creator role) cell has its own declared path. Nothing leaves the
// machine: the recorder answers every request itself. The witness route
// GET /api/ping?scopehaven_witness=<nonce> makes the app send one request to the
// witness host through the same proxy.
//
// Builds (flags; all false is the clean build):
//   staleSession    a suspended user's token keeps working (lifecycle defect)
//   suspendBroken   the suspend endpoint answers 500 and suspends nobody (failed control)
//   signOutKeepsSession  POST /api/sign-out answers signed out, but the token keeps working (self-change lifecycle defect)
//   signOutBroken   POST /api/sign-out answers 500 and signs nobody out (failed self-change control)
//   creatorBypass   any member may delete a note an administrator created (creator-dependent defect)
//   createBroken    note creation answers 201 without the note id (failed control, capture misses)
//   ownDeleteNoop   an owner's delete answers 200 but deletes nothing and sends nothing (failed control);
//                   true breaks every owner's own delete, a user name breaks only that user's
//   refusedCommit   a refused delete still deletes; its webhook goes out when the next request
//                   matching { method, path | pathPrefix, user } arrives (an effect committed after its window);
//                   with creatorRole, only a refused delete of a note that role created
//   lateMs          with refusedCommit { timer: true }: the webhook goes out lateMs after the refusal
// Correlation (run settlement, src/http-settlement.mjs; fixture options, outside every identity hash):
//   forwardCorrelation  'traceparent' or a custom header name ('x-request-id'): each webhook forwards the
//                       triggering request's value of that header (a traceparent keeps its trace id with a new
//                       parent id, as OpenTelemetry propagation does); false (the default) forwards nothing
//   correlationContext  for a deferred webhook: 'origin' (the default) forwards the refused request's value;
//                       'current' forwards the value of the request that flushed it (the stale-context bug of
//                       a queue flushed inside a later request's handler)
import { createServer, request } from 'node:http';
import { randomBytes } from 'node:crypto';

export const HOOK_HOST = 'hooks.desk.example';
export const WITNESS_HOST = 'witness.desk.invalid';
export const USERS = Object.freeze({ admin: 'admin', alice: 'member', bob: 'member', carol: 'member' });
export const TOKEN_ENV = Object.freeze({ admin: 'SCOPEHAVEN_TARGET_DESK_ADMIN', alice: 'SCOPEHAVEN_TARGET_DESK_ALICE', bob: 'SCOPEHAVEN_TARGET_DESK_BOB', carol: 'SCOPEHAVEN_TARGET_DESK_CAROL' });

// One request through the egress recorder as an HTTP proxy (absolute-form target).
function viaSink(sinkPort, method, host, path, extraHeaders = {}) {
  return new Promise(resolve => {
    const req = request({ host: '127.0.0.1', port: sinkPort, method, path: `http://${host}${path}`, headers: { host, 'content-length': '0', connection: 'close', ...extraHeaders }, agent: false }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', () => resolve(null));
    req.end();
  });
}

export async function createCorePracticeApp({ sinkPort, staleSession = false, suspendBroken = false, creatorBypass = false, createBroken = false, ownDeleteNoop = false, signOutKeepsSession = false, signOutBroken = false, refusedCommit = null, lateMs = 0, forwardCorrelation = false, correlationContext = 'origin' } = {}) {
  const tokens = Object.fromEntries(Object.keys(USERS).map(user => [user, randomBytes(18).toString('base64url')]));
  const byToken = new Map(Object.entries(tokens).map(([user, token]) => [token, user]));
  // requests: who sent what, in arrival order (user, or "anonymous" / "unknown" for a missing or unknown token).
  const suspended = new Set(), signedOut = new Set(), notes = new Map(), pending = [], timers = new Set(), requests = [];
  let next = 0;
  // The correlation value a webhook forwards: the header's value as received (a traceparent with a fresh parent id).
  const forwarded = value => typeof value !== 'string' ? {} : { [forwardCorrelation]: forwardCorrelation === 'traceparent' ? value.replace(/^(00-[0-9a-f]{32}-)[0-9a-f]{16}(-[0-9a-f]{2})$/, (_, a, b) => `${a}${randomBytes(8).toString('hex')}${b}`) : value };
  const hook = (deleter, creatorRole, correlation) => viaSink(sinkPort, 'POST', HOOK_HOST, `/hooks/${deleter}/${creatorRole}`, forwarded(correlation));
  const json = (res, status, value) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(value)); };
  const server = createServer((req, res) => { req.resume(); req.on('end', async () => {
    if (req.headers.host !== `127.0.0.1:${server.address().port}` || req.headers.origin) return json(res, 403, {});
    const url = new URL(req.url, 'http://desk.local'), path = url.pathname;
    const token = /^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1];
    const correlation = forwardCorrelation ? req.headers[forwardCorrelation] : undefined;
    const user = token === undefined ? null : byToken.get(token) ?? null;
    // A deferred webhook goes out when the declared trigger request arrives, before that request is handled.
    if (pending.length && refusedCommit && !refusedCommit.timer && req.method === refusedCommit.method && (path === refusedCommit.path || (refusedCommit.pathPrefix !== undefined && path.startsWith(refusedCommit.pathPrefix))) && (!refusedCommit.user || refusedCommit.user === user)) {
      for (const send of pending.splice(0)) await send(correlation);
    }
    requests.push({ user: user ?? (token === undefined ? 'anonymous' : 'unknown'), method: req.method, path });
    if (user === null || (suspended.has(user) && !staleSession) || (signedOut.has(user) && !signOutKeepsSession)) return json(res, 401, { error: 'unauthenticated' });
    if (req.method === 'GET' && path === '/api/me') return json(res, 200, { user, id: `u-${user}`, role: USERS[user] });
    if (req.method === 'GET' && path === '/api/ping') {
      const nonce = url.searchParams.get('scopehaven_witness');
      if (nonce !== null) await viaSink(sinkPort, 'GET', WITNESS_HOST, `/w?scopehaven_witness=${encodeURIComponent(nonce)}`);
      return json(res, 200, { ok: true });
    }
    // A protected route: the caller's own notes (each actor's surface control).
    if (req.method === 'GET' && path === '/api/notes') return json(res, 200, { owner: user, count: [...notes.values()].filter(n => n.owner === user).length });
    if (req.method === 'POST' && path === '/api/notes') {
      const id = `n-${++next}`; notes.set(id, { owner: user, creatorRole: USERS[user] });
      return json(res, 201, createBroken ? { created: true } : { id });
    }
    const del = /^\/api\/notes\/([A-Za-z0-9-]+)\/delete$/.exec(path);
    if (req.method === 'POST' && del) {
      const note = notes.get(del[1]);
      if (!note) return json(res, 404, { error: 'not-found' });
      const allowed = note.owner === user || USERS[user] === 'admin' || (creatorBypass && note.creatorRole === 'admin');
      if (!allowed) {
        if (refusedCommit && (!refusedCommit.creatorRole || refusedCommit.creatorRole === note.creatorRole)) {
          notes.delete(del[1]);
          const send = current => hook(user, note.creatorRole, correlationContext === 'current' ? current : correlation);
          if (refusedCommit.timer) { const t = setTimeout(() => { timers.delete(t); send(undefined); }, lateMs); timers.add(t); } else pending.push(send);
        }
        return json(res, 403, { error: 'forbidden' });
      }
      if (ownDeleteNoop && note.owner === user && (ownDeleteNoop === true || ownDeleteNoop === user)) return json(res, 200, { deleted: true });
      notes.delete(del[1]);
      await hook(user, note.creatorRole, correlation);
      return json(res, 200, { deleted: true });
    }
    // The caller ends its own session (a self-change); the answer names who was signed out.
    if (req.method === 'POST' && path === '/api/sign-out') {
      if (signOutBroken) return json(res, 500, { error: 'sign-out failed' });
      signedOut.add(user);
      return json(res, 200, { signedOut: true, user });
    }
    const suspend = /^\/api\/admin\/users\/u-([a-z]+)\/suspend$/.exec(path);
    if (req.method === 'POST' && suspend) {
      if (USERS[user] !== 'admin') return json(res, 403, { error: 'forbidden' });
      if (!Object.hasOwn(USERS, suspend[1])) return json(res, 404, { error: 'not-found' });
      if (suspendBroken) return json(res, 500, { error: 'suspend failed' });
      suspended.add(suspend[1]);
      return json(res, 200, { status: 'suspended' });
    }
    json(res, 404, { error: 'not-found' });
  }); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const env = Object.fromEntries(Object.entries(tokens).map(([user, token]) => [TOKEN_ENV[user], token]));
  return { origin: `http://127.0.0.1:${server.address().port}`, env, tokens, requests,
    close: async () => { for (const t of timers) clearTimeout(t); pending.length = 0; await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }); } };
}
