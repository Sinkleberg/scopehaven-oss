// A small owned two-tenant app for init's tests: Auth.js-shaped who-am-I (signed out answers 200 null), a session taken
// as a bearer token or a session cookie, and notes owned per user. Synthetic, loopback only.
//   leaky: true        any signed-in user opens any note (the cross-tenant defect the starter profile must decide FAIL)
//   cookieOnly: true   the session is read only from the cookie
//   cookieName         the cookie's name (default authjs.session-token); a custom name is set on GET /login, as many
//                      apps set their session cookie there
//   postgrest: true    notes are read PostgREST style at /rest/v1/notes?id=eq.ID: a row the reader may not see is
//                      filtered out, so another tenant's or a signed-out read answers 200 [] (correct, not a leak)
//   wrapped            with postgrest: true wraps rows as { data: [...] } (a filtered read answers 200 { data: [] });
//                      'message' answers a filtered read with 200 { message: 'no rows' } instead, and 'errors' with
//                      200 { message: 'not allowed', errors: [] }
//   crashSignedOut     GET /api/me answers 500 signed out (a handler that assumes a session) and the user signed in;
//                      /api/auth/session is absent, so /api/me is the only who-am-I route
//   unhealthy: true    every route answers 500
//   echoRef: true      each note answer carries the caller's own session token in a "ref" field (an app that echoes it)
//   gotrue: true       the only who-am-I route is GoTrue's /auth/v1/user (a Supabase app aimed at its gateway)
//   chat: true         GET /api/chat answers 405 (a POST-only assistant route)
//   n8n: true          n8n-shaped: the only who-am-I route is GET /rest/login ({ data: { email } } signed in, 401 signed
//                      out) and the session is read only from the n8n-auth cookie, which no answer sets on a GET
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';

export async function createTwoTenantApp({ leaky = false, cookieOnly = false, cookieName = 'authjs.session-token', postgrest = false, wrapped = false, crashSignedOut = false, unhealthy = false, echoRef = false, gotrue = false, chat = false, n8n = false } = {}) {
  if (n8n) { cookieOnly = true; cookieName = 'n8n-auth'; }
  const users = {
    [randomBytes(18).toString('base64url')]: { id: 'u-ada', email: 'ada@tenant-a.example', note: 'note-a1' },
    [randomBytes(18).toString('base64url')]: { id: 'u-bo', email: 'bo@tenant-b.example', note: 'note-b1' },
  };
  const notes = { 'note-a1': { owner: 'u-ada', title: 'Ada synthetic note' }, 'note-b1': { owner: 'u-bo', title: 'Bo synthetic note' } };
  let requests = 0;
  const escaped = cookieName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const server = createServer((req, res) => {
    requests += 1;
    const send = (status, body, type = 'application/json', headers = {}) => { res.writeHead(status, { 'content-type': type, ...headers }); res.end(type === 'application/json' ? JSON.stringify(body) : body); };
    if (unhealthy) return send(500, { error: 'internal' });
    const url = new URL(req.url, 'http://x'), path = url.pathname;
    const bearer = !cookieOnly && /^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1];
    const cookie = new RegExp(`(?:^|;\\s*)${escaped}=([^;]+)`).exec(req.headers.cookie ?? '')?.[1];
    const user = users[bearer || cookie];
    if (gotrue && path === '/auth/v1/user') return user ? send(200, { id: user.id, aud: 'authenticated', email: user.email }) : send(401, { msg: 'no authorization' });
    if (chat && path === '/api/chat') return send(405, { error: 'method not allowed' });
    if (n8n && path === '/rest/login') return user ? send(200, { data: { id: user.id, email: user.email, role: 'global:member' } }) : send(401, { status: 'error', message: 'Unauthorized' });
    if (path === '/api/auth/session' && !crashSignedOut && !gotrue && !n8n) return send(200, user ? { user: { email: user.email, id: user.id, type: 'regular' } } : null);
    if (path === '/api/auth/signin') return send(200, '<html>sign in</html>', 'text/html');
    if (crashSignedOut && path === '/api/me') return user ? send(200, { email: user.email }) : send(500, { error: 'cannot read user of undefined' });
    if (path === '/login') return send(200, '<html>login</html>', 'text/html', cookieName === 'authjs.session-token' || n8n ? {} : { 'set-cookie': `${cookieName}=; Path=/; HttpOnly` });
    if (postgrest && path === '/rest/v1/notes') {
      const id = /^eq\.([a-z0-9-]+)$/.exec(url.searchParams.get('id') ?? '')?.[1];
      const note = notes[id];
      const rows = note && user && (note.owner === user.id || leaky) ? [{ id, title: note.title }] : [];
      if (wrapped === 'message') return send(200, rows.length ? { data: rows } : { message: 'no rows' });
      if (wrapped === 'errors') return send(200, rows.length ? { data: rows, errors: [] } : { message: 'not allowed', errors: [] });
      return send(200, wrapped ? { data: rows } : rows);
    }
    const m = /^\/api\/notes\/([a-z0-9-]+)$/.exec(path);
    if (m) {
      if (!user) return send(401, { error: 'unauthorized' });
      const note = notes[m[1]];
      if (!note) return send(404, { error: 'not found' });
      if (note.owner !== user.id && !leaky) return send(403, { error: 'forbidden' });
      return send(200, { id: m[1], title: note.title, ...(echoRef ? { ref: bearer || cookie } : {}) });
    }
    send(404, { error: 'not found' });
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  const [tokenA, tokenB] = Object.keys(users);
  return { origin: `http://127.0.0.1:${server.address().port}`, tokenA, tokenB, requests: () => requests,
    close: () => new Promise(done => { server.close(done); server.closeAllConnections(); }) };
}
