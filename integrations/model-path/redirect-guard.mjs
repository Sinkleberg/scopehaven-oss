// Redirect guard: a loopback proxy between the hold gate and the model tap. The tap
// records a status only for the model routes it recognises, and forwards every answer
// as it is. Here any 3xx the model server sends, on any route, is refused: the app gets
// a 502 and never sees the Location, and the refusal is written into the tap's own log
// (the same hash chain) as a gap frame, so the run reads refused from the log alone.
// Requests and other answers pass through unchanged, streams included.
import { createServer, request } from 'node:http';
import { randomUUID } from 'node:crypto';
import { loopbackRequestAllowed } from '../observers/events.mjs';

export const REDIRECT_REFUSED = 'upstream-redirect-refused';

// upstream: the tap's origin (http://127.0.0.1:<port>); log: the tap's TapLog.
export function createRedirectGuard({ upstream, log }) {
  const upstreamUrl = new URL(upstream);
  if (upstreamUrl.protocol !== 'http:' || upstreamUrl.hostname !== '127.0.0.1' || upstreamUrl.pathname !== '/') throw new Error('The redirect guard forwards to a loopback origin only.');
  let server = null, listening = null;
  const handle = (req, res) => {
    if (!loopbackRequestAllowed(req, listening)) { req.resume(); res.writeHead(403).end(); return; }
    if (typeof req.url !== 'string' || !req.url.startsWith('/') || req.url.startsWith('//')) { req.resume(); res.writeHead(400).end(); return; }
    const target = new URL(req.url, upstreamUrl);
    if (target.origin !== upstreamUrl.origin) { req.resume(); res.writeHead(400).end(); return; }
    const up = request(target, { method: req.method, headers: { ...req.headers, host: upstreamUrl.host }, agent: false }, upRes => {
      if (upRes.statusCode >= 300 && upRes.statusCode <= 399) {
        upRes.resume();
        log.push({ kind: 'gap', conn: `guard-${randomUUID()}`, reason: REDIRECT_REFUSED, method: req.method, path: target.pathname.slice(0, 200), status: upRes.statusCode });
        res.writeHead(502, { 'Content-Type': 'application/json', Connection: 'close' });
        res.end('{"error":"the model server answered with a redirect, which the model path refuses"}');
        return;
      }
      res.writeHead(upRes.statusCode, upRes.headers);
      upRes.pipe(res);
    });
    up.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
    res.on('close', () => { if (!res.writableFinished) up.destroy(); });
    req.pipe(up);
  };
  return {
    get url() { return `http://127.0.0.1:${listening}`; },
    async start() { server = createServer(handle); await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); }); listening = server.address().port; },
    async stop() { if (server) { const s = server; server = null; await new Promise(resolve => { s.close(resolve); s.closeAllConnections?.(); }); } },
  };
}
