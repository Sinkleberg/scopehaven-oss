// Forwarding for the egress recorder (readiness edge E1; declaration and outcome rules: src/effect-outcome.mjs).
// One recorded send to a destination that declares `forward` is sent on to its upstream, and the upstream's reply is
// read in full before anything goes back to the app.
//   - Loopback only: the connection always goes to the literal 127.0.0.1 (no name lookup) on the declared port. Neither
//     host nor port comes from the request, and redirects are never followed.
//   - The request is the recorded one: the same method, the path and query the recorder named, and exactly the body
//     bytes it digested. A fixed set of hop-by-hop and framing headers is dropped (Connection itself included); a header
//     the Connection header names is still forwarded, so the upstream receives every header the record read (content
//     type, encoding, idempotency key, correlation token). Host is the destination host; Content-Length is the recorded
//     body's length.
//   - Bounded: the whole exchange (connect, send, full reply) within timeoutMs, the reply body within maxReplyBytes.
//   - Proof (when the destination declares proofEnv): the request carries X-Scopehaven-Forward-Nonce, 32 random hex
//     digits made fresh per request, and the reply must carry X-Scopehaven-Forward-Proof, the lowercase hex
//     HMAC-SHA256 under the secret of forwardProofMessage(...): the nonce, the method, the path and query as received,
//     the SHA-256 of the body as received, its Content-Type (empty when absent) and the status answered. Only a reply
//     whose one proof header matches is proven. Both headers are ScopeHaven's own: an app-sent nonce header is
//     dropped, and the proof header is not passed back to the app. The /1 proof binds those fields only: not Host or the
//     other forwarded headers, and not the reply body. A destination that declares proofVersion 2 expects the /2 proof
//     (forwardProofV2Message): the same fields under the prefix scopehaven-forward-proof/2, followed by the SHA-256 of the
//     reply body as received, so a proven /2 reply's body is the upstream's own (src/effect-outcome.mjs returned ids).
// Result: { complete: true, status, proven, headers, body } for a reply read in full within its bounds with a status
// from 100 to 599; otherwise { complete: false, reason } with reason connect-error, timeout, reply-over-limit,
// reply-incomplete, reply-invalid or stopped. A reply framed by closing the connection reads complete when the
// connection closes: the outcome rests on the status line and the proof, which the reply's head carries in full.
// Every result also carries `connected` (in-doubt resolution R0, src/in-doubt.mjs): true once the TCP connect to the upstream
// completed. Node writes no request byte before that, so false (refused, unreachable, a connect timeout, a stop before connecting)
// means nothing of the request reached the upstream; a reset after connect, even before the body, keeps true.
import { request } from 'node:http';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const UPSTREAM_HOST = '127.0.0.1';
export const NONCE_HEADER = 'x-scopehaven-forward-nonce', PROOF_HEADER = 'x-scopehaven-forward-proof';
// Hop-by-hop and framing headers never forwarded in either direction (RFC 9110 section 7.6.1, plus framing set here),
// and ScopeHaven's own proof headers.
const HOP_BY_HOP = Object.freeze(['connection', 'keep-alive', 'proxy-connection', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length', 'expect', NONCE_HEADER, PROOF_HEADER]);
// Header pairs from Node's rawHeaders, minus the fixed hop-by-hop set, names kept as sent.
function endToEnd(rawHeaders) {
  const pairs = [];
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) if (!HOP_BY_HOP.includes(rawHeaders[i].toLowerCase())) pairs.push([rawHeaders[i], rawHeaders[i + 1]]);
  return pairs;
}
// What the proof covers. contentType: the request's one Content-Type value, or '' when it has none.
export const forwardProofMessage = ({ nonce, method, path, bodySha256, contentType, status }) => `scopehaven-forward-proof/1\n${nonce}\n${method}\n${path}\n${bodySha256}\n${contentType}\n${status}`;
// The proof an upstream returns (exported for upstream doubles and tests).
export const forwardProof = (secret, fields) => createHmac('sha256', secret).update(forwardProofMessage(fields)).digest('hex');
// forward-proof/2: the /1 fields, then replyBodySha256, the hex SHA-256 of the reply body the upstream sends.
export const forwardProofV2Message = ({ nonce, method, path, bodySha256, contentType, status, replyBodySha256 }) => `scopehaven-forward-proof/2\n${nonce}\n${method}\n${path}\n${bodySha256}\n${contentType}\n${status}\n${replyBodySha256}`;
export const forwardProofV2 = (secret, fields) => createHmac('sha256', secret).update(forwardProofV2Message(fields)).digest('hex');

// Send one recorded request to the upstream. secret: the proof secret, or null; proofVersion: 1 or 2. signal: aborted when the recorder stops.
export function forwardRequest({ port, host, method, path, rawHeaders, body, timeoutMs, maxReplyBytes, secret = null, proofVersion = 1, signal }) {
  return new Promise(resolve => {
    let settled = false, req = null, connected = false;
    const done = result => { if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener('abort', onStop); resolve({ ...result, connected }); };
    const fail = reason => { if (settled) return; done({ complete: false, reason }); req?.destroy(); };
    const timer = setTimeout(() => fail('timeout'), timeoutMs);
    const onStop = () => fail('stopped');
    if (signal?.aborted) return fail('stopped');
    signal?.addEventListener('abort', onStop, { once: true });
    const pairs = endToEnd(rawHeaders);
    const types = pairs.filter(([name]) => name.toLowerCase() === 'content-type').map(([, value]) => value);
    // A proof is checked only for a request with at most one Content-Type (the upstream then reads the one the recorder did).
    const nonce = secret !== null && types.length <= 1 ? randomBytes(16).toString('hex') : null;
    const expected = nonce === null ? null : { nonce, method, path, bodySha256: createHash('sha256').update(body).digest('hex'), contentType: types[0] ?? '' };
    const headers = [...pairs.flat(), 'Host', host, 'Content-Length', String(body.length), ...(nonce === null ? [] : ['X-Scopehaven-Forward-Nonce', nonce])];
    try {
      req = request({ host: UPSTREAM_HOST, port, method, path, headers, agent: false, setHost: false, insecureHTTPParser: false });
    } catch { return fail('connect-error'); }
    req.on('socket', socket => { if (socket.connecting === false) connected = true; else socket.once('connect', () => { connected = true; }); });
    req.on('error', () => fail('connect-error'));
    req.on('response', res => {
      if (!(Number.isInteger(res.statusCode) && res.statusCode >= 100 && res.statusCode <= 599)) { fail('reply-invalid'); res.destroy(); return; }
      const chunks = [];
      let bytes = 0;
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > maxReplyBytes) { fail('reply-over-limit'); res.destroy(); return; }
        chunks.push(chunk);
      });
      res.on('error', () => fail('reply-incomplete'));
      res.on('aborted', () => fail('reply-incomplete'));
      res.on('end', () => {
        if (!res.complete) return fail('reply-incomplete');
        const proofs = [];
        for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) if (res.rawHeaders[i].toLowerCase() === PROOF_HEADER) proofs.push(res.rawHeaders[i + 1]);
        const reply = Buffer.concat(chunks);
        const want = expected === null ? null : Buffer.from(proofVersion === 2 ? forwardProofV2(secret, { ...expected, status: res.statusCode, replyBodySha256: createHash('sha256').update(reply).digest('hex') })
          : forwardProof(secret, { ...expected, status: res.statusCode }));
        const proven = want !== null && proofs.length === 1 && /^[0-9a-f]{64}$/.test(proofs[0]) && timingSafeEqual(Buffer.from(proofs[0]), want);
        done({ complete: true, status: res.statusCode, proven, headers: endToEnd(res.rawHeaders), body: reply });
      });
      res.on('close', () => fail('reply-incomplete'));
    });
    req.end(body);
  });
}
