// A loopback request-feed provider stub for tests (scopehaven-request-feed/1, src/request-feed-rules.mjs). The Ed25519 key pair is made in
// this process for each stub (a dummy key that never leaves the test and is never read from the environment), entries and heads are signed
// with it, and the feed is served on 127.0.0.1 only. Owned synthetic data only: hosts, keys and object ids are made-up names, never resolved or
// contacted. For tests only; not in any identity list.
import { generateKeyPairSync, sign } from 'node:crypto';
import { createServer } from 'node:http';
import { REQUEST_FEED_SCHEMA } from '../../src/request-feed-rules.mjs';

export const feedKeys = () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'), privateKey };
};
export const signedEntry = (privateKey, body) => { const text = typeof body === 'string' ? body : JSON.stringify(body); return { body: text, sig: sign(null, Buffer.from(`${REQUEST_FEED_SCHEMA}\n${text}`), privateKey).toString('base64') }; };
export const signedHead = (privateKey, body) => { const text = JSON.stringify(body); return { body: text, sig: sign(null, Buffer.from(`${REQUEST_FEED_SCHEMA} head\n${text}`), privateKey).toString('base64') }; };
const iso = ms => new Date(ms).toISOString();

// entries: the feed as served (signed raw entries in order, the genesis first). add(fields) signs and appends one request entry with the next
// seq; addRaw(raw) appends anything (faults). watermark(): the head's watermark in ms, or null for none (default: the time the head is read).
// serve: { drop: Set(seq) entries left out of pages, order: 'reverse' to serve a page backwards, headSeq: () => a lastSeq to sign instead }.
export function createRequestFeedStub({ feedId = 'crm-requests', keys = feedKeys(), epoch = 'e1', path = '/requests', watermark = () => Date.now(), start = Date.now() - 60000 } = {}) {
  const entries = [signedEntry(keys.privateKey, { feed: feedId, epoch, seq: 1, id: 'genesis', at: iso(start), type: 'epoch-start' })];
  const serve = { drop: new Set(), order: 'forward', headSeq: null, status: 200 };
  let server = null, lastAt = start;
  const stub = {
    feedId, keys, epoch, path, entries, serve, publicKey: keys.publicKey,
    // One request entry: host, route, key, object, state, type (defaults below), at (ms, default now and never earlier than the last), id, tenant.
    add(fields) {
      const seq = entries.length + 1, at = Math.max(fields.at ?? Date.now(), lastAt); lastAt = at;
      const body = { feed: feedId, epoch, seq, id: fields.id ?? `ev-${seq}`, at: iso(at), type: fields.type ?? 'ticket.closed', host: fields.host, route: fields.route ?? 'POST /tickets/T-1/close',
        key: fields.key, object: fields.object ?? 'obj-1', state: fields.state ?? 'closed', ...(fields.tenant === undefined ? {} : { tenant: fields.tenant }), ...(fields.extra ?? {}) };
      entries.push(signedEntry(fields.signer ?? keys.privateKey, body));
      return seq;
    },
    addRaw(raw) { entries.push(raw); return entries.length; },
    // The same event delivered again under the next seq (a redelivery is the same body but its seq).
    redeliver(seq, edit = b => b) { const b = edit({ ...JSON.parse(entries[seq - 1].body), seq: entries.length + 1 }); entries.push(signedEntry(keys.privateKey, b)); return entries.length; },
    async listen(port = 0) {
      server = createServer((req, res) => {
        const url = new URL(req.url, 'http://127.0.0.1');
        const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
        if (serve.status !== 200) return reply(serve.status, {});
        if (url.pathname === `${path}/head`) {
          const lastSeq = serve.headSeq ? serve.headSeq() : entries.length, w = watermark();
          return reply(200, signedHead(keys.privateKey, { feed: feedId, epoch, lastSeq, nonce: url.searchParams.get('nonce'), ...(w === null ? {} : { watermark: iso(w) }) }));
        }
        if (url.pathname !== path) return reply(404, {});
        const after = Number(url.searchParams.get('after') ?? 0), limit = Number(url.searchParams.get('limit') ?? 500);
        let page = entries.map((e, i) => [i + 1, e]).filter(([s]) => s > after && !serve.drop.has(s)).slice(0, limit).map(([, e]) => e);
        if (serve.order === 'reverse') page = [...page].reverse();
        return reply(200, { schema: REQUEST_FEED_SCHEMA, entries: page, more: entries.length - after > page.length + [...serve.drop].filter(s => s > after).length });
      });
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
      stub.port = server.address().port;
      return stub;
    },
    async close() { if (server) await new Promise(resolve => { server.close(() => resolve()); server.closeAllConnections(); }); },
  };
  return stub;
}
