// A provider stub for tests: keeps a signed scopehaven-provider-feed/1 feed in memory, serves it on 127.0.0.1
// (GET /feed?after=&limit= and the signed head GET /feed/head?nonce=), and can append the same entries to a journal file
// (route ii). The tests call accept() where an app's vendor SDK would reach the provider: the entry is in the feed before
// accept() returns. Tests only: every key pair is generated per stub.
import { createServer } from 'node:http';
import { generateKeyPairSync, sign, randomUUID } from 'node:crypto';
import { appendFileSync, writeFileSync } from 'node:fs';

export const ENTRY_PREFIX = 'scopehaven-provider-feed/1\n', HEAD_PREFIX = 'scopehaven-provider-feed/1 head\n';
export const signWith = (prefix, body, privateKey) => {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return { body: text, sig: sign(null, Buffer.from(prefix + text), privateKey).toString('base64') };
};
export const signEntry = (body, privateKey) => signWith(ENTRY_PREFIX, body, privateKey);
export const publicKeyOf = keys => keys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

// options: lagMs (the stub's clock runs this far behind), journal (route ii file).
export async function startStub(t, { feedId = 'helplane-mail', genesis = true, journal = null, lagMs = 0 } = {}) {
  const keys = generateKeyPairSync('ed25519');
  const state = { epoch: randomUUID(), entries: [] };
  // headMode: 'ok', 'stale' (the head signed for the previous nonce), 'unsigned', 'missing' (404), 'behind' (one seq
  // lower, same epoch), 'entry-as-head' (the last entry's own signed object), 'entry-prefix-head' (a true head body signed
  // under the entry prefix: a stub that signed anything as an entry); stallAt: serve no entry past this many while
  // the head still reports the true last seq.
  // headDelayMs: the signed head answers this much later (a slow provider). afterHead: called with each signed head once it is answered
  // (a test's hook for a provider that accepts mail right after it signed a head).
  const control = { headMode: 'ok', stallAt: null, lastHead: null, headDelayMs: 0, afterHead: null };
  let ids = 0, lastAt = 0;
  // The stub stamps "at" when it assigns the seq, never earlier than the last entry.
  const stamp = () => { lastAt = Math.max(Date.now() - lagMs, lastAt); return new Date(lastAt).toISOString(); };
  const push = entry => { state.entries.push(entry); if (journal) appendFileSync(journal, `${JSON.stringify(entry)}\n`); return entry; };
  // fields: the body's own fields; options: { at, key, epoch, seq } to forge or skew an entry on purpose.
  const append = (fields, { at, key = keys.privateKey, epoch = state.epoch, seq = state.entries.length + 1 } = {}) =>
    push(signEntry({ feed: feedId, epoch, seq, id: `evt_${++ids}`, at: at ?? stamp(), ...fields }, key));
  const lastSeq = () => state.entries.length;
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const json = body => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
    if (req.method === 'GET' && url.pathname === '/feed/head') {
      if (control.headDelayMs) await new Promise(resolve => setTimeout(resolve, control.headDelayMs));
      if (control.headMode === 'missing') { res.writeHead(404); res.end(); return; }
      const fresh = signWith(HEAD_PREFIX, { feed: feedId, epoch: state.epoch, lastSeq: control.headMode === 'behind' ? lastSeq() - 1 : lastSeq(), nonce: url.searchParams.get('nonce') }, keys.privateKey);
      const answer = control.headMode === 'stale' && control.lastHead ? control.lastHead : control.headMode === 'unsigned' ? { ...fresh, sig: Buffer.alloc(64).toString('base64') }
        : control.headMode === 'entry-as-head' ? state.entries.at(-1)
        : control.headMode === 'entry-prefix-head' ? signWith(ENTRY_PREFIX, fresh.body, keys.privateKey) : fresh;
      control.lastHead = fresh;
      json(answer);
      control.afterHead?.(fresh);
      return;
    }
    if (req.method !== 'GET' || url.pathname !== '/feed') { res.writeHead(404); res.end(); return; }
    const after = Number(url.searchParams.get('after') ?? 0), limit = Number(url.searchParams.get('limit') ?? 500);
    // Entries in seq order after "after"; a removed entry leaves its seq missing (a gap); a stall serves nothing new.
    const served = control.stallAt === null ? state.entries : state.entries.slice(0, control.stallAt);
    const list = served.filter(e => e !== null && JSON.parse(e.body).seq > after);
    json({ schema: 'scopehaven-provider-feed/1', entries: list.slice(0, limit), more: list.length > limit });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const stub = {
    feedId, keys, control, publicKey: publicKeyOf(keys), port: server.address().port, path: '/feed',
    get epoch() { return state.epoch; }, get entries() { return state.entries; },
    append,
    genesis: () => append({ type: 'epoch-start' }),
    // App-written values (the subject here) sit under "app", where they can never stand for a contract field. fields: a
    // test's own override of contract fields, to forge or break an entry on purpose.
    accept: (recipients, { messageId, subject = 'Your refund', fields = {}, ...options } = {}) => append({ type: 'accepted', messageId: messageId ?? `msg_${ids + 1}`, recipients, app: { subject }, ...fields }, options),
    reject: (recipients, options = {}) => append({ type: 'rejected', messageId: `msg_${ids + 1}`, recipients }, options),
    status: (messageId, options = {}) => append({ type: 'status', messageId, status: 'delivered' }, options),
    // Later outcomes: the provider's later word on a message it accepted (recipients: the ones it is for; omitted, every recipient).
    // fields: a test's own override of contract fields, to break an entry on purpose.
    outcome: (messageId, outcome, { recipients, fields = {}, ...options } = {}) => append({ type: 'outcome', messageId, ...(recipients === undefined ? {} : { recipients }), outcome, ...fields }, options),
    // The same event delivered again under a new seq (a provider redelivery).
    redeliver: seq => { const { seq: _s, ...rest } = JSON.parse(state.entries[seq - 1].body); return push(signEntry({ ...rest, seq: state.entries.length + 1 }, keys.privateKey)); },
    remove: seq => { state.entries[seq - 1] = null; },
    stall: () => { control.stallAt = state.entries.length; },
    // A stub restart: a new epoch from a new genesis.
    reset: ({ withGenesis = true } = {}) => { state.epoch = randomUUID(); state.entries = []; if (journal) writeFileSync(journal, ''); if (withGenesis) append({ type: 'epoch-start' }); },
  };
  if (genesis) stub.genesis();
  return stub;
}
