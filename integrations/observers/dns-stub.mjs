// DNS stub (collector dns-stub/1): a loopback DNS server the application's resolver points at, recording every name it looks
// up, so a value smuggled out inside a host name (a canary in a subdomain label, data split across labels) is seen even when
// no connection follows. It answers every query itself and never recurses or forwards one, so no lookup the app makes during a
// test leaves this machine through it. Wire format: dns-wire.mjs. Windows, witnesses and the quiet period: sink-ledger.mjs,
// as for the SMTP sink and the egress recorder.
//
// Binds. It holds its port on 127.0.0.1 and [::1], over UDP and TCP, each bound exclusively (four sockets), and does not start
// unless all four bind, as the other sinks do (smtp-sink/2, egress-recorder/10): a resolver configured with a name or the
// other loopback address must not reach another process holding the same port there.
//
// Answers. A declared name answers as declared: "loopback" gives A 127.0.0.1 and AAAA ::1 (TTL 0), "nxdomain" (the default)
// gives NXDOMAIN; every other name, the witness included, gets NXDOMAIN. No answer ever names an address outside loopback,
// and no negative answer carries an SOA, so a resolver does not cache it (RFC 2308). Other opcodes get NOTIMP, other classes
// REFUSED, unreadable queries FORMERR (when their header could be read) or nothing.
//
// Witness and authority. Without "routing" (and "witness") the stub is presence-only: a recorded lookup can fail a check,
// silence proves nothing. With "routing": "resolver" and a witness, the connector's witness request makes the app look up
// "<nonce>.<witness domain>" after each check; the window is complete only when that lookup arrives. Like every sink's
// witness, it proves the app's resolver reached the stub for that lookup, not that the app has no other resolver (a hard-coded
// DNS-over-HTTPS client, a cache that answered). Repeats of the witness lookup (A then AAAA, a retry) are the witness, never a
// lookup; any other name under the witness domain makes the window partial.
//
// Nothing secret is stored. A lookup record names a declared name (the query name, or its declared parent when the name
// declares subdomains; compared label by label, so a label holding a dot never matches) or "*"; the full query name is kept only as a digest salted per stub, with its label count and wire
// length, the transport it came over and its arrival time. An operator-supplied scanner (canary-sink.mjs; never from a profile)
// reads each query name in memory as it arrives and the record keeps only what it returns (a canary id the scanner holds, a
// known channel and decoding name), never the name. A scanner that throws or returns anything else never reads as a clean
// scan: the lookup is still recorded, with scanned false, and the window is partial (dns-scan-failed, dns-scan-invalid).
//
// A window is partial (beyond the ledger's rules) when a query was unreadable, was not a query (a response, an UPDATE or
// another opcode), carried other than one question, named the witness domain without being the witness, was cut off on a
// TCP connection, a TCP connection was dropped (over the connection limit, a query over tcpQueryBytes, or more than
// tcpUnreadBytes of replies left unread), its scanner failed, the kernel may have dropped a UDP query (below), or (final, the
// run-end window) a lookup arrived after its end mark before the stub had been quiet for quietMs. Each of those but the late
// lookup is a message the scanner never read in full, and a window holding one never says scanned.
//
// UDP loss. The kernel drops a datagram that arrives while the socket's receive buffer is full, and the stub never sees it. So
// each UDP socket asks for udpRecvBufferBytes (the OS may grant less; udpRecvBuffer reports what it granted), and the stub
// counts each busy period of a socket: from the first datagram read after the socket was found empty until a later turn of the
// event loop reads nothing from it. A drop needs a full buffer, and every datagram the buffer held is read before the socket is
// next found empty, so a period with a drop in it reads at least the whole buffer. Each datagram counts as its length plus
// udpDatagramCost bytes (macOS charges a small query about 192; Linux's charge is not measured, and the half-buffer limit leaves
// room for twice the estimate), and a period that reaches half the granted buffer may have lost one: each of its records is
// marked, and its end is a problem record of its own, so every window it touches reads partial (dns-possible-drop-query). A
// false partial is the price; a silent loss never reads complete.
//
// The run-end drain (as egress-recorder/12's): before the final mark, drain waits until no TCP query is in flight and nothing
// has arrived for quietMs, then looks once more after two turns; markClear says whether a mark found no query in flight.
//
// Stalls. Quiet is never judged on a stale read: the drain and the run-end window's wait accept it (or the wait's cap) only
// after two more turns of the event loop, the second always after a fresh poll, so a datagram a stall (a GC pause, the
// connector's own work) left queued in the kernel is read and counted, in its busy period too, before quiet is judged.
import { createSocket } from 'node:dgram';
import { createServer } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { createSinkLedger, SINK_LEDGER_LIMITS } from './sink-ledger.mjs';
import { parseQuery, encodeResponse, asciiLower } from './dns-wire.mjs';
import { collectorDigest } from '../../src/collector-identity.mjs';

export const DNS_STUB_LABEL = 'dns-stub/1';
export const DNS_STUB_FILES = Object.freeze(['dns-stub.mjs', 'dns-wire.mjs', 'sink-ledger.mjs']);
// The collector record a run carries for this stub, like the egress recorder's (src/collector-identity.mjs): a digest of its
// files and the Node version, so a stub edit or another Node compares as a different collector.
export const DNS_STUB_COLLECTOR = Object.freeze({ label: DNS_STUB_LABEL, digest: await collectorDigest(DNS_STUB_FILES), node: process.versions.node });
export const DNS_STUB_ADDRESSES = Object.freeze([{ host: '127.0.0.1', udp: 'udp4' }, { host: '::1', udp: 'udp6' }]);
// maxConnections: TCP connections open at once, across both addresses. tcpQueryBytes: the longest TCP query read (a stub
// resolver's is far shorter); a longer one is never buffered. tcpUnreadBytes: the replies a TCP client may leave unread.
// Past any of the three the connection is dropped and the drop recorded, so each connection holds a bounded amount of memory.
// udpRecvBufferBytes: the receive buffer each UDP socket asks for (halved down to 1 MiB until the OS accepts it). udpDatagramCost:
// the bytes a datagram is counted as beyond its length when a busy period is weighed against the granted buffer (UDP loss above).
export const DNS_STUB_LIMITS = Object.freeze({ retained: 20000, maxConnections: 64, idleMs: 10000, names: 64, quietMs: [100, 10000], witnessWaitMs: [0, 30000], port: [1024, 65535], tcpQueryBytes: 4096, tcpUnreadBytes: 65536,
  udpRecvBufferBytes: 4 * 1024 * 1024, udpDatagramCost: 1024 });
// The names a scanner's hit may carry: the channels of src/canary.mjs (CANARY_CHANNELS) and the decodings of canary-sink.mjs
// (CANARY_VIAS) and src/canary.mjs (CANARY_ENCODINGS), copied while neither module is on main. A hit naming anything else is
// dropped and the scan reads invalid, so a scanner can never store a decoded value under one of these keys.
const SCAN_CHANNELS = new Set(['verbatim', 'folded', 'skeleton', 'encoded']);
const SCAN_VIAS = new Set(['labels', 'percent', 'quoted-printable', 'unicode-escape', 'tags', 'selectors', 'zero-width', 'whitespace-bits', 'hex', 'base32', 'base64', 'rot13', 'reversed',
  'basic-auth', 'encoded-word', 'percent-double', 'json-escape', 'base64url', 'mime-base64', 'html-entity', 'byte-list', 'gzip', 'zlib', 'deflate-raw']);
// The problem records that stand for a message the scanner never read (and the in-flight TCP query, a foreign witness nonce):
// a window holding one never says scanned.
const UNSCANNED = new Set([...['not-a', 'multi-question', 'malformed', 'opcode', 'witness-malformed', 'incomplete', 'dropped', 'oversize', 'backlog', 'possible-drop'].map(kind => `dns-${kind}-query`),
  'dns-query-in-flight', 'dns-foreign-witness']);
const KEYS = ['id', 'type', 'port', 'routing', 'names', 'witness', 'witnessWaitMs', 'quietMs', 'settleMs'];
const WITNESS_KEYS = ['actorId', 'method', 'path', 'domain'];
const NAME = /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)+$/;
const NONCE_LABEL = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const intIn = (value, [lo, hi]) => Number.isInteger(value) && value >= lo && value <= hi;
const under = (name, parent) => name === parent || name.endsWith(`.${parent}`);
// A query's labels (lowercased) under a declared name's labels, compared label by label: a label that itself holds a dot
// ("x.api" in [x.api, pay, example]) never reads as two labels, so it is never under api.pay.example.
const labelsOf = name => name.split('.');
const underLabels = (labels, parent) => labels.length >= parent.length && parent.every((p, i) => labels[labels.length - parent.length + i] === p);
// n turns of the event loop (setImmediate); of two, the second always comes after a fresh poll (the run-end drain and wait).
const turns = async n => { for (let k = 0; k < n; k++) await new Promise(resolve => setImmediate(resolve)); };

// Throws with a profile-facing message; returns the normalized configuration.
export function validateDnsStubConfig(o, actors) {
  if (!object(o) || Object.keys(o).some(key => !KEYS.includes(key))) throw new Error(`a dns-stub observer is { ${KEYS.join(', ')} } (all but id, type, port and names optional)`);
  if (o.type !== undefined && o.type !== 'dns-stub') throw new Error('"type" must be "dns-stub"');
  if (!intIn(o.port, DNS_STUB_LIMITS.port)) throw new Error('"port" must be an integer from 1024 to 65535 (the stub listens on 127.0.0.1 and [::1], UDP and TCP)');
  if (!Array.isArray(o.names) || o.names.length > DNS_STUB_LIMITS.names) throw new Error('"names" lists up to 64 { name, answer?, subdomains? }: the names the app may look up');
  const names = o.names.map(n => {
    if (!object(n) || Object.keys(n).some(key => !['name', 'answer', 'subdomains'].includes(key)) || typeof n.name !== 'string' || !NAME.test(n.name)) throw new Error('each entry of "names" is { name, answer?, subdomains? } with a lowercase host name of two or more labels and no trailing dot');
    if (n.answer !== undefined && !['loopback', 'nxdomain'].includes(n.answer)) throw new Error('a name\'s "answer" is "loopback" (A 127.0.0.1, AAAA ::1) or "nxdomain" (the default); the stub never answers outside loopback');
    if (n.subdomains !== undefined && typeof n.subdomains !== 'boolean') throw new Error('a name\'s "subdomains" is true or false');
    return { name: n.name, answer: n.answer ?? 'nxdomain', subdomains: n.subdomains === true };
  });
  if (new Set(names.map(n => n.name)).size !== names.length) throw new Error('each name is declared once');
  if ((o.routing === undefined) !== (o.witness === undefined)) throw new Error('"routing" and "witness" go together: silence is authoritative only on a declared route a witness proves');
  if (o.routing !== undefined && o.routing !== 'resolver') throw new Error('"routing" must be "resolver" (the app\'s resolver is this stub)');
  let witness = null;
  if (o.witness !== undefined) {
    const w = o.witness;
    if (!object(w) || Object.keys(w).some(key => !WITNESS_KEYS.includes(key))) throw new Error('"witness" is { actorId, method: "GET", path, domain } and nothing else');
    if (w.method !== 'GET') throw new Error('the witness must be a GET to the app');
    if (!object(actors) || !Object.hasOwn(actors, w.actorId)) throw new Error('the witness "actorId" must be a declared actor');
    if (typeof w.path !== 'string' || !w.path.startsWith('/') || w.path.startsWith('//') || w.path.length > 300 || /[#\s\\]/.test(w.path)) throw new Error('the witness "path" must be an origin-form path without a fragment');
    let decoded;
    try { decoded = decodeURIComponent(w.path); } catch { throw new Error('the witness "path" must be validly percent-encoded'); }
    if (/scopehaven_witness/i.test(decoded)) throw new Error('the witness "path" cannot carry its own witness parameter');
    if (typeof w.domain !== 'string' || !NAME.test(w.domain) || names.some(n => under(n.name, w.domain) || under(w.domain, n.name))) throw new Error('the witness "domain" is a lowercase host name that is not, does not contain and is not under a declared name (the witness is never a lookup)');
    witness = { actorId: w.actorId, method: 'GET', path: w.path, domain: w.domain };
  }
  if (o.witnessWaitMs !== undefined && !intIn(o.witnessWaitMs, DNS_STUB_LIMITS.witnessWaitMs)) throw new Error('"witnessWaitMs" must be an integer from 0 to 30000');
  if (o.quietMs !== undefined && !intIn(o.quietMs, DNS_STUB_LIMITS.quietMs)) throw new Error('"quietMs" must be an integer from 100 to 10000');
  return { port: o.port, routing: o.routing ?? null, names, witness, witnessWaitMs: o.witnessWaitMs ?? 3000, quietMs: o.quietMs ?? 300 };
}

// scanner: operator code only (canary-sink.mjs createCanaryScanner: { scan({ labels, name, where }) -> { hits: [{ canary, channel,
// via? }], complete }, canaries, unavailable }), never from a profile. retained: operator code only. drainTurn: operator and test
// code only (a profile cannot set it): it replaces the run-end drain's wait of two turns before its last look, as the egress
// recorder's hook replaces its one.
export function createDnsStub({ instanceId = 'dns-stub-1', scanner = null, retained = DNS_STUB_LIMITS.retained, drainTurn = null, actors, ...config }) {
  const cfg = validateDnsStubConfig(config, actors ?? (config.witness ? { [config.witness.actorId]: {} } : undefined));
  if (scanner !== null && (typeof scanner?.scan !== 'function' || !Array.isArray(scanner.canaries))) throw new Error('a scanner is { scan({ labels, name, where }) -> { hits, complete }, canaries, unavailable }');
  // The canaries this stub's scanner can match: a judgement of any other canary over its windows reads not scanned.
  const scannedCanaries = scanner ? Object.freeze(scanner.canaries.map(c => c.id).filter(id => !(scanner.unavailable ?? []).some(u => u.canary === id))) : Object.freeze([]);
  const scannerIds = new Set(scanner ? scanner.canaries.map(c => c?.id) : []);
  const ledger = createSinkLedger({ prefix: 'dns', unit: 'query', retained });
  const salt = randomBytes(16);
  const digestName = name => createHash('sha256').update(salt).update(name).digest('hex');
  // issued: the witness nonces this stub's own marks handed out (the connector's, never the app's). Only an issued nonce is ever
  // remembered as seen, so an app looking up many nonce-shaped names cannot grow the stub's memory.
  const issued = new Set(), seenNonces = new Set(), sockets = new Set(), clearAtMark = new WeakMap();
  // lastArrivalSeq: the last record that was not a repeat of a witness (a final window reads partial when one is after its end).
  let udp = null, tcp = null, lastArrivalSeq = 0, lastRecord = null;
  const record = fields => { const r = ledger.record(fields); if (fields.repeatOf === undefined) lastArrivalSeq = r.seq; lastRecord = r; return r; };

  // UDP loss (the header): per UDP socket, the granted buffer and the busy period being read. read: datagrams since the last
  // check; cost: the period's weight; held: its records while it is still under the limit; possible: it reached the limit.
  const busy = DNS_STUB_ADDRESSES.map(() => ({ granted: null, read: 0, cost: 0, held: [], possible: false }));
  let checking = false;
  const udpRecvBuffer = () => ({ requested: DNS_STUB_LIMITS.udpRecvBufferBytes, udp4: busy[0].granted, udp6: busy[1].granted });
  // Runs once per turn of the event loop while datagrams are being read (setImmediate, after the poll that read them). A socket
  // that read nothing since the last check was found empty by that turn's poll: its busy period is over.
  function checkBusy() {
    checking = false;
    let again = false;
    for (const b of busy) {
      if (b.read > 0) { b.read = 0; again = true; continue; }
      if (b.cost === 0) continue;
      if (b.possible && udp) record({ kind: 'possible-drop' });
      b.cost = 0; b.held = []; b.possible = false;
    }
    if (again) { checking = true; setImmediate(checkBusy); }
  }
  function udpRead(b, bytes, r) {
    b.read++; b.cost += bytes + DNS_STUB_LIMITS.udpDatagramCost;
    if (b.possible) r.possibleDrop = true;
    else if (2 * b.cost >= b.granted) { b.possible = true; r.possibleDrop = true; for (const h of b.held) h.possibleDrop = true; b.held = []; }
    else b.held.push(r);
    if (!checking) { checking = true; setImmediate(checkBusy); }
  }

  // What a scan leaves on the lookup: { canaries, scanned, problem }. canaries is null when nothing was read (no scanner, or a
  // scanner that threw); scanned is true only for a full scan whose every hit was valid; a problem names why it was not.
  function scan(q) {
    if (!scanner) return { canaries: null, scanned: false, problem: null };
    try {
      const result = scanner.scan({ labels: q.labels, name: q.name, where: 'dns-qname' });
      // An async scanner breaks the contract: its result is never read, and its rejection is handled here, never left to end the
      // process.
      if (typeof result?.then === 'function') { try { result.then(null, () => {}); } catch {} return { canaries: null, scanned: false, problem: 'dns-scan-invalid' }; }
      if (!object(result) || !Array.isArray(result.hits) || typeof result.complete !== 'boolean') return { canaries: null, scanned: false, problem: 'dns-scan-invalid' };
      const canaries = [];
      let invalid = false;
      for (const h of result.hits) {
        if (object(h) && typeof h.canary === 'string' && scannerIds.has(h.canary) && SCAN_CHANNELS.has(h.channel) && (h.via === undefined || SCAN_VIAS.has(h.via))) canaries.push({ canary: h.canary, channel: h.channel, ...(h.via !== undefined ? { via: h.via } : {}) });
        else invalid = true;
      }
      return { canaries, scanned: !invalid && result.complete, problem: invalid ? 'dns-scan-invalid' : null };
    } catch { return { canaries: null, scanned: false, problem: 'dns-scan-failed' }; }
  }

  // The declared entry a query name falls under: the exact name, or the longest declared parent that declares subdomains.
  const declared = cfg.names.map(n => ({ ...n, labels: labelsOf(n.name) })), witnessLabels = cfg.witness ? labelsOf(cfg.witness.domain) : null;
  const declaredOf = labels => declared.find(n => n.labels.length === labels.length && underLabels(labels, n.labels))
    ?? declared.filter(n => n.subdomains && labels.length > n.labels.length && underLabels(labels, n.labels)).sort((a, b) => b.labels.length - a.labels.length)[0] ?? null;
  // The answer bytes, or null for no answer: a message whose header could not be read, and a response (answering one could
  // start a loop between two servers).
  // transport: udp4, udp6, tcp4 or tcp6.
  function answer(query, transport) {
    if (query.error) {
      record({ kind: query.error === 'dns-not-a-query' ? 'not-a' : query.error === 'dns-question-count' ? 'multi-question' : 'malformed' });
      if (query.id === null || query.error === 'dns-not-a-query') return null;
      return encodeResponse({ id: query.id, opcode: query.opcode, rd: query.rd }, { rcode: 'formerr' });
    }
    if (query.opcode !== 0) { record({ kind: 'opcode' }); return encodeResponse(query, { rcode: 'notimp' }); }
    const q = query.question, name = q.name, lower = q.labels.map(asciiLower);
    // The witness: exactly one nonce label under the witness domain. The first lookup of a nonce this stub issued is the witness;
    // later ones repeat it. A nonce it never issued is a foreign witness every time, never remembered.
    if (cfg.witness && underLabels(lower, witnessLabels)) {
      const nonce = lower.length === witnessLabels.length + 1 ? lower[0] : null;
      if (nonce === null || !NONCE_LABEL.test(nonce)) record({ kind: 'witness-malformed' });
      else if (seenNonces.has(nonce)) record({ kind: 'item', witnessNonces: [], repeatOf: nonce });
      else { if (issued.has(nonce)) seenNonces.add(nonce); record({ kind: 'item', witnessNonces: [nonce] }); }
      return encodeResponse(query, { rcode: 'nxdomain' });
    }
    const entry = declaredOf(lower);
    // Only the hit's names are kept: the canary id, the matching channel and, for a decoded form, which decoding found it; and
    // whether the scanner read the name in full (scanned).
    const s = scan(q);
    record({ kind: 'item', witnessNonces: [], lookup: { type: q.type, class: q.qclass, name: entry?.name ?? '*', exact: entry !== null && entry.labels.length === lower.length, digest: digestName(name), labels: q.labels.length, bytes: q.wireBytes,
      transport, arrivedAt: new Date().toISOString(), canaries: s.canaries, scanned: s.scanned, ...(s.problem ? { scanProblem: s.problem } : {}) } });
    if (q.qclass !== 1 && q.qclass !== 255) return encodeResponse(query, { rcode: 'refused' });
    if (entry?.answer !== 'loopback') return encodeResponse(query, { rcode: 'nxdomain' });
    const records = [...(q.type === 'A' || q.type === 'ANY' ? [{ type: 'A', address: '127.0.0.1' }] : []), ...(q.type === 'AAAA' || q.type === 'ANY' ? [{ type: 'AAAA', address: '::1' }] : [])];
    return encodeResponse(query, { records });
  }

  function onTcp(socket, transport) {
    // One connection over the limit, across both addresses, is dropped and recorded (each server's own limit records the same).
    if (sockets.size >= DNS_STUB_LIMITS.maxConnections) { socket.on('error', () => {}); record({ kind: 'dropped' }); socket.destroy(); return; }
    sockets.add(socket);
    socket.setTimeout(DNS_STUB_LIMITS.idleMs);
    let buffer = Buffer.alloc(0), pending = null;
    // A query whose length prefix arrived but whose bytes did not is in flight; cut off, it is incomplete.
    const cut = () => { if (pending && !pending.done) { pending.done = true; pending.retired = true; record({ kind: 'incomplete' }); } pending = null; };
    // A connection dropped at a limit: the drop is a record of its own (the window reads partial), and whatever it still held
    // unanswered is never read.
    const drop = kind => { record({ kind }); cut(); buffer = Buffer.alloc(0); socket.destroy(); };
    socket.on('timeout', () => { cut(); socket.destroy(); });
    socket.on('error', () => {});
    socket.on('close', () => { cut(); sockets.delete(socket); });
    socket.on('data', chunk => {
      buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk;
      while (buffer.length && !socket.destroyed) {
        // A query longer than tcpQueryBytes is never waited for: no connection buffers more than one short query.
        if (buffer.length >= 2 && buffer.readUInt16BE(0) > DNS_STUB_LIMITS.tcpQueryBytes) { drop('oversize'); return; }
        if (buffer.length < 2 || buffer.length < 2 + buffer.readUInt16BE(0)) { pending ??= record({ kind: 'item', done: false, witnessNonces: [] }); return; }
        const len = buffer.readUInt16BE(0);
        // The in-flight placeholder is retired once the whole message is read: the parsed query is recorded on its own.
        if (pending) { pending.done = true; pending.retired = true; pending = null; }
        const message = buffer.subarray(2, 2 + len); buffer = buffer.subarray(2 + len);
        const reply = answer(parseQuery(message), transport);
        if (reply === null) continue;
        const prefix = Buffer.alloc(2); prefix.writeUInt16BE(reply.length, 0);
        socket.write(Buffer.concat([prefix, reply]));
        // A client that sends and never reads: past tcpUnreadBytes of replies waiting, the connection is dropped.
        if (socket.writableLength > DNS_STUB_LIMITS.tcpUnreadBytes) { drop('backlog'); return; }
      }
    });
  }

  // The receive buffer is asked for once bound (halved until the OS accepts it), and what the OS granted is read back.
  const bindUdp = (type, host) => new Promise((resolve, reject) => {
    const s = createSocket({ type, ...(type === 'udp6' ? { ipv6Only: true } : {}) });
    s.once('error', reject);
    s.bind({ port: cfg.port, address: host, exclusive: true }, () => {
      s.off('error', reject);
      for (let size = DNS_STUB_LIMITS.udpRecvBufferBytes; size >= 1024 * 1024; size /= 2) { try { s.setRecvBufferSize(size); break; } catch {} }
      resolve(s);
    });
  });
  const bindTcp = (host, transport) => new Promise((resolve, reject) => {
    const s = createServer(socket => onTcp(socket, transport));
    s.maxConnections = DNS_STUB_LIMITS.maxConnections;
    s.on('drop', () => { record({ kind: 'dropped' }); });
    s.once('error', reject);
    s.listen({ port: cfg.port, host, exclusive: true }, () => { s.off('error', reject); resolve(s); });
  });
  const closeAll = list => Promise.all(list.map(s => new Promise(resolve => { try { s.close(() => resolve()); } catch { resolve(); } })));

  return {
    kind: 'dns-stub-resolver', instanceId, source: 'dns-query', port: cfg.port, collector: DNS_STUB_COLLECTOR,
    scope: Object.freeze({ operations: ['lookup'], names: cfg.names.map(n => n.name), actorAttribution: 'none', evidence: cfg.routing ? 'authoritative' : 'presence-only', scanned: scanner !== null, scannedCanaries }),
    ...(cfg.witness ? { witnessRequest: Object.freeze({ actorId: cfg.witness.actorId, method: 'GET', path: cfg.witness.path }) } : {}),
    markWitnessRequest(from) { ledger.markWitnessRequest(from); },
    // The receive buffer each UDP socket asked for and what the OS granted (bytes; null before start).
    udpRecvBuffer,
    async start() {
      if (udp) return;
      const bound = [];
      try {
        for (const { host, udp: type } of DNS_STUB_ADDRESSES) { bound.push(await bindUdp(type, host)); bound.push(await bindTcp(host, type === 'udp6' ? 'tcp6' : 'tcp4')); }
      } catch (error) { await closeAll(bound); throw error; }
      udp = bound.filter((_, i) => i % 2 === 0); tcp = bound.filter((_, i) => i % 2 === 1);
      udp.forEach((s, i) => {
        const transport = DNS_STUB_ADDRESSES[i].udp, b = busy[i];
        b.granted = s.getRecvBufferSize();
        // answer records exactly one record per message (lastRecord), which the busy period may mark.
        s.on('message', (message, rinfo) => { const reply = answer(parseQuery(message), transport); udpRead(b, message.length, lastRecord); if (reply !== null) s.send(reply, rinfo.port, rinfo.address, () => {}); });
        s.on('error', () => ledger.down()); s.on('close', () => ledger.down());
      });
      for (const s of tcp) { s.on('error', () => ledger.down()); s.on('close', () => ledger.down()); }
      ledger.started();
    },
    // Each mark also notes whether a TCP query was in flight then (markClear), and issues its witness nonce.
    async mark() {
      const mark = ledger.position();
      issued.add(mark.witnessNonce); clearAtMark.set(mark, mark.ok === true && ledger.notDone() === 0);
      return mark;
    },
    // At this mark (one this stub made) the stub was up and no TCP query was in flight.
    markClear(mark) { return clearAtMark.get(mark) === true; },
    // The drain's own cap: the collect's witness wait and quiet cap.
    drainCapMs() { return cfg.witnessWaitMs + 10 * cfg.quietMs; },
    // Every cut or dropped exchange is a record of its own, which leaves the window it lands in partial: no close swallows a
    // lookup unseen.
    closedAfterCollect() { return false; },
    // Wait, at most capMs, until no TCP query is in flight and quietMs has passed since the last arrival; then look once more
    // after two turns (a datagram read in them is an arrival, and the quiet period starts again). After a stall, timers run
    // before the poll that reads a socket, and a wait resumed in an I/O callback gets its first turn before any fresh poll; the
    // second turn always follows one, so what a stall left queued in the kernel is read before quiet is judged. No time, or a
    // stub that stopped or went down, is never quiescent.
    async drain({ capMs } = {}) {
      const began = performance.now(), result = quiescent => ({ quiescent, waitedMs: performance.now() - began, closedAfterCollect: false });
      const settled = () => ledger.notDone() === 0, quiet = () => performance.now() - ledger.lastArrival() >= cfg.quietMs;
      if (!(capMs > 0)) return result(false);
      while (true) {
        if (!ledger.up()) return result(false);
        if (settled() && quiet()) {
          await (typeof drainTurn === 'function' ? drainTurn() : turns(2));
          if (settled() && quiet() && ledger.up()) return result(true);
        }
        if (!(performance.now() - began < capMs)) return result(false);
        await new Promise(resolve => setTimeout(resolve, Math.min(SINK_LEDGER_LIMITS.pollMs, Math.max(1, capMs - (performance.now() - began)))));
      }
    },
    // The window's lookups (never the witness or its repeats). gap: a settlement gap window (sink-ledger.mjs). final: the run-end
    // window, which nothing follows: it waits (at most the collect's own cap) until nothing has been read for quietMs since its
    // end mark, and still nothing two turns later (Stalls, the header), as a check window waits after its witness; then any
    // lookup or problem recorded after that mark leaves it partial
    // (dns-query-after-final-mark), and a stub that stopped or went down meanwhile fails it. scanned: a scanner read every lookup
    // in the window in full, and the window holds no message the scanner never read (UNSCANNED). udpRecvBuffer: the granted sizes.
    async collect(from, to, { gap = false, final = false } = {}) {
      const w = await ledger.window(from, to, { witness: cfg.witness !== null, witnessWaitMs: cfg.witnessWaitMs, quietMs: cfg.quietMs, gap, scopedUnits: !gap });
      const failed = reason => ({ lookups: [], coverage: 'failed', reason, scanned: false, scannedCanaries, udpRecvBuffer: udpRecvBuffer(), collector: DNS_STUB_COLLECTOR });
      if (w.failed) return failed(w.failed);
      const { problems } = w, lookups = [];
      let scanned = scanner !== null;
      const scanOf = r => { if (r.lookup?.scanProblem) problems.add(r.lookup.scanProblem); if (r.lookup && r.lookup.scanned !== true) scanned = false; };
      // A record of a UDP busy period that may have lost a datagram (UDP loss, the header), whatever the record is.
      const lossOf = r => { if (r.possibleDrop) problems.add('dns-possible-drop-query'); };
      // A repeat of a witness lookup names only a nonce the stub already saw, so it carries nothing of the app's: never a lookup,
      // wherever it lands. A retired TCP placeholder was followed by its own record.
      const skip = r => r.retired || r.repeatOf !== undefined;
      for (const r of w.items) { lossOf(r); if (!skip(r)) { lookups.push({ seq: r.seq, ...r.lookup }); scanOf(r); } }
      for (const r of w.deferred ?? []) { lossOf(r); if (!skip(r)) { problems.add('dns-query-after-witness-request'); scanOf(r); } }
      for (const r of w.pending ?? []) { lossOf(r); if (!skip(r)) problems.add('dns-query-in-flight'); }
      if (final) {
        const began = performance.now(), capMs = cfg.witnessWaitMs + 10 * cfg.quietMs;
        // Quiet, or the cap, is accepted only after two more turns (the drain's rule, above): a datagram a stall left queued in
        // the kernel is read, and counted in its busy period, before the window is judged.
        const quietSince = () => performance.now() - Math.max(ledger.lastArrival(), to.at) >= cfg.quietMs, capped = () => performance.now() - began >= capMs;
        while (true) {
          if (quietSince() || capped()) { await turns(2); if (quietSince() || capped()) break; }
          else await new Promise(resolve => setTimeout(resolve, SINK_LEDGER_LIMITS.pollMs));
        }
        if (!ledger.up()) return failed('dns-listener-down');
        if (lastArrivalSeq > to.seq) problems.add('dns-query-after-final-mark');
      }
      if ([...problems].some(p => UNSCANNED.has(p))) scanned = false;
      const reason = problems.size ? [...problems].sort().join(',').slice(0, 200) : null;
      return { lookups, coverage: reason ? 'partial' : 'complete', reason, scanned, scannedCanaries, udpRecvBuffer: udpRecvBuffer(), collector: DNS_STUB_COLLECTOR };
    },
    async stop() {
      const list = [...(udp ?? []), ...(tcp ?? [])]; udp = null; tcp = null; ledger.stopped();
      for (const socket of sockets) socket.destroy();
      await closeAll(list);
    },
  };
}
