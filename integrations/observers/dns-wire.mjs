// The DNS message codec the loopback DNS stub (dns-stub.mjs) uses: one query in, one answer out. Pure: no I/O, no network.
// It reads only what a stub resolver sends (RFC 1035 section 4: a 12-byte header, then the question section), and writes
// only answers the stub chose (loopback A and AAAA records, NXDOMAIN, NODATA and error codes). It never reads an answer,
// authority or additional section as data, so an EDNS OPT record in a query is skipped, not parsed.
//
// A name is returned three ways, so a caller can match on it without guessing how it was written:
//   - labels: each label's bytes as a binary ("latin1") string, case kept (DNS keeps case on the wire; resolvers that randomize
//     it, the "0x20" trick, still send a case-variant of the same name);
//   - name: the presentation form, lowercased, with "\DDD" escapes for any byte outside letters, digits, "-" and "_", and "\."
//     for a dot inside a label, so a label holding a dot never reads as two labels;
//   - wireBytes: the name's length on the wire, for the RFC 1035 limits (255 octets, 63 per label).
// Compression pointers in a question are followed only backwards and at most 16 times: a forward pointer is malformed, and so is
// a loop (a label followed by a pointer back to it only goes backwards, so the hop limit is what ends it).

export const DNS_TYPES = Object.freeze({ 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 64: 'SVCB', 65: 'HTTPS', 255: 'ANY' });
export const RCODES = Object.freeze({ noerror: 0, formerr: 1, servfail: 2, nxdomain: 3, notimp: 4, refused: 5 });
export const DNS_WIRE_LIMITS = Object.freeze({ nameBytes: 255, labelBytes: 63, pointerHops: 16, udpBytes: 512 });

class DnsWireError extends Error { constructor(code) { super(code); this.code = code; } }
const fail = code => { throw new DnsWireError(code); };

// A label lowercased as DNS compares names (RFC 4343): only A to Z fold. JavaScript's toLowerCase would also fold the bytes
// 0xC0 to 0xDE of a binary string, so two different names would read as one.
export const asciiLower = binary => binary.replace(/[A-Z]+/g, run => run.toLowerCase());

// The presentation form of one label (RFC 1035 section 5.1 escapes), lowercased (A to Z only).
const PLAIN = /^[a-z0-9_-]$/;
export function presentLabel(binary) {
  let out = '';
  for (const ch of asciiLower(binary)) {
    if (PLAIN.test(ch)) out += ch;
    else if (ch === '.' || ch === '\\') out += `\\${ch}`;
    else out += `\\${String(ch.charCodeAt(0)).padStart(3, '0')}`;
  }
  return out;
}

// Reads a name at offset; returns { labels, next, wireBytes }. next is the offset after the name where it started (after the
// first pointer, when one was followed).
function readName(buf, offset) {
  const labels = [];
  let pos = offset, next = null, hops = 0, wireBytes = 1;
  while (true) {
    if (pos >= buf.length) fail('dns-name-truncated');
    const len = buf[pos];
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) fail('dns-name-truncated');
      const target = ((len & 0x3f) << 8) | buf[pos + 1];
      // Only backwards, and a bounded number of times: a label then a pointer back to it does loop, and the hop limit ends it.
      if (target >= pos || ++hops > DNS_WIRE_LIMITS.pointerHops) fail('dns-name-pointer');
      if (next === null) next = pos + 2;
      pos = target;
      continue;
    }
    if (len & 0xc0) fail('dns-label-type');
    if (len === 0) { if (next === null) next = pos + 1; break; }
    if (pos + 1 + len > buf.length) fail('dns-name-truncated');
    labels.push(buf.subarray(pos + 1, pos + 1 + len).toString('latin1'));
    wireBytes += len + 1;
    if (wireBytes > DNS_WIRE_LIMITS.nameBytes) fail('dns-name-too-long');
    pos += 1 + len;
  }
  return { labels, next, wireBytes };
}

// A query: { id, opcode, rd, flags, question: { labels, name, wireBytes, qtype, type, qclass } | null, questions }, or, for
// anything it cannot read, the same with `error` (a 'dns-...' code) and question null. It never throws on its input. `id` is
// null when not even the header could be read, so no answer can be addressed to the query.
export function parseQuery(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return { id: null, opcode: null, rd: 0, flags: 0, questions: 0, question: null, error: 'dns-header-truncated' };
  const id = buf.readUInt16BE(0), flags = buf.readUInt16BE(2);
  const qr = flags >> 15, opcode = (flags >> 11) & 0xf, rd = (flags >> 8) & 1;
  const questions = buf.readUInt16BE(4), answers = buf.readUInt16BE(6), authority = buf.readUInt16BE(8);
  const base = { id, opcode, rd, flags, questions, question: null };
  // A response, or a query carrying answers, is not a stub resolver's query.
  if (qr === 1 || answers !== 0 || authority !== 0) return Object.assign(base, { error: 'dns-not-a-query' });
  if (questions !== 1) return Object.assign(base, { error: 'dns-question-count' });
  try {
    const { labels, next, wireBytes } = readName(buf, 12);
    if (next + 4 > buf.length) fail('dns-question-truncated');
    const qtype = buf.readUInt16BE(next), qclass = buf.readUInt16BE(next + 2);
    const name = labels.map(presentLabel).join('.');
    return Object.assign(base, { question: { labels, name, wireBytes, qtype, type: DNS_TYPES[qtype] ?? `TYPE${qtype}`, qclass }, questionEnd: next + 4 });
  } catch (error) {
    if (error instanceof DnsWireError) return Object.assign(base, { error: error.code });
    throw error;
  }
}

function encodeName(labels) {
  const parts = [];
  for (const label of labels) { const b = Buffer.from(label, 'latin1'); parts.push(Buffer.from([b.length]), b); }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}
const ipv4 = text => Buffer.from(text.split('.').map(Number));
function ipv6(text) {
  const [head, tail] = text.includes('::') ? text.split('::') : [text, null];
  const h = head ? head.split(':') : [], t = tail ? tail.split(':') : [];
  const groups = tail === null ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  const out = Buffer.alloc(16);
  groups.forEach((g, i) => out.writeUInt16BE(parseInt(g, 16), i * 2));
  return out;
}

// An answer to a parsed query. records: [{ type: 'A' | 'AAAA', address }] (TTL 0, so a cache never answers a later lookup for
// the stub). rcode: a name in RCODES. The question is echoed exactly as received (its labels, case kept), with no OPT record:
// a client that sent EDNS reads a plain answer. At most two records follow a name of at most 255 bytes, so an answer always
// fits a 512-byte UDP datagram and never needs the TC bit.
export function encodeResponse(query, { rcode = 'noerror', records = [], authoritative = true } = {}) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(query.id ?? 0, 0);
  let flags = 0x8000 | ((query.opcode ?? 0) << 11) | ((query.rd ?? 0) << 8) | (RCODES[rcode] ?? RCODES.servfail);
  if (authoritative) flags |= 0x0400;
  const q = query.question;
  header.writeUInt16BE(q ? 1 : 0, 4);
  header.writeUInt16BE(q ? records.length : 0, 6);
  const parts = [header];
  if (q) {
    const qname = encodeName(q.labels);
    const tail = Buffer.alloc(4); tail.writeUInt16BE(q.qtype, 0); tail.writeUInt16BE(q.qclass, 2);
    parts.push(qname, tail);
    for (const r of records) {
      const data = r.type === 'A' ? ipv4(r.address) : ipv6(r.address);
      const rr = Buffer.alloc(10);
      // A pointer to the question's name (offset 12): an answer's owner is always the question's name.
      rr.writeUInt16BE(r.type === 'A' ? 1 : 28, 0); rr.writeUInt16BE(1, 2); rr.writeUInt32BE(0, 4); rr.writeUInt16BE(data.length, 8);
      parts.push(Buffer.from([0xc0, 12]), rr, data);
    }
  }
  let out = Buffer.concat(parts);
  out.writeUInt16BE(flags, 2);
  return out;
}

// A query a test or client sends: the labels (binary strings), the type number and an id.
export function encodeQuery({ id = 1, labels, qtype = 1, qclass = 1, rd = 1, edns = false }) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0); header.writeUInt16BE(rd ? 0x0100 : 0, 2); header.writeUInt16BE(1, 4);
  if (edns) header.writeUInt16BE(1, 10);
  const tail = Buffer.alloc(4); tail.writeUInt16BE(qtype, 0); tail.writeUInt16BE(qclass, 2);
  const parts = [header, encodeName(labels), tail];
  // An EDNS(0) OPT pseudo-record: root name, type 41, a 1232-byte UDP size, no options.
  if (edns) parts.push(Buffer.from([0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]));
  return Buffer.concat(parts);
}

// Reads a response's header and answer addresses (tests only; the stub never reads responses).
export function parseResponse(buf) {
  const id = buf.readUInt16BE(0), flags = buf.readUInt16BE(2), qd = buf.readUInt16BE(4), an = buf.readUInt16BE(6);
  let pos = 12;
  for (let i = 0; i < qd; i++) pos = readName(buf, pos).next + 4;
  const answers = [];
  for (let i = 0; i < an; i++) {
    pos = readName(buf, pos).next;
    const type = buf.readUInt16BE(pos), ttl = buf.readUInt32BE(pos + 4), len = buf.readUInt16BE(pos + 8);
    const data = buf.subarray(pos + 10, pos + 10 + len);
    answers.push({ type: DNS_TYPES[type] ?? type, ttl, data });
    pos += 10 + len;
  }
  const rcode = Object.entries(RCODES).find(([, v]) => v === (flags & 0xf))?.[0] ?? flags & 0xf;
  return { id, qr: flags >> 15, aa: (flags >> 10) & 1, tc: (flags >> 9) & 1, rcode, answers };
}
