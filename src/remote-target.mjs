// Direct remote HTTPS (H1 step 3): a target declared "operator-remote" with an https origin, reached without a
// forwarder, only under an authorization record that names that exact origin (src/authorization.mjs).
//
// What the connector dials, and how:
// - The origin is https://host[:port]: a DNS name or a literal IPv4 address, no credentials, path, query or
//   fragment (remoteOriginOf). Plain http to anything but 127.0.0.1 is refused at validation.
// - DNS is pinned for the run. The host is resolved once, before the first request, and every request connects to
//   the first address of that answer (the TLS name stays the host, so the certificate is still checked for it).
//   Before each request the host is resolved again; an answer that is not the same set of addresses refuses the run
//   (remote-dns-changed): no further request is sent and no run is saved. A host whose answer rotates through more
//   addresses than one lookup returns cannot be tested this way; use the forwarder.
// - Every address of the answer must be public. A loopback, private, shared (100.64.0.0/10), link-local, cloud
//   metadata, unspecified, multicast, documentation or other reserved address is refused (remote-address-refused)
//   unless the authorization record lists that exact address in "addresses".
// - TLS is verified against the system trust store (and NODE_EXTRA_CA_CERTS, which Node reads itself) for the
//   host name; TLS 1.2 or newer; no proxy, no connection reuse, and a redirect is a response, never followed.
// Errors name the rule, never the host, an address or a path.
import { isIP, BlockList } from 'node:net';
import { lookup } from 'node:dns/promises';

export const isIpAddress = value => typeof value === 'string' && isIP(value) !== 0;
export class RemoteTargetError extends Error {
  constructor(code, message) { super(message); this.name = 'RemoteTargetError'; this.code = code; }
}
const HOST_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
// The normalized origin of a remote https target, or null: lower case, no default port, a DNS name (at least two
// labels, letters, digits and hyphens) or a literal IPv4 address. IPv6 literals are not supported.
export function remoteOriginOf(value) {
  if (typeof value !== 'string' || value.length > 300 || /[\u0000- \u007f]/.test(value)) return null;
  let url; try { url = new URL(value); } catch { return null; }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || !['', '/'].includes(url.pathname) || value.includes('#') || value.includes('?')) return null;
  const host = url.hostname;
  // The host as written must be the host parsed (case aside): no IPv4 shorthand, decimal or hex forms the URL parser rewrites.
  if (host.startsWith('[') || value.slice(value.indexOf('//') + 2).split(/[/:?#]/)[0].toLowerCase() !== host) return null;
  if (isIP(host) !== 4 && !(host.length <= 253 && host.includes('.') && host.split('.').every(label => HOST_LABEL.test(label)) && !/^[0-9.]+$/.test(host))) return null;
  return url.origin;
}

// Address classes. A public address is one in none of these ranges.
const ranges = (list, family) => { const b = new BlockList(); for (const [net, prefix] of list) b.addSubnet(net, prefix, family); return b; };
const V4 = {
  unspecified: [['0.0.0.0', 8]], loopback: [['127.0.0.0', 8]], private: [['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16]],
  shared: [['100.64.0.0', 10]], 'link-local': [['169.254.0.0', 16]], reserved: [['192.0.0.0', 24], ['192.88.99.0', 24], ['198.18.0.0', 15], ['240.0.0.0', 4], ['255.255.255.255', 32]],
  documentation: [['192.0.2.0', 24], ['198.51.100.0', 24], ['203.0.113.0', 24]], multicast: [['224.0.0.0', 4]],
};
const V6 = {
  unspecified: [['::', 128]], loopback: [['::1', 128]], private: [['fc00::', 7], ['fec0::', 10]], 'link-local': [['fe80::', 10]], multicast: [['ff00::', 8]],
  documentation: [['2001:db8::', 32], ['3fff::', 20]], reserved: [['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 23], ['2002::', 16], ['5f00::', 16]],
};
const V4_BLOCKS = Object.entries(V4).map(([name, list]) => [name, ranges(list, 'ipv4')]), V6_BLOCKS = Object.entries(V6).map(([name, list]) => [name, ranges(list, 'ipv6')]);
// Cloud metadata endpoints: AWS, GCP and Azure (169.254.169.254, also link-local), Alibaba, and AWS over IPv6.
const METADATA = new Set(['169.254.169.254', '169.254.170.2', '100.100.100.200', 'fd00:ec2::254']);
// The eight 16-bit groups of a valid IPv6 address; a trailing dotted IPv4 part counts as the last two.
function hextets(address) {
  let text = address.split('%')[0];
  const tail = [], dotted = /:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(text);
  if (dotted) {
    const o = dotted[1].split('.').map(Number);
    tail.push((o[0] << 8) | o[1], (o[2] << 8) | o[3]);
    text = text.slice(0, dotted.index + 1);
    if (!text.endsWith('::')) text = text.slice(0, -1);
  }
  const parse = part => part === '' ? [] : part.split(':').map(h => parseInt(h, 16));
  if (!text.includes('::')) return [...parse(text), ...tail];
  const [head, rest] = text.split('::'), left = parse(head), right = parse(rest);
  return [...left, ...Array(8 - tail.length - left.length - right.length).fill(0), ...right, ...tail];
}
export function addressClass(address) {
  const family = isIP(address);
  if (family === 0) return 'invalid';
  const lower = address.toLowerCase();
  if (METADATA.has(lower)) return 'metadata';
  if (family === 6) {
    // An address that carries an IPv4 address is classed as that address, in either notation (::ffff:7f00:1 is
    // ::ffff:127.0.0.1): IPv4-mapped (::ffff:0:0/96), IPv4-translated (::ffff:0:0:0/96) and IPv4-compatible (::/96).
    const g = hextets(lower), zero = n => g.slice(0, n).every(x => x === 0);
    if ((zero(5) && g[5] === 0xffff) || (zero(4) && g[4] === 0xffff && g[5] === 0) || (zero(6) && !(g[6] === 0 && g[7] <= 1)))
      return addressClass(`${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`);
    for (const [name, block] of V6_BLOCKS) if (block.check(lower, 'ipv6')) return name;
    return 'public';
  }
  for (const [name, block] of V4_BLOCKS) if (block.check(lower, 'ipv4')) return name;
  return 'public';
}

// The system resolver: every address, in the order the system returns them.
export const systemResolve = async host => (await lookup(host, { all: true, verbatim: true })).map(entry => entry.address);
const answerOf = async (host, resolve) => {
  if (isIP(host)) return [host];
  let addresses;
  try { addresses = await resolve(host); } catch { throw new RemoteTargetError('remote-dns-failed', 'the remote target\'s host did not resolve'); }
  if (!Array.isArray(addresses) || !addresses.length || !addresses.every(a => typeof a === 'string' && isIP(a))) throw new RemoteTargetError('remote-dns-failed', 'the remote target\'s host did not resolve to an address');
  return addresses;
};
const sameSet = (a, b) => a.length === b.length && [...a].sort().every((x, i) => x === [...b].sort()[i]);

// Resolve and check the remote origin once, before any request; returns the pin the transport dials.
// allowedAddresses: the record's "addresses" (non-public addresses the operator authorized for this run).
export async function pinRemoteTarget(origin, { resolve = systemResolve, allowedAddresses = [] } = {}) {
  const normalized = remoteOriginOf(origin);
  if (!normalized) throw new RemoteTargetError('remote-origin-invalid', 'a remote target needs an https origin with a host name or IPv4 address');
  const url = new URL(normalized), host = url.hostname;
  const answer = await answerOf(host, resolve);
  const refused = answer.find(address => addressClass(address) !== 'public' && !allowedAddresses.includes(address));
  if (refused !== undefined) throw new RemoteTargetError('remote-address-refused', `the remote target's host resolves to a ${addressClass(refused)} address the authorization record does not name`);
  const address = answer[0];
  let refusal = null;
  return Object.freeze({
    origin: normalized, host, port: url.port === '' ? 443 : Number(url.port), address, family: isIP(address),
    // Before each request: the same answer, or the run is refused (and stays refused).
    async recheck() {
      if (refusal) throw refusal;
      const now = await answerOf(host, resolve).catch(error => { throw (refusal = error); });
      if (!sameSet(now, answer)) throw (refusal = new RemoteTargetError('remote-dns-changed', 'the remote target\'s DNS answer changed during the run, so it was stopped'));
    },
    refusal: () => refusal,
  });
}
