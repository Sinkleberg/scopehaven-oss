// Egress guard for running an evaluation tool offline: node --import <this file>. It is an
// in-process log and a best-effort refusal for Node's own dns, net, tls and dgram APIs. It is not
// the barrier: network evidence for an offline run comes from the OS sandbox profile the run uses,
// never from this log alone.
//
// In each process that loads it:
// - dns.lookup (callback and promise) refuses every name but 'localhost' and loopback addresses;
//   lookupService refuses non-loopback addresses; every c-ares query (resolve*, reverse, on the
//   module, on dns.promises and on either Resolver) is refused, since an offline run needs no DNS.
// - net and tls: the host asked for must be a loopback address or exactly 'localhost', and only a
//   loopback address when the caller passes its own lookup (that lookup can map 'localhost'
//   anywhere). A name that resolves elsewhere is refused before connecting, and the address
//   actually connected is checked again on 'connect'.
// - dgram: send, connect and connectSync to a non-loopback address are refused, and every socket
//   resolves through a lookup that refuses any answer but loopback, its own lookup included (the
//   unspecified address passes only when asked for, as bind() does).
// - process.binding('tcp_wrap' | 'udp_wrap' | 'cares_wrap'), the raw handles under net, dgram and
//   dns, is refused.
// - syncBuiltinESMExports() makes ESM named imports (import { lookup } from 'node:dns') see the
//   guarded functions.
// - NODE_OPTIONS gains --import <this file>, in this process's environment and in any env object
//   passed to child_process, so node children load it too.
// Each refusal is logged to SCOPEHAVEN_EGRESS_LOG (JSON lines), as is each allowed TCP connection
// with the address it actually reached. Allowed loopback datagrams are not logged.
//
// Not covered: native addons; non-node children (python, curl, a browser) and their sockets; node
// started some other way than child_process with its own environment, or a node too old for
// --import in NODE_OPTIONS; worker threads (Node 24 does not run --import there); modules
// preloaded with --require, which run first and can keep the original functions; experimental
// node:quic; UDP multicast joins. Checked on macOS with Node 24.21 only.
// Promptfoo 0.123.1 sends one "telemetry disabled" request per process even with telemetry off;
// this guard refuses and logs it.
import dns from 'node:dns';
import net from 'node:net';
import dgram from 'node:dgram';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { promisify } from 'node:util';
import { appendFileSync } from 'node:fs';

const LOG = process.env.SCOPEHAVEN_EGRESS_LOG;
const record = entry => { if (LOG) try { appendFileSync(LOG, `${JSON.stringify({ at: new Date().toISOString(), pid: process.pid, ...entry })}\n`); } catch {} };
const refused = (target, via) => Object.assign(new Error(`egress refused: ${target} (${via})`), { code: 'EGRESS_REFUSED' });

// Loopback is an IP literal in 127.0.0.0/8 or ::1, IPv4-mapped forms included. Names never match.
const { isIP } = net;
const LOOPBACK = new net.BlockList();
LOOPBACK.addSubnet('127.0.0.0', 8, 'ipv4');
LOOPBACK.addAddress('::1', 'ipv6');
export const isLoopbackAddress = address => {
  const family = isIP(String(address));
  try { return family !== 0 && LOOPBACK.check(String(address), family === 6 ? 'ipv6' : 'ipv4'); } catch { return false; }
};
// A host a socket may ask for: a loopback address, or exactly 'localhost'.
export const isLoopbackHost = host => isLoopbackAddress(host) || String(host).toLowerCase() === 'localhost';

// util.promisify(dns.lookup) relies on symbol properties of the original; keep them.
const keepSymbols = (from, to) => { for (const s of Object.getOwnPropertySymbols(from)) Object.defineProperty(to, s, Object.getOwnPropertyDescriptor(from, s)); return to; };
const guardCallback = (original, via, allowed) => keepSymbols(original, function guarded(target, ...rest) {
  if (allowed(target)) return original.call(this, target, ...rest);
  record({ kind: 'refused', via, host: String(target) });
  const callback = rest.findLast(a => typeof a === 'function');
  if (callback) process.nextTick(callback, refused(target, via));
  return {};
});
const guardPromise = (original, via, allowed) => async function guarded(target, ...rest) {
  if (allowed(target)) return original.call(this, target, ...rest);
  record({ kind: 'refused', via, host: String(target) });
  throw refused(target, via);
};
const never = () => false;

// getaddrinfo and getnameinfo.
dns.lookup = guardCallback(dns.lookup, 'dns.lookup', isLoopbackHost);
dns.promises.lookup = guardPromise(dns.promises.lookup, 'dns.promises.lookup', isLoopbackHost);
dns.lookupService = guardCallback(dns.lookupService, 'dns.lookupService', isLoopbackAddress);
dns.promises.lookupService = guardPromise(dns.promises.lookupService, 'dns.promises.lookupService', isLoopbackAddress);
// c-ares sends its own queries. The prototypes are patched too: new Resolver() objects use them,
// and dns.setServers() rebinds the module functions from them.
for (const [api, via, guard] of [[dns, 'dns', guardCallback], [dns.promises, 'dns.promises', guardPromise]]) {
  for (const k of Object.getOwnPropertyNames(api.Resolver.prototype).filter(k => k === 'reverse' || k.startsWith('resolve')))
    api[k] = api.Resolver.prototype[k] = guard(api.Resolver.prototype[k], `${via}.${k}`, never);
}

// net and tls (tls.connect connects through net.Socket.prototype.connect).
const isPipeName = s => typeof s === 'string' && !(Number(s) >= 0);
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function guardedConnect(...args) {
  // net.connect() passes its arguments already normalized, as one array [options, callback].
  const [first, second] = Array.isArray(args[0]) ? args[0] : args;
  const opts = typeof first === 'object' && first !== null ? first : isPipeName(first) ? { path: first } : { port: first, host: typeof second === 'string' ? second : undefined };
  if (opts.path != null) return connect.apply(this, args); // a local pipe or Unix socket
  const host = String(opts.host || 'localhost'), port = opts.port ?? null;
  // A caller's own lookup can map 'localhost' anywhere; only an IP literal skips the lookup.
  const callerLookup = typeof opts.lookup === 'function';
  if (callerLookup ? !isLoopbackAddress(host) : !isLoopbackHost(host)) {
    record({ kind: 'refused', via: 'net.connect', host, port, ...(callerLookup && { reason: 'caller-lookup' }) });
    process.nextTick(() => this.destroy(refused(host, 'net.connect')));
    return this;
  }
  // net checks this.connecting right after each 'lookup' event, so destroying here stops the attempt.
  const onLookup = (err, address) => {
    if (err || address === undefined || isLoopbackAddress(address)) return;
    record({ kind: 'refused', via: 'net.lookup', host, address, port });
    this.destroy(refused(`${host} -> ${address}`, 'net.lookup'));
  };
  this.on('lookup', onLookup);
  // The address actually connected decides, and it is what the log records.
  this.prependOnceListener('connect', () => {
    this.off('lookup', onLookup);
    const address = this.remoteAddress ?? null;
    if (isLoopbackAddress(address)) return record({ kind: 'allowed', via: 'net.connect', host, address, port: this.remotePort ?? port });
    record({ kind: 'refused-after-connect', via: 'net.connect', host, address, port: this.remotePort ?? port });
    this.destroy(refused(`${host} -> ${address}`, 'net.connect'));
  });
  return connect.apply(this, args);
};

// dgram. Every socket resolves through a checked lookup: an answer that is not loopback is refused,
// except the unspecified address when it was asked for (that is how bind() binds every interface).
const UNSPECIFIED = new Set(['0.0.0.0', '::']);
const checkedLookup = lookup => function guardedDgramLookup(address, family, callback) {
  return lookup.call(this, address, family, (err, ip, ...rest) => {
    if (err || isLoopbackAddress(ip) || (UNSPECIFIED.has(ip) && UNSPECIFIED.has(address))) return callback(err, ip, ...rest);
    record({ kind: 'refused', via: 'dgram.lookup', host: String(address), address: String(ip) });
    callback(refused(`${address} -> ${ip}`, 'dgram.lookup'));
  });
};
// Node's own default: a literal of the socket's family is itself; anything else goes to dns.lookup.
const dgramLookup = (address, family, callback) => isIP(address) === family ? process.nextTick(callback, null, address, family) : dns.lookup(address, family, callback);
const withCheckedLookup = type => {
  const options = type !== null && typeof type === 'object' ? type : { type };
  return { ...options, lookup: checkedLookup(typeof options.lookup === 'function' ? options.lookup : dgramLookup) };
};
const createSocket = dgram.createSocket;
dgram.createSocket = function guardedCreateSocket(type, ...rest) { return createSocket.call(this, withCheckedLookup(type), ...rest); };
dgram.Socket = new Proxy(dgram.Socket, {
  construct: (target, [type, ...rest], newTarget) => Reflect.construct(target, [withCheckedLookup(type), ...rest], newTarget),
  apply: (target, self, [type, ...rest]) => Reflect.apply(target, self, [withCheckedLookup(type), ...rest]),
});
// The address asked for is checked before any lookup runs; a refusal fails the way dgram's own errors do.
const datagram = dgram.Socket.prototype, { send, connect: dgramConnect, connectSync } = datagram;
const refuseDatagram = (socket, via, address, callback) => {
  record({ kind: 'refused', via, host: String(address) });
  const err = refused(address, via);
  process.nextTick(() => typeof callback === 'function' ? callback(err) : socket.emit('error', err));
};
const isConnected = socket => { try { socket.remoteAddress(); return true; } catch { return false; } };
datagram.send = function guardedSend(buffer, offset, length, port, address, callback) {
  // dgram's own reading of (msg, offset, length, port, address, cb) and (msg, port, address, cb).
  const target = address || (port && typeof port !== 'function') ? address : length;
  if (!isConnected(this) && typeof target === 'string' && target !== '' && !isLoopbackHost(target))
    return refuseDatagram(this, 'dgram.send', target, [...arguments].findLast(a => typeof a === 'function'));
  return send.apply(this, arguments);
};
datagram.connect = function guardedDgramConnect(port, address, callback) {
  if (typeof address === 'string' && address !== '' && !isLoopbackHost(address)) return refuseDatagram(this, 'dgram.connect', address, callback);
  return dgramConnect.apply(this, arguments);
};
if (connectSync) datagram.connectSync = function guardedConnectSync(port, address) {
  if (typeof address === 'string' && address !== '' && !isLoopbackHost(address)) { record({ kind: 'refused', via: 'dgram.connectSync', host: address }); throw refused(address, 'dgram.connectSync'); }
  return connectSync.apply(this, arguments);
};

// The raw handles under net, dgram and dns would skip every check above.
const RAW_BINDINGS = new Set(['tcp_wrap', 'udp_wrap', 'cares_wrap']);
const binding = process.binding;
process.binding = function guardedBinding(name) {
  if (!RAW_BINDINGS.has(String(name))) return binding.call(this, name);
  record({ kind: 'refused', via: 'process.binding', host: String(name) });
  throw refused(name, 'process.binding');
};

// Node children load the guard through NODE_OPTIONS: this process's environment carries it, and so
// does an env object a caller hands to child_process (with the log path, unless it names its own).
// --import takes this file's URL, which has no spaces to quote; it goes first so the guard loads
// before any other --import the child is given.
const withGuard = options => { const s = options == null ? '' : String(options); return s.includes(import.meta.url) ? s : `--import ${import.meta.url} ${s}`.trim(); };
process.env.NODE_OPTIONS = withGuard(process.env.NODE_OPTIONS);
const guardEnv = args => {
  const i = args.findLastIndex(a => typeof a === 'object' && a !== null && !Array.isArray(a));
  const env = args[i]?.env;
  if (env && typeof env === 'object') args[i] = { ...args[i], env: { ...(LOG && { SCOPEHAVEN_EGRESS_LOG: LOG }), ...env, NODE_OPTIONS: withGuard(env.NODE_OPTIONS) } };
  return args;
};
for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
  // exec and execFile carry their own promisify version, which calls the original directly.
  const original = childProcess[name], custom = original[promisify.custom];
  childProcess[name] = function guardedChild(...args) { return original.apply(this, guardEnv(args)); };
  if (custom) Object.defineProperty(childProcess[name], promisify.custom, { value: (...args) => custom(...guardEnv(args)) });
}

syncBuiltinESMExports();
record({ kind: 'guard', argv: process.argv.slice(1, 3).map(a => a.split('/').pop()) });
