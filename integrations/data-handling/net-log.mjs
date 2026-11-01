// Loaded with `node --import` by zero-egress.mjs. Records every socket connect, DNS lookup and UDP send
// that this Node process makes, loopback included, as one JSON line each in SCOPEHAVEN_EGRESS_LOG.
// It blocks nothing and opens no connection itself: the OS sandbox around the run does the blocking.
import net from 'node:net';
import dns from 'node:dns';
import dgram from 'node:dgram';
import { appendFileSync } from 'node:fs';

const file = process.env.SCOPEHAVEN_EGRESS_LOG;
const record = entry => {
  try { appendFileSync(file, `${JSON.stringify({ t: Date.now(), pid: process.pid, script: process.argv[1] ?? null, ...entry })}\n`); } catch {}
};

if (file) {
  const connect = net.Socket.prototype.connect;
  net.Socket.prototype.connect = function (...args) {
    // net.connect() passes its normalized [options, callback] array; direct calls pass options or (port, host).
    const first = Array.isArray(args[0]) ? args[0][0] : args[0];
    if (first && typeof first === 'object') {
      if (typeof first.path === 'string') record({ kind: 'unix', path: first.path });
      else record({ kind: 'connect', host: first.host ?? 'localhost', port: first.port ?? null });
    } else if (typeof first === 'string' && !/^\d+$/.test(first)) record({ kind: 'unix', path: first });
    else record({ kind: 'connect', host: typeof args[1] === 'string' ? args[1] : 'localhost', port: first ?? null });
    return connect.apply(this, args);
  };
  for (const name of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveAny']) {
    const original = dns[name];
    if (typeof original === 'function') dns[name] = function (host, ...rest) { record({ kind: 'dns', host, via: name }); return original.call(this, host, ...rest); };
    const promised = dns.promises?.[name];
    if (typeof promised === 'function') dns.promises[name] = function (host, ...rest) { record({ kind: 'dns', host, via: `promises.${name}` }); return promised.call(this, host, ...rest); };
  }
  const send = dgram.Socket.prototype.send;
  dgram.Socket.prototype.send = function (...args) {
    const port = args.find((value, i) => i > 0 && typeof value === 'number'), host = args.find((value, i) => i > 1 && typeof value === 'string');
    record({ kind: 'udp', host: host ?? 'localhost', port: port ?? null });
    return send.apply(this, args);
  };
}
