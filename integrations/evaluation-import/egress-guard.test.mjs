// The egress guard is checked in child node processes started with --import <guard>, an
// environment of PATH and the log path only, and a timeout. Every outside address a child tries is
// TEST-NET-1 (192.0.2.x) or a name under .invalid, except Promptfoo's telemetry host, which the
// guard must refuse by name; the guard refuses all of them before any packet. Look-alike names in
// the loopback-set test only reach the classifier. Nameserver and peer stand-ins listen on 127.0.0.1.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const GUARD = fileURLToPath(new URL('./promptfoo/egress-guard.mjs', import.meta.url));
// Shared by the child scripts: settle a callback or a promise into an error code, never hang.
const HELPERS = `
  const within = (p, ms = 2000) => Promise.race([p, new Promise(r => setTimeout(() => r('timeout'), ms))]);
  const viaCallback = (fn, ...a) => within(new Promise(r => fn(...a, e => r(e ? e.code : 'resolved'))));
  const viaPromise = p => within(p.then(() => 'resolved', e => e.code));`;

// Runs an ES module under the guard and returns its last stdout line (JSON) and the parsed log.
function underGuard(t, source, env = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven egress guard '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const log = join(dir, 'egress.jsonl');
  const run = spawnSync(process.execPath, ['--import', GUARD, '--input-type=module', '-e', `${HELPERS}\n${source}\nsetTimeout(() => process.exit(0), 20);`],
    { cwd: dir, encoding: 'utf8', env: { PATH: process.env.PATH, SCOPEHAVEN_EGRESS_LOG: log, ...env }, timeout: 30000 });
  assert.equal(run.status, 0, `child failed: ${run.stderr}`);
  const lines = existsSync(log) ? readFileSync(log, 'utf8').trim().split('\n').map(l => JSON.parse(l)) : [];
  return { out: JSON.parse(run.stdout.trim().split('\n').at(-1)), log: lines, pid: run.pid };
}
const has = (log, match) => log.some(line => Object.entries(match).every(([k, v]) => line[k] === v));
const loopbackIp = address => /^(127\.\d+\.\d+\.\d+|::1|::ffff:127\.\d+\.\d+\.\d+)$/.test(address ?? '');

test('fetch: Promptfoo telemetry and an outside address are refused and logged, and a loopback fetch is logged with the address it reached', t => {
  const { out, log, pid } = underGuard(t, `
    import http from 'node:http'; import tls from 'node:tls';
    const attempt = u => within(fetch(u, { signal: AbortSignal.timeout(5000) }).then(r => r.text(), e => e.cause?.code ?? e.name), 6000);
    const out = { telemetry: await attempt('https://r.promptfoo.app/'), testNet: await attempt('http://192.0.2.1/') };
    const server = http.createServer((q, s) => s.end('ok')).listen(0, '127.0.0.1'); await new Promise(r => server.once('listening', r));
    const port = server.address().port;
    out.loopback = await attempt('http://localhost:' + port + '/');
    out.tls = await within(new Promise(r => { const s = tls.connect({ host: '127.0.0.1', port }); s.on('connect', () => { r('connected'); s.destroy(); }); s.on('error', e => r(e.code)); }));
    server.close(); console.log(JSON.stringify(out));`);
  assert.deepEqual(out, { telemetry: 'EGRESS_REFUSED', testNet: 'EGRESS_REFUSED', loopback: 'ok', tls: 'connected' });
  assert.ok(has(log, { kind: 'guard', pid }));
  assert.ok(has(log, { kind: 'refused', via: 'net.connect', host: 'r.promptfoo.app' }), 'the telemetry request is logged as refused');
  assert.ok(has(log, { kind: 'refused', via: 'net.connect', host: '192.0.2.1' }));
  const allowed = log.filter(l => l.kind === 'allowed');
  assert.ok(allowed.some(l => l.host === 'localhost' && loopbackIp(l.address)), 'an allowed line records the address reached, not only the name asked for');
  assert.ok(allowed.some(l => l.host === '127.0.0.1' && l.address === '127.0.0.1'), 'tls connects through the same check');
  assert.ok(allowed.every(l => loopbackIp(l.address)), 'no allowed line names an outside address');
});

test('dns.lookup and dns.promises.lookup refuse names other than localhost and log each refusal, through ESM named imports too', t => {
  const { out, log } = underGuard(t, `
    import dns, { lookup } from 'node:dns'; import { lookup as lookupPromise } from 'node:dns/promises'; import { promisify } from 'node:util';
    console.log(JSON.stringify({
      named: await viaCallback(lookup, 'named-import.invalid'),
      module: await viaCallback(dns.lookup, 'module.invalid'),
      promises: await viaPromise(dns.promises.lookup('promises.invalid')),
      namedPromises: await viaPromise(lookupPromise('named-promises.invalid')),
      localhost: (await promisify(dns.lookup)('localhost')).address,
    }));`);
  assert.deepEqual({ ...out, localhost: loopbackIp(out.localhost) }, { named: 'EGRESS_REFUSED', module: 'EGRESS_REFUSED', promises: 'EGRESS_REFUSED', namedPromises: 'EGRESS_REFUSED', localhost: true });
  for (const [via, host] of [['dns.lookup', 'named-import.invalid'], ['dns.lookup', 'module.invalid'], ['dns.promises.lookup', 'promises.invalid'], ['dns.promises.lookup', 'named-promises.invalid']])
    assert.ok(has(log, { kind: 'refused', via, host }), `refused ${via} ${host} is logged`);
});

test('c-ares resolution is refused and logged: resolveTxt, a Resolver, dns.promises.resolve, reverse and lookupService; no query reaches a nameserver', t => {
  const { out, log } = underGuard(t, `
    import dns, { resolveTxt } from 'node:dns'; import dgram from 'node:dgram';
    const ns = dgram.createSocket('udp4'); let queries = 0; ns.on('message', () => queries++);
    await new Promise(r => ns.bind(0, '127.0.0.1', r)); const server = '127.0.0.1:' + ns.address().port;
    dns.setServers([server]); dns.promises.setServers([server]);
    const resolver = new dns.Resolver({ timeout: 300, tries: 1 }); resolver.setServers([server]);
    const promisesResolver = new dns.promises.Resolver({ timeout: 300, tries: 1 }); promisesResolver.setServers([server]);
    const out = {
      resolveTxt: await viaCallback(dns.resolveTxt, 'txt.invalid'),
      namedResolveTxt: await viaCallback(resolveTxt, 'named.invalid'),
      resolver: await viaCallback((...a) => resolver.resolve4(...a), 'resolver.invalid'),
      resolverGeneric: await viaCallback((...a) => resolver.resolve(...a), 'generic.invalid', 'A'),
      reverse: await viaCallback(dns.reverse, '192.0.2.1'),
      promisesResolve: await viaPromise(dns.promises.resolve('promises.invalid', 'A')),
      promisesResolver: await viaPromise(promisesResolver.resolveTxt('promises-resolver.invalid')),
      lookupService: await viaCallback(dns.lookupService, '192.0.2.1', 80),
      promisesLookupService: await viaPromise(dns.promises.lookupService('192.0.2.1', 80)),
    };
    await new Promise(r => setTimeout(r, 200)); ns.close();
    console.log(JSON.stringify({ ...out, queries }));`);
  const { queries, ...results } = out;
  assert.deepEqual(Object.entries(results).filter(([, v]) => v !== 'EGRESS_REFUSED'), [], 'every resolution is refused');
  assert.equal(queries, 0, 'no query reached the stand-in nameserver');
  for (const via of ['dns.resolveTxt', 'dns.resolve4', 'dns.resolve', 'dns.reverse', 'dns.promises.resolve', 'dns.promises.resolveTxt', 'dns.lookupService', 'dns.promises.lookupService'])
    assert.ok(has(log, { kind: 'refused', via }), `refused ${via} is logged`);
});

test('dgram: send, connect and connectSync to an outside address are refused and logged, and a socket lookup cannot point localhost elsewhere', t => {
  const { out, log } = underGuard(t, `
    import dgram, { Socket } from 'node:dgram';
    // Answers localhost with an outside address and every other name, the bind address included, with itself.
    const outside = (h, o, cb) => process.nextTick(cb, null, h === 'localhost' ? '192.0.2.1' : h, 4);
    const receiver = dgram.createSocket('udp4'); let received = 0; receiver.on('message', () => received++);
    await new Promise(r => receiver.bind(0, '127.0.0.1', r)); const port = receiver.address().port;
    const sockets = [];
    const udp = options => { const s = options instanceof Socket ? options : dgram.createSocket(options); sockets.push(s); s.on('error', () => {}); return s; };
    const sendTo = (s, address, p = 9) => within(new Promise(r => s.send(Buffer.from('x'), p, address, e => r(e ? e.code : 'sent'))));
    const out = {
      loopback: await sendTo(udp('udp4'), '127.0.0.1', port),
      testNet: await sendTo(udp('udp4'), '192.0.2.1'),
      connect: await within(new Promise(r => udp('udp4').connect(9, '192.0.2.1', e => r(e ? e.code : 'connected')))),
      connectSync: (() => { try { udp('udp4').connectSync(9, '192.0.2.1'); return 'connected'; } catch (e) { return e.code; } })(),
      callerLookup: await sendTo(udp({ type: 'udp4', lookup: outside }), 'localhost'),
      constructed: await sendTo(udp(new Socket({ type: 'udp4', lookup: outside })), 'localhost'),
      // The unspecified address is allowed only when it was asked for, as bind() does.
      unspecified: await sendTo(udp({ type: 'udp4', lookup: (h, o, cb) => process.nextTick(cb, null, h === 'localhost' ? '0.0.0.0' : h, 4) }), 'localhost'),
    };
    await new Promise(r => setTimeout(r, 100)); for (const s of [receiver, ...sockets]) try { s.close(); } catch {}
    console.log(JSON.stringify({ ...out, received }));`);
  assert.deepEqual(out, { loopback: 'sent', testNet: 'EGRESS_REFUSED', connect: 'EGRESS_REFUSED', connectSync: 'EGRESS_REFUSED', callerLookup: 'EGRESS_REFUSED', constructed: 'EGRESS_REFUSED', unspecified: 'EGRESS_REFUSED', received: 1 });
  assert.ok(has(log, { kind: 'refused', via: 'dgram.send', host: '192.0.2.1' }), 'refused at send, before any lookup');
  assert.ok(has(log, { kind: 'refused', via: 'dgram.connect', host: '192.0.2.1' }));
  assert.ok(has(log, { kind: 'refused', via: 'dgram.connectSync', host: '192.0.2.1' }));
  assert.equal(log.filter(l => l.kind === 'refused' && l.via === 'dgram.lookup' && l.host === 'localhost' && l.address === '192.0.2.1').length, 2, 'createSocket and new Socket both check the lookup answer');
  assert.ok(has(log, { kind: 'refused', via: 'dgram.lookup', host: 'localhost', address: '0.0.0.0' }));
});

test('net: a caller lookup cannot point localhost elsewhere, a name that resolves elsewhere is refused before connecting, and the connected address is checked', t => {
  const { out, log } = underGuard(t, `
    import net from 'node:net'; import http from 'node:http'; import dns from 'node:dns';
    const server = net.createServer(s => s.on('error', () => {})).listen(0, '127.0.0.1'); await new Promise(r => server.once('listening', r));
    const port = server.address().port;
    const outside = (h, o, cb) => { if (typeof o === 'function') cb = o; process.nextTick(() => o?.all ? cb(null, [{ address: '192.0.2.1', family: 4 }]) : cb(null, '192.0.2.1', 4)); };
    // How a socket ended, and every address it tried to reach.
    const outcome = s => within(new Promise(r => { const tried = []; s.on('connectionAttempt', ip => tried.push(ip));
      s.on('connect', () => setTimeout(() => r({ result: s.destroyed ? 'destroyed' : 'connected', tried }), 50)); s.on('error', e => r({ result: e.code, tried })); }))
      .then(o => { s.destroy(); return o === 'timeout' ? { result: 'timeout' } : o; });
    const out = {
      callerLookup: await outcome(net.connect({ host: 'localhost', port: 9, lookup: outside })),
      httpCallerLookup: await within(new Promise(r => http.get({ host: 'localhost', port: 9, lookup: outside }).on('error', e => r(e.code)).on('response', () => r('response')))),
      literalWithLookup: await outcome(net.connect({ host: '127.0.0.1', port, lookup: outside })),
    };
    // Another resolver answering localhost with an outside address.
    const lookup = dns.lookup; dns.lookup = outside;
    out.remapped = await outcome(net.connect({ host: 'localhost', port: 9 }));
    dns.lookup = lookup;
    // A socket whose peer reads as an outside address once connected.
    const peer = new net.Socket(); Object.defineProperty(peer, 'remoteAddress', { get: () => '192.0.2.1' });
    out.peer = await outcome(peer.connect(port, '127.0.0.1'));
    server.close(); console.log(JSON.stringify(out));`);
  assert.deepEqual(out, {
    callerLookup: { result: 'EGRESS_REFUSED', tried: [] }, httpCallerLookup: 'EGRESS_REFUSED', literalWithLookup: { result: 'connected', tried: ['127.0.0.1'] },
    remapped: { result: 'EGRESS_REFUSED', tried: [] }, peer: { result: 'EGRESS_REFUSED', tried: ['127.0.0.1'] },
  });
  assert.equal(log.filter(l => l.kind === 'refused' && l.via === 'net.connect' && l.host === 'localhost' && l.reason === 'caller-lookup').length, 2, 'net.connect and http.get with their own lookup are refused by name');
  assert.ok(has(log, { kind: 'refused', via: 'net.lookup', host: 'localhost', address: '192.0.2.1' }), 'refused on the lookup answer, before connecting');
  assert.ok(has(log, { kind: 'refused-after-connect', via: 'net.connect', address: '192.0.2.1' }));
  assert.ok(has(log, { kind: 'allowed', via: 'net.connect', host: '127.0.0.1', address: '127.0.0.1' }));
  assert.ok(!log.some(l => l.kind === 'allowed' && (l.host === 'localhost' || !loopbackIp(l.address))), 'never logged as allowed');
});

test('the loopback set is 127.0.0.0/8 and ::1 with their IPv4-mapped forms, plus the name localhost; 0.0.0.0, 10.0.0.1 and look-alike names are not', t => {
  const loopback = ['127.0.0.1', '127.255.255.254', '::1', '0:0:0:0:0:0:0:1', '::ffff:127.0.0.1', 'localhost', 'LocalHost'];
  const outside = ['0.0.0.0', '10.0.0.1', '192.0.2.1', '::', '::ffff:10.0.0.1', 'localhost.example', 'localhost.', '127.0.0.1.nip.io', '[::1]', '127.1', ''];
  const { out, log } = underGuard(t, `
    import net from 'node:net';
    const guard = await import(${JSON.stringify(pathToFileURL(GUARD).href)});
    const server = net.createServer(s => s.on('error', () => {})).listen(0, '127.0.0.1'); await new Promise(r => server.once('listening', r));
    const zero = await within(new Promise(r => net.connect({ host: '0.0.0.0', port: server.address().port }).on('connect', function () { r('connected'); this.destroy(); }).on('error', e => r(e.code))));
    server.close();
    console.log(JSON.stringify({
      notLoopback: ${JSON.stringify(loopback)}.filter(h => !guard.isLoopbackHost(h)),
      loopback: ${JSON.stringify(outside)}.filter(h => guard.isLoopbackHost(h)),
      nameAsAddress: guard.isLoopbackAddress('localhost'), zero,
    }));`);
  assert.deepEqual(out, { notLoopback: [], loopback: [], nameAsAddress: false, zero: 'EGRESS_REFUSED' });
  assert.ok(has(log, { kind: 'refused', via: 'net.connect', host: '0.0.0.0' }));
});

// A node child that fetches an outside address and reports the outcome, its pid and one NODE_OPTIONS value.
const CHILD_FETCH = `"fetch('http://192.0.2.1/', { signal: AbortSignal.timeout(3000) }).then(() => 'reached', e => e.cause?.code ?? e.name).then(result => console.log(JSON.stringify({ result, pid: process.pid, maxHeaderSize: require('node:http').maxHeaderSize })))"`;

test('a node child that inherits the environment is guarded too: NODE_OPTIONS carries the guard first and keeps existing options, and the child refuses and logs an outside fetch', t => {
  const { out, log, pid } = underGuard(t, `
    import { spawnSync } from 'node:child_process';
    const child = spawnSync(process.execPath, ['-e', ${CHILD_FETCH}], { encoding: 'utf8', timeout: 15000 });
    console.log(JSON.stringify({ nodeOptions: process.env.NODE_OPTIONS, child: JSON.parse(child.stdout.trim() || '{}') }));`,
  { NODE_OPTIONS: '--max-http-header-size=12345' });
  assert.equal(out.child.result, 'EGRESS_REFUSED');
  assert.equal(out.child.maxHeaderSize, 12345, 'existing NODE_OPTIONS reach the child');
  assert.equal(out.nodeOptions, `--import ${pathToFileURL(GUARD).href} --max-http-header-size=12345`);
  assert.notEqual(out.child.pid, pid);
  assert.ok(has(log, { kind: 'guard', pid: out.child.pid }), 'the child loaded the guard');
  assert.ok(has(log, { kind: 'refused', via: 'net.connect', host: '192.0.2.1', pid: out.child.pid }), 'the child logged its refusal');
});

test('a node child given its own env object is guarded too, through spawnSync and a promisified execFile, and logs to the same file', t => {
  const { out, log } = underGuard(t, `
    import { spawnSync, execFile } from 'node:child_process'; import { promisify } from 'node:util';
    const env = { PATH: process.env.PATH };
    const sync = spawnSync(process.execPath, ['-e', ${CHILD_FETCH}], { encoding: 'utf8', timeout: 15000, env });
    const promised = await promisify(execFile)(process.execPath, ['-e', ${CHILD_FETCH}], { encoding: 'utf8', timeout: 15000, env });
    console.log(JSON.stringify({ sync: JSON.parse(sync.stdout.trim() || '{}'), promised: JSON.parse(promised.stdout.trim() || '{}'), envUntouched: Object.keys(env) }));`);
  assert.deepEqual([out.sync.result, out.promised.result, out.envUntouched], ['EGRESS_REFUSED', 'EGRESS_REFUSED', ['PATH']]);
  for (const child of [out.sync, out.promised]) assert.ok(has(log, { kind: 'refused', via: 'net.connect', host: '192.0.2.1', pid: child.pid }), 'each child logged its refusal');
});

test('process.binding refuses the raw tcp, udp and c-ares handles and logs each, and other bindings still load', t => {
  const { out, log } = underGuard(t, `
    const out = {};
    for (const name of ['tcp_wrap', 'udp_wrap', 'cares_wrap', 'constants']) { try { out[name] = typeof process.binding(name); } catch (e) { out[name] = e.code; } }
    console.log(JSON.stringify(out));`);
  assert.deepEqual(out, { tcp_wrap: 'EGRESS_REFUSED', udp_wrap: 'EGRESS_REFUSED', cares_wrap: 'EGRESS_REFUSED', constants: 'object' });
  for (const name of ['tcp_wrap', 'udp_wrap', 'cares_wrap']) assert.ok(has(log, { kind: 'refused', via: 'process.binding', host: name }));
});
