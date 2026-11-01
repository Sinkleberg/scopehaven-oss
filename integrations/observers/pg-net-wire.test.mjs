// pg-net-wire: windows over a scripted tap (no docker, no database), and the tap script's own frame classification run on
// this machine's python3 with crafted frames (no socket opened). The live run is pg-net-wire.live.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { spawnSync } from 'node:child_process';
import { createPgNetWire, tapArgs, TAP_SCRIPT, PG_NET_QUEUE, PG_NET_WIRE_SCHEMA, PG_NET_WIRE_REMEDY } from './pg-net-wire.mjs';
import { digest } from '../../src/domain.mjs';

const GW = '192.168.65.254';
// A scripted tap: answers each mark command after everything emitted before it, as the real tap does.
// A docker CLI call other than the tap's run: answers on stdout and exits 0 (or 1 when out is null).
function fakeCli(out) {
  const k = new EventEmitter(); k.stdout = new PassThrough(); k.kill = () => {};
  setImmediate(() => { if (out !== null) k.stdout.end(out); k.emit('exit', out === null ? 1 : 0); });
  return k;
}
// sharing(): the names of other containers in the database container's namespace, each call (null: docker ps fails).
// image: whether docker image inspect finds the tap's image; runExit: the tap's docker run exits with this code before it is ready.
function fakeTap({ gw = GW, drops = () => 0, lo = () => 0, epoch = () => 'tap-1', ifs = () => ['eth0', 'lo'], sharing = () => [], dbMode = 'supabase_network_copy', image = true, runExit = null } = {}) {
  const stdout = new PassThrough(), child = new EventEmitter();
  const emit = o => stdout.write(`${typeof o === 'string' ? o : JSON.stringify(o)}\n`);
  child.stdout = stdout;
  child.stdin = new Writable({ write(chunk, _enc, done) {
    for (const line of chunk.toString().split('\n').filter(Boolean)) { const [k, n] = line.split(' '); setImmediate(() => emit({ k, n: Number(n), drops: drops(), packets: 0, lo: lo(), epoch: epoch(), ifs: ifs() })); }
    done();
  } });
  child.stdin.on('finish', () => setImmediate(() => child.emit('exit', 0)));
  child.kill = () => child.emit('exit', null);
  const cli = args => {
    tap.calls.push(args.join(' '));
    if (args[0] === 'image') return fakeCli(image ? 'sha256:imageid\n' : null);
    if (args[0] === 'inspect' && args[2] === '{{.Id}} {{.HostConfig.NetworkMode}}') return fakeCli(`dbid0 ${dbMode}\n`);
    if (args[0] === 'ps') { const others = sharing(); tap.sharingNow = others; return fakeCli(others === null ? null : ['dbid0', 'tapid', ...others.map((_, i) => `other${i}`)].join('\n') + '\n'); }
    if (args[0] === 'inspect') { const name = tap.args[tap.args.indexOf('--name') + 1]; return fakeCli([`/supabase_db_copy default`, `/${name} container:dbid0`, ...(tap.sharingNow ?? []).map(n => `/${n} container:supabase_db_copy`)].join('\n') + '\n'); }
    return fakeCli('');
  };
  const tap = { child, emit, args: null, spawned: 0, calls: [], spawn: (_cmd, args) => { if (args[0] !== 'run') return cli(args); tap.args = args; tap.spawned += 1; setImmediate(() => (runExit === null ? emit({ k: 'ready', gw, listen: 1, epoch: epoch(), ifs: ifs() }) : child.emit('exit', runExit))); return child; } };
  return tap;
}
// pg_net, scripted: each queued witness is sent (a SYN to its port) after delayMs, unless witness(i) says otherwise; the statement's
// first four results are the custody readings: program-capable login roles, extensions, and the two function counts.
function fakePg(tap, { delayMs = 20, witness = () => true, fail = () => false, programs = () => ['supabase_admin'], extensions = () => ['pg_net', 'plpgsql'], untrusted = () => 0, definers = () => 0, reach = () => ['app_gateway', 'app_service'] } = {}) {
  let i = 0;
  const pg = { sql: [], connect: async () => ({
    async query(sql) {
      pg.sql.push(sql); const n = ++i;
      if (fail(n)) throw new Error('permission denied');
      const port = Number(/:(\d+)\/scopehaven-pg-net-witness/.exec(sql)[1]);
      if (witness(n)) setTimeout(() => { pg.before?.(n); tap.emit({ k: 'syn', i: 'eth0', d: GW, dp: port, sp: 40000 + n }); pg.after?.(n); }, delayMs);
      const roles = programs(n);
      return roles === null ? [{ rows: [['1']] }] : [{ rows: roles.map(r => [r]) }, { rows: extensions(n).map(e => [e]) }, { rows: [[String(untrusted(n))]] }, { rows: [[String(definers(n))]] }, { rows: reach(n).map(r => [r]) }, { rows: [['1']] }];
    },
    close() {},
  }) };
  return pg;
}
const ENV = { SCOPEHAVEN_TARGET_PGNET: 'postgres:pw' };
const IMAGE = `python@sha256:${'ab'.repeat(32)}`;
const make = (tap, pg, extra = {}) => createPgNetWire({ env: ENV, container: 'supabase_db_copy', image: IMAGE, host: '127.0.0.1', port: 54322, database: 'postgres',
  credentialEnv: 'SCOPEHAVEN_TARGET_PGNET', programRoles: ['supabase_admin'], requestRoles: ['app_gateway'], witnessWaitMs: 1000, quietMs: 100, spawn: tap.spawn, connect: pg.connect, ...extra });
const window = async (o, between = async () => {}) => { const from = await o.mark(); await between(); const to = await o.mark(); return o.collect(from, to); };
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

test('a window with nothing but the two witnesses is complete and covers the queue', async t => {
  const tap = fakeTap(), pg = fakePg(tap), o = make(tap, pg); await o.start(); t.after(() => o.stop());
  const w = await window(o, () => pause(50));
  assert.deepEqual([w.coverage, w.reason, w.covers, w.events, w.custody], ['complete', null, [PG_NET_QUEUE], [], 'observer-held']);
  assert.deepEqual([w.wire.custody, w.wire.programRoles], ['observer-held', { declared: 1, read: true, undeclared: 0 }]);
  assert(!Object.hasOwn(w.wire, 'remedy'));
  assert.deepEqual([w.wire.schema, w.wire.witness, w.wire.sends, w.wire.drops], [PG_NET_WIRE_SCHEMA, { start: true, end: true }, 0, { start: 0, end: 0 }]);
  // The interfaces the tap read, so "every interface" can be checked against the namespace.
  assert.deepEqual(w.wire.tap, { socket: 'AF_PACKET, every interface', interfaces: { start: ['eth0', 'lo'], window: ['eth0', 'lo'], end: ['eth0', 'lo'] }, sameTap: true });
  const { digest: sealed, ...record } = w.wire;
  assert.equal(sealed, digest(record));
  // The witness is queued through pg_net, to the host gateway the tap resolved, on a fresh port per mark.
  assert.equal(pg.sql.length, 2);
  assert(pg.sql.every(s => s.includes(`SELECT net.http_get('http://${GW}:`)));
  // The program-capable login roles are read in the same statement, before the witness is queued.
  assert(pg.sql.every(s => s.indexOf('pg_execute_server_program') > 0 && s.indexOf('pg_execute_server_program') < s.indexOf('net.http_get')));
  assert.notEqual(/:(\d+)\//.exec(pg.sql[0])[1], /:(\d+)\//.exec(pg.sql[1])[1]);
});

test('anything else sent in the window makes it partial; the record keeps digests, never a host, target, name or address', async t => {
  for (const [frames, kinds] of [
    [[{ k: 'syn', i: 'eth0', d: '203.0.113.7', dp: 443, sp: 41000 }], { tcp: 1 }],
    [[{ k: 'seg', i: 'eth0', d: '203.0.113.7', dp: 80, sp: 41001, r: 'http', m: 'POST', t: '/hook?ticket=T-9', h: 'hooks.example.test' }], { segment: 1 }],
    [[{ k: 'seg', i: 'eth0', d: '203.0.113.7', dp: 443, sp: 41002, r: 'tls', sni: 'hooks.example.test' }], { segment: 1 }],
    [[{ k: 'udp', i: 'lo', d: '127.0.0.11', dp: 53999, q: 'hooks.example.test', dns: true }], { dns: 1 }],
    [[{ k: 'syn', i: 'lo', d: '127.0.0.11', dp: 40123, sp: 41003 }], { dns: 1 }],
    [[{ k: 'udp', i: 'eth0', d: '203.0.113.7', dp: 9999, q: null, dns: false }], { udp: 1 }],
    [[{ k: 'ip', i: 'eth0', p: 132, d: '203.0.113.7' }], { ip: 1 }],
  ]) {
    const tap = fakeTap(), o = make(tap, fakePg(tap)); await o.start(); t.after(() => o.stop());
    const w = await window(o, async () => { await pause(40); for (const f of frames) tap.emit(f); });
    assert.deepEqual([w.coverage, w.reason, w.covers, w.wire.kinds], ['partial', 'pg-net-sent', [], kinds], JSON.stringify(frames));
    const text = JSON.stringify(w);
    for (const raw of ['hooks.example.test', '/hook', 'T-9', '203.0.113.7']) assert(!text.includes(raw), `${raw} in ${text}`);
  }
  const tap = fakeTap(), o = make(tap, fakePg(tap)); await o.start(); t.after(() => o.stop());
  const w = await window(o, async () => { await pause(40); tap.emit({ k: 'seg', i: 'eth0', d: '203.0.113.7', dp: 80, sp: 41001, r: 'http', m: 'POST', t: '/hook', h: 'hooks.example.test' }); });
  assert.deepEqual(Object.keys(w.wire.listed[0]).sort(), ['addressDigest', 'dport', 'dst', 'iface', 'kind', 'request']);
  assert.deepEqual([w.wire.listed[0].dst, w.wire.listed[0].request.kind], ['public', 'http']);
  assert.match(w.wire.listed[0].request.hostDigest, /^[0-9a-f]{64}$/);
});

test('ICMP, link-layer frames and connections inside the container are counted, never sends', async t => {
  let lo = 0;
  const tap = fakeTap({ lo: () => lo }), o = make(tap, fakePg(tap)); await o.start(); t.after(() => o.stop());
  const w = await window(o, async () => { await pause(40); tap.emit({ k: 'icmp', i: 'eth0' }); tap.emit({ k: 'link', i: 'eth0', p: 2054 }); lo = 3; });
  assert.deepEqual([w.coverage, w.wire.icmp, w.wire.link, w.wire.inContainer], ['complete', 1, 1, 3]);
});

test('the window starts at the start witness and ends after the quiet period that follows the end witness', async t => {
  // A send of the earlier batch (between the start mark and its witness) is the earlier window's.
  const tap = fakeTap(), pg = fakePg(tap), o = make(tap, pg); await o.start(); t.after(() => o.stop());
  pg.before = n => { if (n === 1) tap.emit({ k: 'syn', i: 'eth0', d: '203.0.113.7', dp: 443, sp: 41000 }); };
  const earlier = await window(o, () => pause(60));
  assert.deepEqual([earlier.coverage, earlier.wire.sends], ['complete', 0]);
  // A send of the end witness's own batch that reaches the wire just after it is this window's.
  const tap2 = fakeTap(), pg2 = fakePg(tap2), o2 = make(tap2, pg2); await o2.start(); t.after(() => o2.stop());
  pg2.after = n => { if (n === 2) setTimeout(() => tap2.emit({ k: 'syn', i: 'eth0', d: '203.0.113.8', dp: 443, sp: 41001 }), 50); };
  const late = await window(o2, () => pause(10));
  assert.deepEqual([late.coverage, late.reason, late.wire.sends], ['partial', 'pg-net-sent', 1]);
});

test('a missing witness, kernel drops or an unreadable line make the window partial', async t => {
  const tap = fakeTap(), o = make(tap, fakePg(tap, { witness: n => n !== 2 })); await o.start(); t.after(() => o.stop());
  const missing = await window(o);
  assert.deepEqual([missing.coverage, missing.reason, missing.wire.witness, missing.covers], ['partial', 'pg-net-witness-missing', { start: true, end: false }, []]);
  assert(missing.wire.waitedMs >= 1000, String(missing.wire.waitedMs));
  let drops = 0;
  const tap2 = fakeTap({ drops: () => drops }), o2 = make(tap2, fakePg(tap2)); await o2.start(); t.after(() => o2.stop());
  const dropped = await window(o2, async () => { drops = 4; });
  assert.deepEqual([dropped.coverage, dropped.reason, dropped.wire.drops], ['partial', 'pg-net-tap-drops', { start: 0, end: 4 }]);
  const tap3 = fakeTap(), o3 = make(tap3, fakePg(tap3)); await o3.start(); t.after(() => o3.stop());
  const unreadable = await window(o3, async () => { await pause(40); tap3.emit('{not json'); });
  assert.deepEqual([unreadable.coverage, unreadable.reason], ['partial', 'pg-net-tap-unreadable']);
});

test('a tap that stops, or a witness that cannot be queued, fails the window', async t => {
  const tap = fakeTap(), o = make(tap, fakePg(tap)); await o.start(); t.after(() => o.stop());
  const from = await o.mark(); await pause(40); tap.child.emit('exit', 1);
  const to = await o.mark();
  assert.deepEqual([(await o.collect(from, to)).coverage, (await o.collect(from, to)).reason], ['failed', 'pg-net-tap-down']);
  const tap2 = fakeTap(), o2 = make(tap2, fakePg(tap2, { fail: n => n === 2 })); await o2.start(); t.after(() => o2.stop());
  const failed = await window(o2);
  assert.deepEqual([failed.coverage, failed.reason, failed.covers], ['failed', 'pg-net-mark-failed', []]);
  assert.deepEqual((await o2.collect({ index: 99 }, { index: 100 })).reason, 'pg-net-mark-failed');
});

test('start refuses a tap that could not resolve the host gateway; the sidecar drops every capability but NET_RAW', async () => {
  const tap = fakeTap({ gw: null }), o = make(tap, fakePg(tap));
  await assert.rejects(o.start(), /did not resolve host\.docker\.internal/);
  const args = tapArgs({ container: 'supabase_db_copy', image: IMAGE, name: 'scopehaven-pg-net-tap-x' });
  const at = flag => args[args.indexOf(flag) + 1];
  // Never pulled: --pull never, before the image.
  assert.deepEqual([args[0], at('--pull')], ['run', 'never']);
  assert(args.indexOf('--pull') < args.indexOf(IMAGE));
  assert.deepEqual([at('--network'), at('--cap-drop'), at('--cap-add'), at('--security-opt'), at('--entrypoint')], ['container:supabase_db_copy', 'ALL', 'NET_RAW', 'no-new-privileges', 'python3']);
  assert(args.includes('--read-only') && args.includes('--rm'));
  for (const flag of ['-v', '--volume', '--mount', '--privileged', '-p', '--publish', '--pid', '-e', '--env']) assert(!args.includes(flag), flag);
  assert.deepEqual(args.slice(-4, -1), ['-I', '-u', '-c']);
});

test('an image that is not on this machine fails start closed: nothing is pulled and no tap runs', async () => {
  const tap = fakeTap({ image: false }), o = make(tap, fakePg(tap));
  await assert.rejects(o.start(), /tap image is not on this machine/);
  assert.equal(tap.spawned, 0);
  assert.deepEqual(tap.calls, [`image inspect --format {{.Id}} ${IMAGE}`]);
  assert(!tap.calls.some(c => /\bpull\b/.test(c)));
  assert.deepEqual(await o.mark(), { index: 1 });
  const w = await o.collect({ index: 1 }, { index: 1 });
  assert.deepEqual([w.coverage, w.reason, w.covers], ['failed', 'pg-net-tap-not-started', []]);
  // Removed after the check: docker run --pull never exits before the tap is ready, and start still refuses.
  const gone = fakeTap({ runExit: 125 }), o2 = make(gone, fakePg(gone));
  await assert.rejects(o2.start(), /the tap did not start/);
  assert.equal(gone.args[gone.args.indexOf('--pull') + 1], 'never');
});

test('configuration: a container name, loopback, bounded waits and a SCOPEHAVEN_TARGET_ credential', () => {
  const tap = fakeTap(), pg = fakePg(tap);
  for (const [extra, message] of [[{ container: 'db; rm' }, /container/], [{ host: 'localhost' }, /127\.0\.0\.1/], [{ witnessWaitMs: 10 }, /witnessWaitMs/],
    [{ quietMs: 50 }, /quietMs/], [{ credentialEnv: 'PGPASSWORD' }, /SCOPEHAVEN_TARGET_/], [{ image: 'Bad Image' }, /image/], [{ image: undefined }, /digest/], [{ image: 'python:3.12-slim' }, /digest/],
    [{ image: `python:3.12-slim@sha256:${'ab'.repeat(32)}` }, /digest/], [{ image: 'python@sha256:abc' }, /digest/], [{ docker: 'docker' }, /absolute path/]])
    assert.throws(() => make(tap, pg, extra), message, JSON.stringify(extra));
});

// The tap's own classification, on crafted frames, in this machine's python3 (the script's main() opens no socket here).
const PY = spawnSync('python3', ['-I', '-c', 'import sys; print(sys.version_info[0])'], { encoding: 'utf8' });
test('the tap reports only what the namespace sends, classified', { skip: PY.status !== 0 && 'python3 not found' }, () => {
  const harness = String.raw`
import json, socket, struct, sys
g = {'__name__': 'tap'}
exec(sys.stdin.read(), g)
out = []
g['emit'] = lambda o: out.append(o)
g['state']['listen'], g['state']['listenAt'] = {5432}, 1e18
def ip4(src, dst, proto, body, frag=0):
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 0, frag, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst)) + body
def ip6(src, dst, nh, body):
    return struct.pack('!IHBB', 6 << 28, len(body), nh, 64) + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + body
def tcp(sp, dp, flags, payload=b''): return struct.pack('!HHIIBBHHH', sp, dp, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload
def udp(sp, dp, payload): return struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
def dnsq(name): return b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b''.join(bytes([len(l)]) + l.encode() for l in name.split('.')) + b'\x00\x00\x01\x00\x01'
def hello(name):
    sni = name.encode(); ext = struct.pack('!HHHBH', 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
    body = b'\x03\x03' + b'\x00' * 32 + b'\x00' + b'\x00\x02\x13\x01' + b'\x01\x00' + struct.pack('!H', len(ext)) + ext
    hs = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs
E, L = ('eth0', 0x0800), ('lo', 0x0800)
cases = [
  ('syn out', ip4('172.20.0.2', '203.0.113.7', 6, tcp(41000, 443, 0x02)), E, 4),
  ('syn in', ip4('203.0.113.7', '172.20.0.2', 6, tcp(443, 41000, 0x02)), E, 0),
  ('syn-ack out', ip4('172.20.0.2', '172.20.0.5', 6, tcp(5432, 50000, 0x12)), E, 4),
  ('syn lo inside', ip4('127.0.0.1', '127.0.0.1', 6, tcp(41000, 5432, 0x02)), L, 4),
  ('syn lo resolver', ip4('127.0.0.1', '127.0.0.11', 6, tcp(41000, 40123, 0x02)), L, 4),
  ('server segment', ip4('172.20.0.2', '172.20.0.5', 6, tcp(5432, 50000, 0x18, b'Rdata')), E, 4),
  ('http segment', ip4('172.20.0.2', '203.0.113.7', 6, tcp(41001, 80, 0x18, b'POST /hook HTTP/1.1\r\nHost: hooks.example.test\r\n\r\n{}')), E, 4),
  ('tls segment', ip4('172.20.0.2', '203.0.113.7', 6, tcp(41002, 443, 0x18, hello('hooks.example.test'))), E, 4),
  ('opaque segment', ip4('172.20.0.2', '203.0.113.7', 6, tcp(41003, 9000, 0x18, b'\x00\x01binary')), E, 4),
  ('dns via resolver', ip4('127.0.0.1', '127.0.0.11', 17, udp(50000, 41234, dnsq('a.example.test'))), L, 4),
  ('resolver reply', ip4('127.0.0.11', '127.0.0.1', 17, udp(41234, 50000, b'x' * 20)), L, 4),
  ('udp lo inside', ip4('127.0.0.1', '127.0.0.1', 17, udp(1, 2, b'x')), L, 4),
  ('udp out', ip4('172.20.0.2', '203.0.113.7', 17, udp(5000, 9999, b'x')), E, 4),
  ('later fragment', ip4('172.20.0.2', '203.0.113.7', 6, tcp(41004, 443, 0x02), frag=0x0010), E, 4),
  ('icmp', ip4('172.20.0.2', '203.0.113.7', 1, b'\x03\x03' + b'\x00' * 6), E, 4),
  ('sctp', ip4('172.20.0.2', '203.0.113.7', 132, b'\x00' * 12), E, 4),
  ('arp', b'\x00' * 28, ('eth0', 0x0806), 4),
  ('ipv6 syn', ip6('fd00::2', '2001:db8::1', 6, tcp(41005, 443, 0x02)), ('eth0', 0x86DD), 4),
  ('short', b'\x45', E, 4),
]
result = {}
for name, pkt, (ifname, proto), ptype in cases:
    out.clear(); g['handle'](pkt, ifname, proto, ptype, 100.0 + len(result)); result[name] = list(out)
result['lo'] = g['state']['lo']
# The per-connection segment throttle: a second segment within 250 ms is not reported, unless a mark came between them.
seg = lambda: ip4('172.20.0.2', '203.0.113.7', 6, tcp(42000, 9000, 0x18, b'\x00more'))
out.clear(); g['handle'](seg(), 'eth0', 0x0800, 4, 200.0); g['handle'](seg(), 'eth0', 0x0800, 4, 200.1); result['throttled'] = [o['k'] for o in out]
out.clear(); g['handle'](seg(), 'eth0', 0x0800, 4, 300.0); g['reply']('m', 7); g['handle'](seg(), 'eth0', 0x0800, 4, 300.1); result['across a mark'] = [o['k'] for o in out]
print(json.dumps(result))
`;
  const run = spawnSync('python3', ['-I', '-c', harness], { input: TAP_SCRIPT, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const r = JSON.parse(run.stdout);
  const only = name => { assert.equal(r[name].length, 1, `${name}: ${JSON.stringify(r[name])}`); return r[name][0]; };
  for (const name of ['syn in', 'syn-ack out', 'syn lo inside', 'server segment', 'resolver reply', 'udp lo inside', 'later fragment']) assert.deepEqual(r[name], [], name);
  assert.equal(r.lo, 2, 'connections and datagrams inside the container are counted');
  assert.deepEqual(only('syn out'), { k: 'syn', i: 'eth0', d: '203.0.113.7', dp: 443, sp: 41000 });
  assert.deepEqual(only('syn lo resolver'), { k: 'syn', i: 'lo', d: '127.0.0.11', dp: 40123, sp: 41000 });
  assert.deepEqual(only('http segment'), { k: 'seg', i: 'eth0', d: '203.0.113.7', dp: 80, sp: 41001, r: 'http', m: 'POST', t: '/hook', h: 'hooks.example.test' });
  assert.deepEqual(only('tls segment'), { k: 'seg', i: 'eth0', d: '203.0.113.7', dp: 443, sp: 41002, r: 'tls', sni: 'hooks.example.test' });
  assert.equal(only('opaque segment').r, 'opaque');
  assert.deepEqual(only('dns via resolver'), { k: 'udp', i: 'lo', d: '127.0.0.11', dp: 41234, q: 'a.example.test', dns: true });
  assert.deepEqual(only('udp out'), { k: 'udp', i: 'eth0', d: '203.0.113.7', dp: 9999, q: null, dns: false });
  assert.deepEqual([only('icmp').k, only('sctp').k, only('sctp').p, only('arp').k, only('short').k], ['icmp', 'ip', 132, 'link', 'bad']);
  assert.deepEqual(only('ipv6 syn'), { k: 'syn', i: 'eth0', d: '2001:db8::1', dp: 443, sp: 41005 });
  assert.deepEqual([r.throttled, r['across a mark']], [['seg'], ['seg', 'm', 'seg']]);
});

test('a witness is read only from a SYN to the host gateway at its own port', async t => {
  const tap = fakeTap(), pg = fakePg(tap), o = make(tap, pg); await o.start(); t.after(() => o.stop());
  const w = await window(o, async () => { await pause(40); tap.emit({ k: 'syn', i: 'eth0', d: '203.0.113.7', dp: Number(/:(\d+)\//.exec(pg.sql[0])[1]), sp: 41000 }); });
  assert.deepEqual([w.coverage, w.reason, w.wire.sends], ['partial', 'pg-net-sent', 1]);
});

test('one tap must answer the whole window over the same interfaces; a mark before the tap started fails', async t => {
  let tapEpoch = 'tap-1', ifs = ['eth0', 'lo'];
  const tap = fakeTap({ epoch: () => tapEpoch, ifs: () => ifs }), o = make(tap, fakePg(tap)); await o.start(); t.after(() => o.stop());
  const gap = await window(o, async () => { await pause(40); tapEpoch = 'tap-2'; });
  assert.deepEqual([gap.coverage, gap.reason, gap.covers, gap.wire.tap.sameTap], ['partial', 'pg-net-tap-gap', [], false]);
  tapEpoch = 'tap-1';
  const added = await window(o, async () => { await pause(40); ifs = ['eth0', 'eth1', 'lo']; });
  assert.deepEqual([added.coverage, added.reason, added.wire.tap.interfaces.end], ['partial', 'pg-net-interfaces-changed', ['eth0', 'eth1', 'lo']]);
  const tap2 = fakeTap(), o2 = make(tap2, fakePg(tap2));
  const early = await o2.mark(); await o2.start(); t.after(() => o2.stop()); const later = await o2.mark();
  assert.deepEqual([(await o2.collect(early, later)).coverage, (await o2.collect(early, later)).reason], ['failed', 'pg-net-tap-not-started']);
  // A tap that cannot list the namespace's interfaces does not start.
  const tap3 = fakeTap({ ifs: () => null }), o3 = make(tap3, fakePg(tap3));
  await assert.rejects(o3.start(), /did not start/);
});

// The row the stack connector wires (a database-only prohibition on a Supabase copy), through the HTTP connector: pg-wal's scripted
// session, this observer over the scripted tap, and an owned app on loopback. pg_net's queue exists (unlogged) at every mark.
const { createServer } = await import('node:http');
const { runHttpAssessment } = await import('../../src/http-connector.mjs');
const { validateHttpRunEvidence } = await import('../../src/contracts.mjs');
const { observerInstanceId } = await import('../../src/http-effects.mjs');
const { createPgWalObserver } = await import('./pg-wal.mjs');
const { fakeServer } = await import('./fixtures/fake-pg-wal.mjs');
async function assessRow(t, { wired, onRead = () => {} }) {
  const tap = fakeTap(), pg = fakePg(tap);
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    if (req.headers.authorization !== 'Bearer synthetic-bob') return reply(401, {});
    if (req.url === '/me') return reply(200, { user: 'bob' });
    if (req.url === '/orders/b') return reply(200, { id: 'b' });
    if (req.url === '/orders/a') { onRead(tap); return reply(404, {}); }
    reply(404, {});
  }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const profile = { id: 'orders', name: 'Orders', applicationId: 'orders-app', origin, buildLabel: 'b1', contextId: 'synthetic-orders',
    actors: { bob: { principalId: 'bob', credentialEnv: 'SCOPEHAVEN_TARGET_BOB', identityValue: 'bob' } }, requiredControlIds: ['WHOAMI', 'B-OWN-RECORD'],
    observers: [{ id: 'wal', type: 'pg-wal', host: '127.0.0.1', port: 54322, database: 'postgres', credentialEnv: 'SCOPEHAVEN_TARGET_WAL', settleMs: 250, platform: 'supabase', barrierMs: 100,
      tables: [{ table: 'orders', key: 'id' }] }],
    checks: [
      { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'bob', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'bob' }] },
      { id: 'B-OWN-RECORD', title: 'Bob opens his own order (allowed use)', category: 'Access', severity: 'control', actorId: 'bob', method: 'GET', path: '/orders/b', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/id', expected: 'b' }] },
      { id: 'B-READS-A-RECORD-BACKEND', title: 'The foreign record\'s row is not changed by the read', category: 'Access', severity: 'high', actorId: 'bob', method: 'GET', path: '/orders/a', evidenceRequirement: 'backend',
        assertions: [{ kind: 'status.in', expected: [403, 404] }], effects: [{ kind: 'effect.none', select: { source: 'sql-wal', name: 'orders' } }] },
    ] };
  const s = fakeServer(); s.notInWal = [PG_NET_QUEUE];
  const factory = configs => configs.map(c => Object.assign(createPgWalObserver({ instanceId: observerInstanceId(c.type, c.id), env: { SCOPEHAVEN_TARGET_WAL: 'wal:pw' }, host: c.host, port: c.port, database: c.database,
    credentialEnv: c.credentialEnv, tables: c.tables, platform: c.platform, barrierMs: c.barrierMs, connect: s.connect, ...(wired ? { wire: make(tap, pg) } : {}) }), { postResponseSettleMs: c.settleMs }));
  const run = await runHttpAssessment(profile, { env: { SCOPEHAVEN_TARGET_BOB: 'synthetic-bob', SCOPEHAVEN_TARGET_WAL: 'wal:pw' }, observerFactory: factory });
  validateHttpRunEvidence(run);
  const row = run.results.find(r => r.id === 'B-READS-A-RECORD-BACKEND');
  return { row, window: row.trace[1].data.windows[0], tap };
}

test('the backend row: inconclusive while pg_net\'s queue is unobserved, decided when the wire saw nothing, inconclusive when pg_net sent', async t => {
  const bare = await assessRow(t, { wired: false });
  assert.deepEqual([bare.row.status, bare.window.coverage, bare.window.reason], ['inconclusive', 'partial', 'table-not-in-wal']);
  const quiet = await assessRow(t, { wired: true });
  assert.deepEqual([quiet.row.status, quiet.row.backendEvidence, quiet.window.coverage], ['pass', 'observed', 'complete']);
  const sent = await assessRow(t, { wired: true, onRead: tap => setTimeout(() => tap.emit({ k: 'syn', i: 'eth0', d: '203.0.113.7', dp: 443, sp: 41000 }), 60) });
  assert.deepEqual([sent.row.status, sent.window.coverage, sent.window.reason], ['inconclusive', 'partial', 'table-not-in-wal']);
});

test('custody: a window covers the queue only when every program-capable login role read at both marks is declared', async t => {
  const run = async (extra, programs) => { const tap = fakeTap(), o = make(tap, fakePg(tap, { programs }), extra); await o.start(); t.after(() => o.stop()); return window(o, () => pause(40)); };
  // No declaration: the subject may hold such a role, so it could have closed the window early. Complete, but it covers nothing.
  const bare = await run({ programRoles: undefined });
  assert.deepEqual([bare.coverage, bare.reason, bare.custody, bare.covers, bare.wire.programRoles], ['complete', null, 'subject-writable', [], { declared: 0, read: true, undeclared: null }]);
  // A subject-writable window names the remedy (a fixed text, never a role); an observer-held one does not.
  assert.equal(bare.wire.remedy, PG_NET_WIRE_REMEDY);
  assert.match(PG_NET_WIRE_REMEDY, /^Declare in programRoles only roles you control\. .*move such functions to an owner without those powers\.$/);
  // Not even when no such role exists: the declaration is what says the subject holds none.
  const none = await run({ programRoles: undefined }, () => []);
  assert.deepEqual([none.custody, none.covers], ['subject-writable', []]);
  // A role nobody declared appears at the end mark: subject-writable, counted, never named.
  const extra = await run({}, n => (n === 2 ? ['app_owner', 'supabase_admin'] : ['supabase_admin']));
  assert.deepEqual([extra.coverage, extra.custody, extra.covers, extra.wire.programRoles], ['complete', 'subject-writable', [], { declared: 1, read: true, undeclared: 1 }]);
  // An observed role is never named; only the declaration is, word for word.
  assert(!JSON.stringify(extra).includes('app_owner'));
  assert.deepEqual(extra.declaration.programRoles, ['supabase_admin']);
  // The roles could not be read at a mark: not observer-held.
  const unread = await run({}, n => (n === 1 ? null : ['supabase_admin']));
  assert.deepEqual([unread.custody, unread.covers, unread.wire.programRoles], ['subject-writable', [], { declared: 1, read: false, undeclared: null }]);
  // Fewer roles than declared is still observer-held; a partial window never covers, whatever its custody.
  const fewer = await run({ programRoles: ['supabase_admin', 'operator_two'] }, () => []);
  assert.deepEqual([fewer.custody, fewer.covers], ['observer-held', [PG_NET_QUEUE]]);
  const tap = fakeTap(), o = make(tap, fakePg(tap)); await o.start(); t.after(() => o.stop());
  const sent = await window(o, async () => { await pause(40); tap.emit({ k: 'syn', i: 'eth0', d: '203.0.113.7', dp: 443, sp: 41000 }); });
  assert.deepEqual([sent.coverage, sent.custody, sent.covers], ['partial', 'observer-held', []]);
  for (const programRoles of [[], 'supabase_admin', ['a', 'a'], ['bad-name'], ['(PUBLIC)'], Array.from({ length: 17 }, (_, i) => `r${i}`)])
    assert.throws(() => make(fakeTap(), fakePg(fakeTap()), { programRoles }), /programRoles is a list/);
});

test('custody: a backend network path, a lent superuser power or another container in the namespace keeps a window subject-writable', async t => {
  const run = async (pgOptions = {}, tapOptions = {}) => { const tap = fakeTap(tapOptions), pg = fakePg(tap, pgOptions), o = make(tap, pg); await o.start(); t.after(() => o.stop()); return { w: await window(o, () => pause(40)), pg, tap }; };
  const { w: clean, pg, tap } = await run();
  assert.deepEqual([clean.custody, clean.wire.backendNetwork, clean.wire.sharedNamespace], ['observer-held', { extensions: [], untrustedFunctions: 0, definerFunctions: 0 }, 0]);
  // The statement reads roles reached by SET ROLE too, and the extensions and functions, before the witness.
  assert.match(pg.sql[0], /WITH RECURSIVE edge\(a, b\)[\s\S]*pg_extension[\s\S]*lanpltrusted[\s\S]*net\.http_get/);
  // The functions initdb created (OIDs below 16384) are not read as untrusted or lending; a lending function is one whose owner holds the power.
  const statements = pg.sql[0].split('; ');
  // initdb's own are exactly those below FirstNormalObjectId in pg_catalog: never a name, a schema the app can create, or an owner.
  const initdbKey = "\\(p\\.oid >= 16384 OR p\\.pronamespace <> 'pg_catalog'::pg_catalog\\.regnamespace\\)";
  // Every power is read over the roles a login role can SET ROLE to (INHERIT or not).
  // Reach is a closure: SET ROLE (membership, INHERIT or not) and SECURITY DEFINER calls (the function runs as its owner), any number of steps.
  assert.match(statements[0], /^\/\* sh:pg-net-witness \*\/ WITH RECURSIVE edge\(a, b\) AS \(SELECT x\.oid, y\.oid FROM pg_catalog\.pg_roles x, pg_catalog\.pg_roles y WHERE pg_catalog\.pg_has_role\(x\.oid, y\.oid, 'MEMBER'\) UNION SELECT x\.oid, p\.proowner FROM pg_catalog\.pg_roles x JOIN pg_catalog\.pg_proc p ON p\.prosecdef AND /);
  assert.match(statements[0], /AND pg_catalog\.has_function_privilege\(x\.oid, p\.oid, 'EXECUTE'\)\), reach\(s, t\) AS \(SELECT oid, oid FROM pg_catalog\.pg_roles UNION SELECT r\.s, e\.b FROM reach r JOIN edge e ON e\.a = r\.t\) SELECT r\.rolname FROM pg_catalog\.pg_roles r WHERE r\.rolcanlogin AND EXISTS \(SELECT 1 FROM reach x JOIN pg_catalog\.pg_roles g ON g\.oid = x\.t WHERE x\.s = r\.oid AND \(g\.oid IN \(SELECT s\.oid FROM pg_catalog\.pg_roles s WHERE s\.rolsuper OR pg_catalog\.pg_has_role\(s\.oid, 'pg_execute_server_program', 'MEMBER'\)\)/);
  // CREATEROLE before PostgreSQL 16; CREATE in the database with a trusted extension outside the list or pg_create_subscription; supautils' privileged role.
  assert.match(statements[0], / OR \(g\.rolcreaterole AND pg_catalog\.current_setting\('server_version_num'\)::int < 160000\)/);
  assert.match(statements[0], / OR \(pg_catalog\.has_database_privilege\(g\.oid, pg_catalog\.current_database\(\), 'CREATE'\) AND \(EXISTS \(SELECT 1 FROM pg_catalog\.pg_available_extension_versions v WHERE v\.trusted AND NOT \(v\.name::text = ANY \(ARRAY\['btree_gin', /);
  assert.match(statements[0], / OR EXISTS \(SELECT 1 FROM pg_catalog\.pg_roles x WHERE x\.rolname = 'pg_create_subscription' AND pg_catalog\.pg_has_role\(g\.oid, x\.oid, 'MEMBER'\)\)\)\)/);
  assert.match(statements[0], / OR \(EXISTS \(SELECT 1 FROM pg_catalog\.pg_roles w WHERE w\.rolname = pg_catalog\.current_setting\('supautils\.privileged_role', true\) AND pg_catalog\.pg_has_role\(g\.oid, w\.oid, 'MEMBER'\)\) AND EXISTS \(SELECT 1 FROM pg_catalog\.unnest\(pg_catalog\.string_to_array\(pg_catalog\.replace\(COALESCE\(pg_catalog\.current_setting\('supautils\.privileged_extensions', true\), ''\)/);
  // A lending function: SECURITY DEFINER, not initdb's, not an extension's, owned by a role that can SET ROLE to one with any power; its callers count through SET ROLE too.
  assert.match(statements[0], new RegExp(`JOIN pg_catalog\\.pg_proc p ON p\\.prosecdef AND ${initdbKey} AND NOT EXISTS`));
  // The number of SECURITY DEFINER functions whose owner can act as a role with a power, through the same closure.
  assert.match(statements[3], new RegExp(`^WITH RECURSIVE edge[\\s\\S]* SELECT count\\(\\*\\) FROM pg_catalog\\.pg_proc p WHERE p\\.prosecdef AND ${initdbKey} AND NOT EXISTS[\\s\\S]* AND EXISTS \\(SELECT 1 FROM reach x JOIN pg_catalog\\.pg_roles g ON g\\.oid = x\\.t WHERE x\\.s = p\\.proowner AND \\(g\\.oid IN`));

  assert.match(statements[2], new RegExp(`lanpltrusted AND l\\.lanname <> 'internal' AND ${initdbKey} AND NOT EXISTS`));
  for (const s of [statements[0], statements[2]]) assert.doesNotMatch(s, /\bproname\b|\bnspname\b|proowner <>|proowner =|has_function_privilege\(r\.oid|has_database_privilege\(r\.oid|r\.rolcreaterole/);
  // supautils unseen by the witness's session (either setting) but set for some role or database, and any subscription: undeclarable entries.
  assert.match(statements[0], / UNION SELECT '\(supautils unconfirmed\)' WHERE CASE WHEN pg_catalog\.current_setting\('supautils\.privileged_role', true\) IS NULL OR pg_catalog\.current_setting\('supautils\.privileged_extensions', true\) IS NULL THEN EXISTS \(SELECT 1 FROM pg_catalog\.pg_db_role_setting d, pg_catalog\.unnest\(d\.setconfig\) c\(v\) WHERE c\.v ILIKE '%preload_libraries=%' OR c\.v ILIKE 'supautils\.%'\) ELSE false END/);
  assert.match(statements[0], / UNION SELECT '\(subscription\)' WHERE EXISTS \(SELECT 1 FROM pg_catalog\.pg_subscription s WHERE s\.oid IS NOT NULL\) ORDER BY 1$/);
  // PUBLIC holding EXECUTE on a lending function reads as an entry no declaration can name.
  assert.match(statements[0], /UNION SELECT '\(PUBLIC\)' WHERE EXISTS \(SELECT 1 FROM pg_catalog\.pg_proc p, pg_catalog\.aclexplode\(COALESCE\(p\.proacl, pg_catalog\.acldefault\('f', p\.proowner\)\)\) a WHERE p\.prosecdef AND [\s\S]*? AND a\.grantee = 0 AND a\.privilege_type = 'EXECUTE' AND EXISTS \(SELECT 1 FROM reach x JOIN pg_catalog\.pg_roles g ON g\.oid = x\.t WHERE x\.s = p\.proowner AND /);
  // The namespace was read at the tap's start and at the end probe, by the database container's id, excluding the tap itself.
  assert.equal(tap.calls.filter(c => c.startsWith('ps ')).length, 2);
  for (const [pgOptions, tapOptions, check] of [
    [{ extensions: () => ['dblink', 'pg_net', 'plpgsql'] }, {}, w => assert.deepEqual(w.wire.backendNetwork.extensions, ['dblink'])],
    [{ extensions: n => (n === 2 ? ['pg_cron', 'pg_net'] : ['pg_net']) }, {}, w => assert.deepEqual(w.wire.backendNetwork.extensions, ['pg_cron'])],
    [{ untrusted: () => 1 }, {}, w => assert.equal(w.wire.backendNetwork.untrustedFunctions, 1)],
    [{}, { sharing: (() => { let n = 0; return () => (++n === 2 ? ['app_sidecar'] : []); })() }, w => assert.equal(w.wire.sharedNamespace, 1)],
    [{}, { sharing: () => null }, w => assert.equal(w.wire.sharedNamespace, null)],
    // The database container itself in another container's namespace.
    [{}, { dbMode: 'container:app_runner' }, w => assert.equal(w.wire.sharedNamespace, 1)],
    // Or the host's network, which every host process shares.
    [{}, { dbMode: 'host' }, w => assert.equal(w.wire.sharedNamespace, 1)],
  ]) {
    const { w } = await run(pgOptions, tapOptions);
    assert.deepEqual([w.coverage, w.custody, w.covers], ['complete', 'subject-writable', []], JSON.stringify(w.wire));
    check(w);
  }
});

test('custody: lending functions are a reading only; who may call them is in the program roles', async t => {
  const tap = fakeTap(), o = make(tap, fakePg(tap, { definers: () => 2 })); await o.start(); t.after(() => o.stop());
  const w = await window(o, () => pause(40));
  assert.deepEqual([w.custody, w.covers, w.wire.backendNetwork.definerFunctions], ['observer-held', [PG_NET_QUEUE], 2]);
  // A role that may call one is read as a program role: undeclared, it keeps the window subject-writable.
  const tap2 = fakeTap(), o2 = make(tap2, fakePg(tap2, { definers: () => 1, programs: () => ['pool_auth', 'supabase_admin'] })); await o2.start(); t.after(() => o2.stop());
  assert.equal((await window(o2, () => pause(40))).custody, 'subject-writable');
  // PUBLIC may call one: '(PUBLIC)' is undeclared whatever the declaration lists.
  const tap3 = fakeTap(), o3 = make(tap3, fakePg(tap3, { definers: () => 1, programs: () => ['(PUBLIC)', 'supabase_admin'] })); await o3.start(); t.after(() => o3.stop());
  const pub = await window(o3, () => pause(40));
  assert.deepEqual([pub.custody, pub.covers, pub.wire.programRoles.undeclared], ['subject-writable', [], 1]);
  const tap4 = fakeTap(), o4 = make(tap4, fakePg(tap4, { programs: () => ['(supautils unconfirmed)', 'supabase_admin'] })); await o4.start(); t.after(() => o4.stop());
  assert.deepEqual([(await window(o4, () => pause(40))).custody], ['subject-writable']);
});

test('a tap that stops after the end mark fails the window', async t => {
  const tap = fakeTap(), o = make(tap, fakePg(tap)); await o.start(); t.after(() => o.stop());
  const a = await o.mark(); await pause(40); const b = await o.mark();
  tap.child.emit('exit', 1);
  const w = await o.collect(a, b);
  assert.deepEqual([w.coverage, w.reason, w.covers], ['failed', 'pg-net-tap-down', []]);
});

test('a second connection to a witness\'s port makes the window partial; a retransmitted SYN does not', async t => {
  const run = async extraSource => {
    const tap = fakeTap(), pg = fakePg(tap), o = make(tap, pg); await o.start(); t.after(() => o.stop());
    pg.after = n => { if (n === 2 && extraSource !== null) tap.emit({ k: 'syn', i: 'eth0', d: GW, dp: Number(/:(\d+)\//.exec(pg.sql[1])[1]), sp: extraSource }); };
    return window(o, () => pause(40));
  };
  const forged = await run(51000);
  assert.deepEqual([forged.coverage, forged.reason, forged.covers], ['partial', 'pg-net-witness-repeated', []]);
  const retransmit = await run(40002);
  assert.deepEqual([retransmit.coverage, retransmit.reason], ['complete', null]);
  assert.deepEqual((await run(null)).coverage, 'complete');
});

test('a frame to an earlier mark\'s witness port is a send in a later window, not a witness', async t => {
  const tap = fakeTap(), pg = fakePg(tap), o = make(tap, pg); await o.start(); t.after(() => o.stop());
  const m1 = await o.mark(); await pause(40); const m2 = await o.mark();
  assert.equal((await o.collect(m1, m2)).coverage, 'complete');
  const firstPort = Number(/:(\d+)\//.exec(pg.sql[0])[1]);
  const m3 = await o.mark(); await pause(60);
  tap.emit({ k: 'syn', i: 'eth0', d: GW, dp: firstPort, sp: 52000 });
  const m4 = await o.mark();
  const w = await o.collect(m3, m4);
  assert.deepEqual([w.coverage, w.reason, w.covers, w.wire.kinds, w.wire.listed[0].dst], ['partial', 'pg-net-sent', [], { tcp: 1 }, 'host-gateway']);
  // A window spanning all four marks counts that frame as a second connection to its own first witness: partial either way.
  const span = await o.collect(m1, m4);
  assert.deepEqual([span.coverage, span.reason, span.covers], ['partial', 'pg-net-witness-repeated', []]);
});

test('a window spanning several marks reads a second connection to an intermediate mark\'s witness port as repeated', async t => {
  const tap = fakeTap(), pg = fakePg(tap), o = make(tap, pg); await o.start(); t.after(() => o.stop());
  const m1 = await o.mark(); await pause(40); await o.mark(); await pause(60);
  // A second source at the middle mark's port (its own witness used source 40002).
  tap.emit({ k: 'syn', i: 'eth0', d: GW, dp: Number(/:(\d+)\//.exec(pg.sql[1])[1]), sp: 53000 });
  await pause(20); const m3 = await o.mark();
  const w = await o.collect(m1, m3);
  assert.deepEqual([w.coverage, w.reason, w.covers], ['partial', 'pg-net-witness-repeated', []]);
  // The same span without it is complete.
  const tap2 = fakeTap(), pg2 = fakePg(tap2), o2 = make(tap2, pg2); await o2.start(); t.after(() => o2.stop());
  const n1 = await o2.mark(); await pause(40); await o2.mark(); await pause(80); const n3 = await o2.mark();
  assert.equal((await o2.collect(n1, n3)).coverage, 'complete');
});

test('custody: a declared program role the application\'s request roles reach is refused; the declaration goes beside every verdict', async t => {
  const run = async (extra, pgOptions = {}) => { const tap = fakeTap(), pg = fakePg(tap, pgOptions), o = make(tap, pg, extra); await o.start(); t.after(() => o.stop()); return { w: await window(o, () => pause(40)), pg }; };
  const { w: held, pg } = await run({});
  assert.deepEqual([held.custody, held.declaration], ['observer-held', { programRoles: ['supabase_admin'], requestRoles: ['app_gateway'], refused: [], checked: true }]);
  assert.deepEqual(held.wire.declaration, held.declaration);
  assert.deepEqual(make(fakeTap(), fakePg(fakeTap()), { requestRoles: ['b_role', 'a_role'] }).declaration(), { programRoles: ['supabase_admin'], requestRoles: ['a_role', 'b_role'], refused: null, checked: false });
  // The reach statement reads, from the declared request roles, every SET ROLE target and every owner of a SECURITY DEFINER function they may run.
  assert.match(pg.sql[0], /; WITH RECURSIVE edge[^;]*SELECT g\.rolname FROM pg_catalog\.pg_roles q JOIN reach x ON x\.s = q\.oid JOIN pg_catalog\.pg_roles g ON g\.oid = x\.t WHERE q\.rolname = ANY \(ARRAY\['app_gateway'\]::text\[\]\) UNION SELECT '\(missing request role\)'/);
  // The gateway shape: the gateway reaches service_role, which may run functions postgres owns. Declaring postgres is refused.
  const { w: over } = await run({ programRoles: ['postgres', 'supabase_admin'] }, { programs: () => ['postgres', 'supabase_admin'], reach: () => ['app_gateway', 'postgres', 'service_role'] });
  assert.deepEqual([over.coverage, over.custody, over.covers, over.declaration.refused, over.wire.remedy], ['complete', 'subject-writable', [], ['postgres'], PG_NET_WIRE_REMEDY]);
  // No request roles declared: nothing is checked, so nothing is observer-held.
  const { w: unchecked } = await run({ requestRoles: undefined });
  assert.deepEqual([unchecked.custody, unchecked.declaration], ['subject-writable', { programRoles: ['supabase_admin'], requestRoles: [], refused: [], checked: false }]);
  // Request roles without program roles: checked, nothing refused, and still not observer-held (nothing is declared as the operator's).
  const { w: requestOnly } = await run({ programRoles: undefined });
  assert.deepEqual([requestOnly.custody, requestOnly.declaration], ['subject-writable', { programRoles: [], requestRoles: ['app_gateway'], refused: [], checked: true }]);
  // A declared request role that does not exist cannot be checked.
  const { w: missing } = await run({}, { reach: () => ['(missing request role)'] });
  assert.deepEqual([missing.custody, missing.declaration.checked], ['subject-writable', false]);
  // The reach unread at a mark: not observer-held.
  const { w: unread } = await run({}, { reach: n => (n === 1 ? [] : ['app_gateway']), programs: n => (n === 1 ? null : ['supabase_admin']) });
  assert.equal(unread.custody, 'subject-writable');
  for (const requestRoles of [[], 'app_gateway', ['a', 'a'], ['bad-name'], ['(PUBLIC)']]) assert.throws(() => make(fakeTap(), fakePg(fakeTap()), { requestRoles }), /requestRoles is a list/);
});
