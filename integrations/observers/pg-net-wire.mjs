// pg_net on the wire (pg-net-wire/1): what pg_net sent, read from the database container's own network, so that a pg-wal
// observer may count pg_net's request queue (net.http_request_queue) as observed for a window. The queue is unlogged, so the
// WAL never carries it; its rows are requests the pg_net worker sends and then deletes. Reading the queue, the migrations or
// the catalog says what could be sent, never what was. This reads what was: every packet the database's network namespace
// sends, through a tap that shares that namespace, and a witness request pg_net itself sends at each mark.
//
// The tap: a sidecar container (docker run --network container:<db>) that shares the database container's network namespace,
// with every capability dropped except NET_RAW, a read-only root, no new privileges and a small memory and process limit. It
// runs TAP_SCRIPT (Python standard library only) from an image already on this machine, named only by digest (name@sha256:...;
// no default), checked with docker image inspect before the tap starts and run with --pull never, so it is never pulled, on one
// AF_PACKET socket bound to no interface, so it receives every frame the namespace sends on every interface (eth0 and lo).
// Nothing inside the namespace has a route around it: there is no other interface to send on. It reports, one JSON line each,
// only frames the namespace sends:
//   syn   a TCP connection the namespace opened (SYN without ACK): interface, destination address and port
//   seg   a TCP segment with payload on a connection the namespace opened (its source port is not one the namespace listens
//         on, read from /proc/net/tcp and tcp6): its first bytes classified as an HTTP request (method, target, Host), a TLS
//         hello (its server name) or opaque. At most one per connection per 250 ms. This is how a request on a connection
//         opened before the tap started, or reused by curl, is seen.
//   udp   a UDP datagram, with the DNS question name when it is a DNS query (port 53, or Docker's resolver at 127.0.0.11,
//         whose port the namespace's own NAT rewrites before the frame reaches the tap). Replies from that resolver are skipped.
//   icmp, link, ip   other frames (ICMP, ARP and other link-layer frames, other IP protocols), counted.
// A connection on lo to a loopback address other than Docker's resolver never leaves the container (a health check, pg_cron's
// own session): the tap counts those (its replies report them) and reports nothing else about them. A server's answers to
// connections it accepted are never reported.
//
// The witness: at each mark, after the tap has read everything sent up to that moment (its reply to the mark command comes
// after every earlier frame on its stdout), this observer queues one request through pg_net itself:
//   SELECT net.http_get('http://<host gateway>:<port>/scopehaven-pg-net-witness', timeout_milliseconds := 1000)
// to a fresh port on the address host.docker.internal names inside the namespace (resolved by the tap at start). Nothing needs
// to listen there: the tap reads the witness from the connection's SYN, by its address and port. pg_net's worker takes the queue
// in id order (pg_net 0.20.4: SELECT id FROM net.http_request_queue ORDER BY id LIMIT $1, then deletes those rows), so a
// request queued before the mark has a lower id than the witness and is sent in the witness's batch or an earlier one. Requests
// in one batch go out concurrently, so a window is judged only once the end witness was seen and nothing else was sent for
// quietMs after it.
//
// A window (from, to) holds every frame the tap reported after the start witness (after the start mark's reply, when that
// witness was not seen) up to the end of its quiet period. It is
//   complete   both witnesses were seen, the tap dropped nothing, and the namespace sent nothing else: pg_net sent no request
//              in the window but the witness. covers names the queue table the caller may then count as observed.
//   partial    pg-net-sent (anything else was sent: a connection, a DNS query, a datagram, an unknown IP protocol),
//              pg-net-witness-missing (a witness did not arrive within witnessWaitMs), pg-net-tap-drops (the kernel dropped
//              frames before the tap read them), pg-net-tap-unreadable (a line the tap wrote could not be read),
//              pg-net-tap-gap (the marks and the end probe were not all answered by the one tap that started before the window:
//              each tap start draws its own epoch), pg-net-interfaces-changed (the namespace's interface list, read with each
//              answer, differs from the one at the tap's start).
//   failed     pg-net-mark-failed (a mark could not be taken or its witness could not be queued), pg-net-tap-not-started (a mark
//              taken before the tap started), pg-net-tap-down (the tap was not running at a mark or stopped since),
//              pg-net-records-evicted (the window's records are no longer held).
// The record lists the namespace's interfaces at the tap's start, at the start mark and at the end probe, so "every interface"
// can be checked against the namespace.
// covers is empty unless the window is complete. The record keeps counts, interfaces, ports, an address class and salted
// digests (this observer's own salt) of each address, Host, request target and DNS name: never a value the app sent.
//
// Limits: the tap sees the database's namespace only. A request another service makes on pg_net's behalf, or one pg_net sends
// after the window's quiet period, is not in that window (the next window's start witness bounds it there). A send that never
// produced a frame (a URL curl refused before connecting) is not seen, and carried nothing out. Docker Desktop on macOS and a
// container the copy owns are what this was checked on; the tap needs a local image with Python 3, pinned by digest, and the
// docker CLI. An absent image fails start; nothing is downloaded.
import { spawn as spawnProcess } from 'node:child_process';
import { createHmac, randomBytes, randomInt } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { pgConnect } from './pg-wire.mjs';
import { credentialFrom } from './events.mjs';
import { digest } from '../../src/domain.mjs';

export const PG_NET_WIRE_COLLECTOR = 'pg-net-wire/1';
export const PG_NET_WIRE_SCHEMA = 'scopehaven-pg-net-wire/1';
// The queue table a complete window covers.
export const PG_NET_QUEUE = 'net.http_request_queue';
export const PG_NET_WIRE_LIMITS = Object.freeze({ witnessWaitMs: [1000, 60000], quietMs: [100, 10000], retainedRecords: 20000, retainedMarks: 64,
  lineBytes: 8192, sendsListed: 50, readyMs: 30000, replyMs: 10000, stopMs: 5000 });
const CONTAINER = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
// Only name@sha256:<digest>: a tag can name different bytes tomorrow, and the tap is never pulled (tapArgs, start).
const IMAGE = /^[a-z0-9][a-z0-9._/-]{0,199}@sha256:[0-9a-f]{64}$/;
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const RESOLVER = '127.0.0.11';
const WITNESS_PATH = '/scopehaven-pg-net-witness';
const ROLE = /^[A-Za-z_][A-Za-z0-9_$]{0,62}$/;
// Every role a role can act as, by any number of steps of two kinds: SET ROLE (membership, INHERIT or not), and calling a SECURITY
// DEFINER function another role owns (one no extension owns and initdb did not create: initdb's own are exactly those with an OID
// below 16384 in pg_catalog, which no role can create later), which runs as its owner. reach(s, t): s can act as t (s itself included).
const DEFINER = "p.prosecdef AND (p.oid >= 16384 OR p.pronamespace <> 'pg_catalog'::pg_catalog.regnamespace) AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass AND d.objid = p.oid AND d.deptype = 'e')";
const CLOSURE = "WITH RECURSIVE edge(a, b) AS (SELECT x.oid, y.oid FROM pg_catalog.pg_roles x, pg_catalog.pg_roles y WHERE pg_catalog.pg_has_role(x.oid, y.oid, 'MEMBER')"
  + " UNION SELECT x.oid, p.proowner FROM pg_catalog.pg_roles x JOIN pg_catalog.pg_proc p ON " + DEFINER + " AND pg_catalog.has_function_privilege(x.oid, p.oid, 'EXECUTE')),"
  + " reach(s, t) AS (SELECT oid, oid FROM pg_catalog.pg_roles UNION SELECT r.s, e.b FROM reach r JOIN edge e ON e.a = r.t) ";
// The roles the application's declared request roles reach (pgNetWire's requestRoles: the roles the application's own requests run as,
// such as an API gateway's login role), through CLOSURE. A declared program role among them is refused: the application can act as it.
// A declared request role that does not exist reads '(missing request role)'. The names are declared role names checked against ROLE
// (no quote can occur), so they are safe as literals.
const requestReachSql = names => {
  const requested = `ARRAY[${names.map(n => `'${n}'`).join(', ')}]::text[]`;
  return CLOSURE + `SELECT g.rolname FROM pg_catalog.pg_roles q JOIN reach x ON x.s = q.oid JOIN pg_catalog.pg_roles g ON g.oid = x.t WHERE q.rolname = ANY (${requested})`
    + ` UNION SELECT '(missing request role)' WHERE EXISTS (SELECT 1 FROM pg_catalog.unnest(${requested}) n(name) WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles x WHERE x.rolname = n.name)) ORDER BY 1`;
};
// Extensions that open no network connection from a backend or a background worker. Any other (dblink, postgres_fdw, http, wrappers,
// pg_cron, whose job rows name a host to connect to, or one this list does not know) could send a frame to a witness's port outside
// pg_net's queue order, so its presence keeps a window subject-writable. pg_net itself is the path the witnesses bound.
// What a subject-writable window's record names to do about it (a fixed text, naming no role).
export const PG_NET_WIRE_REMEDY = 'Declare in programRoles only roles you control. A role the application can act as or through (its own login roles, an API gateway\'s login role and the roles it can SET ROLE to, the owner of a SECURITY DEFINER function any of those may call) must hold no superuser, pg_execute_server_program, database CREATE, extension or subscription power: move such functions to an owner without those powers.';
export const NO_BACKEND_NETWORK = Object.freeze(['btree_gin', 'btree_gist', 'citext', 'cube', 'earthdistance', 'fuzzystrmatch', 'hstore', 'hypopg', 'index_advisor',
  'intarray', 'isn', 'ltree', 'moddatetime', 'pg_buffercache', 'pg_graphql', 'pg_hashids', 'pg_jsonschema', 'pg_net', 'pg_prewarm', 'pg_stat_statements', 'pg_trgm',
  'pg_walinspect', 'pgcrypto', 'pgjwt', 'pgsodium', 'pgtap', 'plpgsql', 'seg', 'supabase_vault', 'tablefunc', 'unaccent', 'uuid-ossp', 'vector']);
const ALLOWED = `ARRAY[${NO_BACKEND_NETWORK.map(e => `'${e}'`).join(', ')}]::text[]`;
// Custody, read with every witness in the same statement before the witness is queued (createPgNetWire below). A login role counts
// as a program role when anything it can act as (CLOSURE: SET ROLE, INHERIT or not, and SECURITY DEFINER calls, any number of steps)
// holds a power to put a frame on the wire outside pg_net's queue order (POWER):
//   - a superuser or a member of pg_execute_server_program;
//   - on PostgreSQL 15 and earlier, a role with CREATEROLE (it can grant itself pg_execute_server_program between two marks);
//   - a role that may create in this database and either create a trusted extension outside NO_BACKEND_NETWORK or, on PostgreSQL 16
//     and later, a subscription (pg_create_subscription): either connects out between two marks;
//   - a member of supautils' privileged role while its extension list names one outside NO_BACKEND_NETWORK.
// Entries no declaration can name: '(PUBLIC)' when PUBLIC may execute a SECURITY DEFINER function whose owner can act as such a role,
// '(supautils unconfirmed)' when supautils' settings are not defined in this session (not loaded server-wide) while some role or
// database has its own preload or supautils settings, and '(subscription)' while any subscription exists (its worker connects out).
// Also read: the installed extensions (only those in NO_BACKEND_NETWORK may be present); functions in an untrusted language (C
// included) that no extension owns and initdb did not create; and the number of SECURITY DEFINER functions whose owner can act as a
// role with a power (a reading: who may call them is in the roles above).
const PROGRAM = "SELECT s.oid FROM pg_catalog.pg_roles s WHERE s.rolsuper OR pg_catalog.pg_has_role(s.oid, 'pg_execute_server_program', 'MEMBER')";
// A role g's own powers (the alias g is a pg_roles row).
const POWER = "(g.oid IN (" + PROGRAM + ")"
  + " OR (g.rolcreaterole AND pg_catalog.current_setting('server_version_num')::int < 160000)"
  + " OR (pg_catalog.has_database_privilege(g.oid, pg_catalog.current_database(), 'CREATE') AND (EXISTS (SELECT 1 FROM pg_catalog.pg_available_extension_versions v WHERE v.trusted AND NOT (v.name::text = ANY (" + ALLOWED + ")))"
  + " OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles x WHERE x.rolname = 'pg_create_subscription' AND pg_catalog.pg_has_role(g.oid, x.oid, 'MEMBER'))))"
  + " OR (EXISTS (SELECT 1 FROM pg_catalog.pg_roles w WHERE w.rolname = pg_catalog.current_setting('supautils.privileged_role', true) AND pg_catalog.pg_has_role(g.oid, w.oid, 'MEMBER'))"
  + " AND EXISTS (SELECT 1 FROM pg_catalog.unnest(pg_catalog.string_to_array(pg_catalog.replace(COALESCE(pg_catalog.current_setting('supautils.privileged_extensions', true), ''), ' ', ''), ',')) e(name) WHERE e.name <> '' AND NOT (e.name = ANY (" + ALLOWED + ")))))";
// Whether the role at start can act as one with a power.
const POWERED = start => "EXISTS (SELECT 1 FROM reach x JOIN pg_catalog.pg_roles g ON g.oid = x.t WHERE x.s = " + start + " AND " + POWER + ")";
export const PROGRAM_ROLES_SQL = CLOSURE + "SELECT r.rolname FROM pg_catalog.pg_roles r WHERE r.rolcanlogin AND " + POWERED('r.oid')
  // PUBLIC holding EXECUTE on such a function (the default on a new function) is one more entry, which no declaration can name.
  + " UNION SELECT '(PUBLIC)' WHERE EXISTS (SELECT 1 FROM pg_catalog.pg_proc p, pg_catalog.aclexplode(COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) a"
  + " WHERE " + DEFINER + " AND a.grantee = 0 AND a.privilege_type = 'EXECUTE' AND " + POWERED('p.proowner') + ")"
  // supautils unseen by this session (either setting NULL: not loaded server-wide, which would define both here too) yet possibly
  // loaded or set for some role or database through per-role or per-database settings: one more entry no declaration can name. Its rows
  // are read only then; the catalog's permission is checked at every execution, so a catalog this session may not read fails every mark.
  + " UNION SELECT '(supautils unconfirmed)' WHERE CASE WHEN pg_catalog.current_setting('supautils.privileged_role', true) IS NULL OR pg_catalog.current_setting('supautils.privileged_extensions', true) IS NULL"
  + " THEN EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting d, pg_catalog.unnest(d.setconfig) c(v) WHERE c.v ILIKE '%preload_libraries=%' OR c.v ILIKE 'supautils.%')"
  + " ELSE false END"
  // A subscription's worker connects out on its own: another entry no declaration can name.
  + " UNION SELECT '(subscription)' WHERE EXISTS (SELECT 1 FROM pg_catalog.pg_subscription s WHERE s.oid IS NOT NULL) ORDER BY 1";
const CUSTODY_SQL = [
  PROGRAM_ROLES_SQL,
  'SELECT extname FROM pg_catalog.pg_extension ORDER BY 1',
  "SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid = p.prolang WHERE NOT l.lanpltrusted AND l.lanname <> 'internal' AND (p.oid >= 16384 OR p.pronamespace <> 'pg_catalog'::pg_catalog.regnamespace) AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass AND d.objid = p.oid AND d.deptype = 'e')",
  CLOSURE + "SELECT count(*) FROM pg_catalog.pg_proc p WHERE " + DEFINER + " AND " + POWERED('p.proowner'),
].join('; ');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
// The namespace's interface names as the tap listed them (if_nameindex), sorted; null when unreadable.
const interfacesOf = list => (Array.isArray(list) && list.length >= 1 && list.length <= 64 && list.every(n => typeof n === 'string' && /^[A-Za-z0-9_.@:-]{1,32}$/.test(n)) ? [...list].sort() : null);
const sameList = (x, y) => x !== null && y !== null && x.length === y.length && x.every((n, i) => n === y[i]);

// The tap, run as python3 -I -u -c TAP_SCRIPT inside the sidecar. Reads mark commands ("m <n>", "q <n>") on stdin and answers
// each after every frame read before it; exits at end of input.
export const TAP_SCRIPT = String.raw`
import json, os, select, socket, struct, sys, time
SOL_PACKET, PACKET_STATISTICS, OUTGOING, RESOLVER = 263, 6, 4, '127.0.0.11'
state = {'packets': 0, 'drops': 0, 'lo': 0, 'listen': set(), 'listenAt': 0.0, 'last': {}, 'epoch': os.urandom(8).hex()}
def interfaces():
    try: return sorted(n for _, n in socket.if_nameindex())[:64]
    except OSError: return None
def emit(o):
    sys.stdout.write(json.dumps(o, separators=(',', ':')) + '\n'); sys.stdout.flush()
def listening():
    ports = set()
    for f in ('/proc/net/tcp', '/proc/net/tcp6'):
        try:
            with open(f) as h:
                next(h)
                for line in h:
                    x = line.split()
                    if len(x) > 3 and x[3] == '0A': ports.add(int(x[1].rsplit(':', 1)[1], 16))
        except (OSError, ValueError, StopIteration): pass
    state['listen'], state['listenAt'] = ports, time.monotonic()
def sni(b):
    try:
        i = 43
        i += 1 + b[i]; i += 2 + int.from_bytes(b[i:i + 2], 'big'); i += 1 + b[i]
        end = i + 2 + int.from_bytes(b[i:i + 2], 'big'); i += 2
        while i + 4 <= min(end, len(b)):
            t, n = int.from_bytes(b[i:i + 2], 'big'), int.from_bytes(b[i + 2:i + 4], 'big')
            if t == 0: return b[i + 9:i + 9 + int.from_bytes(b[i + 7:i + 9], 'big')].decode('latin-1')[:256]
            i += 4 + n
    except IndexError: pass
    return None
def first_bytes(b):
    head = b[:2048]
    if len(head) > 5 and head[0] == 0x16 and head[1] == 3: return {'r': 'tls', 'sni': sni(head)}
    text = head.decode('latin-1')
    line, _, rest = text.partition('\r\n')
    parts = line.split(' ')
    if len(parts) == 3 and parts[2].startswith('HTTP/1.') and parts[0].isalpha() and parts[0].isupper() and len(parts[0]) <= 16:
        host = None
        for h in rest.split('\r\n'):
            if h.lower().startswith('host:'): host = h[5:].strip()[:256]; break
        return {'r': 'http', 'm': parts[0], 't': parts[1][:512], 'h': host}
    return {'r': 'opaque'}
def qname(b):
    try:
        i, labels = 12, []
        while b[i]:
            if b[i] & 0xC0: return None
            labels.append(b[i + 1:i + 1 + b[i]].decode('latin-1')); i += 1 + b[i]
        return '.'.join(labels)[:255]
    except IndexError: return None
def handle(pkt, ifname, proto, ptype, now):
    if ptype != OUTGOING: return
    lo = ifname == 'lo'
    if proto == 0x0800:
        if len(pkt) < 20: return emit({'k': 'bad', 'i': ifname})
        ihl, total = (pkt[0] & 15) * 4, struct.unpack('!H', pkt[2:4])[0]
        if struct.unpack('!H', pkt[6:8])[0] & 0x1FFF: return
        nh, src, dst = pkt[9], socket.inet_ntoa(pkt[12:16]), socket.inet_ntoa(pkt[16:20])
        body = pkt[ihl:total] if total else pkt[ihl:]
        loopback = dst.startswith('127.')
    elif proto == 0x86DD:
        if len(pkt) < 40: return emit({'k': 'bad', 'i': ifname})
        nh, src, dst = pkt[6], socket.inet_ntop(socket.AF_INET6, pkt[8:24]), socket.inet_ntop(socket.AF_INET6, pkt[24:40])
        length = struct.unpack('!H', pkt[4:6])[0]
        body = pkt[40:40 + length] if length else pkt[40:]
        loopback = dst == '::1'
    else:
        return emit({'k': 'link', 'i': ifname, 'p': proto})
    if nh == 6:
        if len(body) < 20: return emit({'k': 'bad', 'i': ifname})
        sport, dport = struct.unpack('!HH', body[0:4])
        off, flags = (body[12] >> 4) * 4, body[13]
        payload = body[off:]
        inside = lo and loopback and dst != RESOLVER
        if flags & 0x02 and not flags & 0x10:
            if inside: state['lo'] += 1; return
            return emit({'k': 'syn', 'i': ifname, 'd': dst, 'dp': dport, 'sp': sport})
        if not payload or inside: return
        if now - state['listenAt'] > 2.0: listening()
        if sport in state['listen']: return
        flow = (ifname, sport, dst, dport)
        if now - state['last'].get(flow, -1.0) < 0.25: return
        if len(state['last']) > 4096: state['last'].clear()
        state['last'][flow] = now
        o = {'k': 'seg', 'i': ifname, 'd': dst, 'dp': dport, 'sp': sport}
        o.update(first_bytes(payload))
        return emit(o)
    if nh == 17:
        if len(body) < 8: return emit({'k': 'bad', 'i': ifname})
        sport, dport = struct.unpack('!HH', body[0:4])
        if src == RESOLVER: return
        if lo and loopback and dst != RESOLVER: state['lo'] += 1; return
        dns = dst == RESOLVER or dport == 53
        return emit({'k': 'udp', 'i': ifname, 'd': dst, 'dp': dport, 'q': qname(body[8:]) if dns else None, 'dns': dns})
    if nh in (1, 58): return emit({'k': 'icmp', 'i': ifname})
    return emit({'k': 'ip', 'i': ifname, 'p': nh, 'd': dst})
# The answer to a mark (m) or the end probe (q), after everything sent before it was read. It starts every connection's 250 ms
# segment throttle afresh, so a segment reported just before a mark cannot hide one on the same connection just after it.
def reply(kind, n):
    state['last'].clear()
    emit({'k': kind, 'n': n, 'drops': state['drops'], 'packets': state['packets'], 'lo': state['lo'], 'epoch': state['epoch'], 'ifs': interfaces()})

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
    try: s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    except OSError: pass
    s.setblocking(False)
    def stats():
        p, d = struct.unpack('II', s.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))
        state['packets'] += p; state['drops'] += d
    def drain():
        while True:
            try: pkt, addr = s.recvfrom(262144)
            except BlockingIOError: return
            try: handle(pkt, addr[0], addr[1], addr[2], time.monotonic())
            except Exception: emit({'k': 'bad', 'i': addr[0]})
    listening()
    try: gw = socket.gethostbyname('host.docker.internal')
    except OSError: gw = None
    drain(); stats()
    emit({'k': 'ready', 'gw': gw, 'listen': len(state['listen']), 'epoch': state['epoch'], 'ifs': interfaces()})
    pending = b''
    while True:
        r, _, _ = select.select([s, 0], [], [], 1.0)
        if s in r: drain()
        if 0 in r:
            data = os.read(0, 4096)
            if not data: return
            pending += data
            while b'\n' in pending:
                line, pending = pending.split(b'\n', 1)
                cmd = line.decode('ascii', 'replace').split()
                if len(cmd) == 2 and cmd[0] in ('m', 'q') and cmd[1].isdigit():
                    drain(); stats(); reply(cmd[0], int(cmd[1]))
if __name__ == '__main__': main()
`;

// The docker command that starts the tap. It never pulls; every capability but NET_RAW is dropped; only the image, container and
// name vary.
export function tapArgs({ container, image, name }) {
  return ['run', '--pull', 'never', '--rm', '-i', '--name', name, '--network', `container:${container}`, '--cap-drop', 'ALL', '--cap-add', 'NET_RAW', '--read-only',
    '--security-opt', 'no-new-privileges', '--memory', '64m', '--pids-limit', '8', '--entrypoint', 'python3', image, '-I', '-u', '-c', TAP_SCRIPT];
}

// The address class kept beside an address's digest.
const addressClass = (address, gw) => (address === gw ? 'host-gateway' : address === RESOLVER ? 'resolver' : /^127\.|^::1$/.test(address) ? 'loopback'
  : /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|f[cd]|fe80:)/i.test(address) ? 'private' : 'public');

// container: the database container's name; credentialEnv: a SCOPEHAVEN_TARGET_ name whose value is user:password for a role that
// may call net.http_get (the witness), read when a mark queues it and never kept. host/port/database: the database on loopback.
// programRoles (optional, 1 to 16 role names): the login roles that can run a program inside the database's container, each held
// by the operator and none by the subject (a declaration). Custody: the tap's frames are copied by the kernel into a container the
// subject cannot write, but the window's ends are witnesses pg_net sends from the subject's database. Through pg_net alone the
// subject cannot send ahead of them (pg_net sends its queue in id order): a request it queues, locks or deletes is seen, keeps the
// witness from arriving, or never leaves. Anything else that can put a frame on the wire from the database's namespace could send
// to a witness's port and close a window early: a role that can run a program in the container, a backend network path (an
// extension outside NO_BACKEND_NETWORK, a function in an untrusted language), a role that may call a SECURITY DEFINER function
// lending such a role's power, or another container in the same namespace. So a window is observer-held only when programRoles is
// declared and, at both marks, every role that holds or can borrow that power is declared, every extension is in NO_BACKEND_NETWORK
// and no untrusted-language function exists that no extension owns and initdb did not create; and, at the tap's start and at the
// end probe, no other container shares the namespace. Otherwise it is
// subject-writable and covers nothing (its record still reports what was sent). A second connection to a witness's port (two
// source ports) makes the window partial (pg-net-witness-repeated).
// image: the tap's image, already on this machine, as name@sha256:<digest> (never pulled). docker: the docker CLI's absolute path;
// spawn, connect and now are test seams.
export function createPgNetWire({ instanceId = 'pg-net-wire-1', env = process.env, container, image, docker = '/usr/local/bin/docker',
  host, port, database, credentialEnv, programRoles, requestRoles, witnessWaitMs = 10000, quietMs = 1500, spawn = spawnProcess, connect = pgConnect, now = () => performance.now() }) {
  const within = (v, [min, max]) => Number.isInteger(v) && v >= min && v <= max;
  if (typeof container !== 'string' || !CONTAINER.test(container)) throw new Error('pg-net-wire: container is the database container\'s name.');
  if (typeof image !== 'string' || !IMAGE.test(image)) throw new Error('pg-net-wire: image is a local image with Python 3 named by digest (name@sha256:<64 hex>); it is never pulled.');
  if (typeof docker !== 'string' || !docker.startsWith('/')) throw new Error('pg-net-wire: docker is the docker CLI\'s absolute path.');
  if (host !== '127.0.0.1') throw new Error('pg-net-wire: the Postgres host must be the literal loopback address 127.0.0.1.');
  if (!within(port, [1, 65535]) || typeof database !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(database)) throw new Error('pg-net-wire: declare the Postgres port and database.');
  if (!within(witnessWaitMs, PG_NET_WIRE_LIMITS.witnessWaitMs)) throw new Error('pg-net-wire: witnessWaitMs is an integer from 1000 to 60000.');
  if (!within(quietMs, PG_NET_WIRE_LIMITS.quietMs)) throw new Error('pg-net-wire: quietMs is an integer from 100 to 10000.');
  credentialFrom(env, credentialEnv, 'pg-net-wire credential');
  if (programRoles !== undefined && (!Array.isArray(programRoles) || programRoles.length < 1 || programRoles.length > 16 || !programRoles.every(r => typeof r === 'string' && ROLE.test(r))
    || new Set(programRoles).size !== programRoles.length)) throw new Error('pg-net-wire: programRoles is a list of 1 to 16 distinct role names.');
  const declared = programRoles === undefined ? null : new Set(programRoles);
  if (requestRoles !== undefined && (!Array.isArray(requestRoles) || requestRoles.length < 1 || requestRoles.length > 16 || !requestRoles.every(r => typeof r === 'string' && ROLE.test(r))
    || new Set(requestRoles).size !== requestRoles.length)) throw new Error('pg-net-wire: requestRoles is a list of 1 to 16 distinct role names.');
  const requested = requestRoles === undefined ? null : [...requestRoles].sort();
  const reachSql = requestReachSql(requested ?? []);
  // The declaration, word for word, beside every custody verdict: whose word a window rests on.
  const declaration = (refused = null, checked = false) => ({ programRoles: programRoles === undefined ? [] : [...programRoles].sort(), requestRoles: requested ?? [], refused, checked });

  const salt = randomBytes(32), sealed = (kind, value) => (typeof value === 'string' ? createHmac('sha256', salt).update(`${PG_NET_WIRE_SCHEMA} ${kind}\n${value}`).digest('hex') : null);
  const records = [], marks = new Map(), witnessPorts = new Map(), waiters = new Map();
  let child = null, gw = null, epoch = null, interfaceList = null, seq = 0, nextIndex = 1, nextQuery = 1, downAt = null, lastSendAt = null, buffered = '', ready = null, firstRetained = 1;
  const name = `scopehaven-pg-net-tap-${randomBytes(6).toString('hex')}`;
  const dockerEnv = { PATH: '/usr/bin:/bin:/usr/local/bin', ...(env.HOME ? { HOME: env.HOME } : {}) };
  // One docker CLI call's output (null on any failure or after 10 s).
  const dockerOut = args => new Promise(resolve => {
    let out = '', done = false;
    const finish = value => { if (!done) { done = true; clearTimeout(timer); resolve(value); } };
    const k = spawn(docker, args, { stdio: ['ignore', 'pipe', 'ignore'], env: dockerEnv });
    const timer = setTimeout(() => { try { k.kill('SIGTERM'); } catch { /* gone */ } finish(null); }, 10000);
    k.stdout?.setEncoding('utf8'); k.stdout?.on('data', c => { out += c; if (out.length > 1 << 20) finish(null); });
    k.on('exit', code => finish(code === 0 ? out : null)); k.on('error', () => finish(null));
  });
  // The containers other than this tap whose network is the database container's (docker run --network container:<db>), plus one when the
// database container itself uses another's or the host's network (every host process would share it); null if unread.
  let dbId = null, dbJoined = null, startSharing = null;
  const sharing = async () => {
    const ids = await dockerOut(['ps', '-q', '--no-trunc']);
    if (ids === null || dbId === null || dbJoined === null) return null;
    const list = ids.split('\n').filter(Boolean);
    if (!list.length) return dbJoined ? 1 : 0;
    const modes = await dockerOut(['inspect', '--format', '{{.Name}} {{.HostConfig.NetworkMode}}', ...list]);
    if (modes === null) return null;
    // The database container itself in another container's namespace counts as one more.
    return modes.split('\n').filter(Boolean).filter(l => { const [n, mode] = l.split(' '); return n !== `/${name}` && (mode === `container:${dbId}` || mode === `container:${container}`); }).length + (dbJoined ? 1 : 0);
  };

  const keep = record => {
    records.push(record);
    if (records.length > PG_NET_WIRE_LIMITS.retainedRecords) firstRetained = records.shift().seq + 1;
  };
  // One line the tap wrote, classified as it arrives.
  const take = line => {
    const at = now(), s = ++seq;
    let o;
    try { o = Buffer.byteLength(line) <= PG_NET_WIRE_LIMITS.lineBytes ? JSON.parse(line) : null; } catch { o = null; }
    if (o === null || typeof o !== 'object' || typeof o.k !== 'string') return keep({ seq: s, at, kind: 'unreadable' });
    if (o.k === 'ready') {
      gw = typeof o.gw === 'string' && IPV4.test(o.gw) ? o.gw : null; epoch = typeof o.epoch === 'string' ? o.epoch : null; interfaceList = interfacesOf(o.ifs);
      if (ready) { ready.saw = true; ready.resolve(); }
      return;
    }
    if (o.k === 'm' || o.k === 'q') {
      const key = `${o.k}${o.n}`, w = waiters.get(key);
      if (w) { waiters.delete(key); w({ seq: s, at, drops: Number.isInteger(o.drops) ? o.drops : null, lo: Number.isInteger(o.lo) ? o.lo : null, epoch: typeof o.epoch === 'string' ? o.epoch : null, ifs: interfacesOf(o.ifs) }); }
      return;
    }
    if (o.k === 'icmp' || o.k === 'link') return keep({ seq: s, at, kind: o.k });
    if (o.k === 'bad') return keep({ seq: s, at, kind: 'unreadable' });
    const iface = o.i === 'lo' ? 'lo' : 'eth';
    if (o.k === 'syn' || o.k === 'seg') {
      const request = o.k === 'seg' ? { kind: ['http', 'tls'].includes(o.r) ? o.r : 'opaque', hostDigest: sealed('host', o.r === 'http' ? o.h : o.r === 'tls' ? o.sni : null),
        targetDigest: sealed('target', o.r === 'http' ? `${o.m} ${o.t}` : null) } : null;
      const send = { kind: o.k === 'syn' ? (o.d === RESOLVER ? 'dns' : 'tcp') : 'segment', iface, dport: Number.isInteger(o.dp) ? o.dp : null,
        dst: addressClass(o.d, gw), addressDigest: sealed('address', o.d), ...(request ? { request } : {}) };
      // A frame to a witness's port is kept as that mark's witness. A window counts only its own marks' witnesses (an index at or
      // after its start mark): a frame to an earlier mark's port is a send there (collect).
      const witness = o.d === gw ? witnessPorts.get(o.dp) : undefined;
      lastSendAt = at;
      if (witness !== undefined) {
        const m = marks.get(witness);
        if (m && o.k === 'syn') { if (m.witnessSeq === null) { m.witnessSeq = s; m.witnessAt = at; } (m.witnessSources ??= new Set()).add(o.sp); }
        return keep({ seq: s, at, kind: 'witness', index: witness, source: o.sp, send });
      }
      return keep({ seq: s, at, kind: 'send', send });
    }
    if (o.k === 'udp') {
      lastSendAt = at;
      return keep({ seq: s, at, kind: 'send', send: { kind: o.dns ? 'dns' : 'udp', iface, dport: Number.isInteger(o.dp) ? o.dp : null, dst: addressClass(o.d, gw),
        addressDigest: sealed('address', o.d), ...(o.dns ? { nameDigest: sealed('name', o.q) } : {}) } });
    }
    if (o.k === 'ip') { lastSendAt = at; return keep({ seq: s, at, kind: 'send', send: { kind: 'ip', iface, dport: null, dst: addressClass(o.d, gw), addressDigest: sealed('address', o.d) } }); }
    return keep({ seq: s, at, kind: 'unreadable' });
  };
  const ask = (kind, n) => new Promise(resolve => {
    const key = `${kind}${n}`, timer = setTimeout(() => { waiters.delete(key); resolve(null); }, PG_NET_WIRE_LIMITS.replyMs);
    waiters.set(key, reply => { clearTimeout(timer); resolve(reply); });
    try { child.stdin.write(`${kind} ${n}\n`); } catch { /* a closed tap answers nothing: the timer resolves null */ }
  });
  const up = () => child !== null && downAt === null && gw !== null && epoch !== null && interfaceList !== null;

  // The witness: one pg_net request to a port this observer chose, queued on a session of its own.
  const queueWitness = async index => {
    let witnessPort;
    do witnessPort = randomInt(20000, 65000); while (witnessPorts.has(witnessPort));
    witnessPorts.set(witnessPort, index);
    const secret = credentialFrom(env, credentialEnv, 'pg-net-wire credential');
    const split = typeof secret === 'string' ? secret.indexOf(':') : -1;
    if (split < 1) throw new Error('credential-missing');
    const client = await connect({ host, port, database, user: secret.slice(0, split), password: secret.slice(split + 1), connectTimeoutMs: 5000 });
    let results;
    try { results = await client.query(`/* sh:pg-net-witness */ ${CUSTODY_SQL}; ${reachSql}; SELECT net.http_get('http://${gw}:${witnessPort}${WITNESS_PATH}', timeout_milliseconds := 1000)::text`, { queryTimeoutMs: 10000, maxRows: 401 }); }
    finally { client.close(); }
    const rows = i => (Array.isArray(results) && results.length === 6 && Array.isArray(results[i]?.rows) && results[i].rows.every(r => typeof r?.[0] === 'string') ? results[i].rows.map(r => r[0]) : null);
    const names = i => (rows(i) ? [...new Set(rows(i))].sort() : null), count = i => (rows(i)?.length === 1 && /^\d+$/.test(rows(i)[0]) ? Number(rows(i)[0]) : null);
    return { port: witnessPort, custody: { programs: names(0), extensions: names(1), untrusted: count(2), definers: count(3), reach: names(4) } };
  };

  return {
    kind: 'pg-net-wire', instanceId, collector: PG_NET_WIRE_COLLECTOR, covers: Object.freeze([PG_NET_QUEUE]),
    // The address host.docker.internal names inside the namespace, as the tap resolved it (null before start).
    gateway: () => gw,
    // The declaration as configured (program and request roles, sorted), before any mark checks it.
    declaration: () => declaration(),
    async start() {
      if (child) return;
      // Refused before anything starts when the image is not on this machine: ScopeHaven never pulls it (tapArgs: --pull never).
      if ((await dockerOut(['image', 'inspect', '--format', '{{.Id}}', image])) === null) throw new Error('pg-net-wire: the tap image is not on this machine; load it yourself by digest (ScopeHaven never pulls it).');
      ready = {};
      const started = new Promise(resolve => { ready.resolve = resolve; });
      child = spawn(docker, tapArgs({ container, image, name }), { stdio: ['pipe', 'pipe', 'ignore'], env: { PATH: '/usr/bin:/bin:/usr/local/bin', ...(env.HOME ? { HOME: env.HOME } : {}) } });
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', chunk => {
        buffered += chunk;
        for (let i; (i = buffered.indexOf('\n')) >= 0;) { const line = buffered.slice(0, i); buffered = buffered.slice(i + 1); if (line) take(line); }
        if (buffered.length > PG_NET_WIRE_LIMITS.lineBytes) { buffered = ''; keep({ seq: ++seq, at: now(), kind: 'unreadable' }); }
      });
      const gone = () => { downAt ??= seq; ready?.resolve(); for (const [key, w] of waiters) { waiters.delete(key); w(null); } };
      child.on('exit', gone); child.on('error', gone);
      child.stdin.on('error', () => {});
      const timer = setTimeout(() => ready.resolve(), PG_NET_WIRE_LIMITS.readyMs);
      await started; clearTimeout(timer);
      const self = (await dockerOut(['inspect', '--format', '{{.Id}} {{.HostConfig.NetworkMode}}', container]))?.trim().split(' ') ?? [];
      dbId = self[0] || null; dbJoined = self.length === 2 ? self[1] === 'host' || self[1].startsWith('container:') : null;
      startSharing = up() ? await sharing() : null;
      if (!up()) {
        const message = ready.saw && gw === null && downAt === null ? 'pg-net-wire: the tap did not resolve host.docker.internal' : 'pg-net-wire: the tap did not start';
        await this.stop(); throw new Error(message);
      }
    },
    // Reads everything the tap saw up to now, then queues this mark's witness.
    async mark() {
      const index = nextIndex++;
      if (child === null) { marks.set(index, { ok: false, reason: 'pg-net-tap-not-started' }); return { index }; }
      if (!up()) { marks.set(index, { ok: false, reason: 'pg-net-tap-down' }); return { index }; }
      const reply = await ask('m', index);
      if (!reply || reply.drops === null) { marks.set(index, { ok: false, reason: 'pg-net-tap-down' }); return { index }; }
      const m = { ok: true, seq: reply.seq, at: reply.at, drops: reply.drops, lo: reply.lo, epoch: reply.epoch, ifs: reply.ifs, witnessSeq: null, witnessAt: null };
      marks.set(index, m);
      try { ({ port: m.port, custody: m.custody } = await queueWitness(index)); } catch { marks.set(index, { ok: false, reason: 'pg-net-mark-failed' }); }
      marks.delete(index - PG_NET_WIRE_LIMITS.retainedMarks);
      return { index };
    },
    // { events: [], coverage, reason, covers, wire }: waits for the end witness and the quiet period after it.
    async collect(from, to) {
      const a = marks.get(from?.index), b = marks.get(to?.index), started = now();
      const result = (coverage, reasons, extra = {}, custody = 'subject-writable') => {
        const record = { schema: PG_NET_WIRE_SCHEMA, collector: PG_NET_WIRE_COLLECTOR, coverage, reasons: [...reasons].sort(), custody, declaration: declaration(), ...extra };
        return { events: [], coverage, reason: reasons.size ? [...reasons].sort().join(',') : null, custody, declaration: record.declaration,
          covers: coverage === 'complete' && custody === 'observer-held' ? [PG_NET_QUEUE] : [], wire: { ...record, digest: digest(record) } };
      };
      if (!a || !b) return result('failed', new Set(['pg-net-mark-failed']));
      if (!a.ok || !b.ok) return result('failed', new Set([!a.ok ? a.reason : b.reason]));
      // The end witness, then quietMs with nothing sent after it; never longer than witnessWaitMs plus ten quiet periods.
      const cap = started + witnessWaitMs + 10 * quietMs;
      while (now() < cap && downAt === null) {
        const end = b.witnessAt;
        if (end !== null && now() - Math.max(end, lastSendAt ?? end) >= quietMs) break;
        if (end === null && now() - started >= witnessWaitMs) break;
        await sleep(Math.min(50, quietMs));
      }
      const probe = up() ? await ask('q', nextQuery++) : null;
      const reasons = new Set();
      if (downAt !== null || !probe || probe.drops === null) return result('failed', new Set(['pg-net-tap-down']));
      const startSeq = a.witnessSeq ?? a.seq;
      if (startSeq + 1 < firstRetained) return result('failed', new Set(['pg-net-records-evicted']));
      if (a.witnessSeq === null || b.witnessSeq === null) reasons.add('pg-net-witness-missing');
      if (probe.drops > a.drops) reasons.add('pg-net-tap-drops');
      // One tap, started before the window opened, answered both marks and the end probe; and the namespace kept its interfaces.
      if (a.epoch === null || a.epoch !== epoch || b.epoch !== epoch || probe.epoch !== epoch) reasons.add('pg-net-tap-gap');
      if (!sameList(a.ifs, interfaceList) || !sameList(b.ifs, interfaceList) || !sameList(probe.ifs, interfaceList)) reasons.add('pg-net-interfaces-changed');
      const inWindow = records.filter(r => r.seq > startSeq && r.seq <= probe.seq);
      const sends = inWindow.filter(r => r.kind === 'send' || (r.kind === 'witness' && r.index < from.index));
      if (sends.length) reasons.add('pg-net-sent');
      if (inWindow.some(r => r.kind === 'unreadable')) reasons.add('pg-net-tap-unreadable');
      // Two source ports at one of this window's witness ports (a retransmitted SYN keeps its port).
      const sources = new Map([[from.index, new Set(a.witnessSources ?? [])], [to.index, new Set(b.witnessSources ?? [])]]);
      for (const r of inWindow) if (r.kind === 'witness' && r.index >= from.index) { if (!sources.has(r.index)) sources.set(r.index, new Set()); sources.get(r.index).add(r.source); }
      if ([...sources.values()].some(set => set.size > 1)) reasons.add('pg-net-witness-repeated');
      const count = kind => inWindow.filter(r => r.kind === kind).length;
      const kinds = {};
      for (const r of sends) kinds[r.send.kind] = (kinds[r.send.kind] ?? 0) + 1;
      // Custody (createPgNetWire's header): counts and extension names; the only role names are the declaration's, word for word.
      const endSharing = await sharing();
      const read = [a, b].every(m => Array.isArray(m.custody?.programs) && Array.isArray(m.custody?.extensions) && m.custody.untrusted !== null && m.custody.definers !== null && Array.isArray(m.custody?.reach));
      const both = key => [...(a.custody?.[key] ?? []), ...(b.custody?.[key] ?? [])], most = key => Math.max(a.custody?.[key] ?? 0, b.custody?.[key] ?? 0);
      const undeclared = declared && read ? new Set(both('programs').filter(r => !declared.has(r))).size : null;
      const extensions = read ? [...new Set(both('extensions').filter(e => !NO_BACKEND_NETWORK.includes(e)))].sort().slice(0, 32) : null;
      const untrusted = read ? most('untrusted') : null, definers = read ? most('definers') : null;
      const shared = startSharing === null || endSharing === null ? null : Math.max(startSharing, endSharing);
      // A declared program role the application's request roles reach is refused; without declared request roles nothing is checked.
      const reach = read ? new Set(both('reach')) : null;
      const checked = requested !== null && reach !== null && !reach.has('(missing request role)');
      // Read once the reach is read, with or without declared program roles (none declared: nothing refused, and nothing observer-held).
      const refused = reach ? [...(declared ?? [])].filter(r => reach.has(r)).sort() : null;
      const custody = undeclared === 0 && checked && refused?.length === 0 && extensions?.length === 0 && untrusted === 0 && shared === 0 ? 'observer-held' : 'subject-writable';
      return result(reasons.size ? 'partial' : 'complete', reasons, {
        declaration: declaration(refused, checked), programRoles: { declared: declared?.size ?? 0, read, undeclared }, ...(custody === 'observer-held' ? {} : { remedy: PG_NET_WIRE_REMEDY }), backendNetwork: { extensions, untrustedFunctions: untrusted, definerFunctions: definers },
        sharedNamespace: shared,
        tap: { socket: 'AF_PACKET, every interface', interfaces: { start: interfaceList, window: a.ifs, end: probe.ifs }, sameTap: !reasons.has('pg-net-tap-gap') },
        witness: { start: a.witnessSeq !== null, end: b.witnessSeq !== null }, sends: sends.length, kinds, listed: sends.slice(0, PG_NET_WIRE_LIMITS.sendsListed).map(r => r.send),
        listedOmitted: Math.max(0, sends.length - PG_NET_WIRE_LIMITS.sendsListed), icmp: count('icmp'), link: count('link'),
        inContainer: probe.lo !== null && a.lo !== null ? probe.lo - a.lo : null, drops: { start: a.drops, end: probe.drops }, waitedMs: Math.round(now() - started) }, custody);
    },
    async stop() {
      const c = child;
      if (!c) return;
      try { c.stdin.end(); } catch { /* already closed */ }
      const exited = downAt !== null ? Promise.resolve() : new Promise(resolve => c.once('exit', resolve));
      if (await Promise.race([exited.then(() => true), sleep(PG_NET_WIRE_LIMITS.stopMs).then(() => false)])) return;
      // The tap did not end with its input: remove its container by the name this observer gave it, then end the CLI by PID.
      await dockerOut(['rm', '-f', name]);
      try { c.kill('SIGTERM'); } catch { /* gone */ }
    },
  };
}
