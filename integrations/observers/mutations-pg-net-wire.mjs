#!/usr/bin/env node
// Mutation sweep for pg_net on the wire (./pg-net-wire.mjs and its use in ./pg-wal.mjs): one mutation per property; each
// must make a unit test fail. A survivor is a test gap.
//   node integrations/observers/mutations-pg-net-wire.mjs [--out FILE] [--only ID,ID...]
// As mutations-background-writers.mjs: a temporary copy (in a folder whose name has spaces) of the modules the tests load,
// never the checkout; the tests run once unmutated (they must pass), then once per mutation. Each edit must match once.
// The tap's own rules (T*) are pinned by the python3 test in pg-net-wire.test.mjs, which reads TAP_SCRIPT from the module.
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const UNIT = ['integrations/observers/pg-net-wire.test.mjs', 'integrations/observers/pg-wal.test.mjs'];
const m = (id, property, file, edits) => ({ id, property, file, edits });
const N = 'integrations/observers/pg-net-wire.mjs', W = 'integrations/observers/pg-wal.mjs';
export const MUTATIONS = [
  // pg-wal: the queue is observed only through a complete wire window.
  m('WW1', 'pg-wal: a wire window covers its tables only when complete', W, [["const covered = new Set(wired?.coverage === 'complete' && wired.custody === 'observer-held' ? wired.covers : []);", "const covered = new Set(wired?.custody === 'observer-held' ? wired.covers : []);"]]),
  m('WW6', 'pg-wal: a wire window covers its tables only when observer-held', W, [["const covered = new Set(wired?.coverage === 'complete' && wired.custody === 'observer-held' ? wired.covers : []);", "const covered = new Set(wired?.coverage === 'complete' ? wired.covers : []);"]]),
  m('WW2', 'pg-wal: a failed wire mark fails the wire window', W, [["      : { coverage: 'failed', reason: 'pg-net-mark-failed', covers: [], wire: null };", "      : { coverage: 'complete', reason: null, covers: wire.covers, wire: null };"]]),
  m('WW3', 'pg-wal: a covered table leaves only its own name off the list', W, [['&& !covered.has(name); }).sort();', '&& !covered.size; }).sort();']]),
  m('WW4', 'pg-wal: the wire starts and stops with the observer', W, [['async stop() { await serial(async () => { await drop(); await wire?.stop(); }); },', 'async stop() { await serial(drop); },']]),
  m('WW5', 'pg-wal: a wire attaches only before the first start', W, [["      if (wire !== null || begun) throw new Error('pg-wal: a wire attaches once, before the observer starts.');", "      if (wire !== null) throw new Error('pg-wal: a wire attaches once, before the observer starts.');"]]),
  m('WW7', 'pg-wal: an attached wire is checked like a constructed one', W, [["      if (!wireShape(w)) throw new Error('wire is a pg_net wire observer (./pg-net-wire.mjs).');\n", '']]),
  // The wire's windows.
  m('P1', 'wire: anything else sent makes the window partial', N, [["      if (sends.length) reasons.add('pg-net-sent');\n", '']]),
  m('P2', 'wire: both witnesses must arrive', N, [["      if (a.witnessSeq === null || b.witnessSeq === null) reasons.add('pg-net-witness-missing');\n", '']]),
  m('P3', 'wire: kernel drops make the window partial', N, [["      if (probe.drops > a.drops) reasons.add('pg-net-tap-drops');\n", '']]),
  m('P4', 'wire: the window starts at the start witness', N, [['const startSeq = a.witnessSeq ?? a.seq;', 'const startSeq = a.seq;']]),
  m('P5', 'wire: the window waits out the quiet period after the end witness', N, [['if (end !== null && now() - Math.max(end, lastSendAt ?? end) >= quietMs) break;', 'if (end !== null) break;']]),
  m('P6', 'wire: covers is empty unless the window is complete', N, [["covers: coverage === 'complete' && custody === 'observer-held' ? [PG_NET_QUEUE] : []", "covers: custody === 'observer-held' ? [PG_NET_QUEUE] : []"]]),
  // Custody: the program-capable login roles (programRoles).
  m('C1', 'wire: covers is empty unless the window is observer-held', N, [["covers: coverage === 'complete' && custody === 'observer-held' ? [PG_NET_QUEUE] : []", "covers: coverage === 'complete' ? [PG_NET_QUEUE] : []"]]),
  m('C2', 'wire: an undeclared program-capable role makes the window subject-writable', N, [["new Set(both('programs').filter(r => !declared.has(r))).size", "new Set(both('programs').filter(() => false)).size"]]),
  m('C3', 'wire: custody read at both marks, not one', N, [['const read = [a, b].every(m => Array.isArray(m.custody?.programs)', 'const read = [a, b].some(m => Array.isArray(m.custody?.programs)']]),
  m("C6", "wire: reach follows SET ROLE (membership, INHERIT or not)", N, [["WHERE pg_catalog.pg_has_role(x.oid, y.oid, 'MEMBER')\"", "WHERE x.oid = y.oid\""]]),
  m('C7', 'wire: an extension outside NO_BACKEND_NETWORK keeps the window subject-writable', N, [["both('extensions').filter(e => !NO_BACKEND_NETWORK.includes(e))", "both('extensions').filter(() => false)"]]),
  m('C8', 'wire: an untrusted-language function outside an extension keeps the window subject-writable', N, [['&& untrusted === 0 && shared === 0', '&& shared === 0']]),
  m("C9", "wire: reach follows SECURITY DEFINER calls (the function runs as its owner)", N, [[" UNION SELECT x.oid, p.proowner FROM pg_catalog.pg_roles x JOIN pg_catalog.pg_proc p ON \" + DEFINER", " UNION SELECT x.oid, p.proowner FROM pg_catalog.pg_roles x JOIN pg_catalog.pg_proc p ON false AND \" + DEFINER"]]),
  m('C14', 'wire: initdb\'s exemption needs pg_catalog too, not an OID alone', N, [["WHERE NOT l.lanpltrusted AND l.lanname <> 'internal' AND (p.oid >= 16384 OR p.pronamespace <> 'pg_catalog'::pg_catalog.regnamespace) AND", "WHERE NOT l.lanpltrusted AND l.lanname <> 'internal' AND p.oid >= 16384 AND"]]),
  m('C15', 'wire: initdb\'s exemption is never a name', N, [["WHERE NOT l.lanpltrusted AND l.lanname <> 'internal' AND (p.oid >= 16384 OR p.pronamespace <> 'pg_catalog'::pg_catalog.regnamespace) AND", "WHERE NOT l.lanpltrusted AND l.lanname <> 'internal' AND p.proname !~ '_to_' AND"]]),
  m('C16', 'wire: initdb\'s exemption is never a schema alone', N, [["WHERE NOT l.lanpltrusted AND l.lanname <> 'internal' AND (p.oid >= 16384 OR p.pronamespace <> 'pg_catalog'::pg_catalog.regnamespace) AND", "WHERE NOT l.lanpltrusted AND l.lanname <> 'internal' AND p.pronamespace <> 'pg_catalog'::pg_catalog.regnamespace AND"]]),
  m('C17', 'wire: PUBLIC holding EXECUTE on a lending function is read', N, [["  + \" UNION SELECT '(PUBLIC)' WHERE EXISTS", "  + \" UNION SELECT NULL WHERE false AND EXISTS"]]),
  m("C18", "wire: a definer function's initdb exemption needs pg_catalog too", N, [["const DEFINER = \"p.prosecdef AND (p.oid >= 16384 OR p.pronamespace <> 'pg_catalog'::pg_catalog.regnamespace) AND", "const DEFINER = \"p.prosecdef AND p.oid >= 16384 AND"]]),
  m("C19", "wire: CREATEROLE before PostgreSQL 16 counts", N, [["  + \" OR (g.rolcreaterole AND pg_catalog.current_setting('server_version_num')::int < 160000)\"", "  + \"\""]]),
  m("C20", "wire: a role that may create a trusted networked extension counts", N, [["AND (EXISTS (SELECT 1 FROM pg_catalog.pg_available_extension_versions v WHERE v.trusted", "AND (false AND EXISTS (SELECT 1 FROM pg_catalog.pg_available_extension_versions v WHERE v.trusted"]]),
  m("C21", "wire: supautils' privileged role counts while its list names a networked extension", N, [["  + \" OR (EXISTS (SELECT 1 FROM pg_catalog.pg_roles w WHERE", "  + \" OR (false AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles w WHERE"]]),
  m("C22", "wire: the lending count reads the owner's closure", N, [["CLOSURE + \"SELECT count(*) FROM pg_catalog.pg_proc p WHERE \" + DEFINER + \" AND \" + POWERED('p.proowner'),", "CLOSURE + \"SELECT count(*) FROM pg_catalog.pg_proc p WHERE \" + DEFINER + \" AND p.proowner IN (\" + PROGRAM + \")\","]]),
  m('C24', 'wire: supautils unseen by the witness but set for a role or database is an undeclarable entry', N, [['  + " UNION SELECT \'(supautils unconfirmed)\' WHERE CASE WHEN', '  + " UNION SELECT NULL WHERE false AND CASE WHEN']]),
  m("C25", "wire: a role that may create a subscription (PostgreSQL 16 and later) counts", N, [["  + \" OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles x WHERE x.rolname = 'pg_create_subscription'", "  + \" OR false AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles x WHERE x.rolname = 'pg_create_subscription'"]]),
  m("C26", "wire: '(PUBLIC)' reads the function owner's closure, every power", N, [["AND a.privilege_type = 'EXECUTE' AND \" + POWERED('p.proowner') + \")\"", "AND a.privilege_type = 'EXECUTE' AND p.proowner IN (\" + PROGRAM + \"))\""]]),
  m("C27", "wire: supautils unconfirmed when either of its settings is unseen", N, [[" OR pg_catalog.current_setting('supautils.privileged_extensions', true) IS NULL\"", "\""]]),
  m("C28", "wire: an existing subscription is an undeclarable entry", N, [["  + \" UNION SELECT '(subscription)' WHERE EXISTS", "  + \" UNION SELECT NULL WHERE false AND EXISTS"]]),
  m("C29", "wire: a subject-writable window's record names the remedy", N, [[" ...(custody === 'observer-held' ? {} : { remedy: PG_NET_WIRE_REMEDY }),", ""]]),
  m("C30", "wire: reach goes any number of steps, not one", N, [["reach(s, t) AS (SELECT oid, oid FROM pg_catalog.pg_roles UNION SELECT r.s, e.b FROM reach r JOIN edge e ON e.a = r.t)", "reach(s, t) AS (SELECT oid, oid FROM pg_catalog.pg_roles UNION SELECT e.a, e.b FROM edge e)"]]),
  m("R1", "wire: a declared program role the request roles reach is refused", N, [["undeclared === 0 && checked && refused?.length === 0 && extensions", "undeclared === 0 && checked && extensions"]]),
  m("R2", "wire: without declared request roles nothing is observer-held", N, [["const checked = requested !== null && reach !== null && !reach.has('(missing request role)');", "const checked = reach !== null && !reach.has('(missing request role)');"]]),
  m("R3", "wire: a declared request role that does not exist cannot be checked", N, [["const checked = requested !== null && reach !== null && !reach.has('(missing request role)');", "const checked = requested !== null && reach !== null;"]]),
  m("R4", "wire: the request roles' reach is the whole closure", N, [["SELECT g.rolname FROM pg_catalog.pg_roles q JOIN reach x ON x.s = q.oid", "SELECT g.rolname FROM pg_catalog.pg_roles q JOIN (SELECT oid AS s, oid AS t FROM pg_catalog.pg_roles) x ON x.s = q.oid"]]),
  m("R5", "wire: the declaration goes beside every verdict", N, [["        return { events: [], coverage, reason: reasons.size ? [...reasons].sort().join(',') : null, custody, declaration: record.declaration,", "        return { events: [], coverage, reason: reasons.size ? [...reasons].sort().join(',') : null, custody,"]]),
  m("WW8", "pg-wal: the wire's declaration goes beside the window", W, [["...(wire !== null ? { declaration: wired?.declaration ?? null } : {}), ", ""]]),
  m("R6", "wire: request roles without program roles still read what is refused (nothing), so the declaration is a valid checked one", N, [["const refused = reach ? [...(declared ?? [])].filter(r => reach.has(r)).sort() : null;", "const refused = declared && reach ? [...declared].filter(r => reach.has(r)).sort() : null;"]]),
  m('C23', 'wire: a database on the host\'s network counts as shared', N, [["self[1] === 'host' || self[1].startsWith('container:')", "self[1].startsWith('container:')"]]),
  m('C10', 'wire: another container in the namespace keeps the window subject-writable', N, [['&& shared === 0 ?', '?']]),
  m('C11', 'wire: the namespace is read again at the end probe', N, [['const endSharing = await sharing();', 'const endSharing = startSharing;']]),
  m('C12', 'wire: the tap itself is not counted as another container', N, [['return n !== `/${name}` && (mode', 'return (mode']]),
  m('W1', 'wire: a second connection to a witness port makes the window partial', N, [["      if ([...sources.values()].some(set => set.size > 1)) reasons.add('pg-net-witness-repeated');\n", '']]),
  m('W2', 'wire: a retransmitted SYN is one connection (source ports, not frames)', N, [['(m.witnessSources ??= new Set()).add(o.sp)', '(m.witnessSources ??= new Set()).add(s)']]),
  m('W3', 'wire: a frame to an earlier mark\'s witness port is a send', N, [["const sends = inWindow.filter(r => r.kind === 'send' || (r.kind === 'witness' && r.index < from.index));", "const sends = inWindow.filter(r => r.kind === 'send');"]]),
  m('W4', 'wire: a second source at a witness port inside the window is repeated', N, [['for (const r of inWindow) if (r.kind === \'witness\' && r.index >= from.index) {', 'for (const r of []) if (r.kind === \'witness\' && r.index >= from.index) {']]),
  m('T10', 'tap: a mark restarts the per-connection segment throttle', N, [["    state['last'].clear()\n    emit({'k': kind", "    emit({'k': kind"]]),
  m('C13', 'wire: a database container in another container\'s namespace counts', N, [["container:${container}`); }).length + (dbJoined ? 1 : 0);", "container:${container}`); }).length;"]]),
  m('C4', 'wire: without a declaration nothing is observer-held', N, [['const declared = programRoles === undefined ? null : new Set(programRoles);', 'const declared = new Set(programRoles ?? []);']]),
  m('C5', 'wire: the custody readings come in the witness\'s statement, before it is queued', N, [['/* sh:pg-net-witness */ ${CUSTODY_SQL}; ${reachSql}; SELECT net.http_get(', '/* sh:pg-net-witness */ SELECT 1; ${reachSql}; SELECT net.http_get(']]),
  m('P7', 'wire: a stopped tap fails the window', N, [["      if (downAt !== null || !probe || probe.drops === null) return result('failed', new Set(['pg-net-tap-down']));\n", '']]),
  m('P8', 'wire: a witness that cannot be queued fails the mark', N, [["      try { ({ port: m.port, custody: m.custody } = await queueWitness(index)); } catch { marks.set(index, { ok: false, reason: 'pg-net-mark-failed' }); }", '      try { ({ port: m.port, custody: m.custody } = await queueWitness(index)); } catch { /* kept */ }']]),
  m('P9', 'wire: an unreadable line makes the window partial', N, [["      if (inWindow.some(r => r.kind === 'unreadable')) reasons.add('pg-net-tap-unreadable');\n", '']]),
  m('P10', 'wire: a witness is recognised only at the host gateway', N, [['const witness = o.d === gw ? witnessPorts.get(o.dp) : undefined;', 'const witness = witnessPorts.get(o.dp);']]),
  m('P11', 'wire: the record keeps digests, not the host', N, [["hostDigest: sealed('host', o.r === 'http' ? o.h : o.r === 'tls' ? o.sni : null),", "hostDigest: o.r === 'http' ? o.h : null,"]]),
  m('P12', 'wire: ICMP is counted, not a send', N, [["    if (o.k === 'icmp' || o.k === 'link') return keep({ seq: s, at, kind: o.k });", "    if (o.k === 'link') return keep({ seq: s, at, kind: o.k });"]]),
  m('P13', 'wire: the sidecar drops every capability but NET_RAW', N, [["'--cap-drop', 'ALL', '--cap-add', 'NET_RAW',", "'--cap-add', 'NET_RAW',"]]),
  m('P13b', 'wire: the tap never pulls its image', N, [["['run', '--pull', 'never', '--rm',", "['run', '--rm',"]]),
  m('P13c', 'wire: an image not on this machine fails start before the tap runs', N, [["      if ((await dockerOut(['image', 'inspect', '--format', '{{.Id}}', image])) === null) throw", "      if (false) throw"]]),
  m('P13d', 'wire: the image is named only by digest', N, [["const IMAGE = /^[a-z0-9][a-z0-9._/-]{0,199}@sha256:[0-9a-f]{64}$/;", "const IMAGE = /^[a-z0-9][a-z0-9._/-]{0,199}(?:(?::[A-Za-z0-9_.-]{1,128})|@sha256:[0-9a-f]{64})$/;"]]),
  m('P14', 'wire: a gateway the tap could not resolve refuses the start', N, [["gw = typeof o.gw === 'string' && IPV4.test(o.gw) ? o.gw : null;", "gw = typeof o.gw === 'string' ? o.gw : '0.0.0.0';"]]),
  m('P15', 'wire: one tap answers the whole window', N, [["      if (a.epoch === null || a.epoch !== epoch || b.epoch !== epoch || probe.epoch !== epoch) reasons.add('pg-net-tap-gap');\n", '']]),
  m('P16', 'wire: the namespace keeps its interfaces', N, [["      if (!sameList(a.ifs, interfaceList) || !sameList(b.ifs, interfaceList) || !sameList(probe.ifs, interfaceList)) reasons.add('pg-net-interfaces-changed');\n", '']]),
  m('P17', 'wire: a mark before the tap started fails', N, [["      if (child === null) { marks.set(index, { ok: false, reason: 'pg-net-tap-not-started' }); return { index }; }\n", '']]),
  m('P18', 'wire: a tap that cannot list its interfaces does not start', N, [['&& epoch !== null && interfaceList !== null;', '&& epoch !== null;']]),
  // The tap.
  m('T1', 'tap: frames the namespace receives are not reported', N, [['    if ptype != OUTGOING: return\n', '']]),
  m('T2', 'tap: a server\'s answers on its listening port are not reported', N, [["        if sport in state['listen']: return\n", '']]),
  m('T3', 'tap: connections inside the container are counted, not reported', N, [['        inside = lo and loopback and dst != RESOLVER\n', '        inside = False\n']]),
  m('T4', 'tap: a DNS query to Docker\'s resolver is reported', N, [["        if lo and loopback and dst != RESOLVER: state['lo'] += 1; return\n", "        if lo: state['lo'] += 1; return\n"]]),
  m('T5', 'tap: the resolver\'s replies are not reported', N, [['        if src == RESOLVER: return\n', '']]),
  m('T6', 'tap: a SYN-ACK is not a connection the namespace opened', N, [['        if flags & 0x02 and not flags & 0x10:', '        if flags & 0x02:']]),
  m('T7', 'tap: IPv6 is read', N, [['    elif proto == 0x86DD:', '    elif False:']]),
  m('T9', 'tap: a UDP datagram the namespace sends is reported', N, [["        return emit({'k': 'udp', 'i': ifname,", "        return None and emit({'k': 'udp', 'i': ifname,"]]),
  m('T8', 'tap: a later fragment is skipped', N, [["        if struct.unpack('!H', pkt[6:8])[0] & 0x1FFF: return\n", '']]),
];

function runFiles(root, files) {
  // Never a bare node --test: an empty list or a missing file would make it discover and run the whole suite.
  if (!files.length || files.some(f => !f.endsWith('.test.mjs') || !existsSync(join(root, f)))) throw new Error('refused: a test file list that is empty or names a missing file');
  const failed = [];
  for (const file of files) {
    const out = spawnSync(process.execPath, ['--test', '--test-isolation=none', file], { cwd: root, encoding: 'utf8', timeout: 600000, env: process.env });
    const lines = (out.stdout ?? '').split('\n');
    if (out.status !== 0) failed.push(...new Set(lines.filter(l => /^✖ /.test(l)).map(l => `${file.split('/').pop()}: ${l.slice(2).replace(/ \([\d.]+ms\)$/, '')}`)), ...(out.status === null ? [`${file}: timeout`] : []));
  }
  return failed;
}

async function main() {
  const arg = flag => (process.argv.includes(flag) ? process.argv[process.argv.indexOf(flag) + 1] : null);
  const outFile = arg('--out'), only = arg('--only')?.split(',') ?? null;
  const tmp = mkdtempSync(join(tmpdir(), 'scopehaven pg net wire mutations '));
  try {
    for (const dir of ['src', 'integrations', 'test']) cpSync(join(ROOT, dir), join(tmp, dir), { recursive: true });
    cpSync(join(ROOT, 'package.json'), join(tmp, 'package.json'));
    const base = runFiles(tmp, UNIT);
    if (base.length) throw new Error(`Unmutated tests fail: ${base.join('; ')}`);
    const results = [];
    for (const mu of MUTATIONS.filter(x => !only || only.includes(x.id))) {
      const path = join(tmp, mu.file), original = readFileSync(path, 'utf8');
      const counts = mu.edits.map(([find]) => original.split(find).length - 1);
      if (counts.some(c => c !== 1)) { results.push({ id: mu.id, property: mu.property, status: 'not-applied', reason: `finds matched ${counts.join(', ')} times` }); process.stderr.write(`${mu.id} not-applied\n`); continue; }
      writeFileSync(path, mu.edits.reduce((text, [find, replace]) => text.replace(find, () => replace), original));
      try {
        const failed = runFiles(tmp, UNIT);
        results.push({ id: mu.id, property: mu.property, file: mu.file, status: failed.length ? 'killed' : 'SURVIVED', killedBy: failed.slice(0, 3) });
      } finally { writeFileSync(path, original); }
      process.stderr.write(`${mu.id} ${results.at(-1).status}\n`);
    }
    const summary = { schema: 'scopehaven-pg-net-wire-mutations/1', at: new Date().toISOString(), node: process.version, unit: UNIT, total: results.length, killed: results.filter(r => r.status === 'killed').length, results };
    if (outFile) writeFileSync(outFile, `${JSON.stringify(summary, null, 1)}\n`);
    process.stdout.write(`${JSON.stringify({ total: summary.total, killed: summary.killed, survivors: results.filter(r => r.status !== 'killed').map(r => `${r.id} ${r.status}`) })}\n`);
    if (summary.killed !== summary.total) process.exitCode = 1;
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
