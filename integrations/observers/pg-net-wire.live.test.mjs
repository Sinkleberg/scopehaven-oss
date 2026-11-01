// pg_net on the wire against a real Supabase database container. Skipped unless SCOPEHAVEN_PG_NET_LIVE names a disposable
// copy's database as "user:password@127.0.0.1:port/database@container" for a role that may create tables and roles and call
// net.http_get (the local stack's supabase_admin), with pg_net installed, wal_level = logical, the docker CLI, and
// SCOPEHAVEN_PG_NET_LIVE_IMAGE naming a Python 3 image already on this machine by digest (name@sha256:...; nothing is pulled). Each test creates its own table and roles and drops them after. Every request it
// makes pg_net send goes to the host gateway at a port nothing listens on: nothing leaves this machine.
//
// Covers what the scripted tap cannot: the sidecar sharing the database's network namespace, pg_net's worker sending the
// witness, the tap reading real frames, and pg-wal counting the queue as observed only through a complete wire window.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomInt } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { pgConnect } from './pg-wire.mjs';
import { createPgNetWire, PG_NET_QUEUE, PROGRAM_ROLES_SQL } from './pg-net-wire.mjs';
import { createPgWalObserver } from './pg-wal.mjs';

const live = /^([^:@/]+):([^@]+)@127\.0\.0\.1:(\d+)\/([A-Za-z_][A-Za-z0-9_]*)@([A-Za-z0-9][A-Za-z0-9_.-]{0,127})$/.exec(process.env.SCOPEHAVEN_PG_NET_LIVE ?? '');
const [, adminUser, adminPassword, portText, database, container] = live ?? [];
const port = Number(portText);
const image = process.env.SCOPEHAVEN_PG_NET_LIVE_IMAGE ?? '';
const connectAs = (user, password) => pgConnect({ host: '127.0.0.1', port, database, user, password });
let skip = !live ? 'set SCOPEHAVEN_PG_NET_LIVE=user:password@127.0.0.1:port/db@container (a disposable Supabase copy) to run'
  : !/^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$/.test(image) ? 'set SCOPEHAVEN_PG_NET_LIVE_IMAGE=name@sha256:<digest> (a local Python 3 image) to run' : false;
if (!skip) {
  try {
    const probe = await connectAs(adminUser, adminPassword);
    try {
      const [level, net] = await probe.query("SHOW wal_level; SELECT count(*) FROM pg_catalog.pg_extension WHERE extname = 'pg_net'");
      if (level.rows[0][0] !== 'logical') skip = `the server's wal_level is ${level.rows[0][0]}`;
      else if (net.rows[0][0] !== '1') skip = 'pg_net is not installed in that database';
    } finally { probe.close(); }
  } catch (error) { skip = `the server named by SCOPEHAVEN_PG_NET_LIVE could not be reached (${error.code ?? 'error'})`; }
}
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

async function fixture(t) {
  const admin = await connectAs(adminUser, adminPassword);
  const x = randomBytes(4).toString('hex'), table = `sh_pgnet_orders_${x}`, walRole = `sh_pgnet_wal_${x}`, witnessRole = `sh_pgnet_witness_${x}`;
  const walPass = randomBytes(12).toString('hex'), witnessPass = randomBytes(12).toString('hex');
  const requestRole = `sh_pgnet_request_${x}`;
  t.after(async () => {
    await admin.query(`DROP TABLE IF EXISTS public.${table}; DROP ROLE IF EXISTS ${walRole}; DROP ROLE IF EXISTS ${requestRole}; REVOKE ALL ON SCHEMA net FROM ${witnessRole}; REVOKE ALL ON ALL TABLES IN SCHEMA net FROM ${witnessRole};
      REVOKE ALL ON ALL SEQUENCES IN SCHEMA net FROM ${witnessRole}; REVOKE ALL ON ALL FUNCTIONS IN SCHEMA net FROM ${witnessRole}; DROP ROLE IF EXISTS ${witnessRole}`).catch(() => {});
    admin.close();
  });
  await admin.query(`CREATE TABLE public.${table} (id text PRIMARY KEY, status text); INSERT INTO public.${table} VALUES ('o1', 'open');
    CREATE ROLE ${walRole} LOGIN REPLICATION PASSWORD '${walPass}'; CREATE ROLE ${requestRole} LOGIN;
    CREATE ROLE ${witnessRole} LOGIN PASSWORD '${witnessPass}'; GRANT USAGE ON SCHEMA net TO ${witnessRole};
    GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA net TO ${witnessRole}; GRANT INSERT ON ALL TABLES IN SCHEMA net TO ${witnessRole}; GRANT USAGE ON ALL SEQUENCES IN SCHEMA net TO ${witnessRole}`);
  const env = { SCOPEHAVEN_TARGET_LIVE_WAL: `${walRole}:${walPass}`, SCOPEHAVEN_TARGET_LIVE_PGNET: `${witnessRole}:${witnessPass}`, HOME: process.env.HOME };
  // This disposable copy's program-capable login roles, all held by this test (the declaration a profile makes).
  const [roles] = await admin.query(PROGRAM_ROLES_SQL);
  // '(PUBLIC)' (PUBLIC may call a lending function) can never be declared: a copy that has one reads subject-writable.
  const programRoles = roles.rows.map(r => r[0]).filter(r => r !== '(PUBLIC)');
  // The application's request role here is a plain login role of this test's, which reaches none of the declared program roles.
  const wire = (extra = {}) => createPgNetWire({ env, container, image, host: '127.0.0.1', port, database, credentialEnv: 'SCOPEHAVEN_TARGET_LIVE_PGNET', programRoles, requestRoles: [requestRole], quietMs: 1500, ...extra });
  const wal = w => createPgWalObserver({ instanceId: `wal-${x}`, env, host: '127.0.0.1', port, database, credentialEnv: 'SCOPEHAVEN_TARGET_LIVE_WAL', platform: 'supabase',
    tables: [{ table, key: 'id', values: ['status'] }], ...(w ? { wire: w } : {}) });
  return { admin, table, wire, wal, env, programRoles, requestRole, x };
}
// A request pg_net sends on this test's behalf, to the host gateway at a port nothing listens on.
const queueSend = (admin, gw) => admin.query(`SELECT net.http_get('http://${gw}:${randomInt(20000, 65000)}/sh-live-send', timeout_milliseconds := 1000)::text`);

test('live: a window holding only the witnesses is complete; a request pg_net sends makes it partial', { skip }, async t => {
  const f = await fixture(t), o = f.wire(); await o.start(); t.after(() => o.stop());
  const m0 = await o.mark(); await pause(500); const m1 = await o.mark();
  const quiet = await o.collect(m0, m1);
  // Observer-held needs this copy's extensions all in NO_BACKEND_NETWORK and no unowned untrusted or lending function: the record says which.
  assert.deepEqual([quiet.coverage, quiet.reason, quiet.covers, quiet.wire.witness, quiet.custody], ['complete', null, [PG_NET_QUEUE], { start: true, end: true }, 'observer-held'], JSON.stringify(quiet.wire));
  const m2 = await o.mark(); await pause(300);
  await queueSend(f.admin, o.gateway());
  const m3 = await o.mark();
  const sent = await o.collect(m2, m3);
  assert.deepEqual([sent.coverage, sent.reason, sent.covers], ['partial', 'pg-net-sent', []], JSON.stringify(sent.wire));
  assert(sent.wire.kinds.tcp >= 1, JSON.stringify(sent.wire.kinds));
  assert.equal(sent.wire.listed[0].dst, 'host-gateway');
});

test('live: pg-wal counts pg_net\'s unlogged queue as observed only through a complete wire window', { skip }, async t => {
  const f = await fixture(t);
  const bare = f.wal(null); await bare.start(); t.after(() => bare.stop());
  const b0 = await bare.mark(); await f.admin.query(`UPDATE public.${f.table} SET status = 'paid' WHERE id = 'o1'`); const b1 = await bare.mark();
  const without = await bare.collect(b0, b1);
  assert.deepEqual([without.coverage, without.reason, without.wal.others.notInWal], ['partial', 'table-not-in-wal', [PG_NET_QUEUE]], JSON.stringify(without.wal.others));
  await bare.stop();
  const tap = f.wire(), wired = f.wal(tap); await wired.start(); t.after(() => wired.stop());
  const gateway = tap.gateway();
  const w0 = await wired.mark(); await f.admin.query(`UPDATE public.${f.table} SET status = 'shipped' WHERE id = 'o1'`); const w1 = await wired.mark();
  const withWire = await wired.collect(w0, w1);
  assert.deepEqual([withWire.coverage, withWire.reason, withWire.wal.others.notInWal, withWire.wal.others.wire.covered], ['complete', null, [], [PG_NET_QUEUE]], JSON.stringify(withWire.wal.others));
  assert.deepEqual(withWire.wal.tables[0].counts, { insert: 0, update: 1, delete: 0 });
  // A pg_net request in the window: the wire window is partial, so the queue is counted again.
  const w2 = await wired.mark(); await pause(300); await queueSend(f.admin, gateway); const w3 = await wired.mark();
  const sentWindow = await wired.collect(w2, w3);
  assert.deepEqual([sentWindow.reason, sentWindow.wal.others.wire.coverage, sentWindow.wal.others.wire.covered], ['table-not-in-wal', 'partial', []], JSON.stringify(sentWindow.wal.others));
});

test('live control: a missing end witness keeps the window partial (the witness is never queued)', { skip }, async t => {
  const f = await fixture(t);
  let queries = 0;
  // The connect seam: the second mark's witness statement is replaced by one that queues nothing.
  const connect = async opts => { const c = await pgConnect(opts); return { ...c, query: (sql, o) => c.query(++queries === 2 ? '/* sh:no-witness */ SELECT 1' : sql, o), close: () => c.close() }; };
  const o = createPgNetWire({ env: f.env, container, image, host: '127.0.0.1', port, database,
    credentialEnv: 'SCOPEHAVEN_TARGET_LIVE_PGNET', quietMs: 1500, witnessWaitMs: 3000, connect });
  await o.start(); t.after(() => o.stop());
  const m0 = await o.mark(); await pause(300); const m1 = await o.mark();
  const w = await o.collect(m0, m1);
  assert.deepEqual([w.coverage, w.reason, w.wire.witness, w.covers], ['partial', 'pg-net-witness-missing', { start: true, end: false }, []], JSON.stringify(w.wire));
});

test('live control: a UDP datagram sent from inside the database\'s network is seen; an IPv6 attempt on loopback is read (counted, never a send)', { skip }, async t => {
  const f = await fixture(t), o = f.wire(); await o.start(); t.after(() => o.stop());
  // Synthetic traffic from the harness, in a container of its own that joins the same network namespace: one UDP datagram to the host
  // gateway at a port nothing listens on, then a TCP attempt to [::1] when the namespace has IPv6 on loopback.
  const probe = gw => execFileSync('/usr/local/bin/docker', ['run', '--pull', 'never', '--rm', '--network', `container:${container}`, '--cap-drop', 'ALL', '--read-only', '--entrypoint', 'python3', image, '-I', '-c',
    `import socket\nu = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.sendto(b'scopehaven-udp-control', ('${gw}', ${randomInt(20000, 65000)}))\ntry:\n  s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(1); s.connect(('::1', 9)); print('v6 open')\nexcept ConnectionRefusedError: print('v6 refused')\nexcept OSError as e: print('v6 none', e.errno)`],
    { encoding: 'utf8', env: { PATH: '/usr/bin:/bin:/usr/local/bin', HOME: process.env.HOME } }).trim();
  const m0 = await o.mark(); await pause(500); const v6 = probe(o.gateway()); const m1 = await o.mark();
  const w = await o.collect(m0, m1);
  assert.deepEqual([w.coverage, w.reason], ['partial', 'pg-net-sent'], JSON.stringify(w.wire));
  assert(w.wire.kinds.udp >= 1, JSON.stringify(w.wire.kinds));
  assert(w.wire.listed.some(x => x.kind === 'udp' && x.dst === 'host-gateway'), JSON.stringify(w.wire.listed));
  if (!v6.startsWith('v6 none')) assert(w.wire.inContainer >= 1, `${v6}: ${JSON.stringify(w.wire)}`);
  t.diagnostic(`IPv6 on loopback in the namespace: ${v6}; interfaces ${JSON.stringify(w.wire.tap.interfaces.start)}`);
});

test('live control: custody reads the server\'s program-capable login roles at each mark', { skip }, async t => {
  const f = await fixture(t);
  // Undeclared: the same quiet window is complete but covers nothing.
  const bare = f.wire({ programRoles: undefined }); await bare.start(); t.after(() => bare.stop());
  const b0 = await bare.mark(); await pause(300); const b1 = await bare.mark();
  const u = await bare.collect(b0, b1);
  assert.deepEqual([u.coverage, u.custody, u.covers, u.wire.programRoles.declared], ['complete', 'subject-writable', [], 0], JSON.stringify(u.wire));
  await bare.stop();
  // A superuser nobody declared, created before the end mark: subject-writable, counted once, never named.
  const extra = `sh_pgnet_prog_${f.x}`;
  const o = f.wire(); await o.start(); t.after(() => o.stop());
  let w;
  try {
    const m0 = await o.mark(); await f.admin.query(`CREATE ROLE ${extra} LOGIN SUPERUSER`); const m1 = await o.mark();
    w = await o.collect(m0, m1);
  } finally { await f.admin.query(`DROP ROLE IF EXISTS ${extra}`); }
  assert.deepEqual([w.coverage, w.custody, w.covers, w.wire.programRoles], ['complete', 'subject-writable', [], { declared: f.programRoles.length, read: true, undeclared: 1 }], JSON.stringify(w.wire));
  assert(!JSON.stringify(w).includes(extra));
  // A login role that may call a SECURITY DEFINER function a superuser owns borrows that power: read as a program role too.
  const borrower = `sh_pgnet_borrow_${f.x}`, lender = `public.sh_pgnet_lend_${f.x}`;
  const o2 = f.wire(); await o2.start(); t.after(() => o2.stop());
  let lent;
  try {
    await f.admin.query(`CREATE ROLE ${borrower} LOGIN; CREATE FUNCTION ${lender}() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1';
      REVOKE ALL ON FUNCTION ${lender}() FROM PUBLIC; GRANT EXECUTE ON FUNCTION ${lender}() TO ${borrower}`);
    const n0 = await o2.mark(); await pause(300); const n1 = await o2.mark();
    lent = await o2.collect(n0, n1);
  } finally { await f.admin.query(`DROP FUNCTION IF EXISTS ${lender}(); DROP ROLE IF EXISTS ${borrower}`); }
  assert.deepEqual([lent.coverage, lent.custody, lent.wire.programRoles.undeclared], ['complete', 'subject-writable', 1], JSON.stringify(lent.wire));
  assert(lent.wire.backendNetwork.definerFunctions >= 1);
  // A lending function PUBLIC may call (EXECUTE is PUBLIC's by default on a new function): '(PUBLIC)' is read and never declared.
  const open = `public.sh_pgnet_open_${f.x}`, o3 = f.wire(); await o3.start(); t.after(() => o3.stop());
  let pub;
  try {
    await f.admin.query(`CREATE FUNCTION ${open}() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'`);
    const p0 = await o3.mark(); await pause(300); const p1 = await o3.mark();
    pub = await o3.collect(p0, p1);
  } finally { await f.admin.query(`DROP FUNCTION IF EXISTS ${open}()`); }
  assert.deepEqual([pub.coverage, pub.custody], ['complete', 'subject-writable'], JSON.stringify(pub.wire));
  assert(pub.wire.programRoles.undeclared >= 1);
  // A C function the application side creates, named like one of initdb's conversion functions, in a schema that is not pg_catalog:
  // counted as untrusted (initdb's own are told apart by OID and pg_catalog, never by name).
  const lookalike = `public.big5_to_utf8`, o4 = f.wire(); await o4.start(); t.after(() => o4.stop());
  let c;
  try {
    await f.admin.query(`CREATE FUNCTION ${lookalike}(integer, integer, cstring, internal, integer, boolean) RETURNS integer AS '$libdir/utf8_and_big5', 'big5_to_utf8' LANGUAGE c STRICT`);
    const c0 = await o4.mark(); await pause(300); const c1 = await o4.mark();
    c = await o4.collect(c0, c1);
  } finally { await f.admin.query(`DROP FUNCTION IF EXISTS ${lookalike}(integer, integer, cstring, internal, integer, boolean)`); }
  assert.deepEqual([c.coverage, c.custody, c.wire.backendNetwork.untrustedFunctions], ['complete', 'subject-writable', 1], JSON.stringify(c.wire));
  // Powers held through membership: a login role in a superuser role (SET ROLE), one in pg_execute_server_program, and the caller of a
  // SECURITY DEFINER function whose owner is a member of a superuser role. Each is read as an undeclared program role.
  const su = `sh_pgnet_su_${f.x}`, owner = `sh_pgnet_owner_${f.x}`, viaSu = `sh_pgnet_viasu_${f.x}`, viaProg = `sh_pgnet_viaprog_${f.x}`, caller = `sh_pgnet_caller_${f.x}`, fn = `public.sh_pgnet_owned_${f.x}`;
  const db = database, viaCreate = `sh_pgnet_viacreate_${f.x}`, viaPriv = `sh_pgnet_viapriv_${f.x}`, grantee = `sh_pgnet_grantee_${f.x}`, noinherit = `sh_pgnet_noinherit_${f.x}`;
  const owner2 = `sh_pgnet_owner2_${f.x}`, caller2 = `sh_pgnet_caller2_${f.x}`, fn2 = `public.sh_pgnet_owned2_${f.x}`, fn3 = `public.sh_pgnet_owned3_${f.x}`, sub = `sh_pgnet_sub_${f.x}`;
  const [[privRole]] = (await f.admin.query("SELECT COALESCE(pg_catalog.current_setting('supautils.privileged_role', true), '')"))[0].rows;
  // Each control: statements run one at a time (CREATE SUBSCRIPTION may not run in a transaction block), then dropped.
  const setups = [
    ['a login role in a superuser role (SET ROLE)', [`CREATE ROLE ${su} NOLOGIN SUPERUSER`, `CREATE ROLE ${viaSu} LOGIN`, `GRANT ${su} TO ${viaSu}`], [`DROP ROLE IF EXISTS ${viaSu}`, `DROP ROLE IF EXISTS ${su}`]],
    ['a pg_execute_server_program member', [`CREATE ROLE ${viaProg} LOGIN`, `GRANT pg_execute_server_program TO ${viaProg}`], [`DROP ROLE IF EXISTS ${viaProg}`]],
    ['the caller of a lending function whose owner is a member of a superuser role', [`CREATE ROLE ${su} NOLOGIN SUPERUSER`, `CREATE ROLE ${owner} NOLOGIN`, `GRANT ${su} TO ${owner}`, `CREATE ROLE ${caller} LOGIN`,
      `CREATE FUNCTION ${fn}() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'`, `ALTER FUNCTION ${fn}() OWNER TO ${owner}`, `REVOKE ALL ON FUNCTION ${fn}() FROM PUBLIC`, `GRANT EXECUTE ON FUNCTION ${fn}() TO ${caller}`],
     [`DROP FUNCTION IF EXISTS ${fn}()`, `DROP ROLE IF EXISTS ${caller}`, `DROP ROLE IF EXISTS ${owner}`, `DROP ROLE IF EXISTS ${su}`]],
    ['a NOINHERIT login role that can SET ROLE to the only grantee of a lending function', [`CREATE ROLE ${grantee} NOLOGIN`, `CREATE ROLE ${noinherit} LOGIN NOINHERIT`, `GRANT ${grantee} TO ${noinherit}`,
      `CREATE FUNCTION ${fn3}() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'`, `REVOKE ALL ON FUNCTION ${fn3}() FROM PUBLIC`, `GRANT EXECUTE ON FUNCTION ${fn3}() TO ${grantee}`],
     [`DROP FUNCTION IF EXISTS ${fn3}()`, `DROP ROLE IF EXISTS ${noinherit}`, `DROP ROLE IF EXISTS ${grantee}`]],
    ['a login role with CREATE in the database (trusted extensions outside the list are available)', [`CREATE ROLE ${viaCreate} LOGIN`, `GRANT CREATE ON DATABASE ${db} TO ${viaCreate}`],
     [`REVOKE CREATE ON DATABASE ${db} FROM ${viaCreate}`, `DROP ROLE IF EXISTS ${viaCreate}`]],
    ['the caller of a lending function whose owner may only create in the database', [`CREATE ROLE ${owner2} NOLOGIN`, `GRANT CREATE ON DATABASE ${db} TO ${owner2}`, `CREATE ROLE ${caller2} LOGIN`,
      `CREATE FUNCTION ${fn2}() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'`, `ALTER FUNCTION ${fn2}() OWNER TO ${owner2}`, `REVOKE ALL ON FUNCTION ${fn2}() FROM PUBLIC`, `GRANT EXECUTE ON FUNCTION ${fn2}() TO ${caller2}`],
     [`DROP FUNCTION IF EXISTS ${fn2}()`, `DROP ROLE IF EXISTS ${caller2}`, `REVOKE CREATE ON DATABASE ${db} FROM ${owner2}`, `DROP ROLE IF EXISTS ${owner2}`]],
    ...(privRole ? [['a member of supautils\' privileged role', [`CREATE ROLE ${viaPriv} LOGIN`, `GRANT "${privRole}" TO ${viaPriv}`], [`DROP ROLE IF EXISTS ${viaPriv}`]]] : []),
    ['an existing subscription (disabled, never connected)', [`CREATE SUBSCRIPTION ${sub} CONNECTION 'host=127.0.0.1 port=1 dbname=none' PUBLICATION none WITH (connect = false, enabled = false, create_slot = false, slot_name = NONE)`],
     [`DROP SUBSCRIPTION IF EXISTS ${sub}`]],
  ];
  for (const [label, create, drop] of setups) {
    const om = f.wire(); await om.start(); t.after(() => om.stop());
    let m;
    try {
      for (const sql of create) await f.admin.query(sql);
      const q0 = await om.mark(); await pause(300); const q1 = await om.mark();
      m = await om.collect(q0, q1);
    } finally { for (const sql of drop) await f.admin.query(sql).catch(() => {}); await om.stop(); }
    assert.deepEqual([m.coverage, m.custody, m.wire.programRoles.undeclared], ['complete', 'subject-writable', 1], `${label}: ${JSON.stringify(m.wire)}`);
    t.diagnostic(`control held: ${label}`);
  }
  // A declaration naming a role the application's requests reach is refused: a gateway login role (NOINHERIT) that can SET ROLE to an API
  // role, which may run a SECURITY DEFINER function owned by a role with CREATE in the database. Declaring that owner reads subject-writable.
  const gate = `sh_pgnet_gate_${f.x}`, api = `sh_pgnet_api_${f.x}`, fnOwner = `sh_pgnet_fnowner_${f.x}`, rpc = `public.sh_pgnet_rpc_${f.x}`;
  const oc = f.wire({ programRoles: [...f.programRoles, fnOwner], requestRoles: [gate] }); await oc.start(); t.after(() => oc.stop());
  let refusedWindow;
  try {
    for (const sql of [`CREATE ROLE ${fnOwner} LOGIN`, `GRANT CREATE ON DATABASE ${db} TO ${fnOwner}`, `CREATE ROLE ${api} NOLOGIN`, `CREATE ROLE ${gate} LOGIN NOINHERIT`, `GRANT ${api} TO ${gate}`,
      `CREATE FUNCTION ${rpc}() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'`, `ALTER FUNCTION ${rpc}() OWNER TO ${fnOwner}`, `REVOKE ALL ON FUNCTION ${rpc}() FROM PUBLIC`, `GRANT EXECUTE ON FUNCTION ${rpc}() TO ${api}`])
      await f.admin.query(sql);
    const r0 = await oc.mark(); await pause(300); const r1 = await oc.mark();
    refusedWindow = await oc.collect(r0, r1);
  } finally {
    for (const sql of [`DROP FUNCTION IF EXISTS ${rpc}()`, `DROP ROLE IF EXISTS ${gate}`, `DROP ROLE IF EXISTS ${api}`, `REVOKE CREATE ON DATABASE ${db} FROM ${fnOwner}`, `DROP ROLE IF EXISTS ${fnOwner}`]) await f.admin.query(sql).catch(() => {});
    await oc.stop();
  }
  assert.deepEqual([refusedWindow.coverage, refusedWindow.custody, refusedWindow.declaration.refused, refusedWindow.declaration.checked], ['complete', 'subject-writable', [fnOwner], true], JSON.stringify(refusedWindow.wire));
  t.diagnostic('control held: a declared role the request roles reach is refused');
  // Two SECURITY DEFINER steps: the request role may run a function owned by a role with no power of its own, which alone may run a
  // function owned by a pg_execute_server_program member. That member is read as reached (refused when declared), and the request role
  // itself, which can act as it, is read as a program role.
  const gw2 = `sh_pgnet_gw2_${f.x}`, mid = `sh_pgnet_mid_${f.x}`, prog2 = `sh_pgnet_prog2_${f.x}`, run2 = `public.sh_pgnet_run2_${f.x}`, ship2 = `public.sh_pgnet_ship2_${f.x}`;
  const o2h = f.wire({ programRoles: [...f.programRoles, prog2], requestRoles: [gw2] }); await o2h.start(); t.after(() => o2h.stop());
  let twoHop;
  try {
    for (const sql of [`CREATE ROLE ${prog2} LOGIN`, `GRANT pg_execute_server_program TO ${prog2}`, `CREATE ROLE ${mid} NOLOGIN`, `CREATE ROLE ${gw2} LOGIN`,
      `CREATE FUNCTION ${ship2}() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'`, `ALTER FUNCTION ${ship2}() OWNER TO ${prog2}`, `REVOKE ALL ON FUNCTION ${ship2}() FROM PUBLIC`, `GRANT EXECUTE ON FUNCTION ${ship2}() TO ${mid}`,
      `CREATE FUNCTION ${run2}() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'`, `ALTER FUNCTION ${run2}() OWNER TO ${mid}`, `REVOKE ALL ON FUNCTION ${run2}() FROM PUBLIC`, `GRANT EXECUTE ON FUNCTION ${run2}() TO ${gw2}`])
      await f.admin.query(sql);
    const h0 = await o2h.mark(); await pause(300); const h1 = await o2h.mark();
    twoHop = await o2h.collect(h0, h1);
  } finally {
    for (const sql of [`DROP FUNCTION IF EXISTS ${run2}()`, `DROP FUNCTION IF EXISTS ${ship2}()`, `DROP ROLE IF EXISTS ${gw2}`, `DROP ROLE IF EXISTS ${mid}`, `DROP ROLE IF EXISTS ${prog2}`]) await f.admin.query(sql).catch(() => {});
    await o2h.stop();
  }
  assert.deepEqual([twoHop.coverage, twoHop.custody, twoHop.declaration.refused, twoHop.wire.programRoles.undeclared], ['complete', 'subject-writable', [prog2], 1], JSON.stringify(twoHop.wire));
  t.diagnostic('control held: a power two SECURITY DEFINER steps away is reached');
  t.diagnostic(`program-capable login roles on this copy before the controls: ${f.programRoles.length}`);
});
