// Postgres actor capture (pg-actor, NC2 item 2): who made each write the Postgres observers see. Opt-in, on the test
// copy only. Dependency-free (./pg-wire.mjs).
//
// Why. pg-snapshot and pg-wal record what changed, not who changed it: both declare actorAttribution "none", so an effect
// clause pinned to an actor ("ana's session wrote no globex row") is unobservable on them. On Supabase the acting user is
// not a database role either: PostgREST runs every request as one of a few roles (anon, authenticated, service_role) and
// puts the user in a per-transaction setting, request.jwt.claims.
//
// Who installs it. A superuser (supabase_admin on a local Supabase stack), never a role the application writes with: the
// capture's objects are owned by the install role, and a role that owns the audit table could rewrite it, grant it or
// replace the function. installActorCapture refuses a role that is not a superuser. No application role can become a
// superuser, and the definitions check below covers owners and privileges, so a grant or a change of owner reads altered.
// (On Supabase the postgres role is a member of pg_read_all_data, so it can read the audit table, never write it; a GRANT it
// attempts grants nothing. The audit table's own catalog row version is left out of the check, so VACUUM FULL, which
// rewrites the table, changes nothing it reads.)
//
// What it installs (installSql), in one transaction, before any observer starts (the observers' catalog fingerprint,
// ./catalog.mjs, covers triggers, so an installation after their baseline reads schema-drift):
//   - a schema of its own (scopehaven_actor by default), marked with a comment, which an existing schema without the mark
//     never becomes and which uninstallation drops only with the mark (never a platform schema: auth, storage, net and
//     the others in PLATFORM_SCHEMAS are refused). It holds one append-only audit table,
//       (seq, txid, tbl, key, op, rowcount, depth, row_xmin, claims_sub, claims_role, legacy_sub, set_role, session_role,
//        app_actor, at),
//     with every privilege revoked from PUBLIC and row-level security on with no policy;
//   - one trigger function, SECURITY DEFINER with a pinned search_path, that the trigger mechanism alone can call (a
//     function returning trigger cannot be called directly, and no role but the owner may attach it to a table);
//   - one reader function, ledger(after_seq, max_rows), SECURITY DEFINER with a pinned search_path, that returns the audit
//     rows after a sequence number to the roles granted EXECUTE on it (the observers' roles: installSql readers). An
//     observer reads under row_security = off, where a role without BYPASSRLS reading a table with row-level security
//     fails, so the observers read through it and the audit table keeps no policy at all. It reads under the caller's
//     snapshot, so a snapshot observer's ledger is exactly the rows its own mark sees;
//   - per declared table (each checked first: an ordinary or partitioned table with the declared key and actor columns and a
//     unique index on the key alone, and plan-checked after: the trigger's own expressions over the table, writing nothing),
//     three AFTER ... FOR EACH STATEMENT triggers (insert, update, delete) with transition tables, named for this
//     installation's schema so two installations never share a name. Each statement writes one audit row per changed row
//     (its key, the new key for an update), and a statement that changed no row writes one row with rowcount 0 and no
//     key: an UPDATE or DELETE that row-level security filtered to nothing is recorded, which neither the WAL nor a
//     snapshot can show (./supabase-rules.mjs reads it, NC2 item 3). Each row carries:
//       txid                     txid_current(): the top-level transaction (64-bit, epoch included);
//       row_xmin                 the written row's own xmin, read back in the statement: inside a savepoint or a plpgsql
//                                EXCEPTION block it is the subtransaction's id, which is what a snapshot's xmin shows;
//       depth                    pg_trigger_depth(): 2 or more for a statement a user trigger ran; a foreign-key action's
//                                statement (a cascade) reads 1 on PostgreSQL 17, like one the session sent, so depth
//                                does not mark cascades;
//       claims_sub, claims_role  the "sub" and "role" of current_setting('request.jwt.claims', true) (null when unset or
//                                empty; role "?unreadable" when it is not JSON); legacy_sub: request.jwt.claim.sub, the
//                                older per-claim setting auth.uid() reads first; header_sub: the "sub" of the bearer token
//                                in request.headers (the request's own Authorization header, which PostgREST copies there),
//                                read without verifying it;
//       set_role, session_role   current_setting('role') (what SET ROLE chose; a SECURITY DEFINER function does not change
//                                it; "none" without SET ROLE) and session_user (the login role);
//       app_actor                the declared app column (a table's actorColumn): on INSERT the new row's; on UPDATE only
//                                when the statement changed it (an unchanged column says who wrote it last, not who writes
//                                now); never on DELETE.
//
// What is recorded about it. installationRecord: the change to the target the run carries (the objects, the declared
// tables, the install role, and the sha256 of the definitions). verifySql/verifyRecord: at each mark the definitions are
// read again, as structured catalog fields (never text that depends on the session's search_path), with every object's
// owner, privileges and catalog-row xmin, so a trigger disabled and enabled again, a function replaced, a grant, a policy,
// a rule or a change of owner reads altered; a missing or disabled piece reads absent. Only intact, against the
// installation's own digest, attributes anyone; every actor of a window without it is unattributed.
//
// The joins. attributeChange (pg-wal: each decoded write on its own) takes a change's actor from the audit rows of the
// same 32-bit transaction id, table, key and operation; attributeNetChange (pg-snapshot: one event per row) needs every
// write to the row in the window to resolve to one actor, the last one matched on its row_xmin. None reads
// actor-unattributed, two different actors actor-ambiguous, a null key key-null; each is a null actor, so an
// actor-pinned clause reads missing (inconclusive), never a pass. The callers pass the capture's status: there is no
// default. The resolver decides what a row says (resolveActor below; ./supabase-rules.mjs for the service role). pg-wal
// and pg-snapshot apply the joins (NC9 item 2 wired them, through a pg-snapshot observer's actorCapture profile key).
// The net join (pg-snapshot) is operation-aware: a row deleted in the window is attributed only when its last captured
// write is a DELETE, and a row inserted only when a captured INSERT of it is in the window, so a write the capture never
// saw is never credited to the captured writer when it decides the row's net change. A write it never saw before a
// captured one (an earlier UPDATE) leaves no trace a snapshot can read: so an actor-pinned absence never decides on a
// net-only snapshot window (src/effect-events.mjs exactFor), and only pg-wal, which lists every write, decides one.
//
// Limits. A session that may set session_replication_role = replica (a superuser; on Supabase also roles that supautils
// lets set it) skips the triggers: its writes have no audit row. pg-wal reads each such write unattributed; pg-snapshot
// reads a row whose net change such a write decided unattributed, and a row it wrote before a captured write as the
// captured writer's net change (see the net join above: no pinned absence decides there). TRUNCATE has
// no transition table and is not captured (pg-wal reports it as table-truncated). A key changed by an UPDATE is recorded
// under its new key. The app column pairs each new row with the old row of its key, so an UPDATE that moves rows onto keys
// other rows of the same statement held (a key swap) records, at each key, the column of the row now there, though the
// statement did not write it: under actor "column" such a write reads as that row's earlier writer's. Writes to tables not declared here are not captured. The claims are whatever the transaction's SQL
// set (any role may call set_config): resolveActor trusts them only as PostgREST binds them (below), cross-checked with the
// bearer token's sub; SQL that rewrites both the claims and request.headers is not detected. The app column is the
// application's own record (subject-writable). The binding trusts the authenticator login: a role that can set its
// password (on Supabase, postgres holds ADMIN OPTION on it) can log in as it. Writes sent straight to a partition of a
// declared partitioned table are not captured (the triggers are the parent's), and a row an UPDATE moves between partitions
// is recorded under the parent's triggers only as PostgreSQL routes it. A key's text is the writer's session's (a timestamp
// key depends on its TimeZone), so a key whose text depends on session settings may not join. It needs a superuser, so it
// runs on a local or self-hosted copy, never on a hosted Supabase project. Each ledger read reads the run's whole ledger,
// at most PG_ACTOR_LIMITS.ledgerRows rows (past that a read is refused, never partial).
import { createHash } from 'node:crypto';
import { digest } from '../../src/domain.mjs';
import { credentialFrom } from './events.mjs';

export const PG_ACTOR_SCHEMA = 'scopehaven-pg-actor/1';
export const ACTOR_SOURCES = Object.freeze(['jwt-claims', 'current-user', 'column']);
export const PG_ACTOR_REASONS = Object.freeze(['actor-unattributed', 'actor-ambiguous', 'key-null', 'claims-unbound', 'claims-conflict', 'not-a-user-role', 'capture-absent', 'capture-altered', 'capture-unreadable', 'ledger-truncated']);
export const PG_ACTOR_LIMITS = Object.freeze({ tables: 32, principals: 64, value: 200, roles: 8, ledgerRows: 200000 });
export const PG_ACTOR_OPS = Object.freeze(['INSERT', 'UPDATE', 'DELETE']);
// Platform schemas a capture never takes (and so never drops): Supabase's own, and the system ones.
export const PLATFORM_SCHEMAS = Object.freeze(['public', 'auth', 'storage', 'extensions', 'realtime', '_realtime', 'graphql', 'graphql_public', 'vault', 'net', 'cron', 'pgbouncer', 'pgsodium', 'pgsodium_masks', 'supabase_functions', 'supabase_migrations', 'information_schema']);
// The audit row's columns, in the order every ledger read selects them.
export const AUDIT_COLUMNS = Object.freeze(['seq', 'txid', 'xid32', 'tbl', 'key', 'op', 'rowcount', 'depth', 'row_xmin', 'claims_sub', 'claims_role', 'legacy_sub', 'header_sub', 'set_role', 'session_role', 'app_actor']);
const AUDIT_TABLE_COLUMNS = 'seq,txid,tbl,key,op,rowcount,depth,row_xmin,claims_sub,claims_role,legacy_sub,header_sub,set_role,session_role,app_actor,at';
const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const PRINCIPAL = /^[A-Za-z0-9_-]{1,80}$/;
const UNSAFE_KEYS = ['__proto__', 'prototype', 'constructor'];
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const bad = message => { throw new Error(`actorCapture: ${message}`); };
const quote = name => { if (!IDENT.test(name)) throw new Error(`Unsupported SQL identifier "${String(name).slice(0, 64)}".`); return `"${name}"`; };
const literal = name => { if (!IDENT.test(name)) throw new Error(`Unsupported SQL identifier "${String(name).slice(0, 64)}".`); return `'${name}'`; };
const roleList = (value, where) => { if (!(Array.isArray(value) && value.length >= 1 && value.length <= PG_ACTOR_LIMITS.roles && value.every(r => typeof r === 'string' && IDENT.test(r)) && new Set(value).size === value.length)) bad(`"${where}" lists 1 to ${PG_ACTOR_LIMITS.roles} distinct role names`); };

// The profile block:
//   { testCopy: true, installCredentialEnv, schema?, tables: [{ table, key, schema?, actorColumn? }],
//     actor: { from: "jwt-claims", claim?, authenticators?, userRoles? } | { from: "current-user" } | { from: "column" },
//     principals: { "<value the source reads>": "<declared principalId>" } }
// testCopy: true is the operator's statement that the database is a disposable copy (the installation changes its
// schema). installCredentialEnv: a SCOPEHAVEN_TARGET_ variable holding user:password for a superuser; it installs and
// removes, never observes. actor "column" needs each table's actorColumn. jwt-claims: authenticators are the login roles
// PostgREST connects as (default ["authenticator"]) and userRoles the roles it runs a signed-in user as (default
// ["authenticated"]). principals: at most 64; a value the source reads that is not listed reads unlisted:<digest>.
export function validateActorCapture(block, { actors } = {}) {
  if (!plain(block)) bad('must be a JSON object');
  const allowed = ['testCopy', 'installCredentialEnv', 'schema', 'tables', 'actor', 'principals'];
  const unknown = Reflect.ownKeys(block).find(key => typeof key !== 'string' || !allowed.includes(key));
  if (unknown !== undefined) bad(`unsupported field "${String(unknown).slice(0, 32)}"`);
  if (block.testCopy !== true) bad('"testCopy": true is required: the installation changes the database\'s schema, so it runs on a disposable copy only');
  credentialFrom({}, block.installCredentialEnv, 'actorCapture "installCredentialEnv"');
  if (block.schema !== undefined && !(typeof block.schema === 'string' && IDENT.test(block.schema) && !/^pg_/i.test(block.schema) && !PLATFORM_SCHEMAS.includes(block.schema.toLowerCase()))) bad('"schema" is a plain identifier of a schema of its own (not pg_* or a platform schema such as public, auth, storage or net)');
  if (!Array.isArray(block.tables) || block.tables.length < 1 || block.tables.length > PG_ACTOR_LIMITS.tables) bad(`"tables" lists 1 to ${PG_ACTOR_LIMITS.tables} tables`);
  const seen = new Set();
  block.tables.forEach((t, i) => {
    if (!plain(t) || Object.keys(t).some(key => !['table', 'key', 'schema', 'actorColumn'].includes(key))) bad(`table ${i + 1} is { table, key, schema?, actorColumn? }`);
    for (const key of ['table', 'key']) if (typeof t[key] !== 'string' || !IDENT.test(t[key])) bad(`table ${i + 1}: "${key}" is a plain identifier`);
    for (const key of ['schema', 'actorColumn']) if (t[key] !== undefined && !(typeof t[key] === 'string' && IDENT.test(t[key]))) bad(`table ${i + 1}: "${key}" is a plain identifier`);
    if (t.actorColumn !== undefined && t.actorColumn === t.key) bad(`table ${i + 1}: the key is never the actor column`);
    const name = `${t.schema ?? 'public'}.${t.table}`;
    if (seen.has(name)) bad(`table ${i + 1} is declared twice`); seen.add(name);
    if ((t.schema ?? 'public') === schemaOf(block)) bad(`table ${i + 1} is in the capture's own schema`);
  });
  if (!plain(block.actor) || !ACTOR_SOURCES.includes(block.actor.from)) bad(`"actor" is { "from": ${ACTOR_SOURCES.map(s => `"${s}"`).join(', ')} }`);
  const actorKeys = block.actor.from === 'jwt-claims' ? ['from', 'claim', 'authenticators', 'userRoles'] : ['from'];
  if (Object.keys(block.actor).some(key => !actorKeys.includes(key))) bad(`"actor" from "${block.actor.from}" allows only ${actorKeys.map(k => `"${k}"`).join(', ')}`);
  if (block.actor.claim !== undefined && block.actor.claim !== 'sub') bad('"actor" "claim" is "sub" (the claim the capture records)');
  for (const key of ['authenticators', 'userRoles']) if (block.actor[key] !== undefined) roleList(block.actor[key], `actor ${key}`);
  if (block.actor.from === 'column' && block.tables.some(t => t.actorColumn === undefined)) bad('"actor" from "column" needs every table\'s "actorColumn"');
  if (!plain(block.principals) || Object.keys(block.principals).length < 1 || Object.keys(block.principals).length > PG_ACTOR_LIMITS.principals) bad(`"principals" maps 1 to ${PG_ACTOR_LIMITS.principals} values the source reads to declared principals`);
  const declared = actors ? new Set(Object.values(actors).map(a => a?.principalId)) : null;
  for (const [value, principal] of Object.entries(block.principals)) {
    if (UNSAFE_KEYS.includes(value) || value.length < 1 || value.length > PG_ACTOR_LIMITS.value || /[\u0000-\u001f\u007f]/.test(value)) bad(`a "principals" value is 1 to ${PG_ACTOR_LIMITS.value} characters without control characters, and not __proto__, prototype or constructor`);
    if (typeof principal !== 'string' || !PRINCIPAL.test(principal)) bad('each "principals" entry names a principal id');
    if (declared && !declared.has(principal)) bad('each "principals" entry names the principalId of a declared actor');
  }
  return block;
}
export const schemaOf = block => block.schema ?? 'scopehaven_actor';
// The installation's trigger names: its schema's short digest, so two installations never share one.
const triggerNames = block => { const h = createHash('sha256').update(`${PG_ACTOR_SCHEMA}\n${schemaOf(block)}`).digest('hex').slice(0, 10); return { INSERT: `sh_actor_${h}_insert`, UPDATE: `sh_actor_${h}_update`, DELETE: `sh_actor_${h}_delete` }; };
const tableName = t => `${t.schema ?? 'public'}.${t.table}`;
const qualified = t => `${quote(t.schema ?? 'public')}.${quote(t.table)}`;

// The trigger function. One statement per changed set: the rows of the transition table, or one zero-row row.
function functionSql(schema) {
  const audit = `${quote(schema)}.audit`;
  return `CREATE FUNCTION ${quote(schema)}.capture() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $scopehaven_actor$
DECLARE
  raw text := pg_catalog.current_setting('request.jwt.claims', true);
  legacy text := NULLIF(pg_catalog.current_setting('request.jwt.claim.sub', true), '');
  headers text := pg_catalog.current_setting('request.headers', true);
  sub text; jrole text; hsub text; bearer text; n bigint;
  keycol text := TG_ARGV[0];
  appcol text := NULLIF(TG_ARGV[1], '');
  rel text := pg_catalog.format('%I.%I', TG_TABLE_SCHEMA, TG_TABLE_NAME);
  src text := CASE TG_OP WHEN 'DELETE' THEN 'scopehaven_old' ELSE 'scopehaven_new' END;
  actor_sql text; join_sql text := '';
  xmin_sql text;
BEGIN
  IF raw IS NOT NULL AND raw <> '' THEN
    BEGIN
      sub := (raw::pg_catalog.jsonb) ->> 'sub';
      jrole := (raw::pg_catalog.jsonb) ->> 'role';
    EXCEPTION WHEN OTHERS THEN
      sub := NULL; jrole := '?unreadable';
    END;
  END IF;
  -- The sub of the bearer token the request carried (PostgREST copies the request's headers into request.headers): the
  -- token's payload, base64url, read without verifying it, as a cross-check on the claims, which SQL can rewrite.
  IF headers IS NOT NULL AND headers <> '' THEN
    BEGIN
      bearer := pg_catalog.split_part(pg_catalog.substring((headers::pg_catalog.jsonb) ->> 'authorization', '^[Bb]earer (.*)$'), '.', 2);
      IF bearer <> '' THEN
        bearer := pg_catalog.translate(bearer, '-_', '+/');
        bearer := bearer || pg_catalog.repeat('=', (4 - pg_catalog.length(bearer) % 4) % 4);
        hsub := (pg_catalog.convert_from(pg_catalog.decode(bearer, 'base64'), 'UTF8')::pg_catalog.jsonb) ->> 'sub';
      END IF;
    EXCEPTION WHEN OTHERS THEN
      hsub := '?unreadable';
    END;
  END IF;
  IF appcol IS NULL OR TG_OP = 'DELETE' THEN actor_sql := 'NULL';
  ELSIF TG_OP = 'INSERT' THEN actor_sql := pg_catalog.format('(r.%I)::pg_catalog.text', appcol);
  ELSE
    -- Only when the statement changed it, compared as text (a json column has no equality), and never when the UPDATE moved
    -- the row to another key (no old row of that key: who wrote the column is then unknown).
    actor_sql := pg_catalog.format('CASE WHEN o.%2$I IS NULL THEN NULL WHEN (o.%1$I)::pg_catalog.text IS DISTINCT FROM (r.%1$I)::pg_catalog.text THEN (r.%1$I)::pg_catalog.text END', appcol, keycol);
    join_sql := pg_catalog.format(' LEFT JOIN scopehaven_old o ON o.%1$I = r.%1$I', keycol);
  END IF;
  -- The written row's own xmin, through the key's unique index (the install checks there is one).
  xmin_sql := CASE WHEN TG_OP = 'DELETE' THEN 'NULL' ELSE pg_catalog.format('(SELECT x.xmin::pg_catalog.text FROM %s x WHERE x.%2$I = r.%2$I LIMIT 1)', rel, keycol) END;
  EXECUTE pg_catalog.format('INSERT INTO ${audit} (txid, tbl, key, op, rowcount, depth, row_xmin, claims_sub, claims_role, legacy_sub, header_sub, set_role, session_role, app_actor) SELECT pg_catalog.txid_current(), %L, (r.%I)::pg_catalog.text, %L, NULL, pg_catalog.pg_trigger_depth(), %s, $1, $2, $3, $4, $5, $6, %s FROM %I r%s',
    TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, keycol, TG_OP, xmin_sql, actor_sql, src, join_sql)
    USING sub, jrole, legacy, hsub, pg_catalog.current_setting('role'), session_user::pg_catalog.text;
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n = 0 THEN
    INSERT INTO ${audit} (txid, tbl, key, op, rowcount, depth, row_xmin, claims_sub, claims_role, legacy_sub, header_sub, set_role, session_role, app_actor)
      VALUES (pg_catalog.txid_current(), TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, NULL, TG_OP, 0, pg_catalog.pg_trigger_depth(), NULL, sub, jrole, legacy, hsub, pg_catalog.current_setting('role'), session_user::pg_catalog.text, NULL);
  END IF;
  RETURN NULL;
END
$scopehaven_actor$`;
}
// The reader function: the audit rows after a sequence number, oldest first, at most max_rows of them.
function ledgerFunctionSql(schema) {
  return `CREATE FUNCTION ${quote(schema)}.ledger(after_seq bigint, max_rows integer) RETURNS TABLE (seq bigint, txid bigint, tbl text, key text, op text, rowcount integer, depth integer, row_xmin text, claims_sub text, claims_role text, legacy_sub text, header_sub text, set_role text, session_role text, app_actor text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $scopehaven_actor$
  SELECT a.seq, a.txid, a.tbl, a.key, a.op, a.rowcount, a.depth, a.row_xmin, a.claims_sub, a.claims_role, a.legacy_sub, a.header_sub, a.set_role, a.session_role, a.app_actor FROM ${quote(schema)}.audit a WHERE a.seq > after_seq ORDER BY a.seq LIMIT max_rows
$scopehaven_actor$`;
}
// The statements that create this installation, in order (run inside the install's transaction, after the checks and
// the removal of an earlier marked installation). readers: roles that may read the ledger, through the reader function.
export function installSql(block, { readers = [] } = {}) {
  const schema = schemaOf(block), names = triggerNames(block);
  for (const r of readers) if (!IDENT.test(r)) throw new Error('Unsupported SQL identifier for a reader role.');
  return [`CREATE SCHEMA ${quote(schema)}`, `COMMENT ON SCHEMA ${quote(schema)} IS '${PG_ACTOR_SCHEMA}'`, `REVOKE ALL ON SCHEMA ${quote(schema)} FROM PUBLIC`,
    `CREATE TABLE ${quote(schema)}.audit (seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, txid bigint NOT NULL, tbl text NOT NULL, key text, op text NOT NULL, rowcount integer, depth integer NOT NULL, row_xmin text, claims_sub text, claims_role text, legacy_sub text, header_sub text, set_role text, session_role text, app_actor text, at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp())`,
    `REVOKE ALL ON ${quote(schema)}.audit FROM PUBLIC`, `ALTER TABLE ${quote(schema)}.audit ENABLE ROW LEVEL SECURITY`,
    functionSql(schema), `REVOKE ALL ON FUNCTION ${quote(schema)}.capture() FROM PUBLIC`,
    ledgerFunctionSql(schema), `REVOKE ALL ON FUNCTION ${quote(schema)}.ledger(bigint, integer) FROM PUBLIC`,
    ...block.tables.flatMap(t => {
      const args = `${literal(t.key)}, ${t.actorColumn ? literal(t.actorColumn) : "''"}`;
      return [`CREATE TRIGGER ${names.INSERT} AFTER INSERT ON ${qualified(t)} REFERENCING NEW TABLE AS scopehaven_new FOR EACH STATEMENT EXECUTE FUNCTION ${quote(schema)}.capture(${args})`,
        `CREATE TRIGGER ${names.UPDATE} AFTER UPDATE ON ${qualified(t)} REFERENCING OLD TABLE AS scopehaven_old NEW TABLE AS scopehaven_new FOR EACH STATEMENT EXECUTE FUNCTION ${quote(schema)}.capture(${args})`,
        `CREATE TRIGGER ${names.DELETE} AFTER DELETE ON ${qualified(t)} REFERENCING OLD TABLE AS scopehaven_old FOR EACH STATEMENT EXECUTE FUNCTION ${quote(schema)}.capture(${args})`];
    }),
    ...readers.flatMap(r => [`GRANT USAGE ON SCHEMA ${quote(schema)} TO ${quote(r)}`, `GRANT EXECUTE ON FUNCTION ${quote(schema)}.ledger(bigint, integer) TO ${quote(r)}`])];
}
// Removes this installation's triggers from the declared tables and drops its schema (table and functions with it). The
// caller checks the schema's mark first (removeActorCapture, installActorCapture): an unmarked schema is never dropped.
export function uninstallSql(block) {
  const names = triggerNames(block);
  return [...block.tables.flatMap(t => PG_ACTOR_OPS.map(op => `DROP TRIGGER IF EXISTS ${names[op]} ON ${qualified(t)}`)), `DROP SCHEMA IF EXISTS ${quote(schemaOf(block))} CASCADE`];
}
// The schema's state: absent, marked (an earlier installation of ours) or foreign (anything else, never touched).
const markSql = block => `SELECT pg_catalog.obj_description(n.oid, 'pg_namespace') FROM pg_catalog.pg_namespace n WHERE n.nspname = ${literal(schemaOf(block))}`;
const markOf = rows => (!rows.length ? 'absent' : rows[0][0] === PG_ACTOR_SCHEMA ? 'marked' : 'foreign');
// Each declared table, one row per table in order: an ordinary or partitioned table holding the key and the actor column, with
// a unique index on the key alone (a plain, non-partial one: keys name one row each, and the trigger's lookups and joins go
// through it; a partitioned table qualifies only when it is partitioned on its key, and a table keyed on several columns is
// refused).
const tablesSql = block => block.tables.map(t => `SELECT c.relkind::pg_catalog.text, (SELECT pg_catalog.count(*) FROM pg_catalog.pg_attribute a WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped AND a.attname = ${literal(t.key)})::pg_catalog.text, ${t.actorColumn ? `(SELECT pg_catalog.count(*) FROM pg_catalog.pg_attribute a WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped AND a.attname = ${literal(t.actorColumn)})::pg_catalog.text` : "'1'"}, (SELECT pg_catalog.count(*) FROM pg_catalog.pg_index i JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum = i.indkey[0] WHERE i.indrelid = c.oid AND i.indisunique AND i.indnkeyatts = 1 AND i.indpred IS NULL AND i.indexprs IS NULL AND a.attname = ${literal(t.key)})::pg_catalog.text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = ${literal(t.schema ?? 'public')} AND c.relname = ${literal(t.table)}`).join('; ');
// A plan check per declared table, writing nothing and firing no trigger: the trigger's own expressions over the table itself
// (its transition tables have the table's row type), naming only the declared key and actor column. A key or actor column the
// trigger cannot cast, look up or compare refuses the install instead of failing the application's writes.
const planSql = block => block.tables.map(t => `SELECT (r.${quote(t.key)})::pg_catalog.text, (SELECT x.xmin::pg_catalog.text FROM ${qualified(t)} x WHERE x.${quote(t.key)} = r.${quote(t.key)} LIMIT 1)${t.actorColumn
  ? `, CASE WHEN o.${quote(t.key)} IS NULL THEN NULL WHEN (o.${quote(t.actorColumn)})::pg_catalog.text IS DISTINCT FROM (r.${quote(t.actorColumn)})::pg_catalog.text THEN (r.${quote(t.actorColumn)})::pg_catalog.text END` : ''} FROM ${qualified(t)} r LEFT JOIN ${qualified(t)} o ON o.${quote(t.key)} = r.${quote(t.key)} WHERE false`);

// What verifies an installation: one round trip of five results, read as structured catalog fields (so no session setting
// changes them): the schema (owner, privileges, mark, row version), its functions, the triggers that call them, the audit
// table, and its columns. Owners are read with whether each is a superuser.
export function verifySql(block) {
  const s = literal(schemaOf(block));
  const ns = `(SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = ${s})`;
  const owner = col => `(SELECT r.rolname::pg_catalog.text || ':' || r.rolsuper::pg_catalog.text FROM pg_catalog.pg_roles r WHERE r.oid = ${col})`;
  return [`SELECT ${owner('n.nspowner')}, n.nspacl::pg_catalog.text, pg_catalog.obj_description(n.oid, 'pg_namespace'), n.xmin::pg_catalog.text FROM pg_catalog.pg_namespace n WHERE n.nspname = ${s}`,
    `SELECT p.proname::pg_catalog.text, pg_catalog.pg_get_function_identity_arguments(p.oid), p.prosecdef::pg_catalog.text, p.proconfig::pg_catalog.text, pg_catalog.md5(p.prosrc), ${owner('p.proowner')}, p.proacl::pg_catalog.text, p.xmin::pg_catalog.text, p.provolatile::pg_catalog.text FROM pg_catalog.pg_proc p WHERE p.pronamespace = ${ns} ORDER BY 1, 2`,
    `SELECT cn.nspname || '.' || c.relname, t.tgname::pg_catalog.text, t.tgenabled::pg_catalog.text, t.tgtype::pg_catalog.text, pg_catalog.encode(t.tgargs, 'hex'), COALESCE(t.tgoldtable::pg_catalog.text, ''), COALESCE(t.tgnewtable::pg_catalog.text, ''), (t.tgqual IS NULL)::pg_catalog.text, t.tgattr::pg_catalog.text, p.proname::pg_catalog.text, t.xmin::pg_catalog.text FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid JOIN pg_catalog.pg_namespace cn ON cn.oid = c.relnamespace JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid WHERE NOT t.tgisinternal AND p.pronamespace = ${ns} ORDER BY 1, 2`,
    `SELECT c.relrowsecurity::pg_catalog.text, c.relforcerowsecurity::pg_catalog.text, c.relpersistence::pg_catalog.text, c.relkind::pg_catalog.text, (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid = c.oid AND NOT t.tgisinternal)::pg_catalog.text, (SELECT pg_catalog.count(*) FROM pg_catalog.pg_rewrite w WHERE w.ev_class = c.oid)::pg_catalog.text, (SELECT pg_catalog.count(*) FROM pg_catalog.pg_policy y WHERE y.polrelid = c.oid)::pg_catalog.text, ${owner('c.relowner')}, c.relacl::pg_catalog.text FROM pg_catalog.pg_class c WHERE c.relnamespace = ${ns} AND c.relname = 'audit'`,
    `SELECT a.attname::pg_catalog.text, pg_catalog.format_type(a.atttypid, a.atttypmod) FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid WHERE c.relnamespace = ${ns} AND c.relname = 'audit' AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum`].join(';\n');
}
const PINNED_PATH = /^\{"?search_path=pg_catalog, ?pg_temp"?\}$/;
// The verification of one read (verifySql's five results) against the installation's digest, which every mark must
// pass: { status: intact | absent | altered | unreadable, sha256, reason?, missing?, altered? }. verifyAtInstall reads
// the same rules without a digest, once, for the installation itself.
export function verifyRecord(results, block, installedSha256) {
  if (typeof installedSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(installedSha256)) throw new Error('actorCapture: verifyRecord needs the installation\'s digest');
  return verifyRules(results, block, installedSha256);
}
export const verifyAtInstall = (results, block) => verifyRules(results, block, null);
function verifyRules(results, block, installedSha256) {
  if (!Array.isArray(results) || results.length !== 5 || !results.every(r => Array.isArray(r?.rows))) return { status: 'unreadable', sha256: null, reason: 'capture-unreadable' };
  const [schema, fn, triggers, table, columns] = results.map(r => r.rows);
  const names = triggerNames(block), wanted = block.tables.flatMap(t => PG_ACTOR_OPS.map(op => `${tableName(t)}|${names[op]}`));
  const present = new Map(triggers.map(row => [`${row[0]}|${row[1]}`, row[2]]));
  const missing = [];
  const capture = fn.find(f => f[0] === 'capture' && f[1] === ''), reader = fn.find(f => f[0] === 'ledger' && f[1] === 'after_seq bigint, max_rows integer');
  if (schema.length !== 1) missing.push('schema');
  if (!capture || !reader) missing.push('function');
  if (table.length !== 1 || !columns.length) missing.push('audit-table');
  for (const w of wanted) if (!present.has(w)) missing.push('trigger');
  // A disabled trigger ('D'), or one that fires only under replication ('R'), captures nothing in an ordinary session.
  if ([...present.values()].some(enabled => enabled !== 'O' && enabled !== 'A')) missing.push('trigger-disabled');
  const sha256 = createHash('sha256').update(JSON.stringify({ schema: PG_ACTOR_SCHEMA, rows: [schema, fn, triggers, table, columns] })).digest('hex');
  if (missing.length) return { status: 'absent', sha256, reason: 'capture-absent', missing: [...new Set(missing)] };
  const altered = [];
  if (schema[0][2] !== PG_ACTOR_SCHEMA) altered.push('schema-mark');
  // Exactly the two functions, each SECURITY DEFINER with the pinned search_path; every object owned by a superuser.
  if (fn.length !== 2) altered.push('functions');
  if (fn.some(f => f[2] !== 'true')) altered.push('function-not-security-definer');
  if (fn.some(f => !PINNED_PATH.test(f[3] ?? ''))) altered.push('function-search-path');
  if ([schema[0][0], ...fn.map(f => f[5]), table[0][7]].some(o => typeof o !== 'string' || !o.endsWith(':true'))) altered.push('owner-not-superuser');
  // Exactly our triggers: one per declared table and operation, none on another table.
  if (triggers.length !== wanted.length || triggers.some(row => !wanted.includes(`${row[0]}|${row[1]}`) || row[9] !== 'capture')) altered.push('triggers');
  // The audit table: row-level security on with no policy, a permanent ordinary table, no trigger or rule of its own.
  const [rls, , persistence, kind, ownTriggers, rules, policies] = table[0];
  if (rls !== 'true' || policies !== '0') altered.push('audit-row-security');
  if (persistence !== 'p' || kind !== 'r') altered.push('audit-persistence');
  if (ownTriggers !== '0' || rules !== '0') altered.push('audit-rewritten');
  if (columns.map(c => c[0]).join(',') !== AUDIT_TABLE_COLUMNS) altered.push('audit-columns');
  // Anything else (a privilege granted, a trigger disabled and enabled again, a body replaced, an owner changed): the
  // catalog rows' versions and fields differ from the installation's.
  if (installedSha256 !== null && sha256 !== installedSha256) altered.push('definition-changed');
  return altered.length ? { status: 'altered', sha256, reason: 'capture-altered', altered } : { status: 'intact', sha256 };
}

// Installs on a session of a superuser, in one transaction: the role is checked, the schema's mark read (a foreign schema
// is refused, an earlier marked installation removed), each declared table checked, the objects created and committed;
// then the definitions are read back. Any refusal or error rolls everything back. Returns the record a run keeps as a
// change to the target.
export async function installActorCapture(session, block, { readers = [], at = new Date().toISOString() } = {}) {
  validateActorCapture(block);
  const [role] = await session.query('SELECT current_user::pg_catalog.text, (SELECT r.rolsuper::pg_catalog.text FROM pg_catalog.pg_roles r WHERE r.rolname = current_user)');
  if (role?.rows[0]?.[1] !== 'true') throw new Error('actorCapture: install with a superuser (on a local Supabase stack, supabase_admin): the capture is owned by the install role, which no application role may be or become');
  await session.query('BEGIN');
  let replaced = false;
  try {
    const mark = markOf((await session.query(markSql(block)))[0].rows);
    if (mark === 'foreign') throw new Error(`actorCapture: schema ${schemaOf(block)} exists and is not a capture's; choose another "schema"`);
    replaced = mark === 'marked';
    const checks = await session.query(tablesSql(block));
    block.tables.forEach((_table, i) => {
      const row = checks[i]?.rows[0];
      if (!row) throw new Error(`actorCapture: table ${i + 1} does not exist`);
      if (!['r', 'p'].includes(row[0])) throw new Error(`actorCapture: table ${i + 1} is not an ordinary or partitioned table`);
      if (row[1] !== '1') throw new Error(`actorCapture: table ${i + 1} has no column named as its "key"`);
      if (row[2] !== '1') throw new Error(`actorCapture: table ${i + 1} has no column named as its "actorColumn"`);
      if (row[3] === '0') throw new Error(`actorCapture: table ${i + 1} has no unique index on its "key" alone`);
    });
    for (const sql of [...(replaced ? uninstallSql(block) : []), ...installSql(block, { readers })]) await session.query(sql);
    try { for (const sql of planSql(block)) await session.query(sql); }
    catch (error) { throw Object.assign(new Error(`actorCapture: a declared table's "key" or "actorColumn" cannot be read as the trigger reads it (${error.sqlState ?? error.code ?? 'error'}): check their types`), { sqlState: error.sqlState }); }
    await session.query('COMMIT');
  } catch (error) { try { await session.query('ROLLBACK'); } catch {} throw error; }
  const check = verifyAtInstall(await session.query(verifySql(block)), block);
  if (check.status !== 'intact') { try { await removeActorCapture(session, block); } catch {} throw new Error(`actorCapture: the installation did not verify (${check.reason})`); }
  return installationRecord(block, check.sha256, { at, replaced, installRole: role.rows[0][0] });
}
// Removes a marked installation (its triggers and its schema), in one transaction; refuses a schema that is not marked.
export async function removeActorCapture(session, block) {
  await session.query('BEGIN');
  try {
    const mark = markOf((await session.query(markSql(block)))[0].rows);
    if (mark === 'foreign') throw new Error(`actorCapture: schema ${schemaOf(block)} is not a capture's; nothing was removed`);
    if (mark === 'marked') for (const sql of uninstallSql(block)) await session.query(sql);
    await session.query('COMMIT');
  } catch (error) { try { await session.query('ROLLBACK'); } catch {} throw error; }
  return { schema: PG_ACTOR_SCHEMA, change: 'removed', objects: objectsOf(block) };
}
const objectsOf = block => { const names = triggerNames(block); return { schema: schemaOf(block), table: 'audit', functions: ['capture', 'ledger'], triggers: block.tables.map(t => `${tableName(t)}: ${PG_ACTOR_OPS.map(op => names[op]).join(', ')}`) }; };
// The change to the target, as the run carries it (counts, names and digests; no captured value). auditTable is the
// table the observers' join treats as the capture's own (pg-wal puts it on its ignore list).
export function installationRecord(block, sha256, { at, replaced = false, installRole = null } = {}) {
  return { schema: PG_ACTOR_SCHEMA, change: 'installed', at, testCopy: true, objects: objectsOf(block), auditTable: `${schemaOf(block)}.audit`, installRole, actorSource: block.actor.from,
    principals: Object.keys(block.principals).length, definitionSha256: sha256, replacedEarlier: replaced };
}

// The ledger rows since a sequence number (exclusive), oldest first, through the reader function (so the install role and
// a reader role read the same way, under the caller's snapshot). One row past the limit is asked for, so a read cut
// short is known (parseLedger refuses it). The 32-bit id is the one the WAL carries.
export function ledgerSql(block, { afterSeq = 0, limit = PG_ACTOR_LIMITS.ledgerRows } = {}) {
  if (!Number.isSafeInteger(afterSeq) || afterSeq < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > PG_ACTOR_LIMITS.ledgerRows) throw new Error('actorCapture: invalid ledger bounds');
  return `SELECT l.seq::pg_catalog.text, l.txid::pg_catalog.text, (l.txid % 4294967296)::pg_catalog.text, l.tbl, l.key, l.op, l.rowcount::pg_catalog.text, l.depth::pg_catalog.text, l.row_xmin, l.claims_sub, l.claims_role, l.legacy_sub, l.header_sub, l.set_role, l.session_role, l.app_actor FROM ${quote(schemaOf(block))}.ledger(${afterSeq}, ${limit + 1}) AS l`;
}
// Ledger entries from ledgerSql's rows; a row of another shape, or more rows than the read's limit, is refused (never
// read as an actor, never a partial ledger).
export function parseLedger(rows, { limit = PG_ACTOR_LIMITS.ledgerRows } = {}) {
  if (!Array.isArray(rows)) throw new Error('actorCapture: unreadable ledger');
  if (rows.length > limit) throw Object.assign(new Error('actorCapture: the ledger read was cut at its limit'), { code: 'ledger-truncated' });
  return rows.map(row => {
    if (!Array.isArray(row) || row.length !== AUDIT_COLUMNS.length) throw new Error('actorCapture: unreadable ledger row');
    const [seq, txid, xid32, tbl, key, op, rowcount, depth, rowXmin, claimsSub, claimsRole, legacySub, headerSub, setRole, sessionRole, appActor] = row;
    if (!/^\d+$/.test(seq ?? '') || !/^\d+$/.test(txid ?? '') || !/^\d+$/.test(xid32 ?? '') || typeof tbl !== 'string' || !PG_ACTOR_OPS.includes(op) || !(rowcount === null || rowcount === '0')
      || !/^[1-9]\d{0,2}$/.test(depth ?? '') || !(rowXmin === null || /^\d+$/.test(rowXmin))) throw new Error('actorCapture: unreadable ledger row');
    if (BigInt(txid) % 4294967296n !== BigInt(xid32)) throw new Error('actorCapture: unreadable ledger row');
    return Object.freeze({ seq: Number(seq), txid, xid: xid32, table: tbl, key, op, zeroRow: rowcount === '0', depth: Number(depth), rowXmin, claimsSub, claimsRole, legacySub, headerSub, setRole, sessionRole, appActor });
  });
}

// The default resolver: what the declared source reads in one ledger entry, and the principal it maps to.
//   { actor: <principalId> | unlisted:<digest> | null, via, reason? }
// jwt-claims names a user only as PostgREST binds the claims to a request: the login role is a declared authenticator,
// SET ROLE chose the claims' own role, that role is a declared user role (authenticated by default), and the request's own
// bearer token names the same sub. Claims on any other session (a direct connection that set them, a pooled session that
// kept them, a service role whose JWT carries a sub) read claims-unbound or not-a-user-role; a legacy request.jwt.claim.sub
// or a bearer sub that disagrees (an RPC or trigger that rewrote the claims mid-request) reads claims-conflict.
const unlisted = value => `unlisted:${digest({ schema: PG_ACTOR_SCHEMA, value }).slice(0, 16)}`;
export const effectiveRole = entry => (entry.setRole && entry.setRole !== 'none' ? entry.setRole : entry.sessionRole);
export function sourceValue(entry, block) {
  if (block.actor.from === 'jwt-claims') return entry.claimsSub;
  if (block.actor.from === 'current-user') return effectiveRole(entry);
  return entry.op === 'DELETE' ? null : entry.appActor;
}
export function claimsBinding(entry, block) {
  const authenticators = block.actor.authenticators ?? ['authenticator'], userRoles = block.actor.userRoles ?? ['authenticated'];
  if (!authenticators.includes(entry.sessionRole) || entry.setRole !== entry.claimsRole) return 'claims-unbound';
  if (!userRoles.includes(entry.claimsRole)) return 'not-a-user-role';
  if (entry.legacySub !== null && entry.legacySub !== undefined && entry.legacySub !== entry.claimsSub) return 'claims-conflict';
  // The request's own bearer token names the same sub (SQL in the transaction, an RPC or a trigger, can rewrite the claims).
  if (entry.headerSub !== entry.claimsSub) return 'claims-conflict';
  return null;
}
export function resolveActor(entry, block) {
  if (block.actor.from === 'jwt-claims') { const unbound = claimsBinding(entry, block); if (unbound) return { actor: null, via: block.actor.from, reason: unbound }; }
  const value = sourceValue(entry, block);
  if (value === null || value === undefined || value === '') return { actor: null, via: block.actor.from, reason: 'actor-unattributed' };
  return Object.hasOwn(block.principals, value) ? { actor: block.principals[value], via: block.actor.from } : { actor: unlisted(value), via: block.actor.from };
}
const CAPTURE_STATES = ['intact', 'absent', 'altered', 'unreadable'];
const requireCapture = capture => { if (!CAPTURE_STATES.includes(capture)) throw new Error('actorCapture: the join needs the window\'s capture status (intact, absent, altered or unreadable)'); };

// The join for one change: { xid, table ("schema.table"), key, op } against the ledger. capture: the window's capture
// status (required). resolve: the resolver (resolveActor, or the Supabase rules' one), called per matching entry.
// xid null: a change whose transaction the observer cannot name matches by table, key and operation among the given
// entries, so the caller passes the window's entries only.
export function attributeChange(change, ledger, block, { capture, resolve = resolveActor } = {}) {
  requireCapture(capture);
  if (capture !== 'intact') return { actor: null, reason: 'actor-unattributed', capture };
  if (typeof change.key !== 'string') return { actor: null, reason: 'key-null' };
  const matching = ledger.filter(e => !e.zeroRow && (change.xid === null || e.xid === String(change.xid)) && e.table === change.table && e.key === change.key && e.op === change.op);
  if (!matching.length) return { actor: null, reason: 'actor-unattributed' };
  const resolved = matching.map(e => resolve(e, block));
  if (new Set(resolved.map(r => r.actor)).size !== 1) return { actor: null, reason: 'actor-ambiguous', reasons: [...new Set(resolved.map(r => r.reason).filter(Boolean))] };
  const [first] = resolved;
  return first.actor === null ? { actor: null, reason: first.reason ?? 'actor-unattributed' } : { ...first };
}
// The join for a net change (a snapshot observer's: one event per row whose end state differs, the xmin of its last
// write, none for a deleted row; op the net operation). Every write to the row in the window counts, whatever its
// operation: the row is attributed only when all of them resolve to one actor, and, with an xid, when the last write is
// among them (matched on the written row's own xmin, so a write inside a savepoint matches too). A row two actors wrote in
// the window is actor-ambiguous: naming the last writer alone would let "ana wrote no globex row" pass when ana wrote it
// and its owner wrote it again before the end mark. The captured writes must account for the net operation (NC9 item 2,
// PR518 review MAJOR 1): a deleted row needs its last captured write (by sequence) to be a DELETE, and an inserted row a
// captured INSERT, otherwise the row reads actor-unattributed. entries: the window's ledger entries only.
export function attributeNetChange(change, entries, block, { capture, resolve = resolveActor } = {}) {
  requireCapture(capture);
  if (capture !== 'intact') return { actor: null, reason: 'actor-unattributed', capture };
  if (typeof change.key !== 'string') return { actor: null, reason: 'key-null' };
  const writes = entries.filter(e => !e.zeroRow && e.table === change.table && e.key === change.key);
  if (!writes.length || (change.xid !== null && !writes.some(e => e.rowXmin === String(change.xid) || e.xid === String(change.xid)))) return { actor: null, reason: 'actor-unattributed' };
  const last = writes.reduce((a, b) => (b.seq > a.seq ? b : a));
  if ((change.op === 'DELETE' && last.op !== 'DELETE') || (change.op === 'INSERT' && !writes.some(e => e.op === 'INSERT'))) return { actor: null, reason: 'actor-unattributed' };
  const resolved = writes.map(e => resolve(e, block));
  if (new Set(resolved.map(r => r.actor)).size !== 1) return { actor: null, reason: 'actor-ambiguous', reasons: [...new Set(resolved.map(r => r.reason).filter(Boolean))] };
  return resolved[0].actor === null ? { actor: null, reason: resolved[0].reason ?? 'actor-unattributed' } : { ...resolved[0] };
}
// The window's entries from two marks' ledger reads: the rows the end mark's read holds that the start mark's did not.
// Under a snapshot read (pg-snapshot's marks) that is exactly what committed between the two snapshots; a read outside
// one (a short session) is what had committed by then.
export function windowLedger(startEntries, endEntries) {
  const seen = new Set(startEntries.map(e => e.seq));
  return endEntries.filter(e => !seen.has(e.seq));
}
// The operation a Postgres observer's event names ('insert', 'update', 'delete'), as the ledger writes it.
export const ledgerOp = operation => ({ insert: 'INSERT', update: 'UPDATE', delete: 'DELETE' })[operation] ?? null;
