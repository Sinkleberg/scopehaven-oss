// Catalog fingerprint (N13, lead-queue item 3): a sha256 over the target database's catalog, read at each mark by
// pg-snapshot, pg-wal and the SQLite observers, so that a window whose schema changed during the run never reads as a
// clean one, and a retest across a migration can say so. One reader for every database observer; pure apart from the SQL
// it builds, the session it opens and the rows it reads.
//
// What it covers (Postgres). Every schema except the system ones (pg_catalog, information_schema, pg_toast and the
// temporary schemas) and the schemas a platform's checked-in list names whole (./ignore-lists/; never one holding a
// declared table or queue). In them:
//   schema          owner and grants
//   relation        tables, partitioned tables, views, materialized views, foreign tables and sequences: kind, persistence,
//                   row-level security and FORCE, options, grants, owner, replica identity, access method, partition key,
//                   inheritance parents, a foreign table's server and options, and for a partitioned table the set of its
//                   partitions' grants, owners, row-level security and replica identity
//   column          position among the live columns, type, NOT NULL, default, generated, identity, collation, grants
//   constraint      table and domain constraints as the server prints them, with their deferral and validation (a clone a
//                   partition attach makes on a referencing table is its parent's)
//   index           as the server prints it, and whether it is valid
//   policy          command, permissive or restrictive, roles, USING and WITH CHECK, on any relation, partitions included
//   trigger         as the server prints it, and its enabled state; a partition's clone of its parent's trigger counts only
//                   when its enabled state differs from the parent's, and an internal one (a foreign key's) only when it
//                   is not enabled
//   rule            as the server prints it (a view's definition is its _RETURN rule), and its enabled state
//   function        functions and procedures as pg_get_functiondef prints them (a sha256 taken in the server), owner and grants; an
//                   aggregate by its transition, final and combine functions, state type and initial value
//   type            enum labels in order, a domain's base type, NOT NULL and default, a range's subtype, a composite's fields
//   extension       name, version and schema
//   event-trigger   event, function, enabled state and tags
//   foreign-server  wrapper, type, version, options, grants and owner (an option whose name reads as a secret by its name
//                   only; user mappings, which can hold passwords, are never read)
//   publication     its operations and the tables named in it
//   default-acl     the privileges new objects get
//   operator, cast  those an application or migration made
// An extension's own members are read like any other object: their definitions are fixed by the extension's version, so
// only access to them (grants, owner, SECURITY DEFINER, settings) or the extension's update changes them. Partitions are
// left out as relations, so a platform's daily partitions are not a migration; what a partition holds apart from the
// others (its grants and column grants, row-level security, replica identity, policies, rules and trigger state) still
// counts (above).
//
// Two digests per kind. The definition digest covers names and definitions only (no oids, no row versions): two databases
// built by the same migrations read the same, and it is what a run records and a comparison reads. The instance digest
// adds each catalog row's version (xmin; a relation's oid), so a change made and changed back between a window's two
// marks (a trigger disabled and enabled again, a function replaced and restored, a policy changed and restored) still
// shows. Some rows are versioned apart (the versions statement): a relation's own row, because TRUNCATE, VACUUM FULL,
// CLUSTER and REFRESH MATERIALIZED VIEW give it a new row version with a new file node (a rewrite, not a schema change;
// observed live), so one whose row moved while its file node did not (row-level security switched off and on, a grant
// revoked and restored) has changed; and the partition clones and internal triggers the kinds leave out, whose rows move
// only when their enabled state does. A materialized view's own row is not versioned: REFRESH ... CONCURRENTLY moves it.
//
// The read. Printing a view, a rule or a policy takes a share lock on each relation it names, so the catalog is read on
// its own short session (openPgCatalogSession), never inside a mark's transaction: it waits at most lockTimeoutMs for a
// lock, and a read that fails for any reason has no fingerprint (catalog-unreadable), never a failed mark or a lost slot.
// Each mark reads it twice, before and after the mark's own reads (bracketCatalog): a catalog that changed in between is a
// change. Definitions are printed under pinned settings (search_path = pg_catalog, so names are schema-qualified) and
// reduced to sha256 digests in the server: no definition leaves the database.
//
// SQLite: every sqlite_master row but SQLite's own (type, name, table and the SQL it holds), user_version and
// application_id, without a platform's tables (Litestream's) and their indexes and triggers; its instance is the schema
// cookie (schema_version), which every schema change bumps.
//
// The rule (catalogReasons). A window reads schema-drift when either mark's definition digest differs from the run's
// baseline (read at the observer's start), when the instance changed between the window's own two marks, or when a mark's
// or the baseline's bracket saw a change; it reads catalog-unreadable when the baseline or either mark has no fingerprint.
// Both make the window partial and keep its events, so a fail stays a fail.
// What it does not see: role attributes and memberships (BYPASSRLS, superuser; they are cluster-wide); session settings
// (session_replication_role = replica stops triggers without a catalog change); an object created and dropped inside one
// window, or dropped and recreated the same (an index has no version of its own); a relation's own row changed and changed
// back in the same window as a rewrite of that relation, and a materialized view's; a definition whose printed text does
// not change (a C function's library replaced on disk); a publication's schema membership (PostgreSQL 15), user mappings,
// access methods, large objects and other databases on the server.
// Lasting reads with no schema change by the application: a partitioned table whose partitions differ from one another
// (a grant, row-level security) reads a change when a partition with a combination of its own is added or dropped, and
// when its first partition is made; an extension that makes tables as it runs (TimescaleDB's chunks) reads every new one
// as a change. A partition's owner is not in its parent's set (a partition made by another role is not a change), so a
// partition's owner changed reads in its own window only. And the catalog's own session is one more connection per mark:
// a role at its connection limit cannot read it (catalog-unreadable at a mark; a start refused).
// One window can read schema-drift without a schema change: VACUUM FULL or CLUSTER on a table with a column added with a
// default since its last rewrite (the rewrite writes the column's catalog row), REINDEX CONCURRENTLY, and ANALYZE on an
// inheritance parent left without children. A server major version can print some definitions differently: across such an
// upgrade the fingerprint reads changed. SQLite: the cookie is the whole database's, so the first ANALYZE (it creates
// sqlite_stat1), VACUUM and a platform's table created during the run also move it, and the window they fall in reads
// schema-drift; later windows do not, since the definitions leave those objects out.
import { digest } from '../../src/domain.mjs';

export const CATALOG_SCHEMA = 'scopehaven-catalog/1';
export const SCHEMA_DRIFT = 'schema-drift';
export const CATALOG_UNREADABLE = 'catalog-unreadable';
export const CATALOG_KINDS = Object.freeze({
  postgres: Object.freeze(['schema', 'relation', 'column', 'constraint', 'index', 'policy', 'trigger', 'rule', 'function', 'type', 'extension', 'event-trigger',
    'foreign-server', 'publication', 'default-acl', 'operator', 'cast']),
  sqlite: Object.freeze(['table', 'index', 'view', 'trigger', 'pragma']) });
// versions: the catalog rows a read versions apart (relations, and triggers kept by their enabled state), at most; past it
// the read has no fingerprint (catalog-unreadable). lockTimeoutMs: the catalog's own session waits at most this long for a
// lock (printing a view, rule or policy locks the relations it names); past it the read has no fingerprint either.
export const CATALOG_LIMITS = Object.freeze({ versions: 50000, lockTimeoutMs: 1000 });

const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const literal = name => { if (!IDENT.test(name)) throw new Error(`Unsupported SQL identifier "${String(name).slice(0, 64)}".`); return `'${name}'`; };
const HEX64 = /^[0-9a-f]{64}$/;

// The platform's own objects the fingerprint leaves out, from a resolved ignore list (./ignore-lists/ignore-list.mjs): on
// Postgres the schemas it names whole (a platform table's grants, policies and triggers are the application's concern, so
// a table entry stays in); on SQLite its tables (SQLite has no grants or policies, and Litestream creates its tables when
// it starts). A profile's own entries name application tables and stay in. A platform entry that covers a declared table
// or queue is not applied: a schema-wide one is dropped whole, a table one for that table.
export function catalogExclusions(ignoreList, { declared = [], queues = [], engine = 'postgres' } = {}) {
  const fold = n => (engine === 'sqlite' ? n.replace(/[A-Z]/g, c => c.toLowerCase()) : n);
  const watched = [...declared, ...queues];
  const covers = e => watched.some(w => w.schema === e.schema && (e.table === null || fold(w.table) === fold(e.table)));
  const kept = (ignoreList?.platformEntries ?? []).filter(e => !covers(e));
  return Object.freeze({ schemas: Object.freeze(kept.filter(e => e.table === null).map(e => e.schema).sort()),
    tables: Object.freeze(engine === 'sqlite' ? kept.filter(e => e.table !== null).map(e => `${e.schema}.${e.table}`).sort() : []) });
}

// The two statements a Postgres catalog read runs (marked /* sh:dbcatalog */ and /* sh:dbversions */), on the catalog's own
// session (openPgCatalogSession). Each kind is one row: [kind, objects, definition sha256, instance sha256], in
// CATALOG_KINDS order; the versions are [id, xmin, file node]: each relation's own catalog row by its oid (a materialized
// view's is left out: REFRESH ... CONCURRENTLY moves it without a new file), and each trigger the kinds leave out as a
// definition but whose enabled state matters (a partition's clone, an internal one), as "t" and its oid with no file node.
export function pgCatalogSql({ schemas = [] } = {}) {
  const sha = text => `pg_catalog.encode(pg_catalog.sha256(pg_catalog.textsend(${text})), 'hex')`;
  const user = oid => `pg_catalog.pg_get_userbyid(${oid})`;
  const qname = (nsp, rel) => `pg_catalog.quote_ident(${nsp}) || '.' || pg_catalog.quote_ident(${rel})`;
  // Options as text, a key that reads as a secret (a password, a token, an API key) by its name only.
  const options = col => `(SELECT pg_catalog.json_agg(CASE WHEN pg_catalog.split_part(o, '=', 1) ~* '(pass|secret|token|key|credential|auth)' THEN pg_catalog.split_part(o, '=', 1) ELSE o END ORDER BY o COLLATE "C") FROM pg_catalog.unnest(${col}) o)::pg_catalog.text`;
  const outSchemas = schemas.length ? ` AND n.nspname NOT IN (${schemas.map(literal).join(', ')})` : '';
  // An ordered JSON array of a subquery's text values (x), or null when it has none.
  const agg = query => `(SELECT pg_catalog.json_agg(s.x ORDER BY s.x COLLATE "C") FROM (${query}) s)::pg_catalog.text`;
  const scope = `nsp AS (SELECT n.oid, n.xmin, n.nspname, n.nspowner, n.nspacl FROM pg_catalog.pg_namespace n
      WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') AND n.nspname !~ '^pg_(toast_)?temp_'${outSchemas}),
    relall AS (SELECT c.oid, c.xmin, c.relfilenode, c.relkind, c.relpersistence, c.relrowsecurity, c.relforcerowsecurity, c.reloptions, c.relacl, c.relowner, c.relispartition,
        c.relreplident, c.relam, ${qname('n.nspname', 'c.relname')} AS qname
      FROM pg_catalog.pg_class c JOIN nsp n ON n.oid = c.relnamespace WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')),
    rel AS (SELECT * FROM relall WHERE NOT relispartition),
    own AS (SELECT * FROM rel),
    trg AS (SELECT g.*, g.xmin, r.qname, (SELECT p.tgenabled FROM pg_catalog.pg_trigger p WHERE p.oid = g.tgparentid) AS parentenabled
      FROM pg_catalog.pg_trigger g JOIN relall r ON r.oid = g.tgrelid)`;
  const kinds = CATALOG_KINDS.postgres;
  const catalog = `/* sh:dbcatalog */ WITH ${scope},
    items(kind, name, def, token) AS (
      SELECT 'schema', pg_catalog.quote_ident(n.nspname), pg_catalog.json_build_array(${user('n.nspowner')}, n.nspacl::pg_catalog.text)::pg_catalog.text, n.xmin::pg_catalog.text FROM nsp n
      UNION ALL
      SELECT 'relation', r.qname, pg_catalog.json_build_array(r.relkind, r.relpersistence, r.relrowsecurity, r.relforcerowsecurity, r.reloptions::pg_catalog.text, r.relacl::pg_catalog.text, ${user('r.relowner')}, r.relreplident,
          (SELECT a.amname FROM pg_catalog.pg_am a WHERE a.oid = r.relam), CASE WHEN r.relkind = 'p' THEN pg_catalog.pg_get_partkeydef(r.oid) END,
          ${agg(`SELECT ${qname('pn.nspname', 'pc.relname')} AS x FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class pc ON pc.oid = i.inhparent JOIN pg_catalog.pg_namespace pn ON pn.oid = pc.relnamespace WHERE i.inhrelid = r.oid`)},
          (SELECT pg_catalog.json_build_array(fs.srvname, ${options('ft.ftoptions')}) FROM pg_catalog.pg_foreign_table ft JOIN pg_catalog.pg_foreign_server fs ON fs.oid = ft.ftserver WHERE ft.ftrelid = r.oid)::pg_catalog.text,
          -- A partitioned table: the set of its partitions' (at every level) grants, column grants, row-level security and
          -- replica identity, so a partition changed apart from the others stays a change while a new partition made like
          -- the others is not one (whichever role made it).
          CASE WHEN r.relkind = 'p' THEN ${agg(`WITH RECURSIVE down(oid) AS (SELECT i.inhrelid FROM pg_catalog.pg_inherits i WHERE i.inhparent = r.oid UNION SELECT i.inhrelid FROM pg_catalog.pg_inherits i JOIN down ON i.inhparent = down.oid)
            SELECT DISTINCT pg_catalog.json_build_array(pc.relacl::pg_catalog.text, pc.relrowsecurity, pc.relforcerowsecurity, pc.relreplident,
              (SELECT pg_catalog.json_agg(pg_catalog.json_build_array(a.attname, a.attacl::pg_catalog.text) ORDER BY a.attname) FROM pg_catalog.pg_attribute a WHERE a.attrelid = pc.oid AND a.attnum > 0 AND NOT a.attisdropped AND a.attacl IS NOT NULL))::pg_catalog.text AS x
            FROM down JOIN pg_catalog.pg_class pc ON pc.oid = down.oid`)} END)::pg_catalog.text,
        r.oid::pg_catalog.text FROM rel r
      UNION ALL
      SELECT 'column', r.qname || '.' || pg_catalog.quote_ident(a.attname),
        pg_catalog.json_build_array(pg_catalog.row_number() OVER (PARTITION BY a.attrelid ORDER BY a.attnum), pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnotnull,
          pg_catalog.pg_get_expr(ad.adbin, ad.adrelid), a.attgenerated, a.attidentity, CASE WHEN a.attcollation <> ty.typcollation THEN co.collname END, a.attacl::pg_catalog.text)::pg_catalog.text, a.xmin::pg_catalog.text
      FROM own r JOIN pg_catalog.pg_attribute a ON a.attrelid = r.oid AND a.attnum > 0 AND NOT a.attisdropped JOIN pg_catalog.pg_type ty ON ty.oid = a.atttypid
        LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum LEFT JOIN pg_catalog.pg_collation co ON co.oid = a.attcollation
      UNION ALL
      -- A constraint a partition attach clones onto a referencing table (conparentid) is its parent's.
      SELECT 'constraint', COALESCE(r.qname, ${qname('tn.nspname', 't.typname')}) || '.' || pg_catalog.quote_ident(k.conname),
        pg_catalog.json_build_array(k.contype, pg_catalog.pg_get_constraintdef(k.oid), k.condeferrable, k.condeferred, k.convalidated)::pg_catalog.text, k.xmin::pg_catalog.text
      FROM pg_catalog.pg_constraint k LEFT JOIN own r ON r.oid = k.conrelid LEFT JOIN pg_catalog.pg_type t ON t.oid = k.contypid LEFT JOIN nsp tn ON tn.oid = t.typnamespace
      WHERE k.conparentid = 0 AND ((k.conrelid <> 0 AND r.oid IS NOT NULL) OR (k.conrelid = 0 AND k.contypid <> 0 AND tn.oid IS NOT NULL))
      UNION ALL
      SELECT 'index', r.qname || '.' || pg_catalog.quote_ident(ic.relname), pg_catalog.json_build_array(pg_catalog.pg_get_indexdef(x.indexrelid), x.indisvalid)::pg_catalog.text, ''
      FROM pg_catalog.pg_index x JOIN own r ON r.oid = x.indrelid JOIN pg_catalog.pg_class ic ON ic.oid = x.indexrelid
      UNION ALL
      SELECT 'policy', r.qname || '.' || pg_catalog.quote_ident(p.polname),
        pg_catalog.json_build_array(p.polcmd, p.polpermissive, ${agg(`SELECT CASE WHEN g = 0 THEN 'public' ELSE ${user('g')}::pg_catalog.text END AS x FROM pg_catalog.unnest(p.polroles) g`)},
          pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid))::pg_catalog.text, p.xmin::pg_catalog.text
      FROM pg_catalog.pg_policy p JOIN relall r ON r.oid = p.polrelid
      UNION ALL
      -- A trigger of its own (not internal, not a partition's clone), on any relation. A clone whose enabled state differs from
      -- its parent's, and an internal one that is not enabled (the foreign keys' triggers), are kept by that state.
      SELECT 'trigger', g.qname || '.' || pg_catalog.quote_ident(g.tgname), pg_catalog.json_build_array(pg_catalog.pg_get_triggerdef(g.oid), g.tgenabled)::pg_catalog.text, g.xmin::pg_catalog.text
      FROM trg g WHERE NOT g.tgisinternal AND g.tgparentid = 0
      UNION ALL
      SELECT 'trigger', g.qname || '.' || pg_catalog.quote_ident(g.tgname), pg_catalog.json_build_array('clone', g.tgenabled)::pg_catalog.text, ''
      FROM trg g WHERE g.tgparentid <> 0 AND g.tgenabled IS DISTINCT FROM g.parentenabled
      UNION ALL
      SELECT 'trigger', g.qname || '.' || COALESCE((SELECT pg_catalog.quote_ident(k.conname) FROM pg_catalog.pg_constraint k WHERE k.oid = g.tgconstraint), '') || '.' || g.tgfoid::pg_catalog.regproc::pg_catalog.text || '.' || g.tgtype::pg_catalog.text,
        pg_catalog.json_build_array('internal', g.tgenabled)::pg_catalog.text, ''
      FROM trg g WHERE g.tgisinternal AND g.tgparentid = 0 AND g.tgenabled <> 'O'
      UNION ALL
      SELECT 'rule', r.qname || '.' || pg_catalog.quote_ident(w.rulename), pg_catalog.json_build_array(pg_catalog.pg_get_ruledef(w.oid), w.ev_enabled)::pg_catalog.text, w.xmin::pg_catalog.text
      FROM pg_catalog.pg_rewrite w JOIN relall r ON r.oid = w.ev_class
      UNION ALL
      SELECT 'function', ${qname('n.nspname', 'p.proname')} || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')',
        pg_catalog.json_build_array(p.prokind, ${user('p.proowner')}, p.proacl::pg_catalog.text,
          CASE WHEN p.prokind = 'a' THEN (SELECT pg_catalog.json_build_array(ag.aggtransfn::pg_catalog.regproc::pg_catalog.text, ag.aggfinalfn::pg_catalog.regproc::pg_catalog.text, ag.aggcombinefn::pg_catalog.regproc::pg_catalog.text,
            pg_catalog.format_type(ag.aggtranstype, NULL), ag.agginitval, pg_catalog.pg_get_function_result(p.oid))::pg_catalog.text FROM pg_catalog.pg_aggregate ag WHERE ag.aggfnoid = p.oid)
            ELSE ${sha('pg_catalog.pg_get_functiondef(p.oid)')} END)::pg_catalog.text, p.xmin::pg_catalog.text
      FROM pg_catalog.pg_proc p JOIN nsp n ON n.oid = p.pronamespace
      UNION ALL
      SELECT 'type', ${qname('n.nspname', 't.typname')},
        pg_catalog.json_build_array(t.typtype, ${user('t.typowner')}, t.typacl::pg_catalog.text,
          CASE t.typtype WHEN 'e' THEN (SELECT pg_catalog.json_agg(e.enumlabel ORDER BY e.enumsortorder) FROM pg_catalog.pg_enum e WHERE e.enumtypid = t.oid)::pg_catalog.text
            WHEN 'd' THEN pg_catalog.json_build_array(pg_catalog.format_type(t.typbasetype, t.typtypmod), t.typnotnull, t.typdefault)::pg_catalog.text
            WHEN 'r' THEN (SELECT pg_catalog.format_type(g.rngsubtype, NULL) FROM pg_catalog.pg_range g WHERE g.rngtypid = t.oid)
            WHEN 'c' THEN (SELECT pg_catalog.json_agg(pg_catalog.json_build_array(a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod)) ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
              WHERE a.attrelid = t.typrelid AND a.attnum > 0 AND NOT a.attisdropped)::pg_catalog.text END)::pg_catalog.text, t.xmin::pg_catalog.text
      FROM pg_catalog.pg_type t JOIN nsp n ON n.oid = t.typnamespace
      WHERE t.typtype IN ('e', 'd', 'r', 'c') AND (t.typtype <> 'c' OR (SELECT c.relkind FROM pg_catalog.pg_class c WHERE c.oid = t.typrelid) = 'c')
      UNION ALL
      SELECT 'extension', pg_catalog.quote_ident(e.extname), pg_catalog.json_build_array(e.extversion, (SELECT x.nspname FROM pg_catalog.pg_namespace x WHERE x.oid = e.extnamespace))::pg_catalog.text, e.xmin::pg_catalog.text
      FROM pg_catalog.pg_extension e
      UNION ALL
      SELECT 'event-trigger', pg_catalog.quote_ident(v.evtname), pg_catalog.json_build_array(v.evtevent, v.evtfoid::pg_catalog.regproc::pg_catalog.text, v.evtenabled, v.evttags::pg_catalog.text)::pg_catalog.text, v.xmin::pg_catalog.text
      FROM pg_catalog.pg_event_trigger v
      UNION ALL
      -- A foreign server's wrapper, options and grants (a user mapping, which may hold a password, is never read).
      SELECT 'foreign-server', pg_catalog.quote_ident(s.srvname), pg_catalog.json_build_array(w.fdwname, s.srvtype, s.srvversion, ${options('s.srvoptions')}, s.srvacl::pg_catalog.text, ${user('s.srvowner')})::pg_catalog.text, s.xmin::pg_catalog.text
      FROM pg_catalog.pg_foreign_server s JOIN pg_catalog.pg_foreign_data_wrapper w ON w.oid = s.srvfdw
      UNION ALL
      -- A publication's operations and the tables named in it (what logical replication, Supabase Realtime among them, sends).
      SELECT 'publication', pg_catalog.quote_ident(p.pubname), pg_catalog.json_build_array(p.puballtables, p.pubinsert, p.pubupdate, p.pubdelete, p.pubtruncate, ${user('p.pubowner')},
          ${agg(`SELECT ${qname('pn.nspname', 'pc.relname')} AS x FROM pg_catalog.pg_publication_rel pr JOIN pg_catalog.pg_class pc ON pc.oid = pr.prrelid JOIN pg_catalog.pg_namespace pn ON pn.oid = pc.relnamespace WHERE pr.prpubid = p.oid`)})::pg_catalog.text, p.xmin::pg_catalog.text
      FROM pg_catalog.pg_publication p
      UNION ALL
      SELECT 'default-acl', ${user('d.defaclrole')} || '.' || COALESCE((SELECT x.nspname FROM pg_catalog.pg_namespace x WHERE x.oid = d.defaclnamespace), '') || '.' || d.defaclobjtype::pg_catalog.text,
        pg_catalog.json_build_array(d.defaclacl::pg_catalog.text)::pg_catalog.text, d.xmin::pg_catalog.text
      FROM pg_catalog.pg_default_acl d
      UNION ALL
      SELECT 'operator', pg_catalog.quote_ident(n.nspname) || '.' || o.oprname || '(' || pg_catalog.format_type(o.oprleft, NULL) || ',' || pg_catalog.format_type(o.oprright, NULL) || ')',
        pg_catalog.json_build_array(o.oprcode::pg_catalog.regproc::pg_catalog.text, ${user('o.oprowner')})::pg_catalog.text, o.xmin::pg_catalog.text
      FROM pg_catalog.pg_operator o JOIN nsp n ON n.oid = o.oprnamespace
      UNION ALL
      SELECT 'cast', pg_catalog.format_type(c.castsource, NULL) || '->' || pg_catalog.format_type(c.casttarget, NULL),
        pg_catalog.json_build_array(CASE WHEN c.castfunc <> 0 THEN c.castfunc::pg_catalog.regprocedure::pg_catalog.text END, c.castcontext, c.castmethod)::pg_catalog.text, c.xmin::pg_catalog.text
      FROM pg_catalog.pg_cast c WHERE c.oid >= 16384),
    lines AS (SELECT kind, name, ${sha('pg_catalog.json_build_array(name, def)::pg_catalog.text')} AS line, token FROM items)
    SELECT k.kind, pg_catalog.count(l.kind)::pg_catalog.text,
      ${sha(`COALESCE(pg_catalog.string_agg(l.line, '' ORDER BY l.name COLLATE "C", l.line), '')`)},
      ${sha(`COALESCE(pg_catalog.string_agg(l.line || ':' || l.token || ';', '' ORDER BY l.name COLLATE "C", l.line), '')`)}
    FROM (VALUES ${kinds.map((k, i) => `(${i}, '${k}')`).join(', ')}) AS k(i, kind) LEFT JOIN lines l ON l.kind = k.kind GROUP BY k.i, k.kind ORDER BY k.i`;
  const versions = `/* sh:dbversions */ WITH ${scope}
    SELECT v.id, v.xmin, v.node FROM (SELECT r.oid::pg_catalog.text AS id, r.xmin::pg_catalog.text AS xmin, r.relfilenode::pg_catalog.text AS node FROM relall r WHERE r.relkind <> 'm'
      UNION ALL SELECT 't' || g.oid::pg_catalog.text, g.xmin::pg_catalog.text, '' FROM trg g WHERE g.tgisinternal OR g.tgparentid <> 0) v
    ORDER BY v.id LIMIT ${CATALOG_LIMITS.versions + 1}`;
  return Object.freeze({ catalog, versions, rows: kinds.length + CATALOG_LIMITS.versions + 1 });
}

// A Postgres mark's fingerprint from the two results, or { ok: false, reason } when they do not read as one.
export function pgCatalogOf(catalogResult, versionsResult) {
  const kinds = CATALOG_KINDS.postgres, rows = catalogResult?.rows ?? [], versions = versionsResult?.rows ?? [];
  if (rows.length !== kinds.length || !rows.every((r, i) => r.length === 4 && r[0] === kinds[i] && /^\d{1,9}$/.test(r[1]) && HEX64.test(r[2]) && HEX64.test(r[3]))) return { ok: false, reason: CATALOG_UNREADABLE };
  if (versions.length > CATALOG_LIMITS.versions || !versions.every(r => r.length === 3 && /^t?\d{1,10}$/.test(r[0]) && /^\d{1,10}$/.test(r[1]) && /^\d{0,10}$/.test(r[2]))) return { ok: false, reason: CATALOG_UNREADABLE };
  return fingerprint('postgres', rows.map(([kind, n, def, inst]) => ({ kind, objects: Number(n), sha256: def, instance: inst })), new Map(versions.map(([oid, xmin, node]) => [oid, `${xmin}/${node}`])));
}

// The catalog's own short session, apart from the mark's: printing a view, a rule or a policy takes a share lock on every
// relation it names, which must neither hold the application back (until a mark's transaction ends) nor wait behind it.
// The session pins the settings the printed definitions depend on, waits for a lock at most lockTimeoutMs and a statement
// at most statementTimeoutMs; any error, a lock wait past the limit included, reads as no fingerprint (catalog-unreadable),
// never as a failed mark. JIT is off: a catalog read never gains from it, and a partitioned table's estimated set can push
// the statement past jit_above_cost (2.4 s instead of 13 ms on PostgreSQL 15 with 200 partitions, review round 3). connect
// and options are the observer's own (./pg-wire.mjs pgConnect and its login).
export const PG_CATALOG_SETTINGS = Object.freeze(['SET search_path = pg_catalog', 'SET quote_all_identifiers = off', 'SET standard_conforming_strings = on', "SET DateStyle = 'ISO, MDY'",
  "SET TimeZone = 'UTC'", "SET IntervalStyle = 'postgres'", 'SET extra_float_digits = 1', "SET bytea_output = 'hex'", "SET lc_monetary = 'C'", 'SET jit = off']);
const UNREADABLE = Object.freeze({ ok: false, reason: CATALOG_UNREADABLE });
export async function openPgCatalogSession(connect, options, sql, { statementTimeoutMs }) {
  const queryTimeoutMs = statementTimeoutMs + 1000;
  let client = null;
  try {
    client = await connect(options);
    await client.query([...PG_CATALOG_SETTINGS, `SET lock_timeout = ${Math.min(CATALOG_LIMITS.lockTimeoutMs, statementTimeoutMs)}`, `SET statement_timeout = ${statementTimeoutMs}`].join('; '), { queryTimeoutMs });
  } catch { client?.close(); client = null; }
  return {
    async read() {
      if (!client) return UNREADABLE;
      try {
        const [kinds] = await client.query(sql.catalog, { queryTimeoutMs, maxRows: CATALOG_KINDS.postgres.length + 1 });
        const [versions] = await client.query(sql.versions, { queryTimeoutMs, maxRows: CATALOG_LIMITS.versions + 1 });
        return pgCatalogOf(kinds, versions);
      } catch { return UNREADABLE; }
    },
    close() { client?.close(); client = null; },
  };
}
// The run's baseline (an observer's start): the latest read, tried again a few times when it does not read (a lock held past
// the wait, a connection refused), so a passing moment does not leave the whole run without one. An observer whose baseline
// still does not read refuses its start (BASELINE_REFUSED): no window could be judged against it.
export const CATALOG_BASELINE = Object.freeze({ attempts: 3, pauseMs: 250 });
export const BASELINE_REFUSED = 'catalog-unreadable at start: the database catalog fingerprint could not be read (a lock held on a relation a view or policy names, a connection limit, or a role that cannot read the catalog), so no window could be judged against it.';
export async function readPgCatalogBaseline(session, { attempts = CATALOG_BASELINE.attempts, pauseMs = CATALOG_BASELINE.pauseMs } = {}) {
  let fp = UNREADABLE;
  for (let i = 0; i < attempts && !fp.ok; i++) { if (i) await new Promise(resolve => setTimeout(resolve, pauseMs)); fp = await session.read(); }
  return fp;
}
// A mark's fingerprint from the two reads that bracket it: the first, marked unstable when the second differs from it by the
// rule (catalogReasons), so a catalog changed while the mark was read is a change.
export function bracketCatalog(first, second) {
  if (!first?.ok) return first ?? UNREADABLE;
  if (!second?.ok) return second;
  return Object.freeze({ ...first, stable: catalogReasons(first, first, second).length === 0 });
}

// A SQLite mark's fingerprint, read from the private copy the mark reads its tables from (./sqlite.mjs). SQLite's own
// objects (sqlite_ names: its sequence and statistics tables, the automatic indexes of UNIQUE and PRIMARY KEY constraints,
// which the table's SQL already states) and a platform's tables with their indexes and triggers are left out.
export function sqliteCatalogOf(db, { tables = [] } = {}) {
  try {
    const fold = n => n.replace(/[A-Z]/g, c => c.toLowerCase()), out = new Set(tables.map(t => fold(t.split('.').pop())));
    const rows = db.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY type, name").all()
      .filter(r => !out.has(fold(String(r.tbl_name))));
    const pragma = (name) => { const v = db.prepare(`PRAGMA ${name}`).get()?.[name]; if (!Number.isSafeInteger(Number(v))) throw new Error('pragma-unreadable'); return Number(v); };
    const byKind = Object.fromEntries(CATALOG_KINDS.sqlite.map(k => [k, []]));
    for (const r of rows) { if (!Object.hasOwn(byKind, r.type) || r.type === 'pragma') throw new Error('unknown-object'); byKind[r.type].push([String(r.name), String(r.tbl_name), r.sql === null ? null : String(r.sql)]); }
    byKind.pragma = [['user_version', pragma('user_version')], ['application_id', pragma('application_id')]];
    const cookie = String(pragma('schema_version'));
    // The cookie is in every kind's instance: SQLite keeps no row versions, and a relation needs none apart.
    return fingerprint('sqlite', CATALOG_KINDS.sqlite.map(kind => ({ kind, objects: byKind[kind].length, sha256: digest(byKind[kind]), instance: digest([byKind[kind], cookie]) })), new Map());
  } catch { return { ok: false, reason: CATALOG_UNREADABLE }; }
}

const fingerprint = (engine, kinds, versions) => Object.freeze({ ok: true, engine, kinds: Object.freeze(kinds), versions,
  sha256: digest({ schema: CATALOG_SCHEMA, engine, kinds: kinds.map(k => [k.kind, k.objects, k.sha256]) }),
  instance: digest(kinds.map(k => [k.kind, k.instance])) });

// The reasons a window reads, from the run's baseline and the window's two marks (each a fingerprint, or null when the
// mark had none): the definition against the baseline at both marks, the instance and every relation's version between
// the window's own marks (a version whose file node moved is a rewrite, not a change).
export function catalogReasons(baseline, before, after) {
  if (!baseline?.ok || !before?.ok || !after?.ok) return [CATALOG_UNREADABLE];
  // A catalog that changed while a mark (or the baseline) was read: the bracket's two reads differ (bracketCatalog).
  if (baseline.stable === false || before.stable === false || after.stable === false) return [SCHEMA_DRIFT];
  if (before.sha256 !== baseline.sha256 || after.sha256 !== baseline.sha256 || before.instance !== after.instance) return [SCHEMA_DRIFT];
  // A relation at both marks whose catalog row moved under the same file node: DDL (a trigger kept by its enabled state has
  // no file node, so any move of its row is a change). A relation added or dropped already moved the relation kind's
  // instance (its oid); a trigger added with a new partition is not a change.
  for (const [oid, version] of after.versions) {
    const was = before.versions.get(oid);
    if (was !== undefined && was !== version && was.split('/')[1] === version.split('/')[1]) return [SCHEMA_DRIFT];
  }
  return [];
}

// The record a run keeps for one observer (catalog() on the observer): the baseline's digest and per-kind counts and
// digests, the last mark's digest, and changedDuringRun: a mark's definitions differed from the baseline, or a window read
// schema-drift for any reason (a change made and changed back included). Names, definitions, oids and row versions never
// leave the database; only counts and sha256 digests are kept.
export function catalogRecord({ engine, baseline, latest, drifted, excluded }) {
  const kinds = fp => Object.fromEntries(fp.kinds.map(k => [k.kind, { objects: k.objects, sha256: k.sha256 }]));
  return Object.freeze({ schema: CATALOG_SCHEMA, engine, sha256: baseline?.ok ? baseline.sha256 : null, ...(baseline?.ok ? { kinds: kinds(baseline) } : { reason: baseline?.reason ?? CATALOG_UNREADABLE }),
    final: latest?.ok ? latest.sha256 : null, changedDuringRun: Boolean(drifted), excluded: { schemas: [...(excluded?.schemas ?? [])], tables: [...(excluded?.tables ?? [])] } });
}

// Two runs' catalog records, for a retest comparison (VR1): each run's list of { instanceId, ...catalogRecord }, as the
// connector is to record them (proposed with N13; the comparison itself, src/runner.mjs compareRuns, takes this after N11).
//   not-recorded    neither run recorded one (runs from before N13): no flag, as before
//   not-comparable  one run alone recorded them, or the observers, their engines or exclusions differ, or a baseline was
//                   unreadable: catalog-not-comparable, so no repair is credited without saying the schema is unknown
//   changed         a matched observer's baseline definitions differ: migration-between-runs, with the kinds that did
//   unchanged       the same observers read the same definitions at both runs' start
// A run whose own catalog changed during it also carries schema-changed-during-run (its later windows read schema-drift).
export const MIGRATION_BETWEEN_RUNS = 'migration-between-runs', CATALOG_NOT_COMPARABLE = 'catalog-not-comparable', SCHEMA_CHANGED_DURING_RUN = 'schema-changed-during-run';
export function compareCatalogRecords(before, after) {
  const listed = r => Array.isArray(r) && r.length > 0, during = [];
  for (const [side, records] of [['baseline', before], ['candidate', after]]) if (listed(records) && records.some(r => r?.changedDuringRun === true)) during.push(side);
  const flags = list => [...list, ...(during.length ? [SCHEMA_CHANGED_DURING_RUN] : [])];
  const notComparable = reason => ({ state: 'not-comparable', reason, flags: flags([CATALOG_NOT_COMPARABLE]), duringRun: during });
  if (!listed(before) && !listed(after)) return { state: 'not-recorded', flags: [], duringRun: [] };
  if (!listed(before) || !listed(after)) return notComparable('one-run-only');
  const ids = records => records.map(r => r?.instanceId);
  const sameIds = JSON.stringify([...ids(before)].sort()) === JSON.stringify([...ids(after)].sort());
  if (!sameIds || new Set(ids(before)).size !== before.length || !ids(before).every(id => typeof id === 'string')) return notComparable('observers-differ');
  const observers = [];
  for (const a of before) {
    const b = after.find(r => r.instanceId === a.instanceId);
    if (a.schema !== CATALOG_SCHEMA || b.schema !== CATALOG_SCHEMA || a.engine !== b.engine) return notComparable('record-differs');
    if (digest(a.excluded ?? null) !== digest(b.excluded ?? null)) return notComparable('exclusions-differ');
    if (!HEX64.test(a.sha256 ?? '') || !HEX64.test(b.sha256 ?? '')) return notComparable('baseline-unreadable');
    if (a.sha256 === b.sha256) continue;
    const kinds = [...new Set([...Object.keys(a.kinds ?? {}), ...Object.keys(b.kinds ?? {})])].filter(k => digest(a.kinds?.[k] ?? null) !== digest(b.kinds?.[k] ?? null)).sort();
    observers.push({ instanceId: a.instanceId, kinds });
  }
  return observers.length ? { state: 'changed', flags: flags([MIGRATION_BETWEEN_RUNS]), observers, duringRun: during } : { state: 'unchanged', flags: flags([]), duringRun: during };
}
