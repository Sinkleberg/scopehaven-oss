// Postgres row-level security importer (layer "postgres-rls").
// Reads an ordered migration history or a catalog dump (pg_policies plus pg_class
// row-security flags, produced by the operator with CATALOG_DUMP_SQL on a test database;
// this module never connects to a database). Per table, role and command it states what
// the policies declare:
//   RLS not enabled                       -> undeclared (table privileges govern; not evaluated)
//   RLS enabled, no applicable permissive  -> deny (PostgreSQL's documented default deny; a
//                                            policy with no expression for a command grants nothing)
//   a permissive policy USING (true) and no restrictive narrowing -> allow
//   otherwise                             -> conditional, with each expression kept (normalized)
// It follows CREATE/ALTER/DROP POLICY (clauses in PostgreSQL's order), ALTER TABLE row
// security, OWNER TO, RENAME and SET SCHEMA, CREATE/DROP TABLE, ALTER/DROP SCHEMA, and
// search_path (SET, SET SCHEMA, RESET, DISCARD ALL, set_config), resolving unqualified names in path order.
// What it can't follow becomes unknown, never a guess:
//   an unreadable statement, or one PostgreSQL would reject  -> that table
//   a DO block, a called function or an event trigger       -> every table (use a catalog dump)
//   DROP OWNED BY, REASSIGN OWNED, SET LOCAL search_path       -> every table, or later unqualified names
//   a search_path value it can't split as PostgreSQL does, or a set_config of it that is not a bare SELECT list of
//   session-level calls with literal arguments -> later unqualified names (outside a SELECT: for the rest of the history)
//   ROLLBACK, ABORT or PREPARE TRANSACTION (statements already applied may not have happened) -> every table
//   a table pg_database_owner owns without FORCE, or a policy aimed at it (its member is implicit) -> that table
//   role membership, renames or BYPASSRLS/SUPERUSER changes   -> that role (a function body is
//   not executed by defining it, so CREATE FUNCTION alone is no gap)
//   a table owner (or a member of the owning role) without FORCE, a policy aimed at current_user -> those cells
//   any CASCADE (it drops dependent objects, which can include policies) -> every table
//   a U& name or string, standard_conforming_strings set other than on, or a quote after an odd run of
//   backslashes in a '...' string (where the string ends depends on that setting) -> every table
//   in a dump, a role reached through a grant that is not inherited but may be SET ROLE'd, or whose inheritance the dump
//   cannot show (a NOINHERIT role's grant with no inherit_option) -> the cells that role decides
//   in a dump, a role that may SET ROLE to a BYPASSRLS or superuser role -> its cells on RLS tables
//   (a role that may grant itself a role, WITH ADMIN or CREATEROLE before 16, reaches it the same way)
//   client_encoding set other than UTF8 (the server then reads the file's bytes in another encoding) -> every table
//   a call of a function these files define, outside definitions, or a write to a table whose
//   trigger or default calls one                              -> every table
// Replaying migrations models declared DDL only. Code that runs during a migration is flagged
// where it is detected but can't be ruled out, so a catalog dump of the migrated test database
// (CATALOG_DUMP_SQL) is the authoritative input; migration replay is best effort.
import { buildMatrix, canonical, sha256, sourceRecord } from './matrix.mjs';
import { escapedString, render, splitStatements, SqlSyntaxError, stripOuterParens, tokenize, truncateName, unicodeEscaped } from './sql-lexer.mjs';

export const LAYER = 'postgres-rls';
export const COMMANDS = Object.freeze(['SELECT', 'INSERT', 'UPDATE', 'DELETE']);
export const CATALOG_DUMP_SQL = `select json_build_object(
  'tables', (select coalesce(json_agg(json_build_object('schemaname', n.nspname, 'tablename', c.relname,
      'rowsecurity', c.relrowsecurity, 'forcerowsecurity', c.relforcerowsecurity) order by 1), '[]')
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where c.relkind in ('r', 'p') and n.nspname not in ('pg_catalog', 'information_schema', 'pg_toast')),
  'policies', (select coalesce(json_agg(p order by p.schemaname, p.tablename, p.policyname), '[]') from pg_policies p),
  'owners', (select coalesce(json_agg(json_build_object('schemaname', n.nspname, 'tablename', c.relname, 'owner', pg_get_userbyid(c.relowner)) order by 1), '[]')
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where c.relkind in ('r', 'p') and n.nspname not in ('pg_catalog', 'information_schema', 'pg_toast')),
  'roles', (select coalesce(json_agg(json_build_object('rolname', rolname, 'rolbypassrls', rolbypassrls, 'rolsuper', rolsuper, 'rolinherit', rolinherit, 'rolcreaterole', rolcreaterole) order by rolname), '[]') from pg_roles where rolname !~ '^pg_'),
  'members', (select coalesce(json_agg(json_build_object('role', r.rolname, 'member', m.rolname, 'inherit', (to_jsonb(a)->>'inherit_option')::boolean, 'set', (to_jsonb(a)->>'set_option')::boolean, 'admin', a.admin_option) order by 1), '[]')
    from pg_auth_members a join pg_roles r on r.oid = a.roleid join pg_roles m on m.oid = a.member),
  'server_version_num', current_setting('server_version_num')::int,
  'functions', (select coalesce(json_agg(json_build_object('schema', n.nspname, 'name', p.proname, 'digest', md5(pg_get_functiondef(p.oid))) order by 1, 2, 3), '[]')
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname not in ('pg_catalog', 'information_schema') and p.prokind in ('f', 'p')));`;
const NOT_EVALUATED = Object.freeze([
  'table privileges (GRANT/REVOKE on tables): a role without the privilege is refused before RLS applies',
  'role membership and attributes granted outside these files: a member of a role gets that role\'s policies, and BYPASSRLS or superuser roles skip RLS (changes inside the files make the role unknown)',
  'table owners not declared with OWNER TO in these files; declared owners are unknown unless FORCE ROW LEVEL SECURITY is set',
  'security-definer functions, views and triggers that read or write the table',
  'UPDATE and DELETE that read rows (WHERE, RETURNING) also need a SELECT policy; each cell shows only its own command\'s policies',
  'functions a policy calls that these files do not define: their bodies are not read (bodies defined here are hashed into the condition text)',
]);
const REPLAY_LIMITS = 'migration replay does not follow code reached indirectly: functions called through attribute notation or operators, foreign-key actions firing triggers on other tables, and triggers a partition inherits';
const REPLAY_STRINGS = '\'...\' strings are read as PostgreSQL reads them with standard_conforming_strings on (its default since 9.1), including where the setting comes from outside these files; a statement that sets it otherwise, or a quote after an odd run of backslashes in such a string, is a gap on every table';
const REPLAY_ENCODING = 'the files are read as UTF-8 and run with client_encoding UTF8, including where the setting comes from outside these files; a statement that sets it otherwise is a gap on every table. Names are cut to 63 bytes as a server with UTF-8 encoding cuts them; a server in another encoding cuts non-ASCII names elsewhere';
// A run-time error can't be known from the files. The usual runners (the Supabase CLI, psql -v ON_ERROR_STOP=1, migration
// frameworks) stop at the first one, so the deploy fails; a runner that goes on leaves the server where replay can't follow.
const REPLAY_SUCCESS = 'replay reads every statement as having succeeded, as when the runner stops at the first error: a statement the server rejects at run time inside BEGIN ... COMMIT rolls the transaction back, and replay does not see that (a catalog dump reads the real result)';
const REPLAY_NOTE = 'migration replay models declared DDL only; code run during a migration is flagged where detected but not ruled out, so a catalog dump of the migrated test database is the authoritative input';
const CLAUSES = { SELECT: ['using'], INSERT: ['check'], UPDATE: ['using', 'check'], DELETE: ['using'] };
const SPECIAL_ROLES = new Set(['current_role', 'current_user', 'session_user']);
const RLS_TEXT = /\brow\s+level\s+security\b/i;
// Calls a migration may make without running arbitrary code.
const SAFE_CALLS = new Set(['set_config', 'current_setting', 'now', 'pg_notify', 'setval', 'nextval', 'currval', 'pg_catalog.set_config', 'pg_catalog.pg_notify', 'pg_catalog.setval']);
const CLAUSE_ORDER = { as: 0, for: 1, to: 2, using: 3, check: 4 };
const RUNS_SQL = new Set(['select', 'call', 'perform', 'execute', 'with', 'values']);

const isKw = (token, word) => token?.t === 'ident' && token.v === word;
const isPunct = (token, v) => token?.t === 'punct' && token.v === v;
const isName = token => token?.t === 'ident' || token?.t === 'qident';
// With standard_conforming_strings off a backslash escapes the next character of a '...' string, so a quote after an odd
// run of backslashes ends the string elsewhere, and text this reader takes as a string can be statements PostgreSQL runs.
// An E'...' string reads the same either way, and an even run (\\') ends where it is read.
const BACKSLASH_QUOTE = /(?:^|[^\\])(?:\\\\)*\\'/;
const backslashQuote = statement => statement.some(t => t.t === 'string' && t.raw.startsWith("'") && BACKSLASH_QUOTE.test(t.raw.slice(1)));
// A statement that sets a setting this reader depends on to another value: for the session, a role or a database, or
// through set_config. Only "SET [SESSION] <setting> TO|= <accepted value>", DEFAULT and RESET keep the reading; any other
// statement that names the setting (SET LOCAL, ALTER ROLE or DATABASE ... SET, set_config) is read as changing it.
// client_encoding is also set by SET NAMES. Parameter names are case-insensitive, quoted or not, and set_config takes
// the name as any string literal, dollar-quoted included.
function setsOtherThan(statement, setting, accepted) {
  const named = t => ((t?.t === 'ident' || t?.t === 'qident') && t.v.toLowerCase() === setting) || ((t?.t === 'string' || t?.t === 'dollar') && t.v.trim().toLowerCase() === setting);
  const names = setting === 'client_encoding' && isKw(statement[0], 'set') && statement.slice(1, 3).some(t => isKw(t, 'names'));
  if (!names && !statement.some(named)) return false;
  const c = cursor(statement);
  if (c.kw('reset')) return !(named(c.peek()) && c.skip() && c.done());
  if (!c.kw('set')) return true;
  c.kw('session');
  if (!(names && c.kw('names'))) {
    if (!named(c.peek())) return true;
    c.skip();
    if (!(c.kw('to') || (c.peek()?.t === 'op' && c.peek().v === '=' && c.skip()))) return true;
  }
  const value = c.peek();
  if (!['ident', 'string', 'number'].includes(value?.t) || !(String(value.v).toLowerCase() === 'default' || accepted(String(value.v).toLowerCase()))) return true;
  c.skip();
  return !c.done();
}
// One literal set_config can take as a setting name or value: a '...' or dollar-quoted string. An E'...' string with a
// backslash is not one, since PostgreSQL decodes its escapes: E'client\x5fencoding' and E'\143lient_encoding' are client_encoding.
const plainLiteral = t => (t?.t === 'string' && !escapedString(t)) || t?.t === 'dollar';
const isSetConfig = (tokens, k) => isName(tokens[k]) && tokens[k].v === 'set_config' && isPunct(tokens[k + 1], '(');
// set_config whose setting name is not one plain literal (with an optional ::text) could change any
// setting this reader depends on (client_encoding, standard_conforming_strings, search_path).
function setConfigNameUnread(statement) {
  return statement.some((_, k) => {
    if (!isSetConfig(statement, k)) return false;
    // The first argument's tokens up to the first comma or closing parenthesis: enough to tell a lone literal (any nested
    // call or parenthesis is not one).
    const arg = [];
    for (let j = k + 2; j < statement.length && !isPunct(statement[j], ',') && !isPunct(statement[j], ')'); j++) arg.push(statement[j]);
    return !(plainLiteral(arg[0]) && (arg.length === 1 || (arg.length === 3 && arg[1].t === 'op' && arg[1].v === '::' && isKw(arg[2], 'text'))));
  });
}
// standard_conforming_strings: on, as pg_dump writes it.
const SCS_ON = new Set(['on', 'true', 'yes', '1']);
const conformingStringsOff = statement => setsOtherThan(statement, 'standard_conforming_strings', v => SCS_ON.has(v));
// client_encoding: the server converts the file's bytes from it before lexing, so in another encoding a byte this reader
// takes as a backslash or a quote can be part of a character (or the reverse). UTF8 (pg_dump writes 'UTF8') keeps the reading.
const clientEncodingChanged = statement => setsOtherThan(statement, 'client_encoding', v => ['utf8', 'unicode'].includes(v.replace(/[-_]/g, '')));
const ident = v => /^[a-z_][a-z0-9_$]*$/.test(v) ? v : `"${v.replaceAll('"', '""')}"`;
export const tableKeyOf = (schema, name) => `${ident(schema)}.${ident(name)}`;

class Unreadable extends Error {}
const at = (error, scope) => Object.assign(error, { scope });

// PostgreSQL's owner check is has_privs_of_role, so every role with the owner's privileges skips RLS
// like the owner itself, not only the owning role. Membership is known only from a catalog dump.
const ownsTable = (st, t, role) => t.owner !== null && (t.owner === role || Boolean(st.effective?.(role).has(t.owner)));

function state() { return { tables: new Map(), gaps: [], steps: [], assumptions: new Set(), path: ['public'], pathLost: false, functions: new Map(), bodies: new Map(), codeOnWrite: new Set(), catalogRoles: null, effective: null, possible: null, settable: null }; }
function table(st, key) {
  if (!st.tables.has(key)) st.tables.set(key, { key, rls: false, force: false, owner: null, ownerCite: null, policies: new Map(), cites: [] });
  return st.tables.get(key);
}
function moveTable(st, from, to, cite) {
  const t = st.tables.get(from) ?? table(st, from);
  st.tables.delete(from);
  st.tables.set(to, { ...t, key: to, cites: [...t.cites, cite] });
  for (const gap of st.gaps) if (gap.scope === from) gap.scope = to;
  if (st.codeOnWrite.delete(from)) st.codeOnWrite.add(to);
}

// Unqualified names resolve against known tables in search_path order, as PostgreSQL does;
// a new table goes in the first schema listed.
function resolve(st, parts, { create = false } = {}) {
  if (parts.length === 2) return tableKeyOf(parts[0], parts[1]);
  if (st.path === null) throw new Unreadable('unqualified table name while search_path could not be read');
  if (create) { if (!st.path.length) throw new Unreadable('CREATE TABLE with an empty search_path'); return tableKeyOf(st.path[0], parts[0]); }
  for (const schema of ['pg_temp', ...st.path]) if (st.tables.has(tableKeyOf(schema, parts[0]))) return tableKeyOf(schema, parts[0]);
  if (st.path.length === 1) return tableKeyOf(st.path[0], parts[0]);
  throw new Unreadable(`unqualified table ${parts[0]} can't be resolved against search_path (${st.path.join(', ') || 'empty'})`);
}
// A null name: the path can't be read. Once a set_config of search_path may run later (st.pathLost), no statement makes it
// readable again.
function setPath(st, names) {
  if (st.pathLost || names.some(n => n === null)) { st.path = null; return; }
  if (names.includes('$user')) st.assumptions.add('"$user" in search_path is treated as a schema that does not exist');
  st.path = names.filter(n => n !== '$user');
}
// One string constant as a search_path entry (SET quotes it as one name, case kept), cut to 63 bytes as PostgreSQL cuts a
// name. Read only when it is plain and non-empty with no comma; PostgreSQL rejects an empty name.
const pathString = t => plainLiteral(t) && t.v !== '' && !t.v.includes(',') ? truncateName(t.v) : null;
// set_config's search_path value as PostgreSQL splits it: names between commas, with spaces, tabs or line breaks around
// them. A plain ASCII name (or $user) is folded to lower case and a quoted one kept as written, each cut to 63 bytes.
// Anything else is null: an empty name, or one this reader would have to fold or split as PostgreSQL does.
function pathList(value) {
  if (/^[ \t\n\r\f]*$/.test(value)) return [];
  return value.split(',').map(s => /^[ \t\n\r\f]*(?:"([^"]+)"|([A-Za-z_][A-Za-z0-9_$]*|\$user))[ \t\n\r\f]*$/.exec(s))
    .map(m => m === null ? null : truncateName(m[1] ?? m[2].toLowerCase()));
}
// set_config calls that name search_path. Only a SELECT that is nothing but a list of [pg_catalog.]set_config(<literal>,
// <literal>, false) calls runs each once, at session level, in order, so only that is followed. Any other SELECT with one (a
// FROM, WHERE or LIMIT may run it any number of times; a true or computed is_local ends with the transaction; a computed
// value) leaves the path unknown until it is next set. In any other statement (a CTE, VALUES, EXPLAIN ANALYZE, an INSERT,
// CREATE TABLE AS, a column default or CHECK, a view, a rule or a policy) it may also run on a later statement, so the path
// stays unknown for the rest of the history.
function followSetConfigPath(st, statement) {
  if (!statement.some((_, k) => isSetConfig(statement, k) && plainLiteral(statement[k + 2]) && statement[k + 2].v.toLowerCase() === 'search_path')) return;
  if (!isKw(statement[0], 'select')) { st.pathLost = true; st.path = null; return; }
  const calls = splitTopLevel(statement.slice(1)).map(item => isName(item[0]) && item[0].v === 'pg_catalog' && isPunct(item[1], '.') ? item.slice(2) : item);
  const sessionLevel = t => isKw(t, 'false') || (plainLiteral(t) && t.v.toLowerCase() === 'false');
  if (!calls.every(c => c.length === 8 && isSetConfig(c, 0) && plainLiteral(c[2]) && isPunct(c[3], ',') && plainLiteral(c[4]) && isPunct(c[5], ',') && sessionLevel(c[6]))) { st.path = null; return; }
  for (const c of calls) if (c[2].v.toLowerCase() === 'search_path') setPath(st, pathList(c[4].v));
}

function expression(tokens) {
  const core = stripOuterParens(tokens);
  if (!core.length) throw new Unreadable('empty expression');
  return render(core);
}

// CREATE POLICY and ALTER POLICY clauses, in the order PostgreSQL's grammar requires.
function readPolicyClauses(c, policy, { create }) {
  let last = -1;
  while (!c.done()) {
    let clause;
    if (create && c.kw('as')) { clause = 'as'; if (c.kw('permissive')) policy.permissive = true; else if (c.kw('restrictive')) policy.permissive = false; else throw new Unreadable('expected PERMISSIVE or RESTRICTIVE'); }
    else if (create && c.kw('for')) { clause = 'for'; const t = c.peek(); if (!isKw(t, 'all') && !COMMANDS.some(cmd => isKw(t, cmd.toLowerCase()))) throw new Unreadable('expected a command'); c.name(); policy.command = t.v.toUpperCase(); }
    else if (c.kw('to')) { clause = 'to'; policy.roles = readNames(c, { roles: true }); }
    else if (c.kw('using')) { clause = 'using'; policy.using = expression(c.paren()); }
    else if (c.kw('with', 'check')) { clause = 'check'; policy.check = expression(c.paren()); }
    else throw new Unreadable(`unexpected ${c.peek().raw}`);
    if (CLAUSE_ORDER[clause] <= last) throw new Unreadable(`${clause.toUpperCase()} is out of PostgreSQL's clause order (AS, FOR, TO, USING, WITH CHECK), so this statement would fail`);
    last = CLAUSE_ORDER[clause];
  }
}
function readNames(c, { roles = false } = {}) {
  const names = [];
  for (;;) {
    const t = c.peek();
    if (!isName(t)) throw new Unreadable(roles ? 'expected a role' : 'expected a name');
    c.name();
    names.push(roles && t.t === 'ident' && SPECIAL_ROLES.has(t.v) ? `<${t.v}>` : t.v);
    if (!isPunct(c.peek(), ',')) return names;
    c.comma();
  }
}
function validatePolicy(policy) {
  if (policy.command === 'INSERT' && policy.using !== undefined) throw new Unreadable('PostgreSQL rejects USING on an INSERT policy, so this statement would fail');
  if (['SELECT', 'DELETE'].includes(policy.command) && policy.check !== undefined) throw new Unreadable(`PostgreSQL rejects WITH CHECK on a ${policy.command} policy, so this statement would fail`);
}

function dispatch(st, c, tokens, cite) {
  if (c.kw('create', 'policy')) {
    const name = c.name(); c.need('on'); const key = resolve(st, c.qualified());
    const policy = { name, permissive: true, command: 'ALL', roles: ['public'], cite };
    try { readPolicyClauses(c, policy, { create: true }); validatePolicy(policy); } catch (error) { throw at(error, key); }
    const t = table(st, key);
    if (t.policies.has(name)) throw at(new Unreadable(`policy ${name} already exists on ${key}, so this statement would fail`), key);
    t.policies.set(name, policy);
    return;
  }
  if (c.kw('drop', 'policy')) {
    const ifExists = c.kw('if', 'exists'); const name = c.name(); c.need('on'); const key = resolve(st, c.qualified());
    c.kw('cascade') || c.kw('restrict');
    if (!c.done()) throw at(new Unreadable('unexpected tokens after DROP POLICY'), key);
    if (!table(st, key).policies.delete(name) && !ifExists) throw at(new Unreadable(`DROP POLICY ${name} on ${key}: no such policy in the history read`), key);
    return;
  }
  if (c.kw('alter', 'policy')) {
    const name = c.name(); c.need('on'); const key = resolve(st, c.qualified());
    const t = table(st, key), policy = t.policies.get(name);
    if (!policy) throw at(new Unreadable(`ALTER POLICY ${name} on ${key}: no such policy in the history read`), key);
    if (c.kw('rename', 'to')) {
      const next = c.name();
      if (!c.done()) throw at(new Unreadable('unexpected tokens after ALTER POLICY RENAME'), key);
      if (t.policies.has(next)) throw at(new Unreadable(`policy ${next} already exists on ${key}, so this rename would fail`), key);
      t.policies.delete(name); t.policies.set(next, { ...policy, name: next, cite }); return;
    }
    const altered = { ...policy, cite };
    try { readPolicyClauses(c, altered, { create: false }); validatePolicy(altered); } catch (error) { throw at(error, key); }
    t.policies.set(name, altered);
    return;
  }
  if (c.kw('alter', 'table')) {
    c.kw('if', 'exists'); c.kw('only');
    const parts = c.qualified(), key = resolve(st, parts);
    if (c.peek()?.t === 'op' && c.peek().v === '*') c.skip();
    if (c.kw('rename', 'to')) {
      const to = tableKeyOf(splitKey(key)[0], c.name());
      if (!c.done()) throw at(new Unreadable('ALTER TABLE RENAME TO takes an unqualified name, so this statement would fail'), key);
      if (st.tables.has(to)) throw at(new Unreadable(`${to} already exists, so this rename would fail`), key);
      moveTable(st, key, to, cite); return;
    }
    if (c.kw('set', 'schema')) {
      const to = tableKeyOf(c.name(), splitKey(key)[1]);
      if (!c.done()) throw at(new Unreadable('unexpected tokens after ALTER TABLE SET SCHEMA'), key);
      if (st.tables.has(to)) throw at(new Unreadable(`${to} already exists, so this move would fail`), key);
      moveTable(st, key, to, cite); return;
    }
    for (const action of splitTopLevel(c.rest())) {
      const a = cursor(action), t = table(st, key);
      if (a.kw('enable', 'row', 'level', 'security')) { t.rls = true; t.cites.push(cite); }
      else if (a.kw('disable', 'row', 'level', 'security')) { t.rls = false; t.cites.push(cite); }
      else if (a.kw('force', 'row', 'level', 'security')) { t.force = true; t.cites.push(cite); }
      else if (a.kw('no', 'force', 'row', 'level', 'security')) { t.force = false; t.cites.push(cite); }
      else if (a.kw('owner', 'to')) { t.owner = a.name(); t.ownerCite = cite; }
      else if (['enable', 'disable', 'force', 'no'].some(w => isKw(action[0], w)) && RLS_TEXT.test(render(action))) throw at(new Unreadable('an ALTER TABLE row-security action could not be read'), key);
      else continue;
      if (!a.done()) throw at(new Unreadable('unexpected tokens after an ALTER TABLE action'), key);
    }
    return;
  }
  if (c.kw('alter', 'schema')) {
    const from = c.name();
    if (c.kw('rename', 'to')) {
      const to = c.name();
      if ([...st.tables.keys()].some(key => splitKey(key)[0] === to)) throw at(new Unreadable(`schema ${to} already exists, so this rename would fail`), '*');
      for (const key of [...st.tables.keys()]) if (splitKey(key)[0] === from) moveTable(st, key, tableKeyOf(to, splitKey(key)[1]), cite);
    }
    return;
  }
  if (c.kw('drop', 'schema')) {
    c.kw('if', 'exists');
    const schemas = readNames(c), cascade = c.kw('cascade');
    const inside = [...st.tables.keys()].filter(key => schemas.includes(splitKey(key)[0]));
    if (inside.length && !cascade) throw at(new Unreadable(`DROP SCHEMA without CASCADE on a schema with tables, so this statement would fail`), '*');
    for (const key of inside) st.tables.delete(key);
    return;
  }
  if (c.kw('drop', 'owned')) throw at(new Unreadable('DROP OWNED BY removes policies and objects of roles whose ownership is not modelled'), '*');
  if (c.kw('reassign', 'owned')) throw at(new Unreadable('REASSIGN OWNED changes the owners of tables whose ownership is not modelled'), '*');
  if (c.kw('create', 'event', 'trigger')) throw at(new Unreadable('an event trigger runs code on later DDL'), '*');
  if ((isKw(c.peek(), 'create') || isKw(c.peek(), 'alter')) && ['role', 'user', 'group'].some(w => isKw(c.peek(1), w))) {
    c.skip(); c.skip();
    const role = c.name();
    if (c.kw('rename', 'to')) { const next = c.name(); throw Object.assign(new Unreadable(`role ${role} is renamed to ${next}; policies follow the role`), { scope: [`role:${role}`, `role:${next}`] }); }
    const rest = render(c.rest());
    if (/(?:^|\s)(?:in\s+role|in\s+group|role|admin|user)\s/i.test(` ${rest} `)) throw at(new Unreadable(`role ${role} gains or grants memberships, which change which policies apply`), '*');
    if (/\b(no)?(bypassrls|superuser)\b/i.test(rest)) throw at(new Unreadable(`role ${role}'s BYPASSRLS or SUPERUSER attribute changes in these files`), `role:${role}`);
    return;
  }
  if (isKw(c.peek(), 'grant') || isKw(c.peek(), 'revoke')) {
    if (tokens.some(t => isKw(t, 'on'))) return; // object privileges: not evaluated (stated on every matrix)
    const keyword = isKw(tokens[0], 'grant') ? 'to' : 'from';
    const index = tokens.findIndex(t => isKw(t, keyword));
    if (index < 0) throw at(new Unreadable('could not read a role membership change'), '*');
    const grantees = cursor(tokens.slice(index + 1)); let names;
    try { names = readNames(grantees, { roles: true }); } catch { throw at(new Unreadable('could not read a role membership change'), '*'); }
    throw Object.assign(new Unreadable(`role membership changes for ${names.join(', ')}`), { scope: names.map(n => `role:${n}`) });
  }
  if (c.kw('create', 'schema')) {
    c.kw('if', 'not', 'exists');
    if (c.kw('authorization')) c.name(); else { c.name(); if (c.kw('authorization')) c.name(); }
    if (!c.done()) throw at(new Unreadable('CREATE SCHEMA with schema elements is not followed'), '*');
    return;
  }
  if (c.kw('create', 'trigger') || c.kw('create', 'or', 'replace', 'trigger') || c.kw('create', 'constraint', 'trigger')) {
    const on = tokens.findIndex(t => isKw(t, 'on')), exec = tokens.findIndex(t => isKw(t, 'execute'));
    if (on < 0 || exec < 0) throw at(new Unreadable('could not read CREATE TRIGGER'), '*');
    if (callsUserFunction(st, tokens)) {
      const target = cursor(tokens.slice(on + 1)); st.codeOnWrite.add(resolve(st, target.qualified()));
    }
    return;
  }
  if (c.kw('create')) {
    c.kw('global') || c.kw('local');
    const temp = c.kw('temporary') || c.kw('temp'); c.kw('unlogged');
    // ON COMMIT DROP: the table is gone at the end of its transaction.
    if (temp && tokens.some((t, k) => isKw(t, 'commit') && isKw(tokens[k + 1], 'drop'))) return;
    if (c.kw('table')) {
      c.kw('if', 'not', 'exists');
      const parts = c.qualified();
      const key = temp && parts.length === 1 ? tableKeyOf('pg_temp', parts[0]) : resolve(st, parts, { create: true });
      const t = table(st, key); t.cites.push(cite);
      if (callsUserFunction(st, c.rest())) st.codeOnWrite.add(key);
    }
    return;
  }
  if (c.kw('drop', 'table')) {
    c.kw('if', 'exists');
    for (;;) { st.tables.delete(resolve(st, c.qualified())); if (!isPunct(c.peek(), ',')) break; c.skip(); }
    return;
  }
  if (c.kw('discard')) {
    const all = c.kw('all');
    if (all || c.kw('temp') || c.kw('temporary')) for (const key of [...st.tables.keys()]) if (splitKey(key)[0] === 'pg_temp') st.tables.delete(key);
    if (all) setPath(st, ['$user', 'public']); // DISCARD ALL runs RESET ALL
    return;
  }
  // Setting names are case-insensitive, quoted or not.
  const isSearchPath = t => isName(t) && t.v.toLowerCase() === 'search_path';
  if (isKw(c.peek(), 'reset') && (isSearchPath(c.peek(1)) || isKw(c.peek(1), 'all'))) { setPath(st, ['$user', 'public']); return; }
  if (c.kw('set')) {
    const local = c.kw('local'); if (!local) c.kw('session');
    // SET SCHEMA 'name' is PostgreSQL's alias for SET search_path TO 'name'.
    const schema = c.kw('schema');
    if (!schema && !isSearchPath(c.peek())) return;
    if (!schema) c.skip();
    // A transaction-scoped path ends at COMMIT, which is not modelled: later unqualified names are gaps.
    if (local) { st.path = null; return; }
    if (schema) { setPath(st, [c.rest().length === 1 ? pathString(c.peek()) : null]); return; }
    if (!(c.kw('to') || (c.peek()?.t === 'op' && c.peek().v === '=' && c.skip()))) throw new Unreadable('could not read SET search_path');
    if (c.kw('default') && c.done()) { setPath(st, ['$user', 'public']); return; }
    setPath(st, splitTopLevel(c.rest()).map(part => part.length !== 1 ? null : isName(part[0]) ? part[0].v : pathString(part[0])));
  }
}

const splitKey = key => { const m = /^("(?:[^"]|"")*"|[^."]+)\.("(?:[^"]|"")*"|[^."]+)$/.exec(key); const un = p => p.startsWith('"') ? p.slice(1, -1).replaceAll('""', '"') : p; return [un(m[1]), un(m[2])]; };
export { splitKey };

function splitTopLevel(tokens) {
  const parts = []; let cur = [], depth = 0;
  for (const t of tokens) {
    if (isPunct(t, '(')) depth++; if (isPunct(t, ')')) depth--;
    if (isPunct(t, ',') && depth === 0) { parts.push(cur); cur = []; continue; }
    cur.push(t);
  }
  if (cur.length) parts.push(cur);
  return parts;
}

// Feeds one migration file into the state. A statement that can't be read becomes a gap
// on its table, its role, or every table when the scope isn't known.
// pg_dump (the 2025 minor releases on) brackets its output in two psql meta-commands: \restrict <key> is its first line that
// is not a comment, and \unrestrict <key> its last. Exactly that pair, with one key, is blanked (line numbers kept); any
// other backslash command still makes the file unreadable.
function withoutPgDumpBrackets(text) {
  const lines = text.split('\n');
  const first = lines.findIndex(l => l.trim() !== '' && !l.trimStart().startsWith('--'));
  let last = lines.length - 1;
  while (last > first && lines[last].trim() === '') last--;
  const open = /^\\restrict ([A-Za-z0-9]+)\r?$/.exec(lines[first] ?? ''), close = /^\\unrestrict ([A-Za-z0-9]+)\r?$/.exec(lines[last] ?? '');
  if (!open || !close || open[1] !== close[1] || first >= last) return text;
  lines[first] = ''; lines[last] = '';
  return lines.join('\n');
}

// A gap's identity subject (matrix.mjs): the statement's tokens, comments and spacing dropped, so a gap keeps its id when
// lines move or other statements change. Unquoted names and keywords are folded as PostgreSQL folds them; every other token
// keeps its raw text (quoting, E'' escapes, dollar tags), so any change PostgreSQL could read differently is a new gap.
const subjectOf = statement => statement.map(t => t.t === 'ident' ? t.v : t.raw).join(' ');
// Where a replayed gap sits: st.steps holds one digest per statement read, or per file that could not be tokenized, in
// history order. A gap's identity takes the digest of every step before it (position), so migrations appended later keep
// every earlier id, while a move, insertion, deletion or edit of an earlier statement gives it a new id (a DO block's
// effect depends on what ran before it). A gap that changes how every later byte is read (client_encoding set other than
// UTF8, or a set_config that could set it) also takes the digest of every step after it (rest), so once the history sets
// such an encoding every later change is a new gap: after the desync the two readers disagree on every later quote.
// Catalog and export gaps have no order and take neither.
const historyDigest = steps => sha256(steps.join('\n'));
function placeGaps(st) {
  return st.gaps.map(({ identity, ...gap }) => {
    if (identity?.at === undefined) return identity ? { ...gap, identity } : gap;
    const { at, rest, ...basis } = identity;
    return { ...gap, identity: { ...basis, position: historyDigest(st.steps.slice(0, at)), ...(rest ? { rest: historyDigest(st.steps.slice(at + 1)) } : {}) } };
  });
}

function applySql(st, text, sourceId) {
  let tokens;
  text = withoutPgDumpBrackets(text);
  try { tokens = tokenize(text); }
  catch (error) {
    // Nothing in the file is read (psql runs a statement above a meta-command before reaching it), so the whole file, after
    // the pg_dump brackets, is the gap's subject; its line number is left out of the kind.
    if (error instanceof SqlSyntaxError) {
      st.gaps.push({ source: sourceId, line: error.line, scope: '*', reason: `could not tokenize: ${error.message}`,
        identity: { kind: `could not tokenize: ${error.message.replace(/ \(line \d+\)$/, '')}`, subject: text, at: st.steps.length } });
      st.steps.push(sha256(`file\u0000${text}`));
      return;
    }
    throw error;
  }
  const statements = splitStatements(tokens);
  if (statements.unclosed) st.gaps.push({ source: sourceId, line: statements.at(-1)?.[0]?.line ?? null, scope: '*', reason: 'a BEGIN ATOMIC body is never closed, so later statements cannot be separated',
    identity: { subject: subjectOf(statements.at(-1) ?? []), at: st.steps.length + statements.length - 1 } });
  for (const statement of statements) {
    const step = st.steps.length, subject = subjectOf(statement);
    st.steps.push(sha256(`statement\u0000${subject}`));
    const head = render(statement.slice(0, 6));
    const cite = { source: sourceId, line: statement[0].line, statement: head.length > 120 ? `${head.slice(0, 117)}...` : head };
    const depth = statement.reduce((d, t) => d + (isPunct(t, '(') ? 1 : isPunct(t, ')') ? -1 : 0), 0);
    if (depth !== 0) { st.gaps.push({ source: sourceId, line: statement[0].line, scope: '*', reason: 'unbalanced parentheses: later statements in this file cannot be separated', identity: { subject, at: step } }); continue; }
    const gap = (reason, rest = false) => st.gaps.push({ source: sourceId, line: statement[0].line, scope: '*', reason: `${reason}; import a catalog dump instead`, identity: { subject, at: step, ...(rest ? { rest } : {}) } });
    // Undecoded, a U& name could resolve to any table, so the statement is a gap on every table.
    if (unicodeEscaped(statement)) { gap('a Unicode-escape name or string (U&"..." or U&\'...\') is not decoded'); continue; }
    if (backslashQuote(statement)) { gap('a \'...\' string has a quote after an odd run of backslashes, which ends it elsewhere when standard_conforming_strings is off'); continue; }
    if (setConfigNameUnread(statement)) { gap('set_config with a setting name that is not one literal could change any setting, including how this file is read', true); continue; }
    if (conformingStringsOff(statement)) { gap('standard_conforming_strings is set other than on, so later \'...\' strings may end where this reader cannot tell'); continue; }
    if (clientEncodingChanged(statement)) { gap('client_encoding is set other than UTF8, so the server reads later bytes as other characters than this reader does', true); continue; }
    // Transactions are not modelled: a rollback undoes statements this reader applied (policies, search_path), and a
    // prepared transaction's statements take effect only if it is committed.
    if (isKw(statement[0], 'rollback') || isKw(statement[0], 'abort') || (isKw(statement[0], 'prepare') && isKw(statement[1], 'transaction'))) { gap('ROLLBACK, ABORT or PREPARE TRANSACTION: statements already applied may not have happened'); continue; }
    // A foreign-key action (ON DELETE/UPDATE CASCADE) is a row action, not a drop.
    const dropCascade = statement.some((t, k) => isKw(t, 'cascade') && !isKw(statement[k - 1], 'delete') && !isKw(statement[k - 1], 'update'));
    if (dropCascade && !(isKw(statement[0], 'drop') && isKw(statement[1], 'policy')) && !isKw(statement[0], 'truncate')) { gap('CASCADE drops dependent objects, which can include policies'); continue; }
    const definition = isKw(statement[0], 'create') && (isKw(statement[1], 'function') || isKw(statement[1], 'procedure') || (isKw(statement[1], 'or') && isKw(statement[2], 'replace') && (isKw(statement[3], 'function') || isKw(statement[3], 'procedure'))));
    if (definition) { defineFunction(st, statement); continue; } // defining runs nothing
    // CREATE TABLE ... AS and CREATE MATERIALIZED VIEW run their query; a plain view runs nothing.
    const head4 = statement.slice(0, 5);
    const asAt = statement.findIndex((t, k) => k > 1 && isKw(t, 'as') && !statement.slice(0, k).some(x => isPunct(x, '(')));
    const runsCreate = isKw(statement[0], 'create') && (head4.some(t => isKw(t, 'table')) || head4.some(t => isKw(t, 'materialized'))) && asAt > 0
      && (['select', 'with', 'values', 'table', 'execute'].some(w => isKw(statement[asAt + 1], w)) || isPunct(statement[asAt + 1], '('));
    const runs = RUNS_SQL.has(statement[0].v) || isPunct(statement[0], '(') || runsCreate;
    const calls = runs ? callNames(statement) : [];
    if (isKw(statement[0], 'do') || isKw(statement[0], 'execute') || calls.some(name => !SAFE_CALLS.has(name))) { gap('procedural code (a DO block, EXECUTE or a called function) is not evaluated'); continue; }
    // Statements that define or name a function without calling it; ALTER TABLE is not one of
    // them, since a DEFAULT, USING or CHECK runs on the rows already there.
    const objects = ['policy', 'trigger', 'table', 'index', 'view', 'function', 'procedure', 'routine', 'aggregate', 'type', 'domain', 'sequence', 'schema', 'extension'];
    const alterTable = isKw(statement[0], 'alter') && isKw(statement[1], 'table');
    const definitionLike = !runsCreate && !alterTable && ((['create', 'alter', 'drop'].includes(statement[0].v) && head4.some(t => objects.some(w => isKw(t, w))))
      || ['comment', 'grant', 'revoke', 'security'].includes(statement[0].v));
    if (!definitionLike && callsUserFunction(st, statement)) { gap(`${alterTable ? 'an ALTER TABLE runs' : 'a statement calls'} a function defined in these files`); continue; }
    const write = writesTo(st, statement);
    if (write !== null && (write === '*' ? st.codeOnWrite.size > 0 : st.codeOnWrite.has(write))) { gap('a write to a table whose trigger or default calls a function defined in these files'); continue; }
    try { dispatch(st, cursor(statement), statement, cite); }
    catch (error) {
      if (!(error instanceof Unreadable)) throw error;
      for (const scope of [error.scope ?? '*'].flat()) st.gaps.push({ source: sourceId, line: statement[0].line, scope, reason: error.message, identity: { subject, at: step } });
    }
    // After the statement's own names resolve: a set_config call runs as the statement executes.
    followSetConfigPath(st, statement);
  }
}

const callNames = statement => statement.flatMap((t, k) => isName(t) && isPunct(statement[k + 1], '(')
  ? [(isPunct(statement[k - 1], '.') && isName(statement[k - 2]) ? `${statement[k - 2].v}.` : '') + t.v] : []);
const lastPart = name => name.split('.').at(-1);
const callsUserFunction = (st, tokens) => callNames(tokens).some(name => st.functions.has(lastPart(name)));
// The whole definition is hashed (body, SECURITY DEFINER, SET search_path...). Overloads share
// a name, so their definitions accumulate under it rather than the last one winning.
function defineFunction(st, statement) {
  const c = cursor(statement); c.kw('create'); c.kw('or', 'replace'); c.kw('function') || c.kw('procedure');
  let name; try { name = lastPart(c.qualified().join('.')); } catch { return; }
  const definition = statement.map(t => t.t === 'dollar' || t.t === 'string' ? `'${t.v}'` : render([t])).join(' ');
  const body = statement.filter(t => t.t === 'dollar' || t.t === 'string').map(t => t.v).join(' ') || render(statement);
  const replace = isKw(statement[1], 'or');
  const prior = replace ? '' : (st.bodies.get(name) ?? '');
  st.bodies.set(name, `${prior}\n${body}`);
  st.functions.set(name, sha256(`${replace ? '' : (st.functions.get(name) ?? '')}|${definition}`).slice(0, 12));
}
// The table a DML statement writes, '*' when it can't be resolved, or null for no write.
function writesTo(st, statement) {
  const c = cursor(statement);
  if (!(c.kw('insert', 'into') || c.kw('update') || c.kw('delete', 'from') || c.kw('merge', 'into') || c.kw('copy') || c.kw('truncate'))) return null;
  c.kw('table'); c.kw('only');
  try { return resolve(st, c.qualified()); } catch { return '*'; }
}

// One statement's cursor. Every read throws Unreadable when the shape is unexpected.
function cursor(tokens) {
  let i = 0;
  const c = {
    peek: (o = 0) => tokens[i + o], done: () => i >= tokens.length, rest: () => tokens.slice(i),
    kw(...words) { if (words.every((w, k) => isKw(tokens[i + k], w))) { i += words.length; return true; } return false; },
    need(...words) { if (!c.kw(...words)) throw new Unreadable(`expected ${words.join(' ').toUpperCase()}`); },
    name() { const t = tokens[i]; if (!isName(t)) throw new Unreadable('expected a name'); i++; return t.v; },
    qualified() {
      const parts = [c.name()];
      while (isPunct(tokens[i], '.')) { i++; parts.push(c.name()); }
      if (parts.length > 3) throw new Unreadable('name has too many parts');
      return parts.slice(-2);
    },
    paren() {
      if (!isPunct(tokens[i], '(')) throw new Unreadable('expected (');
      let depth = 0; const start = i;
      for (; i < tokens.length; i++) {
        if (isPunct(tokens[i], '(')) depth++;
        if (isPunct(tokens[i], ')') && --depth === 0) { i++; return tokens.slice(start + 1, i - 1); }
      }
      throw new Unreadable('unbalanced parentheses');
    },
    skip() { if (i >= tokens.length) throw new Unreadable('unexpected end'); i++; return true; },
    comma() { if (!isPunct(tokens[i], ',')) throw new Unreadable('expected ,'); i++; },
  };
  return c;
}

function applyCatalog(st, dump, sourceId) {
  if (!dump || !Array.isArray(dump.tables) || !Array.isArray(dump.policies)) throw new Error('A catalog dump is JSON with "tables" and "policies" arrays (see CATALOG_DUMP_SQL).');
  st.assumptions.add('catalog dump: expressions are PostgreSQL\'s deparsed text');
  dump.tables.forEach((row, index) => {
    if (typeof row?.schemaname !== 'string' || typeof row?.tablename !== 'string' || typeof row.rowsecurity !== 'boolean') { st.gaps.push({ source: sourceId, line: null, scope: '*', reason: `tables[${index}] is not a readable table row`, identity: { kind: 'tables[] is not a readable table row', subject: canonical(row ?? null) } }); return; }
    const key = tableKeyOf(row.schemaname, row.tablename), t = table(st, key);
    t.rls = row.rowsecurity; t.force = row.forcerowsecurity === true;
    t.cites.push({ source: sourceId, line: null, statement: `tables[${index}] ${key} rowsecurity=${row.rowsecurity}` });
  });
  dump.policies.forEach((row, index) => {
    if (typeof row?.schemaname !== 'string' || typeof row?.tablename !== 'string' || typeof row.policyname !== 'string') { st.gaps.push({ source: sourceId, line: null, scope: '*', reason: `policies[${index}] is not a readable policy row`, identity: { kind: 'policies[] is not a readable policy row', subject: canonical(row ?? null) } }); return; }
    const key = tableKeyOf(row.schemaname, row.tablename), cite = { source: sourceId, line: null, statement: `policies[${index}] ${row.policyname} ON ${key}` };
    const roles = Array.isArray(row.roles) ? row.roles : typeof row.roles === 'string' ? row.roles.replace(/^\{|\}$/g, '').split(',').filter(Boolean).map(r => r.replace(/^"(.*)"$/, '$1')) : null;
    const command = String(row.cmd ?? '').toUpperCase();
    if (!roles || !['ALL', ...COMMANDS].includes(command) || !['PERMISSIVE', 'RESTRICTIVE'].includes(row.permissive)) {
      st.gaps.push({ source: sourceId, line: null, scope: key, reason: `policies[${index}] has an unreadable roles, cmd or permissive field`, identity: { kind: 'policies[] has an unreadable roles, cmd or permissive field', subject: canonical(row) } }); return;
    }
    const text = v => { if (v === null || v === undefined) return undefined; const tokens = tokenize(String(v)); if (unicodeEscaped(tokens)) throw new Error('a Unicode-escape name or string is not decoded'); return render(stripOuterParens(tokens)); };
    let using, check;
    try { using = text(row.qual); check = text(row.with_check); }
    catch (error) { st.gaps.push({ source: sourceId, line: null, scope: key, reason: `policies[${index}] expression could not be read: ${error.message}`, identity: { kind: `policies[] expression could not be read: ${error.message}`, subject: canonical(row) } }); return; }
    table(st, key).policies.set(row.policyname, { name: row.policyname, permissive: row.permissive === 'PERMISSIVE', command, roles: roles.map(r => SPECIAL_ROLES.has(r) ? `<${r}>` : r), using, check, cite });
  });
  // Owners, role attributes, memberships and function definitions (newer dumps): what replay
  // can't see. A dump without them keeps those lines in notEvaluated.
  if (Array.isArray(dump.owners)) dump.owners.forEach((row, index) => {
    const t = st.tables.get(tableKeyOf(String(row?.schemaname), String(row?.tablename)));
    if (t && typeof row.owner === 'string') { t.owner = row.owner; t.ownerCite = { source: sourceId, line: null, statement: `owners[${index}] owner ${row.owner}` }; t.ownerFromCatalog = true; }
  });
  if (Array.isArray(dump.roles) && Array.isArray(dump.members)) {
    st.catalogRoles = new Map(dump.roles.filter(r => typeof r?.rolname === 'string').map((r, index) => [r.rolname, { ...r, index }]));
    // A role gets the policies (and an owner's RLS bypass) of every role it inherits from, transitively (has_privs_of_role).
    // From PostgreSQL 16 that is decided per grant (pg_auth_members.inherit_option, the dump's "inherit"; rolinherit is only the
    // default for new grants); before 16 a NOINHERIT role inherits through none of its grants. A grant that is not inherited
    // can still be used with SET ROLE (from 16 unless set_option is false; before 16 always), a grant WITH ADMIN lets the member
    // grant the role to itself, and a grant without the flag from a NOINHERIT role (the matrix role itself included) could be
    // either. Those are followed only into st.possible: a cell that depends on a role reached only that way is unknown.
    const flag = v => typeof v === 'boolean' ? v : null;
    const grants = new Map();
    for (const m of dump.members) if (typeof m?.role === 'string' && typeof m?.member === 'string') grants.set(m.member, [...(grants.get(m.member) ?? []), { role: m.role, inherit: flag(m.inherit), set: flag(m.set), admin: m.admin === true }]);
    const follows = (r, grant) => grant.inherit === true ? true : grant.inherit === false ? (grant.set === false && !grant.admin ? false : null)
      : st.catalogRoles.get(r)?.rolinherit === false ? null : true;
    // Before PostgreSQL 16 a CREATEROLE role can grant itself any role but a superuser; from 16 that needs ADMIN on the role,
    // which a grant row shows. A dump without server_version_num is read as before 16.
    const version = Number.isInteger(dump.server_version_num) ? dump.server_version_num : null;
    const selfGrants = r => st.catalogRoles.get(r)?.rolcreaterole === true && !(version !== null && version >= 160000) ? [...st.catalogRoles.keys()].filter(x => !st.catalogRoles.get(x).rolsuper) : [];
    const reach = (role, maybe) => { const seen = new Set([role]), queue = [role], add = r => { if (!seen.has(r)) { seen.add(r); queue.push(r); } };
      while (queue.length) { const r = queue.shift(); for (const grant of grants.get(r) ?? []) { const f = follows(r, grant); if (f === true || (maybe && f === null)) add(grant.role); } if (maybe) selfGrants(r).forEach(add); }
      return seen; };
    st.effective = role => reach(role, false);
    st.possible = role => reach(role, true);
    // SET ROLE needs a chain of grants that allow it (set_option from 16, any grant before), not inheritance. BYPASSRLS and
    // superuser are not inherited, so they are reached only this way.
    st.settable = role => { const seen = new Set([role]), queue = [role], add = r => { if (!seen.has(r)) { seen.add(r); queue.push(r); } };
      while (queue.length) { const r = queue.shift(); for (const grant of grants.get(r) ?? []) if (grant.set !== false || grant.admin) add(grant.role); selfGrants(r).forEach(add); }
      return seen; };
    st.assumptions.add('catalog dump: role attributes and memberships read from pg_roles and pg_auth_members');
  }
  if (Array.isArray(dump.functions)) {
    for (const f of [...dump.functions].filter(f => typeof f?.name === 'string' && typeof f.digest === 'string').sort((a, b) => `${a.schema}.${a.name}.${a.digest}` < `${b.schema}.${b.name}.${b.digest}` ? -1 : 1))
      st.functions.set(f.name, sha256(`${st.functions.get(f.name) ?? ''}|${f.schema}|${f.digest}`).slice(0, 12));
    st.assumptions.add('catalog dump: function definitions are hashed from pg_get_functiondef; helpers a function calls are not followed');
  }
}

// Per command, which expression a policy contributes for each clause: null when the
// policy doesn't cover the command, undefined when it covers it with no expression.
function clauseExpression(policy, command, clause) {
  if (policy.command !== 'ALL' && policy.command !== command) return null;
  if (clause === 'using') return policy.using;
  return policy.check ?? policy.using;
}

function evaluate(st, { roles: declaredRoles = [], bypassRoles = [] }) {
  const cells = [];
  const policyRoles = new Set();
  for (const t of st.tables.values()) for (const p of t.policies.values()) for (const r of p.roles) if (r !== 'public') policyRoles.add(r);
  let roles = [...new Set([...declaredRoles, ...bypassRoles, ...policyRoles])].filter(r => !r.startsWith('<')).sort();
  if (!roles.length) roles = ['public'];
  const gapCites = scope => st.gaps.filter(g => g.scope === '*' || g.scope === scope).map(g => ({ source: g.source, line: g.line, statement: `gap: ${g.reason}` }));
  // Roles each role may reach without inheriting them: by SET ROLE, or through a grant whose flag the dump does not show.
  const unsureOf = new Map(roles.map(role => { const sure = st.effective ? st.effective(role) : new Set([role]); return [role, new Set(st.possible ? [...st.possible(role)].filter(r => !sure.has(r)) : [])]; }));
  // BYPASSRLS or superuser roles each role may SET ROLE to (a role that is one itself is already allow).
  const bypassReach = new Map(roles.map(role => [role, st.settable ? [...st.settable(role)].filter(r => st.catalogRoles.get(r)?.rolbypassrls || st.catalogRoles.get(r)?.rolsuper).sort() : []]));
  for (const t of [...st.tables.values()].sort((a, b) => a.key < b.key ? -1 : 1)) {
    const tableGap = st.gaps.some(g => g.scope === '*' || g.scope === t.key);
    const policies = [...t.policies.values()];
    const special = policies.some(p => p.roles.some(r => r.startsWith('<')));
    // pg_database_owner's one member is the database's owner, implicitly: no grant row shows it, and a dump leaves out pg_
    // roles. Any role could own the database, so a table pg_database_owner owns without FORCE, or a policy aimed at it,
    // decides cells this reader can't.
    const databaseOwnerCites = [...(!t.force && t.owner === 'pg_database_owner' ? [t.ownerCite] : []), ...policies.filter(p => p.roles.includes('pg_database_owner')).map(p => p.cite)];
    for (const role of roles) for (const command of COMMANDS) {
      const base = { role, resource: t.key, action: command };
      let cell;
      const attrs = st.catalogRoles?.get(role);
      if (bypassRoles.includes(role)) cell = { ...base, decision: 'allow', basis: 'bypassrls-declared-by-operator', citations: [{ source: 'operator-options', line: null, statement: `bypassRoles includes ${role}` }] };
      else if (attrs && (attrs.rolbypassrls || attrs.rolsuper)) cell = { ...base, decision: 'allow', basis: attrs.rolsuper ? 'superuser (catalog)' : 'bypassrls (catalog)', citations: [{ source: 'catalog', line: null, statement: `roles[${attrs.index}] ${role}` }] };
      else if (t.rls && t.ownerFromCatalog && !t.force && ownsTable(st, t, role)) cell = { ...base, decision: 'allow', ...(t.owner === role
        ? { basis: 'table owner bypasses RLS (catalog; no FORCE ROW LEVEL SECURITY)', citations: [t.ownerCite] }
        : { basis: `table owner bypasses RLS (catalog; ${role} has the privileges of owner ${t.owner}; no FORCE ROW LEVEL SECURITY)`, citations: [t.ownerCite, { source: 'catalog', line: null, statement: `members: ${role} has the privileges of ${t.owner}` }] }) };
      else if (!t.rls) cell = { ...base, decision: 'undeclared', basis: policies.length ? `rls-not-enabled (${policies.length} polic${policies.length === 1 ? 'y is' : 'ies are'} inert)` : 'rls-not-enabled',
        citations: policies.map(p => p.cite) };
      else cell = decide(base, t, policies, role, command, st);
      if (bypassRoles.includes(role) || ['superuser (catalog)', 'bypassrls (catalog)'].includes(cell.basis) || cell.basis.startsWith('table owner bypasses RLS (catalog')) { if (st.gaps.some(g => g.scope === '*' || g.scope === t.key)) cell = { ...cell, computedDecision: cell.decision, decision: 'unknown', basis: 'source-gap', unknownReasons: ['source-gap'] }; cells.push(cell); continue; }
      // Every reason is kept (unknownReasons), not only the last basis: behind a standing gap the last one is source-gap, and a
      // reason a release adds (an owner that bypasses RLS, a policy for current_user) would otherwise leave no trace in the cell.
      const unknownBecause = (basis, citations) => { cell = { ...cell, computedDecision: cell.computedDecision ?? cell.decision, decision: 'unknown', basis,
        unknownReasons: [...(cell.unknownReasons ?? []), basis], citations: citations.length ? citations : cell.citations }; };
      if (t.rls && special) unknownBecause('policy-targets-current_user-or-session_user', []);
      if (t.rls && !t.force && ownsTable(st, t, role)) unknownBecause(t.owner === role ? 'table-owner-bypasses-rls (no FORCE ROW LEVEL SECURITY)' : 'owning-role-member-bypasses-rls (no FORCE ROW LEVEL SECURITY)', [t.ownerCite]);
      if (t.rls && databaseOwnerCites.length) unknownBecause('pg_database_owner-member-is-implicit (the database owner, any role)', databaseOwnerCites);
      const unsure = unsureOf.get(role);
      if (t.rls && unsure.size && ((!t.force && unsure.has(t.owner)) || policies.some(p => p.roles.some(r => unsure.has(r)))))
        unknownBecause('role-reachable-without-inheritance (SET ROLE, or a NOINHERIT grant with no inherit_option in the dump)', [{ source: 'catalog', line: null, statement: `members: ${role} may reach ${[...unsure].sort().join(', ')}` }]);
      if (t.rls && bypassReach.get(role).length) unknownBecause('role-may-set-role-to-a-bypassrls-or-superuser-role', [{ source: 'catalog', line: null, statement: `members: ${role} may SET ROLE ${bypassReach.get(role).join(', ')}` }]);
      if (st.gaps.some(g => g.scope === `role:${role}`)) unknownBecause('role-membership-or-attributes-changed', gapCites(`role:${role}`));
      if (tableGap) unknownBecause('source-gap', cell.citations.length ? cell.citations : t.cites.length ? t.cites : gapCites(t.key));
      if (cell.decision === 'unknown' && cell.computedDecision === 'unknown') delete cell.computedDecision;
      cells.push(cell);
    }
  }
  return { cells, roles };
}

// Names called in a piece of SQL text, quoted names included, cut to 63 bytes as PostgreSQL cuts them.
const calledIn = text => [...String(text).matchAll(/("(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)\s*\(/g)].map(m => truncateName(m[1].startsWith('"') ? m[1].slice(1, -1).replaceAll('""', '"') : m[1].replace(/[A-Z]+/g, x => x.toLowerCase())));
function decide(base, t, policies, role, command, st = state()) {
  const functions = st.functions;
  // A condition carries the hashes of the functions it calls and, transitively, of the helpers
  // their bodies call (from these files), so a changed definition shows as a changed condition.
  const withBodies = expr => {
    const used = new Set(), queue = calledIn(expr).filter(n => functions.has(n));
    while (queue.length) { const n = queue.shift(); if (used.has(n)) continue; used.add(n); for (const m of calledIn(st.bodies.get(n) ?? '')) if (functions.has(m) && !used.has(m)) queue.push(m); }
    return used.size ? `${expr} {${[...used].sort().map(n => `${n}#${functions.get(n)}`).join(' ')}}` : expr;
  };
  const effective = st.effective ? st.effective(role) : new Set([role]);
  const applies = p => p.roles.includes('public') || p.roles.some(r => effective.has(r));
  const enable = t.cites.length ? [t.cites.at(-1)] : [];
  const conditions = [], citations = [];
  let allTrue = true;
  for (const clause of CLAUSES[command]) {
    const permissive = [], restrictive = [], empty = [];
    for (const p of policies) {
      if (!applies(p)) continue;
      const expr = clauseExpression(p, command, clause);
      if (expr === null) continue;
      if (expr === undefined) { empty.push(p); continue; } // PostgreSQL adds only non-NULL quals: this policy grants nothing here
      (p.permissive ? permissive : restrictive).push({ expr, p });
      citations.push(p.cite);
    }
    const live = permissive.filter(x => x.expr !== 'false');
    if (!live.length) return { ...base, decision: 'deny', basis: permissive.length ? `every applicable permissive policy is false (${clause})` : `rls-default-deny: no permissive policy applies${empty.length ? ' (policies with no expression for this command grant nothing)' : ''}`,
      citations: permissive.length ? permissive.map(x => x.p.cite) : [...enable, ...empty.map(p => p.cite)] };
    if (restrictive.some(x => x.expr === 'false')) return { ...base, decision: 'deny', basis: `a restrictive policy is false (${clause})`, citations: restrictive.filter(x => x.expr === 'false').map(x => x.p.cite) };
    const narrowing = restrictive.filter(x => x.expr !== 'true');
    if (!live.some(x => x.expr === 'true')) { allTrue = false; for (const x of live) conditions.push(`permissive ${clause}: ${withBodies(x.expr)} [${x.p.name}]`); }
    if (narrowing.length) { allTrue = false; for (const x of narrowing) conditions.push(`restrictive ${clause}: ${withBodies(x.expr)} [${x.p.name}]`); }
  }
  const unique = [...new Map(citations.map(c => [`${c.source}:${c.line}:${c.statement}`, c])).values()];
  return allTrue ? { ...base, decision: 'allow', basis: 'permissive-policy-true', citations: unique } : { ...base, decision: 'conditional', basis: 'policy-expressions', conditions, citations: unique };
}

// files: [{ id, content, kind: 'sql' | 'catalog-json' }], applied in the order given.
export function importRls(files, { application, roles = [], bypassRoles = [] } = {}) {
  if (!Array.isArray(files) || !files.length) throw new Error('Give at least one migration file or catalog dump.');
  const st = state(), sources = [];
  for (const file of files) {
    const text = Buffer.isBuffer(file.content) ? file.content.toString('utf8') : String(file.content);
    sources.push(sourceRecord({ id: file.id, kind: file.kind === 'catalog-json' ? 'pg-catalog-json' : 'sql-migration', content: text }));
    if (file.kind === 'catalog-json') {
      let dump; try { dump = JSON.parse(text); } catch { throw new Error(`${file.id} is not valid JSON.`); }
      applyCatalog(st, dump, file.id);
    } else applySql(st, text, file.id);
  }
  const { cells } = evaluate(st, { roles, bypassRoles });
  if (files.some(f => f.kind !== 'catalog-json')) { st.assumptions.add(REPLAY_NOTE); st.assumptions.add(REPLAY_LIMITS); st.assumptions.add(REPLAY_STRINGS); st.assumptions.add(REPLAY_ENCODING); st.assumptions.add(REPLAY_SUCCESS); st.assumptions.add('migration files run in one session, in order: search_path and temporary tables carry from one file to the next'); }
  const assumptions = [...st.assumptions, 'the files given are the complete history for these tables, applied in the order listed',
    'unqualified names resolve against known tables in search_path order (public by default); a new table goes in the first schema listed'];
  if (bypassRoles.length) assumptions.push(`operator declared these roles bypass RLS: ${bypassRoles.join(', ')}`);
  return buildMatrix({ application, layer: LAYER, sources, cells, gaps: placeGaps(st), notEvaluated: [...NOT_EVALUATED], assumptions });
}
