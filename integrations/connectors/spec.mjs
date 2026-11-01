// Stack connectors (scopehaven-connector/1): one declarative file per stack, so a customer on a supported stack gets the
// stack's identity rules, refusal forms, observers, policy importer, packs and reset in one step instead of an assessor
// writing them per company. `scopehaven init --stack NAME` reads one (integrations/init/stack.mjs).
//
// A connector file (catalog/<stack>.json) holds:
//   schema, stack, title, kind ("http" | "payments" | "model"), summary
//   identity     http: how a signed-in actor is carried (credential slot, gateway headers every request also needs), the
//                who-am-I routes to try with the pointer that names the user, and what a signed-out who-am-I answers
//   refusals     how the stack refuses a read: each { status, body, means }. A 2xx refusal must name its body shape
//                ("empty-array", "null", "empty"): a boundary check on such a stack judges the body or the row, never the
//                status alone (PostgREST answers a row that row-level security hides with 200 [] and an UPDATE it filters
//                with 204, never 403)
//   records      http: path templates the stack's record reads follow, so init can name the table and key an observer
//                watches without asking ("{table}", "{key}" and "{id}" are the only placeholders)
//   observers    each { type, role, source, why, defaults, credentialEnvSuffix?, setup? }: the observer types the stack
//                exposes on loopback, which window source decides with them, and whether it may decide an absence on a
//                boundary row (role "absence": its custody holds for an absence) or only presence and allowed-use controls
//   backendRow   http: how init's backend row is decided ({ observer, clauses, title }), or null when no observer can decide
//                it. clauses are the ones init may use: record-row-unchanged (no committed change to the record's row; init uses
//                it with the owner's write twin, which shows the row pin selects) and record-table-unchanged (none to its
//                table; init uses it on a check that expects a refusal status, where an unpinned absence needs no twin)
//   policyImporter  the integrations/policy-import source kind and where the stack keeps its declarations, or null
//   rules        stack identity rules the profile may carry (supabaseRules: the service roles that bypass row-level security)
//   packs        the default check packs (integrations/packs-v2/packs/<name>) and, for payments, the payments pack
//   payments     payments: the provider double, the app's client environment names and the routes the pack reads
//   model        model: the protocol, the base-URL environment names a framework reads, and what the model path holds
//   reset        the command that returns a disposable copy to its seed ({ argv, cwd, note }), or null
//   limits       what the connector does not do, in plain words
//
// The loader is strict: every object's keys are listed, every string is bounded, unknown keys and schemas are refused, and
// an observer type must be one the connector builds (src/http-effects.mjs OBSERVER_TYPES). It never reads an environment
// value or a credential: environment entries are names, and credential entries are SCOPEHAVEN_TARGET_ suffixes.
// Pure apart from readConnector and listConnectors, which read the catalog folder only.
import { readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { OBSERVER_TYPES, OBSERVER_OUTPUT, SETTLE_BOUNDS } from '../../src/http-effects.mjs';
import { credentialHeaderProblem } from '../../src/contracts.mjs';
import { CUSTODY_BY_SOURCE, INDEPENDENT_CUSTODY } from '../../src/custody.mjs';

export const CONNECTOR_SCHEMA = 'scopehaven-connector/1';
export const CONNECTOR_KINDS = Object.freeze(['http', 'payments', 'model']);
export const BODY_FORMS = Object.freeze(['any', 'empty-array', 'null', 'empty']);
export const OBSERVER_ROLES = Object.freeze(['absence', 'presence']);
export const BACKEND_CLAUSES = Object.freeze(['record-row-unchanged', 'record-table-unchanged']);
export const POLICY_SOURCES = Object.freeze(['rls', 'openapi', 'openwebui']);
export const MODEL_PROTOCOLS = Object.freeze(['chat-completions']);
export const CONNECTOR_LIMITS = Object.freeze({ fileBytes: 64 * 1024 });
// The profile fields a connector's observer defaults may set, per observer type: the connection, and the settle and barrier
// timings within the product's own bounds (init --stack reports the timings as assumptions in stack-report.json, since a window
// counts as complete when the app commits within settleMs). Everything else (type, id, tables, the credential, and the fields
// that change what a window may leave out or wait for on the platform's side: ignore, queues, runLease, the drain and poll
// timings, actorCapture) comes from init or the operator, never from a connector.
// The product's bounds for each timing or size default (src/http-effects.mjs SETTLE_BOUNDS, src/contracts.mjs), so a connector
// value the profile check would refuse is refused here, before init sends anything.
export const DEFAULT_BOUNDS = Object.freeze({ settleMs: Object.freeze([SETTLE_BOUNDS.minMs, SETTLE_BOUNDS.maxMs]), barrierMs: Object.freeze([100, 30000]),
  statementTimeoutMs: Object.freeze([500, 60000]), rowsPerTable: Object.freeze([1, 200000]) });
export const DEFAULT_KEYS = Object.freeze({
  'pg-wal': Object.freeze(['host', 'port', 'database', 'platform', 'settleMs', 'barrierMs', 'statementTimeoutMs']),
  'pg-snapshot': Object.freeze(['host', 'port', 'database', 'platform', 'settleMs', 'rowsPerTable', 'statementTimeoutMs']),
  'mysql-snapshot': Object.freeze(['host', 'port', 'database', 'settleMs']),
});
// The live checks an unloggedTables entry may name (integrations/init/stack.mjs runs them on the copy, under the record, and
// reports what they found; nothing is ignored on them).
export const LIVE_CHECKS = Object.freeze(['pg_net']);
// Each live check covers one table only (pg_net: its own unlogged request queue).
export const LIVE_CHECK_ENTRIES = Object.freeze({ pg_net: 'net.http_request_queue' });
// And the file half of each check: the strings a declaration that uses it must be scanned for, and the folder it must scan.
export const LIVE_CHECK_FILES = Object.freeze({ pg_net: Object.freeze({ usedBy: Object.freeze(['net.http_', 'pg_net', 'supabase_functions.http_request', 'http_post(', 'http_get(', 'http_delete(', 'http_collect_response(']), scan: 'supabase/migrations' }) });
export const CATALOG_DIR = fileURLToPath(new URL('./catalog/', import.meta.url));
const PACKS_DIR = fileURLToPath(new URL('../packs-v2/packs/', import.meta.url));
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const STACK = /^[a-z][a-z0-9-]{1,39}$/;
const ENV_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;
const ENV_SUFFIX = /^[A-Z][A-Z0-9_]{0,31}$/;
const POINTER = /^(\/([^~/]|~[01])*)*$/;
const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const PLACEHOLDERS = ['table', 'key', 'id'];

export class ConnectorError extends Error {
  constructor(where, message) { super(`${where}: ${message}`); this.name = 'ConnectorError'; this.where = where; }
}
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
function shape(value, where, required, optional = []) {
  if (!plain(value)) throw new ConnectorError(where, 'must be an object');
  for (const key of required) if (!Object.hasOwn(value, key)) throw new ConnectorError(where, `is missing "${key}"`);
  const unknown = Object.keys(value).filter(key => ![...required, ...optional].includes(key));
  if (unknown.length) throw new ConnectorError(where, `has unknown key "${String(unknown[0]).slice(0, 40)}"`);
}
function text(value, where, max = 400) {
  if (typeof value !== 'string' || !value.trim() || value.length > max) throw new ConnectorError(where, `must be a nonempty string up to ${max} characters`);
  return value;
}
function list(value, where, { min = 0, max = 16, item }) {
  if (!Array.isArray(value) || value.length < min || value.length > max) throw new ConnectorError(where, `must be a list of ${min} to ${max} entries`);
  value.forEach((v, i) => item(v, `${where}[${i}]`));
  return value;
}
const oneOf = (value, where, allowed) => { if (!allowed.includes(value)) throw new ConnectorError(where, `must be one of ${allowed.join(', ')}`); return value; };
const statusCode = (value, where) => { if (!Number.isInteger(value) || value < 100 || value > 599) throw new ConnectorError(where, 'must be an HTTP status from 100 to 599'); return value; };
const ok = status => status >= 200 && status < 300;

// A safe app path: absolute, no "//", "." or ".." segment, space, backslash or fragment (as init's probe paths).
function appPath(value, where) {
  text(value, where, 512);
  if (!value.startsWith('/') || value.includes('//') || value.includes('#') || value.includes('\\') || /[\u0000- \u007f]/.test(value) || value.split('?')[0].split('/').some(s => s === '.' || s === '..')) throw new ConnectorError(where, 'must be an absolute app path with no "//", "." or ".." segment, space or fragment');
  return value;
}
function slot(value, where) {
  if (value === 'bearer') return value;
  const m = /^(cookie|header):([A-Za-z0-9!#$%&'*+.^_`|~-]{1,128})$/.exec(typeof value === 'string' ? value : '');
  if (!m) throw new ConnectorError(where, 'must be bearer, cookie:NAME or header:NAME');
  if (m[1] === 'header' && credentialHeaderProblem(m[2].toLowerCase()) !== null) throw new ConnectorError(where, 'names a header the connector, HTTP framing or a proxy owns');
  return value;
}

function validateIdentity(identity, where) {
  shape(identity, where, ['credential', 'whoami', 'signedOut'], ['gatewayHeaders']);
  slot(identity.credential, `${where}.credential`);
  if (Object.hasOwn(identity, 'gatewayHeaders')) list(identity.gatewayHeaders, `${where}.gatewayHeaders`, { max: 4, item: (g, w) => {
    shape(g, w, ['header', 'envSuffix', 'required', 'why']);
    if (typeof g.header !== 'string' || credentialHeaderProblem(g.header) !== null || g.header !== g.header.toLowerCase()) throw new ConnectorError(`${w}.header`, 'must be a lower-case header name a credential may use (not Host, Cookie, Authorization or a proxy header)');
    if (!ENV_SUFFIX.test(g.envSuffix)) throw new ConnectorError(`${w}.envSuffix`, 'must be an upper-case SCOPEHAVEN_TARGET_<APP>_ suffix');
    if (typeof g.required !== 'boolean') throw new ConnectorError(`${w}.required`, 'must be true or false');
    text(g.why, `${w}.why`);
  } });
  const headers = (identity.gatewayHeaders ?? []).map(g => g.header);
  if (new Set(headers).size !== headers.length) throw new ConnectorError(`${where}.gatewayHeaders`, 'names a header twice');
  if (identity.credential.startsWith('header:') && headers.includes(identity.credential.slice(7).toLowerCase())) throw new ConnectorError(`${where}.gatewayHeaders`, 'repeats the credential header');
  list(identity.whoami, `${where}.whoami`, { min: 1, max: 8, item: (w0, w) => {
    shape(w0, w, ['path', 'pointer']);
    appPath(w0.path, `${w}.path`);
    if (typeof w0.pointer !== 'string' || !POINTER.test(w0.pointer) || !w0.pointer) throw new ConnectorError(`${w}.pointer`, 'must be a nonempty JSON pointer');
  } });
  list(identity.signedOut, `${where}.signedOut`, { min: 1, max: 4, item: (s, w) => { statusCode(s, w); if (ok(s)) throw new ConnectorError(w, 'a signed-out who-am-I must not answer 2xx'); } });
}

function validateRefusals(refusals, where) {
  list(refusals, where, { min: 1, max: 8, item: (r, w) => {
    shape(r, w, ['status', 'body', 'means']);
    statusCode(r.status, `${w}.status`);
    oneOf(r.body, `${w}.body`, BODY_FORMS);
    // The rule the whole spec exists for: a 2xx refusal is judged by its body, never by its status.
    if (ok(r.status) && r.body === 'any') throw new ConnectorError(`${w}.body`, 'a 2xx refusal must name its body shape (empty-array, null or empty): a status alone cannot tell a hidden row from a served one');
    if (!ok(r.status) && r.body !== 'any') throw new ConnectorError(`${w}.body`, 'a non-2xx refusal is judged by its status, so its body is "any"');
    text(r.means, `${w}.means`);
  } });
  const keys = refusals.map(r => `${r.status}:${r.body}`);
  if (new Set(keys).size !== keys.length) throw new ConnectorError(where, 'lists one refusal twice');
}

function validateRecords(records, where) {
  shape(records, where, ['templates']);
  list(records.templates, `${where}.templates`, { min: 1, max: 8, item: (t, w) => {
    if (typeof t !== 'string') throw new ConnectorError(w, 'must be a path template string');
    appPath(t.replace(/\{(table|key|id)\}/g, 'x'), w);
    const names = [...t.matchAll(/\{([^}]*)\}/g)].map(m => m[1]);
    if (names.some(n => !PLACEHOLDERS.includes(n)) || !names.includes('table') || !names.includes('id') || new Set(names).size !== names.length) throw new ConnectorError(w, 'uses {table} and {id} once each, {key} at most once, and no other placeholder');
  } });
}

function validateObservers(observers, where) {
  list(observers, where, { max: 8, item: (o, w) => {
    shape(o, w, ['type', 'role', 'source', 'why', 'defaults'], ['credentialEnvSuffix', 'setup', 'unloggedTables']);
    oneOf(o.type, `${w}.type`, OBSERVER_TYPES);
    oneOf(o.role, `${w}.role`, OBSERVER_ROLES);
    if (o.source !== OBSERVER_OUTPUT[o.type]?.source) throw new ConnectorError(`${w}.source`, `is the window source ${o.type} writes (${OBSERVER_OUTPUT[o.type]?.source})`);
    // Only a source whose custody can support a pass may decide a boundary row's absence (src/custody.mjs): a record the
    // application can write (its database rows, its audit table) never decides one.
    if (o.role === 'absence' && !INDEPENDENT_CUSTODY.includes(CUSTODY_BY_SOURCE[o.source])) throw new ConnectorError(`${w}.role`, 'only an observer held outside the application (pg-wal, the egress recorder, the SMTP sink, a provider feed) decides an absence on a boundary row');
    text(o.why, `${w}.why`);
    if (!plain(o.defaults)) throw new ConnectorError(`${w}.defaults`, 'must be an object');
    const allowedDefaults = DEFAULT_KEYS[o.type] ?? [];
    for (const [key, value] of Object.entries(o.defaults)) {
      if (!allowedDefaults.includes(key)) throw new ConnectorError(`${w}.defaults`, `may not set "${String(key).slice(0, 32)}" on ${o.type}${allowedDefaults.length ? ` (only ${allowedDefaults.join(', ')})` : ''}; type, id, tables, the credential and what a window may leave out come from init or the operator`);
      const at = `${w}.defaults.${key}`;
      if (key === 'host' && value !== '127.0.0.1') throw new ConnectorError(at, 'must be the literal 127.0.0.1');
      if (key === 'port' && !(Number.isInteger(value) && value >= 1 && value <= 65535)) throw new ConnectorError(at, 'must be a TCP port');
      if (key === 'database' && !(typeof value === 'string' && IDENT.test(value))) throw new ConnectorError(at, 'must be a database name');
      if (key === 'platform' && !['none', 'supabase'].includes(value)) throw new ConnectorError(at, 'must be none or supabase (a checked-in ignore list)');
      const bounds = DEFAULT_BOUNDS[key];
      if (bounds && !(Number.isInteger(value) && value >= bounds[0] && value <= bounds[1])) throw new ConnectorError(at, `must be an integer from ${bounds[0]} to ${bounds[1]} (the product's bounds)`);
    }
    if (Object.hasOwn(o, 'credentialEnvSuffix') && !ENV_SUFFIX.test(o.credentialEnvSuffix)) throw new ConnectorError(`${w}.credentialEnvSuffix`, 'must be an upper-case SCOPEHAVEN_TARGET_<APP>_ suffix');
    if (Object.hasOwn(o, 'setup')) list(o.setup, `${w}.setup`, { min: 1, max: 12, item: (s, w2) => text(s, w2, 600) });
    // A platform table the observer cannot read (pg_net's unlogged request queue): the WAL never carries it, so while it exists
    // every window reads partial. init --stack never ignores it; it runs the entry's file scan and live check and reports what
    // they found as the reason the windows stay partial (an entry is listed only once its requests are observed on the wire).
    if (Object.hasOwn(o, 'unloggedTables')) {
      if (!['pg-wal', 'pg-snapshot'].includes(o.type)) throw new ConnectorError(`${w}.unloggedTables`, 'is for a database observer');
      list(o.unloggedTables, `${w}.unloggedTables`, { min: 1, max: 4, item: (g, w2) => {
        shape(g, w2, ['entry', 'usedBy', 'live', 'scan', 'why']);
        oneOf(g.live, `${w2}.live`, LIVE_CHECKS);
        list(g.scan, `${w2}.scan`, { min: 1, max: 8, item: (x, w3) => { text(x, w3, 200); if (x.startsWith('/') || x.split('/').includes('..')) throw new ConnectorError(w3, 'is a path inside the app folder'); } });
        if (typeof g.entry !== 'string' || !/^[a-z_][a-z0-9_]{0,62}\.[a-z_][a-z0-9_]{0,62}$/.test(g.entry)) throw new ConnectorError(`${w2}.entry`, 'must be schema.table');
        if (g.entry !== LIVE_CHECK_ENTRIES[g.live]) throw new ConnectorError(`${w2}.entry`, `must be the table its live check covers (${g.live}: ${LIVE_CHECK_ENTRIES[g.live]})`);
        list(g.usedBy, `${w2}.usedBy`, { min: 1, max: 8, item: (u, w3) => text(u, w3, 64) });
        const files = LIVE_CHECK_FILES[g.live];
        if (!files.usedBy.every(u => g.usedBy.includes(u))) throw new ConnectorError(`${w2}.usedBy`, `must list every string its live check's file half scans for (${files.usedBy.join(', ')})`);
        if (!g.scan.includes(files.scan)) throw new ConnectorError(`${w2}.scan`, `must include ${files.scan}`);
        text(g.why, `${w2}.why`);
      } });
    }
  } });
  const types = observers.map(o => o.type);
  if (new Set(types).size !== types.length) throw new ConnectorError(where, 'lists one observer type twice');
}

function validateBackendRow(row, where, observers) {
  if (row === null) return;
  shape(row, where, ['observer', 'clauses', 'title']);
  const observer = observers.find(o => o.type === row.observer);
  if (!observer) throw new ConnectorError(`${where}.observer`, 'must name one of the connector\'s observers');
  if (observer.role !== 'absence') throw new ConnectorError(`${where}.observer`, 'a backend row on a boundary check is decided by an observer whose role is "absence"');
  // init wires the row as a database observer on the record's table, with its own credential and the port it dials.
  if (!['pg-wal', 'pg-snapshot', 'mysql-snapshot'].includes(observer.type) || typeof observer.defaults?.host !== 'string' || !Number.isInteger(observer.defaults?.port) || !Object.hasOwn(observer, 'credentialEnvSuffix')) throw new ConnectorError(`${where}.observer`, 'must be a database observer with a default host and port and a credentialEnvSuffix');
  list(row.clauses, `${where}.clauses`, { min: 1, max: 2, item: (c, w) => oneOf(c, w, BACKEND_CLAUSES) });
  if (new Set(row.clauses).size !== row.clauses.length) throw new ConnectorError(`${where}.clauses`, 'lists one clause twice');
  text(row.title, `${where}.title`, 200);
}

function validatePolicyImporter(p, where) {
  if (p === null) return;
  shape(p, where, ['source', 'paths'], ['roles', 'bypassRoles']);
  oneOf(p.source, `${where}.source`, POLICY_SOURCES);
  list(p.paths, `${where}.paths`, { min: 1, max: 8, item: (s, w) => { text(s, w, 200); if (s.startsWith('/') || s.split('/').includes('..')) throw new ConnectorError(w, 'is a path inside the app folder'); } });
  for (const key of ['roles', 'bypassRoles']) if (Object.hasOwn(p, key)) list(p[key], `${where}.${key}`, { min: 1, max: 12, item: (r, w) => { if (!IDENT.test(r)) throw new ConnectorError(w, 'must be a role name'); } });
}

function validateRules(rules, where) {
  shape(rules, where, [], ['supabaseRules']);
  if (Object.hasOwn(rules, 'supabaseRules')) {
    shape(rules.supabaseRules, `${where}.supabaseRules`, ['serviceRoles', 'needs']);
    list(rules.supabaseRules.serviceRoles, `${where}.supabaseRules.serviceRoles`, { min: 1, max: 8, item: (r, w) => { if (!IDENT.test(r)) throw new ConnectorError(w, 'must be a role name'); } });
    text(rules.supabaseRules.needs, `${where}.supabaseRules.needs`);
  }
}

function validatePacks(packs, where, { packsDir = PACKS_DIR } = {}) {
  let shipped;
  try { shipped = new Set(readdirSync(packsDir, { withFileTypes: true }).filter(e => e.isDirectory()).map(e => e.name)); } catch { shipped = new Set(); }
  list(packs, where, { max: 8, item: (p, w) => {
    if (p === 'payments-pack') return;
    if (typeof p !== 'string' || !/^[a-z][a-z0-9-]{1,63}$/.test(p) || !shipped.has(p)) throw new ConnectorError(w, 'must name a shipped pack (integrations/packs-v2/packs/<name>) or "payments-pack"');
  } });
  if (new Set(packs).size !== packs.length) throw new ConnectorError(where, 'lists one pack twice');
}

function validatePayments(p, where) {
  shape(p, where, ['provider', 'clientEnv', 'routePrefix', 'witnessPrefix', 'runsIn']);
  oneOf(p.provider, `${where}.provider`, ['payments-double']);
  list(p.clientEnv, `${where}.clientEnv`, { min: 1, max: 8, item: (n, w) => { if (!ENV_NAME.test(n)) throw new ConnectorError(w, 'must be an environment variable name'); } });
  appPath(p.routePrefix, `${where}.routePrefix`);
  appPath(p.witnessPrefix, `${where}.witnessPrefix`);
  oneOf(p.runsIn, `${where}.runsIn`, ['assess', 'payments-command']);
}

function validateModel(m, where) {
  shape(m, where, ['protocol', 'baseUrlEnv', 'holds', 'templates']);
  oneOf(m.protocol, `${where}.protocol`, MODEL_PROTOCOLS);
  list(m.baseUrlEnv, `${where}.baseUrlEnv`, { min: 1, max: 8, item: (n, w) => { if (!ENV_NAME.test(n)) throw new ConnectorError(w, 'must be an environment variable name'); } });
  text(m.holds, `${where}.holds`);
  list(m.templates, `${where}.templates`, { min: 1, max: 16, item: (t, w) => { if (typeof t !== 'string' || !/^[A-Z][A-Z0-9-]{1,63}$/.test(t)) throw new ConnectorError(w, 'must be a class template code'); } });
}

function validateReset(r, where) {
  if (r === null) return;
  shape(r, where, ['argv', 'cwd', 'note']);
  list(r.argv, `${where}.argv`, { min: 1, max: 8, item: (a, w) => { text(a, w, 64); if (/[;&|`$<>]/.test(a)) throw new ConnectorError(w, 'is a plain argument (no shell syntax)'); } });
  oneOf(r.cwd, `${where}.cwd`, ['app']);
  text(r.note, `${where}.note`);
}

// Validates one parsed connector; returns it frozen, or throws a ConnectorError naming the first problem.
export function validateConnector(c, { file, packsDir } = {}) {
  const where = file ?? 'connector';
  shape(c, where, ['schema', 'stack', 'title', 'kind', 'summary', 'observers', 'packs', 'reset', 'limits'], ['identity', 'refusals', 'records', 'backendRow', 'policyImporter', 'rules', 'payments', 'model']);
  if (c.schema !== CONNECTOR_SCHEMA) throw new ConnectorError(`${where}.schema`, `must be ${CONNECTOR_SCHEMA}`);
  if (typeof c.stack !== 'string' || !STACK.test(c.stack)) throw new ConnectorError(`${where}.stack`, 'must be 2 to 40 lower-case letters, digits or "-"');
  text(c.title, `${where}.title`, 120);
  oneOf(c.kind, `${where}.kind`, CONNECTOR_KINDS);
  text(c.summary, `${where}.summary`, 800);
  // Each kind carries its own sections and no other kind's.
  const sections = { http: ['identity', 'refusals', 'records', 'backendRow'], payments: ['payments'], model: ['model'] };
  for (const [kind, keys] of Object.entries(sections)) for (const key of keys) {
    if (kind === c.kind && !Object.hasOwn(c, key) && key !== 'records') throw new ConnectorError(where, `a ${c.kind} connector needs "${key}"`);
    if (kind !== c.kind && Object.hasOwn(c, key)) throw new ConnectorError(where, `"${key}" belongs to a ${kind} connector, not a ${c.kind} one`);
  }
  if (c.kind === 'http') { validateIdentity(c.identity, `${where}.identity`); validateRefusals(c.refusals, `${where}.refusals`); if (Object.hasOwn(c, 'records')) validateRecords(c.records, `${where}.records`); }
  validateObservers(c.observers, `${where}.observers`);
  if (c.kind === 'http') validateBackendRow(c.backendRow, `${where}.backendRow`, c.observers);
  if (Object.hasOwn(c, 'policyImporter')) validatePolicyImporter(c.policyImporter, `${where}.policyImporter`);
  if (Object.hasOwn(c, 'rules')) validateRules(c.rules, `${where}.rules`);
  validatePacks(c.packs, `${where}.packs`, { packsDir });
  if (c.kind === 'payments') { validatePayments(c.payments, `${where}.payments`); if (!c.packs.includes('payments-pack')) throw new ConnectorError(`${where}.packs`, 'a payments connector ships the payments pack'); }
  else if (c.packs.includes('payments-pack')) throw new ConnectorError(`${where}.packs`, 'only a payments connector ships the payments pack');
  if (c.kind === 'model') validateModel(c.model, `${where}.model`);
  validateReset(c.reset, `${where}.reset`);
  list(c.limits, `${where}.limits`, { min: 1, max: 16, item: (s, w) => text(s, w, 600) });
  return deepFreeze(structuredClone(c));
}
const deepFreeze = v => { if (v && typeof v === 'object') { Object.values(v).forEach(deepFreeze); Object.freeze(v); } return v; };

// Parses connector bytes (a regular file's, bounded) and validates them; the file name must be the stack's.
export function parseConnector(bytes, { file = 'connector', packsDir } = {}) {
  if (bytes.length > CONNECTOR_LIMITS.fileBytes) throw new ConnectorError(file, `is larger than ${CONNECTOR_LIMITS.fileBytes} bytes`);
  let parsed;
  try { parsed = JSON.parse(Buffer.isBuffer(bytes) ? bytes.toString('utf8') : bytes); } catch { throw new ConnectorError(file, 'is not valid JSON'); }
  const c = validateConnector(parsed, { file, packsDir });
  if (file.endsWith('.json') && file.replace(/^.*\//, '') !== `${c.stack}.json`) throw new ConnectorError(file, `is named for its stack (${c.stack}.json)`);
  return c;
}

// The shipped connectors, by stack name.
export function listConnectors(dir = CATALOG_DIR) {
  return readdirSync(dir, { withFileTypes: true }).filter(e => e.isFile() && e.name.endsWith('.json')).map(e => e.name.slice(0, -5)).sort();
}

// Reads one shipped connector by stack name, with the sha256 of the bytes it validated. A name that is not shipped is refused
// before any file is opened.
export async function loadConnector(stack, { dir = CATALOG_DIR } = {}) {
  if (typeof stack !== 'string' || !STACK.test(stack)) throw new ConnectorError('--stack', 'is 2 to 40 lower-case letters, digits or "-"');
  const shipped = listConnectors(dir);
  if (!shipped.includes(stack)) throw new ConnectorError('--stack', `"${stack}" is not a shipped connector (shipped: ${shipped.join(', ')})`);
  const bytes = await readFile(join(dir, `${stack}.json`));
  return { connector: parseConnector(bytes, { file: `${stack}.json` }), sha256: createHash('sha256').update(bytes).digest('hex') };
}
export const readConnector = async (stack, options) => (await loadConnector(stack, options)).connector;

// The app path of a record under one of the connector's templates: { table, key, id } or null. Only an exact template
// match counts; a query string other than the template's own is no match.
export function matchRecord(connector, path) {
  for (const template of connector.records?.templates ?? []) {
    const names = [];
    const pattern = template.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\{(table|key|id)\}/g, (_, name) => { names.push(name); return name === 'id' ? '([^/?&#]+)' : '([A-Za-z_][A-Za-z0-9_]{0,62})'; });
    const m = new RegExp(`^${pattern}$`).exec(path);
    if (!m) continue;
    const found = Object.fromEntries(names.map((name, i) => [name, m[i + 1]]));
    let id;
    try { id = decodeURIComponent(found.id); } catch { continue; }
    return { table: found.table, key: found.key ?? 'id', id };
  }
  return null;
}

export const ROOT_DIR = ROOT;
