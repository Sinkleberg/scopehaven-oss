// Write binding (goal 03, scopehaven-policy-write-binding/1): how the operator's stated resources and actions reach the
// application for write cases. Named so it never reads as a successor to the read-only binding /1 that draft.mjs still
// requires. It says where each request goes, how a refusal looks, which observed effect decides it, how each object is
// created, prechecked and reverted, which actors stand for which role and tenant, and the budget. It states no intent:
// what should happen comes only from the sealed statement (statement.mjs). Configuration, not code: nothing here names
// an application. Local only.
import { HTTP_CHECK_METHODS, HTTP_WRITE_METHODS } from '../../src/contracts.mjs';
import { OPERATIONS, PRESENCE_ONLY_SOURCES, SOURCES, REPORT_ONLY_SOURCES } from '../../src/effect-events.mjs';
import { canonical, sha256 } from './matrix.mjs';

export const WRITE_BINDING_SCHEMA = 'scopehaven-policy-write-binding/1';
export const REFUSAL_KINDS = Object.freeze(['status', 'silent']);
// Placeholders a template may use, each a whole path segment or a whole body string value. The case fills them.
export const PLACEHOLDERS = Object.freeze(['id', 'actor', 'tenant']);
export const BUDGET_DEFAULTS = Object.freeze({ maxCases: 50, inventoryLimit: 5000 });
export const BUDGET_LIMITS = Object.freeze({ maxCases: 500, inventoryLimit: 100000, settleMs: 10000 });
// How a SQL snapshot decides an update's absence: a change column the operator audited, or Postgres row versions (xmin).
export const EXACTNESS = Object.freeze(['change-column', 'xmin']);

const IDENT = /^[A-Za-z0-9_.-]{1,80}$/;
const POINTER = /^(\/[^/~]*(~[01][^/~]*)*)+$/;
const SAFE_SEGMENT = /^[A-Za-z0-9._~!$&'()*+,;=:@%-]+$/;
const PLACEHOLDER = /^\{\{([a-z]+)\}\}$/;
const fail = message => { throw new Error(`write binding: ${message}`); };
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const name = (v, max = 200) => typeof v === 'string' && v.length >= 1 && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v);
const onlyKeys = (o, keys, where) => { const extra = Object.keys(o).filter(k => !keys.includes(k)); if (extra.length) fail(`${where} has unknown field${extra.length === 1 ? '' : 's'} ${extra.join(', ')}`); };
const own = (map, key) => (plain(map) && Object.hasOwn(map, key) ? map[key] : undefined);
const status = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;

// A path template: absolute, every segment either safe literal text or one whole placeholder, at most one query.
function pathTemplate(t, where) {
  if (typeof t !== 'string' || !t.startsWith('/') || t.startsWith('//') || t.length > 400) fail(`${where}: pathTemplate is an absolute path`);
  const [path, query, extra] = t.split('?');
  if (extra !== undefined) fail(`${where}: pathTemplate has at most one "?"`);
  const used = [];
  for (const seg of path.split('/').slice(1)) {
    if (seg === '') continue;
    const m = PLACEHOLDER.exec(seg);
    if (m) { if (!PLACEHOLDERS.includes(m[1])) fail(`${where}: unknown placeholder {{${m[1]}}} (${PLACEHOLDERS.join(', ')})`); used.push(m[1]); }
    else if (seg.includes('{') || seg.includes('}') || !SAFE_SEGMENT.test(seg) || seg === '.' || seg === '..') fail(`${where}: a path segment is literal text or one whole {{placeholder}}`);
  }
  if (query !== undefined && (query.includes('{') || !/^[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$/.test(query))) fail(`${where}: the query is literal text`);
  return used;
}
// A body template: a JSON object whose placeholders are whole string values, never keys.
function bodyTemplate(b, where) {
  const used = [];
  const walk = v => {
    if (typeof v === 'string') { const m = PLACEHOLDER.exec(v); if (m) { if (!PLACEHOLDERS.includes(m[1])) fail(`${where}: unknown placeholder {{${m[1]}}}`); used.push(m[1]); } else if (v.includes('{{')) fail(`${where}: a placeholder is a whole string value`); return; }
    if (Array.isArray(v)) return v.forEach(walk);
    if (plain(v)) { for (const [k, x] of Object.entries(v)) { if (k.includes('{{')) fail(`${where}: a placeholder never goes in a body key`); walk(x); } return; }
    if (!(v === null || typeof v === 'number' || typeof v === 'boolean')) fail(`${where}: the body is JSON`);
  };
  if (!plain(b)) fail(`${where}: bodyTemplate is a JSON object`);
  walk(b);
  if (Buffer.byteLength(JSON.stringify(b)) > 8192) fail(`${where}: bodyTemplate exceeds 8 KiB`);
  return used;
}

function validateRoute(r, where) {
  if (!plain(r)) fail(`${where} is { method, pathTemplate, object, allowStatus, refusal, bodyTemplate?, consumes?, transition? }`);
  onlyKeys(r, ['method', 'pathTemplate', 'bodyTemplate', 'object', 'allowStatus', 'refusal', 'consumes', 'transition'], where);
  if (!HTTP_CHECK_METHODS.includes(r.method)) fail(`${where}: method is ${HTTP_CHECK_METHODS.join(', ')}`);
  const used = pathTemplate(r.pathTemplate, where);
  if (r.bodyTemplate !== undefined) {
    if (!HTTP_WRITE_METHODS.includes(r.method)) fail(`${where}: only a write method (${HTTP_WRITE_METHODS.join(', ')}) carries a body`);
    used.push(...bodyTemplate(r.bodyTemplate, where));
  }
  if (r.object !== null && !(typeof r.object === 'string' && IDENT.test(r.object))) fail(`${where}: object names the object type the request acts on, or is null for a create on a collection`);
  // A request on an existing object names it; a create on a collection names none.
  if (r.object !== null && !used.includes('id')) fail(`${where}: a request on an object puts {{id}} in its path or body`);
  if (r.object === null && used.includes('id')) fail(`${where}: {{id}} needs the object the request acts on`);
  if (!status(r.allowStatus, 200, 299)) fail(`${where}: allowStatus is a 2xx status`);
  const f = r.refusal;
  if (!plain(f) || !REFUSAL_KINDS.includes(f.kind)) fail(`${where}: refusal is { kind: "status", statuses, notFoundIsRefusal? } or { kind: "silent", status }`);
  if (f.kind === 'status') {
    onlyKeys(f, ['kind', 'statuses', 'notFoundIsRefusal'], `${where} refusal`);
    // A 5xx is never a refusal; a 404 is one only when the operator says so (otherwise a missing record reads refused).
    if (!Array.isArray(f.statuses) || f.statuses.length < 2 || f.statuses.length > 5 || new Set(f.statuses).size !== f.statuses.length || !f.statuses.every(s => status(s, 400, 499)))
      fail(`${where}: refusal.statuses lists 2 to 5 distinct 4xx statuses (a 5xx is never a refusal)`);
    if (f.notFoundIsRefusal !== undefined && typeof f.notFoundIsRefusal !== 'boolean') fail(`${where}: refusal.notFoundIsRefusal is true or false`);
    if (f.statuses.includes(404) && f.notFoundIsRefusal !== true) fail(`${where}: 404 is a refusal only with notFoundIsRefusal: true`);
  } else {
    onlyKeys(f, ['kind', 'status'], `${where} refusal`);
    if (!status(f.status, 200, 299)) fail(`${where}: a silent refusal answers a 2xx status`);
  }
  if (r.consumes !== undefined && typeof r.consumes !== 'boolean') fail(`${where}: consumes is true or false`);
  if (r.method === 'DELETE' && r.consumes === false) fail(`${where}: a DELETE consumes its object`);
  if (r.transition !== undefined && !(typeof r.transition === 'string' && IDENT.test(r.transition))) fail(`${where}: transition names the lifecycle transition this route performs`);
  return { ...r, consumes: r.consumes ?? r.method === 'DELETE' };
}

function validateEffect(e, where) {
  if (!plain(e)) fail(`${where} is { source, operation, name, resourceTemplate?, actorAttributed, exactness? }`);
  onlyKeys(e, ['source', 'operation', 'name', 'resourceTemplate', 'actorAttributed', 'exactness'], where);
  if (!SOURCES.includes(e.source) || REPORT_ONLY_SOURCES.includes(e.source)) fail(`${where}: source is one of ${SOURCES.filter(s => !REPORT_ONLY_SOURCES.includes(s)).join(', ')}`);
  if (!OPERATIONS.includes(e.operation)) fail(`${where}: operation is one of ${OPERATIONS.join(', ')}`);
  // A prefix name is accepted here and classified later (prefix-effect-name): a prefix cannot decide absence.
  if (!(name(e.name, 128) || (plain(e.name) && Object.keys(e.name).length === 1 && name(e.name.prefix, 128)))) fail(`${where}: name is the exact effect name, or { prefix }`);
  if (e.resourceTemplate !== undefined && !(name(e.resourceTemplate, 200) && [...e.resourceTemplate.matchAll(/\{\{([a-z]+)\}\}/g)].every(m => PLACEHOLDERS.includes(m[1])))) fail(`${where}: resourceTemplate is text with known placeholders`);
  if (typeof e.actorAttributed !== 'boolean') fail(`${where}: actorAttributed says whether the effect records the acting principal`);
  if (e.exactness !== undefined && !(EXACTNESS.includes(e.exactness) && e.source === 'sql-snapshot' && e.operation === 'update')) fail(`${where}: exactness (${EXACTNESS.join(' or ')}) applies to a sql-snapshot update only`);
  return e;
}

// Can this effect decide an absence (effect.none) for one actor? Only an authoritative source that records the acting
// principal, and a SQL snapshot only for an update it decides exactly (change column or xmin): its insert and delete
// absences are not exact (src/effect-events.mjs exactFor). A presence is decidable from any source that sees it.
export function absenceDecidable(effect) {
  if (!effect || typeof effect.name !== 'string') return false;
  if (PRESENCE_ONLY_SOURCES.includes(effect.source) || !effect.actorAttributed) return false;
  if (effect.source === 'sql-snapshot') return effect.operation === 'update' && EXACTNESS.includes(effect.exactness);
  return true;
}

// Validate a write binding against the routes it names. Returns the binding in canonical form with its bindingDigest.
export function validateWriteBinding(binding) {
  if (!plain(binding) || binding.schema !== WRITE_BINDING_SCHEMA) fail(`a write binding needs schema "${WRITE_BINDING_SCHEMA}"`);
  onlyKeys(binding, ['schema', 'application', 'targetId', 'actors', 'routes', 'effects', 'objects', 'identityControls', 'observers', 'budget', 'bindingDigest'], 'the binding');
  if (!name(binding.application, 120)) fail('application names the application');
  if (typeof binding.targetId !== 'string' || !IDENT.test(binding.targetId)) fail('targetId names the profile target');
  if (!plain(binding.actors) || !Object.keys(binding.actors).length) fail('actors maps profile actor ids to { role, tenant }');
  for (const [id, a] of Object.entries(binding.actors)) {
    if (!IDENT.test(id) || !plain(a)) fail(`actor ${id} is { role, tenant }`);
    onlyKeys(a, ['role', 'tenant'], `actor ${id}`);
    if (!name(a.role)) fail(`actor ${id}: role is a statement role name`);
    if (a.tenant !== null && !(typeof a.tenant === 'string' && IDENT.test(a.tenant))) fail(`actor ${id}: tenant is a name or null`);
  }
  const routes = {}, effects = {};
  if (!plain(binding.routes)) fail('routes maps resource to action to a route');
  for (const [resource, byAction] of Object.entries(binding.routes)) {
    if (!name(resource, 400) || !plain(byAction)) fail(`routes.${resource} maps actions to routes`);
    routes[resource] = {};
    for (const [action, r] of Object.entries(byAction)) { if (!name(action, 40)) fail(`routes.${resource}: an action is a name`); routes[resource][action] = validateRoute(r, `route ${resource} ${action}`); }
  }
  for (const [resource, byAction] of Object.entries(binding.effects ?? {})) {
    if (!plain(byAction)) fail(`effects.${resource} maps actions to effects`);
    effects[resource] = {};
    for (const [action, e] of Object.entries(byAction)) {
      if (!own(routes[resource], action)) fail(`effect ${resource} ${action} has no route`);
      const where = `effect ${resource} ${action}`, r = routes[resource][action], effect = validateEffect(e, where);
      // The effect is what the route itself does: a GET reads; a request that consumes its object does not update it; a
      // create on a collection neither updates nor deletes an existing record. Otherwise an observer that cannot see the
      // route's own effect would read as deciding it.
      if (r.method === 'GET' && effect.operation !== 'read') fail(`${where}: a GET route binds a read effect only`);
      if (r.consumes && effect.operation === 'update') fail(`${where}: a route that consumes its object cannot bind an update`);
      if (r.object === null && r.method !== 'GET' && ['update', 'delete'].includes(effect.operation)) fail(`${where}: a create on a collection cannot bind an update or a delete`);
      effects[resource][action] = effect;
    }
  }
  const routeOf = ref => own(own(routes, ref?.resource), ref?.action);
  const objects = {};
  for (const [type, o] of Object.entries(binding.objects ?? {})) {
    if (!IDENT.test(type) || !plain(o)) fail(`objects.${type} is { create?, precheck?, revert }`);
    onlyKeys(o, ['create', 'precheck', 'revert'], `object ${type}`);
    if (o.create !== undefined) {
      if (!plain(o.create) || !routeOf(o.create) || routeOf(o.create).object !== null || !HTTP_WRITE_METHODS.includes(routeOf(o.create).method)) fail(`object ${type}: create names a bound write route on a collection`);
      if (typeof o.create.capture !== 'string' || !POINTER.test(o.create.capture)) fail(`object ${type}: create.capture is the JSON pointer of the new id in its reply`);
      onlyKeys(o.create, ['resource', 'action', 'capture'], `object ${type} create`);
    }
    if (o.precheck !== undefined && (!plain(o.precheck) || routeOf(o.precheck)?.method !== 'GET' || routeOf(o.precheck)?.object !== type)) fail(`object ${type}: precheck names a bound GET route on this object type`);
    // Without a declared revert the object's cases are not drafted (no-declared-revert); a revert given must be well formed.
    if (o.revert !== undefined) {
      if (!plain(o.revert)) fail(`object ${type}: revert is { steps } or { environmentReset }`);
      onlyKeys(o.revert, ['steps', 'environmentReset'], `object ${type} revert`);
      if ((o.revert.steps === undefined) === (o.revert.environmentReset === undefined)) fail(`object ${type}: revert gives steps or an environmentReset label, one of them`);
      if (o.revert.steps !== undefined && !(Array.isArray(o.revert.steps) && o.revert.steps.length && o.revert.steps.every(s => plain(s) && routeOf(s)))) fail(`object ${type}: revert.steps name bound routes`);
      if (o.revert.environmentReset !== undefined && !name(o.revert.environmentReset, 120)) fail(`object ${type}: revert.environmentReset names the reset`);
    }
    objects[type] = o;
  }
  for (const [resource, byAction] of Object.entries(routes)) for (const [action, r] of Object.entries(byAction))
    if (r.object !== null && !own(objects, r.object)) fail(`route ${resource} ${action} acts on object type ${r.object}, which objects does not declare`);
  for (const [actor, check] of Object.entries(binding.identityControls ?? {})) if (!own(binding.actors, actor) || typeof check !== 'string' || !IDENT.test(check)) fail(`identityControls maps a bound actor to its GET identity control's check id (${actor})`);
  const o = binding.observers;
  if (!plain(o) || !name(o.path, 400) || !status(o.settleMs, 0, BUDGET_LIMITS.settleMs)) fail(`observers is { path, settleMs } with a declared settle of 0 to ${BUDGET_LIMITS.settleMs} ms`);
  onlyKeys(o, ['path', 'settleMs'], 'observers');
  if (!plain(binding.budget ?? {})) fail('budget is { maxCases, inventoryLimit }');
  const budget = { ...BUDGET_DEFAULTS, ...(binding.budget ?? {}) };
  onlyKeys(budget, ['maxCases', 'inventoryLimit'], 'budget');
  if (!status(budget.maxCases, 1, BUDGET_LIMITS.maxCases)) fail(`budget.maxCases is 1 to ${BUDGET_LIMITS.maxCases}`);
  if (!status(budget.inventoryLimit, 1, BUDGET_LIMITS.inventoryLimit)) fail(`budget.inventoryLimit is 1 to ${BUDGET_LIMITS.inventoryLimit}`);
  const body = { schema: WRITE_BINDING_SCHEMA, application: binding.application, targetId: binding.targetId, actors: binding.actors, routes, effects, objects,
    identityControls: binding.identityControls ?? {}, observers: o, budget };
  const bindingDigest = sha256(canonical(body));
  if (binding.bindingDigest !== undefined && binding.bindingDigest !== bindingDigest) fail('bindingDigest does not match the binding (it was edited after it was computed)');
  return { ...body, bindingDigest };
}

// The route, effect and object a resource and action reach, or undefined. Own keys only.
export const routeFor = (binding, resource, action) => own(own(binding.routes, resource), action);
export const effectFor = (binding, resource, action) => own(own(binding.effects, resource), action);
export const objectFor = (binding, type) => own(binding.objects, type);

// ---- The values seam (scopehaven-policy-values/1) ---------------------------------------------------------------------
// The one place concrete values (an object's id) enter a case: produced before the run by the operator's seed, a setup
// receipt, or (reserved for core captures) a capture, and identified by a digest the setup-ready step checks. A plan names
// the records it needs; it never holds values itself.
export const VALUES_SCHEMA = 'scopehaven-policy-values/1';
export const VALUE_PRODUCERS = Object.freeze(['operator-seed', 'setup-receipt', 'capture']);
const RECORD_KEY = /^WC-[0-9A-F]{12}\/[A-Za-z][A-Za-z0-9_-]{0,40}$/;
const VALUE = /^[A-Za-z0-9_.:-]{1,200}$/;

export function validateValues(values) {
  if (!plain(values) || values.schema !== VALUES_SCHEMA) fail(`values need schema "${VALUES_SCHEMA}"`);
  onlyKeys(values, ['schema', 'contextId', 'producer', 'records', 'valuesDigest'], 'the values');
  if (!name(values.contextId, 200)) fail('values name the contextId they were produced in');
  if (!VALUE_PRODUCERS.includes(values.producer)) fail(`values.producer is ${VALUE_PRODUCERS.join(', ')}`);
  if (values.producer === 'capture') fail('the capture producer is reserved for core captures (C1), not yet available');
  if (!plain(values.records)) fail('values.records maps case object keys (WC-.../REF) to { name: value }');
  for (const [key, record] of Object.entries(values.records)) {
    if (!RECORD_KEY.test(key) || !plain(record) || !Object.keys(record).length) fail(`record ${key} is { name: value } under a case object key`);
    // Plain identifiers only, as a capture would be: a value never adds a path segment, a query or a placeholder.
    for (const [k, v] of Object.entries(record)) if (!PLACEHOLDERS.includes(k) || !(typeof v === 'string' && VALUE.test(v) && !/^\.+$/.test(v))) fail(`record ${key}: ${k} is a known placeholder with a plain identifier value`);
  }
  const body = { schema: VALUES_SCHEMA, contextId: values.contextId, producer: values.producer, records: values.records };
  const valuesDigest = sha256(canonical(body));
  if (values.valuesDigest !== undefined && values.valuesDigest !== valuesDigest) fail('valuesDigest does not match the values (they were edited after it was computed)');
  return { ...body, valuesDigest };
}

// The value records a plan needs: one per case object, keyed by case id and object ref, each needing its id. An object a
// state-conditioned case acts on names the state setup must put it in.
export const valuesNeeded = plan => plan.cases.flatMap(c => c.objects.map(o => ({ key: `${c.caseId}/${o.ref}`, type: o.type, owner: o.owner, ...(o.state !== undefined ? { state: o.state } : {}), needs: ['id'] })));
// Which needed records the values leave out: setup is not ready for those cases.
export function missingValues(plan, values) {
  const v = validateValues(values);
  return valuesNeeded(plan).filter(n => !n.needs.every(k => typeof v.records[n.key]?.[k] === 'string'));
}
