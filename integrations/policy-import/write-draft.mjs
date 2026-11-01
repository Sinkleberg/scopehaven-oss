// Write-check drafting (scopehaven-write-draft/1): POST, PUT, PATCH and DELETE checks drafted from an OpenAPI
// document's security requirements and from Postgres RLS policies, with their bindings inferred from path parameters and
// request schemas. Every drafted write cell gets, in run order:
//   owner-read-before  the other owner (B) reads the record the probe will aim at (required control; ONBOARDING: a record used
//                      up by an earlier run then fails this control instead of reading as restored)
//   own-read           A reads its own record (required control): the allowed-use GET on a protected route that the connector
//                      brackets around A's prohibitions (actor-identity/4), so a refusal is told apart from a rejected credential.
//                      With binding.surfaceReads, one surface-read control per actor stands at the top of the draft instead
//   twin-before        the allowed-use twin: A does the write on A's own record (required control)
//   foreign-owner      A does the same write on B's record, every path parameter B's (B's parent too, so a parent-scope 404
//                      never stands for a refusal) (expected refusal)
//   anonymous          no credential does the write on A's record (expected refusal; skipped when the layer declares the
//                      operation public for its anonymous role: "anonymous" for OpenAPI, "anon" for RLS). Through PostgREST
//                      an UPDATE or DELETE is a silent probe aimed at B's row and decided by the read-back
//   read-back          B reads its record again: through PostgREST the row is still there (its key, json.equals /0/<key>) and the
//                      declared field is unchanged; over REST the declared field is unchanged, or for a DELETE a 200 shows it
//                      is still there (a silent refusal, PostgREST's 204, is decided here, never by the probe's status)
//   twin-after         the twin again, so a refusal that starts partway through the run still fails a required control
// A deny cell gets one role-refusal check. Each check carries the status "draft, human-confirmed: no" in its provenance until
// confirmWriteDraft turns it into "confirmed by label; not authenticated": confirmedBy is a label the caller supplies, so the
// record never asserts that a human confirmed anything. The checks themselves are plain profile checks (the validator allows
// no extra fields), and the runner does not read provenance: a drafted check pasted into a profile runs with no record. GET drafting (draft.mjs) and the matrix diff are untouched: this
// module writes its own ids (PW-) and its own schemas.
// A write is a real change on the target, and a timeout does not undo it (docs/ONBOARDING.md). The confirmation record says
// so and names the reset declaration (reset.mjs) a comparison needs. Nothing here reads an application or sends a request.
import { validateTargetFile } from '../../src/contracts.mjs';
import { canonical, isMatrix, sha256 } from './matrix.mjs';

export const WRITE_DRAFT_SCHEMA = 'scopehaven-write-draft/1';
export const WRITE_DRAFT_BINDING_SCHEMA = 'scopehaven-write-draft-binding/1';
export const WRITE_DRAFT_CONFIRMATION_SCHEMA = 'scopehaven-write-draft-confirmation/1';
export const VARIANTS = Object.freeze(['surface-read', 'owner-read-before', 'own-read', 'twin-before', 'foreign-owner', 'anonymous', 'read-back', 'twin-after', 'role-refusal']);
export const DRAFT_STATUS = 'draft, human-confirmed: no';
export const CONFIRMED_STATUS = 'confirmed by label; not authenticated';
export const WRITE_METHODS = Object.freeze(['POST', 'PUT', 'PATCH', 'DELETE']);
export const RLS_WRITES = Object.freeze({ INSERT: 'POST', UPDATE: 'PATCH', DELETE: 'DELETE' });
export const RESET_RULE = 'A POST, PUT, PATCH or DELETE check is a real change on the target, and a timeout does not undo it. Reset the target to the same seed before every run a comparison uses (docs/ONBOARDING.md; integrations/policy-import/reset.mjs).';
const CATEGORY = 'Declared policy (write)';
const IDENT = /^[A-Za-z0-9_-]{1,80}$/;
const SAFE_PATH = /^\/(?!\/)[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$/;
const SAFE_VALUE = /^[A-Za-z0-9._~!$&'()*+,;=:@-]{1,120}$/;
const DEFAULT_STATUSES = Object.freeze({ created: 201, ok: 200, deleted: 200, foreign: [401, 403, 404], anonymous: [401, 403], silent: 204 });
const POSTGREST_STATUSES = Object.freeze({ created: 201, ok: 204, deleted: 204 });
const SYNTHETIC = Object.freeze({ email: 'synthetic@example.test', 'date-time': '2026-01-01T00:00:00Z', date: '2026-01-01', uuid: '00000000-0000-4000-8000-000000000001', uri: 'http://127.0.0.1/synthetic' });
const fail = message => { throw new Error(`write draft: ${message}`); };
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const byCode = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const checkIdFor = (resource, action, variant, role) => `PW-${sha256(`${resource}\u0000${action}\u0000${variant}\u0000${role ?? ''}`).slice(0, 12).toUpperCase()}`;
const statusList = (list, lo, hi) => Array.isArray(list) && list.length >= 2 && list.length <= 5 && new Set(list).size === list.length && list.every(s => Number.isInteger(s) && s >= lo && s <= hi);
const status2xx = s => Number.isInteger(s) && s >= 200 && s <= 299;

// ---- binding --------------------------------------------------------------------------------------------------------------

function validateWriteBinding(binding) {
  if (binding?.schema !== WRITE_DRAFT_BINDING_SCHEMA) fail(`a binding needs schema "${WRITE_DRAFT_BINDING_SCHEMA}"`);
  if (typeof binding.targetId !== 'string' || !IDENT.test(binding.targetId)) fail('a binding needs the profile target id it adds checks to');
  if (!plain(binding.pairs) || !Object.keys(binding.pairs).length) fail('a binding maps each matrix role to its two actors ("pairs": { role: { A, B } }), both of that role in two tenants');
  for (const [role, pair] of Object.entries(binding.pairs)) {
    if (!plain(pair) || !IDENT.test(String(pair.A))) fail(`role ${role} needs actor id A (and B, a second actor of the role in another tenant, for the foreign-owner side)`);
    // B may be absent (an API with one identity class, such as admin API keys): then only the twins and the anonymous probe are drafted.
    if (pair.B !== undefined && (!IDENT.test(String(pair.B)) || pair.A === pair.B)) fail(`role ${role} needs two distinct actor ids A and B`);
  }
  if (binding.anonymous !== undefined && (typeof binding.anonymous !== 'string' || !IDENT.test(binding.anonymous))) fail('anonymous names the profile actor without a credential');
  const st = binding.statuses ?? {};
  if (!plain(st)) fail('statuses is an object');
  for (const key of ['created', 'ok', 'deleted', 'silent']) if (st[key] !== undefined && !status2xx(st[key])) fail(`statuses.${key} is a 2xx status`);
  for (const key of ['foreign', 'anonymous']) if (st[key] !== undefined && !statusList(st[key], 400, 499)) fail(`statuses.${key} is 2 to 5 distinct 4xx statuses`);
  if (st.operations !== undefined) { if (!plain(st.operations)) fail('statuses.operations maps "METHOD /template" to a 2xx status'); for (const [op, s] of Object.entries(st.operations)) if (!status2xx(s)) fail(`statuses.operations["${op}"] is a 2xx status`); }
  for (const key of ['parameters', 'tables', 'bodies', 'foreignFields', 'surfaceReads']) if (binding[key] !== undefined && !plain(binding[key])) fail(`${key} is an object`);
  for (const [actor, path] of Object.entries(binding.surfaceReads ?? {})) if (!IDENT.test(actor) || typeof path !== 'string' || !SAFE_PATH.test(path)) fail(`surfaceReads.${actor} is a protected GET path as the profile sends it`);
  for (const [name, p] of Object.entries(binding.parameters ?? {})) {
    if (!plain(p) || !plain(p.values)) fail(`parameter ${name} needs values { A: [...], B: [...] }`);
    for (const side of ['A', 'B']) if (!Array.isArray(p.values[side]) || !p.values[side].length || p.values[side].some(v => typeof v !== 'string' || !SAFE_VALUE.test(v))) fail(`parameter ${name}: values.${side} is a non-empty list of safe path values`);
    if (p.read !== undefined && (typeof p.read !== 'string' || !p.read.includes(`{${name}}`) || !SAFE_PATH.test(p.read.replace(/\{[^}]+\}/g, 'x')))) fail(`parameter ${name}: read is a GET path template containing {${name}} (parent parameters may appear too)`);
    if (p.unchanged !== undefined && (!plain(p.unchanged) || typeof p.unchanged.pointer !== 'string' || !p.unchanged.pointer.startsWith('/') || !Object.hasOwn(p.unchanged, 'B'))) fail(`parameter ${name}: unchanged is { pointer, B: value }`);
  }
  for (const [table, t] of Object.entries(binding.tables ?? {})) {
    if (!plain(t) || typeof t.key !== 'string' || !/^[a-z_][a-z0-9_]*$/.test(t.key) || !plain(t.values)) fail(`table ${table} needs key and values { A: [...], B: [...] }`);
    for (const side of ['A', 'B']) if (!Array.isArray(t.values[side]) || !t.values[side].length || t.values[side].some(v => typeof v !== 'string' || !SAFE_VALUE.test(v))) fail(`table ${table}: values.${side} is a non-empty list of safe key values`);
    if (t.insert !== undefined && (!plain(t.insert) || !plain(t.insert.body) || typeof t.insert.ownerColumn !== 'string' || !plain(t.insert.owners) || !Object.hasOwn(t.insert.owners, 'A') || !Object.hasOwn(t.insert.owners, 'B'))) fail(`table ${table}: insert is { body, ownerColumn, owners: { A, B } }`);
    if (t.update !== undefined && (!plain(t.update) || !plain(t.update.body) || !Object.keys(t.update.body).length)) fail(`table ${table}: update is { body } with at least one column`);
    if (t.unchanged !== undefined && (!plain(t.unchanged) || typeof t.unchanged.column !== 'string' || !Object.hasOwn(t.unchanged, 'B'))) fail(`table ${table}: unchanged is { column, B: value }`);
  }
  if (binding.postgrest !== undefined && (typeof binding.postgrest?.basePath !== 'string' || !SAFE_PATH.test(binding.postgrest.basePath))) fail('postgrest.basePath must be a path such as /rest/v1');
  // How the anonymous actor reaches PostgREST, which decides what a refused anonymous UPDATE or DELETE answers, so it is declared,
  // never assumed:
  //   "anon-key"           the project's anon key, and the anon role holds the table's write grant: RLS filters the write and
  //                        answers 204 either way, so the probe is silent and the read-back decides it
  //   "anon-key-no-grant"  the anon key, and the anon role's write grant is revoked: the write is refused with 401 (42501)
  //   "no-key"             no key at all: the gateway answers 401 before RLS (the probe then tests the gateway, not the policy)
  // Undeclared, the anonymous UPDATE and DELETE probes are not drafted: one expected status for the wrong case would fail an
  // enforcing app, and the contract's status.in cannot hold a 2xx beside a refusal.
  if (binding.postgrest?.anonymous !== undefined && !['anon-key', 'anon-key-no-grant', 'no-key'].includes(binding.postgrest.anonymous)) fail('postgrest.anonymous is "anon-key", "anon-key-no-grant" or "no-key"');
  for (const [op, body] of Object.entries(binding.bodies ?? {})) if (!plain(body)) fail(`bodies["${op}"] is a JSON object`);
  for (const [op, fields] of Object.entries(binding.foreignFields ?? {})) {
    if (!plain(fields) || !Object.keys(fields).length) fail(`foreignFields["${op}"] maps a JSON pointer to { A, B }`);
    for (const [pointer, v] of Object.entries(fields)) if (!pointer.startsWith('/') || !plain(v) || !Object.hasOwn(v, 'A') || !Object.hasOwn(v, 'B')) fail(`foreignFields["${op}"]["${pointer}"] is { A: value, B: value }`);
  }
}
const statuses = (binding, layer) => ({ ...DEFAULT_STATUSES, ...(layer === 'postgres-rls' ? POSTGREST_STATUSES : {}), ...(binding.statuses ?? {}) });

// ---- OpenAPI request bodies ------------------------------------------------------------------------------------------------

// A synthetic value for a JSON schema: examples and defaults first, then one value per type. Bounded depth; $ref within
// #/components/schemas only.
function resolveRef(doc, ref) {
  const m = /^#\/components\/schemas\/([^/]+)$/.exec(ref ?? '');
  return m ? doc.components?.schemas?.[decodeURIComponent(m[1].replaceAll('~1', '/').replaceAll('~0', '~'))] : undefined;
}
function synthetic(doc, schema, depth, seen) {
  if (!plain(schema) || depth > 6) return undefined;
  if (typeof schema.$ref === 'string') { if (seen.has(schema.$ref)) return undefined; const next = new Set(seen); next.add(schema.$ref); return synthetic(doc, resolveRef(doc, schema.$ref), depth + 1, next); }
  if (Object.hasOwn(schema, 'example')) return schema.example;
  if (Array.isArray(schema.examples) && schema.examples.length) return schema.examples[0];
  if (Object.hasOwn(schema, 'default')) return schema.default;
  if (Object.hasOwn(schema, 'const')) return schema.const;
  if (Array.isArray(schema.enum) && schema.enum.length) return schema.enum[0];
  if (Array.isArray(schema.allOf)) { const merged = {}; for (const part of schema.allOf) { const v = synthetic(doc, part, depth + 1, seen); if (plain(v)) Object.assign(merged, v); } return merged; }
  for (const key of ['oneOf', 'anyOf']) if (Array.isArray(schema[key]) && schema[key].length) return synthetic(doc, schema[key][0], depth + 1, seen);
  const type = Array.isArray(schema.type) ? schema.type.find(t => t !== 'null') : schema.type ?? (schema.properties ? 'object' : schema.items ? 'array' : undefined);
  switch (type) {
    case 'string': return SYNTHETIC[schema.format] ?? 'synthetic';
    case 'integer': case 'number': return Number.isFinite(schema.minimum) ? schema.minimum : 1;
    case 'boolean': return true;
    case 'null': return null;
    case 'array': { const item = synthetic(doc, schema.items, depth + 1, seen); return item === undefined ? [] : [item]; }
    case 'object': {
      const out = {}, props = plain(schema.properties) ? schema.properties : {};
      const names = Array.isArray(schema.required) && schema.required.length ? schema.required.filter(n => Object.hasOwn(props, n)) : Object.keys(props).slice(0, 8);
      for (const n of names) { const v = synthetic(doc, props[n], depth + 1, seen); if (v !== undefined) out[n] = v; }
      return out;
    }
    default: return undefined;
  }
}
// The JSON request body an operation declares, as a synthetic object, or why none can be inferred.
export function inferBody(doc, path, method) {
  const op = doc?.paths?.[path]?.[method.toLowerCase()];
  if (!plain(op)) return { skip: 'operation not in the document' };
  if (!plain(op.requestBody)) return { body: null };
  const rb = typeof op.requestBody.$ref === 'string' ? doc.components?.requestBodies?.[op.requestBody.$ref.replace('#/components/requestBodies/', '')] : op.requestBody;
  const media = plain(rb?.content) ? Object.entries(rb.content).find(([type]) => /^application\/(?:[^;]+\+)?json\b/i.test(type)) : undefined;
  if (!media) return rb?.required === true ? { skip: 'the request body is not JSON; give a body in the binding' } : { body: null };
  const value = synthetic(doc, media[1].schema, 0, new Set());
  if (!plain(value)) return { skip: 'no JSON object schema to infer a body from; give a body in the binding' };
  return { body: value, inferred: true };
}

// ---- drafting --------------------------------------------------------------------------------------------------------------

const setPointer = (body, pointer, value) => {
  const parts = pointer.split('/').slice(1).map(p => p.replaceAll('~1', '/').replaceAll('~0', '~'));
  let cur = body;
  for (const part of parts.slice(0, -1)) { if (!plain(cur[part])) cur[part] = {}; cur = cur[part]; }
  cur[parts.at(-1)] = value;
  return body;
};
const check = ({ id, title, severity, actorId, method, path, body, assertions }) => ({ id, title, category: CATEGORY, severity, actorId, method, path, ...(body ? { body } : {}), evidenceRequirement: 'response', assertions });
const eq = expected => ({ kind: 'status.equals', expected });
const oneOf = expected => ({ kind: 'status.in', expected: [...expected] });

// The requests of one write cell: a plan per variant, or a reason. Shared by OpenAPI and RLS, which differ only in how a path,
// a body and a read are formed (the "shape" the layer-specific code passes in).
function planCell({ binding, cell, pair, shape, st, publicOps }) {
  const hasSurface = actor => typeof binding.surfaceReads?.[actor] === 'string';
  // What a read of B's record can decide after a probe: a declared field unchanged decides any write; for a DELETE, the row's
  // presence decides it (PostgREST: its key in /0; REST: a 200, since a deleted record answers 404).
  const decides = read => !read.skip && (Boolean(read.unchanged) || (shape.method === 'DELETE' && (Boolean(read.present) || shape.statusShowsPresence)));
  const readAssertions = read => [eq(200), ...(read.present ? [{ kind: 'json.equals', pointer: read.present.pointer, expected: read.present.value }] : []), ...(read.unchanged ? [{ kind: 'json.equals', pointer: read.unchanged.pointer, expected: read.unchanged.value }] : [])];
  const plans = [], skipped = [];
  const key = `${cell.action} ${cell.resource}`;
  const where = { role: cell.role, resource: cell.resource, action: cell.action, decision: cell.decision, ...(cell.conditions?.length ? { conditions: cell.conditions } : {}) };
  const add = (variant, actorId, severity, request, assertions, extra = {}) => plans.push({ variant, where, actorId, severity, ...request, assertions, ...extra });
  const skip = (variant, reason) => skipped.push({ ...where, variant, reason });
  const method = shape.method;
  if (cell.decision === 'deny') {
    const r = shape.request('A', 0);
    if (r.skip) skip('role-refusal', r.skip);
    else if (shape.refusal === 'silent') skip('role-refusal', 'the refusal is silent (PostgREST answers 204 whether or not a row matched) and a deny cell has no owner read-back to decide it; observe it with a database snapshot instead');
    else add('role-refusal', pair.A, 'high', r, [oneOf(st.foreign)], { refusal: shape.refusal });
    return { plans, skipped };
  }
  // allow or conditional: the twin, the foreign-owner probe, the anonymous probe, the owner read before and the read-back after.
  // The twin's status: the binding's per-operation status, else the operation's documented 2xx (OpenAPI responses), else the default.
  const twinStatus = st.operations?.[key] ?? shape.successStatus ?? (method === 'POST' ? st.created : method === 'DELETE' ? st.deleted : st.ok);
  // A delete twin uses up its record, so delete twins take A's second and third values and A's own read keeps the first.
  const twinIndex = method === 'DELETE' ? 1 : 0;
  const own0 = shape.request('A', twinIndex);
  if (own0.skip) { skip('twin-before', own0.skip); skip('twin-after', own0.skip); skip('foreign-owner', own0.skip); skip('anonymous', own0.skip); return { plans, skipped }; }
  const read = pair.B === undefined ? { skip: `no second actor of this role (pairs.${cell.role}.B), so there is no other owner to read or to aim the write at` } : shape.read('B', 0);
  if (read.skip) skip('owner-read-before', read.skip);
  else add('owner-read-before', pair.B, 'control', read, readAssertions(read));
  if (!hasSurface(pair.A)) {
    const ownRead = shape.read('A', 0);
    if (ownRead.skip) skip('own-read', ownRead.skip);
    else add('own-read', pair.A, 'control', { method: 'GET', path: ownRead.path }, [eq(200), ...(ownRead.present ? [{ kind: 'json.equals', pointer: ownRead.present.pointer, expected: ownRead.present.value }] : [])]);
  }
  add('twin-before', pair.A, 'control', own0, [eq(twinStatus)]);
  const foreign = pair.B === undefined ? { skip: read.skip } : shape.request('A', 0, { foreign: true });
  if (foreign.skip) skip('foreign-owner', foreign.skip);
  else if (cell.decision === 'allow' && shape.foreignNeedsCondition) skip('foreign-owner', 'the policy allows the write on every row (no owner predicate); no foreign-owner refusal is declared, so write the expectation by hand if it is intended');
  // A silent refusal (PostgREST's 204 whether or not a row matched) is a probe whose row only records that it was sent (medium); the
  // read-back decides it, so without a read-back the probe is not drafted.
  else if (shape.refusal === 'silent' && !decides(read)) skip('foreign-owner', 'the refusal is silent (204 either way), so the probe needs the read-back to decide it: declare the other owner\'s read and "unchanged"');
  else if (shape.refusal === 'silent') add('foreign-owner', pair.A, 'medium', foreign, [eq(st.silent)], { refusal: 'silent', decidedBy: 'read-back' });
  else add('foreign-owner', pair.A, 'high', foreign, [oneOf(st.foreign)], { refusal: shape.refusal, ...(read.skip ? {} : { decidedBy: 'read-back' }) });
  if (!binding.anonymous) skip('anonymous', 'no anonymous actor in the binding');
  else if (publicOps.has(key)) skip('anonymous', 'the layer declares this operation open to its anonymous role (allow or conditional), so no refusal is declared');
  else if (shape.anonymousMode === 'undeclared') skip('anonymous', 'through PostgREST a refused anonymous UPDATE or DELETE answers 204 when the anon role holds the write grant and 401 when it does not: declare postgrest.anonymous ("anon-key", "anon-key-no-grant" or "no-key") to draft it');
  else if (shape.anonymousMode === 'refused-on-B') {
    // The anon key without the write grant: a status refusal, aimed at B's row so the read-back also shows it untouched.
    if (pair.B === undefined || foreign.skip) skip('anonymous', 'the anonymous probe aims at B\'s row, and this cell has none');
    else add('anonymous', binding.anonymous, 'high', foreign, [oneOf(st.anonymous)], { refusal: 'status' });
  } else if (shape.anonymousSilent) {
    // PostgREST with the anon key: RLS filters the write and answers 204 either way, so the probe aims at B's row and the read-back
    // decides it. Without a read that decides, nothing is drafted.
    if (pair.B === undefined || foreign.skip || !decides(read)) skip('anonymous', 'through PostgREST an anonymous UPDATE or DELETE is a silent refusal (204 either way): it needs B\'s row and a read-back that decides it ("unchanged", or a DELETE)');
    else add('anonymous', binding.anonymous, 'medium', foreign, [eq(st.silent)], { refusal: 'silent', decidedBy: 'read-back' });
  } else add('anonymous', binding.anonymous, 'high', own0, [oneOf(st.anonymous)]);
  if (read.skip) skip('read-back', read.skip);
  else if (!decides(read)) skip('read-back', 'declare "unchanged" (a field and B\'s seed value) so a silent change of B\'s record is decided by this read');
  else add('read-back', pair.B, 'high', read, readAssertions(read));
  const own1 = method === 'DELETE' ? shape.request('A', twinIndex + 1) : own0;
  if (own1.skip) skip('twin-after', own1.skip);
  else add('twin-after', pair.A, 'control', own1, [eq(twinStatus)]);
  return { plans, skipped };
}

// OpenAPI: resource is a path template, action a method. Path parameters are filled from the binding's parameters; the body from
// the document's request schema (or the binding's override); the read from the parameter's declared read template.
function openapiShape({ binding, cell, doc, bases }) {
  const method = cell.action, template = cell.resource, key = `${method} ${template}`;
  const params = [...template.matchAll(/\{([^}]+)\}/g)].map(m => m[1]);
  const unbound = params.filter(p => !binding.parameters?.[p]);
  const inferred = binding.bodies?.[key] ? { body: binding.bodies[key], inferred: false } : inferBody(doc, template, method);
  // index (a delete twin's second or third record) applies to the record parameter (the write template's last); a parent
  // parameter (the workspace of a thread) keeps its first value, so a nested delete stays inside the same parent. Every
  // parameter takes the same side's values: the foreign probe is B's whole chain (B's parent, B's record), never A's parent
  // with B's record, which a parent-scoped app answers 404 whether or not it leaks.
  const fillPath = (t, side, index) => {
    let path = t;
    const last = params.at(-1);
    for (const p of [...t.matchAll(/\{([^}]+)\}/g)].map(m => m[1])) {
      if (!binding.parameters?.[p]) return { skip: `parameter ${p} of ${t} not bound (binding.parameters)` };
      const list = binding.parameters[p].values[side], at = p === last ? index : 0;
      if (at >= list.length) return { skip: `parameter ${p}: values.${side} needs ${at + 1} value(s)` };
      path = path.replaceAll(`{${p}}`, list[at]);
    }
    const full = `${bases[0]}${path}`;
    return SAFE_PATH.test(full) ? { path: full } : { skip: 'the derived path is not a safe absolute path' };
  };
  const lastParam = params.at(-1), foreignField = binding.foreignFields?.[key];
  // The lowest documented 2xx response of the operation, when the document lists one (a "2XX" range or "default" says nothing exact).
  const documented = Object.keys(doc?.paths?.[template]?.[method.toLowerCase()]?.responses ?? {}).filter(k => /^2\d\d$/.test(k)).map(Number).sort((a, b) => a - b);
  const shape = {
    successStatus: documented[0],
    // OpenAPI declares who may call, never which records: the foreign-owner refusal is drafted for a person to confirm.
    method, refusal: 'status', foreignNeedsCondition: false, statusShowsPresence: true, anonymousSilent: false, anonymousMode: 'status',
    request(side, index, { foreign = false } = {}) {
      if (unbound.length) return { skip: `path parameter${unbound.length === 1 ? '' : 's'} ${unbound.join(', ')} not bound (binding.parameters)` };
      if (inferred.skip) return { skip: inferred.skip };
      if (foreign && !lastParam && !foreignField) return { skip: 'a create on a collection has no path parameter; declare the owned field in binding.foreignFields to aim it at the other owner' };
      const p = fillPath(template, foreign && lastParam ? 'B' : side, index);
      if (p.skip) return p;
      let body = inferred.body ? structuredClone(inferred.body) : null;
      if (foreignField) { body ??= {}; for (const [pointer, v] of Object.entries(foreignField)) setPointer(body, pointer, foreign ? v.B : v[side]); }
      return { method, path: p.path, ...(body ? { body } : {}), bodyInferred: inferred.inferred === true };
    },
    read(side, index) {
      if (!lastParam) return { skip: 'no path parameter names the record, so no owner read is drafted' };
      const p = binding.parameters[lastParam];
      if (p?.read === undefined) return { skip: `declare parameters.${lastParam}.read (the GET path of one record) for the owner read and read-back` };
      const r = fillPath(p.read, side, index);
      if (r.skip) return r;
      return { method: 'GET', path: r.path, ...(p.unchanged ? { unchanged: { pointer: p.unchanged.pointer, value: p.unchanged.B } } : {}) };
    },
  };
  return shape;
}

// RLS through PostgREST: resource is schema.table, action INSERT, UPDATE or DELETE. The key column and seed rows come from the
// binding's tables; a refusal of UPDATE or DELETE is silent (204 whether or not a row matched), so the read-back decides it.
function rlsShape({ binding, cell, selectAllowed }) {
  const method = RLS_WRITES[cell.action], t = binding.tables?.[cell.resource], base = binding.postgrest?.basePath?.replace(/\/$/, '');
  const m = /^public\.([a-z_][a-z0-9_]*)$/.exec(cell.resource), name = m?.[1];
  const skipAll = !base ? 'no postgrest.basePath in the binding' : !name ? 'only public-schema tables with plain names are drafted for PostgREST' : !t ? `table ${cell.resource} not bound (binding.tables)` : null;
  const row = (side, index) => { const list = t.values[side]; return index < list.length ? list[index] : null; };
  return {
    method, refusal: cell.action === 'INSERT' ? 'status' : 'silent', foreignNeedsCondition: true, statusShowsPresence: false,
    // An anonymous INSERT is refused with a status either way; an UPDATE or DELETE depends on the declared postgrest.anonymous.
    anonymousSilent: cell.action !== 'INSERT' && binding.postgrest?.anonymous === 'anon-key',
    anonymousMode: cell.action === 'INSERT' || binding.postgrest?.anonymous === 'no-key' ? 'status'
      : binding.postgrest?.anonymous === 'anon-key' ? 'silent' : binding.postgrest?.anonymous === 'anon-key-no-grant' ? 'refused-on-B' : 'undeclared',
    request(side, index, { foreign = false } = {}) {
      if (skipAll) return { skip: skipAll };
      if (cell.action === 'INSERT') {
        if (!t.insert) return { skip: `declare tables["${cell.resource}"].insert (body, ownerColumn, owners) to draft the insert` };
        const body = { ...structuredClone(t.insert.body), [t.insert.ownerColumn]: t.insert.owners[foreign ? 'B' : side] };
        return { method, path: `${base}/${name}`, body };
      }
      const id = row(foreign ? 'B' : side, index);
      if (id === null) return { skip: `table ${cell.resource}: values.${foreign ? 'B' : side} needs ${index + 1} value(s)` };
      // A refused update needs no real change: the key column set to itself is still gated by the policy.
      if (cell.action === 'UPDATE' && !t.update && cell.decision !== 'deny') return { skip: `declare tables["${cell.resource}"].update.body to draft the update` };
      const body = cell.action === 'UPDATE' ? (t.update ? structuredClone(t.update.body) : { [t.key]: id }) : undefined;
      return { method, path: `${base}/${name}?${t.key}=eq.${id}`, ...(body ? { body } : {}) };
    },
    read(side, index) {
      if (skipAll) return { skip: skipAll };
      if (cell.action === 'INSERT') return { skip: 'a create has no existing record to read' };
      if (!selectAllowed) return { skip: 'no declared SELECT for the other owner, so it cannot read its own row back' };
      const id = row(side, index);
      if (id === null) return { skip: `table ${cell.resource}: values.${side} needs ${index + 1} value(s)` };
      // PostgREST answers 200 [] for a row that is gone or filtered, so the read asserts the row: its key in the first element.
      return { method: 'GET', path: `${base}/${name}?${t.key}=eq.${id}&select=*`, present: { pointer: `/0/${t.key}`, value: id }, ...(t.unchanged && side === 'B' ? { unchanged: { pointer: `/0/${t.unchanged.column}`, value: t.unchanged.B } } : {}) };
    },
  };
}

const titleFor = (p, layer) => {
  const what = `${p.where.role} ${p.where.decision === 'deny' ? 'may not' : 'may'} ${p.where.action} ${p.where.resource}`;
  const tail = { 'owner-read-before': 'the other owner reads its record first', 'own-read': 'the actor reads its own record (allowed-use GET control)', 'twin-before': 'allowed-use twin (before)', 'twin-after': 'allowed-use twin (after)',
    'foreign-owner': p.refusal === 'silent' ? 'the same write aimed at the other owner\'s record (silent refusal; the read-back decides)' : 'the same write on the other owner\'s record is refused',
    anonymous: p.refusal === 'silent' ? 'the same write without a user session, aimed at the other owner\'s record (silent refusal; the read-back decides)' : 'the same write without a credential is refused',
    'read-back': 'the other owner\'s record is still there and unchanged', 'role-refusal': 'refused as declared' }[p.variant];
  return `${what}: ${tail} (${layer})`;
};

// matrix: an openapi-security or postgres-rls matrix. document: the OpenAPI document the matrix was imported from (OpenAPI only).
export function draftWriteChecks(matrix, binding, { document } = {}) {
  if (!isMatrix(matrix)) fail('the matrix is missing or was edited after import (its matrixId no longer matches)');
  validateWriteBinding(binding);
  if (!['openapi-security', 'postgres-rls'].includes(matrix.layer)) fail(`write checks are drafted from openapi-security or postgres-rls matrices, not ${matrix.layer}`);
  const warnings = [], notDrafted = [], checks = [], provenance = [];
  const st = statuses(binding, matrix.layer);
  let doc = null, bases = null;
  if (matrix.layer === 'openapi-security') {
    // The document's bytes, as imported: the matrix keeps only their digest, so the same bytes must be given again.
    if (!(Buffer.isBuffer(document) || typeof document === 'string')) fail('OpenAPI write drafting needs the document bytes the matrix was imported from (request bodies come from its schemas)');
    const bytes = Buffer.isBuffer(document) ? document : Buffer.from(document);
    if (sha256(bytes) !== matrix.sources?.[0]?.sha256) fail('the document is not the one the matrix was imported from (its sha256 differs from the matrix source)');
    try { doc = JSON.parse(bytes.toString('utf8')); } catch { fail('the document is not JSON'); }
    bases = matrix.context?.serverBases;
    if (!Array.isArray(bases) || bases.length !== 1) fail('the document has several or unreadable servers; write drafting needs exactly one server base');
  }
  if (!matrix.complete) warnings.push(`the matrix has ${matrix.gaps.length} source gap(s); affected cells are unknown and not drafted`);
  // The layer's anonymous role: OpenAPI's derived "anonymous"; the RLS importer's "anon". An operation that role may do (allow, or
  // conditional on something the drafter cannot see) gets no anonymous refusal probe.
  const anonRole = matrix.layer === 'postgres-rls' ? 'anon' : 'anonymous';
  const publicOps = new Set(matrix.cells.filter(c => c.role === anonRole && ['allow', 'conditional'].includes(c.decision)).map(c => `${c.action} ${c.resource}`));
  const selectAllow = new Set(matrix.cells.filter(c => c.action === 'SELECT' && ['allow', 'conditional'].includes(c.decision)).map(c => `${c.role}\u0000${c.resource}`));
  const anonymousDone = new Set();
  for (const [actorId, path] of Object.entries(binding.surfaceReads ?? {})) {
    const id = checkIdFor('', '', 'surface-read', actorId);
    checks.push(check({ id, title: `${actorId} reads a protected route (allowed-use GET control the prohibitions are bracketed with)`, severity: 'control', actorId, method: 'GET', path, assertions: [eq(200)] }));
    provenance.push({ checkId: id, variant: 'surface-read', role: actorId, resource: '', action: '', decision: 'allow', status: DRAFT_STATUS, basis: 'binding.surfaceReads', citations: [] });
  }
  // Deletes last: a delete twin uses up a record the other operations' twins still probe.
  const isDelete = c => c.action === 'DELETE';
  const cells = [...matrix.cells.filter(c => !isDelete(c)), ...matrix.cells.filter(isDelete)];
  for (const cell of cells) {
    const isWrite = matrix.layer === 'openapi-security' ? WRITE_METHODS.includes(cell.action) : Object.hasOwn(RLS_WRITES, cell.action);
    if (!isWrite) continue;
    const where = { role: cell.role, resource: cell.resource, action: cell.action, decision: cell.decision };
    // The anonymous variant of each authenticated role's operation covers the layer's anonymous role; it is listed, not dropped.
    if (cell.role === anonRole) { notDrafted.push({ ...where, variant: null, reason: `${cell.decision}: the layer's anonymous role is covered by the anonymous variant of each authenticated role's operation` }); continue; }
    if (!['allow', 'conditional', 'deny'].includes(cell.decision)) { notDrafted.push({ ...where, variant: null, reason: `${cell.decision}: nothing declared to test` }); continue; }
    if (matrix.layer === 'openapi-security' && matrix.context?.ownServers?.includes(`${cell.action} ${cell.resource}`)) { notDrafted.push({ ...where, variant: null, reason: 'the operation declares its own servers; bind its path by hand' }); continue; }
    const pair = binding.pairs[cell.role];
    if (!pair) { notDrafted.push({ ...where, variant: null, reason: 'role not mapped to an actor pair' }); continue; }
    if (matrix.layer === 'postgres-rls' && cell.decision === 'allow') warnings.push(`${cell.role} ${cell.action} ${cell.resource}: the policy allows every row, so only the twin and the anonymous probe are drafted`);
    const shape = matrix.layer === 'openapi-security' ? openapiShape({ binding, cell, doc, bases }) : rlsShape({ binding, cell, selectAllowed: selectAllow.has(`${cell.role}\u0000${cell.resource}`) });
    const { plans, skipped } = planCell({ binding, cell, pair, shape, st, publicOps });
    notDrafted.push(...skipped);
    for (const p of plans) {
      const opKey = `${cell.action} ${cell.resource}`;
      if (p.variant === 'anonymous') { if (anonymousDone.has(opKey)) continue; anonymousDone.add(opKey); }
      const id = checkIdFor(cell.resource, cell.action, p.variant, p.variant === 'anonymous' ? null : cell.role);
      if (checks.some(c => c.id === id)) continue;
      checks.push(check({ id, title: titleFor(p, matrix.layer), severity: p.severity, actorId: p.actorId, method: p.method, path: p.path, body: p.body, assertions: p.assertions }));
      provenance.push({ checkId: id, variant: p.variant, ...p.where, status: DRAFT_STATUS, basis: cell.basis, citations: cell.citations,
        ...(p.bodyInferred ? { bodyInferred: true } : {}), ...(p.refusal ? { refusal: p.refusal } : {}),
        ...(p.decidedBy ? { decidedBy: checkIdFor(cell.resource, cell.action, 'read-back', cell.role) } : {}) });
    }
  }
  for (const actorId of new Set(checks.filter(c => WRITE_METHODS.includes(c.method) && c.severity !== 'control').map(c => c.actorId))) {
    if (actorId !== binding.anonymous && !checks.some(c => c.actorId === actorId && c.method === 'GET' && c.severity === 'control')) warnings.push(`${actorId} has no allowed-use GET control in this draft (no read template reached it); add binding.surfaceReads.${actorId} or keep one in the profile, or its prohibitions read identity-unproven`);
  }
  if (checks.some(c => WRITE_METHODS.includes(c.method))) warnings.push(RESET_RULE);
  const body = { schema: WRITE_DRAFT_SCHEMA, confirmed: false, application: matrix.application, layer: matrix.layer, matrixId: matrix.matrixId, targetId: binding.targetId,
    checks, provenance, notDrafted, warnings, counts: countVariants(provenance) };
  return { ...body, draftId: sha256(canonical(body)) };
}
const countVariants = provenance => Object.fromEntries(VARIANTS.map(v => [v, provenance.filter(p => p.variant === v).length]).filter(([, n]) => n));

export function verifyWriteDraftId(draft) {
  const { draftId, ...body } = draft ?? {};
  return draft?.schema === WRITE_DRAFT_SCHEMA && typeof draftId === 'string' && draftId === sha256(canonical(body));
}

// Every property confirmation promises, checked on the checks themselves (so a recomputed draftId cannot smuggle a change).
export function checkWriteDraftChecks(draft) {
  if (!Array.isArray(draft.checks) || !Array.isArray(draft.provenance) || draft.checks.length !== draft.provenance.length) fail('each drafted check needs exactly one provenance entry');
  const byId = new Map();
  for (const p of draft.provenance) { if (byId.has(p.checkId)) fail(`provenance names ${p.checkId} twice`); byId.set(p.checkId, p); }
  const allowed = new Set(['id', 'title', 'category', 'severity', 'actorId', 'method', 'path', 'body', 'evidenceRequirement', 'assertions']);
  for (const c of draft.checks) {
    const p = byId.get(c.id), bad = why => fail(`check ${c.id} ${why}, so it was not drafted from a declaration as recorded`);
    if (!p || !VARIANTS.includes(p.variant) || p.status !== DRAFT_STATUS) bad('has no draft provenance entry');
    if (p.variant === 'surface-read') { if (c.id !== checkIdFor('', '', 'surface-read', c.actorId) || c.method !== 'GET' || c.severity !== 'control' || c.body !== undefined || canonical(c.assertions) !== canonical([eq(200)])) bad('is not the surface read as drafted'); continue; }
    if (c.id !== checkIdFor(p.resource, p.action, p.variant, p.variant === 'anonymous' ? null : p.role)) bad('does not carry its cell\'s id');
    if (Object.keys(c).some(k => !allowed.has(k))) bad('has fields a draft never writes');
    if (c.category !== CATEGORY || c.evidenceRequirement !== 'response' || typeof c.path !== 'string' || !SAFE_PATH.test(c.path) || !IDENT.test(String(c.actorId))) bad('has a changed category, evidence requirement, path or actor');
    const reads = ['owner-read-before', 'own-read', 'read-back'].includes(p.variant);
    if (reads ? c.method !== 'GET' || c.body !== undefined : !WRITE_METHODS.includes(c.method)) bad('has a method its variant does not allow');
    const control = ['owner-read-before', 'own-read', 'twin-before', 'twin-after'].includes(p.variant), silent = p.refusal === 'silent';
    if (silent && (!['foreign-owner', 'anonymous'].includes(p.variant) || !p.decidedBy)) bad('records a silent refusal without the read-back that decides it');
    if (c.severity !== (control ? 'control' : silent ? 'medium' : 'high')) bad('has a severity its variant does not allow');
    const a = c.assertions;
    const ok = control ? Array.isArray(a) && a[0]?.kind === 'status.equals' && status2xx(a[0].expected) && a.slice(1).every(x => x.kind === 'json.equals')
      : p.variant === 'read-back' ? Array.isArray(a) && a[0]?.kind === 'status.equals' && a[0].expected === 200 && a.slice(1).every(x => x.kind === 'json.equals')
        : silent ? Array.isArray(a) && a.length === 1 && a[0].kind === 'status.equals' && status2xx(a[0].expected)
          : Array.isArray(a) && a.length === 1 && a[0].kind === 'status.in' && statusList(a[0].expected, 400, 499);
    if (!ok) bad('has assertions its variant does not allow');
  }
}

// Adds the drafted checks (all, or the listed checkIds, in draft order) to one target of the profile under a named person.
// Returns a new profile the product validator accepted and a sealed record that names every confirmed check.
export function confirmWriteDraft(draft, profile, { confirmedBy, matrix, binding, document, checkIds, now = new Date(), requireControls = true, reset = null } = {}) {
  if (!verifyWriteDraftId(draft)) fail('the draft is missing or was edited after drafting (its draftId no longer matches)');
  if (draft.confirmed !== false) fail('this draft is already marked confirmed');
  if (typeof confirmedBy !== 'string' || !confirmedBy.trim() || confirmedBy.length > 120) fail('name the person confirming these checks (confirmedBy, 1 to 120 characters)');
  if (!matrix || !binding) fail('confirmation needs the matrix and binding the draft came from');
  if (matrix.matrixId !== draft.matrixId) fail('the matrix given is not the one this draft came from');
  if (draftWriteChecks(matrix, binding, { document }).draftId !== draft.draftId) fail('the draft is not what this matrix and binding produce, so it was not drafted from a declaration as recorded');
  checkWriteDraftChecks(draft);
  const wanted = checkIds === undefined ? null : new Set(checkIds);
  if (wanted) for (const id of wanted) if (!draft.checks.some(c => c.id === id)) fail(`checkIds names ${id}, which the draft does not contain`);
  const selected = draft.checks.filter(c => !wanted || wanted.has(c.id));
  if (!selected.length) fail('the draft has no checks to confirm');
  // A probe confirmed without its twins is a write with no allowed-use control beside it, and one decided by a read-back is
  // confirmed only with that read-back: both refused. (The owner read before is a control of its own and is not required here.)
  const byVariant = new Map(draft.provenance.map(p => [p.checkId, p]));
  for (const c of selected) {
    const p = byVariant.get(c.id);
    if (['foreign-owner', 'anonymous', 'role-refusal'].includes(p.variant)) {
      const twins = draft.provenance.filter(q => q.resource === p.resource && q.action === p.action && q.role === p.role && ['twin-before', 'twin-after'].includes(q.variant)).map(q => q.checkId);
      if (p.variant !== 'role-refusal' && !twins.every(id => selected.some(s => s.id === id))) fail(`${c.id} (${p.variant}) is confirmed only together with its twins (${twins.join(', ')})`);
      if (p.decidedBy && !selected.some(s => s.id === p.decidedBy)) fail(`${c.id} is decided by its read-back ${p.decidedBy}; confirm both`);
    }
  }
  const next = JSON.parse(JSON.stringify(profile));
  const target = next?.targets?.find(t => t.id === draft.targetId);
  if (!target) fail(`the profile has no target "${draft.targetId}"`);
  const ids = new Set((target.checks ?? []).map(c => c.id));
  for (const c of selected) {
    if (ids.has(c.id)) fail(`the profile already has a check ${c.id}`);
    if (!Object.hasOwn(target.actors ?? {}, c.actorId)) fail(`check ${c.id} uses actor ${c.actorId}, which the target doesn't declare`);
  }
  target.checks = [...(target.checks ?? []), ...selected];
  const controls = selected.filter(c => c.severity === 'control').map(c => c.id);
  if (requireControls) target.requiredControlIds = [...new Set([...(target.requiredControlIds ?? []), ...controls])];
  const validated = validateTargetFile(next).find(t => t.id === draft.targetId);
  const added = new Set(selected.map(c => c.id));
  const checks = validated.checks.filter(c => added.has(c.id));
  const provenance = draft.provenance.filter(p => added.has(p.checkId)).map(p => ({ ...p, status: CONFIRMED_STATUS }));
  const warnings = draft.application !== target.applicationId ? [`the matrix names application ${draft.application}; the profile target is ${target.applicationId}`] : [];
  if (reset === null && checks.some(c => WRITE_METHODS.includes(c.method))) warnings.push('no reset declaration was named; a comparison of two runs needs one (RESET_RULE)');
  const body = { schema: WRITE_DRAFT_CONFIRMATION_SCHEMA, draftId: draft.draftId, matrixId: draft.matrixId, application: draft.application, layer: draft.layer, targetId: draft.targetId,
    targetApplicationId: target.applicationId, confirmedBy: confirmedBy.trim(), confirmedAt: now.toISOString(), checks, provenance, requiredControlsAdded: requireControls ? controls : [],
    notConfirmed: draft.checks.filter(c => !added.has(c.id)).map(c => c.id).sort(byCode), resetRule: RESET_RULE, reset, warnings };
  return { profile: next, record: { ...body, recordDigest: sha256(canonical(body)) } };
}

export function verifyWriteDraftRecord(record) {
  const { recordDigest, ...body } = record ?? {};
  return record?.schema === WRITE_DRAFT_CONFIRMATION_SCHEMA && typeof recordDigest === 'string' && recordDigest === sha256(canonical(body));
}

// The share of a profile that was generated: every check of the target, split by where it came from.
export function generatedShare(target, records) {
  const generated = new Set(records.flatMap(r => (r.checks ?? []).map(c => c.id)));
  const all = (target.checks ?? []).map(c => c.id);
  const counts = { total: all.length, generated: all.filter(id => generated.has(id)).length };
  counts.handWritten = counts.total - counts.generated;
  counts.share = counts.total ? Math.round(1000 * counts.generated / counts.total) / 1000 : 0;
  return counts;
}
