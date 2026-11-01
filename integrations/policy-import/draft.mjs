// Draft connector checks from an expected-permission matrix, confirm them into a
// profile, and explain a run against the declarations they came from.
// A draft is a proposal: it stays "confirmed: false" until a named person confirms it,
// and only confirmDraft turns it into profile checks. Only GET checks are drafted, so a
// draft sends no write method, and a write action bound to GET is not drafted. That does
// not show a GET changes nothing: a GET handler that writes is not seen. Conditional,
// undeclared and unknown cells are listed as not drafted, with what a person would need
// to write instead.
// Allow cells become allowed-use controls (status.equals, required for repair
// comparisons); deny cells become refusal checks (4xx only: a 5xx is not a refusal).
// The draftId only detects careless edits, since anyone can recompute it. So confirmDraft
// takes the matrix and binding the draft came from, verifies the matrix, re-drafts, and
// accepts only an identical draft; it also re-checks each check's safety properties (GET,
// no body, its cell's id, one provenance entry, the assertions its decision allows). That
// guarantees consistency with the given matrix, not with the sources: re-import them to
// check a matrix. The confirmation record is sealed and holds each confirmed check and the
// contract fields of its actors, so explainRun can tell, in any later profile that still
// contains them unchanged, whether the run tested what was confirmed. Declared policy is
// what the owner says should happen; the run is what happened; explainRun lines them up.
import { digest } from '../../src/domain.mjs';
import { contractDigest, validateTargetFile } from '../../src/contracts.mjs';
import { canonical, cellKey, isMatrix, sha256 } from './matrix.mjs';

export const DRAFT_SCHEMA = 'scopehaven-policy-draft/1';
export const BINDING_SCHEMA = 'scopehaven-policy-binding/1';
export const CONFIRMATION_SCHEMA = 'scopehaven-policy-confirmation/1';
const BOUND_DENY = Object.freeze([401, 403, 404]);
// A path derived from a document, not chosen by a person, may simply not exist; a 404 there is no refusal.
const DERIVED_DENY = Object.freeze([401, 403]);
const IDENT = /^[A-Za-z0-9_-]{1,80}$/;
const SAFE_PATH = /^\/(?!\/)[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$/;
const REQUEST_KINDS = new Set(['bound', 'postgrest', 'postgrest-privilege', 'openapi-literal']);
const ACTOR_CONTRACT = ['principalId', 'tenantId', 'role', 'credentialEnv', 'credentialCookie', 'identityValue', 'signInRedirectStatus'];
const actorContract = actor => Object.fromEntries(ACTOR_CONTRACT.filter(k => Object.hasOwn(actor ?? {}, k)).map(k => [k, actor[k]]));

// The declared decision is part of the id, so a flipped cell is a different check, never
// the same id with the opposite expectation.
export const checkIdFor = cell => `PI-${sha256(`${cellKey(cell)}\u0000${cell.decision}`).slice(0, 12).toUpperCase()}`;
const titleFor = cell => `${cell.role} ${cell.decision === 'allow' ? 'may' : 'may not'} ${cell.action} ${cell.resource} (declared)`;

function validateBinding(binding) {
  if (binding?.schema !== BINDING_SCHEMA) throw new Error(`A binding needs schema "${BINDING_SCHEMA}".`);
  if (typeof binding.targetId !== 'string' || !IDENT.test(binding.targetId)) throw new Error('A binding needs the profile target id it adds checks to.');
  if (!binding.actors || typeof binding.actors !== 'object') throw new Error('A binding maps matrix roles to profile actors ("actors").');
  for (const [role, actor] of Object.entries(binding.actors)) if (typeof actor !== 'string' || !IDENT.test(actor)) throw new Error(`Role ${role} maps to an invalid actor id.`);
  if (binding.postgrest !== undefined && (typeof binding.postgrest?.basePath !== 'string' || !SAFE_PATH.test(binding.postgrest.basePath))) throw new Error('postgrest.basePath must be a path such as /rest/v1.');
  if (binding.postgrest?.refusal !== undefined && !['empty', 'privilege'].includes(binding.postgrest.refusal)) throw new Error('postgrest.refusal is "empty" (RLS filters rows) or "privilege" (the role lacks the table privilege).');
}
const denyList = list => Array.isArray(list) && list.length >= 2 && list.length <= 5 && new Set(list).size === list.length && list.every(s => Number.isInteger(s) && s >= 400 && s <= 499);
const allowStatusOk = s => Number.isInteger(s) && s >= 200 && s <= 299;

// Where a cell's request goes, or why it can't be drafted.
function requestFor(matrix, binding, cell) {
  const bound = binding.resources?.[cell.resource]?.[cell.action];
  if (bound) {
    if (bound.method !== 'GET') return { skip: `bound to ${bound.method}; only GET checks are drafted because other methods can change data` };
    // A GET response cannot establish whether a declared write was allowed or refused.
    if ((matrix.layer === 'postgres-rls' && ['INSERT', 'UPDATE', 'DELETE'].includes(cell.action))
      || (matrix.layer === 'openapi-security' && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(cell.action))
      || (matrix.layer === 'openwebui-access-grant' && cell.action === 'write')) return { skip: 'write action bound to GET' };
    if (typeof bound.path !== 'string' || !SAFE_PATH.test(bound.path)) return { skip: 'bound path is not a safe absolute path' };
    if (bound.allowStatus !== undefined && !allowStatusOk(bound.allowStatus)) throw new Error(`${cell.resource} ${cell.action}: allowStatus must be a 2xx status.`);
    if (bound.denyStatuses !== undefined && !denyList(bound.denyStatuses)) throw new Error(`${cell.resource} ${cell.action}: denyStatuses must be 2 to 5 distinct 4xx statuses.`);
    return { path: bound.path, allowStatus: bound.allowStatus ?? 200, denyStatuses: bound.denyStatuses ?? [...BOUND_DENY], kind: 'bound' };
  }
  if (matrix.layer === 'postgres-rls' && binding.postgrest && cell.action === 'SELECT') {
    const m = /^([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)$/.exec(cell.resource);
    // Another schema needs an Accept-Profile header, which the connector does not send.
    if (!m || m[1] !== 'public') return { skip: 'only public-schema tables with plain names are drafted for PostgREST (another schema needs an Accept-Profile header)' };
    return { path: `${binding.postgrest.basePath.replace(/\/$/, '')}/${m[2]}?select=*&limit=1`, kind: binding.postgrest.refusal === 'privilege' ? 'postgrest-privilege' : 'postgrest' };
  }
  if (matrix.layer === 'openapi-security' && cell.action === 'GET' && !cell.resource.includes('{')) {
    const bases = matrix.context?.serverBases;
    if (matrix.context?.ownServers?.includes(`GET ${cell.resource}`)) return { skip: 'the operation declares its own servers; bind its path explicitly' };
    if (!Array.isArray(bases) || bases.length !== 1) return { skip: 'the document has several or unreadable servers; bind the path explicitly' };
    const path = `${bases[0]}${cell.resource}`;
    if (!SAFE_PATH.test(path)) return { skip: 'the derived path is not a safe absolute path' };
    return { path, allowStatus: 200, denyStatuses: [...DERIVED_DENY], kind: 'openapi-literal' };
  }
  if (matrix.layer === 'postgres-rls' && cell.action !== 'SELECT') return { skip: `${cell.action} changes data; write it by hand with a reset plan` };
  return { skip: 'no request bound for this resource and action' };
}

function assertionsFor(decision, request) {
  if (request.kind === 'postgrest-privilege') return decision === 'allow'
    ? [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/0', expected: true }]
    // The PostgreSQL error code tells a privilege refusal from a gateway turning away a request.
    : [{ kind: 'status.in', expected: [401, 403] }, { kind: 'json.equals', pointer: '/code', expected: '42501' }];
  if (request.kind === 'postgrest') return decision === 'allow'
    ? [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/0', expected: true }]
    : [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/0', expected: false }];
  return decision === 'allow' ? [{ kind: 'status.equals', expected: request.allowStatus }] : [{ kind: 'status.in', expected: request.denyStatuses }];
}

export function draftChecks(matrix, binding) {
  if (!isMatrix(matrix)) throw new Error('The matrix is missing or was edited after import (its matrixId no longer matches).');
  validateBinding(binding);
  const checks = [], provenance = [], notDrafted = [], warnings = [];
  if (!matrix.complete) warnings.push(`the matrix has ${matrix.gaps.length} source gap(s); affected cells are unknown and not drafted`);
  // A PostgREST refusal (200 with no rows) means something only next to a role that does see rows.
  const visible = new Set(matrix.cells.filter(c => c.action === 'SELECT' && c.decision === 'allow' && binding.actors[c.role]).map(c => c.resource));
  const byActor = new Map();
  for (const [role, actor] of Object.entries(binding.actors)) byActor.set(actor, [...(byActor.get(actor) ?? []), role]);
  for (const [actor, roles] of byActor) if (roles.length > 1) warnings.push(`actor ${actor} stands for several roles (${roles.join(', ')}); its checks test each declaration with one identity`);
  for (const cell of matrix.cells) {
    const where = { role: cell.role, resource: cell.resource, action: cell.action, decision: cell.decision };
    if (!['allow', 'deny'].includes(cell.decision)) {
      notDrafted.push({ ...where, reason: cell.decision === 'conditional' ? `conditional on ${cell.conditions.join('; ') || cell.basis}: write paired checks with records that meet and miss the condition` : `${cell.decision}: nothing declared to test` });
      continue;
    }
    const actorId = binding.actors[cell.role];
    if (!actorId) { notDrafted.push({ ...where, reason: 'role not mapped to a profile actor' }); continue; }
    const request = requestFor(matrix, binding, cell);
    if (request.skip) { notDrafted.push({ ...where, reason: request.skip }); continue; }
    if (request.kind === 'postgrest' && cell.decision === 'deny' && !visible.has(cell.resource)) {
      notDrafted.push({ ...where, reason: 'no mapped role is allowed to read this table, so an empty result could not show a refusal' }); continue;
    }
    const id = checkIdFor(cell);
    if (request.kind.startsWith('postgrest') && cell.decision === 'allow') warnings.push(`${id}: seed at least one row ${cell.role} can read in ${cell.resource}; this control requires it`);
    checks.push({ id, title: titleFor(cell), category: 'Declared policy', severity: cell.decision === 'allow' ? 'control' : 'high',
      actorId, method: 'GET', path: request.path, evidenceRequirement: 'response', assertions: assertionsFor(cell.decision, request) });
    provenance.push({ checkId: id, ...where, requestKind: request.kind, basis: cell.basis, citations: cell.citations });
  }
  const body = { schema: DRAFT_SCHEMA, confirmed: false, application: matrix.application, layer: matrix.layer, matrixId: matrix.matrixId, targetId: binding.targetId, checks, provenance, notDrafted, warnings };
  return { ...body, draftId: sha256(canonical(body)) };
}

export function verifyDraftId(draft) {
  const { draftId, ...body } = draft ?? {};
  return draft?.schema === DRAFT_SCHEMA && typeof draftId === 'string' && draftId === sha256(canonical(body));
}

// Every property confirmation promises, checked on the checks themselves.
export function checkDraftChecks(draft) {
  if (!Array.isArray(draft.checks) || !Array.isArray(draft.provenance) || draft.checks.length !== draft.provenance.length) throw new Error('Each drafted check needs exactly one provenance entry.');
  const byId = new Map();
  for (const p of draft.provenance) {
    if (byId.has(p.checkId)) throw new Error(`Provenance names ${p.checkId} twice.`);
    byId.set(p.checkId, p);
  }
  const allowed = new Set(['id', 'title', 'category', 'severity', 'actorId', 'method', 'path', 'evidenceRequirement', 'assertions']);
  for (const check of draft.checks) {
    const p = byId.get(check.id), fail = why => { throw new Error(`Check ${check.id} ${why}, so it was not drafted from a declaration as recorded.`); };
    if (!p) fail('has no provenance entry');
    if (!['allow', 'deny'].includes(p.decision) || !REQUEST_KINDS.has(p.requestKind)) fail('has an unsupported decision or request kind');
    if (check.id !== checkIdFor(p)) fail('does not carry its cell\'s id');
    if (Object.keys(check).some(k => !allowed.has(k))) fail('has fields a draft never writes (such as a body)');
    if (check.method !== 'GET') fail('is not a GET');
    if (typeof check.path !== 'string' || !SAFE_PATH.test(check.path)) fail('has an unsafe path');
    if (typeof check.actorId !== 'string' || !IDENT.test(check.actorId)) fail('has an invalid actor');
    if (check.title !== titleFor(p) || check.category !== 'Declared policy' || check.evidenceRequirement !== 'response') fail('has a changed title, category or evidence requirement');
    if (check.severity !== (p.decision === 'allow' ? 'control' : 'high')) fail('has a severity its decision does not allow');
    const a = check.assertions;
    const ok = p.requestKind.startsWith('postgrest')
      ? canonical(a) === canonical(assertionsFor(p.decision, { kind: p.requestKind }))
      : p.decision === 'allow'
        ? Array.isArray(a) && a.length === 1 && a[0].kind === 'status.equals' && allowStatusOk(a[0].expected)
        : Array.isArray(a) && a.length === 1 && a[0].kind === 'status.in' && denyList(a[0].expected) && (p.requestKind !== 'openapi-literal' || !a[0].expected.includes(404));
    if (!ok) fail('has assertions its decision does not allow');
  }
}

// Adds the drafted checks to one target of a profile. Returns a new profile; the caller
// validates it with the product's own validator before writing it.
export function confirmDraft(draft, profile, { confirmedBy, matrix, binding, now = new Date(), requireControls = true } = {}) {
  if (!verifyDraftId(draft)) throw new Error('The draft is missing or was edited after drafting (its draftId no longer matches).');
  if (draft.confirmed !== false) throw new Error('This draft is already marked confirmed.');
  if (typeof confirmedBy !== 'string' || !confirmedBy.trim() || confirmedBy.length > 120) throw new Error('Name the person confirming these checks (confirmedBy, 1 to 120 characters).');
  if (!draft.checks.length) throw new Error('The draft has no checks to confirm.');
  if (!matrix || !binding) throw new Error('Confirmation needs the matrix and binding the draft came from.');
  if (matrix.matrixId !== draft.matrixId) throw new Error('The matrix given is not the one this draft came from.');
  if (draftChecks(matrix, binding).draftId !== draft.draftId) throw new Error('The draft is not what this matrix and binding produce, so it was not drafted from a declaration as recorded.');
  checkDraftChecks(draft);
  const next = JSON.parse(JSON.stringify(profile));
  const target = next?.targets?.find(t => t.id === draft.targetId);
  if (!target) throw new Error(`The profile has no target "${draft.targetId}".`);
  const ids = new Set((target.checks ?? []).map(c => c.id));
  for (const check of draft.checks) {
    if (ids.has(check.id)) throw new Error(`The profile already has a check ${check.id}.`);
    if (!Object.hasOwn(target.actors ?? {}, check.actorId)) throw new Error(`Check ${check.id} uses actor ${check.actorId}, which the target doesn't declare.`);
  }
  target.checks = [...(target.checks ?? []), ...draft.checks];
  const controls = draft.checks.filter(c => c.severity === 'control').map(c => c.id);
  if (requireControls) target.requiredControlIds = [...new Set([...(target.requiredControlIds ?? []), ...controls])];
  const validated = validateTargetFile(next).find(t => t.id === draft.targetId);
  const added = new Set(draft.checks.map(c => c.id));
  const checks = validated.checks.filter(c => added.has(c.id));
  const actors = Object.fromEntries([...new Set(checks.map(c => c.actorId))].sort().map(alias => [alias, actorContract(validated.actors[alias])]));
  const warnings = draft.application !== target.applicationId ? [`the matrix names application ${draft.application}; the profile target is ${target.applicationId}`] : [];
  const body = { schema: CONFIRMATION_SCHEMA, draftId: draft.draftId, matrixId: draft.matrixId, application: draft.application, layer: draft.layer,
    targetId: draft.targetId, targetApplicationId: target.applicationId, confirmedBy: confirmedBy.trim(), confirmedAt: now.toISOString(),
    checks, actors, target: { origin: validated.origin, contextId: validated.contextId, targetContext: validated.targetContext ?? 'local-app' }, requiredControlsAdded: requireControls ? controls : [], provenance: draft.provenance, warnings };
  return { profile: next, record: { ...body, recordDigest: sha256(canonical(body)) } };
}

export function verifyRecord(record) {
  const { recordDigest, ...body } = record ?? {};
  return record?.schema === CONFIRMATION_SCHEMA && typeof recordDigest === 'string' && recordDigest === sha256(canonical(body));
}

// A saved run file ({ core, sha256 }) or an exported run ({ ...core, integrity, notes }) is
// checked against the store's own checksum first; anything else is read but labelled unverified.
function runCore(run) {
  const matches = (core, sum) => { try { return digest(core) === sum; } catch { return false; } };
  if (run && typeof run === 'object' && run.core && typeof run.sha256 === 'string') {
    if (!matches(run.core, run.sha256)) throw new Error('The saved run no longer matches its checksum.');
    return { core: run.core, integrity: 'store-checksum-verified' };
  }
  if (typeof run?.integrity?.sha256 === 'string') {
    const { integrity, notes, ...core } = run;
    if (!matches(core, integrity.sha256)) throw new Error('The exported run no longer matches its checksum.');
    return { core, integrity: 'export-checksum-verified' };
  }
  return { core: run, integrity: 'unverified' };
}

// Lines a run's results up with the declarations. The record must be sealed; the profile the
// run used must hash to the run's profileHash and still hold every confirmed check and the
// contract fields of its actors unchanged (later confirmations may add checks). A failed
// refusal check reads "not refused as declared" (it could be a 200 or a 500), never proof
// of access. A check missing from the run is not run, and a result whose title, severity,
// actor or request path differs from the confirmed check is a different check. verified
// is true only when every row is consistent and the run's checksum held.
export function explainRun(input, record, { profile } = {}) {
  if (!verifyRecord(record)) throw new Error('Explain needs an unedited confirmation record (its recordDigest no longer matches).');
  const { core: run, integrity } = runCore(input);
  if (run?.targetId !== record.targetId || run?.applicationId !== record.targetApplicationId)
    throw new Error(`The run is from target ${run?.targetId ?? 'unknown'} / application ${run?.applicationId ?? 'unknown'}, not ${record.targetId} / ${record.targetApplicationId}.`);
  if (!profile) throw new Error('Explain needs the profile the run used.');
  const target = validateTargetFile(profile).find(t => t.id === record.targetId);
  if (!target || contractDigest(target) !== run.profileHash) throw new Error('The run is not of this profile (its profileHash differs).');
  const inProfile = new Map(target.checks.map(c => [c.id, c]));
  for (const check of record.checks) if (canonical(inProfile.get(check.id) ?? null) !== canonical(check)) throw new Error(`Confirmed check ${check.id} is missing or changed in this profile, so the profile changed after confirmation.`);
  for (const [alias, contract] of Object.entries(record.actors)) if (canonical(actorContract(target.actors[alias])) !== canonical(contract)) throw new Error(`Actor ${alias} changed in this profile after confirmation.`);
  if (canonical({ origin: target.origin, contextId: target.contextId, targetContext: target.targetContext ?? 'local-app' }) !== canonical(record.target)) throw new Error('The target origin or context changed in this profile after confirmation.');
  const byId = new Map((Array.isArray(run.results) ? run.results : []).map(r => [r.id, r]));
  const confirmed = new Map(record.checks.map(c => [c.id, c]));
  const sent = result => result?.trace?.find(t => t?.type === 'http-observation')?.data ?? {};
  const rows = record.provenance.map(p => {
    const result = byId.get(p.checkId), check = confirmed.get(p.checkId);
    let reading;
    if (!result) reading = 'not-run';
    else if (!check || result.severity !== check.severity || result.title !== check.title || sent(result).actorId !== check.actorId || sent(result).requestPathHash !== digest(check.path)) reading = 'check-differs-from-draft';
    else if (result.status === 'pass') reading = p.decision === 'allow' ? 'consistent: allowed as declared' : 'consistent: refused as declared';
    else if (result.status === 'fail') reading = p.decision === 'allow' ? 'mismatch: declared allow, not granted' : 'mismatch: declared deny, not refused';
    else reading = `no-verdict (${result.status})`;
    return { ...p, status: result?.status ?? null, reading };
  });
  const counts = {};
  for (const row of rows) counts[row.reading] = (counts[row.reading] ?? 0) + 1;
  const mismatches = rows.filter(r => r.reading.startsWith('mismatch'));
  const verified = integrity !== 'unverified' && rows.length > 0 && rows.every(r => r.reading.startsWith('consistent'));
  return { runId: run.id ?? null, runIntegrity: integrity, matrixId: record.matrixId, confirmedBy: record.confirmedBy, verified, counts, mismatches, rows };
}
