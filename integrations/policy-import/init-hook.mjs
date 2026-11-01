// init hook: `scopehaven init` (integrations/init/hooks.mjs) loads this module and calls draftForInit({ profile, openapi,
// root }), expecting { checks, notDrafted, warnings }. init already drafts the GET checks from --openapi with draft.mjs; this hook
// drafts the WRITE checks (write-draft.mjs) from the same document, with the binding inferred from init's starter profile:
//   - every authenticated role of the document maps to identity a (and b, when the profile has two identities), anonymous to
//     the anonymous actor, as init's GET binding does;
//   - the record parameter comes from the profile's A-OWN-RECORD and B-OWN-RECORD paths: the one segment where they differ is
//     the record id, and the document's path template that matches them names the parameter; it is bound with A's and B's
//     record and read back through the same template.
// What it returns is a proposal: every check carries "draft, human-confirmed: no" in the draft's provenance, and confirming it
// is a named person's step (./scopehaven policy write-draft-confirm), never init's. The extra fields (draft, binding, inferred)
// let a caller write the draft to a file for that step. Reads local files only; sends nothing.
import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { importOpenApi } from './openapi.mjs';
import { WRITE_DRAFT_BINDING_SCHEMA, draftWriteChecks } from './write-draft.mjs';

const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const segments = path => path.split('?')[0].split('/').slice(1);

// The record id each identity owns, from the starter profile's own-record controls: { aPath, bPath, index, a, b } or null.
export function recordsFromProfile(profile) {
  const own = key => (profile?.checks ?? []).find(c => c.id === `${key}-OWN-RECORD` && c.method === 'GET');
  const a = own('A'), b = own('B');
  if (!a) return null;
  if (!b) return { aPath: a.path, bPath: null, index: null, a: null, b: null };
  const sa = segments(a.path), sb = segments(b.path);
  if (sa.length !== sb.length) return { aPath: a.path, bPath: b.path, index: null, a: null, b: null };
  const diff = sa.map((s, i) => (s === sb[i] ? null : i)).filter(i => i !== null);
  if (diff.length !== 1) return { aPath: a.path, bPath: b.path, index: null, a: null, b: null };
  const dec = s => { try { return decodeURIComponent(s); } catch { return s; } };
  return { aPath: a.path, bPath: b.path, index: diff[0], a: dec(sa[diff[0]]), b: dec(sb[diff[0]]) };
}

// The document's path template that matches the record path (literal segments equal, one parameter at the record segment).
export function matchTemplate(templates, recordPath, index, base = '') {
  if (index === null) return null;
  const rel = base && recordPath.startsWith(`${base}/`) ? recordPath.slice(base.length) : recordPath;
  const shift = segments(recordPath).length - segments(rel).length;
  const target = segments(rel), at = index - shift;
  if (at < 0) return null;
  for (const t of templates) {
    const ts = segments(t);
    if (ts.length !== target.length) continue;
    const m = /^\{([^}]+)\}$/.exec(ts[at] ?? '');
    if (!m) continue;
    if (ts.every((s, i) => i === at || s === target[i])) return { template: t, parameter: m[1] };
  }
  return null;
}

export async function draftForInit({ profile, openapi, root: _root, document } = {}) {
  if (!openapi && document === undefined) {
    return { checks: [], notDrafted: [{ reason: 'no OpenAPI document: write checks are drafted from the app\'s OpenAPI document (pass --openapi FILE to init)' }], warnings: [] };
  }
  if (!plain(profile) || !plain(profile.actors) || !Object.hasOwn(profile.actors, 'a')) throw new Error('policy-import init hook: the profile has no identity a');
  const bytes = document !== undefined ? (Buffer.isBuffer(document) ? document : Buffer.from(document)) : await readFile(openapi);
  const matrix = importOpenApi({ id: openapi ? basename(openapi) : 'openapi.json', content: bytes }, { application: profile.applicationId ?? profile.id });
  const two = Object.hasOwn(profile.actors, 'b');
  const anonymous = Object.hasOwn(profile.actors, 'anonymous') ? 'anonymous' : undefined;
  const pairs = {};
  for (const role of new Set(matrix.cells.map(c => c.role))) if (role !== 'anonymous') pairs[role] = two ? { A: 'a', B: 'b' } : { A: 'a' };
  const warnings = [], inferred = { records: null, parameter: null };
  const base = Array.isArray(matrix.context?.serverBases) && matrix.context.serverBases.length === 1 ? matrix.context.serverBases[0] : null;
  if (base === null) warnings.push('the document has several or unreadable servers; write drafting needs exactly one server base, so nothing is drafted');
  const parameters = {};
  const records = recordsFromProfile(profile);
  if (records?.index !== null && records?.index !== undefined && base !== null) {
    const match = matchTemplate([...new Set(matrix.cells.map(c => c.resource))], records.aPath, records.index, base);
    if (match) {
      parameters[match.parameter] = { values: { A: [records.a], ...(two ? { B: [records.b] } : { B: [records.a] }) }, read: match.template };
      inferred.records = { a: records.a, b: records.b };
      inferred.parameter = { name: match.parameter, read: match.template };
      warnings.push(`record parameter {${match.parameter}} inferred from A-OWN-RECORD and B-OWN-RECORD (${records.a}, ${records.b}); a delete twin needs two more of A's records, so deletes are listed until the binding names them`);
    } else warnings.push('no path template of the document matches the profile\'s own-record path; bind the record parameter by hand (binding.parameters)');
  } else if (records && records.index === null) warnings.push('the profile\'s two own-record paths differ in more than one segment, so the record parameter is not inferred');
  if (!Object.keys(pairs).length) return { checks: [], notDrafted: [{ reason: 'the document declares no authenticated requirement, so no role maps to an identity' }], warnings, inferred };
  if (base === null) return { checks: [], notDrafted: [], warnings, inferred };
  const binding = { schema: WRITE_DRAFT_BINDING_SCHEMA, targetId: profile.id, pairs, ...(anonymous ? { anonymous } : {}), parameters };
  const draft = draftWriteChecks(matrix, binding, { document: bytes });
  // The starter profile already carries each identity's allowed-use GET control (A-OWN-RECORD, B-OWN-RECORD), so the drafter's
  // "no allowed-use GET control in this draft" warning does not apply to an actor that has one in the profile.
  const hasGetControl = actor => (profile.checks ?? []).some(c => c.actorId === actor && c.method === 'GET' && c.severity === 'control' && (profile.requiredControlIds ?? []).includes(c.id));
  for (const w of draft.warnings) { const m = /^(\S+) has no allowed-use GET control/.exec(w); if (!(m && hasGetControl(m[1]))) warnings.push(w); }
  return { checks: draft.checks, notDrafted: draft.notDrafted, warnings, draft, binding, matrix, inferred,
    confirm: 'proposal only: confirm with ./scopehaven policy write-draft-confirm DRAFT --matrix MATRIX --binding BINDING --document OPENAPI --profile PROFILE --confirmed-by NAME' };
}
