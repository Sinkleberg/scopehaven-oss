// Scopehaven policy import: the expected-permission matrix (scopehaven-policy-matrix/2).
// An importer reads one layer of an application's own authorization declarations
// (Postgres row-level security, OpenAPI security requirements, Open WebUI access
// grants) and states, per role x resource x action, what that layer declares:
//   allow        a declared, unconditional grant
//   conditional  a declared grant gated by a predicate or setting, kept verbatim
//   deny         a declared refusal, explicit or the documented default of a mechanism
//                the source turned on (RLS enabled with no applicable policy)
//   undeclared   the layer says nothing about this cell
//   unknown      the source tried to say something the importer could not read completely
// Undeclared never becomes deny, and a parse gap turns a table's or operation's
// cells into unknown rather than guessing. Every cell cites where it came from.
// A matrix is a reading of declarations, not an observation of behaviour, and it is
// never authoritative until a human confirms the checks drafted from it (draft.mjs).
// Schema 2 gives every gap an identity (id), so a diff can tell a new gap from a standing one.
import { createHash } from 'node:crypto';

export const MATRIX_SCHEMA = 'scopehaven-policy-matrix/2';
// The matrices this version reads. A /1 matrix has no gap identities: every reader takes it as before, and diff
// compares its gaps fail-closed (any gap in the after matrix is gated).
export const MATRIX_SCHEMAS = Object.freeze(['scopehaven-policy-matrix/1', MATRIX_SCHEMA]);
export const DECISIONS = Object.freeze(['allow', 'conditional', 'deny', 'undeclared', 'unknown']);
// Diff kinds a release gate fails on: more access, or a declaration that stopped being readable or stopped existing.
// An added cell that isn't declared closed (allow, conditional, undeclared or unknown: a new
// role, a renamed or new resource, a new table without RLS) is gated too, since a release can
// widen access by adding cells as easily as by changing them.
// A new gap is gated too, whatever its cells read: where cells are already unknown, a gap is the
// only sign that the release added something the importer could not read. So is every gap of an
// after matrix whose gaps can't be compared by identity (one side is a /1 matrix with gaps).
// Reasons a cell is unknown because of a gap, which the gap comparison already gates.
const GAP_REASONS = Object.freeze(['source-gap']);
export const GATED_KINDS = Object.freeze(['widened', 'became-unknown', 'became-undeclared', 'added-open', 'gap-added', 'gap-unidentified']);

export const sha256 = value => createHash('sha256').update(value).digest('hex');
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
export const cellKey = ({ role, resource, action }) => `${role}\u0000${resource}\u0000${action}`;
export const isMatrix = m => MATRIX_SCHEMAS.includes(m?.schema) && verifyMatrixId(m);
const GAP_ID = /^[a-f0-9]{64}$/;

// A gap's identity is a digest of its scope (the table, role or "*"), its kind (the reason, without line numbers or row
// indexes), its subject (the statement's tokens, comments and spacing dropped; a file that could not be tokenized, whole;
// or the unreadable row or item) and, for a replayed statement, its position (a digest of the history before it) and,
// where it changes how everything after it is read, the rest (a digest of the history after it). An occurrence count
// among gaps with the same basis comes last. Renumbering lines, renaming or splitting a file without reordering it, and
// appending migrations keep a gap's id; editing it, or moving, adding, removing or editing a statement before it, gives a
// new id. An importer passes { kind, subject, scope, position, rest } as gap.identity; without it the kind is the reason
// and the rest is empty. The source file name is left out, so a dated catalog dump or a renamed migration keeps its gaps.
function identifyGaps(list) {
  const seen = new Map();
  return list.map(({ identity = {}, ...gap }) => {
    if (!identity || typeof identity !== 'object' || Array.isArray(identity)) throw new Error('A gap identity is { kind, subject, scope, position, rest }.');
    const basis = canonical({ scope: identity.scope ?? gap.scope ?? null, kind: identity.kind ?? gap.reason ?? null, subject: identity.subject ?? null,
      position: identity.position ?? null, rest: identity.rest ?? null });
    const occurrence = (seen.get(basis) ?? 0) + 1;
    seen.set(basis, occurrence);
    return { ...gap, id: sha256(`${basis}\u0000${occurrence}`) };
  });
}

export function sourceRecord({ id, kind, content, label }) {
  const bytes = Buffer.isBuffer(content) ? content : Buffer.from(String(content));
  return { id, kind, label: label ?? id, bytes: bytes.length, sha256: sha256(bytes) };
}

// cells: [{ role, resource, action, decision, basis, conditions?, citations, computedDecision?, unknownReasons? }]. An unknown cell is
// written with unknownReasons, the sorted set of every reason it is unknown (its basis when the importer gives none).
// gaps: [{ source, line, scope, reason, identity? }], in history order; each is written with its id.
// context: layer facts a drafter needs that aren't cells (OpenAPI server paths).
const unique = values => [...new Set(values)].sort();
export function buildMatrix({ application, layer, sources, cells, notEvaluated = [], assumptions = [], gaps = [], context = {} }) {
  if (typeof application !== 'string' || !application) throw new Error('A matrix needs an application id.');
  if (typeof layer !== 'string' || !layer) throw new Error('A matrix needs a layer name.');
  const seen = new Set();
  for (const cell of cells) {
    if (!DECISIONS.includes(cell.decision)) throw new Error(`Unknown decision "${cell.decision}".`);
    if (typeof cell.basis !== 'string' || !cell.basis) throw new Error('Every cell needs a basis.');
    if (!Array.isArray(cell.citations) || (cell.decision !== 'undeclared' && !cell.citations.length)) throw new Error(`Cell ${cell.role}/${cell.resource}/${cell.action} needs a citation.`);
    if (cell.unknownReasons !== undefined && (!Array.isArray(cell.unknownReasons) || !cell.unknownReasons.length || cell.unknownReasons.some(r => typeof r !== 'string' || !r))) throw new Error(`Cell ${cell.role}/${cell.resource}/${cell.action} has unreadable unknownReasons.`);
    const key = cellKey(cell);
    if (seen.has(key)) throw new Error(`Duplicate cell ${cell.role}/${cell.resource}/${cell.action}.`);
    seen.add(key);
  }
  const sorted = [...cells].sort((a, b) => cellKey(a) < cellKey(b) ? -1 : cellKey(a) > cellKey(b) ? 1 : 0)
    .map(({ role, resource, action, decision, basis, conditions = [], citations, computedDecision, unknownReasons }) =>
      ({ role, resource, action, decision, basis, conditions, citations, ...(computedDecision ? { computedDecision } : {}),
        ...(decision === 'unknown' ? { unknownReasons: unique(unknownReasons ?? [basis]) } : {}) }));
  const body = { schema: MATRIX_SCHEMA, application, layer, sources, roles: unique(sorted.map(c => c.role)), resources: unique(sorted.map(c => c.resource)),
    actions: unique(sorted.map(c => c.action)), cells: sorted, gaps: identifyGaps(gaps), notEvaluated, assumptions, context, complete: gaps.length === 0 };
  return { ...body, matrixId: sha256(canonical(body)) };
}

export function verifyMatrixId(matrix) {
  const { matrixId, ...body } = matrix;
  return typeof matrixId === 'string' && matrixId === sha256(canonical(body));
}

export function summarize(matrix) {
  const counts = Object.fromEntries(DECISIONS.map(d => [d, 0]));
  for (const cell of matrix.cells) counts[cell.decision] += 1;
  return { application: matrix.application, layer: matrix.layer, matrixId: matrix.matrixId, roles: matrix.roles.length, resources: matrix.resources.length,
    cells: matrix.cells.length, counts, complete: matrix.complete, gaps: matrix.gaps.length };
}

// Release-to-release diff of one layer of one application. Widened means a cell moved
// toward access (deny/undeclared/unknown -> allow/conditional, or conditional -> allow).
// A cell that became undeclared (RLS turned off, a security requirement deleted) or
// unknown is its own kind, and GATED_KINDS fail a release gate.
// Gaps are compared by identity in gapChanges: gap-added (gated) and gap-removed (not gated).
// When either side has a gap without an identity (a /1 matrix), every gap of the after matrix
// is gap-unidentified (gated), and gapNote says why.
export function diffMatrices(before, after) {
  for (const [name, m] of [['before', before], ['after', after]]) if (!isMatrix(m) || !Array.isArray(m.gaps)) return { comparable: false, reason: `${name}-matrix-invalid` };
  if (before.application !== after.application) return { comparable: false, reason: 'application-differs' };
  if (before.layer !== after.layer) return { comparable: false, reason: 'layer-differs' };
  const index = m => new Map(m.cells.map(c => [cellKey(c), c]));
  const a = index(before), b = index(after), changes = [];
  const rank = d => d === 'allow' ? 2 : d === 'conditional' ? 1 : 0;
  for (const [key, cell] of b) {
    const old = a.get(key);
    if (!old) { changes.push({ kind: cell.decision === 'deny' ? 'added' : 'added-open', ...pick(cell), to: cell.decision, toConditions: cell.conditions }); continue; }
    const conditionsChanged = canonical(old.conditions) !== canonical(cell.conditions);
    // Between two unknown cells, compare what each would have decided, so one gap in the
    // history doesn't blind every later diff to a widening, or to RLS turned off: a cell that
    // would now be undeclared, from any other state (unknown included), became undeclared. A cell that stays unknown but gains
    // a reason other than a source gap (an owner that now bypasses RLS, a policy for current_user) became unknown again: the
    // gap that already hid it says nothing about the new reason. A reason lost is listed, not gated. A /1 cell records only
    // its basis, so a cell unknown for several reasons gates once against a /1 baseline.
    const bothUnknown = old.decision === 'unknown' && cell.decision === 'unknown';
    const computedChanged = bothUnknown && (old.computedDecision ?? 'unknown') !== (cell.computedDecision ?? 'unknown');
    const reasonsOf = c => new Set(Array.isArray(c.unknownReasons) ? c.unknownReasons : [c.basis]);
    const [fromReasons, toReasons] = bothUnknown ? [reasonsOf(old), reasonsOf(cell)] : [new Set(), new Set()];
    const addedReasons = [...toReasons].filter(r => !fromReasons.has(r)).sort(), removedReasons = [...fromReasons].filter(r => !toReasons.has(r)).sort();
    const reasonGained = addedReasons.some(r => !GAP_REASONS.includes(r));
    if (old.decision === cell.decision && !conditionsChanged && !computedChanged && !addedReasons.length && !removedReasons.length) continue;
    let kind;
    if (computedChanged) kind = cell.computedDecision === 'undeclared' ? 'became-undeclared' : rank(cell.computedDecision ?? 'unknown') > rank(old.computedDecision ?? 'unknown') ? 'widened' : reasonGained ? 'became-unknown' : 'changed';
    else if (reasonGained) kind = 'became-unknown';
    else if (bothUnknown && !conditionsChanged) kind = 'changed';
    else if (old.decision === cell.decision) kind = 'conditions-changed';
    else if (cell.decision === 'unknown') kind = 'became-unknown';
    else if (cell.decision === 'undeclared') kind = 'became-undeclared';
    else if (rank(cell.decision) > rank(old.decision)) kind = 'widened';
    else if (rank(cell.decision) < rank(old.decision)) kind = 'narrowed';
    else kind = 'changed';
    changes.push({ kind, ...pick(cell), from: old.decision, to: cell.decision, ...(computedChanged ? { fromComputed: old.computedDecision ?? null, toComputed: cell.computedDecision ?? null } : {}),
      ...(addedReasons.length || removedReasons.length ? { addedReasons, removedReasons } : {}), fromConditions: old.conditions, toConditions: cell.conditions });
  }
  for (const [key, cell] of a) if (!b.has(key)) changes.push({ kind: 'removed', ...pick(cell), from: cell.decision, fromConditions: cell.conditions });
  const order = { widened: 0, 'added-open': 1, 'became-unknown': 2, 'became-undeclared': 3, 'conditions-changed': 4, narrowed: 5, changed: 6, added: 7, removed: 8 };
  changes.sort((x, y) => order[x.kind] - order[y.kind] || (cellKey(x) < cellKey(y) ? -1 : 1));
  const counts = {};
  for (const c of changes) counts[c.kind] = (counts[c.kind] ?? 0) + 1;
  const gaps = diffGaps(before, after), gapCounts = {};
  for (const c of gaps.gapChanges) gapCounts[c.kind] = (gapCounts[c.kind] ?? 0) + 1;
  return { comparable: true, application: after.application, layer: after.layer, beforeMatrixId: before.matrixId, afterMatrixId: after.matrixId, counts,
    gated: [...changes, ...gaps.gapChanges].some(c => GATED_KINDS.includes(c.kind)), changes, gapComparison: gaps.gapComparison, ...(gaps.gapNote ? { gapNote: gaps.gapNote } : {}), gapCounts, gapChanges: gaps.gapChanges };
}
const pick = ({ role, resource, action }) => ({ role, resource, action });

// Gaps match by id as a multiset: an after gap with no unmatched before gap of its id is added, and a before gap left
// over is removed. An id is trusted only on a schema-2 matrix where every gap has one.
const GAP_NOTES = {
  'before-unidentified': 'the before matrix has gaps without identities (a scopehaven-policy-matrix/1 matrix), so a new gap cannot be told from a standing one: every gap of the after matrix is gated. Re-import the before matrix\'s sources to compare gaps.',
  'after-unidentified': 'the after matrix has gaps without identities (a scopehaven-policy-matrix/1 matrix), so a new gap cannot be told from a standing one: every gap of the after matrix is gated. Re-import its sources to compare gaps.',
};
function diffGaps(before, after) {
  const unidentified = m => m.gaps.length > 0 && !(m.schema === MATRIX_SCHEMA && m.gaps.every(g => typeof g?.id === 'string' && GAP_ID.test(g.id)));
  const record = (kind, g) => ({ kind, id: typeof g?.id === 'string' ? g.id : null, scope: g?.scope ?? null, reason: g?.reason ?? null, source: g?.source ?? null, line: g?.line ?? null });
  const side = unidentified(before) ? 'before-unidentified' : unidentified(after) ? 'after-unidentified' : null;
  if (side) return { gapComparison: side, gapNote: GAP_NOTES[side], gapChanges: after.gaps.map(g => record('gap-unidentified', g)) };
  const left = new Map();
  for (const g of before.gaps) left.set(g.id, (left.get(g.id) ?? 0) + 1);
  const gapChanges = [];
  for (const g of after.gaps) { const n = left.get(g.id) ?? 0; if (n) left.set(g.id, n - 1); else gapChanges.push(record('gap-added', g)); }
  for (const g of before.gaps) { const n = left.get(g.id) ?? 0; if (n) { left.set(g.id, n - 1); gapChanges.push(record('gap-removed', g)); } }
  return { gapComparison: 'identity', gapChanges };
}
