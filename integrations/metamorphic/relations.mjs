// Metamorphic relations over record deltas (scopehaven-metamorphic/1): a finding without a task-specific assertion.
//
// The tenant-swap relation. One declared task runs twice with a scripted or recorded model: once as identity A, once
// as identity B. Each run's record delta (rows inserted, updated and deleted per table, and outbound sends by
// destination and declared fields) is normalised and the two must be equal:
//   * every declared identity value is renamed by role, per run: the acting identity's values read self:<role> and
//     the other identity's other:<role>, so renaming A's identifiers to B's and B's to A's is one comparison
//     (whole values only: a string equal to a declared value, an object key, or an array element);
//   * each table's declared ignorable columns (generated keys, timestamps, random references) are dropped before
//     comparison. A declared key that is ignorable still matches rows across one run's own snapshots, and the two
//     runs' rows are then compared as a multiset of contents. A table the profile does not declare is compared
//     whole, with its key detected as the collateral state diff detects it (a unique `id`, else a multiset);
//   * sends keep their source, destination name, resource, outcome and declared captured fields; a declared send
//     may name captured pointers to ignore. Body digests are salted per recorder, so they are never compared.
// Any row or send present in one delta and not the other is a finding naming the table (or destination), the key
// and the side. Equal deltas read "no difference observed", never pass: the relation is FAIL-only, because with
// any model run-to-run variance can make two runs differ, and a pass needs allowlisted deterministic evidence
// (a check with its own assertion). Every row says so in its custody tag.
//
// The complement (TENANT family). A symmetric bug (A's task writes B's row and B's writes A's) satisfies the swap.
// So the same normalised deltas are also read for any changed row or send that carries the other identity's
// declared value, in either run. It is the record-delta reading of the TENANT family's rule (TENANT-01 in
// src/domain.mjs for the owned fixture, json.noForeignValues in src/tenant-values.mjs for responses), not a
// replacement for either: it reads only the declared values, whole, in the observed records.
//
// Inputs. A run record per side: { side, actor, task: { id, digest? }, model: { kind, id }, states?, windows? }.
//   states   { before, after }: whole-state snapshots ({ table: rows[] }, the collateral state diff's input), with
//            row values, so the projection applies (content level). Custody: the application's own store.
//   windows  observer windows (scopehaven-effect/1), one per observer instance for the task. sql-snapshot windows
//            carry keys and whole-row digests only, so a table seen only there is compared by operation and
//            normalised key (key level; a declared ignorable key compares counts), never by content: a snapshot
//            observer that seals a projected digest is a proposal (README). http-egress,
//            smtp-capture and provider-feed send windows compare by destination and declared fields. Windows of
//            other sources are listed as not compared.
// Missing or unusable evidence on either side (a missing snapshot, a failed or partial window, a send window that
// is not complete and authoritative, an observer present on one side only, a send with an unknown outcome, a live
// model, two different tasks) reads inconclusive with its reasons, never a finding.
//
// Pure: no I/O, no clock and no randomness. Findings carry tables, keys, field names, destinations and roles, never
// a row value: contents are compared as sha256 digests of typed canonical forms (state-diff.mjs `canonical`).
import { createHash } from 'node:crypto';
import { canonical, StateDiffError } from '../collateral/state-diff.mjs';
import { validateWindow, custodyWindows, EFFECT_LIMITS } from '../observers/events.mjs';
import { custodyOf, CUSTODY, CUSTODY_BY_SOURCE } from '../../src/custody.mjs';
import { digest } from '../../src/domain.mjs';

export const METAMORPHIC_SCHEMA = 'scopehaven-metamorphic/1';
export const METAMORPHIC_RESULT_SCHEMA = 'scopehaven-metamorphic-result/1';
export const RELATIONS = Object.freeze(['tenant-swap']);
// Designed in README.md, built in a CVP session: a profile naming it is refused here.
export const DESIGNED_RELATIONS = Object.freeze(['canary-plant']);
export const MODEL_KINDS = Object.freeze(['scripted', 'recorded']);
export const SIDES = Object.freeze(['A', 'B']);
export const SWAP_CHECK = 'META-TENANT-SWAP';
export const OTHER_CHECK = 'META-TENANT-OTHER';
// Never 'pass': a FAIL-only relation either flags a finding or reads inconclusive.
export const RELATION_STATUSES = Object.freeze(['fail', 'inconclusive']);
export const RELATION_VERDICTS = Object.freeze(['fail', 'no-difference-observed', 'no-other-identity-observed', 'inconclusive']);
export const FAIL_ONLY_TAG = 'fail-only';
export const SNAPSHOT_SOURCES = Object.freeze(['sql-snapshot']);
export const SEND_SOURCES = Object.freeze(['http-egress', 'smtp-capture', 'provider-feed']);
export const METAMORPHIC_LIMITS = Object.freeze({ roles: 32, valueChars: 200, actorChars: 128, taskChars: 120, tables: 64, ignore: 32, sends: 32,
  rowsPerTable: 10000, findings: 64, depth: 32 });
export const FAIL_ONLY_BASIS = 'This relation is FAIL-only: it compares two runs of one task under a scripted or recorded model and can flag a difference, never grant a pass (a pass needs allowlisted deterministic evidence, such as a check with its own assertion).';

export class MetamorphicError extends Error { constructor(code) { super(`Metamorphic profile: ${code}.`); this.name = 'MetamorphicError'; this.code = code; } }
// Run data that cannot be compared: becomes an inconclusive reason, never a finding.
class Unusable extends Error { constructor(code) { super(code); this.code = code; } }
const refuse = code => { throw new MetamorphicError(code); };
const unusable = code => { throw new Unusable(code); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const bounded = (value, maximum) => typeof value === 'string' && value.length >= 1 && value.length <= maximum && !/[\u0000-\u001f\u007f]/.test(value);
const onlyKeys = (value, keys) => Object.keys(value).every(key => keys.includes(key));
const COLUMN = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const ROLE = /^[a-z][A-Za-z0-9_-]{0,31}$/;
const POINTER = /^(\/([^~/]|~[01])*){1,32}$/;
const listOf = (list, ok) => Array.isArray(list) && list.length >= 1 && list.length <= METAMORPHIC_LIMITS.ignore && list.every(ok) && new Set(list).size === list.length;
const columns = list => listOf(list, c => typeof c === 'string' && COLUMN.test(c));
const pointers = list => listOf(list, p => typeof p === 'string' && p.length <= 200 && POINTER.test(p));
const sha = text => createHash('sha256').update(text).digest('hex');
const sorted = list => [...list].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
const unique = list => sorted(new Set(list));

// ---------------------------------------------------------------------------------------------------------------
// The profile declaration.
//   { schema, id?, relation: 'tenant-swap',
//     identities: { A: { actor, values: { <role>: <value> } }, B: { actor, values: { <same roles> } } },
//     tables?: [{ table, key?: <column> | null, ignore?: [<column>], identity?: [<column>] }],
//     sends?: [{ source, name, ignore?: [<captured pointer>], identity?: [<captured pointer>] }] }
// Every value is distinct across both identities (a value both share could not say whose it is). A string equal to a
// declared value is renamed anywhere; a number only in a declared identity column or pointer (an integer tenant key),
// because small numbers elsewhere are amounts and counts. A send declaration applies to both identities' destinations
// of the same role.
export function validateMetamorphicProfile(profile) {
  if (!plain(profile) || !onlyKeys(profile, ['schema', 'id', 'relation', 'identities', 'tables', 'sends'])) refuse('profile');
  if (profile.schema !== METAMORPHIC_SCHEMA) refuse('schema');
  if (profile.id !== undefined && !bounded(profile.id, 80)) refuse('id');
  if (DESIGNED_RELATIONS.includes(profile.relation)) refuse('relation-designed-only');
  if (!RELATIONS.includes(profile.relation)) refuse('relation');
  const identities = profile.identities;
  if (!plain(identities) || sorted(Object.keys(identities)).join() !== SIDES.join()) refuse('identities');
  const roles = side => {
    const identity = identities[side];
    if (!plain(identity) || !onlyKeys(identity, ['actor', 'values']) || !bounded(identity.actor, METAMORPHIC_LIMITS.actorChars) || !plain(identity.values)) refuse(`identity-${side}`);
    const names = Object.keys(identity.values);
    if (!names.length || names.length > METAMORPHIC_LIMITS.roles || !names.every(role => ROLE.test(role) && bounded(identity.values[role], METAMORPHIC_LIMITS.valueChars))) refuse(`identity-values-${side}`);
    return sorted(names).join();
  };
  if (roles('A') !== roles('B')) refuse('identity-roles');
  if (identities.A.actor === identities.B.actor) refuse('identity-actors');
  const values = SIDES.flatMap(side => Object.values(identities[side].values));
  if (new Set(values).size !== values.length) refuse('identity-values-repeated');
  if (profile.tables !== undefined) {
    if (!Array.isArray(profile.tables) || profile.tables.length > METAMORPHIC_LIMITS.tables) refuse('tables');
    for (const t of profile.tables) {
      if (!plain(t) || !onlyKeys(t, ['table', 'key', 'ignore', 'identity']) || !bounded(t.table, EFFECT_LIMITS.name)) refuse('table');
      if (t.key !== undefined && t.key !== null && !COLUMN.test(t.key)) refuse('table-key');
      if (t.ignore !== undefined && !columns(t.ignore)) refuse('table-ignore');
      if (t.identity !== undefined && (!columns(t.identity) || t.identity.some(c => t.ignore?.includes(c)))) refuse('table-identity');
    }
    if (new Set(profile.tables.map(t => t.table)).size !== profile.tables.length) refuse('table-repeated');
  }
  if (profile.sends !== undefined) {
    if (!Array.isArray(profile.sends) || profile.sends.length > METAMORPHIC_LIMITS.sends) refuse('sends');
    for (const s of profile.sends) {
      if (!plain(s) || !onlyKeys(s, ['source', 'name', 'ignore', 'identity']) || !SEND_SOURCES.includes(s.source) || !bounded(s.name, EFFECT_LIMITS.name)) refuse('send');
      if (s.ignore === undefined && s.identity === undefined) refuse('send-ignore');
      if (s.ignore !== undefined && !pointers(s.ignore)) refuse('send-ignore');
      if (s.identity !== undefined && (!pointers(s.identity) || s.identity.some(p => s.ignore?.includes(p)))) refuse('send-identity');
    }
    // A declaration applies to both identities' destinations of its role, so two for one role (or one name) are refused.
    const roleOfName = name => SIDES.map(side => Object.entries(identities[side].values).find(([, v]) => v === name)?.[0]).find(Boolean);
    if (new Set(profile.sends.map(s => `${s.source}\n${roleOfName(s.name) ? `role:${roleOfName(s.name)}` : `name:${s.name}`}`)).size !== profile.sends.length) refuse('send-repeated');
  }
  return profile;
}

// ---------------------------------------------------------------------------------------------------------------
// Renaming by role. One map per run: the acting identity's values read self:<role>, the other's other:<role>.
// A declared value that reads as a number (an integer tenant key, '1') is renamed only in declared identity columns or
// pointers, as text, number or bigint: elsewhere '1' is a row id, a quantity or a counter. Other values are renamed anywhere.
const NUMERIC_TEXT = /^[+-]?\d+(\.\d+)?$/;
function identityMap(profile, side) {
  const map = new Map(), other = side === 'A' ? 'B' : 'A';
  for (const [role, value] of Object.entries(profile.identities[side].values)) map.set(value, `self:${role}`);
  for (const [role, value] of Object.entries(profile.identities[other].values)) map.set(value, `other:${role}`);
  return map;
}
// The role a value reads as here, or undefined: a numeric-looking value only where `numeric` (an identity column) holds.
const roleIn = (value, ids, numeric) => {
  const text = typeof value === 'string' ? value : (typeof value === 'number' && Number.isFinite(value)) || typeof value === 'bigint' ? String(value) : null;
  if (text === null || !ids.has(text) || (NUMERIC_TEXT.test(text) && !numeric) || (typeof value !== 'string' && !numeric)) return undefined;
  return ids.get(text);
};
const keyOrder = ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0);
// A typed canonical form with declared identity values renamed. A renamed value ('r:self:tenant', or 'r:n:self:tenant'
// for a number in an identity column) can never equal an application string, which canonical() writes as s:"...".
function canon(value, ids, depth = 0, numeric = false) {
  if (depth > METAMORPHIC_LIMITS.depth) unusable('value-depth');
  const role = roleIn(value, ids, numeric);
  if (role !== undefined) return typeof value === 'string' ? `r:${role}` : `r:n:${role}`;
  if (Array.isArray(value)) return `[${value.map(v => canon(v, ids, depth + 1, numeric)).join(',')}]`;
  if (plain(value)) return `{${Object.keys(value).map(k => [roleIn(k, ids, false) !== undefined ? `r:${ids.get(k)}` : JSON.stringify(k), value[k]]).sort(keyOrder).map(([k, v]) => `${k}:${canon(v, ids, depth + 1, numeric)}`).join(',')}}`;
  try { return canonical(value); } catch (error) { if (error instanceof StateDiffError) unusable('value-unsupported'); throw error; }
}
// The other identity's roles anywhere in a value (strings, array elements, object keys).
function otherRoles(value, ids, numeric = false, found = new Set(), depth = 0) {
  if (depth > METAMORPHIC_LIMITS.depth) return found;
  const hit = (v, inIdentity = numeric) => { const role = roleIn(v, ids, inIdentity); if (role?.startsWith('other:')) found.add(role.slice(6)); };
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'bigint') hit(value);
  else if (Array.isArray(value)) for (const v of value) otherRoles(v, ids, numeric, found, depth + 1);
  else if (plain(value)) for (const [k, v] of Object.entries(value)) { hit(k, false); otherRoles(v, ids, numeric, found, depth + 1); }
  return found;
}

// ---------------------------------------------------------------------------------------------------------------
// One run's normalised delta. Each element: { kind, via, table | source+name, op, key, keyText, content, fields,
// changed?, other }. `key` is the renamed key (null when the key is ignorable or the table has none); `content` the
// digest the two runs compare; `fields` per-field digests, so a pair of differing elements names the fields.
const keyText = value => (typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value))) ? String(value) : null;
function keyFieldOf(name, before, after, declared) {
  const isUnique = (rows, field) => { const keys = rows.map(r => keyText(r[field])); return keys.every(k => k !== null && k.length <= 160) && new Set(keys).size === keys.length; };
  if (declared !== undefined) {
    if (declared === null) return null;
    if (!isUnique(before, declared) || !isUnique(after, declared)) unusable(`key-not-unique:${name}`);
    return declared;
  }
  return before.length + after.length > 0 && isUnique(before, 'id') && isUnique(after, 'id') ? 'id' : null;
}

function stateElements(states, profile, ids) {
  const { before, after } = states, elements = [];
  let ignoredOnly = 0;
  const names = unique([...Object.keys(before), ...Object.keys(after)]);
  if (names.length > METAMORPHIC_LIMITS.tables) unusable('table-limit');
  for (const name of names) {
    if (!Object.hasOwn(before, name) || !Object.hasOwn(after, name)) unusable(`table-missing:${name}`);
    const a = before[name], b = after[name];
    if (!Array.isArray(a) || !Array.isArray(b) || !a.every(plain) || !b.every(plain)) unusable(`table-shape:${name}`);
    if (a.length > METAMORPHIC_LIMITS.rowsPerTable || b.length > METAMORPHIC_LIMITS.rowsPerTable) unusable(`row-limit:${name}`);
    const declared = profile.tables?.find(t => t.table === name), ignore = new Set(declared?.ignore ?? []), numeric = new Set(declared?.identity ?? []);
    const key = keyFieldOf(name, a, b, declared?.key);
    const project = row => Object.fromEntries(Object.entries(row).filter(([field]) => field !== key && !ignore.has(field)));
    const keyed = key !== null && !ignore.has(key);
    // One column's canonical form (numbers renamed only in identity columns), and a row's, column by column.
    const cell = (f, v) => canon(v, ids, 1, numeric.has(f));
    const rowCanon = r => `{${Object.keys(r).sort().map(f => `${JSON.stringify(f)}:${cell(f, r[f])}`).join(',')}}`;
    // An update carries both contents, field by field (before>after), so a row that started differently also differs
    // and the finding names the field. `changed` lists the fields the update moved.
    const element = (op, row, old = null) => {
      const projected = project(row), previous = old === null ? null : project(old), keyValue = key === null ? null : row[key];
      const at = (r, f) => (Object.hasOwn(r, f) ? cell(f, r[f]) : '-');
      const names = unique(Object.keys({ ...projected, ...(previous ?? {}) }));
      const fields = Object.fromEntries(names.map(f => [f, sha(previous === null ? at(projected, f) : `${at(previous, f)}>${at(projected, f)}`)]));
      const changed = previous === null ? null : names.filter(f => at(previous, f) !== at(projected, f));
      const touched = [projected, ...(previous === null ? [] : [previous])];
      const other = [...(keyed && otherRoles(keyValue, ids, numeric.has(key)).size ? ['(key)'] : []), ...touched.flatMap(r => Object.entries(r).filter(([f, v]) => otherRoles(v, ids, numeric.has(f)).size).map(([f]) => f))];
      return { kind: 'row', via: 'states', table: name, op, key: keyed ? cell(key, keyValue) : null, keyText: key === null ? null : keyText(keyValue),
        content: sha(previous === null ? rowCanon(projected) : `${rowCanon(previous)}>${rowCanon(projected)}`), fields, ...(changed ? { changed } : {}), other: unique(other) };
    };
    if (key !== null) {
      const left = new Map(a.map(r => [keyText(r[key]), r])), right = new Map(b.map(r => [keyText(r[key]), r]));
      for (const [k, row] of right) {
        if (!left.has(k)) { elements.push(element('insert', row)); continue; }
        const old = left.get(k);
        if (typeof old[key] !== typeof row[key] || rowCanon(project(old)) !== rowCanon(project(row))) elements.push(element('update', row, old));
        else if (rowCanon(old) !== rowCanon(row)) ignoredOnly++;
      }
      for (const [k, row] of left) if (!right.has(k)) elements.push(element('delete', row));
    } else {
      // No key: a multiset of projected rows. A surplus is an insert, a shortfall a delete.
      const count = rows => rows.reduce((m, r) => { const c = rowCanon(project(r)); m.set(c, [...(m.get(c) ?? []), r]); return m; }, new Map());
      const left = count(a), right = count(b);
      for (const c of unique([...left.keys(), ...right.keys()])) {
        const l = left.get(c) ?? [], r = right.get(c) ?? [];
        for (let i = l.length; i < r.length; i++) elements.push(element('insert', r[i]));
        for (let i = r.length; i < l.length; i++) elements.push(element('delete', l[i]));
      }
    }
  }
  return { elements, ignoredOnly, tables: names };
}

const committed = e => e.outcome === 'committed' || e.outcome === 'denied';
const sendKey = (name, ids) => (ids.has(name) ? `role:${ids.get(name).slice(ids.get(name).indexOf(':') + 1)}` : `name:${name}`);
function windowElements(windows, profile, ids, stateTables) {
  const elements = [];
  for (const w of windows) {
    if (SNAPSHOT_SOURCES.includes(w.source)) {
      for (const e of w.events) {
        // A table the run's whole-state snapshots also hold is decided there, by content.
        if (stateTables.includes(e.name) || !['insert', 'update', 'delete'].includes(e.operation)) continue;
        if (e.outcome !== 'committed') unusable(`row-outcome-${e.outcome}:${w.instanceId}`);
        const declared = profile.tables?.find(t => t.table === e.name), raw = e.resource === null ? null : e.resource.slice(e.resource.indexOf('/') + 1);
        // No comparable key: an ignorable or undeclared-as-none key, or a keyless table's row digest ('~...'), counts only.
        // The key column as the states path reads it: the declared key, else 'id'. A numeric-looking key is renamed only
        // when that column is a declared identity column (the observers write every key as text).
        const keyColumn = declared?.key === undefined ? 'id' : declared.key, keyIdentity = Boolean(declared?.identity?.includes(keyColumn));
        const keyless = raw === null || raw.startsWith('~') || keyColumn === null || Boolean(declared?.ignore?.includes(keyColumn));
        elements.push({ kind: 'row', via: `${w.source}/${w.instanceId}`, table: e.name, op: e.operation, key: keyless ? null : canon(raw, ids, 0, keyIdentity), keyText: raw,
          content: 'not-projected', fields: {}, other: !keyless && otherRoles(raw, ids, keyIdentity).size ? ['(key)'] : [] });
      }
    } else if (SEND_SOURCES.includes(w.source)) {
      for (const e of w.events) {
        if (e.operation !== 'send') continue;
        if (!committed(e)) unusable(`send-outcome-${e.outcome}:${w.instanceId}`);
        // A declaration names one destination; it applies to the other identity's destination of the same role.
        const declared = profile.sends?.find(s => s.source === w.source && sendKey(s.name, ids) === sendKey(e.name, ids));
        const ignore = new Set(declared?.ignore ?? []), numeric = new Set(declared?.identity ?? []);
        const values = plain(e.captured?.values) ? Object.fromEntries(Object.entries(e.captured.values).filter(([pointer]) => !ignore.has(pointer))) : {};
        const record = { '#status': e.captured?.status ?? null, ...values };
        const fields = Object.fromEntries(Object.entries(record).map(([pointer, v]) => [pointer, sha(canon(v, ids, 1, numeric.has(pointer)))]));
        const other = [...(otherRoles(e.name, ids).size ? ['(name)'] : []), ...(otherRoles(e.resource, ids).size ? ['(resource)'] : []),
          ...Object.entries(values).filter(([pointer, v]) => otherRoles(v, ids, numeric.has(pointer)).size).map(([pointer]) => pointer)];
        elements.push({ kind: 'send', via: `${w.source}/${w.instanceId}`, source: w.source, name: canon(e.name, ids), nameText: e.name, op: 'send', outcome: e.outcome,
          key: canon(e.resource, ids), keyText: e.resource, content: sha(`{${Object.keys(record).sort().map(k => `${JSON.stringify(k)}:${fields[k]}`).join(',')}}`), fields, other: unique(other),
          // A destination that captures but could not read this body: its declared fields were not compared.
          ...(e.captured && e.captured.status !== 'captured' ? { unread: true } : {}) });
      }
    }
  }
  return elements;
}

// ---------------------------------------------------------------------------------------------------------------
// Run checks: what has to hold on each side before two deltas can be compared.
const COMPARED = [...SNAPSHOT_SOURCES, ...SEND_SOURCES];
function readRun(run, side, profile, reasons) {
  if (!plain(run)) { reasons.push(`run-missing:${side}`); return null; }
  if (run.side !== undefined && run.side !== side) reasons.push(`side-mismatch:${side}`);
  if (run.actor !== profile.identities[side].actor) reasons.push(`actor-mismatch:${side}`);
  if (!plain(run.task) || !bounded(run.task.id, METAMORPHIC_LIMITS.taskChars)) reasons.push(`task-missing:${side}`);
  if (!plain(run.model) || !MODEL_KINDS.includes(run.model.kind) || !bounded(run.model.id, 120)) reasons.push(`model-not-scripted:${side}`);
  if (run.states !== undefined) for (const point of ['before', 'after']) if (!plain(run.states?.[point])) reasons.push(`snapshot-missing:${side}:${point}`);
  const windows = run.windows ?? [];
  if (!Array.isArray(windows)) { reasons.push(`windows-invalid:${side}`); return null; }
  custodyWindows(windows, 'tenantSwap');
  windows.forEach((w, i) => validateWindow(w, `run ${side} window ${i + 1}`));
  const seen = new Set(), scopes = new Map();
  for (const w of windows.filter(w => COMPARED.includes(w.source))) {
    const id = `${w.source}/${w.instanceId}`;
    if (seen.has(id)) reasons.push(`window-repeated:${side}:${w.instanceId}`);
    seen.add(id); scopes.set(id, canonical(w.scope));
    if (w.coverage === 'failed') reasons.push(`window-failed:${side}:${w.instanceId}${w.reason ? `:${w.reason}` : ''}`);
    // Partial includes a window with destination-scoped late entries (coverage v2): sends it does not list.
    else if (w.coverage === 'partial') reasons.push(`window-partial:${side}:${w.instanceId}`);
    else if (SEND_SOURCES.includes(w.source) && (w.scope.evidence !== 'authoritative' || w.coverage !== 'complete')) reasons.push(`window-presence-only:${side}:${w.instanceId}`);
  }
  return { run, windows, instances: seen, scopes };
}

function extract(read, profile, side, reasons) {
  if (!read || reasons.some(r => r.startsWith(`snapshot-missing:${side}`))) return null;
  const ids = identityMap(profile, side);
  try {
    const states = read.run.states === undefined ? { elements: [], ignoredOnly: 0, tables: [] } : stateElements(read.run.states, profile, ids);
    return { ...states, elements: [...states.elements, ...windowElements(read.windows, profile, ids, states.tables)] };
  } catch (error) {
    if (error instanceof Unusable) { reasons.push(`${error.code}:${side}`); return null; }
    throw error;
  }
}

const identity = e => JSON.stringify([e.kind, e.table ?? `${e.source}\n${e.name}`, e.op, e.outcome ?? null, e.key, e.content]);
const slot = e => JSON.stringify([e.kind, e.table ?? `${e.source}\n${e.name}`, e.op, e.outcome ?? null, e.key]);
// The multiset difference, one finding per unmatched element; an A-only and a B-only element in the same slot
// (same table or destination, operation and key) with exactly one each are one finding naming the fields that differ.
function compare(a, b) {
  const bag = list => list.reduce((m, e) => { const k = identity(e); m.set(k, [...(m.get(k) ?? []), e]); return m; }, new Map());
  const left = bag(a), right = bag(b), onlyA = [], onlyB = [];
  for (const k of unique([...left.keys(), ...right.keys()])) {
    const l = left.get(k) ?? [], r = right.get(k) ?? [];
    onlyA.push(...l.slice(r.length)); onlyB.push(...r.slice(l.length));
  }
  const findings = [], bySlot = list => list.reduce((m, e) => { const k = slot(e); m.set(k, [...(m.get(k) ?? []), e]); return m; }, new Map());
  const slotsA = bySlot(onlyA), slotsB = bySlot(onlyB);
  for (const k of unique([...slotsA.keys(), ...slotsB.keys()])) {
    const l = slotsA.get(k) ?? [], r = slotsB.get(k) ?? [];
    if (l.length === 1 && r.length === 1) {
      const fields = unique(Object.keys({ ...l[0].fields, ...r[0].fields }).filter(f => l[0].fields[f] !== r[0].fields[f]));
      // A capture status that differs where either body went unread (over the cap, not JSON) can come from the identity
      // values' own lengths: that pair is not compared.
      const unreadPair = l[0].kind === 'send' && fields.includes('#status') && (l[0].unread || r[0].unread);
      findings.push({ ...describe(l[0], 'both-differ'), keyTextB: r[0].keyText, fields, via: unique([l[0].via, r[0].via]), ...(unreadPair ? { unreadPair: true } : {}) });
    } else {
      findings.push(...l.map(e => ({ ...describe(e, 'A-only'), via: [e.via] })), ...r.map(e => ({ ...describe(e, 'B-only'), via: [e.via] })));
    }
  }
  return findings;
}
const roleOf = key => (typeof key === 'string' && key.startsWith('r:') ? key.slice(key.startsWith('r:n:') ? 4 : 2) : null);
function describe(e, side) {
  const where = e.kind === 'row' ? { table: e.table } : { source: e.source, destination: e.nameText };
  return { side, kind: e.kind, ...where, op: e.op, ...(e.outcome ? { outcome: e.outcome } : {}), key: e.keyText, keyRole: roleOf(e.key), ...(e.changed ? { changed: e.changed } : {}),
    ...(e.content === 'not-projected' ? { level: 'key' } : {}) };
}

function weakest(list) {
  const present = list.filter(c => CUSTODY.includes(c));
  return present.length ? present.reduce((w, c) => (CUSTODY.indexOf(c) < CUSTODY.indexOf(w) ? c : w)) : null;
}
// Custody of each place an element came from, keyed as elements name it: 'states' (the run's whole-state snapshots, the
// application's own store) or '<source>/<instanceId>', which no window can name 'states'.
function custodyByVia(read) {
  const map = new Map([['states', CUSTODY_BY_SOURCE['sql-snapshot']]]);
  for (const w of read?.windows ?? []) if (COMPARED.includes(w.source)) map.set(`${w.source}/${w.instanceId}`, custodyOf(w));
  return map;
}
// A run whose identity is in doubt (another actor, another slot, no task) is not read under that slot's identity.
const misread = (reasons, side) => reasons.some(r => [`run-missing:${side}`, `side-mismatch:${side}`, `actor-mismatch:${side}`, `task-missing:${side}`].includes(r));

// ---------------------------------------------------------------------------------------------------------------
// The relation. runs: { A: <run record>, B: <run record> }. Returns the result and its two report rows.
export function tenantSwap(profile, runs) {
  validateMetamorphicProfile(profile);
  if (!plain(runs)) refuse('runs');
  const reasons = [];
  const reads = Object.fromEntries(SIDES.map(side => [side, readRun(runs[side], side, profile, reasons)]));
  if (reads.A && reads.B) {
    const [a, b] = [reads.A.run, reads.B.run];
    if (plain(a.task) && plain(b.task) && (a.task.id !== b.task.id || (a.task.digest !== undefined && b.task.digest !== undefined && a.task.digest !== b.task.digest))) reasons.push('task-mismatch');
    if (plain(a.model) && plain(b.model) && a.model.id !== b.model.id) reasons.push('model-mismatch');
    for (const side of SIDES) {
      const other = side === 'A' ? reads.B : reads.A;
      if ((reads[side].run.states === undefined) !== (other.run.states === undefined) && reads[side].run.states === undefined) reasons.push(`snapshot-missing:${side}`);
      for (const id of other.instances) if (!reads[side].instances.has(id)) reasons.push(`collector-missing:${side}:${id.slice(id.indexOf('/') + 1)}`);
    }
    // One observer, two scopes (another table list, another evidence level): the sides did not observe the same things.
    for (const [id, scope] of reads.A.scopes) if (reads.B.scopes.has(id) && reads.B.scopes.get(id) !== scope) reasons.push(`scope-differs:${id.slice(id.indexOf('/') + 1)}`);
  }
  const deltas = Object.fromEntries(SIDES.map(side => [side, extract(reads[side], profile, side, reasons)]));
  // A table one side's snapshots hold and the other's do not is missing evidence, never "nothing changed there".
  if (deltas.A && deltas.B && reads.A.run.states && reads.B.run.states) for (const side of SIDES) {
    const other = side === 'A' ? deltas.B : deltas.A;
    for (const table of other.tables) if (!deltas[side].tables.includes(table)) reasons.push(`table-missing:${table}:${side}`);
  }
  // Neither side read a table or a compared observer: there is nothing to compare, not an equal nothing.
  if (deltas.A && deltas.B && !reads.A.instances.size && !reads.B.instances.size && !deltas.A.tables.length && !deltas.B.tables.length) reasons.push('nothing-observed');
  const custody = Object.fromEntries(SIDES.map(side => [side, custodyByVia(reads[side])]));
  const custodyOfVias = vias => weakest(SIDES.flatMap(side => vias.map(v => custody[side].get(v))));
  let swapFindings = reasons.length === 0 ? compare(deltas.A.elements, deltas.B.elements) : [];
  const unreadPairs = swapFindings.filter(f => f.unreadPair);
  if (unreadPairs.length) { reasons.push(...unreadPairs.map(f => `capture-unread:${f.via.join('+')}`)); swapFindings = []; }
  const reasonList = unique(reasons);
  const comparable = reasonList.length === 0;
  const otherFindings = SIDES.filter(side => !misread(reasonList, side)).flatMap(side => (deltas[side]?.elements ?? []).filter(e => e.other.length).map(e => ({ ...describe(e, side), fields: e.other, via: [e.via] })));
  const allVias = unique(SIDES.flatMap(side => (deltas[side] ? [...(reads[side].run.states ? ['states'] : []), ...reads[side].instances] : [])));
  const notCompared = unique(SIDES.flatMap(side => (reads[side]?.windows ?? []).filter(w => !COMPARED.includes(w.source)).map(w => `${w.source}/${w.instanceId}`)));
  const counts = Object.fromEntries(SIDES.map(side => [side, deltas[side] ? { rows: deltas[side].elements.filter(e => e.kind === 'row').length, sends: deltas[side].elements.filter(e => e.kind === 'send').length,
    sendsUnread: deltas[side].elements.filter(e => e.unread).length, ignoredOnlyUpdates: deltas[side].ignoredOnly } : null]));
  const task = reads.A?.run.task?.id ?? reads.B?.run.task?.id ?? null, model = reads.A?.run.model?.kind ?? null;
  const result = { schema: METAMORPHIC_RESULT_SCHEMA, relation: 'tenant-swap', profileDigest: digest(profile), task, model, comparable, reasons: reasonList,
    counts, compared: allVias, notCompared, findings: { swap: swapFindings, other: otherFindings } };
  return { ...result, rows: relationRows(result, { actors: [profile.identities.A.actor, profile.identities.B.actor], custodyOfVias }) };
}

const capped = list => ({ findings: list.slice(0, METAMORPHIC_LIMITS.findings), ...(list.length > METAMORPHIC_LIMITS.findings ? { truncated: list.length - METAMORPHIC_LIMITS.findings } : {}) });
const findingText = f => `${f.side} ${f.op} ${f.table ?? `${f.source} ${f.destination}`}${f.key === null || f.key === undefined ? '' : ` ${f.keyRole ? `<${f.keyRole}>` : f.key}`}${f.fields?.length ? ` (fields ${f.fields.join(', ')})` : ''}`;
// Two rows in the shape of the existing check rows (collateralRows): check, status, verdict, reason, basis, custody,
// plus the FAIL-only tag and the findings. A relation row is never 'pass'.
export function relationRows(result, { actors = ['A', 'B'], custodyOfVias = () => null } = {}) {
  const tag = custody => ({ custody, custodyTag: custody ? `${FAIL_ONLY_TAG}:${custody}` : FAIL_ONLY_TAG, failOnly: true });
  const pair = `${result.task ?? 'the task'} under ${actors[0]} and under ${actors[1]}`;
  const swap = result.findings.swap, other = result.findings.other, unread = (result.counts?.A?.sendsUnread ?? 0) + (result.counts?.B?.sendsUnread ?? 0);
  const swapRow = !result.comparable
    ? { check: SWAP_CHECK, status: 'inconclusive', verdict: 'inconclusive', reason: result.reasons[0], reasons: result.reasons, basis: `Not compared (${result.reasons.join(', ')}). ${FAIL_ONLY_BASIS}`.slice(0, 1200), ...tag(null), ...capped([]) }
    : swap.length
      ? { check: SWAP_CHECK, status: 'fail', verdict: 'fail', reason: 'deltas-differ', reasons: [], basis: `${swap.length} difference${swap.length === 1 ? '' : 's'} between the record deltas of ${pair}, with identity values renamed by role: ${swap.slice(0, 8).map(findingText).join('; ')}${swap.length > 8 ? '; ...' : ''}. ${FAIL_ONLY_BASIS}`.slice(0, 1200), ...tag(custodyOfVias(unique(swap.flatMap(f => f.via)))), ...capped(swap) }
      : { check: SWAP_CHECK, status: 'inconclusive', verdict: 'no-difference-observed', reason: 'no-difference-observed', reasons: [], basis: `No difference observed between the record deltas of ${pair} (${result.compared.join(', ') || 'nothing'} compared${result.notCompared.length ? `; not compared: ${result.notCompared.join(', ')}` : ''}${unread ? `; ${unread} send${unread === 1 ? '' : 's'} compared by destination only, their declared fields unread` : ''}). ${FAIL_ONLY_BASIS}`.slice(0, 1200), ...tag(custodyOfVias(result.compared)), ...capped([]) };
  const otherRow = other.length
    ? { check: OTHER_CHECK, family: 'TENANT', status: 'fail', verdict: 'fail', reason: 'other-identity-changed', reasons: result.reasons, basis: `${other.length} change${other.length === 1 ? '' : 's'} carrying the other identity's declared values: ${other.slice(0, 8).map(findingText).join('; ')}${other.length > 8 ? '; ...' : ''}. The record-delta complement of the TENANT family (TENANT-01, json.noForeignValues).${result.reasons.length ? ` The pair itself was not comparable (${result.reasons.join(', ')}); these come from runs read under their own identity.` : ''} ${FAIL_ONLY_BASIS}`.slice(0, 1200), ...tag(custodyOfVias(unique(other.flatMap(f => f.via)))), ...capped(other) }
    : result.reasons.length
      ? { check: OTHER_CHECK, family: 'TENANT', status: 'inconclusive', verdict: 'inconclusive', reason: result.reasons[0], reasons: result.reasons, basis: `No change carrying the other identity's declared values was observed, but not every record was read (${result.reasons.join(', ')}). ${FAIL_ONLY_BASIS}`.slice(0, 1200), ...tag(null), ...capped([]) }
      : { check: OTHER_CHECK, family: 'TENANT', status: 'inconclusive', verdict: 'no-other-identity-observed', reason: 'no-other-identity-observed', reasons: [], basis: `No change carrying the other identity's declared values in either run (${result.compared.join(', ') || 'nothing'} read). ${FAIL_ONLY_BASIS}`.slice(0, 1200), ...tag(custodyOfVias(result.compared)), ...capped([]) };
  return [swapRow, otherRow];
}
