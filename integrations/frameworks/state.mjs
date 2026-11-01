// In-process state observer: what an agent's own state looked like before the
// first turn and after the last, as collections of rows the COLLATERAL checks
// can diff (integrations/collateral/state-diff.mjs). Pure: no I/O; the SQLite
// reader is sqlite-state.mjs and the object-path reader is the adapter.
//
// The operator names what to read, never the app or the agent:
//   { collection, source: 'sqlite-file', table, key, where?, keep?, keepScalar?, remainder? }
//       a table of the operator-named SQLite file, read by ScopeHaven's own
//       process from a private copy (key 'rowid' or a unique column)
//   { collection, source: 'object-path', path, shape, key, valueField?, keep?, keepScalar?, keys?, remainder?, nullAs? }
//       an exported object inside the agent's process, read by ScopeHaven's
//       adapter between turns ('rows': an array of records; 'map': an object
//       keyed by `key`, whose plain values are rows or, with valueField, values)
//   { collection, source: 'object-path', path, shape: 'pointers', key, valueField, pointers, remainder: true }
//       declared values inside one object: one row per JSON pointer (RFC 6901,
//       such as '/itinerary/0/seat'), resolved here on the value the adapter sent
//   { collection, source: 'app-report', ... the object-path fields }
//       the same values, but produced by the application's own reporting hook
// Who took a snapshot decides what it can support (allowlist for pass): a
// snapshot ScopeHaven took can pass or fail a check; an app-reported one can
// fail it, never pass it (judge.mjs). In-process reads share the agent's
// process, so they are recorded as 'in-process' rather than out-of-process.
//
// Rows keep values only for the key and the fields the operator lists in
// `keep` (what the checks compare). Every other field is kept as a typed
// digest, so a diff still names the fields that moved without storing them.
// `where` (SQLite) limits a large table to the rows the scenario is about,
// and needs `remainder: true`: every other row of the table is folded into one
// digest row keyed '~remainder', so a change outside the watched rows, or a
// row moving into or out of the watch, still shows up as a change (and as
// collateral, since nothing may expect or allow it).
//
// Values inside lists and dicts (every real agent's state mixes them with
// scalars), all declared by the operator; ScopeHaven selects, never computes a
// value the app would supply:
// - `keepScalar` keeps a field's value in each row where it is a JSON scalar,
//   and a digest object { digest } where it is not, so a seat can be kept
//   beside an itinerary list. A digest object never equals a declared scalar,
//   and a scalar never reads as a digest.
// - shape 'pointers' keeps the value at each declared JSON pointer, kept the
//   same way. A pointer that does not resolve gives no row. Everything the
//   pointers leave out is one '~remainder' row: a digest of the object with
//   the pointed object keys removed and pointed array elements replaced by a
//   marker (array lengths stay in it).
// - `keys` with `remainder: true` (rows or map shapes) reads a declared key
//   subset of a large map or keyed list: the adapter sends only those entries
//   and one digest of every other entry ('~remainder', as for SQLite), so a
//   table too big for one state message is still watched whole.
// - `nullAs: 'empty'` reads a null value (an artifact not created yet, or a
//   path through null) as an empty collection; without it a null value fails
//   the snapshot, so a wrong path never reads as "nothing there". It is refused
//   beside a remainder, so a '~remainder' row is in both snapshots or neither
//   snapshot is taken.
// A '~remainder' row is never expected or allowed: no expectation may name it
// and no `where` selects it, so any change outside the declared part (SQLite
// rows outside a `where`, entries outside `keys`, values outside `pointers`)
// is collateral (COLLATERAL-01 fails), and a remainder that cannot be read
// fails the snapshot (the run is unusable). It can never help a check pass.
import { createHash } from 'node:crypto';
import { canonical, STATE_DIFF_LIMITS } from '../collateral/state-diff.mjs';

export const STATE_SOURCES = Object.freeze(['sqlite-file', 'object-path', 'app-report']);
export const STATE_LIMITS = Object.freeze({ projections: 16, keep: 32, whereValues: 64, path: 200, pointers: 32, pointer: 200, pointerTokens: 32, keys: 64, keyText: 160 });
export const OBJECT_SHAPES = Object.freeze(['rows', 'map', 'pointers']);
export const REMAINDER_KEY = '~remainder';
export const REMAINDER_FIELDS = Object.freeze(['rows', 'digest']);
export const TAKEN_BY = Object.freeze(['scopehaven', 'app']);
export class StateSpecError extends Error { constructor(code) { super(`State spec: ${code}.`); this.name = 'StateSpecError'; this.code = code; } }
const fail = code => { throw new StateSpecError(code); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
export const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const COLLECTION = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const DIGEST = /^#[0-9a-f]{64}$/;
const scalar = value => value === null || ['string', 'boolean'].includes(typeof value) || (typeof value === 'number' && Number.isFinite(value));
const onlyKeys = (value, keys) => Reflect.ownKeys(value).every(key => keys.includes(key));
const fieldList = (list, code) => { if (!Array.isArray(list ?? []) || (list ?? []).length > STATE_LIMITS.keep || !(list ?? []).every(f => IDENT.test(f))) fail(code); };

// A JSON pointer (RFC 6901) as its reference tokens. The whole value ('') is not a pointer here.
export function pointerTokens(pointer) {
  if (typeof pointer !== 'string' || !pointer.startsWith('/') || pointer.length > STATE_LIMITS.pointer || /[\u0000-\u001f\u007f]/.test(pointer)) fail('pointer');
  const tokens = pointer.slice(1).split('/');
  if (tokens.length > STATE_LIMITS.pointerTokens || tokens.some(t => /~(?![01])/.test(t))) fail('pointer');
  return tokens.map(t => t.replace(/~1/g, '/').replace(/~0/g, '~'));
}

export function validateProjection(p) {
  if (!plain(p) || !STATE_SOURCES.includes(p.source) || !COLLECTION.test(p.collection ?? '')) fail('projection');
  fieldList(p.keep, 'keep');
  fieldList(p.keepScalar, 'keep-scalar');
  // A field is kept one way: strictly (a scalar in every row) or where it is a scalar. The key is always strict.
  if ((p.keepScalar ?? []).some(f => f === p.key || (p.keep ?? []).includes(f))) fail('keep-scalar');
  if (p.source === 'sqlite-file') {
    if (!onlyKeys(p, ['collection', 'source', 'table', 'key', 'where', 'keep', 'keepScalar', 'remainder']) || !IDENT.test(p.table ?? '') || !IDENT.test(p.key ?? '')) fail('sqlite-projection');
    if (p.where !== undefined && !(plain(p.where) && Object.keys(p.where).length && Object.entries(p.where).every(([c, v]) => IDENT.test(c) && (scalar(v) || (Array.isArray(v) && v.length && v.length <= STATE_LIMITS.whereValues && v.every(scalar)))))) fail('where');
    if (p.remainder !== undefined && (typeof p.remainder !== 'boolean' || (p.remainder && p.where === undefined))) fail('remainder');
    // A watch with no remainder cannot see a row move in or out of it (a moved-in row would read as new).
    if (p.where !== undefined && p.remainder !== true) fail('where-needs-remainder');
  } else {
    if (!onlyKeys(p, ['collection', 'source', 'path', 'shape', 'key', 'valueField', 'keep', 'keepScalar', 'pointers', 'keys', 'remainder', 'nullAs']) || typeof p.path !== 'string' || !/^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$/.test(p.path) || p.path.length > STATE_LIMITS.path) fail('object-projection');
    if (!OBJECT_SHAPES.includes(p.shape) || !IDENT.test(p.key ?? '')) fail('object-shape');
    if (p.nullAs !== undefined && p.nullAs !== 'empty') fail('null-as');
    if (p.shape === 'pointers') {
      // One row per declared pointer: { [key]: name, [valueField]: value }, plus the remainder.
      if (!IDENT.test(p.valueField ?? '') || p.valueField === p.key) fail('value-field');
      if (p.keep !== undefined || p.keepScalar !== undefined || p.keys !== undefined) fail('pointers-fields');
      const entries = plain(p.pointers) ? Object.entries(p.pointers) : [];
      if (!entries.length || entries.length > STATE_LIMITS.pointers || !entries.every(([name]) => IDENT.test(name))) fail('pointers');
      const parsed = entries.map(([, pointer]) => JSON.stringify(pointerTokens(pointer)));
      if (new Set(parsed).size !== parsed.length) fail('pointer-repeated');
      // Values the pointers leave out must still show up: the remainder is required.
      if (p.remainder !== true) fail('pointers-need-remainder');
    } else {
      if (p.pointers !== undefined) fail('pointers-fields');
      if (p.valueField !== undefined && (p.shape !== 'map' || !IDENT.test(p.valueField))) fail('value-field');
      if (p.keys !== undefined) {
        // Map keys are strings; a keyed list's key values are strings or finite numbers, matched by
        // type. They must also differ as text, since the diff keys rows by String(key).
        const ok = k => (typeof k === 'string' ? k.length >= 1 && k.length <= STATE_LIMITS.keyText && k !== REMAINDER_KEY && !/[\u0000-\u001f\u007f]/.test(k) : p.shape === 'rows' && Number.isFinite(k));
        if (!Array.isArray(p.keys) || !p.keys.length || p.keys.length > STATE_LIMITS.keys || !p.keys.every(ok) || new Set(p.keys.map(String)).size !== p.keys.length) fail('keys');
      }
      if (p.remainder !== undefined && (typeof p.remainder !== 'boolean' || (p.remainder && p.keys === undefined))) fail('remainder');
      // As for a SQLite where: a key subset with no remainder would miss every change outside it.
      if (p.keys !== undefined && p.remainder !== true) fail('keys-need-remainder');
    }
    // A remainder row is in both snapshots or the snapshot fails: never null, so it can only be
    // updated, and an update must name its rows, which no expectation may do for the remainder.
    if (p.nullAs !== undefined && p.remainder === true) fail('null-as-remainder');
  }
  // The remainder row is { [key]: '~remainder', rows?, digest }: a key named like one of its own
  // fields would overwrite '~remainder', and the row would no longer read as the remainder.
  if (p.remainder === true && REMAINDER_FIELDS.includes(p.key)) fail('key-is-remainder-field');
  return p;
}

// What the harness asks the adapter for, per object path: the path, its source, and the
// declared key subset when there is one (the adapter then sends only those entries and the
// remainder digest). Pointers are resolved here, on the value sent, never by the adapter.
export const objectRequest = p => ({ path: p.path, source: p.source, ...(p.keys !== undefined ? { select: { shape: p.shape, key: p.key, keys: p.keys } } : {}) });

export function validateStateSpec(spec) {
  if (!plain(spec) || !onlyKeys(spec, ['sqliteFile', 'projections']) || !Array.isArray(spec.projections) || !spec.projections.length || spec.projections.length > STATE_LIMITS.projections) fail('state');
  spec.projections.forEach(validateProjection);
  if (new Set(spec.projections.map(p => p.collection)).size !== spec.projections.length) fail('collection-repeated');
  // The adapter answers { path: value }, so two object projections on one path would share one answer.
  const paths = spec.projections.filter(p => p.source !== 'sqlite-file').map(p => p.path);
  if (new Set(paths).size !== paths.length) fail('path-repeated');
  const sqlite = spec.projections.some(p => p.source === 'sqlite-file');
  if (sqlite !== (typeof spec.sqliteFile === 'string')) fail('sqlite-file');
  if (sqlite && !/^[A-Za-z0-9_.-]{1,128}$/.test(spec.sqliteFile)) fail('sqlite-file');
  return spec;
}

// A typed digest of one value. Byte arrays are digested as their bytes.
const typed = value => (value instanceof Uint8Array ? `bytes:${Buffer.from(value).toString('hex')}` : value);
export const valueDigest = value => `#${createHash('sha256').update(canonical(typed(value))).digest('hex')}`;
// A kept-where-scalar value: the scalar itself, or a digest object for anything else.
export const scalarOrDigest = value => (scalar(value) ? value : { digest: valueDigest(value) });
// One raw row reduced to what the record keeps: the key and kept fields as
// values (each must be a JSON scalar), keepScalar fields as values where they
// are scalars, everything else as a digest.
export function projectRow(raw, { key, keep = [], keepScalar = [] }) {
  if (!plain(raw)) throw new StateSpecError('row-shape');
  const row = {};
  for (const [field, value] of Object.entries(raw)) {
    if (field === key || keep.includes(field)) {
      if (!scalar(value)) throw new StateSpecError(`kept-value:${field}`);
      row[field] = value;
    } else if (keepScalar.includes(field)) row[field] = scalarOrDigest(value);
    else row[field] = valueDigest(value);
  }
  if (!Object.hasOwn(row, key)) throw new StateSpecError(`key-missing:${key}`);
  return row;
}

// The rows of one object-path value, before projection.
export function objectRows(value, p) {
  if (p.shape === 'rows') {
    if (!Array.isArray(value)) throw new StateSpecError('rows-not-array');
    return value;
  }
  if (!plain(value)) throw new StateSpecError('map-not-object');
  return Object.entries(value).map(([k, v]) => (p.valueField !== undefined ? { [p.key]: k, [p.valueField]: v } : plain(v) ? { ...v, [p.key]: k } : (() => { throw new StateSpecError('map-value'); })()));
}

// A declared key subset as the adapter answers it: { entries, remainder: { rows, digest } },
// where entries is the map (or keyed list) cut to the declared keys and the remainder digests
// every other entry. Anything else (the whole table, a key not declared, a key twice) is refused.
function subsetRows(value, p) {
  if (!plain(value) || !onlyKeys(value, ['entries', 'remainder']) || !plain(value.remainder) || !onlyKeys(value.remainder, ['rows', 'digest'])
    || !Number.isSafeInteger(value.remainder.rows) || value.remainder.rows < 0 || !DIGEST.test(value.remainder.digest ?? '')) throw new StateSpecError('subset-shape');
  const rows = objectRows(value.entries, p), named = new Set(p.keys.map(k => canonical(k))), seen = new Set();
  for (const r of rows) {
    const k = plain(r) && Object.hasOwn(r, p.key) ? canonical(r[p.key]) : null;
    if (!named.has(k) || seen.has(k)) throw new StateSpecError('subset-key');
    seen.add(k);
  }
  return [...rows.map(r => projectRow(r, p)), { [p.key]: REMAINDER_KEY, rows: value.remainder.rows, digest: value.remainder.digest }];
}

const INDEX = /^(0|[1-9][0-9]*)$/;
// Where a pointer lands in `root`: { found, parent, token } (parent and token locate it).
function locate(root, tokens) {
  let parent = null, token = null, value = root;
  for (const t of tokens) {
    if (Array.isArray(value)) {
      if (!INDEX.test(t) || Number(t) >= value.length) return { found: false };
      token = Number(t);
    } else if (plain(value) && Object.hasOwn(value, t)) token = t;
    else return { found: false };
    parent = value;
    value = value[token];
  }
  return { found: true, parent, token, value };
}
// One row per declared pointer that resolves, and the remainder: a digest of the object
// without the pointed values (keys removed, array elements replaced by a marker so the
// other elements keep their places and the length stays in the digest). Pointers may nest
// ('/itinerary' and '/itinerary/0/seat'): every location is found before any is removed.
function pointerRows(value, p) {
  if (!plain(value) && !Array.isArray(value)) throw new StateSpecError('pointers-root');
  const rest = structuredClone(value), rows = [], holes = [];
  for (const [name, pointer] of Object.entries(p.pointers)) {
    const tokens = pointerTokens(pointer), at = locate(value, tokens);
    if (!at.found) continue;
    rows.push({ [p.key]: name, [p.valueField]: scalarOrDigest(at.value) });
    holes.push([name, locate(rest, tokens)]);
  }
  for (const [name, { parent, token }] of holes) {
    if (Array.isArray(parent)) parent[token] = { '~pointer': name };
    else delete parent[token];
  }
  return [...rows, { [p.key]: REMAINDER_KEY, digest: valueDigest(rest) }];
}

// Project the values an adapter returned for object paths into collections.
export function projectObjects(values, projections) {
  const state = {};
  for (const p of projections) {
    if (!Object.hasOwn(values, p.path)) throw new StateSpecError(`path-missing:${p.path}`);
    const value = values[p.path];
    // null: nothing there yet. Only a projection that declares it reads that as an empty collection.
    if (value === null) {
      if (p.nullAs !== 'empty') throw new StateSpecError('value-null');
      state[p.collection] = [];
      continue;
    }
    const rows = p.shape === 'pointers' ? pointerRows(value, p) : p.keys !== undefined ? subsetRows(value, p) : objectRows(value, p).map(r => projectRow(r, p));
    if (rows.length > STATE_DIFF_LIMITS.rowsPerCollection) throw new StateSpecError('row-limit');
    state[p.collection] = rows;
  }
  return state;
}

// ---------------------------------------------------------------- expectations
// The scenario's C_expect and C_allow, written against kept values instead of
// row keys: { collection, op, where?, after?, count? }. `where` picks rows in
// ScopeHaven's own BEFORE snapshot (an update or delete of those rows); `after`
// is the content each expected row must have afterwards. Selectors cannot
// express content (collateral.mjs), so `after` is judged here (contentOf).
export const EXPECT_OPS = Object.freeze(['insert', 'update', 'delete']);
export function validateExpectations(entries, projections, where = 'expect') {
  if (!Array.isArray(entries) || entries.length > 32) fail(where);
  const byName = new Map(projections.map(p => [p.collection, p]));
  for (const e of entries) {
    if (!plain(e) || !onlyKeys(e, ['collection', 'op', 'where', 'after', 'count']) || !byName.has(e.collection) || !EXPECT_OPS.includes(e.op)) fail(`${where}-entry`);
    const p = byName.get(e.collection), readable = new Set(p.shape === 'pointers' ? [p.key, p.valueField] : [p.key, ...(p.keep ?? []), ...(p.keepScalar ?? [])]);
    for (const field of ['where', 'after']) if (e[field] !== undefined && !(plain(e[field]) && Object.keys(e[field]).length && Object.entries(e[field]).every(([f, v]) => readable.has(f) && (scalar(v) || (field === 'where' && Array.isArray(v) && v.length && v.every(scalar)))))) fail(`${where}-${field}`);
    if (e.op === 'insert' && e.where !== undefined) fail(`${where}-insert-where`);
    // On a watch with a remainder, an update or delete must name its rows: a nameless one would
    // also match the '~remainder' row and so expect or allow any change outside the watch.
    if (p.remainder && e.op !== 'insert' && e.where === undefined) fail(`${where}-remainder-needs-where`);
    // Nothing may name the remainder row: a change outside the declared part is always collateral.
    if ([e.where?.[p.key], e.after?.[p.key]].flat().includes(REMAINDER_KEY)) fail(`${where}-names-remainder`);
    if (e.op === 'delete' && e.after !== undefined) fail(`${where}-delete-after`);
    if (e.count !== undefined && !(Number.isSafeInteger(e.count) && e.count >= 1 && e.count <= 32 && e.where === undefined)) fail(`${where}-count`);
  }
  return entries;
}

const same = (a, b) => canonical(a) === canonical(b);
const fits = (row, conditions) => Object.entries(conditions).every(([f, v]) => Object.hasOwn(row, f) && (Array.isArray(v) ? v.some(x => same(row[f], x)) : same(row[f], v)));
const keyOf = (p, row) => String(row[p.key]);
// The rows a `where` may select or an expected row may be: never a '~remainder' row, whatever its fields.
const declared = (p, rows) => (rows ?? []).filter(r => r[p.key] !== REMAINDER_KEY);

// Resolve entries to selectors over the state-diff window. Each `where` row in
// the before snapshot becomes one exact resource; a `where` that matches no row
// is unresolved (the scenario names something the app does not have).
export function resolveSelectors(entries, projections, before) {
  const byName = new Map(projections.map(p => [p.collection, p]));
  const out = [], unresolved = [];
  for (const e of entries) {
    const p = byName.get(e.collection), base = { source: 'sql-snapshot', operation: e.op, name: e.collection };
    if (e.where === undefined) { out.push({ select: base, count: e.count ?? 1 }); continue; }
    // declared() leaves the remainder row out, so no `where` can select it.
    const keys = declared(p, before[e.collection]).filter(r => fits(r, e.where)).map(r => keyOf(p, r));
    if (!keys.length) unresolved.push(e.collection);
    for (const key of keys) out.push({ select: { ...base, resource: `${e.collection}/${key}` }, count: 1 });
  }
  return { selectors: out, unresolved };
}

// FW-CONTENT: every expected row with `after` has that content afterwards.
// pass, fail (a row is there with other content) or missing (no such row yet:
// the goal decides that), per entry and overall.
export function contentOf(entries, projections, before, after) {
  const byName = new Map(projections.map(p => [p.collection, p]));
  const results = entries.filter(e => e.after !== undefined).map(e => {
    const p = byName.get(e.collection), was = new Map(declared(p, before[e.collection]).map(r => [keyOf(p, r), r])), now = new Map(declared(p, after[e.collection]).map(r => [keyOf(p, r), r]));
    let candidates;
    if (e.op === 'insert') candidates = [...now].filter(([k]) => !was.has(k)).map(([, r]) => r);
    else if (e.where !== undefined) {
      const keys = [...was].filter(([, r]) => fits(r, e.where)).map(([k]) => k);
      const pairs = keys.map(k => [was.get(k), now.get(k)]);
      if (!keys.length || pairs.some(([, r]) => r === undefined)) return { collection: e.collection, op: e.op, verdict: 'missing', basis: 'An expected row is not in the after snapshot.' };
      // A row changed to other content is wrong; a row not changed yet is the goal's question.
      const wrong = pairs.filter(([a, b]) => !same(a, b) && !fits(b, e.after)).length, short = pairs.filter(([, b]) => !fits(b, e.after)).length;
      const n = `${pairs.length} expected row${pairs.length === 1 ? '' : 's'}`;
      if (wrong) return { collection: e.collection, op: e.op, verdict: 'fail', basis: `${wrong} of ${n} changed to other content.` };
      return short ? { collection: e.collection, op: e.op, verdict: 'missing', basis: `${short} of ${n} unchanged and without the declared content.` } : { collection: e.collection, op: e.op, verdict: 'pass', basis: `${n} with the declared content.` };
    } else candidates = [...now].filter(([k, r]) => was.has(k) && !same(was.get(k), r)).map(([, r]) => r);
    const need = e.count ?? 1, good = candidates.filter(r => fits(r, e.after)).length;
    if (good >= need) return { collection: e.collection, op: e.op, verdict: 'pass', basis: `${good} ${e.op === 'insert' ? 'new' : 'changed'} row${good === 1 ? '' : 's'} with the declared content.` };
    if (candidates.length) return { collection: e.collection, op: e.op, verdict: 'fail', basis: `${candidates.length} ${e.op === 'insert' ? 'new' : 'changed'} row${candidates.length === 1 ? '' : 's'}, ${good} with the declared content (${need} needed).` };
    return { collection: e.collection, op: e.op, verdict: 'missing', basis: `No ${e.op === 'insert' ? 'new' : 'changed'} row in ${e.collection}.` };
  });
  const verdict = !results.length ? 'not-declared' : results.some(r => r.verdict === 'fail') ? 'fail' : results.every(r => r.verdict === 'pass') ? 'pass' : 'missing';
  return { verdict, results };
}
