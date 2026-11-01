// Whole-state diff: the net change between two snapshots of an application's
// own records, as one sql-snapshot effect window (scopehaven-effect/1) plus the
// changed field names a finding needs. Pure: no I/O. Rows are reduced to keys,
// field names and digests; no value is kept.
//
// Technique: AppWorld (arXiv 2407.18901) §3.2 pp.5-6 judges a task by the
// database diff, and App. D pp.14-15 hashes each row without its id. Here a
// keyed row (a unique `id`, or the declared key field) is matched by key and its
// content hash leaves the key out, so an update names the fields that moved; a key
// whose type changed (1 to "1") is an update of the key field. An unkeyed
// collection (rows with no id, such as an activity feed) is compared as a multiset
// of row hashes: a surplus is an insert, a shortfall a delete. Values are hashed
// with their type (a string "1" is not the number 1; Dates, NaN, Infinity, BigInt
// and undefined are distinct); anything else (a Map, a class instance, a function)
// makes the diff fail rather than hash to nothing.
//
// Two snapshots show net change only: a row written and then removed between
// them is invisible. The window says so (coverage "net-only"), so it can decide
// what persisted (COLLATERAL-01) and can fail effect.only, but cannot pass
// effect.only (COLLATERAL-02; see only.mjs). A diff that cannot be computed is a
// failed window; one with more changes than a window holds is partial and keeps
// the first ones, so it can still fail but never pass.
import { createHash } from 'node:crypto';
import { makeEffect, validateWindow, EFFECT_LIMITS, EffectError } from '../observers/events.mjs';

export const STATE_DIFF_LIMITS = Object.freeze({ collections: 64, rowsPerCollection: 10000, depth: 32 });
export const STATE_DIFF_KIND = 'whole-state-diff';
export class StateDiffError extends Error { constructor(code) { super(`State diff: ${code}.`); this.name = 'StateDiffError'; this.code = code; } }
const fail = code => { throw new StateDiffError(code); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const bounded = (value, maximum) => typeof value === 'string' && value.length >= 1 && value.length <= maximum && !/[\u0000-\u001f\u007f]/.test(value);

// A typed canonical form: equal only for values of the same type and content.
export function canonical(value, depth = 0) {
  if (depth > STATE_DIFF_LIMITS.depth) fail('value-depth');
  if (value === null) return 'null';
  if (value === undefined) return 'u:';
  switch (typeof value) {
    case 'string': return `s:${JSON.stringify(value)}`;
    case 'boolean': return `b:${value}`;
    case 'number': return Object.is(value, -0) ? 'n:-0' : `n:${String(value)}`;
    case 'bigint': return `i:${value.toString()}`;
    default: break;
  }
  if (value instanceof Date) return `d:${Number.isNaN(value.getTime()) ? 'invalid' : value.toISOString()}`;
  if (Array.isArray(value)) return `[${value.map(v => canonical(v, depth + 1)).join(',')}]`;
  if (plain(value)) return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k], depth + 1)}`).join(',')}}`;
  return fail('unsupported-value');
}
const hash = value => createHash('sha256').update(canonical(value)).digest('hex');
// The row hash AppWorld uses: every field except the key.
export function rowHash(row, keyField = null) {
  return hash(Object.fromEntries(Object.entries(row).filter(([field]) => field !== keyField)));
}
const keyText = value => (typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value))) ? String(value) : null;

// The key field of one collection: the declared one, else `id` when every row in
// both snapshots carries a unique string or number id, else none (multiset).
function keyFieldOf(name, beforeRows, afterRows, declared) {
  const unique = (rows, field) => { const keys = rows.map(r => keyText(r[field])); return keys.every(k => k !== null && bounded(k, 160)) && new Set(keys).size === keys.length; };
  if (declared !== undefined) {
    if (declared === null) return null;
    if (!bounded(declared, 64)) fail('key-field');
    if (!unique(beforeRows, declared) || !unique(afterRows, declared)) fail(`key-not-unique:${name}`);
    return declared;
  }
  return beforeRows.length + afterRows.length > 0 && unique(beforeRows, 'id') && unique(afterRows, 'id') ? 'id' : null;
}

const changedFields = (a, b) => [...new Set([...Object.keys(a), ...Object.keys(b)])].filter(f => !Object.hasOwn(a, f) || !Object.hasOwn(b, f) || canonical(a[f]) !== canonical(b[f])).sort();

// Diff two whole-state snapshots ({ collection: rows[] }). Both must name the
// same collections, each an array of plain rows. Options:
//   keys        { collection: keyField | null } overrides key detection
//   collections the collections to compare (default: every one in either snapshot)
// Returns { collections, changes: [{ collection, op, key, keyField, fields, hash }] }
// in a stable order (collection, then key). `fields` lists changed field names
// for an update and is null for an insert or delete.
export function diffState(before, after, { keys = {}, collections } = {}) {
  if (!plain(before) || !plain(after)) fail('state');
  if (!plain(keys)) fail('keys');
  const names = collections ?? [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
  if (!Array.isArray(names) || !names.length || names.length > STATE_DIFF_LIMITS.collections || new Set(names).size !== names.length || !names.every(n => bounded(n, EFFECT_LIMITS.name))) fail('collections');
  const changes = [];
  for (const name of names) {
    // A collection created or dropped between the snapshots is not a row change: the shape moved.
    if (!Object.hasOwn(before, name) || !Object.hasOwn(after, name)) fail(`collection-missing:${name}`);
    const a = before[name], b = after[name];
    if (!Array.isArray(a) || !Array.isArray(b) || !a.every(plain) || !b.every(plain)) fail(`collection-shape:${name}`);
    if (a.length > STATE_DIFF_LIMITS.rowsPerCollection || b.length > STATE_DIFF_LIMITS.rowsPerCollection) fail(`row-limit:${name}`);
    const keyField = keyFieldOf(name, a, b, keys[name]);
    const found = [];
    if (keyField) {
      const left = new Map(a.map(r => [keyText(r[keyField]), r])), right = new Map(b.map(r => [keyText(r[keyField]), r]));
      for (const [key, row] of right) {
        if (!left.has(key)) { found.push({ collection: name, op: 'insert', key, keyField, fields: null, hash: rowHash(row, keyField) }); continue; }
        const old = left.get(key), retyped = typeof old[keyField] !== typeof row[keyField];
        if (retyped || rowHash(old, keyField) !== rowHash(row, keyField)) found.push({ collection: name, op: 'update', key, keyField, fields: [...new Set([...(retyped ? [keyField] : []), ...changedFields(old, row)])].sort(), hash: rowHash(row, keyField) });
      }
      for (const [key, row] of left) if (!right.has(key)) found.push({ collection: name, op: 'delete', key, keyField, fields: null, hash: rowHash(row, keyField) });
    } else {
      const count = rows => rows.reduce((m, r) => { const h = rowHash(r); m.set(h, (m.get(h) ?? 0) + 1); return m; }, new Map());
      const left = count(a), right = count(b);
      for (const h of new Set([...left.keys(), ...right.keys()])) {
        const surplus = (right.get(h) ?? 0) - (left.get(h) ?? 0);
        for (let i = 0; i < Math.abs(surplus); i++) found.push({ collection: name, op: surplus > 0 ? 'insert' : 'delete', key: `~${h.slice(0, 16)}`, keyField: null, fields: null, hash: h });
      }
    }
    found.sort((x, y) => (x.key < y.key ? -1 : x.key > y.key ? 1 : x.op < y.op ? -1 : x.op > y.op ? 1 : 0));
    changes.push(...found);
  }
  return { collections: names, changes };
}

// The diff as a sql-snapshot window over the snapshotted collections. Each
// change becomes one committed effect named by its collection, with resource
// "<collection>/<key>" and the row hash as its digest. Snapshots carry no actor.
export function stateDiffWindow(before, after, { instanceId = 'state-diff-1', observedAt = new Date().toISOString(), ...options } = {}) {
  const observer = { kind: STATE_DIFF_KIND, instanceId };
  const scopeOf = names => ({ operations: ['insert', 'update', 'delete'], names, actorAttribution: 'none', evidence: 'authoritative' });
  const declaredNames = Array.isArray(options.collections) && options.collections.length && options.collections.every(n => bounded(n, EFFECT_LIMITS.name)) ? options.collections : null;
  const failed = code => ({ window: validateWindow({ source: 'sql-snapshot', instanceId, scope: scopeOf(declaredNames), coverage: 'failed', reason: code.split(':')[0], events: [] }), changes: [], error: code });
  let diff;
  try { diff = diffState(before, after, options); }
  catch (error) { if (error instanceof StateDiffError) return failed(error.code); throw error; }
  const kept = diff.changes.slice(0, EFFECT_LIMITS.eventsPerWindow), partial = diff.changes.length > kept.length;
  let events;
  try {
    events = kept.map((c, i) => makeEffect({ source: 'sql-snapshot', observer, seq: i + 1, observedAt, actor: null, operation: c.op, name: c.collection,
      resource: `${c.collection}/${c.key}`.slice(0, EFFECT_LIMITS.resource), outcome: 'committed', content: c.hash }));
  } catch (error) { if (error instanceof EffectError) return failed(`effect-${error.code}`); throw error; }
  const window = validateWindow({ source: 'sql-snapshot', instanceId, scope: scopeOf(diff.collections), coverage: partial ? 'partial' : 'net-only', reason: partial ? 'event-limit' : 'net-change-between-snapshots', events });
  return { window, changes: kept, error: null, ...(partial ? { truncated: diff.changes.length } : {}) };
}
