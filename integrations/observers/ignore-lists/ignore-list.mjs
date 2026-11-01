// Per-platform ignore lists (N12, lead-queue item 2): the tables a platform's own background writers change while an
// application is under test, so that system noise neither fails an absence check nor keeps one from ever passing, and
// so that nothing else is ever ignored. One reader for every database observer (pg-wal, pg-snapshot, sqlite-snapshot).
//
// One list per platform, checked in beside this reader as JSON (scopehaven-ignore-list/1): each entry names a table, or a
// whole schema the platform owns outright, with its writer and why its writes carry no application effect. A profile adds
// its own background tables (a cron or worker table) with "ignore". The rules, the same for every observer:
//   - a declared table is never ignored: a platform entry that covers one is overridden for that table (the record names
//     the override), and a profile entry that names one is refused. Each observer also keeps a declared table's
//     partitions and inheritance children out of the list, by oid where it reads them;
//   - a declared queue (the end barrier's, ./end-barrier.mjs) is never ignored either, in the same way;
//   - a profile's schema-wide entry is refused for a schema that holds a declared table or queue: list its tables;
//   - nothing else is ignored. A change on a table that is neither declared, a queue nor listed is unlisted, and an
//     observer that can see one keeps it from passing an absence (pg-wal always; sqlite-snapshot once it declares a list).
// What each observer does with the list is in its own header (pg-snapshot attributes in-flight writers by the platform's
// own entries only, platformEntries below). An ignored table's changes never decide a check in either
// direction: no observer emits events for them, so an absence about an ignored table can never pass on the list.
//
// Engines: a Postgres entry is "schema" or "schema.table"; a SQLite entry is a table name (schema "main"). Pure apart from
// reading the checked-in lists once, at import.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { digest } from '../../../src/domain.mjs';

export const IGNORE_LIST_SCHEMA = 'scopehaven-ignore-list/1';
export const IGNORE_LIMITS = Object.freeze({ entries: 64, profile: 64, text: 300 });
// The built-in lists by engine; "none" is the empty list.
export const IGNORE_PLATFORMS = Object.freeze({ postgres: Object.freeze(['none', 'supabase']), sqlite: Object.freeze(['none', 'litestream']) });
const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const text = v => typeof v === 'string' && v.trim().length > 0 && v.length <= IGNORE_LIMITS.text;
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);

// A checked-in list, validated as it is read: a malformed file fails the import, never a run.
export function readPlatformList(json, { platform, engine }) {
  const fail = why => { throw new Error(`ignore list ${platform}: ${why}`); };
  if (!plain(json) || json.schema !== IGNORE_LIST_SCHEMA || json.platform !== platform || json.engine !== engine || typeof json.note !== 'string' || !json.note.trim() || !Array.isArray(json.entries))
    fail(`not a ${IGNORE_LIST_SCHEMA} list for ${engine}`);
  if (!json.entries.length || json.entries.length > IGNORE_LIMITS.entries) fail(`1 to ${IGNORE_LIMITS.entries} entries`);
  const keys = engine === 'postgres' ? ['schema', 'table', 'writer', 'why'] : ['table', 'writer', 'why'];
  const seen = new Set();
  const entries = json.entries.map((e, i) => {
    if (!plain(e) || Object.keys(e).some(k => !keys.includes(k)) || !text(e.writer) || !text(e.why)) fail(`entry ${i + 1} is { ${keys.join(', ')} } with a writer and a reason`);
    const schema = engine === 'postgres' ? e.schema : 'main', table = e.table ?? null;
    if (!IDENT.test(schema ?? '') || (table !== null && !IDENT.test(table)) || (engine === 'sqlite' && table === null)) fail(`entry ${i + 1} names an unsupported identifier`);
    const name = table === null ? schema : `${schema}.${table}`;
    if (seen.has(name)) fail(`entry ${i + 1} repeats ${name}`);
    seen.add(name);
    return Object.freeze({ schema, table, writer: e.writer, why: e.why });
  });
  // A schema-wide entry covers its tables: a table entry under it would be dead weight.
  if (entries.some(e => e.table !== null && seen.has(e.schema))) fail('a table entry sits under a schema-wide entry');
  return Object.freeze({ platform, engine, entries: Object.freeze(entries), digest: digest(entries) });
}

const LISTS = Object.freeze(Object.fromEntries(Object.entries(IGNORE_PLATFORMS).flatMap(([engine, names]) => names.filter(n => n !== 'none').map(platform =>
  [`${engine}:${platform}`, readPlatformList(JSON.parse(readFileSync(fileURLToPath(new URL(`./${platform}.json`, import.meta.url)), 'utf8')), { platform, engine })]))));

// The checked-in list of one platform for one engine ("none": no entries).
export function platformList(platform, engine) {
  if (!Object.hasOwn(IGNORE_PLATFORMS, engine)) throw new Error(`Unknown database engine "${String(engine).slice(0, 32)}".`);
  if (!IGNORE_PLATFORMS[engine].includes(platform)) throw new Error(`platform is one of ${IGNORE_PLATFORMS[engine].join(', ')}.`);
  return platform === 'none' ? Object.freeze({ platform, engine, entries: Object.freeze([]), digest: digest([]) }) : LISTS[`${engine}:${platform}`];
}

// The effective list for one observer: the platform's entries and the profile's own, with every declared table and queue
// kept out. declared and queues are [{ schema, table }] (SQLite: schema "main"). Throws on a profile entry the rules refuse.
export function resolveIgnoreList({ engine, platform = 'none', ignore = [], declared = [], queues = [] }) {
  const base = platformList(platform, engine);
  if (!Array.isArray(ignore) || ignore.length > IGNORE_LIMITS.profile) throw new Error(`ignore lists up to ${IGNORE_LIMITS.profile} names.`);
  // SQLite folds ASCII letters only (a Kelvin sign is not a k); Postgres names arrive exactly as the catalog holds them.
  const fold = n => n.replace(/[A-Z]/g, c => c.toLowerCase());
  const same = engine === 'sqlite' ? (a, b) => fold(a) === fold(b) : (a, b) => a === b;
  const watched = [...declared.map(t => ({ ...t, as: 'declared table' })), ...queues.map(t => ({ ...t, as: 'declared queue' }))];
  const watchedHere = (schema, table) => watched.find(w => w.schema === schema && (table === null || same(w.table, table)));
  const own = ignore.map(name => {
    const parts = typeof name === 'string' ? name.split('.') : [];
    const ok = engine === 'postgres' ? parts.length >= 1 && parts.length <= 2 : parts.length === 1;
    if (!ok || !parts.every(p => IDENT.test(p))) throw new Error(engine === 'postgres' ? "ignore lists 'schema' or 'schema.table' names." : 'ignore lists table names.');
    const schema = engine === 'postgres' ? parts[0] : 'main', table = engine === 'postgres' ? parts[1] ?? null : parts[0];
    // The system schemas hold no application table and are never the profile's to ignore.
    if (engine === 'postgres' && (/^pg_/i.test(schema) || schema.toLowerCase() === 'information_schema')) throw new Error(`The ignore list never names the system schema ${schema}.`);
    const hit = watchedHere(schema, table);
    if (hit) throw new Error(table === null
      ? `The ignore list cannot cover schema ${schema} whole: it holds the ${hit.as} ${hit.schema}.${hit.table}; list its other tables instead.`
      : `${engine === 'postgres' ? `${schema}.` : ''}${table} is a ${hit.as}; an observed table or queue is never on the ignore list.`);
    return Object.freeze({ schema, table, writer: 'profile', why: 'declared by the profile' });
  });
  const names = own.map(e => (e.table === null ? e.schema : `${e.schema}.${e.table}`));
  if (new Set(names.map(n => (engine === 'sqlite' ? fold(n) : n))).size !== names.length) throw new Error('Each ignore entry is listed once.');
  const entries = Object.freeze([...base.entries, ...own]);
  // Platform entries that would cover a declared table or queue: kept, but never applied to it.
  const overridden = Object.freeze(watched.filter(w => base.entries.some(e => e.schema === w.schema && (e.table === null || same(e.table, w.table)))).map(w => `${w.schema}.${w.table}`).sort());
  const ignores = (schema, table) => !watchedHere(schema, table) && entries.some(e => e.schema === schema && (e.table === null || same(e.table, table)));
  const record = Object.freeze({ schema: IGNORE_LIST_SCHEMA, platform, platformDigest: base.digest, profile: Object.freeze(names), overridden, digest: digest({ platform, entries, overridden }) });
  // platformEntries: the checked-in list's own entries (pg-snapshot attributes writers by these only).
  return Object.freeze({ engine, platform, entries, platformEntries: base.entries, overridden, ignores, record });
}
