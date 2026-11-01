// The run's catalog identity (N13): the database catalog a run was judged against, beside the suite identity
// (src/suite.mjs re-exports it there). A suite's checks say what is judged; the catalog says on which schema. One record
// per database observer (its catalog(), integrations/observers/catalog.mjs catalogRecord, by instance) and one sha256 over
// what each record says about its start: instance, engine, record schema, baseline digest and exclusions. The sha256 is null
// when any baseline was unreadable, so an unknown schema never reads as the same schema. A comparison reads the records
// one by one (compareCatalogRecords); the sha256 is a shorthand for an exact match. A record holds counts and sha256 digests
// only. A run whose observers read no catalog has no catalog identity (null), as before. Kept in its own module so the HTTP
// evaluator identity, whose shared validator calls validCatalogIdentity, covers its bytes.
import { digest } from './domain.mjs';

export const CATALOG_IDENTITY_SCHEMA = 'scopehaven-catalog-identity/1';
export const CATALOG_RECORD_SCHEMA = 'scopehaven-catalog/1';
// The declared observer types that read a catalog, and the kinds each engine's record holds (as the observers' reader,
// integrations/observers/catalog.mjs CATALOG_KINDS, names them; a test pins the two together).
export const CATALOG_OBSERVER_TYPES = Object.freeze(['pg-snapshot', 'pg-wal', 'sqlite-snapshot', 'sqlite-audit']);
export const CATALOG_RECORD_KINDS = Object.freeze({
  postgres: Object.freeze(['schema', 'relation', 'column', 'constraint', 'index', 'policy', 'trigger', 'rule', 'function', 'type', 'extension', 'event-trigger',
    'foreign-server', 'publication', 'default-acl', 'operator', 'cast']),
  sqlite: Object.freeze(['table', 'index', 'view', 'trigger', 'pragma']) });
const HEX64 = /^[0-9a-f]{64}$/, MAX_CATALOG_OBSERVERS = 32;
const byInstance = (a, b) => (a.instanceId < b.instanceId ? -1 : a.instanceId > b.instanceId ? 1 : 0);

export function catalogIdentity(records) {
  const observers = (Array.isArray(records) ? records : []).filter(r => r !== null && typeof r === 'object').sort(byInstance);
  if (!observers.length) return null;
  const known = observers.every(r => typeof r.sha256 === 'string');
  return { schema: CATALOG_IDENTITY_SCHEMA, sha256: known ? digest(observers.map(r => [r.instanceId, r.engine, r.schema, r.sha256, r.excluded ?? null])) : null, observers };
}

// A catalog identity by shape and by its own digest, its observers among instanceIds (the run's declared database
// observers), each once, in order. Only what the observers write: each engine's kinds exactly, no table exclusions on
// Postgres (its platform exclusions are schemas), and a record without a baseline names why, carries no kinds and never
// drifted (with no baseline nothing is compared).
export function validCatalogIdentity(identity, instanceIds) {
  const plain = (x, keys) => x !== null && typeof x === 'object' && !Array.isArray(x) && Object.keys(x).every(k => keys.includes(k));
  const hexOrNull = v => v === null || (typeof v === 'string' && HEX64.test(v));
  const names = list => Array.isArray(list) && list.length <= 64 && list.every(n => typeof n === 'string' && /^[A-Za-z_][A-Za-z0-9_.]{0,127}$/.test(n));
  const kindsOf = (engine, kinds) => plain(kinds, CATALOG_RECORD_KINDS[engine]) && Object.keys(kinds).length === CATALOG_RECORD_KINDS[engine].length
    && Object.values(kinds).every(k => plain(k, ['objects', 'sha256']) && Number.isSafeInteger(k.objects) && k.objects >= 0 && HEX64.test(k.sha256));
  const record = r => plain(r, ['instanceId', 'schema', 'engine', 'sha256', 'kinds', 'reason', 'final', 'changedDuringRun', 'excluded'])
    // A string engine first: Object.hasOwn coerces its key, so ["sqlite"] would read as sqlite for its kinds and as not sqlite below.
    && typeof r.instanceId === 'string' && instanceIds.includes(r.instanceId) && r.schema === CATALOG_RECORD_SCHEMA && typeof r.engine === 'string' && Object.hasOwn(CATALOG_RECORD_KINDS, r.engine)
    && hexOrNull(r.sha256) && hexOrNull(r.final) && typeof r.changedDuringRun === 'boolean'
    && plain(r.excluded, ['schemas', 'tables']) && names(r.excluded.schemas) && names(r.excluded.tables) && (r.engine === 'sqlite' || r.excluded.tables.length === 0)
    && (r.sha256 === null
      ? r.reason === 'catalog-unreadable' && !Object.hasOwn(r, 'kinds') && r.changedDuringRun === false
      : !Object.hasOwn(r, 'reason') && kindsOf(r.engine, r.kinds));
  if (!plain(identity, ['schema', 'sha256', 'observers']) || identity.schema !== CATALOG_IDENTITY_SCHEMA || !Array.isArray(identity.observers)) return false;
  const { observers } = identity;
  if (!observers.length || observers.length > MAX_CATALOG_OBSERVERS || !observers.every(record)) return false;
  // Strictly in instance order, which also holds each instance to once.
  return identity.sha256 === catalogIdentity(observers).sha256 && observers.every((r, i) => i === 0 || byInstance(observers[i - 1], r) < 0);
}
