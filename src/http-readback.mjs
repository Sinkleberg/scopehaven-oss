// Postgres read-back in HTTP checks (ROADMAP v2 item 2): "the reply said done, the record says otherwise". Pure: no I/O.
//
// A pg-snapshot table may declare "readBack" (src/pg-readback.mjs validateReadBack: the value columns to read, which are
// sensitive, which may be revealed, and what must hold: values per row key, changes, insert and delete counts, the
// remainder). A check names the tables it is judged on:
//   "readBack": [{ "observer": "<pg-snapshot id>", "table": "<table>" }]
// The observer builds one read-back record per window from the table's declaration (integrations/observers/pg-snapshot.mjs);
// the connector seals that table's record beside the check's windows as data.readBack, and each entry becomes one
// assertion "Read-back N (table)", judged by judgeReadBack over the sealed record alone, so the validator judges it again.
//
// Fail-only on a boundary: the database is one the application can write (custody subject-writable), so in any check but
// an allowed-use control a judged pass reads inconclusive (subject-writable-custody); a fail stands, and anything the
// judge could not decide (a window the observer could not follow, a violated table, a forbidden remainder change, an
// unreadable value) is inconclusive. In an allowed-use control the pass stands and custody is a tag, as for effects.
//
// Values: a column the declaration lists as sensitive and does not reveal is kept only as a digest the observer sealed
// under its own salt. The validator refuses a sealed entry whose record holds such a column's value in clear.
import { digest, stable } from './domain.mjs';
import { validateReadBack, judgeReadBack, looksSensitive, canonicalExpected, PG_READBACK_SCHEMA, READBACK_CUSTODY, PG_READBACK_LIMITS } from './pg-readback.mjs';
import { observerInstanceId } from './http-effects.mjs';

export const READBACK_ASSERTION_PATTERN = /^Read-back (\d{1,2}) \(([A-Za-z_][A-Za-z0-9_]{0,62})\)$/;
export const readBackAssertionName = (index, table) => `Read-back ${index + 1} (${table})`;
export const MAX_READBACKS = 8;
export const READBACK_CUSTODY_REASON = 'subject-writable-custody';
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const SEALED = /^[0-9a-f]{64}$/;
// The only error values a read-back record holds in place of a value (src/pg-readback.mjs canonicalValue, canonicalExpected).
const VALUE_ERRORS = Object.freeze(['value-unreadable', 'value-too-long', 'value-not-canonical', 'value-not-decimal', 'type-refused', 'expectation-not-canonical']);

// A declaration as the run may carry it: what is read, what is sealed, the counts and remainder, and each expectation's row
// key, column and mode, with the declared value only for a column kept in clear (the record carries that value in clear too).
// A sealed column's expected value is never in the view, the run or the suite, in clear or as an unsalted digest: it is the
// planted secret itself, and a digest of it could be guessed back. Its expectation is bound only by the observer's salted
// seal in the record, which nothing outside the observer can recompute.
const sealedIn = rb => c => rb.sensitive.includes(c) && !rb.reveal.includes(c);
const viewOf = rb => ({ columns: [...rb.columns], sensitive: [...rb.sensitive], reveal: [...rb.reveal], remainder: rb.remainder, range: rb.range ?? null, inserts: rb.inserts, deletes: rb.deletes,
  expect: rb.expect.map(e => ({ key: e.key, column: e.column, mode: e.mode, ...(sealedIn(rb)(e.column) ? {} : { ...(e.mode === 'change' ? { from: e.from } : {}), to: e.to }) })) });
// The read-back tables a check is judged on, each with its observer's instance id, the table's key column, the declaration's
// view and its digest; null when the check declares none. Shared by the registry (the suite binds each), the connector and
// the profile loader. An entry that names no declared read-back table, or one whose declaration the observer would refuse,
// resolves to null: the profile loader refuses it (readBackProblem) before any run.
export function readBackDeclarations(target, check) {
  if (!Array.isArray(check?.readBack)) return null;
  const observers = Array.isArray(target?.observers) ? target.observers : [];
  return check.readBack.map(c => {
    const o = observers.find(x => x?.type === 'pg-snapshot' && x.id === c?.observer);
    const t = Array.isArray(o?.tables) ? o.tables.find(x => x?.table === c?.table && plain(x.readBack)) : undefined;
    if (!t) return null;
    let rb;
    try { rb = validateReadBack(t.readBack, { key: t.key, where: `${t.table} readBack` }); } catch { return null; }
    return { instanceId: observerInstanceId(o.type, o.id), table: t.table, key: t.key, view: viewOf(rb) };
  });
}
// The profile and suite digests (src/contracts.mjs contractDigest) read a table's readBack as this digest of its view, so a sealed
// column's expected value is in no unsalted digest anywhere. A declaration the observer would refuse is digested whole (the
// profile loader refuses it anyway).
export function readBackDigestOf(table) {
  try { return { viewDigest: digest(viewOf(validateReadBack(table.readBack, { key: table.key, where: `${table.table} readBack` }))) }; } catch { return table.readBack; }
}
// The suite's view of one: the instance id, the table and a digest of the view (no expected value is written into the suite).
export const readBackSuiteView = d => ({ instanceId: d.instanceId, table: d.table, viewDigest: digest(d.view) });

// A check's readBack member, against the profile's observers: 1 to MAX_READBACKS distinct { observer, table } naming a
// pg-snapshot table that declares readBack. Returns a problem text, or null.
export function readBackProblem(target, check) {
  const list = check.readBack;
  if (!Array.isArray(list) || list.length < 1 || list.length > MAX_READBACKS) return `"readBack" lists 1 to ${MAX_READBACKS} { observer, table }`;
  if (!list.every(c => plain(c) && Object.keys(c).length === 2 && typeof c.observer === 'string' && typeof c.table === 'string')) return '"readBack" entries are { observer, table }';
  if (new Set(list.map(c => `${c.observer}\n${c.table}`)).size !== list.length) return 'each "readBack" table is named once per check';
  if (readBackDeclarations(target, check).some(d => d === null)) return 'each "readBack" entry names a pg-snapshot observer of this target and one of its tables that declares a valid "readBack"';
  return null;
}

// One table's slice of a read-back record (the record the observer built for the window), or null when it built none. The
// check's own window of that observer, as the connector settled it, decides whether the record may be read at all: a window
// that is not net-only (no settle declared, a horizon cut short, a suspend) blocks it with the window's reason.
const blockedBy = window => (window?.coverage === 'net-only' ? null : typeof window?.reason === 'string' ? window.reason : 'window-not-followed');
const sliceOf = (record, table, window) => (plain(record) && Array.isArray(record.tables)
  ? { schema: record.schema, custody: record.custody, status: record.status === 'ok' && blockedBy(window) ? blockedBy(window) : record.status, tables: record.tables.filter(t => plain(t) && t.name === table) } : null);
// The judged verdict under the check's role: a boundary pass reads inconclusive (custody), a fail stands.
function decided(judged, role) {
  if (judged.verdict === 'pass' && role !== 'control') return { verdict: 'inconclusive', custody: READBACK_CUSTODY, custodyReason: READBACK_CUSTODY_REASON };
  return { verdict: judged.verdict, custody: READBACK_CUSTODY };
}
// records: Map of instance id to the record its observer built for this check's window (absent or null: none); windows: the
// check's windows ({ instanceId, coverage, reason }) as the connector settled them.
export function decideReadBack(declarations, records, role, windows = []) {
  return declarations.map(d => {
    const record = sliceOf(records.get(d.instanceId) ?? null, d.table, windows.find(w => w?.instanceId === d.instanceId));
    const judged = judgeReadBack(record);
    return { ...d, record, judged: judged.verdict, reasons: judged.reasons, basis: judged.basis, ...decided(judged, role) };
  });
}
const EXPECTED = { control: 'Each declared read-back check on this table holds in the database',
  boundary: 'Each declared read-back check on this table holds in the database (fail-only: the application can write it)' };
export function readBackRows(decisions, role) {
  return decisions.map((d, index) => ({ name: readBackAssertionName(index, d.table), status: d.verdict === 'pass' ? 'pass' : d.verdict === 'fail' ? 'fail' : 'inconclusive',
    expected: EXPECTED[role === 'control' ? 'control' : 'boundary'],
    actual: `${d.verdict}: ${d.basis}${d.judged !== 'pass' && d.reasons.length ? ` (${d.reasons.join(', ')})` : ''}${d.custodyReason ? `; judged ${d.judged}, read inconclusive under custody ${d.custody}` : ''}`.slice(0, 600),
    custody: d.custody, ...(d.custodyReason ? { custodyReason: d.custodyReason } : {}) }));
}
// data.readBack: the declaration's view, the table's record and what was decided.
export const sealReadBack = decisions => decisions.map(d => ({ instanceId: d.instanceId, table: d.table, key: d.key, view: d.view, record: d.record,
  judged: d.judged, verdict: d.verdict, custody: d.custody, ...(d.custodyReason ? { custodyReason: d.custodyReason } : {}) }));

// A sealed view, read without trusting it: plain identifiers, every column whose name reads as a secret or personal data
// listed as sensitive (the rule the profile loader applies), reveal a subset of sensitive, expectations on declared columns.
const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const count = v => v === null || (Number.isSafeInteger(v) && v >= 0 && v <= PG_READBACK_LIMITS.count);
function viewProblem(v) {
  const names = list => Array.isArray(list) && list.every(c => typeof c === 'string' && IDENT.test(c)) && new Set(list).size === list.length;
  if (!plain(v) || Object.keys(v).length !== 8 || !names(v.columns) || v.columns.length > PG_READBACK_LIMITS.columns || !names(v.sensitive) || !names(v.reveal)) return 'view';
  if (v.sensitive.some(c => !v.columns.includes(c)) || v.reveal.some(c => !v.sensitive.includes(c)) || v.columns.some(c => looksSensitive(c) && !v.sensitive.includes(c))) return 'sensitive';
  if (!['unchanged', 'may-change'].includes(v.remainder) || !(v.range === null || plain(v.range)) || !count(v.inserts) || !count(v.deletes)) return 'view';
  const scalar = x => x === null || ['string', 'number', 'boolean'].includes(typeof x);
  const shaped = e => { const clear = !(v.sensitive.includes(e.column) && !v.reveal.includes(e.column)), want = ['key', 'column', 'mode', ...(clear ? ['to', ...(e.mode === 'change' ? ['from'] : [])] : [])];
    return Object.keys(e).length === want.length && want.every(k => Object.hasOwn(e, k)) && (!clear || (scalar(e.to) && (e.mode !== 'change' || scalar(e.from)))); };
  if (!Array.isArray(v.expect) || v.expect.length > PG_READBACK_LIMITS.expectations || v.expect.some(e => !plain(e) || typeof e.key !== 'string' || !v.columns.includes(e.column) || !['value', 'change'].includes(e.mode) || !shaped(e))) return 'view';
  return null;
}
// The record agrees with its declaration's view, and every column the declaration keeps sealed holds only sealed digests,
// errors or absent rows, never a value in clear.
function recordProblem(record, table, rb) {
  if (record === null) return null;
  if (!plain(record) || record.schema !== PG_READBACK_SCHEMA || record.custody !== READBACK_CUSTODY || typeof record.status !== 'string' || !Array.isArray(record.tables) || record.tables.length > 1) return 'record';
  const t = record.tables[0];
  if (t === undefined) return null;
  if (!plain(t) || t.name !== table || t.remainderPolicy !== rb.remainder || stable(t.range ?? null) !== stable(rb.range)
    || !plain(t.expected) || t.expected.inserts !== rb.inserts || t.expected.deletes !== rb.deletes) return 'declaration';
  const sealedColumn = new Map(rb.columns.map(c => [c, rb.sensitive.includes(c) && !rb.reveal.includes(c)]));
  if (!Array.isArray(t.columns) || t.columns.length !== rb.columns.length || t.columns.some((c, i) => !plain(c) || c.name !== rb.columns[i] || c.sealed !== sealedColumn.get(c.name))) return 'columns';
  if (!Array.isArray(t.expect) || t.expect.length !== rb.expect.length || t.expect.some((e, i) => !plain(e) || e.key !== rb.expect[i].key || e.column !== rb.expect[i].column || e.mode !== rb.expect[i].mode)) return 'expect';
  const kept = v => v === null || (plain(v) && Object.keys(v).length === 1 && ((typeof v.sealed === 'string' && SEALED.test(v.sealed)) || VALUE_ERRORS.includes(v.error)));
  const clearIn = values => values !== null && (!plain(values) || rb.columns.some(c => sealedColumn.get(c) && Object.hasOwn(values, c) && !kept(values[c])));
  if (!Array.isArray(t.rows) || t.rows.some(r => !plain(r) || clearIn(r.before ?? null) || clearIn(r.after ?? null))) return 'sealed-value-in-clear';
  if (t.expect.some(e => sealedColumn.get(e.column) && ((Object.hasOwn(e, 'to') && !kept(e.to)) || (Object.hasOwn(e, 'from') && !kept(e.from))))) return 'sealed-value-in-clear';
  // A column in clear: on a table read back, each expectation carries the declared value as the column's kind reads it, so an
  // exported suite (which binds the view) binds what the record was judged against.
  if (t.status === 'ok') {
    const kindOf = new Map(t.columns.map(c => [c.name, c.kind]));
    const asRead = (column, value) => { const c = canonicalExpected(kindOf.get(column), value); return stable(c.error ? c : c.value); };
    if (t.expect.some((e, i) => { const d = rb.expect[i]; if (sealedColumn.get(e.column)) return !Object.hasOwn(e, 'to') || (e.mode === 'change' && !Object.hasOwn(e, 'from'));
      return !Object.hasOwn(e, 'to') || stable(e.to) !== asRead(e.column, d.to) || (e.mode === 'change' && (!Object.hasOwn(e, 'from') || stable(e.from) !== asRead(e.column, d.from))); })) return 'expectation';
  }
  return null;
}
// The validator's side: a sealed data.readBack (absent, or 1 to MAX_READBACKS entries) decided again under the row's role.
// Each entry's declaration must be one the profile loader accepts for its key column, its record must agree with it, and
// the verdict and custody must be exactly what judging the sealed record gives. Throws 'effect-trace' on a malformed entry,
// 'effect-verdict' on a verdict that differs, and 'unexpected-suite-evidence' when an exported suite's views ({ instanceId,
// table, viewDigest }, or null for none) differ. observers: the run's declared observer records.
export function recomputeReadBack(sealed, role, { declared, observers = [], windows = [] } = {}) {
  if (sealed === undefined) { if (declared !== undefined && declared !== null) throw new Error('unexpected-suite-evidence'); return { decisions: [], rows: [] }; }
  if (!Array.isArray(sealed) || sealed.length < 1 || sealed.length > MAX_READBACKS) throw new Error('effect-trace');
  const instances = new Set((Array.isArray(observers) ? observers : []).filter(o => o?.type === 'pg-snapshot').map(o => observerInstanceId(o.type, o.id)));
  const decisions = sealed.map(e => {
    if (!plain(e) || typeof e.instanceId !== 'string' || !instances.has(e.instanceId) || typeof e.table !== 'string' || !IDENT.test(e.table) || typeof e.key !== 'string' || !IDENT.test(e.key)
      || viewProblem(e.view) !== null) throw new Error('effect-trace');
    if (recordProblem(e.record, e.table, e.view) !== null) throw new Error('effect-trace');
    // The sealed record is the one decided: re-deciding it against the row's sealed window must leave its status as it is.
    const [d] = decideReadBack([{ instanceId: e.instanceId, table: e.table, key: e.key, view: e.view }], new Map([[e.instanceId, e.record]]), role, windows);
    if (stable(d.record) !== stable(e.record)) throw new Error('effect-trace');
    if (d.judged !== e.judged || d.verdict !== e.verdict || d.custody !== e.custody || (d.custodyReason ?? null) !== (e.custodyReason ?? null)) throw new Error('effect-verdict');
    return d;
  });
  if (new Set(decisions.map(d => `${d.instanceId}\n${d.table}`)).size !== decisions.length) throw new Error('effect-trace');
  if (declared !== undefined && digest(declared ?? null) !== digest(decisions.map(readBackSuiteView))) throw new Error('unexpected-suite-evidence');
  return { decisions, rows: readBackRows(decisions, role) };
}
