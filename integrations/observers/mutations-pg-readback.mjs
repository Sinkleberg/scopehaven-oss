#!/usr/bin/env node
// Mutation sweep for Postgres read-back (src/pg-readback.mjs and its reads in pg-snapshot.mjs): one mutation per
// property; each must make pg-readback.test.mjs (observer) or test/pg-readback.test.mjs (pure) fail. A survivor is a
// test gap.
//   node integrations/observers/mutations-pg-readback.mjs [--out FILE] [--only ID,ID...]
// As integrations/frameworks/mutations-state.mjs: a temporary copy of the modules the tests load, never the checkout;
// the tests run once unmutated (they must pass), then once per mutation, one at a time. Each edit must match once.
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const TESTS = ['integrations/observers/pg-readback.test.mjs', 'test/pg-readback.test.mjs'];
const m = (id, property, file, ...edits) => ({ id, property, file, edits });
const RB = 'src/pg-readback.mjs', OBS = 'integrations/observers/pg-snapshot.mjs';
export const MUTATIONS = [
  // The declaration.
  m('D1', 'an expectation names only a declared column', RB, ["if (!columns.includes(c)) fail('column-undeclared', `${at} > ${c}`); ", '']),
  m('D2', 'the key is never a value column', RB, ["  if (columns.includes(key)) fail('column-is-key', where);\n", '']),
  m('D3', 'a column that reads as a secret or personal data must be declared sensitive', RB, ["  if (undeclared !== undefined) fail('sensitive-undeclared', `${where} > ${undeclared}`);\n", '']),
  m('D4', 'sensitive names are flagged by word', RB, ['return words.some(w => SENSITIVE_WORDS.has(w)) ||', 'return false ||']),
  m('D7', 'the strongest sensitive words are found anywhere in a name', RB, ["SENSITIVE_PARTS.some(part => words.join('').includes(part))", 'false']),
  m('D5', 'an expectation key appears once', RB, ["    if (keys.has(e.key)) fail('expect-key-repeated', at);\n", '']),
  m('D6', 'a declaration that reads nothing is refused', RB, ["  if (!columns.length && inserts === null && deletes === null) fail('nothing-declared', where);\n", '']),
  // Reads and kinds.
  m('R1', 'the remainder never holds a declared column', OBS, ['.filter(name => name !== t.key && !rb.columns.includes(name))', '.filter(name => name !== t.key)']),
  m('R2', 'a missing column leaves read-back unusable', OBS, ["rb.columns.some(c => !byName.has(c)) ? 'column-missing' : ", '']),
  m('R3', 'a virtual generated column is refused', OBS, ["rb.columns.some(c => byName.get(c).generated === 'v') ? 'column-virtual'\n    : ", '']),
  m('R4', 'a type the reader cannot canonicalise is refused before any read', OBS, ["columns.some(c => !c.kind) ? 'type-refused' : ", '']),
  m('R5', 'a domain reads as its base type one level only', RB, ["typtype === 'd' ? KIND_OF_TYPE[basetype] ?? null", "typtype === 'd' ? KIND_OF_TYPE[basetype] ?? 'text'"]),
  m('R6', 'a scan row without its values and remainder fails the mark', OBS, ["    if (rows.some(row => row.length !== width)) throw new PgError('unexpected-result');\n", '']),
  m('R7', 'a table without read-back reads and collects as before', OBS, ['  if (!readBackAt.length) return api;\n', '']),
  m('R8', 'a sensitive column is sealed unless revealed', OBS, ['sealed: rb.sensitive.includes(name) && !rb.reveal.includes(name)', 'sealed: false']),
  m('R10', 'an inheritance child holding a column the parent lacks leaves read-back unusable', OBS, ["plans[i] = { ...plan, status: 'descendant-columns' };", 'void plan;']),
  m('R11', 'other rows keep their values only within the budget', OBS, ['if (budget >= 0) {', 'if (true) {']),
  m('R12', 'a value is read as text, never through a cast that could fail the mark', OBS, ['const valueSql = column => `pg_catalog.left((r.${column})::pg_catalog.text,', 'const valueSql = column => `pg_catalog.left((r.${column})::pg_catalog.jsonb::pg_catalog.text,']),
  m('R9', 'a revealed sensitive column is kept in clear', OBS, ['sealed: rb.sensitive.includes(name) && !rb.reveal.includes(name)', 'sealed: rb.sensitive.includes(name)']),
  // Canonical values.
  m('V1', 'a decimal loses its trailing fraction zeros', RB, ["frac = frac.replace(/0+$/, '');", '']),
  m('V2', 'NaN and infinities are not decimals', RB, ["return d === null ? { error: 'value-not-decimal' } : { value: d };", 'return { value: d ?? text };']),
  m('V3', 'timestamptz is read only at UTC', RB, ['(?:\\.(\\d{1,6}))?\\+00$/, date:', '(?:\\.(\\d{1,6}))?[+-]\\d\\d$/, date:']),
  m('V4', 'a JSON number is read as the exact decimal of its own text, never through a double', RB, ['decimalOf(context.source) : null', 'decimalOf(String(v)) : null']),
  m('V12', 'a json expectation is JSON text, never a value a double has already rounded', RB, ["const c = typeof value === 'string' ? canonicalJson(value) : null;", "const c = typeof value === 'string' ? canonicalJson(value) : jsonValue(value) ? stable(value) : null;"]),
  m('V13', 'a uuid expectation is compared in lower case', RB, ['{ value: value.toLowerCase() }', '{ value }']),
  m('V14', 'the JSON value null is not SQL NULL', RB, ["return c === null ? { error: 'value-not-canonical' } : { value: c };", "return c === null ? { error: 'value-not-canonical' } : { value: c === 'null' ? null : c };"]),
  m('V5', 'a text, char or json value holding U+FFFD is refused', RB, ["  if (['text', 'char', 'json'].includes(kind) && text.includes('\\uFFFD')) return { error: 'value-not-canonical' };\n", '']),
  m('V6', 'a value cut at the limit is refused', RB, ['if (text.length > PG_READBACK_LIMITS.valueChars) return', 'if (text.length > PG_READBACK_LIMITS.valueChars + 1) return']),
  m('V7', 'an expected value is read as the column kind', RB, ['const c = canonicalExpected(col.kind, v);', 'const c = { value: v };']),
  m('V8', 'a seal covers the kind with the value', RB, ['${SEAL_LABEL}${kind}\\n${stable(value)}', '${SEAL_LABEL}${stable(value)}']),
  m('V10', 'a char expectation is compared without trailing spaces', RB, ["{ value: value.replace(/ +$/, '') }", '{ value }']),
  m('V11', 'a numeric expectation written as a JSON number must be a safe integer', RB, ['Number.isSafeInteger(value) ? String(value)', "typeof value === 'number' ? decimalOf(String(value))"]),
  m('V9', 'a seal equals only the same seal', RB, ["typeof a.sealed === 'string' && a.sealed === b.sealed", "typeof a.sealed === 'string'"]),
  // Counts and the remainder.
  m('C1', 'inserts are counted only in the range', RB, ['inserted: inserted.filter(placed).length', 'inserted: inserted.length']),
  m('C2', 'deletes are counted only in the range', RB, ['deleted: deleted.filter(placed).length', 'deleted: deleted.length']),
  m('C3', 'a changed key an integer range cannot place decides no count', RB, ['[...inserted, ...deleted].some(k => place(k) === null)', 'false']),
  m('C4', 'a count must equal the declared one exactly', RB, ['tableChecks.push(seen === want ?', 'tableChecks.push(seen >= want ?']),
  m('C14', 'an exact-key range places only its own keys', RB, ['if (range.keys !== undefined) return range.keys.includes(key);', 'if (range.keys !== undefined) return true;']),
  m('C15', 'an exact-key range compares keys as the key column reads them (review m5)', RB, ['return { place: k => { const c = canonicalKey(keyKind, k); return c === null ? null : inRange({ keys }, c); }, refused: null };', 'return { place: k => inRange(range, k), refused: null };']),
  m('C16', 'a declared exact key its kind cannot read is refused (review m5)', RB, ["  if (keys.includes(null)) return { place: () => null, refused: 'range-key-not-canonical' };\n", '']),
  m('C17', 'an exact-key range over a key column of another kind is refused (review m5)', RB, ["  if (!KEY_KINDS.has(keyKind)) return { place: () => null, refused: 'range-key-type-refused' };\n", '']),
  m('C18', 'the mark reads the key column kind from the catalog (review m5)', OBS, ['keyKind: byName.has(t.key) ? keyKindOfColumn(byName.get(t.key)) : null', "keyKind: 'text'"]),
  m('C5', 'an integer range compares keys as numbers', RB, ['return (range.min === undefined || k >= BigInt(range.min))', 'return (range.min === undefined || key >= range.min)']),
  m('C6', 'an insert or delete no count declares stays in the remainder', RB, ['new Set([...(decl.inserts === null ? [] : inserted), ...(decl.deletes === null ? [] : deleted)].filter(placed))', 'new Set([...inserted, ...deleted].filter(placed))']),
  m('C7', 'the remainder covers the other rows', RB, ["[k, 'row', rb.shas.get(k) ?? null]", "[k, 'row', null]"]),
  m('C8', 'the remainder covers an expected row\'s undeclared columns', RB, ["[k, 'rest', rb.rows.get(k)?.rest ?? null]", "[k, 'rest', null]"]),
  m('C9', 'a declared column no expectation names is compared', RB, ["else if (!sameValue(x.values[c], y.values[c])) unnamed = 'changed';", "else if (false) unnamed = 'changed';"]),
  m('C10', 'a forbidden remainder change leaves each pass of its table inconclusive', RB, ["tableChecks = tableChecks.map(c => (moved && c.status === 'pass'", "tableChecks = tableChecks.map(c => (false && c.status === 'pass'"]),
  m('C12', 'a guarded table has a remainder check of its own', RB, ["      tableChecks.push({ table: t.name, check: 'remainder', status: moved ? 'inconclusive' : 'pass', reason: moved });\n", '']),
  m('C13', 'a blocked table with no check of its own still contributes one', RB, ["if (!tableChecks.length) tableChecks.push({ table: t.name, check: 'table', status: 'inconclusive', reason: blocked });", '']),
  m('C11', 'the remainder is sealed under the observer salt', RB, ["const remainderOf = (map, rb) => seal('remainder',", "const remainderOf = (map, rb) => sealWith(Buffer.alloc(32))('remainder',"]),
  // The judge.
  m('J1', 'an expected value decides the check', RB, ['tableChecks.push(sameValue(after, e.to) ?', 'tableChecks.push(true ?']),
  m('J2', 'a change needs its precondition', RB, ["if (!sameValue(before, e.from)) { tableChecks.push({ ...c, status: 'inconclusive', reason: 'precondition-not-held' }); continue; }", '']),
  m('J3', 'a change on a row absent at the start mark is inconclusive', RB, ["if (before === undefined) { tableChecks.push({ ...c, status: 'inconclusive', reason: 'precondition-row-absent' }); continue; }", '']),
  m('J4', 'an expected row absent at the end mark fails', RB, ["tableChecks.push({ ...c, status: 'fail', reason: 'row-absent' });", "tableChecks.push({ ...c, status: 'inconclusive', reason: 'row-absent' });"]),
  m('J5', 'a blocked window or table decides nothing', RB, ["const blocked = record.status !== 'ok' ? record.status : t.status !== 'ok' ? t.status : null;", 'const blocked = null;']),
  m('J6', 'a violated table decides nothing', RB, ["  if (violated) return unusable('table-violated');\n", '']),
  m('J7', 'only a net-only window is decided', OBS, ["status = window.coverage === 'net-only' ? 'ok' : window.reason;", "status = window.coverage === 'failed' ? window.reason : 'ok';"]),
  m('J9', 'a malformed stored record reads unreadable, never a throw', RB, [' || !record.tables.every(readableTable))', ')']),
  m('J8', 'nothing declared never passes', RB, ["const verdict = !checks.length ? 'inconclusive' :", 'const verdict = !checks.length ? \'pass\' :']),
];

function runTests(root) {
  const out = spawnSync(process.execPath, ['--test', '--test-concurrency=1', ...TESTS], { cwd: root, encoding: 'utf8', timeout: 300000 });
  const lines = (out.stdout ?? '').split('\n');
  const failed = [...new Set(lines.filter(l => /^✖ /.test(l)).map(l => l.slice(2).replace(/ \([\d.]+ms\)$/, '')))];
  return { code: out.status, failed };
}

async function main() {
  const arg = flag => (process.argv.includes(flag) ? process.argv[process.argv.indexOf(flag) + 1] : null);
  const outFile = arg('--out'), only = arg('--only')?.split(',') ?? null;
  const tmp = mkdtempSync(join(tmpdir(), 'scopehaven-pg-readback-mutations-'));
  try {
    for (const dir of ['src', 'integrations', 'test']) cpSync(join(ROOT, dir), join(tmp, dir), { recursive: true });
    cpSync(join(ROOT, 'package.json'), join(tmp, 'package.json'));
    const base = runTests(tmp);
    if (base.code !== 0) throw new Error(`Unmutated tests fail: ${base.failed.join('; ')}`);
    const results = [];
    for (const mu of MUTATIONS.filter(x => !only || only.includes(x.id))) {
      const path = join(tmp, mu.file), original = readFileSync(path, 'utf8');
      const counts = mu.edits.map(([find]) => original.split(find).length - 1);
      if (counts.some(c => c !== 1)) { results.push({ id: mu.id, property: mu.property, status: 'not-applied', reason: `finds matched ${counts.join(', ')} times` }); continue; }
      writeFileSync(path, mu.edits.reduce((text, [find, replace]) => text.replace(find, () => replace), original));
      try {
        const r = runTests(tmp);
        results.push({ id: mu.id, property: mu.property, file: mu.file, status: r.code === 0 ? 'SURVIVED' : 'killed', killedBy: r.failed.slice(0, 3) });
      } finally { writeFileSync(path, original); }
      process.stderr.write(`${mu.id} ${results.at(-1).status}\n`);
    }
    const summary = { schema: 'scopehaven-pg-readback-mutations/1', at: new Date().toISOString(), node: process.version, test: TESTS.join(' '), total: results.length, killed: results.filter(r => r.status === 'killed').length, results };
    if (outFile) writeFileSync(outFile, `${JSON.stringify(summary, null, 1)}\n`);
    process.stdout.write(`${JSON.stringify({ total: summary.total, killed: summary.killed, survivors: results.filter(r => r.status !== 'killed').map(r => `${r.id} ${r.status}`) })}\n`);
    if (summary.killed !== summary.total) process.exitCode = 1;
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
