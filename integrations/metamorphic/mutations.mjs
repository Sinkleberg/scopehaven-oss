#!/usr/bin/env node
// Mutation sweep for integrations/metamorphic: one mutation per property of relations.mjs; each must make
// relations.test.mjs fail. A survivor is a test gap.
//   node integrations/metamorphic/mutations.mjs [--out FILE] [--only ID,ID...]
// Works on a temporary copy (in a folder whose name has a space) of the modules the tests load: the checkout is
// never edited. Runs the test file once unmutated (it must pass), then once per mutation, one at a time, then unmutated
// again (it must still pass). A kill that rests only on loopback tests is run a second time before it counts.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const TEST = 'integrations/metamorphic/relations.test.mjs';
const m = (id, property, find, replace) => ({ id, property, file: 'integrations/metamorphic/relations.mjs', find, replace });
export const MUTATIONS = [
  m('P1', 'profile: canary-plant is designed only, refused by name', "  if (DESIGNED_RELATIONS.includes(profile.relation)) refuse('relation-designed-only');\n", ''),
  m('P2', 'profile: both identities declare the same roles', "  if (roles('A') !== roles('B')) refuse('identity-roles');\n", ''),
  m('P3', 'profile: every identity value is distinct', "  if (new Set(values).size !== values.length) refuse('identity-values-repeated');\n", ''),
  m('P4', 'profile: the two actors differ', "  if (identities.A.actor === identities.B.actor) refuse('identity-actors');\n", ''),
  m('N1', 'the acting identity\'s values are renamed the same way in both runs', 'map.set(value, `self:${role}`);', 'map.set(value, `self:${role}:${side}`);'),
  m('N2', 'the other identity\'s values are renamed apart from the actor\'s', 'map.set(value, `other:${role}`);', 'map.set(value, `self:${role}`);'),
  m('N3', 'a renamed value never equals an application string', "return typeof value === 'string' ? `r:${role}` : `r:n:${role}`;", 'return typeof value === \'string\' ? canonical(role) : `r:n:${role}`;'),
  m('N4', 'array elements are renamed one by one', "  if (Array.isArray(value)) return `[${value.map(v => canon(v, ids, depth + 1, numeric)).join(',')}]`;\n", ''),
  m('N6', 'a value nested past the depth bound is unusable, never cut short', "  if (depth > METAMORPHIC_LIMITS.depth) unusable('value-depth');\n", ''),
  m('N7', 'object key order never matters', '.sort(keyOrder)', ''),
  m('N8', 'a number in a declared identity column is renamed', "(typeof value === 'number' && Number.isFinite(value)) || typeof value === 'bigint' ? String(value) : null;", 'null;'),
  m('N10', 'a numeric-looking value is renamed only in identity columns', '(NUMERIC_TEXT.test(text) && !numeric) || ', ''),
  m('N11', 'the number 1 never reads as the string "1"', "typeof value === 'string' ? `r:${role}` : `r:n:${role}`", '`r:${role}`'),
  m('W11', 'a window key column defaults to id, as the states path reads it', "const keyColumn = declared?.key === undefined ? 'id' : declared.key", 'const keyColumn = declared?.key'),
  m('W12', 'a numeric-looking snapshot key is renamed only when the key is an identity column', 'canon(raw, ids, 0, keyIdentity)', 'canon(raw, ids, 0, true)'),
  m('C4', 'a capture status that differs where a body went unread is not compared', "fields.includes('#status') && (l[0].unread || r[0].unread)", 'false'),
  m('R20', 'nothing observed on either side is not an equal nothing', "!deltas.A.tables.length && !deltas.B.tables.length) reasons.push('nothing-observed');", "false) reasons.push('nothing-observed');"),
  m('P9', 'profile: one send declaration per role', "roleOfName(s.name) ? `role:${roleOfName(s.name)}` : `name:${s.name}`", '`name:${s.name}`'),
  m('N9', 'a number outside the declared identity columns is never renamed', 'const cell = (f, v) => canon(v, ids, 1, numeric.has(f));', 'const cell = (f, v) => canon(v, ids, 1, true);'),
  m('N5', 'object keys are renamed', "roleIn(k, ids, false) !== undefined ? `r:${ids.get(k)}` : JSON.stringify(k)", 'JSON.stringify(k)'),
  m('D1', 'declared ignorable columns are dropped before comparison', 'field !== key && !ignore.has(field)', 'field !== key'),
  m('D2', 'an ignorable key compares rows as a multiset of contents', 'const keyed = key !== null && !ignore.has(key);', 'const keyed = key !== null;'),
  m('D3', 'an update carries where the row started', 'sha(previous === null ? at(projected, f) : `${at(previous, f)}>${at(projected, f)}`)', 'sha(at(projected, f))'),
  m('D4', 'an update compares where the row started (content)', 'content: sha(previous === null ? rowCanon(projected) : `${rowCanon(previous)}>${rowCanon(projected)}`)', 'content: sha(rowCanon(projected))'),
  m('D5', 'a write that moves only ignorable columns is no element', 'rowCanon(project(old)) !== rowCanon(project(row))', 'rowCanon(old) !== rowCanon(row)'),
  m('D6', 'a keyed row only in the after snapshot is an insert', "        if (!left.has(k)) { elements.push(element('insert', row)); continue; }\n", "        if (!left.has(k)) continue;\n"),
  m('D7', 'a keyed row only in the before snapshot is a delete', "      for (const [k, row] of left) if (!right.has(k)) elements.push(element('delete', row));\n", ''),
  m('D8', 'a multiset surplus is an insert', "        for (let i = l.length; i < r.length; i++) elements.push(element('insert', r[i]));\n", ''),
  m('D9', 'a multiset shortfall is a delete', "        for (let i = r.length; i < l.length; i++) elements.push(element('delete', l[i]));\n", ''),
  m('D10', 'a table missing from one snapshot is unusable', "    if (!Object.hasOwn(before, name) || !Object.hasOwn(after, name)) unusable(`table-missing:${name}`);\n", ''),
  m('D11', 'a declared key that is not unique is unusable', 'if (!isUnique(before, declared) || !isUnique(after, declared)) unusable(', 'if (false) unusable('),
  m('D12', 'a value the canonical form cannot read is unusable', "if (error instanceof StateDiffError) unusable('value-unsupported'); throw error;", 'return \'u:\';'),
  m('W1', 'a table the run\'s snapshots hold is decided there, not twice', 'if (stateTables.includes(e.name) || !', 'if (!'),
  m('W2', 'a snapshot window with an ignorable key compares counts', ' || Boolean(declared?.ignore?.includes(keyColumn));', ';'),
  m('W7', 'a keyless table\'s row digest is no key', "raw.startsWith('~') || ", ''),
  m('W8', 'a snapshot row change that is not committed is unusable', "if (e.outcome !== 'committed') unusable(", 'if (false) unusable('),
  m('W9', 'a send declaration applies to both identities\' destinations of its role', 'sendKey(s.name, ids) === sendKey(e.name, ids)', 's.name === e.name'),
  m('W10', 'a send compares its capture status', "const record = { '#status': e.captured?.status ?? null, ...values };", 'const record = { ...values };'),
  m('W3', 'a send with an unknown outcome is unusable', 'if (!committed(e)) unusable(', 'if (false) unusable('),
  m('W4', 'a declared send pointer is ignored', '.filter(([pointer]) => !ignore.has(pointer))', '.filter(() => true)'),
  m('W5', 'a send compares its captured fields', "content: sha(`{${Object.keys(record).sort().map(k => `${JSON.stringify(k)}:${fields[k]}`).join(',')}}`)", "content: sha(fields['#status'])"),
  m('W6', 'a send compares its destination by role', 'name: canon(e.name, ids), nameText', 'name: e.nameText, nameText'),
  m('R1', 'a failed window reads inconclusive', "if (w.coverage === 'failed') reasons.push(", "if (w.coverage === 'failed') (() => {})("),
  m('R2', 'a partial window reads inconclusive', "else if (w.coverage === 'partial') reasons.push(", "else if (w.coverage === 'partial') (() => {})("),
  m('R3', 'a send window must be complete and authoritative', "(w.scope.evidence !== 'authoritative' || w.coverage !== 'complete')", 'false'),
  m('R4', 'one window per observer instance', 'if (seen.has(id)) reasons.push(', 'if (false) reasons.push('),
  m('R5', 'an observer present on one side only reads inconclusive', 'if (!reads[side].instances.has(id)) reasons.push(', 'if (false) reasons.push('),
  m('R6', 'snapshots on one side only read inconclusive', '&& reads[side].run.states === undefined) reasons.push(', '&& false) reasons.push('),
  m('R7', 'a missing before or after snapshot reads inconclusive', "if (!plain(run.states?.[point])) reasons.push(`snapshot-missing:${side}:${point}`);", 'if (false) reasons.push(\'\');'),
  m('R8', 'a live model reads inconclusive', '!MODEL_KINDS.includes(run.model.kind)', 'false'),
  m('R9', 'two models read inconclusive', 'a.model.id !== b.model.id', 'false'),
  m('R10', 'two tasks read inconclusive', '(a.task.id !== b.task.id || (', '(false || ('),
  m('R11', 'the run\'s actor must be the declared identity', 'if (run.actor !== profile.identities[side].actor) reasons.push(', 'if (false) reasons.push('),
  m('R12', 'the run\'s side must be its slot', 'if (run.side !== undefined && run.side !== side) reasons.push(', 'if (false) reasons.push('),
  m('R13', 'an app-log window never enters the relation', "  custodyWindows(windows, 'tenantSwap');\n", ''),
  m('R14', 'one observer with two scopes reads inconclusive', 'if (reads.B.scopes.has(id) && reads.B.scopes.get(id) !== scope) reasons.push(', 'if (false) reasons.push('),
  m('R15', 'a table one side snapshotted and the other did not reads inconclusive', 'if (!deltas[side].tables.includes(table)) reasons.push(', 'if (false) reasons.push('),
  m('R16', 'a run with no task reads inconclusive', 'if (!plain(run.task) || !bounded(run.task.id, METAMORPHIC_LIMITS.taskChars)) reasons.push(', 'if (false) reasons.push('),
  m('R17', 'every window is validated', "  windows.forEach((w, i) => validateWindow(w, `run ${side} window ${i + 1}`));\n", ''),
  m('R18', 'a table that is not a list of rows is unusable', 'if (!Array.isArray(a) || !Array.isArray(b) || !a.every(plain) || !b.every(plain)) unusable(', 'if (false) unusable('),
  m('R19', 'a send window must be complete, not only authoritative', " || w.coverage !== 'complete')) reasons.push(", ')) reasons.push('),
  m('C1', 'elements only in A are findings', 'onlyA.push(...l.slice(r.length));', ''),
  m('C2', 'elements only in B are findings', 'onlyB.push(...r.slice(l.length));', ''),
  m('C3', 'a paired finding names only the fields that differ', '.filter(f => l[0].fields[f] !== r[0].fields[f])', '.filter(() => true)'),
  m('T1', 'the complement reads row fields', '...touched.flatMap(r => Object.entries(r).filter(([f, v]) => otherRoles(v, ids, numeric.has(f)).size).map(([f]) => f))', ''),
  m('T2', 'the complement reads keys', "...(keyed && otherRoles(keyValue, ids, numeric.has(key)).size ? ['(key)'] : [])", ''),
  m('T3', 'the complement reads where an updated row started', 'const touched = [projected, ...(previous === null ? [] : [previous])];', 'const touched = [projected];'),
  m('T4', 'the complement reads send destinations', "...(otherRoles(e.name, ids).size ? ['(name)'] : [])", ''),
  m('T5', 'the complement fails from a run it read even when the pair is not comparable', 'SIDES.filter(side => !misread(reasonList, side)).flatMap(', '(comparable ? SIDES : []).flatMap('),
  m('T6', 'the complement reads object keys', '{ hit(k, false); otherRoles(v, ids, numeric, found, depth + 1); }', '{ otherRoles(v, ids, numeric, found, depth + 1); }'),
  m('T7', 'the complement never reads a run under the wrong identity', 'SIDES.filter(side => !misread(reasonList, side)).flatMap(', 'SIDES.flatMap('),
  m('T8', 'the complement reads array elements', '\n  else if (Array.isArray(value)) for (const v of value) otherRoles(v, ids, numeric, found, depth + 1);', ''),
  m('T9', 'the complement reads captured send fields', '...Object.entries(values).filter(([pointer, v]) => otherRoles(v, ids, numeric.has(pointer)).size).map(([pointer]) => pointer)]', ']'),
  m('T10', 'the complement reads a send\'s resource (an SMTP address)', "...(otherRoles(e.resource, ids).size ? ['(resource)'] : []),", ''),
  m('T11', 'the complement reads numbers in identity columns', "if (typeof value === 'string' || typeof value === 'number' || typeof value === 'bigint') hit(value);", "if (typeof value === 'string') hit(value);"),
  m('V1', 'no difference is never a pass', "status: 'inconclusive', verdict: 'no-difference-observed'", "status: 'pass', verdict: 'no-difference-observed'"),
  m('V2', 'no other-identity change is never a pass', "status: 'inconclusive', verdict: 'no-other-identity-observed'", "status: 'pass', verdict: 'no-other-identity-observed'"),
  m('V3', 'custody is the weakest of the places involved', 'CUSTODY.indexOf(c) < CUSTODY.indexOf(w) ? c : w', 'CUSTODY.indexOf(c) > CUSTODY.indexOf(w) ? c : w'),
  m('V4', 'whole-state snapshots are the application\'s own store', "new Map([['states', CUSTODY_BY_SOURCE['sql-snapshot']]])", "new Map([['states', 'independent']])"),
  m('V5', 'findings are capped', 'findings: list.slice(0, METAMORPHIC_LIMITS.findings)', 'findings: list'),
  m('V6', 'a complement fail row carries the pair\'s reasons', "reason: 'other-identity-changed', reasons: result.reasons,", "reason: 'other-identity-changed', reasons: [],"),
  m('V7', 'no difference says when send fields went unread', "${unread ? `; ${unread} send${unread === 1 ? '' : 's'} compared by destination only, their declared fields unread` : ''}", ''),
  m('V8', 'custody is keyed by source and instance, so no window can stand for the snapshots', "map.set(`${w.source}/${w.instanceId}`, custodyOf(w))", 'map.set(w.instanceId, custodyOf(w))'),
  m('P5', 'profile: an identity has only an actor and values', "!onlyKeys(identity, ['actor', 'values'])", 'false'),
  m('P6', 'profile: role names are plain identifiers', 'names.every(role => ROLE.test(role) && bounded(', 'names.every(role => bounded('),
  m('P7', 'profile: ignorable columns are column names', "const columns = list => listOf(list, c => typeof c === 'string' && COLUMN.test(c));", "const columns = list => listOf(list, c => typeof c === 'string');"),
  m('P8', 'profile: a column is ignorable or an identity column, not both', ' || t.identity.some(c => t.ignore?.includes(c))', ''),
];

// Tests that use loopback (the egress recorder): a kill that rests on these alone is confirmed by a second run, since a
// late witness under load reads partial, which a mutation did not cause.
const LOOPBACK = ['sends', 'snapshot observer windows', 'canonical forms', 'review fixes'];
const loopbackOnly = failed => failed.length > 0 && failed.every(name => LOOPBACK.some(prefix => name.startsWith(prefix)));
function runTests(root) {
  const out = spawnSync(process.execPath, ['--test', '--test-concurrency=1', TEST], { cwd: root, encoding: 'utf8', timeout: 300000 });
  const failed = [...new Set((out.stdout ?? '').split('\n').filter(l => /^✖ /.test(l)).map(l => l.slice(2).replace(/ \([\d.]+ms\)$/, '')))].filter(l => l !== 'failing tests:');
  return { code: out.status, failed };
}

async function main() {
  const arg = flag => (process.argv.includes(flag) ? process.argv[process.argv.indexOf(flag) + 1] : null);
  const outFile = arg('--out'), only = arg('--only')?.split(',') ?? null;
  const tmp = mkdtempSync(join(tmpdir(), 'scopehaven metamorphic-mutations-'));
  try {
    for (const dir of ['src', 'integrations/collateral', 'integrations/observers', 'integrations/evid-subject', 'integrations/metamorphic']) cpSync(join(ROOT, dir), join(tmp, dir), { recursive: true });
    const base = runTests(tmp);
    if (base.code !== 0) throw new Error(`Unmutated tests fail: ${base.failed.join('; ')}`);
    const results = [];
    for (const mu of MUTATIONS.filter(x => !only || only.includes(x.id))) {
      const path = join(tmp, mu.file), original = readFileSync(path, 'utf8');
      const count = original.split(mu.find).length - 1;
      if (count !== 1) { results.push({ id: mu.id, property: mu.property, status: 'not-applied', reason: `find matched ${count} times` }); process.stderr.write(`${mu.id} not-applied\n`); continue; }
      writeFileSync(path, original.replace(mu.find, mu.replace));
      try {
        let r = runTests(tmp), confirmed = false;
        if (r.code !== 0 && loopbackOnly(r.failed)) { r = runTests(tmp); confirmed = true; }
        results.push({ id: mu.id, property: mu.property, file: mu.file, status: r.code === 0 ? 'SURVIVED' : 'killed', killedBy: r.failed.slice(0, 3), ...(confirmed ? { rerun: true } : {}) });
      } finally { writeFileSync(path, original); }
      process.stderr.write(`${mu.id} ${results.at(-1).status}\n`);
    }
    const control = runTests(tmp);
    if (control.code !== 0) throw new Error(`Unmutated tests fail after the sweep: ${control.failed.join('; ')}`);
    const sha256 = file => createHash('sha256').update(readFileSync(join(ROOT, file))).digest('hex');
    const summary = { schema: 'scopehaven-metamorphic-mutations/1', control: 'passed before and after',
      sources: Object.fromEntries([...new Set(MUTATIONS.map(x => x.file)), TEST].map(file => [file, sha256(file)])), at: new Date().toISOString(), node: process.version, test: TEST, total: results.length, killed: results.filter(r => r.status === 'killed').length, results };
    if (outFile) writeFileSync(outFile, `${JSON.stringify(summary, null, 1)}\n`);
    process.stdout.write(`${JSON.stringify({ total: summary.total, killed: summary.killed, survivors: results.filter(r => r.status !== 'killed').map(r => `${r.id} ${r.status}`) })}\n`);
    if (summary.killed !== summary.total) process.exitCode = 1;
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
