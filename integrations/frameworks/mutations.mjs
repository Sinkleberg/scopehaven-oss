#!/usr/bin/env node
// Mutation sweep for integrations/frameworks: one mutation per property; each must
// make frameworks.test.mjs fail. A survivor is a test gap.
//   node integrations/frameworks/mutations.mjs [--out FILE] [--only ID,ID...]
// Works on a temporary copy of the modules the tests load (src/, collateral,
// observers, evid-subject, frameworks): the checkout is never edited. Runs the test
// file once unmutated (it must pass), then once per mutation, one at a time.
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const TEST = 'integrations/frameworks/frameworks.test.mjs';
const m = (id, property, file, find, replace) => ({ id, property, file: `integrations/frameworks/${file}`, find, replace });
export const MUTATIONS = [
  m('C1', 'a returned ledger record carries no exception', 'contract.mjs', "record.status === 'returned' ? Object.hasOwn(record, 'exception') :", "record.status === 'returned' ? false :"),
  m('C2', 'a fault-injected or exception record carries no result', 'contract.mjs', "text(record.exception, CONTRACT_LIMITS.text)) || Object.hasOwn(record, 'result')) fail('ledger-outcome');", "text(record.exception, CONTRACT_LIMITS.text))) fail('ledger-outcome');"),
  m('C3', 'ledger sequence numbers run 1, 2, 3', 'contract.mjs', 'const ordered = records.every((r, i) => r.seq === i + 1);', 'const ordered = true;'),
  m('C4', 'unknown adapter message types are refused', 'contract.mjs', "      return fail('type');", '      return message;'),
  m('C5', 'extra fields on a turn-end are refused', 'contract.mjs', "if (!onlyKeys(message, ['type', 'id', 'reply', 'messages', 'stub', 'failure']) || !counter(message.id)", 'if (!counter(message.id)'),
  m('C6', 'a turn-end must carry the stub status', 'contract.mjs', '      if (!(plain(message.stub) && onlyKeys(', '      if (message.stub !== undefined && !(plain(message.stub) && onlyKeys('),
  m('C7', 'names, ids and failures are one line', 'contract.mjs', '!/[\\u0000-\\u001f\\u007f]/.test(value);', '!/[\\u0000-\\u0009\\u000b-\\u001f\\u007f]/.test(value);'),
  m('F1', 'a tool never called never counts as a fired fault', 'fault.mjs', 'if (!injected.length) return { planned: true, fired: false,', 'if (!injected.length) return { planned: true, fired: true,'),
  m('F2', 'a fault fires once', 'fault.mjs', 'if (injected.length > 1) return', 'if (false) return'),
  m('F3', 'the fault fired on the planned tool', 'fault.mjs', 'if (hit.tool !== plan.tool) return', 'if (false) return'),
  m('F4', 'the fault replaced the first call to the tool', 'fault.mjs', 'if (first !== hit) return', 'if (false) return'),
  m('F5', 'an unordered ledger shows no fired fault', 'fault.mjs', "  if (!ledger?.ordered) return { planned: true, fired: false, reason: 'ledger-unordered' };\n", ''),
  m('J1', 'a record judged against another scenario decides nothing', 'judge.mjs', "  if (record.scenarioDigest !== digest(scenario)) return ['scenario-mismatch'];\n", ''),
  m('J2', 'FW-EXEC: adapter not ready', 'judge.mjs', "  if (!record.ready) reasons.push('adapter-not-ready');\n", ''),
  m('J3', 'FW-EXEC: every turn ended', 'judge.mjs', "  if (record.turns.length !== scenario.turns.length || record.turns.some(t => !t.ended)) reasons.push('turn-not-ended');\n", ''),
  m('J4', 'FW-EXEC: no adapter or protocol error', 'judge.mjs', "  if (record.errors.length) reasons.push('adapter-error');\n", ''),
  m('J5', 'FW-EXEC: the stub script did not run out', 'judge.mjs', "  if (record.turns.some(t => t.stub?.exhausted)) reasons.push('stub-script-exhausted');\n", ''),
  m('J6', 'FW-EXEC: the ledger is in order', 'judge.mjs', "  if (!record.ledger?.ordered) reasons.push('ledger-unordered');\n", ''),
  m('J21', 'FW-EXEC: the stub script played out exactly as written', 'judge.mjs', "  else if (record.turns.some((t, i) => t.ended && t.stub?.consumed !== script[i].length)) reasons.push('stub-script-not-followed');\n", ''),
  m('J22', 'FW-EXEC: a turn the framework raised out of', 'judge.mjs', "  if (record.turns.some(t => t.failure)) reasons.push('turn-failed');\n", ''),
  m('J23', 'FW-SAID-DID on an app-supplied snapshot never passes', 'judge.mjs', "    rows.push(guard(row('FW-SAID-DID',", "    rows.push((r => r)(row('FW-SAID-DID',"),
  m('J20', 'FW-EXEC: no tool call outside a turn', 'judge.mjs', "  if (record.ledger?.records?.some(r => r.outside)) reasons.push('tool-outside-turn');\n", ''),
  m('R6', 'a tool record after its turn-end is marked outside the turn', 'turn-runner.mjs', 'if (end.message) to = io.state.arrival.get(end.message);', ''),
  m('J7', 'FW-EXEC: both snapshots taken', 'judge.mjs', "  for (const point of ['before', 'after']) if (!record.snapshots?.[point]?.ok) reasons.push(`snapshot-failed:${point}`);\n", ''),
  m('J8', 'an unusable run is inconclusive overall', 'judge.mjs', "  if (reasons.length) return verdict(scenario, record, rows, { verdict: 'inconclusive', reasons });\n  if (fault.planned", '  if (fault.planned'),
  m('J9', 'an unfired fault makes the run inconclusive', 'judge.mjs', "  if (fault.planned && !fault.fired) return verdict(scenario, record, rows, { verdict: 'inconclusive', reasons: [`fault-not-fired:${fault.reason}`] });\n", ''),
  m('J10', 'an app-supplied snapshot never passes', 'judge.mjs', "const guarded = r => (appSupplied && r.status === 'pass'", "const guarded = r => (false && r.status === 'pass'"),
  m('J11', 'goal mode: COLLATERAL-01 decides', 'judge.mjs', "scenario.decide === 'goal' ? ['COLLATERAL-01', 'COLLATERAL-GOAL', 'FW-CONTENT',", "scenario.decide === 'goal' ? ['COLLATERAL-GOAL', 'FW-CONTENT',"),
  m('J12', 'goal mode: the goal decides (do-nothing never passes)', 'judge.mjs', "scenario.decide === 'goal' ? ['COLLATERAL-01', 'COLLATERAL-GOAL', 'FW-CONTENT',", "scenario.decide === 'goal' ? ['COLLATERAL-01', 'FW-CONTENT',"),
  m('J13', 'goal mode: FW-CONTENT decides', 'judge.mjs', "scenario.decide === 'goal' ? ['COLLATERAL-01', 'COLLATERAL-GOAL', 'FW-CONTENT',", "scenario.decide === 'goal' ? ['COLLATERAL-01', 'COLLATERAL-GOAL',"),
  m('J14', 'said-did mode: COLLATERAL-01 decides', 'judge.mjs', ": ['COLLATERAL-01', 'FW-SAID-DID'];", ": ['FW-SAID-DID'];"),
  m('J15', 'M1: said done, nothing persisted', 'judge.mjs', "'done/not-done': ['fail', 'M1']", "'done/not-done': ['pass', null]"),
  m('J16', 'M2: said not done, it persisted', 'judge.mjs', "'not-done/done': ['fail', 'M2']", "'not-done/done': ['pass', null]"),
  m('J17', 'M4: said done, wrong content', 'judge.mjs', "'done/wrong': ['fail', 'M4']", "'done/wrong': ['pass', null]"),
  m('J18', 'an undecided goal is not "not done"', 'judge.mjs', ": goal?.status === 'fail' ? 'not-done' : 'unknown';", ": 'not-done';"),
  m('J19', 'a claim is a whole declared sentence', 'claim-reader.mjs', 'const done = claims.done.some(c => said.has(normal(c)))', "const done = claims.done.some(c => normal(String(reply ?? '')).includes(normal(c)))"),
  m('S1', 'FW-CONTENT: a row changed to other content fails', 'state.mjs', 'const wrong = pairs.filter(([a, b]) => !same(a, b) && !fits(b, e.after)).length', 'const wrong = 0'),
  m('S2', 'FW-CONTENT: a new row with other content fails', 'state.mjs', "if (candidates.length) return { collection: e.collection, op: e.op, verdict: 'fail'", "if (candidates.length) return { collection: e.collection, op: e.op, verdict: 'missing'"),
  m('S3', 'a where selects only the matching before rows', 'state.mjs', '.filter(r => fits(r, e.where)).map(r => keyOf(p, r));', '.map(r => keyOf(p, r));'),
  m('S5', 'a where watch needs a remainder', 'state.mjs', "    if (p.where !== undefined && p.remainder !== true) fail('where-needs-remainder');\n", ''),
  m('S6', 'on a remainder watch, updates and deletes name their rows', 'state.mjs', "    if (p.remainder && e.op !== 'insert' && e.where === undefined) fail(`${where}-remainder-needs-where`);\n", ''),
  m('S4', 'expectations name only readable (kept) fields', 'state.mjs', 'every(([f, v]) => readable.has(f) &&', 'every(([f, v]) => true &&'),
  m('Q1', 'rows outside the watch are covered by the remainder digest', 'sqlite-state.mjs', '    if (p.remainder) {', '    if (false) {'),
  m('Q2', 'a hot journal after the copy refuses it', 'sqlite-state.mjs', 'if (!hotJournal(path) && fileState(path) === file', 'if (fileState(path) === file'),
  m('Q3', 'a commit during the copy refuses it (change counter)', 'sqlite-state.mjs', 'header(path).counter === first.counter && header(copy).counter === first.counter && !header(copy).wal) return { copy, wal: false };', '!header(copy).wal) return { copy, wal: false };'),
  m('Q5', 'rollback journal: the file must not change during the copy (exclusive locking)', 'sqlite-state.mjs', 'if (!hotJournal(path) && fileState(path) === file && header(path).counter', 'if (!hotJournal(path) && header(path).counter'),
  m('Q6', 'a NULL in a watched column puts the row in the remainder', 'sqlite-state.mjs', 'WHERE NOT coalesce((${sql}), 0) ORDER BY', 'WHERE NOT (${sql}) ORDER BY'),
  m('Q4', 'WAL: a checkpoint during the copy refuses it', 'sqlite-state.mjs', 'if (walState(path) === wal && fileState(path) === file && header(path).counter === first.counter && header(copy).wal)', 'if (header(copy).wal)'),
  m('R1', 'only the answer to the harness\'s own snapshot request is used', 'turn-runner.mjs', "m => m.type === 'state' && m.id === id", "m => m.type === 'state'"),
  m('R2', 'an app-report projection makes the snapshot app-supplied', 'turn-runner.mjs', "takenBy: sources.includes('app-report') ? 'app' : 'scopehaven'", "takenBy: 'scopehaven'"),
  m('R3', 'a turn ends only with its own turn-end', 'turn-runner.mjs', "m => m.type === 'turn-end' && m.id === turn", "m => m.type === 'turn-end'"),
  m('R4', 'the adapter gets none of the parent\'s variables', 'turn-runner.mjs', "return { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home,", "return { ...process.env, PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home,"),
  m('R5', 'protocol errors make the run unusable', 'turn-runner.mjs', 'if (io.state.protocolErrors.length) record.errors.push(', 'if (false) record.errors.push('),
  m('R7', 'an error, turn-end or ready nobody waited for makes the run unusable', 'turn-runner.mjs', "    for (const m of io.state.messages) if (m.type !== 'state') record.errors.push(", "    for (const m of []) if (m.type !== 'state') record.errors.push("),
  m('R8', 'an exit other than a clean 0 makes the run unusable', 'turn-runner.mjs', '    else if (exit.code !== 0 || exit.signal) record.errors.push(', '    else if (false) record.errors.push('),
  m('R9', 'a turn-end sent before its turn does not end it', 'turn-runner.mjs', 'm.id === turn && io.state.arrival.get(m) > from', 'm.id === turn'),
  m('R10', "the runner waits for the sync echo before sending the turn, so a record written before it is outside the turn", 'turn-runner.mjs', "      io.send({ type: 'sync', id: barrier });\n      const synced = await io.wait(m => m.type === 'sync' && m.id === barrier, limits.snapshotMs);\n      if (synced.failure) { record.errors.push(`sync-${turn}:${synced.failure}${synced.detail ? `:${synced.detail}` : ''}`.slice(0, 400)); return record; }\n      drainTools();\n      const started = Date.now();\n      [from, to] = [io.state.arrival.get(synced.message), Infinity];", "      io.send({ type: 'sync', id: barrier });\n      drainTools();\n      const started = Date.now();\n      [from, to] = [io.state.count, Infinity];"),
  m('V1', 'said-did needs claims and a planned fault or a declared condition', 'scenario.mjs', "if (s.decide === 'said-did' && (s.claims === undefined || (s.fault === null && s.condition === undefined)))", 'if (false)'),
  m("J24", "a state change between BEFORE and its settle read makes the run unusable", "judge.mjs", "  if (record.snapshots?.before?.ok && record.quiet?.before?.same !== true) reasons.push('state-moved-before-turns');\n", ""),
  m("J25", "a state change after the AFTER snapshot makes the run unusable", "judge.mjs", "  if (record.snapshots?.after?.ok && ((sources.has('sqlite-file') && record.quiet?.afterExit?.same !== true) || ((sources.has('object-path') || sources.has('app-report')) && record.quiet?.afterObjects?.same !== true))) reasons.push('state-moved-after-snapshot');\n", ""),
  m("J26", "an app-report projection in the scenario is app-supplied whatever the record says", "judge.mjs", "  const snapshotCustody = projected.has('app-report') || [before, after]", "  const snapshotCustody = [before, after]"),
  m("J27", "an object-path snapshot is custody in-process", "judge.mjs", "projected.has('object-path') ? 'in-process' : 'out-of-process'", "'out-of-process'"),
  m("J28", "a pass on an in-process snapshot says so in its basis", "judge.mjs", "snapshotCustody === 'in-process' && r.status === 'pass' ? { basis:", "false && r.status === 'pass' ? { basis:"),
  m("R11", "SQLite read again once the adapter group is gone", "turn-runner.mjs", "      record.quiet.afterExit = { same: sameState(record.snapshots.after, exited, sqliteNames) };", "      record.quiet.afterExit = { same: true };"),
  m("R12", "object paths read again a settle interval after AFTER", "turn-runner.mjs", "      record.quiet.afterObjects = { same: sameState(record.snapshots.after, again, objectNames) };", "      record.quiet.afterObjects = { same: true };"),
  m("R13", "BEFORE read again a settle interval later", "turn-runner.mjs", "    record.quiet.before = { same: sameState(record.snapshots.before, settled, [...sqliteNames, ...objectNames]) };", "    record.quiet.before = { same: true };"),
  m("R14", "a last line with no newline makes the run unusable", "turn-runner.mjs", "    if (io.state.buffer.trim()) io.state.protocolErrors.push('partial-line');\n", ""),
  m("R15", "the ledger is bounded (records and bytes)", "turn-runner.mjs", "      if (message.type === 'tool' && (++state.tools > CONTRACT_LIMITS.ledger || (state.toolBytes += line.length) > RUN_DEFAULTS.ledgerBytes)) { state.protocolErrors.push('ledger-limit'); continue; }\n", ""),
  m("R16", "the unread-message queue is bounded", "turn-runner.mjs", "      if (state.messages.length >= RUN_DEFAULTS.queue) { state.protocolErrors.push('queue-limit'); continue; }\n", ""),
  m("R17", "a worker left running makes the run unusable", "turn-runner.mjs", "    if (io.state.survivors) record.errors.push('adapter-left-processes');\n", ""),
  m("P1", "object-path state is plain data only", "adapters/plain-data.mjs", "  throw new PlainDataError(`unsupported:${Object.prototype.toString.call(value).slice(8, -1)}`);", "  return {};"),
  m("C8", "an answer carries at most 16 object paths", "contract.mjs", "Object.keys(message.values).length > CONTRACT_LIMITS.paths || ", ""),
  m("C9", "a ledger holds at most 2,000 records", "contract.mjs", "  if (entries.length > CONTRACT_LIMITS.ledger) fail('ledger-limit');\n", ""),
  m("V2", "the settle interval is 50 ms to 60 s", "scenario.mjs", "(k === 'settleMs' ? v >= 50 && v <= 60000 : v >= 1000 && v <= 900000)", "(v >= 1 && v <= 900000)"),
  m('X1', 'the checkout is at the pinned commit', 'run.mjs', 'if (head !== scenario.template.commit) throw', 'if (false) throw'),
  m('X2', 'the template folder is unchanged', 'run.mjs', 'if (dirty) throw', 'if (false) throw'),
  m('X3', 'every seed matches its sha256', 'run.mjs', 'if (got !== seed.sha256) {', 'if (false) {'),
];

function runTests(root) {
  const out = spawnSync(process.execPath, ['--test', '--test-concurrency=1', TEST], { cwd: root, encoding: 'utf8', timeout: 300000 });
  const failed = [...new Set((out.stdout ?? '').split('\n').filter(l => /^✖ /.test(l)).map(l => l.slice(2).replace(/ \([\d.]+ms\)$/, '')))];
  return { code: out.status, failed };
}

async function main() {
  const arg = flag => (process.argv.includes(flag) ? process.argv[process.argv.indexOf(flag) + 1] : null);
  const outFile = arg('--out'), only = arg('--only')?.split(',') ?? null;
  const tmp = mkdtempSync(join(tmpdir(), 'scopehaven-frameworks-mutations-'));
  try {
    for (const dir of ['src', 'integrations/collateral', 'integrations/observers', 'integrations/evid-subject', 'integrations/frameworks']) cpSync(join(ROOT, dir), join(tmp, dir), { recursive: true });
    const base = runTests(tmp);
    if (base.code !== 0) throw new Error(`Unmutated tests fail: ${base.failed.join('; ')}`);
    const results = [];
    for (const mu of MUTATIONS.filter(x => !only || only.includes(x.id))) {
      const path = join(tmp, mu.file), original = readFileSync(path, 'utf8');
      const count = original.split(mu.find).length - 1;
      if (count !== 1) { results.push({ id: mu.id, property: mu.property, status: 'not-applied', reason: `find matched ${count} times` }); continue; }
      writeFileSync(path, original.replace(mu.find, mu.replace));
      try {
        const r = runTests(tmp);
        results.push({ id: mu.id, property: mu.property, file: mu.file, status: r.code === 0 ? 'SURVIVED' : 'killed', killedBy: r.failed.slice(0, 3) });
      } finally { writeFileSync(path, original); }
      process.stderr.write(`${mu.id} ${results.at(-1).status}\n`);
    }
    const summary = { schema: 'scopehaven-framework-mutations/1', at: new Date().toISOString(), node: process.version, test: TEST, total: results.length, killed: results.filter(r => r.status === 'killed').length, results };
    if (outFile) writeFileSync(outFile, `${JSON.stringify(summary, null, 1)}\n`);
    process.stdout.write(`${JSON.stringify({ total: summary.total, killed: summary.killed, survivors: results.filter(r => r.status !== 'killed').map(r => `${r.id} ${r.status}`) })}\n`);
    if (summary.killed !== summary.total) process.exitCode = 1;
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
