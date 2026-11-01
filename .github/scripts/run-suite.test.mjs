import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

// Only copied launchers and synthetic reporter output run here. Every test run
// (node test/support/bounded-run.mjs, through the launcher or the retry) is
// intercepted; unknown runtime invocations, a bare --test included, are rejected.
const scripts = dirname(fileURLToPath(import.meta.url));
const launcher = resolve(scripts, '../../scopehaven');
const wrapper = join(scripts, 'run-suite.sh');
const bash = '/bin/bash'; // Includes the macOS Bash 3.2 supplied by the runner.

const quote = value => `'${String(value).replaceAll("'", "'\\''")}'`;
const versionProbe = 'process.stdout.write(process.versions.node)';
// Hang guards only, never a speed check: a scenario normally ends in about a
// second, but on a starved runner (1-minute load 15) a correct one took 5.2 s
// and the old 5 s guard failed it. The parser's guard stays below the
// wrapper's, so a hung parser surfaces as the wrapper's error, not as ETIMEDOUT.
const WRAPPER_HANG_MS = 120_000, PARSER_HANG_MS = 60_000;

function tap(rows = [{ name: 'synthetic pass' }]) {
  const totals = { tests: rows.length, suites: 0, pass: 0, fail: 0, cancelled: 0, skipped: 0, todo: 0 };
  const body = ['TAP version 13'];
  rows.forEach((row, index) => {
    const directive = row.todo ? ' # TODO later' : row.skip ? ' # SKIP optional' : '';
    body.push(`# Subtest: ${row.name || `synthetic ${index + 1}`}`);
    body.push(`${row.fail ? 'not ok' : 'ok'} ${index + 1} - ${row.name || `synthetic ${index + 1}`}${directive}`);
    body.push('  ---', '  duration_ms: 1', "  type: 'test'");
    if (row.location) body.push(`  location: '${row.location.replaceAll("'", "''")}:2:1'`);
    if (row.fail) body.push("  failureType: 'testCodeFailure'", "  error: 'synthetic assertion'", "  code: 'ERR_ASSERTION'");
    body.push('  ...');
    if (row.todo) totals.todo++;
    else if (row.skip) totals.skipped++;
    else if (row.fail) totals.fail++;
    else totals.pass++;
  });
  body.push(`1..${rows.length}`);
  for (const [key, value] of Object.entries(totals)) body.push(`# ${key} ${value}`);
  body.push('# duration_ms 1');
  return `${body.join('\n')}\n`;
}

function specFailure(file) {
  return `ℹ tests 1\nℹ suites 0\nℹ pass 0\nℹ fail 1\nℹ cancelled 0\nℹ skipped 0\nℹ todo 0\nℹ duration_ms 1\n\n✖ failing tests:\n\ntest at ${file}:2:1\n✖ synthetic assertion (1ms)\n`;
}

function scenario({ steps, mode = 'false', shard, extraArgs = [], runtime = 'absolute', pinned = 'absent', wrapperPath = wrapper, load = '0.1', scriptAlias = false, failCapture }) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'suite-retry-stub-')));
  const project = join(root, 'scopehaven');
  const scriptDir = join(root, '.github/scripts');
  const bin = join(root, 'bin');
  const temp = join(root, 'temp');
  const ledger = join(root, 'invocations.jsonl');
  const state = join(root, 'steps.json');
  const explicitNode = join(project, 'stub runtime/node');
  const pinnedNode = join(project, '.runtime/node-v24.22.2-darwin-arm64/bin/node');
  const pathNode = join(bin, 'node');
  const files = Array.from({ length: 10 }, (_, index) => join(project, `test/file-${index + 1}.test.mjs`));
  const spaceFile = join(project, 'test/path with spaces.test.mjs');
  const context = { root, project, files, spaceFile, explicitNode, pinnedNode, pathNode };
  try {
    for (const dir of [project, scriptDir, bin, temp, dirname(explicitNode), dirname(pinnedNode), dirname(files[0])]) mkdirSync(dir, { recursive: true });
    copyFileSync(launcher, join(project, 'scopehaven'));
    copyFileSync(wrapperPath, join(scriptDir, 'run-suite.sh'));
    const parser = join(scripts, 'parse-suite-log.mjs');
    if (existsSync(parser)) copyFileSync(parser, join(scriptDir, 'parse-suite-log.mjs'));
    for (const file of [...files, spaceFile]) writeFileSync(file, "throw new Error('Synthetic fixture source must never execute');\n");
    const values = typeof steps === 'function' ? steps(context) : steps;
    writeFileSync(state, JSON.stringify({ index: 0, steps: values }));
    const stub = join(root, 'runtime-stub.mjs');
    writeFileSync(stub, `
import { appendFileSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const [identity, role, ...args] = process.argv.slice(2);
const record = (action, details = {}) => appendFileSync(process.env.SUITE_STUB_LEDGER, JSON.stringify({ identity, role, action, args, ...details }) + '\\n');
if (role === 'broken') { record('broken'); process.exit(126); }
let parserInvocation = false;
try { parserInvocation = realpathSync(args[0]) === process.env.SUITE_STUB_PARSER; } catch {}
if (parserInvocation) {
  record('parser');
  const result = spawnSync(${JSON.stringify(process.execPath)}, args, { encoding: 'utf8', timeout: ${PARSER_HANG_MS} });
  process.stdout.write(result.stdout || ''); process.stderr.write(result.stderr || ''); process.exit(result.status ?? 98);
}
if (args[0] === 'test/support/bounded-run.mjs') {
  record('test');
  if (identity !== process.env.SUITE_STUB_EXPECTED_NODE) { process.stderr.write('Unexpected PATH runtime sentinel\\n'); process.exit(91); }
  const state = JSON.parse(readFileSync(process.env.SUITE_STUB_STATE, 'utf8'));
  const step = state.steps[state.index++]; writeFileSync(process.env.SUITE_STUB_STATE, JSON.stringify(state));
  if (!step) { record('unexpected-test'); process.stderr.write('Unexpected extra test process\\n'); process.exit(97); }
  process.stdout.write(step.output || '');
  // Where the real runner writes its notice of processes a run left running: the file run-suite.sh names, else stderr.
  if (step.notice && process.env.SCOPEHAVEN_TEST_NOTICES) appendFileSync(process.env.SCOPEHAVEN_TEST_NOTICES, 'bounded-run: ' + step.notice + '\\n');
  else if (step.notice) process.stderr.write('\\nbounded-run: ' + step.notice + '\\n');
  if (step.signal) process.kill(process.pid, step.signal);
  else process.exit(step.status ?? 0);
} else { record('unexpected'); process.stderr.write('Unexpected runtime invocation\\n'); process.exit(96); }
`);
    function executable(path, role = 'supported') {
      const probe = JSON.stringify({ identity: path, role, action: role === 'broken' ? 'broken' : 'version', args: ['-e', versionProbe] });
      const version = role === 'unsupported' ? '20.0.0' : process.versions.node;
      // Cache only the exact launcher probe. Ledger identity and role remain
      // unchanged; all parser/test/unknown calls still reach the guarded stub.
      writeFileSync(path, `#!/bin/sh\nif [ "$#" -eq 2 ] && [ "$1" = '-e' ] && [ "$2" = ${quote(versionProbe)} ]; then\n  printf '%s\\n' ${quote(probe)} >> "$SUITE_STUB_LEDGER"\n  ${role === 'broken' ? 'exit 126' : `printf '%s' ${quote(version)}\n  exit 0`}\nfi\nexec ${quote(process.execPath)} ${quote(stub)} ${quote(path)} ${quote(role)} "$@"\n`, { mode: 0o755 });
    }
    executable(explicitNode);
    executable(pathNode);
    if (pinned !== 'absent') executable(pinnedNode, pinned === 'supported' ? 'supported' : pinned);
    writeFileSync(join(bin, 'sysctl'), `#!/bin/sh\nprintf '{ ${load} 0.2 0.3 }\\n'\n`, { mode: 0o755 });
    writeFileSync(join(bin, 'sleep'), `#!/bin/sh\nprintf '%s\\n' "$*" >> ${quote(join(root, 'sleeps.txt'))}\n`, { mode: 0o755 });
    if (failCapture !== undefined) writeFileSync(join(bin, 'tee'), `#!/bin/sh\ncount=0\n[ -f ${quote(join(root, 'captures.txt'))} ] && read -r count < ${quote(join(root, 'captures.txt'))}\ncount=$((count + 1))\nprintf '%s\\n' "$count" > ${quote(join(root, 'captures.txt'))}\n/usr/bin/tee "$@"\nstatus=$?\n[ "$count" -eq ${failCapture} ] && exit 73\nexit "$status"\n`, { mode: 0o755 });
    const expectedNode = runtime === 'absolute' || runtime === 'relative' ? explicitNode : pinned === 'supported' || pinned === 'unsupported' ? pinnedNode : pathNode;
    const env = { ...process.env };
    for (const name of Object.keys(env)) if (name === 'SCOPEHAVEN_NODE' || name === 'NODE_OPTIONS' || name === 'NODE_PATH' || name.startsWith('SUITE_STUB_')) delete env[name];
    Object.assign(env, {
      PATH: `${bin}:/usr/bin:/bin`, RUNNER_TEMP: temp, TMPDIR: `${temp}/`,
      SUITE_STUB_LEDGER: ledger, SUITE_STUB_STATE: state,
      SUITE_STUB_EXPECTED_NODE: expectedNode, SUITE_STUB_PARSER: join(scriptDir, 'parse-suite-log.mjs'),
    });
    if (runtime === 'absolute') env.SCOPEHAVEN_NODE = explicitNode;
    if (runtime === 'relative') env.SCOPEHAVEN_NODE = 'stub runtime/node';
    if (scriptAlias) symlinkSync(root, join(root, 'alias'), 'dir');
    const args = [scriptAlias ? join(root, 'alias/.github/scripts/run-suite.sh') : join(scriptDir, 'run-suite.sh'), mode];
    if (shard !== undefined) args.push(shard);
    args.push(...extraArgs);
    const result = spawnSync(bash, args, { cwd: project, env, encoding: 'utf8', timeout: WRAPPER_HANG_MS, maxBuffer: 1024 * 1024 });
    assert.ifError(result.error);
    assert.equal(result.signal, null, `Wrapper was terminated: ${result.signal}`);
    const calls = existsSync(ledger) ? readFileSync(ledger, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) : [];
    const tests = calls.filter(call => call.action === 'test');
    assert.equal(calls.filter(call => call.action.startsWith('unexpected')).length, 0, 'No unknown command or extra test process may execute');
    return { ...context, result, calls, tests, expectedNode, output: `${result.stdout}${result.stderr}`, sleeps: existsSync(join(root, 'sleeps.txt')) ? readFileSync(join(root, 'sleeps.txt'), 'utf8').trim().split('\n') : [] };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function assertInvocations(run, expectedCount) {
  assert.equal(run.tests.length, expectedCount, run.output);
  for (const call of run.tests) assert.equal(call.identity, run.expectedNode, 'Initial run and retry use the selected executable');
  for (const call of run.calls.filter(call => call.action === 'parser')) assert.equal(call.identity, run.expectedNode, 'Parser uses the selected executable');
  if (expectedCount) assert.ok(run.tests[0].args.includes('--test-reporter=tap'), 'Initial reporter is explicit TAP');
}

function assertRetry(run, files) {
  assertInvocations(run, 2);
  assert.deepEqual(run.tests[1].args, ['test/support/bounded-run.mjs', '--test-reporter=tap', '--test-concurrency=1', ...files], 'Retry is exactly the named files, through the bounded runner, with no shard or full-suite globs');
}

// The bounded runner exits 124 when a run passes its wall-clock bound and is killed as a hang (test/support/bounded-run.mjs).
const partialTap = file => `TAP version 13\n# Subtest: started\nnot ok 1 - started\n  ---\n  duration_ms: 1\n  type: 'test'\n  location: '${file}:2:1'\n  failureType: 'testCodeFailure'\n  error: 'synthetic assertion'\n  code: 'ERR_ASSERTION'\n  ...\n`;
test('a first run killed at its bound stays red with status 124 and is never rerun, whatever its partial TAP names', () => {
  const run = scenario({ steps: ({ files }) => [{ output: partialTap(files[0]), status: 124 }] });
  assert.equal(run.result.status, 124, run.output);
  assertInvocations(run, 1);
  assert.match(run.output, /passed its time bound and was killed as a hang; no rerun/);
  assert.doesNotMatch(run.output, /Flaky test files/);
});

test('a rerun killed at its bound stays red, never flake-plus-green', () => {
  const run = scenario({ steps: ({ files }) => [{ output: tap([{ name: 'fails once', fail: true, location: files[0] }]), status: 1 }, { output: partialTap(files[0]), status: 124 }] });
  assert.equal(run.result.status, 124, run.output);
  assertRetry(run, [run.files[0]]);
  assert.doesNotMatch(run.output, /Flaky test files/);
});

// A run that passed but left processes the runner then stopped keeps its status, as through the launcher: the notice is a warning,
// kept out of the log the parser reads.
test('processes a clean run left running are a warning, not a failure or a malformed log', () => {
  const notice = 'stopped 1 process(es) the run left running: 4242 /bin/sleep 50%.';
  const run = scenario({ steps: [{ output: tap(), notice }] });
  assert.equal(run.result.status, 0, run.output);
  assertInvocations(run, 1);
  assert.ok(run.output.includes(`::warning title=Processes left by the test run::bounded-run: ${notice.replace('%', '%25')}`), run.output);
  assert.doesNotMatch(run.output, /malformed|Flaky test files/);
});

test('clean completion exits zero without a retry', () => {
  const run = scenario({ steps: [{ output: tap() }] });
  assert.equal(run.result.status, 0, run.output);
  assertInvocations(run, 1);
  assert.doesNotMatch(run.output, /Flaky test files/);
});

test('zero tests are nonzero with or without a shard', () => {
  for (const shard of [undefined, '1/4']) {
    const run = scenario({ shard, steps: [{ output: tap([]) }] });
    assert.equal(run.result.status, 1, run.output);
    assertInvocations(run, 1);
  }
});

test('identified failure retries once and warns when the retry passes', () => {
  const run = scenario({ steps: ({ files }) => [{ status: 1, output: tap([{ fail: true, location: files[0] }]) }, { output: tap() }] });
  assert.equal(run.result.status, 0, run.output);
  assertRetry(run, [run.files[0]]);
  assert.match(run.output, /::warning title=Flaky test files::/);
  assert.ok(run.output.includes(run.files[0]));
  assert.match(run.output, /synthetic assertion/);
});

test('an unidentified failure preserves its original status and has no retry', () => {
  const run = scenario({ steps: [{ status: 1, output: tap([{ fail: true }]) }] });
  assert.equal(run.result.status, 1, run.output);
  assertInvocations(run, 1);
});

test('one unidentified failure prevents retrying only the other known failure', () => {
  const run = scenario({ steps: ({ files }) => [{ status: 1, output: tap([{ fail: true, location: files[0] }, { fail: true }]) }] });
  assert.equal(run.result.status, 1, run.output);
  assertInvocations(run, 1);
});

test('more than eight identified failed files preserve failure without a retry', () => {
  const run = scenario({ steps: ({ files }) => [{ status: 1, output: tap(files.slice(0, 9).map(location => ({ fail: true, location }))) }] });
  assert.equal(run.result.status, 1, run.output);
  assertInvocations(run, 1);
});

test('exactly eight failed files are retried once', () => {
  const run = scenario({ steps: ({ files }) => [{ status: 1, output: tap(files.slice(0, 8).map(location => ({ fail: true, location }))) }, { output: tap() }] });
  assert.equal(run.result.status, 0, run.output);
  assertRetry(run, run.files.slice(0, 8));
});

test('multiple failures in the same file do not duplicate the retry file', () => {
  const run = scenario({ steps: ({ files }) => [{ status: 1, output: tap([{ fail: true, location: files[0] }, { fail: true, location: files[0] }]) }, { output: tap() }] });
  assert.equal(run.result.status, 0, run.output);
  assertRetry(run, [run.files[0]]);
});

test('paths containing spaces remain a single exact argument', () => {
  const run = scenario({ steps: ({ spaceFile }) => [{ status: 1, output: tap([{ fail: true, location: spaceFile }]) }, { output: tap() }] });
  assert.equal(run.result.status, 0, run.output);
  assertRetry(run, [run.spaceFile]);
});

test('persistent failure preserves the retry process status with no third attempt', () => {
  const run = scenario({ steps: ({ files }) => [{ status: 1, output: tap([{ fail: true, location: files[0] }]) }, { status: 13, output: tap([{ fail: true, location: files[0] }]) }] });
  assert.equal(run.result.status, 13, run.output);
  assertRetry(run, [run.files[0]]);
  assert.doesNotMatch(run.output, /Flaky test files/);
});

test('missing, truncated, malformed and contradictory completion cannot pass', () => {
  const captures = [
    '',
    'TAP version 13\n# Subtest: unfinished\n',
    tap().replace('# duration_ms 1\n', ''),
    tap().replace('# tests 1', '# tests nonsense'),
    tap().replace('# fail 0', '# fail 1'),
    `noise says # tests 1\n${tap().replace('1..1\n', '')}`,
    `${tap()}# fail 9\n`,
  ];
  for (const output of captures) {
    const run = scenario({ steps: [{ output }] });
    assert.equal(run.result.status, 1, run.output);
    assertInvocations(run, 1);
  }
});

test('termination preserves its signal-derived status and does not retry partial output', () => {
  const run = scenario({ steps: [{ output: 'TAP version 13\n# Subtest: interrupted\n', signal: 'SIGTERM' }] });
  assert.equal(run.result.status, 143, run.output);
  assertInvocations(run, 1);
});

test('a nonzero process cannot pass despite a success summary', () => {
  const run = scenario({ steps: [{ status: 17, output: tap() }] });
  assert.equal(run.result.status, 17, run.output);
  assertInvocations(run, 1);
});

test('an abnormal exit with identified failures is preserved without retry', () => {
  const run = scenario({ steps: ({ files }) => [{ status: 7, output: tap([{ fail: true, location: files[0] }]) }] });
  assert.equal(run.result.status, 7, run.output);
  assertInvocations(run, 1);
});

test('cancelled tests remain nonzero without retry', () => {
  const output = tap([{ fail: true }]).replace("failureType: 'testCodeFailure'", "failureType: 'cancelledByParent'").replace('# fail 1', '# fail 0').replace('# cancelled 0', '# cancelled 1');
  const run = scenario({ steps: [{ status: 1, output }] });
  assert.equal(run.result.status, 1, run.output);
  assertInvocations(run, 1);
});

test('a script path alias still executes CLI completion validation', () => {
  const run = scenario({ scriptAlias: true, steps: [{ output: 'TAP version 13\n# Subtest: incomplete\n' }] });
  assert.equal(run.result.status, 1, run.output);
  assertInvocations(run, 1);
});

test('failed initial log capture preserves tee status and prevents retry', () => {
  const run = scenario({ failCapture: 1, steps: [{ output: tap() }] });
  assert.equal(run.result.status, 73, run.output);
  assertInvocations(run, 1);
  assert.match(run.output, /test log capture failed/);
  assert.equal(run.calls.filter(call => call.action === 'parser').length, 0);
});

test('failed initial capture preserves a nonzero test status', () => {
  const run = scenario({ failCapture: 1, steps: ({ files }) => [{ status: 7, output: tap([{ fail: true, location: files[0] }]) }] });
  assert.equal(run.result.status, 7, run.output);
  assertInvocations(run, 1);
});

test('failed retry log capture stays nonzero without a flake warning', () => {
  const run = scenario({ failCapture: 2, steps: ({ files }) => [{ status: 1, output: tap([{ fail: true, location: files[0] }]) }, { output: tap() }] });
  assert.equal(run.result.status, 73, run.output);
  assertRetry(run, [run.files[0]]);
  assert.match(run.output, /log capture failed/);
  assert.doesNotMatch(run.output, /Flaky test files/);
});

test('an incomplete retry with status zero remains nonzero and has no flake warning', () => {
  const run = scenario({ steps: ({ files }) => [{ status: 1, output: tap([{ fail: true, location: files[0] }]) }, { output: 'TAP version 13\n# Subtest: incomplete retry\n' }] });
  assert.equal(run.result.status, 1, run.output);
  assertRetry(run, [run.files[0]]);
  assert.doesNotMatch(run.output, /Flaky test files/);
});

test('TODO and skipped tests keep their passing semantics', () => {
  const run = scenario({ steps: [{ output: tap([{ fail: true, todo: true }, { skip: true }]) }] });
  assert.equal(run.result.status, 0, run.output);
  assertInvocations(run, 1);
});

test('a TODO failure is excluded from the ordinary failure retry set', () => {
  const run = scenario({ steps: ({ files }) => [{ status: 1, output: tap([{ fail: true, todo: true, location: files[1] }, { fail: true, location: files[0] }, { skip: true }]) }, { output: tap() }] });
  assert.equal(run.result.status, 0, run.output);
  assertRetry(run, [run.files[0]]);
});

for (const [name, config] of [
  ['explicit absolute executable', { runtime: 'absolute', pinned: 'supported' }],
  ['explicit relative executable', { runtime: 'relative', pinned: 'supported' }],
  ['pinned executable before PATH', { runtime: 'automatic', pinned: 'supported' }],
  ['PATH when pinned executable cannot run', { runtime: 'automatic', pinned: 'broken' }],
  ['PATH when pinned executable is absent', { runtime: 'automatic', pinned: 'absent' }],
]) {
  test(`runtime consistency: ${name}`, () => {
    const run = scenario({ ...config, steps: ({ files }) => [{ status: 1, output: tap([{ fail: true, location: files[0] }]) }, { output: tap() }] });
    assert.equal(run.result.status, 0, run.output);
    assertRetry(run, [run.files[0]]);
    if (config.runtime !== 'automatic') assert.ok(run.calls.filter(call => call.action === 'version').every(call => call.identity === run.explicitNode), 'Explicit runtime takes precedence');
    if (config.pinned === 'supported' && config.runtime === 'automatic') assert.ok(run.calls.every(call => call.identity !== run.pathNode), 'Runnable pinned runtime prevents PATH use');
  });
}

test('an unsupported runnable pinned version does not fall back to PATH', () => {
  const run = scenario({ runtime: 'automatic', pinned: 'unsupported', steps: [] });
  assert.equal(run.result.status, 2, run.output);
  assertInvocations(run, 0);
  assert.ok(run.calls.every(call => call.identity !== run.pathNode));
});

test('valid multidigit shard is passed only to the initial run', () => {
  const run = scenario({ shard: '12/24', steps: ({ files }) => [{ status: 1, output: tap([{ fail: true, location: files[0] }]) }, { output: tap() }] });
  assert.equal(run.result.status, 0, run.output);
  assertRetry(run, [run.files[0]]);
  assert.ok(run.tests[0].args.includes('--test-shard=12/24'));
  assert.ok(run.tests[0].args.indexOf('--test-shard=12/24') < run.tests[0].args.indexOf('test/file-1.test.mjs'));
});

test('invalid shards fail before any runtime or test process starts', () => {
  for (const shard of ['0/4', '1/0', '5/4', '01/4', '1/04', '-1/4', '1/4/2', 'a/b', '1', '1/4 ', '1/1e3', '9007199254740993/9007199254740994']) {
    const run = scenario({ shard, steps: [] });
    assert.equal(run.result.status, 2, `${shard}: ${run.output}`);
    assert.equal(run.calls.length, 0, `${shard}: invalid arguments must not launch a runtime`);
  }
});

test('invalid runner modes and extra arguments fail before any process starts', () => {
  for (const config of [{ mode: 'yes' }, { mode: 'TRUE' }, { mode: 'false', shard: '1/4', extraArgs: ['unexpected'] }]) {
    const run = scenario({ ...config, steps: [] });
    assert.equal(run.result.status, 2, run.output);
    assert.equal(run.calls.length, 0);
  }
});

test('self-hosted low-load retry does not sleep and names both observed loads', () => {
  const run = scenario({ mode: 'true', steps: ({ files }) => [{ status: 1, output: tap([{ fail: true, location: files[0] }]) }, { output: tap() }] });
  assert.equal(run.result.status, 0, run.output);
  assertRetry(run, [run.files[0]]);
  assert.equal(run.sleeps.length, 0);
  assert.match(run.output, /load at start: 0\.1/);
  assert.match(run.output, /load at end: 0\.1/);
  assert.match(run.output, /failed at 1-minute load 0\.1.*rerun at 0\.1/);
});

test('self-hosted sustained load keeps the existing bounded wait using a no-op sleep stub', () => {
  const run = scenario({ mode: 'true', load: '40', steps: ({ files }) => [{ status: 1, output: tap([{ fail: true, location: files[0] }]) }, { output: tap() }] });
  assert.equal(run.result.status, 0, run.output);
  assertRetry(run, [run.files[0]]);
  assert.equal(run.sleeps.length, 60);
  assert.ok(run.sleeps.every(value => value === '20'));
  assert.match(run.output, /still 40 after 20 minutes/);
});

const baseline = process.env.SUITE_RETRY_BASELINE;
test('baseline regression: TAP failures do not reach the spec-only retry parser', { skip: !baseline }, () => {
  const run = scenario({ wrapperPath: baseline, steps: ({ files }) => [{ status: 7, output: tap([{ fail: true, location: files[0] }]) }] });
  assert.equal(run.result.status, 7);
  assert.equal(run.tests.length, 1);
  assert.match(run.output, /No rerun: 0 failed test files named/);
});

test('baseline regression: missing completion with status zero incorrectly passes', { skip: !baseline }, () => {
  const run = scenario({ wrapperPath: baseline, steps: [{ output: 'TAP version 13\n# Subtest: incomplete\n' }] });
  assert.equal(run.result.status, 0);
  assert.equal(run.tests.length, 1);
});

test('baseline regression: spec failure retry uses the PATH sentinel instead of selected runtime', { skip: !baseline }, () => {
  const run = scenario({ wrapperPath: baseline, steps: ({ files }) => [{ status: 7, output: specFailure(files[0]) }] });
  assert.equal(run.result.status, 1);
  assert.equal(run.tests.length, 2);
  assert.equal(run.tests[0].identity, run.explicitNode);
  assert.equal(run.tests[1].identity, run.pathNode);
  assert.match(run.output, /Unexpected PATH runtime sentinel/);
});

test('baseline regression: index above total is admitted and reaches the test process', { skip: !baseline }, () => {
  const run = scenario({ wrapperPath: baseline, shard: '5/4', steps: [{ output: tap() }] });
  assert.equal(run.result.status, 0);
  assert.equal(run.tests.length, 1);
  assert.ok(run.tests[0].args.includes('--test-shard=5/4'));
});
