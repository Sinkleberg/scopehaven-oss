// test/support/bounded-run.mjs, the runner behind ./scopehaven test, npm test and the CI retry: node --test under a wall-clock bound.
// Synthetic test files only, in a private temporary directory; the only processes started are node and /bin/sleep.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const RUNNER = fileURLToPath(new URL('./support/bounded-run.mjs', import.meta.url));
const LAUNCHER = fileURLToPath(new URL('../scopehaven', import.meta.url));
const SCRIPTS = fileURLToPath(new URL('../../.github/scripts/', import.meta.url));
async function directory(t, files) {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-bounded-run-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  for (const [name, source] of Object.entries(files)) { await mkdir(dirname(join(dir, name)), { recursive: true }); await writeFile(join(dir, name), source); }
  return dir;
}
// The runner on the named files, with its output and how long it took. The guard (its own process group, killed at 60 s) only ends a
// runner that itself hangs. `bin` goes first on the runner's PATH (a ps stand-in); `notices` is SCOPEHAVEN_TEST_NOTICES; `env` adds
// to the environment; `argv` and `cwd` run another command instead (the launcher, or run-suite.sh).
function run(dir, files, bound, { bin, notices, env: extra = {}, argv = [process.execPath, RUNNER, '--test-reporter=spec', ...files], cwd = dir } = {}) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, SCOPEHAVEN_TEST_BOUND_SECONDS: String(bound) };
    delete env.NODE_TEST_CONTEXT;
    delete env.SCOPEHAVEN_TEST_NOTICES;
    if (bin) env.PATH = `${bin}:${env.PATH}`;
    if (notices) env.SCOPEHAVEN_TEST_NOTICES = notices;
    Object.assign(env, extra);
    const started = performance.now();
    const child = spawn(argv[0], argv.slice(1), { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
    let out = '', hung = false;
    // A runner that died early leaves its detached run holding these pipes, so they are closed here too.
    const guard = setTimeout(() => { hung = true; try { process.kill(-child.pid, 'SIGKILL'); } catch {} child.stdout.destroy(); child.stderr.destroy(); }, 60000);
    child.stdout.on('data', bytes => { out += bytes; }); child.stderr.on('data', bytes => { out += bytes; });
    child.on('error', reject);
    child.on('close', code => { clearTimeout(guard); resolve({ code, out, ms: performance.now() - started, hung }); });
  });
}
const running = marker => spawnSync('ps', ['-A', '-o', 'command='], { encoding: 'utf8' }).stdout.split('\n').filter(line => line.includes(marker));
const marker = () => `/bin/sleep ${(50 + Math.random() * 9).toFixed(4)}`;
const LEAK = 'setInterval(() => {}, 20);';

test('bounded run: a passing run exits 0 and a failing run exits 1, each as soon as it ends', async t => {
  const dir = await directory(t, {
    'passes.test.mjs': "import test from 'node:test';\ntest('passes', () => {});\n",
    'fails.test.mjs': "import test from 'node:test';\nimport assert from 'node:assert/strict';\ntest('fails', () => assert.fail('synthetic failure'));\n",
  });
  const passed = await run(dir, ['passes.test.mjs'], 60), failed = await run(dir, ['fails.test.mjs'], 60);
  assert.deepEqual([passed.code, failed.code], [0, 1], passed.out + failed.out);
  assert.ok(passed.ms < 30000 && failed.ms < 30000, `${passed.ms} ${failed.ms}`);
  assert.match(failed.out, /synthetic failure/);
});

test('bounded run: a file that never exits, and a test that never settles, each fail the run at the bound with status 124 and are named', async t => {
  const dir = await directory(t, {
    // In a directory whose name has a space, as the checkout's does: the file is still named whole.
    'with space/leaks.test.mjs': `import test from 'node:test';\ntest('passes but leaves a timer', () => { ${LEAK} });\n`,
    'pending.test.mjs': `import test from 'node:test';\ntest('never settles', () => { ${LEAK} return new Promise(() => {}); });\n`,
  });
  for (const file of ['with space/leaks.test.mjs', 'pending.test.mjs']) {
    const result = await run(dir, [file], 3);
    assert.equal(result.hung, false, `${file}: the runner itself hung`);
    assert.equal(result.code, 124, `${file}: ${result.out}`);
    assert.ok(result.ms >= 3000 && result.ms < 15000, `${file}: ${Math.round(result.ms)} ms (bound 3 s, then at most 5 s to kill)`);
    assert.match(result.out, new RegExp(`still going after 3 s, so it is treated as a hang and killed \\(exit status 124\\)\\. Test files still running: ${file.replace('.', '\\.')}\\.`));
  }
});

test('bounded run: a failing test registered after a top-level await, or in a timer beside a leaked interval, fails the run instead of vanishing', async t => {
  const dir = await directory(t, {
    'late.test.mjs': "import test from 'node:test';\nimport assert from 'node:assert/strict';\ntest('first', () => {});\nawait new Promise(resolve => setTimeout(resolve, 300));\ntest('late', () => assert.fail('the late test ran'));\n",
    'timer.test.mjs': `import test from 'node:test';\nimport assert from 'node:assert/strict';\ntest('first', () => {});\n${LEAK}\nsetTimeout(() => test('in a timer', () => assert.fail('the timer test ran')), 100);\n`,
  });
  const late = await run(dir, ['late.test.mjs'], 30);
  assert.equal(late.code, 1, late.out);
  assert.match(late.out, /the late test ran/);
  const timer = await run(dir, ['timer.test.mjs'], 3);
  assert.equal(timer.code, 124, timer.out);
  assert.match(timer.out, /the timer test ran/);
});

test('bounded run: the kill at the bound reaches every process the run started, a detached one (its own process group) included', async t => {
  const detached = marker(), piped = marker();
  const dir = await directory(t, {
    'children.test.mjs': `import test from 'node:test';\nimport { spawn } from 'node:child_process';\ntest('hangs with two children', () => {\n  spawn('/bin/sleep', ['${detached.split(' ')[1]}'], { detached: true, stdio: 'ignore' }).unref();\n  spawn('/bin/sleep', ['${piped.split(' ')[1]}'], { stdio: 'pipe' });\n  ${LEAK}\n});\n`,
  });
  const result = await run(dir, ['children.test.mjs'], 3);
  assert.equal(result.code, 124, result.out);
  assert.deepEqual([running(detached), running(piped)], [[], []], 'nothing the run started outlives it');
  assert.doesNotMatch(result.out, /could not stop/);
});

test('bounded run: a process a clean run leaves behind is stopped and named in a notice, and the run keeps its status', async t => {
  // The test outlives several reads of the process table (every 250 ms) after starting its child, so the child is on the record.
  const leaves = name => `import test from 'node:test';\nimport { spawn } from 'node:child_process';\ntest('leaves a detached child', async () => {\n  spawn('/bin/sleep', ['${name.split(' ')[1]}'], { detached: true, stdio: 'ignore' }).unref();\n  await new Promise(resolve => setTimeout(resolve, 1500));\n});\n`;
  const onStderr = marker(), toFile = marker();
  const dir = await directory(t, { 'stderr.test.mjs': leaves(onStderr), 'file.test.mjs': leaves(toFile) });
  const plain = await run(dir, ['stderr.test.mjs'], 30);
  assert.equal(plain.code, 0, plain.out);
  assert.match(plain.out, new RegExp(`bounded-run: stopped 1 process\\(es\\) the run left running: \\d+ ${onStderr.replace('.', '\\.')}`));
  assert.deepEqual(running(onStderr), []);
  // With SCOPEHAVEN_TEST_NOTICES set (run-suite.sh sets it) the notice goes to that file, so it stays out of the reporter's output.
  const notices = join(dir, 'notices.txt');
  const filed = await run(dir, ['file.test.mjs'], 30, { notices });
  assert.equal(filed.code, 0, filed.out);
  assert.doesNotMatch(filed.out, /bounded-run:/);
  assert.match(await readFile(notices, 'utf8'), new RegExp(`^bounded-run: stopped 1 process\\(es\\) the run left running: \\d+ ${toFile.replace('.', '\\.')}\\.\\n$`));
  assert.deepEqual(running(toFile), []);
});

// The bound never waits for ps. Each stand-in is three lines; its sleep carries a marker, so a stand-in left running would show.
test('bounded run: the bound holds when ps is slow, ignores SIGTERM or never returns', async t => {
  const SLOW = 1.2;   // under the runner's 2 s limit on a read
  for (const [kind, body, answers] of [
    ['slow', tag => `/bin/sleep ${tag}\nexec /bin/ps "$@"`, true],
    ['deaf to SIGTERM', tag => `trap '' TERM\nexec /bin/sleep ${tag}`, false],
    ['never returning', tag => `trap '' TERM HUP INT\nexec /bin/sleep ${tag}`, false],
  ]) {
    const detached = marker(), piped = marker();
    const tag = kind === 'slow' ? `${SLOW}${Math.random().toFixed(6).slice(2)}` : kind === 'deaf to SIGTERM' ? `40.${Math.random().toFixed(6).slice(2)}` : `99999.${Math.random().toFixed(6).slice(2)}`;
    const dir = await directory(t, {
      'bin/ps': `#!/bin/sh\n${body(tag)}\n`,
      // A child in the run's process group, and (when ps answers, so it can be found) a detached one. The file stamps the moment
      // the SIGTERM reaches it.
      'hangs.test.mjs': `import test from 'node:test';\nimport { spawn } from 'node:child_process';\nimport { writeFileSync } from 'node:fs';\nprocess.on('SIGTERM', () => { writeFileSync('term-stamp', String(Date.now())); process.exit(143); });\ntest('hangs', () => {\n  ${answers ? `spawn('/bin/sleep', ['${detached.split(' ')[1]}'], { detached: true, stdio: 'ignore' }).unref();\n  ` : ''}spawn('/bin/sleep', ['${piped.split(' ')[1]}'], { stdio: 'pipe' });\n  ${LEAK}\n});\n`,
    });
    await chmod(join(dir, 'bin/ps'), 0o755);
    const bound = answers ? 6 : 3, started = Date.now();
    const result = await run(dir, ['hangs.test.mjs'], bound, { bin: join(dir, 'bin') });
    assert.equal(result.hung, false, `${kind}: the runner itself hung`);
    assert.equal(result.code, 124, `${kind}: ${result.out}`);
    // The SIGTERM lands at the bound, not after a read; after the run ends, the runner spends at most two 2 s reads and a 300 ms
    // pause before exiting.
    const termAt = Number(await readFile(join(dir, 'term-stamp'), 'utf8')) - started;
    assert.ok(termAt >= bound * 1000 && termAt < bound * 1000 + 1500, `${kind}: SIGTERM ${termAt} ms after the start (bound ${bound} s)`);
    assert.ok(result.ms < bound * 1000 + 9000, `${kind}: ${Math.round(result.ms)} ms (bound ${bound} s)`);
    assert.match(result.out, answers ? /Test files still running: hangs\.test\.mjs\./ : /Test files still running: unknown \(the process table could not be read\)\./, kind);
    assert.deepEqual([running(detached), running(piped)], [[], []], `${kind}: nothing the run started outlives it`);
    // A stand-in that never answers is one process (its sleep is exec'd), killed at the read's limit or as the runner exits. The slow
    // one's sleep is a child of its shell and ends on its own.
    if (!answers) assert.deepEqual(running(`/bin/sleep ${tag}`), [], `${kind}: no ps stand-in outlives the run`);
  }
});

test('bounded run: a bound that is not a positive number of seconds is refused', async t => {
  const dir = await directory(t, { 'passes.test.mjs': "import test from 'node:test';\ntest('passes', () => {});\n" });
  for (const bound of ['abc', '0', '-5', '3000000']) {
    const result = await run(dir, ['passes.test.mjs'], bound);
    assert.equal(result.code, 2, `${bound}: ${result.out}`);
    assert.match(result.out, /SCOPEHAVEN_TEST_BOUND_SECONDS must be a positive number of seconds/);
  }
});

// A fault in the runner process only. NODE_OPTIONS loads this into every node process, but it acts only in the runner, from 1 s after
// the runner starts (or, for 'stale', once the file RUNNER_FAULT_FLAG names exists):
// - emfile: the runner opens /dev/null until its descriptors run out (under a 512 limit; the cap of 4096 is a guard), so spawning ps
//   fails with EMFILE, and Node returns a child with no stdout;
// - enomem: spawning ps throws, as Node does for a spawn errno such as ENOMEM;
// - crash: the runner throws an error it does not expect;
// - stale: as enomem, and the runner's clock moves on 60 s, so its last table is a minute old.
// Each says on stderr that it acted, so a test can tell the fault happened.
const FAULT = `import { syncBuiltinESMExports } from 'node:module';
import childProcess from 'node:child_process';
import { existsSync, openSync } from 'node:fs';
const fault = process.env.RUNNER_FAULT;
if (fault && process.argv[1]?.endsWith('/test/support/bounded-run.mjs')) {
  const begin = () => {
    if (fault === 'emfile') { let code = 'none'; for (let i = 0; i < 4096 && code === 'none'; i++) { try { openSync('/dev/null', 'r'); } catch (error) { code = error.code; } } process.stderr.write(\`fault: opening a descriptor failed with \${code}\\n\`); }
    if (fault === 'crash') throw new Error('synthetic fault in the runner');
    if (fault === 'enomem' || fault === 'stale') {
      const real = childProcess.spawn;
      let told = false;
      childProcess.spawn = (command, ...rest) => {
        if (command !== 'ps') return real(command, ...rest);
        if (!told) { told = true; process.stderr.write('fault: spawning ps threw ENOMEM\\n'); }
        throw Object.assign(new Error('spawn ps ENOMEM'), { code: 'ENOMEM', errno: -12, syscall: 'spawn ps' });
      };
      syncBuiltinESMExports();
    }
    if (fault === 'stale') { const now = performance.now.bind(performance); performance.now = () => now() + 60000; }
  };
  if (fault === 'stale') { const wait = setInterval(() => { if (existsSync(process.env.RUNNER_FAULT_FLAG)) { clearInterval(wait); begin(); } }, 20); wait.unref(); }
  else setTimeout(begin, 1000).unref();
}
`;
const faulty = (dir, fault, more = {}) => ({ NODE_OPTIONS: `--import=${pathToFileURL(join(dir, 'fault.mjs')).href}`, RUNNER_FAULT: fault, ...more });
// A file that hangs with a child in the run's process group; it ends itself at 60 s, so a runner that lost the run leaves it only that long.
const hangs = group => `import test from 'node:test';\nimport { spawn } from 'node:child_process';\nsetTimeout(() => process.exit(0), 60000);\ntest('hangs with a child', () => {\n  spawn('/bin/sleep', ['${group.split(' ')[1]}'], { stdio: 'pipe' });\n  ${LEAK}\n});\n`;
const limited = argv => ['/bin/bash', '-c', 'ulimit -n 512 && exec "$@"', 'bash', ...argv];

test('bounded run: a ps that cannot be spawned, or an error in the runner itself, never leaves the run going unbounded', async t => {
  const group = marker(), crashGroup = marker();
  const dir = await directory(t, { 'fault.mjs': FAULT, 'hangs.test.mjs': hangs(group), 'crash.test.mjs': hangs(crashGroup) });
  // Every spawn of ps throws from 1 s on: the run still ends at the bound, with 124, and nothing it started outlives it.
  const thrown = await run(dir, ['hangs.test.mjs'], 4, { env: faulty(dir, 'enomem') });
  assert.equal(thrown.hung, false, 'the runner itself hung');
  assert.equal(thrown.code, 124, thrown.out);
  assert.ok(thrown.ms >= 4000 && thrown.ms < 13000, `${Math.round(thrown.ms)} ms (bound 4 s)`);
  assert.match(thrown.out, /fault: spawning ps threw ENOMEM/);
  assert.match(thrown.out, /still going after 4 s, so it is treated as a hang and killed \(exit status 124\)/);
  assert.deepEqual(running(group), [], 'nothing the run started outlives it');
  // An error the runner does not expect, before the bound: the run is killed at once, and the status is 1.
  const crashed = await run(dir, ['crash.test.mjs'], 30, { env: faulty(dir, 'crash') });
  assert.equal(crashed.code, 1, crashed.out);
  assert.ok(crashed.ms < 15000, `${Math.round(crashed.ms)} ms`);
  assert.match(crashed.out, /internal error, so the run is killed \(exit status 1\): Error: synthetic fault in the runner/);
  assert.deepEqual(running(crashGroup), [], 'nothing the run started outlives it');
});

test('bounded run: with its descriptors exhausted, through the launcher and through run-suite.sh, the run still ends at the bound with 124', { skip: !existsSync(join(SCRIPTS, 'run-suite.sh')) && 'no .github/scripts beside this checkout' }, async t => {
  // A stripped copy of the project: the launcher, the runner, the hanging file, and a passing file for each of the launcher's other
  // selections (a glob's * read as "stub").
  const group = marker(), files = { 'fault.mjs': FAULT, 'scopehaven/test/hangs.test.mjs': hangs(group) };
  const launcher = await readFile(LAUNCHER, 'utf8');
  const arm = /^\s*test\) exec "\$scopehaven_node" test\/support\/bounded-run\.mjs "\$@" (.+) ;;\s*$/m.exec(launcher);
  assert.ok(arm, 'the launcher\'s test arm');
  for (const selection of arm[1].split(' ')) files[`scopehaven/${selection.replaceAll('*', 'stub')}`] = "import test from 'node:test';\ntest('passes', () => {});\n";
  files['scopehaven/scopehaven'] = launcher;
  files['scopehaven/test/support/bounded-run.mjs'] = await readFile(RUNNER, 'utf8');
  for (const name of ['run-suite.sh', 'parse-suite-log.mjs']) files[`.github/scripts/${name}`] = await readFile(join(SCRIPTS, name), 'utf8');
  const dir = await directory(t, files);
  await chmod(join(dir, 'scopehaven/scopehaven'), 0o755);
  const project = join(dir, 'scopehaven'), env = faulty(dir, 'emfile', { SCOPEHAVEN_NODE: process.execPath });
  for (const [path, argv] of [
    ['launcher', [join(project, 'scopehaven'), 'test', '--test-reporter=spec']],
    ['run-suite.sh', ['/bin/bash', join(dir, '.github/scripts/run-suite.sh'), 'false']],
  ]) {
    const result = await run(dir, [], 4, { env, cwd: project, argv: limited(argv) });
    assert.equal(result.hung, false, `${path}: the runner itself hung`);
    assert.equal(result.code, 124, `${path}: ${result.out}`);
    assert.ok(result.ms >= 4000 && result.ms < 13000, `${path}: ${Math.round(result.ms)} ms (bound 4 s)`);
    assert.match(result.out, /fault: opening a descriptor failed with EMFILE/, path);
    assert.match(result.out, /still going after 4 s, so it is treated as a hang and killed \(exit status 124\)/, path);
    if (path === 'run-suite.sh') assert.match(result.out, /passed its time bound and was killed as a hang; no rerun/);
    assert.deepEqual(running(group), [], `${path}: nothing the run started outlives it`);
  }
});

test('bounded run: a remembered process is signalled only from a recent table, so a stale pid is not signalled', async t => {
  // The ps stand-in marks each table read. The file starts a detached child and a group child, waits for two table reads that began
  // after them (reads run one at a time, so the first is on the record), then makes the runner's table a minute old for good.
  const detached = marker(), group = marker();
  const dir = await directory(t, {});
  const reads = join(dir, 'reads'), flag = join(dir, 'stale'), pidFile = join(dir, 'detached-pid');
  await mkdir(join(dir, 'bin'));
  await writeFile(join(dir, 'bin/ps'), `#!/bin/sh\ncase "$*" in *lstart*) printf . >> ${JSON.stringify(reads)} ;; esac\nexec /bin/ps "$@"\n`, { mode: 0o755 });
  await writeFile(join(dir, 'fault.mjs'), FAULT);
  await writeFile(join(dir, 'hangs.test.mjs'), `import test from 'node:test';\nimport { spawn } from 'node:child_process';\nimport { existsSync, readFileSync, writeFileSync } from 'node:fs';\nsetTimeout(() => process.exit(0), 60000);\nconst reads = () => existsSync(${JSON.stringify(reads)}) ? readFileSync(${JSON.stringify(reads)}, 'utf8').length : 0;\ntest('hangs', async () => {\n  const child = spawn('/bin/sleep', ['${detached.split(' ')[1]}'], { detached: true, stdio: 'ignore' });\n  child.unref();\n  writeFileSync(${JSON.stringify(pidFile)}, String(child.pid));\n  spawn('/bin/sleep', ['${group.split(' ')[1]}'], { stdio: 'pipe' });\n  const from = reads();\n  while (reads() < from + 2) await new Promise(resolve => setTimeout(resolve, 20));\n  writeFileSync(${JSON.stringify(flag)}, '');\n  ${LEAK}\n});\n`);
  t.after(async () => { try { process.kill(Number(await readFile(pidFile, 'utf8')), 'SIGKILL'); } catch {} });
  const result = await run(dir, ['hangs.test.mjs'], 4, { bin: join(dir, 'bin'), env: faulty(dir, 'stale', { RUNNER_FAULT_FLAG: flag }) });
  assert.equal(result.hung, false, 'the runner itself hung');
  assert.equal(result.code, 124, result.out);
  assert.match(result.out, /fault: spawning ps threw ENOMEM/);
  assert.match(result.out, /Test files still running: .+ \(as of a process table read \d+ s ago\)\./);
  // The group is always signalled; the detached child, known only from the stale table, is not (the documented limit).
  assert.deepEqual(running(group), [], 'the run\'s process group is stopped');
  assert.equal(running(detached).length, 1, 'a process known only from a minute-old table is not signalled');
});
