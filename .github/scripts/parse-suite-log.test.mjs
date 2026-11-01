import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, symlinkSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { parseSuiteLog, localRetryFiles } from './parse-suite-log.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const fixtures = join(here, 'suite-retry-fixtures');
const capture = name => readFileSync(join(fixtures, name), 'utf8').replaceAll('@ROOT@', root);
const pass = capture('pass.tap');
const fail = capture('failure with spaces.tap');

for (const [name, status, outcome] of [
  ['pass.tap', 0, 'pass'], ['failure with spaces.tap', 1, 'retry'],
  ['mixed.tap', 1, 'retry'], ['console.tap', 0, 'pass'],
  ['aborted.tap', 1, 'retry'], ['zero.tap', 0, 'invalid'],
]) {
  test(`pinned Node 24 capture: ${name}`, () => {
    const result = parseSuiteLog(capture(name), status);
    assert.equal(result.outcome, outcome, result.reason);
    if (outcome === 'retry') {
      assert.equal(result.files.length, 1);
      assert.equal(localRetryFiles(result.files, root).length, 1);
    }
  });
}

test('nested test/suite and TODO failures deduplicate to their file', () => {
  const result = parseSuiteLog(capture('mixed.tap'), 1);
  assert.deepEqual(result.summary && {
    tests: result.summary.tests, suites: result.summary.suites,
    pass: result.summary.pass, fail: result.summary.fail,
    skipped: result.summary.skipped, todo: result.summary.todo,
  }, { tests: 8, suites: 2, pass: 2, fail: 4, skipped: 1, todo: 1 });
  assert.deepEqual(result.files, [join(fixtures, 'mixed.mjs')]);
});

for (const [name, text, status = 0] of [
  ['empty output', ''],
  ['arbitrary matching text', '# tests 99\n'],
  ['spec reporter unsupported', 'ℹ tests 1\nℹ fail 0\n'],
  ['missing header', pass.replace('TAP version 13\n', '')],
  ['duplicate header', `TAP version 13\n${pass}`],
  ['missing duration summary', pass.replace(/# duration_ms .*\n/, '')],
  ['missing final newline', pass.trimEnd()],
  ['truncated diagnostics', pass.replace('  ...\n', '')],
  ['missing diagnostics', pass.replace(/  ---\n[\s\S]*?  \.\.\.\n/, '')],
  ['missing diagnostic type', pass.replace("  type: 'test'\n", '')],
  ['duplicate diagnostic type', pass.replace("  type: 'test'\n", "  type: 'test'\n  type: 'suite'\n")],
  ['unsupported scalar', pass.replace("type: 'test'", 'type: test')],
  ['missing root plan', pass.replace('1..1\n', '')],
  ['wrong root plan count', pass.replace('1..1\n', '1..2\n')],
  ['wrong result number', pass.replace('ok 1 - ', 'ok 2 - ')],
  ['missing subtest start', pass.replace('# Subtest: clean\n', '')],
  ['result name contradiction', pass.replace('ok 1 - clean', 'ok 1 - different')],
  ['orphan nested results', pass.replace(/^(# Subtest:.*|ok .*|  .*)$/gm, '    $1').replace('1..1\n', '    1..1\n1..0\n')],
  ['passing failureType', pass.replace("  type: 'test'\n", "  type: 'test'\n  failureType: 'testCodeFailure'\n")],
  ['passing failure location', pass.replace("  type: 'test'\n", "  type: 'test'\n  location: 'test/a.mjs:1:1'\n")],
  ['duplicate root plan', pass.replace('1..1\n', '1..1\n1..1\n')],
  ['duplicate summary block', pass + pass.slice(pass.indexOf('# tests '))],
  ['summary embedded earlier', pass.replace('# Subtest:', '# tests 99\n# Subtest:')],
  ['contradictory tests count', pass.replace('# tests 1', '# tests 2')],
  ['contradictory fail count', pass.replace('# fail 0', '# fail 1')],
  ['contradictory suites count', pass.replace('# suites 0', '# suites 1')],
  ['negative summary value', pass.replace('# pass 1', '# pass -1')],
  ['unsafe integer', pass.replace('# tests 1', '# tests 9007199254740993')],
  ['duration NaN', pass.replace(/# duration_ms .*/, '# duration_ms NaN')],
  ['diagnostic duration overflow', pass.replace(/  duration_ms: .*/, `  duration_ms: ${'9'.repeat(400)}`)],
  ['summary followed by text', pass + '# extra output\n'],
  ['carriage return', pass.replace('TAP version 13', 'TAP version 13\r')],
  ['NUL', pass.replace('TAP version 13', 'TAP version 13\0')],
  ['failure with zero exit', fail, 0],
  ['success with nonzero exit', pass, 1],
  ['terminated without summary', 'TAP version 13\n# Subtest: unfinished\n', 143],
]) {
  test(`fail closed: ${name}`, () => assert.equal(parseSuiteLog(text, status).outcome, 'invalid'));
}

for (const status of [-1, 256, 1.5, NaN, '0']) {
  test(`invalid status ${String(status)}`, () => assert.equal(parseSuiteLog(pass, status).outcome, 'invalid'));
}
test('abnormal process status cannot trigger retry despite complete failure output', () => {
  assert.equal(parseSuiteLog(fail, 143).outcome, 'fail');
  assert.equal(parseSuiteLog(fail, 7).outcome, 'fail');
});
test('cancelled count stays red and cannot retry', () => {
  const log = fail.replace('# fail 1', '# fail 0').replace('# cancelled 0', '# cancelled 1');
  assert.equal(parseSuiteLog(log, 1).outcome, 'fail');
});
test('an unidentified failure prevents partial retry', () => {
  const log = capture('mixed.tap').replace(/^ +location: .*\n/m, '');
  assert.equal(parseSuiteLog(log, 1).outcome, 'fail');
});
test('locations require complete line and column', () => {
  const log = fail.replace(/:3:1'/, ":3'");
  assert.equal(parseSuiteLog(log, 1).outcome, 'fail');
});
test('eight distinct files retry; nine stay red', () => {
  const resultBlock = fail.slice(fail.indexOf('# Subtest:'), fail.indexOf('1..1\n'));
  for (const total of [8, 9]) {
    let body = 'TAP version 13\n';
    for (let i = 1; i <= total; i++) body += resultBlock.replace('not ok 1 -', `not ok ${i} -`).replaceAll('failure with spaces.mjs', `file-${i}.mjs`);
    body += `1..${total}\n# tests ${total}\n# suites 0\n# pass 0\n# fail ${total}\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 1\n`;
    assert.equal(parseSuiteLog(body, 1).outcome, total === 8 ? 'retry' : 'fail');
  }
});
test('pure TODO/skip completion keeps semantics', () => {
  const log = "TAP version 13\n# Subtest: expected\nnot ok 1 - expected # TODO\n  ---\n  duration_ms: 1\n  type: 'test'\n  failureType: 'testCodeFailure'\n  error: 'expected TODO'\n  ...\n# Subtest: skip\nok 2 - skip # SKIP\n  ---\n  duration_ms: 1\n  type: 'test'\n  ...\n1..2\n# tests 2\n# suites 0\n# pass 0\n# fail 0\n# cancelled 0\n# skipped 1\n# todo 1\n# duration_ms 1\n";
  assert.equal(parseSuiteLog(log, 0).outcome, 'pass');
  assert.equal(parseSuiteLog(log.replace("  error: 'expected TODO'\n", ''), 0).outcome, 'invalid');
});
test('file resolution accepts spaces, rejects absent/outside/symlink/directory paths', () => {
  const scratch = realpathSync(mkdtempSync(join(tmpdir(), 'suite-file-paths-')));
  try {
    const cwd = join(scratch, 'suite'); mkdirSync(cwd);
    const local = join(cwd, 'test with spaces.mjs'); writeFileSync(local, '');
    const external = join(scratch, 'outside.mjs'); writeFileSync(external, '');
    symlinkSync(external, join(cwd, 'link.mjs'));
    assert.deepEqual(localRetryFiles(['test with spaces.mjs', local], cwd), [local]);
    for (const file of ['missing.mjs', external, 'link.mjs', '.', '..']) assert.throws(() => localRetryFiles([file], cwd));
    const newline = join(cwd, 'bad\npath.mjs'); writeFileSync(newline, '');
    assert.throws(() => localRetryFiles([newline], cwd));
  } finally { rmSync(scratch, { recursive: true, force: true }); }
});
test('CLI executes through macOS logical/canonical tempdir aliases', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'suite-parser-cli-'));
  try {
    const log = join(scratch, 'run.log'); writeFileSync(log, pass);
    const cli = join(scratch, 'parse-suite-log.mjs'); symlinkSync(join(here, 'parse-suite-log.mjs'), cli);
    const good = spawnSync(process.execPath, [cli, log, '0'], { encoding: 'utf8', timeout: 5000 });
    assert.equal(good.status, 0, good.stderr);
    writeFileSync(log, 'TAP version 13\n');
    const bad = spawnSync(process.execPath, [cli, log, '0'], { encoding: 'utf8', timeout: 5000 });
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /No rerun:/);
  } finally { rmSync(scratch, { recursive: true, force: true }); }
});
