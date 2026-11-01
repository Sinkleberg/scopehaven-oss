// Report-only mode for the regression gate (report-only.mjs, gate.mjs). node:test, owned synthetic fixture only:
// no env credentials, provider calls, network or existing data. Private temp directories, removed after each test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmod, cp, mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAssessment, compareRuns } from '../../src/runner.mjs';
import { renderReport, comparisonDocument, renderComparisonReport } from '../../src/report.mjs';
import { serializeSarif } from '../../src/sarif.mjs';
import { parseArgs, runGate, summarizeGate } from './gate.mjs';
import { MAX_WINDOW_DAYS, RESULT_MARK, applyReportOnly, checkWindow, runsUsed, stampHtml, stampSarif, validDate, windowState } from './report-only.mjs';

const vulnerable = await runAssessment('demo-vulnerable'), repaired = await runAssessment('demo-repaired');
const NOW = new Date('2026-10-24T12:00:00Z');
const day = (offset, from = NOW) => new Date(Date.parse(`${from.toISOString().slice(0, 10)}T00:00:00Z`) + offset * 86400000).toISOString().slice(0, 10);
const applied = { state: 'applied', until: day(30), runs: null };
const codeOf = fn => { try { fn(); } catch (error) { return error.code; } return null; };
async function directory(t) {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-report-only-'));
  await chmod(dir, 0o700);
  t.after(() => rm(dir, { recursive: true, force: true })); return dir;
}
const verdictOf = ({ reportOnly, ...summary }) => ({ ...summary, current: { ...summary.current, runId: null } });

test('the window needs a bound, a real date or a run count in range, and at most 90 days ahead', () => {
  assert.equal(codeOf(() => checkWindow({}, NOW)), 'report-only-window-required');
  for (const until of ['2026-02-30', '2026-13-01', '26-11-01', '2026-11-1', '', 20261101]) assert.equal(codeOf(() => checkWindow({ until }, NOW)), 'report-only-window-invalid', String(until));
  for (const runs of [0, 101, 1.5, -1, '3']) assert.equal(codeOf(() => checkWindow({ runs }, NOW)), 'report-only-window-invalid', String(runs));
  assert.equal(codeOf(() => checkWindow({ until: day(MAX_WINDOW_DAYS + 1) }, NOW)), 'report-only-window-too-long');
  assert.deepEqual(checkWindow({ until: day(MAX_WINDOW_DAYS) }, NOW), { until: day(MAX_WINDOW_DAYS), runs: null });
  // A date already passed is a window that has ended, not an error.
  assert.deepEqual(checkWindow({ until: '2026-01-01', runs: 100 }, NOW), { until: '2026-01-01', runs: 100 });
  assert.equal(validDate('2028-02-29'), true); assert.equal(validDate('2027-02-29'), false);
});

test('the window applies through its last UTC day and its last run, and ends on whichever comes first', () => {
  assert.deepEqual(windowState({ until: day(0), runs: null }, { now: new Date(`${day(0)}T23:59:59Z`) }), { state: 'applied', until: day(0), runs: null });
  assert.deepEqual(windowState({ until: day(0), runs: null }, { now: new Date(`${day(1)}T00:00:00Z`) }), { state: 'ended', endedBy: 'date-passed', until: day(0), runs: null });
  assert.deepEqual(windowState({ until: null, runs: 2 }, { used: 1, now: NOW }), { state: 'applied', until: null, runs: 2, run: 2 });
  assert.deepEqual(windowState({ until: null, runs: 2 }, { used: 2, now: NOW }), { state: 'ended', endedBy: 'runs-used', until: null, runs: 2, run: 3 });
  assert.equal(windowState({ until: day(-1), runs: 5 }, { used: 0, now: NOW }).endedBy, 'date-passed');
  assert.equal(windowState({ until: day(5), runs: 1 }, { used: 1, now: NOW }).endedBy, 'runs-used');
});

test('report-only relaxes only an assessment-failed exit, and never the verdict it records', () => {
  const failed = summarizeGate({ candidate: vulnerable }), clean = summarizeGate({ candidate: repaired });
  const error = { schemaVersion: 1, outcome: 'config-or-runtime-error', exitCode: 2, reasons: ['runner-error'], current: null, comparison: null };
  const ended = windowState({ until: day(-1), runs: null }, { now: NOW });
  const relaxed = applyReportOnly(failed, applied);
  assert.equal(relaxed.reportOnly.exitCode, 0);
  assert.deepEqual(Object.keys(relaxed).slice(0, 2), ['schemaVersion', 'reportOnly'], 'the window is the first thing a reader sees');
  assert.deepEqual(verdictOf(relaxed), verdictOf(failed));
  assert.equal(relaxed.outcome, 'assessment-failed'); assert.equal(relaxed.exitCode, 1); assert.deepEqual(relaxed.reasons, ['checks-failed']);
  assert.match(relaxed.reportOnly.note, /not a pass/);
  assert.equal(applyReportOnly(error, applied).reportOnly.exitCode, 2, 'an error is never relaxed');
  assert.equal(applyReportOnly(clean, applied).reportOnly.exitCode, 0);
  assert.equal(applyReportOnly(failed, ended).reportOnly.exitCode, 1, 'after the window the normal exit applies');
  assert.equal(applyReportOnly(failed, ended).reportOnly.note, 'Report-only window ended (date-passed): the normal exit codes apply.');
});

test('used runs are counted from saved summaries, and an unreadable one counts as used', async t => {
  const dir = await directory(t), summaries = join(dir, 'gate-summaries');
  await mkdir(summaries, { mode: 0o700 });
  const write = (name, value) => writeFile(join(summaries, name), typeof value === 'string' ? value : JSON.stringify(value), { mode: 0o600 });
  assert.equal(await runsUsed(summaries), 0);
  await write('a.json', applyReportOnly(summarizeGate({ candidate: vulnerable }), applied));
  await write('b.json', summarizeGate({ candidate: vulnerable }));
  await write('c.json', applyReportOnly(summarizeGate({ candidate: vulnerable }), windowState({ until: null, runs: 1 }, { used: 1 })));
  await write('a.report-only.html', 'not json');
  assert.equal(await runsUsed(summaries), 1, 'applied counts; a summary without the mode and an ended one do not; non-summaries are skipped');
  await write('d.json', '{ damaged');
  await write('e.json', { schemaVersion: 1, reportOnly: 'edited' });
  await write('f.json', '[]');
  await symlink(join(summaries, 'b.json'), join(summaries, 'g.json'));
  assert.equal(await runsUsed(summaries), 5, 'damaged, edited, non-object and symlinked summaries count as used');
});

test('the HTML report is marked on its title, cover, every check and the limits, and an unrecognized page is refused', () => {
  const html = renderReport(vulnerable), marked = stampHtml(html, applied);
  assert.match(marked, /<title>REPORT-ONLY · Scopehaven assessment /);
  assert.match(marked, new RegExp(`</style><div class="report-only" role="note">REPORT-ONLY RUN\\. Report-only run \\(through ${applied.until} UTC\\): the gate exits 0 on a failed assessment, so a zero exit is not a pass\\.`));
  const articles = html.split('<article>').length - 1;
  assert.equal(articles, vulnerable.results.length);
  assert.equal(marked.split('<article><p class="report-only-tag">REPORT-ONLY run: not a pass.</p>').length - 1, articles);
  assert.ok(marked.includes('<section class="limits"><p class="report-only-tag">'));
  assert.ok(marked.includes('@page{@top-center{content:"Scopehaven REPORT-ONLY run: not a pass"}}'));
  // Nothing else changes: removing the marks gives the report back.
  const unmarked = marked.replace('REPORT-ONLY · ', '').replace(/\.report-only\{[^}]*\}\.report-only-tag\{[^}]*\}@page\{@top-center\{[^}]*\}\}<\/style><div class="report-only" role="note">[^<]*<\/div>/, '</style>').replaceAll('<p class="report-only-tag">REPORT-ONLY run: not a pass.</p>', '');
  assert.equal(unmarked, html);
  const comparison = stampHtml(renderComparisonReport(comparisonDocument(vulnerable, repaired, compareRuns(vulnerable, repaired))), applied);
  assert.match(comparison, /<title>REPORT-ONLY · Scopehaven comparison /);
  assert.match(comparison, /<div class="report-only" role="note">REPORT-ONLY RUN\./);
  for (const page of ['<html><body>no anchors</body></html>', `${html}${html}`, '<title>x</title><style></style></style>']) assert.equal(codeOf(() => stampHtml(page, applied)), 'report-only-stamp-failed');
  // A run report whose checks or limits section the mark cannot find is refused, not marked on its cover alone.
  assert.equal(codeOf(() => stampHtml(html.replace('<section class="limits">', '<section class="limitations">'), applied)), 'report-only-stamp-failed');
  assert.equal(codeOf(() => stampHtml(html.replaceAll('<article>', '<article class="check">'), applied)), 'report-only-stamp-failed');
  assert.equal(codeOf(() => stampHtml(html, windowState({ until: day(-1), runs: null }, { now: NOW }))), 'report-only-not-applied');
});

test('every SARIF result message is marked; levels, kinds and fingerprints are as recorded', () => {
  const sarif = serializeSarif(vulnerable), before = JSON.parse(sarif), after = JSON.parse(stampSarif(sarif, applied));
  assert.equal(after.runs[0].results.length, vulnerable.results.length);
  after.runs[0].results.forEach((result, index) => {
    const original = before.runs[0].results[index];
    assert.equal(result.message.text, `${RESULT_MARK}${original.message.text}`);
    assert.deepEqual({ ...result, message: original.message }, original);
  });
  assert.deepEqual(after.runs[0].properties.reportOnly, { mode: 'report-only', ...applied, note: after.runs[0].properties.reportOnly.note });
  assert.deepEqual({ ...after.runs[0].properties, reportOnly: undefined }, { ...before.runs[0].properties, reportOnly: undefined });
  assert.match(after.runs[0].invocations[0].toolExecutionNotifications[0].message.text, /^REPORT-ONLY RUN\. Report-only run/);
  assert.equal(after.runs[0].invocations[0].executionSuccessful, before.runs[0].invocations[0].executionSuccessful);
  for (const text of ['not json', '{}', '{"runs":[]}', '{"runs":[{"results":[]}]}']) assert.equal(codeOf(() => stampSarif(text, applied)), 'report-only-stamp-failed');
  assert.equal(codeOf(() => stampSarif(sarif, { ...applied, state: 'ended' })), 'report-only-not-applied');
});

test('the CLI options: a switch, a bounded window, and no window without the switch', () => {
  const base = ['--target', 'demo-vulnerable', '--out', '/tmp/x'];
  assert.deepEqual(parseArgs([...base, '--report-only', '--report-only-runs', '5']), { targetId: 'demo-vulnerable', outputDirectory: '/tmp/x', reportOnly: true, reportOnlyRuns: 5 });
  assert.deepEqual(parseArgs([...base, '--report-only-until', '2026-11-30', '--report-only']), { targetId: 'demo-vulnerable', outputDirectory: '/tmp/x', reportOnlyUntil: '2026-11-30', reportOnly: true });
  for (const extra of [['--report-only'], ['--report-only-until', '2026-11-30'], ['--report-only-runs', '2'], ['--report-only', '--report-only', '--report-only-runs', '2'],
    ['--report-only', '--report-only-runs', '0'], ['--report-only', '--report-only-runs', '1000'], ['--report-only', '--report-only-runs', '2.5'], ['--report-only', '--report-only-runs', '02'],
    ['--report-only', '--report-only-until', '2026-2-30'], ['--report-only', '--report-only-until', 'tomorrow']])
    assert.equal(codeOf(() => parseArgs([...base, ...extra])), 'invalid-options', extra.join(' '));
  // The option parser checks shape; the calendar date and the run cap are checkWindow's (runGate, before anything is read).
  assert.equal(parseArgs([...base, '--report-only', '--report-only-until', '2026-02-30']).reportOnlyUntil, '2026-02-30');
  assert.equal(parseArgs([...base, '--report-only', '--report-only-runs', '101']).reportOnlyRuns, 101);
  // The --require-model-identity switch keeps its own rules beside it.
  assert.equal(parseArgs([...base, '--baseline', 'b1', '--require-model-identity', '--report-only', '--report-only-runs', '1']).requireModelIdentity, true);
});

test('runGate: the window relaxes the exit for its runs, writes marked files, then the normal exit applies', async t => {
  const dir = await directory(t), out = join(dir, 'gate'), options = { targetId: 'demo-vulnerable', outputDirectory: out, reportOnly: true, reportOnlyRuns: 2, reportOnlyUntil: day(30) };
  const normal = summarizeGate({ candidate: vulnerable });
  const first = await runGate(options, { now: NOW });
  assert.deepEqual(first.reportOnly, { mode: 'report-only', state: 'applied', until: day(30), runs: 2, run: 1, exitCode: 0, note: first.reportOnly.note });
  assert.deepEqual(verdictOf(first), verdictOf(normal), 'the recorded verdict is the one without report-only');
  const summaries = join(out, 'gate-summaries'), id = first.current.runId;
  assert.deepEqual((await readdir(summaries)).sort(), [`${id}.json`, `${id}.report-only.html`, `${id}.report-only.sarif`]);
  assert.deepEqual(JSON.parse(await readFile(join(summaries, `${id}.json`), 'utf8')), first);
  assert.match(await readFile(join(summaries, `${id}.report-only.html`), 'utf8'), /<title>REPORT-ONLY · Scopehaven assessment /);
  const sarif = JSON.parse(await readFile(join(summaries, `${id}.report-only.sarif`), 'utf8'));
  assert.ok(sarif.runs[0].results.every(result => result.message.text.startsWith(RESULT_MARK)));
  assert.equal(sarif.runs[0].properties.runId, id);
  // The stored run is the run: no report-only mark in it.
  assert.doesNotMatch(await readFile(join(out, 'runs', `${id}.json`), 'utf8'), /report-only|REPORT-ONLY/i);
  // A damaged summary counts as a used run, so the second run is the last one in the window.
  await writeFile(join(summaries, 'damaged.json'), '{', { mode: 0o600 });
  const third = await runGate(options, { now: NOW });
  assert.deepEqual(third.reportOnly, { mode: 'report-only', state: 'ended', endedBy: 'runs-used', until: day(30), runs: 2, run: 3, exitCode: 1, note: 'Report-only window ended (runs-used): the normal exit codes apply.' });
  assert.ok(!(await readdir(summaries)).some(name => name.startsWith(third.current.runId) && name.includes('report-only')), 'an ended window writes no marked files');
  // The date passes in another directory: the normal exit applies there too, and a clean run is clean either way.
  const late = await runGate({ ...options, outputDirectory: join(dir, 'late'), reportOnlyRuns: undefined }, { now: new Date(`${day(31)}T00:00:00Z`) });
  assert.equal(late.reportOnly.state, 'ended'); assert.equal(late.reportOnly.endedBy, 'date-passed'); assert.equal(late.reportOnly.exitCode, 1);
  const clean = await runGate({ ...options, targetId: 'demo-repaired', outputDirectory: join(dir, 'clean') }, { now: NOW });
  assert.equal(clean.outcome, 'clean'); assert.equal(clean.reportOnly.exitCode, 0); assert.equal(clean.reportOnly.state, 'applied');
});

// Copies of gate.mjs without report-only.mjs (test/install-state-boundary and test/security-review) show it loads without
// the file; the copied-tree test below shows --report-only is then refused, not ignored.
test('the gate imports report-only.mjs only for --report-only, never statically', async () => {
  const source = await readFile(fileURLToPath(new URL('./gate.mjs', import.meta.url)), 'utf8');
  assert.doesNotMatch(source, /^import [^;]*report-only\.mjs/m, 'no static import of report-only.mjs');
  assert.match(source, /await import\('\.\/report-only\.mjs'\)/);
});

test('without report-only.mjs, --report-only is refused (exit 2, report-only-unavailable) and writes nothing', async t => {
  const dir = await directory(t), app = join(dir, 'app');
  await cp(new URL('../../src/', import.meta.url), join(app, 'src'), { recursive: true });
  await cp(new URL('../', import.meta.url), join(app, 'integrations'), { recursive: true });
  await cp(new URL('../../package.json', import.meta.url), join(app, 'package.json'));
  await rm(join(app, 'integrations/regression-gate/report-only.mjs'));
  const gate = args => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(app, 'integrations/regression-gate/cli.mjs'), ...args], { env: {}, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = ''; child.stdout.on('data', bytes => { stdout += bytes; });
    child.once('error', reject); child.once('close', code => resolve({ code, summary: JSON.parse(stdout) }));
  });
  const refused = await gate(['--target', 'demo-vulnerable', '--out', join(dir, 'gate'), '--report-only', '--report-only-runs', '1']);
  assert.equal(refused.code, 2);
  assert.deepEqual(refused.summary, { schemaVersion: 1, outcome: 'config-or-runtime-error', exitCode: 2, reasons: ['report-only-unavailable'], current: null, comparison: null });
  assert.deepEqual(await readdir(dir), ['app'], 'no output directory, summary or marked file');
  // The same copy gates as usual without the switch, so the refusal is the missing module's, not a broken copy's.
  const plain = await gate(['--target', 'demo-vulnerable', '--out', join(dir, 'plain')]);
  assert.deepEqual([plain.code, plain.summary.outcome, plain.summary.reasons, Object.hasOwn(plain.summary, 'reportOnly')], [1, 'assessment-failed', ['checks-failed'], false]);
});

test('runGate: a window too far ahead is refused before the output directory is touched; errors are never relaxed', async t => {
  const dir = await directory(t), out = join(dir, 'gate');
  const far = await runGate({ targetId: 'demo-vulnerable', outputDirectory: out, reportOnly: true, reportOnlyUntil: day(MAX_WINDOW_DAYS + 1) }, { now: NOW });
  assert.deepEqual(far, { schemaVersion: 1, outcome: 'config-or-runtime-error', exitCode: 2, reasons: ['report-only-window-too-long'], current: null, comparison: null });
  await assert.rejects(readdir(out), { code: 'ENOENT' });
  for (const [window, code] of [[{ reportOnlyUntil: '2026-02-30' }, 'report-only-window-invalid'], [{ reportOnlyRuns: 101 }, 'report-only-window-invalid']]) {
    const refused = await runGate({ targetId: 'demo-vulnerable', outputDirectory: out, reportOnly: true, ...window }, { now: NOW });
    assert.deepEqual([refused.exitCode, refused.reasons], [2, [code]], JSON.stringify(window));
    await assert.rejects(readdir(out), { code: 'ENOENT' });
  }
  const unknown = await runGate({ targetId: 'not-a-target', outputDirectory: out, reportOnly: true, reportOnlyRuns: 3 }, { now: NOW });
  assert.equal(unknown.exitCode, 2); assert.equal(unknown.reportOnly, undefined);
});

test('the CLI exits 0 under report-only while its printed summary keeps exit 1, and exits 1 once the window ends', async t => {
  const dir = await directory(t), out = join(dir, 'gate');
  const cli = async args => {
    const child = spawn(process.execPath, [fileURLToPath(new URL('./cli.mjs', import.meta.url)), ...args], { env: {}, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = ''; child.stdout.on('data', bytes => { stdout += bytes; });
    const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
    return { code, summary: JSON.parse(stdout) };
  };
  const args = ['--target', 'demo-vulnerable', '--out', out, '--report-only', '--report-only-runs', '1', '--report-only-until', day(30, new Date())];
  const first = await cli(args);
  assert.equal(first.code, 0); assert.equal(first.summary.exitCode, 1); assert.equal(first.summary.outcome, 'assessment-failed'); assert.equal(first.summary.reportOnly.state, 'applied');
  const second = await cli(args);
  assert.equal(second.code, 1); assert.equal(second.summary.reportOnly.endedBy, 'runs-used');
});

test('the report-only helper CLI: the window state, and a mark that waits for the gate', async t => {
  const dir = await directory(t), helper = fileURLToPath(new URL('./report-only.mjs', import.meta.url));
  const run = args => new Promise(resolve => {
    const child = spawn(process.execPath, [helper, ...args], { env: {}, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = ''; child.stdout.on('data', b => { stdout += b; }); child.stderr.on('data', b => { stderr += b; });
    child.once('close', code => resolve({ code, stdout, stderr }));
  });
  const today = new Date();
  assert.deepEqual(await run(['window', '--until', day(10, today)]), { code: 0, stdout: 'applied\n', stderr: '' });
  assert.deepEqual(await run(['window', '--until', day(-1, today)]), { code: 0, stdout: 'ended\n', stderr: '' });
  assert.deepEqual(await run(['window', '--until', day(MAX_WINDOW_DAYS + 1, today)]), { code: 2, stdout: 'report-only-window-too-long\n', stderr: '' });
  assert.deepEqual(await run(['window', '--until', 'soon']), { code: 2, stdout: 'report-only-window-invalid\n', stderr: '' });
  const report = join(dir, 'report.html'), html = renderReport(vulnerable);
  await writeFile(report, html, { mode: 0o600 });
  const gate = join(dir, 'gate-summary.json');
  await writeFile(gate, JSON.stringify(applyReportOnly(summarizeGate({ candidate: vulnerable }), windowState({ until: day(-1), runs: null }, { now: NOW }))));
  assert.equal((await run(['stamp', '--until', day(10, today), '--file', report, '--gate', gate])).code, 3, 'the gate ended its window: not marked');
  assert.equal(await readFile(report, 'utf8'), html);
  await writeFile(gate, JSON.stringify(applyReportOnly(summarizeGate({ candidate: vulnerable }), applied)));
  assert.deepEqual(await run(['stamp', '--until', day(10, today), '--file', report, '--gate', gate]), { code: 0, stdout: 'marked\n', stderr: '' });
  assert.match(await readFile(report, 'utf8'), /^<!doctype html><html lang="en">.*<title>REPORT-ONLY · /s);
  const broken = join(dir, 'broken.sarif');
  await writeFile(broken, 'not sarif');
  assert.deepEqual(await run(['stamp', '--until', day(10, today), '--file', broken]), { code: 2, stdout: 'report-only-stamp-failed\n', stderr: '' });
  assert.equal(await readFile(broken, 'utf8'), 'not sarif');
  assert.deepEqual((await readdir(dir)).sort(), ['broken.sarif', 'gate-summary.json', 'report.html'], 'no temporary file is left behind');
});
