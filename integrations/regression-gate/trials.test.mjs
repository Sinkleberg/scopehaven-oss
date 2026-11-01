// Repeated trials for the regression gate (trials.mjs, gate.mjs --trials). node:test, one owned loopback HTTP server
// per test on 127.0.0.1 port 0 and the owned synthetic fixture: no env credentials, provider calls or existing data.
// Private temp directories, removed after each test. Defective and fixed twins: a boundary that leaks on one trial
// only, and the same boundary holding on every trial.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { chmod, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs, runGate } from './gate.mjs';
import { FLAKY_REASON, TRIALS_SCHEMA, checkTrials, parseFloor, readingOf } from './trials.mjs';
import { createStore } from '../../src/store.mjs';
import { writeTestAuthorization } from '../../test/support/authorization.mjs';
import { installClock, realNow } from '../../test/support/window-clock.mjs';

const codeOf = fn => { try { fn(); } catch (error) { return error.code; } return null; };
async function directory(t) {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-trials-'));
  await chmod(dir, 0o700);
  t.after(() => rm(dir, { recursive: true, force: true })); return dir;
}
// leaksOn: the 1-based trial numbers on which the boundary answers 200 (a leak), or a function of the trial number, the
// request and the response that answers itself ('done') or returns the status. Each trial sends one request per check.
async function target(t, leaksOn = [], { edit } = {}) {
  const state = { boundaryCalls: 0, calls: 0 };
  const server = createServer(async (req, res) => {
    state.calls++;
    const n = req.url === '/check' ? ++state.boundaryCalls : 0;
    const answer = typeof leaksOn === 'function' && n ? await leaksOn(n, req, res) : null;
    if (answer === 'done') return;
    const leak = n && (typeof leaksOn === 'function' ? answer === 200 : leaksOn.includes(n));
    res.writeHead(req.url === '/control' || leak ? 200 : 403, { 'Content-Type': 'application/json' }); res.end('{"body":"RESPONSE_NOT_FOR_SUMMARY"}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const root = await directory(t), configFile = join(root, 'targets.json');
  const profile = { id: 'owned-trials', name: 'Local trials test', applicationId: 'owned-trials', origin: `http://127.0.0.1:${server.address().port}`, buildLabel: 'build-1', contextId: 'isolated-test',
    actors: { member: { principalId: 'member' } }, requiredControlIds: ['allowed'], checks: [
      { id: 'boundary', title: 'Response boundary', category: 'Response', severity: 'high', actorId: 'member', method: 'GET', path: '/check', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] },
      { id: 'allowed', title: 'Allowed use', category: 'Control', severity: 'control', actorId: 'member', method: 'GET', path: '/control', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    ] };
  const writeConfig = () => writeFile(configFile, JSON.stringify({ schemaVersion: 1, targets: [profile] }), { mode: 0o600 });
  await writeConfig();
  const authorizationFile = writeTestAuthorization(join(root, 'authorization.json'), { ...profile, actors: { member: { principalId: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_TEST_ONLY' } } }, edit ? { edit } : undefined);
  return { state, root, profile, writeConfig, options: { targetId: profile.id, configFile, authorizationFile } };
}
const filesOf = async out => (await readdir(join(out, 'gate-summaries'))).sort();
const checkOf = (summary, id) => summary.trials.checks.find(check => check.id === id);

test('the floor is 1 or a reduced fraction below 1, and trials, k and floor are checked before anything runs', () => {
  for (const floor of ['1', '9/10', '1/2', '999999/1000000']) assert.equal(parseFloor(floor), floor);
  for (const floor of ['0', '2/2', '3/2', '2/4', '0/5', '1/0', '1.0', '0.9', '', '1/1000001', ' 1/2', 1, null]) assert.equal(codeOf(() => parseFloor(floor)), 'trials-floor-invalid', String(floor));
  assert.deepEqual(checkTrials({ trials: 3 }), { trials: 3, k: 1, floor: '1' });
  assert.deepEqual(checkTrials({ trials: 100, k: 100, floor: '9/10' }), { trials: 100, k: 100, floor: '9/10' });
  for (const trials of [1, 0, 101, 2.5, -1, '3', undefined]) assert.equal(codeOf(() => checkTrials({ trials })), 'trials-invalid', String(trials));
  for (const k of [0, 4, 1.5, -1]) assert.equal(codeOf(() => checkTrials({ trials: 3, k })), 'trials-k-invalid', String(k));
});

test('a check reads PASS only when every trial passed; below the floor it reads FAIL-flaky; a floor below 1 never makes it PASS', () => {
  const row = (passed, failed, undecided, exact) => ({ trials: passed + failed + undecided, passed, failed, undecided, exact });
  assert.deepEqual(readingOf(row(3, 0, 0, '1'), '1'), { floorMet: true, reading: 'PASS' });
  assert.deepEqual(readingOf(row(2, 1, 0, '2/3'), '1'), { floorMet: false, reading: 'FAIL-flaky' });
  assert.deepEqual(readingOf(row(2, 0, 1, '2/3'), '1'), { floorMet: false, reading: 'FAIL-flaky' }, 'an undecided trial is not a pass');
  assert.deepEqual(readingOf(row(3, 1, 0, '3/4'), '1/2'), { floorMet: true, reading: 'FAIL' }, 'at or above a floor below 1: the failed trial is reported, never PASS');
  assert.deepEqual(readingOf(row(3, 0, 1, '3/4'), '1/2'), { floorMet: true, reading: 'NOT-PASSED' });
  assert.deepEqual(readingOf(row(1, 1, 0, '1/2'), '1/2'), { floorMet: true, reading: 'FAIL' }, 'a value equal to the floor meets it');
  assert.deepEqual(readingOf(row(1, 2, 0, '1/3'), '1/2'), { floorMet: false, reading: 'FAIL-flaky' });
  assert.deepEqual(readingOf(row(0, 3, 0, '0'), '1'), { floorMet: false, reading: 'FAIL' }, 'no trial passed: a consistent failure, not flaky');
  assert.deepEqual(readingOf(row(0, 0, 3, '0'), '1'), { floorMet: false, reading: 'NOT-PASSED' });
});

test('the option parser takes --trials, --pass-k and --pass-k-floor, and the last two only beside --trials', () => {
  const base = ['--target', 'demo-vulnerable', '--out', '/tmp/scopehaven-trials-parse'];
  assert.deepEqual(parseArgs([...base, '--trials', '5', '--pass-k', '2', '--pass-k-floor', '9/10']), { targetId: 'demo-vulnerable', outputDirectory: '/tmp/scopehaven-trials-parse', trials: 5, passK: 2, passKFloor: '9/10' });
  for (const extra of [['--pass-k', '2'], ['--pass-k-floor', '1'], ['--trials', '0'], ['--trials', '3x'], ['--trials', '1000'], ['--trials', '3', '--pass-k', '0'], ['--trials', '3', '--pass-k-floor', '0.9'], ['--trials', '3', '--trials', '4']])
    assert.equal(codeOf(() => parseArgs([...base, ...extra])), 'invalid-options', extra.join(' '));
  assert.equal(codeOf(() => parseArgs(['--target', 'refund', '--saved-refund', '/a/r.json', '--refund-public-key', '/a/k.pem', '--refund-key-fingerprint', 'a'.repeat(64), '--expected-run', 'r1', '--trials', '3'])), 'invalid-options');
});

test('defective twin: a boundary that leaks on one trial passes a single run but reads FAIL-flaky over three trials', async t => {
  // One run: the first trial holds, so the single-run gate is clean. This is what --trials is for.
  const single = await target(t, [2]);
  const once = await runGate({ ...single.options, outputDirectory: join(single.root, 'out') });
  assert.equal(once.exitCode, 0); assert.deepEqual(once.reasons, []); assert.equal(once.trials, undefined);

  const flaky = await target(t, [2]), out = join(flaky.root, 'out');
  const summary = await runGate({ ...flaky.options, outputDirectory: out, trials: 3 });
  assert.equal(flaky.state.calls, 6, 'three trials, two checks each');
  assert.equal(summary.exitCode, 1); assert.equal(summary.outcome, 'assessment-failed');
  assert.deepEqual(summary.reasons, ['checks-failed', FLAKY_REASON], 'the leaking trial\'s own reason, then checks-flaky');
  assert.equal(summary.current.counts.pass, 2, 'the current block is the first trial\'s');
  assert.equal(summary.trials.schema, TRIALS_SCHEMA);
  assert.equal(summary.trials.trials, 3); assert.equal(summary.trials.k, 1); assert.equal(summary.trials.floor, '1');
  assert.equal(summary.trials.runIds.length, 3); assert.equal(summary.trials.runIds[0], summary.current.runId);
  assert.deepEqual(summary.trials.readings, { PASS: 1, 'FAIL-flaky': 1, FAIL: 0, 'NOT-PASSED': 0 });
  assert.deepEqual(checkOf(summary, 'boundary'), { id: 'boundary', role: 'prohibited-behaviour', trials: 3, passed: 2, failed: 1, undecided: 0, k: 1, floor: '1', exact: '2/3', passHatK: checkOf(summary, 'boundary').passHatK, unpaired: false, floorMet: false, reading: 'FAIL-flaky' });
  assert.ok(Math.abs(checkOf(summary, 'boundary').passHatK - 2 / 3) < 1e-12);
  assert.equal(checkOf(summary, 'allowed').reading, 'PASS');
  assert.deepEqual(summary.trials.perTrial.map(row => row.reasons), [[], ['checks-failed'], []]);
  assert.equal(summary.trials.passK.k, 1); assert.equal(summary.trials.passK.source, 'saved-runs'); assert.equal(summary.trials.passK.checks, undefined);
  assert(!JSON.stringify(summary).includes('RESPONSE_NOT_FOR_SUMMARY'));
  // Every trial is saved; one summary per gate invocation, with the trials' report and SARIF beside it.
  const store = createStore(out);
  assert.ok(summary.current.authorization, 'the run is stamped with its authorization record');
  for (const id of summary.trials.runIds) assert.deepEqual((await store.get(id)).authorization, summary.current.authorization, 'every trial is stamped, not only the first');
  const id = summary.current.runId;
  assert.deepEqual(await filesOf(out), [`${id}.json`, `${id}.trials.html`, `${id}.trials.sarif`]);
  assert.deepEqual(JSON.parse(await readFile(join(out, 'gate-summaries', `${id}.json`), 'utf8')), summary);
  const sarif = JSON.parse(await readFile(join(out, 'gate-summaries', `${id}.trials.sarif`), 'utf8'));
  const result = sarif.runs[0].results.find(row => row.ruleId === 'boundary');
  assert.equal(result.kind, 'fail', 'never kind pass, although the first trial passed'); assert.equal(result.level, 'error');
  assert.deepEqual(result.properties.passKGate, { k: 1, floor: '1', reading: 'FAIL-flaky', floorMet: false, unpaired: false });
  assert.equal(result.properties.passK.exact, '2/3');
  assert.match(result.message.text, /^\[Across 3 trials: FAIL-flaky \(passed 2 of 3; pass\^1 2\/3 \(0\.667\); floor 1\)\.\] First trial: PASS/);
  const control = sarif.runs[0].results.find(row => row.ruleId === 'allowed');
  assert.equal(control.kind, 'pass'); assert.equal(control.properties.passKGate.reading, 'PASS');
  assert.deepEqual(sarif.runs[0].properties.passKGate, { schema: TRIALS_SCHEMA, trials: 3, k: 1, floor: '1', runIds: summary.trials.runIds, readings: summary.trials.readings, outcome: 'assessment-failed' });
  const html = await readFile(join(out, 'gate-summaries', `${id}.trials.html`), 'utf8');
  assert.match(html, /<title>3 trials · /);
  assert.match(html, /<section class="trials"><h2>Repeated trials: pass\^k per check<\/h2>/);
  assert.match(html, /<article><h2>boundary · Response boundary<\/h2><p class="trials-tag not-pass">Across 3 trials: FAIL-flaky \(passed 2 of 3; pass\^1 2\/3 \(0\.667\); floor 1\)\.<\/p>/);
  assert.match(html, /<article><h2>allowed · Allowed use<\/h2><p class="trials-tag">Across 3 trials: PASS/);
});

test('fixed twin: the same boundary holding on every trial reads PASS and the gate is clean', async t => {
  const fixed = await target(t, []), out = join(fixed.root, 'out');
  const summary = await runGate({ ...fixed.options, outputDirectory: out, trials: 3, passK: 3 });
  assert.equal(summary.exitCode, 0); assert.deepEqual(summary.reasons, []);
  assert.deepEqual(summary.trials.readings, { PASS: 2, 'FAIL-flaky': 0, FAIL: 0, 'NOT-PASSED': 0 });
  assert.deepEqual(summary.trials.checks.map(check => [check.id, check.exact, check.k, check.reading]), [['allowed', '1', 3, 'PASS'], ['boundary', '1', 3, 'PASS']]);
  const sarif = JSON.parse(await readFile(join(out, 'gate-summaries', `${summary.current.runId}.trials.sarif`), 'utf8'));
  assert.ok(sarif.runs[0].results.every(row => row.kind === 'pass' && row.properties.passKGate.reading === 'PASS' && !row.message.text.startsWith('[')));
});

test('a floor below 1 never relaxes the verdict: a met floor reads FAIL on the failed trial and the gate still fails', async t => {
  const flaky = await target(t, [4]), out = join(flaky.root, 'out');
  const summary = await runGate({ ...flaky.options, outputDirectory: out, trials: 4, passKFloor: '1/2' });
  assert.equal(summary.exitCode, 1); assert.deepEqual(summary.reasons, ['checks-failed'], 'no checks-flaky: the floor is met, the failed trial still fails the gate');
  assert.deepEqual([checkOf(summary, 'boundary').exact, checkOf(summary, 'boundary').floorMet, checkOf(summary, 'boundary').reading], ['3/4', true, 'FAIL']);
  // The same leak under a higher k falls below the floor: pass^3 = C(3,3)/C(4,3) = 1/4.
  const strict = await target(t, [4]);
  const below = await runGate({ ...strict.options, outputDirectory: join(strict.root, 'out'), trials: 4, passK: 3, passKFloor: '1/2' });
  assert.deepEqual(below.reasons, ['checks-failed', FLAKY_REASON]); assert.deepEqual([checkOf(below, 'boundary').exact, checkOf(below, 'boundary').reading], ['1/4', 'FAIL-flaky']);
});

test('trials are refused before any request for an unsupported target or an invalid count, k or floor', async t => {
  const http = await target(t, []);
  for (const [extra, code] of [[{ trials: 1 }, 'trials-invalid'], [{ trials: 101 }, 'trials-invalid'], [{ trials: 3, passK: 4 }, 'trials-k-invalid'], [{ trials: 3, passKFloor: '2/4' }, 'trials-floor-invalid'], [{ trials: 3, passKFloor: '1/1' }, 'trials-floor-invalid']]) {
    const summary = await runGate({ ...http.options, outputDirectory: join(http.root, `out-${code}-${Object.values(extra).join('-')}`), ...extra });
    assert.equal(summary.exitCode, 2); assert.deepEqual(summary.reasons, [code], JSON.stringify(extra));
  }
  assert.equal(http.state.calls, 0, 'nothing was sent');
  // The owned synthetic demo is scripted: the same run each time, so repeating it is refused, not run once.
  const dir = await directory(t);
  const demo = await runGate({ targetId: 'demo-vulnerable', outputDirectory: join(dir, 'demo'), trials: 3 });
  assert.equal(demo.exitCode, 2); assert.deepEqual(demo.reasons, ['trials-unsupported-target']);
  assert.deepEqual(await readdir(dir), [], 'the output directory was never created');
});

test('a later trial that is undecided, not failed, makes a passing first trial kind open, never kind pass', async t => {
  const reset = await target(t, (n, req) => { if (n === 3) { req.socket.destroy(); return 'done'; } return 403; }), out = join(reset.root, 'out');
  const summary = await runGate({ ...reset.options, outputDirectory: out, trials: 3 });
  const boundary = checkOf(summary, 'boundary');
  assert.deepEqual([boundary.passed, boundary.failed, boundary.undecided, boundary.reading], [2, 0, 1, 'FAIL-flaky']);
  assert.ok(summary.exitCode >= 1); assert.ok(summary.reasons.includes(FLAKY_REASON)); assert.deepEqual(summary.trials.perTrial[0].reasons, []);
  assert.ok(summary.trials.perTrial[2].reasons.length > 0, 'the undecided trial\'s own reason counts');
  const sarif = JSON.parse(await readFile(join(out, 'gate-summaries', `${summary.current.runId}.trials.sarif`), 'utf8'));
  const result = sarif.runs[0].results.find(row => row.ruleId === 'boundary');
  assert.equal(result.kind, 'open'); assert.equal(result.level, 'none'); assert.equal(result.properties.scopehavenStatus ?? 'pass', 'pass', 'the first trial\'s recorded status is kept');
  assert.match(result.message.text, /\] First trial: PASS/);
});

test('report-only with trials marks both trial files and counts the invocation as one run', async t => {
  const flaky = await target(t, [2]), out = join(flaky.root, 'out');
  const first = await runGate({ ...flaky.options, outputDirectory: out, trials: 3, reportOnly: true, reportOnlyRuns: 2 });
  assert.equal(first.exitCode, 1); assert.equal(first.reportOnly.state, 'applied'); assert.equal(first.reportOnly.exitCode, 0); assert.equal(first.reportOnly.run, 1);
  assert.deepEqual(first.reasons, ['checks-failed', FLAKY_REASON], 'the verdict is recorded as without report-only');
  const id = first.current.runId, files = await filesOf(out);
  assert.deepEqual(files, [`${id}.json`, `${id}.report-only.html`, `${id}.report-only.sarif`, `${id}.trials.html`, `${id}.trials.sarif`]);
  assert.match(await readFile(join(out, 'gate-summaries', `${id}.trials.html`), 'utf8'), /REPORT-ONLY/);
  const sarif = JSON.parse(await readFile(join(out, 'gate-summaries', `${id}.trials.sarif`), 'utf8'));
  assert.ok(sarif.runs[0].results.every(row => row.message.text.startsWith('[REPORT-ONLY run: not a pass] ')));
  assert.equal(sarif.runs[0].results.find(row => row.ruleId === 'boundary').kind, 'fail');
  const second = await runGate({ ...flaky.options, outputDirectory: out, trials: 2, reportOnly: true, reportOnlyRuns: 2 });
  assert.equal(second.reportOnly.run, 2, 'three trials were one report-only run');
});

test('a window that ends during the trials saves nothing: no run, no summary', async t => {
  // The record is valid for a minute, so the gate is never refused at the start however slowly it starts. When the second
  // trial's boundary request arrives, the guard's clock jumps past validUntil (test/support/window-clock.mjs) and that
  // request is answered 300 ms later, inside the connector's 3 s request timeout: the window ends during the trials.
  const validUntil = realNow() + 60000, clock = installClock();
  t.after(() => clock.restore());
  const late = await target(t, n => (n === 2 ? (clock.jumpPast(validUntil), new Promise(resolve => setTimeout(() => resolve(403), 300))) : 403),
    { edit: record => { record.validUntil = new Date(validUntil).toISOString().replace(/\.\d{3}Z$/, 'Z'); } });
  const out = join(late.root, 'out');
  const summary = await runGate({ ...late.options, outputDirectory: out, trials: 3 });
  clock.restore();
  assert.equal(late.state.boundaryCalls, 2, 'the window ended at the second trial\'s boundary request, and no boundary request was sent after it');
  assert.equal(late.state.calls, 3, 'nothing at all was sent after it: the first trial\'s two requests and that one');
  assert.equal(summary.exitCode, 2); assert.deepEqual(summary.reasons, ['authorization-window-ended']);
  assert.deepEqual(await readdir(join(out, 'runs')).catch(() => []), []);
  assert.deepEqual((await readdir(join(out, 'gate-summaries')).catch(() => [])).filter(name => !name.startsWith('.')), []);
});

test('with a baseline, a repair the first trial shows is not credited while a check reads FAIL-flaky', async t => {
  const app = await target(t, n => (n === 1 || n === 3 ? 200 : 403)), out = join(app.root, 'out');
  const before = await runGate({ ...app.options, outputDirectory: out });
  assert.equal(before.exitCode, 1); assert.deepEqual(before.reasons, ['checks-failed']);
  app.profile.buildLabel = 'build-2'; await app.writeConfig();
  const after = await runGate({ ...app.options, outputDirectory: out, baselineRunId: before.current.runId, trials: 2 });
  assert.equal(after.comparison.summary.fixed, 1, 'the first trial restored the boundary');
  assert.equal(after.comparison.restorationLabel, 'No verified repair'); assert.equal(after.comparison.restorationWithheld, 'not-every-check-passed-every-trial');
  assert.equal(checkOf(after, 'boundary').reading, 'FAIL-flaky'); assert.equal(after.exitCode, 1);
  // The fixed twin over the same baseline keeps the core's label.
  const fixed = await target(t, n => (n === 1 ? 200 : 403)), fixedOut = join(fixed.root, 'out');
  const baseline = await runGate({ ...fixed.options, outputDirectory: fixedOut });
  fixed.profile.buildLabel = 'build-2'; await fixed.writeConfig();
  const repaired = await runGate({ ...fixed.options, outputDirectory: fixedOut, baselineRunId: baseline.current.runId, trials: 2 });
  assert.equal(repaired.exitCode, 0); assert.equal(repaired.comparison.restorationLabel, 'Response contracts restored'); assert.equal(repaired.comparison.restorationWithheld, undefined);
});

test('on a forwarded target, a boundary pass left unpaired in any trial never reads PASS or kind pass', async t => {
  // The owner reading note 2 is the same-route required control for the member's boundary (GET /notes/2, refused). On the
  // second trial the owner's read fails, so that trial's boundary pass could be the forwarder answering the route itself
  // (src/forwarded-pairing.mjs). The member's identity stays established, so the boundary still passes every trial.
  const TOKENS = { member: 'synthetic-member-token', owner: 'synthetic-owner-token' };
  let trial = 1, signedOut = 0;
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    const json = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    // Each trial ends with the connector's login checks, one request with no credential per actor: they mark the trial's end.
    if (req.headers.authorization === undefined && ++signedOut % 2 === 0) trial++;
    const who = Object.keys(TOKENS).find(name => req.headers.authorization === `Bearer ${TOKENS[name]}`);
    if (!who) return json(401, {});
    if (req.url === '/me') return json(200, { user: `${who}-1` });
    if (req.url === '/profile') return json(200, { name: who });
    if (req.url === '/notes/2') return who === 'owner' ? json(trial === 2 ? 500 : 200, { id: 2 }) : json(403, {});
    return json(403, {});
  }); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const root = await directory(t), configFile = join(root, 'targets.json');
  const whoami = actor => ({ id: `WHOAMI-${actor.toUpperCase()}`, title: `Who am I (${actor})`, category: 'identity', severity: 'control', actorId: actor, method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: `${actor}-1` }] });
  const profile = { id: 'notes-forwarded', name: 'Notes staging', applicationId: 'notes-app', origin: `http://127.0.0.1:${server.address().port}`, buildLabel: 'b1', contextId: 'synthetic-notes',
    targetContext: 'operator-forwarded', targetLabel: 'Notes staging (forwarded)',
    actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member-1' }, owner: { principalId: 'owner-1', credentialEnv: 'SCOPEHAVEN_TARGET_OWNER', identityValue: 'owner-1' } },
    requiredControlIds: ['WHOAMI-MEMBER', 'WHOAMI-OWNER', 'MEMBER-PROFILE', 'OWNER-READ'],
    checks: [whoami('member'), whoami('owner'),
      // The member's login proven on a protected route other than the boundary's, so it never pairs the boundary.
      { id: 'MEMBER-PROFILE', title: 'A member reads their profile', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'GET', path: '/profile', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'OWNER-READ', title: 'The owner reads their note', category: 'allowed-use', severity: 'control', actorId: 'owner', method: 'GET', path: '/notes/2', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'READ-OTHER', title: "A member cannot read another user's note", category: 'object-access', severity: 'high', actorId: 'member', method: 'GET', path: '/notes/2', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] },
    ] };
  await writeFile(configFile, JSON.stringify({ schemaVersion: 1, targets: [profile] }), { mode: 0o600 });
  const authorizationFile = writeTestAuthorization(join(root, 'authorization.json'), profile, { edit: record => { record.forwarded = { destination: 'https://staging.notes.example' }; } });
  const out = join(root, 'out');
  const summary = await runGate({ targetId: profile.id, configFile, authorizationFile, outputDirectory: out, trials: 3 }, { env: { SCOPEHAVEN_TARGET_MEMBER: TOKENS.member, SCOPEHAVEN_TARGET_OWNER: TOKENS.owner } });
  assert.deepEqual(summary.trials.perTrial[0].reasons, [], 'the first trial is clean: its pass is paired');
  assert.ok(summary.trials.perTrial[1].reasons.includes('forwarded-pass-unpaired'), JSON.stringify(summary.trials.perTrial));
  const other = checkOf(summary, 'READ-OTHER');
  assert.deepEqual([other.passed, other.trials, other.unpaired, other.reading], [3, 3, true, 'NOT-PASSED'], 'passed every trial, but not cleanly');
  assert.equal(checkOf(summary, 'OWNER-READ').reading, 'FAIL-flaky');
  assert.equal(summary.exitCode, 1); assert.ok(summary.reasons.includes('forwarded-pass-unpaired'));
  const sarif = JSON.parse(await readFile(join(out, 'gate-summaries', `${summary.current.runId}.trials.sarif`), 'utf8'));
  const result = sarif.runs[0].results.find(row => row.ruleId === 'READ-OTHER');
  assert.equal(result.kind, 'review', 'as src/sarif.mjs projects an unpaired pass, never kind pass'); assert.equal(result.properties.passKGate.unpaired, true);
  assert.match(result.message.text, /^\[Across 3 trials: NOT-PASSED \(passed 3 of 3; pass\^1 1; floor 1; a pass with no passing same-route control in a trial\)\.\] First trial: /);
  assert.match(await readFile(join(out, 'gate-summaries', `${summary.current.runId}.trials.html`), 'utf8'), /<p class="trials-tag not-pass">Across 3 trials: NOT-PASSED/);
});
