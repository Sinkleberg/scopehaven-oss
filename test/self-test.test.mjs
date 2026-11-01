// --self-test (src/self-test.mjs over src/known-negative.mjs) as check-config, assess and the regression gate run it: every
// check's planted violations through the pure evaluators before anything is authorized or sent. A check with a predicate
// that cannot fail or always fails keeps the result off clean (exit 1; the gate adds check-cannot-fail or
// check-always-fails) and never changes a verdict; any target other than an HTTP contract profile is refused (exit 2). Runs
// go to the owned HTTP lab (examples/http-lab.mjs, repaired build, whose profile reads clean without its backend-only check);
// a loopback notes app counts every connection it accepts, to show the config check contacts nothing. The CLI runs as a
// child process. No model, provider or customer system.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync, chmodSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { validateTargetFile } from '../src/contracts.mjs';
import { knownNegativeTarget, KNOWN_NEGATIVE_SCHEMA } from '../src/known-negative.mjs';
import { selfTestFor, selfTestReasons, brokenChecks, SelfTestError, SELF_TEST_REASONS, SELF_TEST_UNSUPPORTED } from '../src/self-test.mjs';
import { parseArgs, runGate } from '../integrations/regression-gate/gate.mjs';
import { createHttpLab, makeLabProfile } from '../examples/http-lab.mjs';
import { writeTestAuthorization } from './support/authorization.mjs';

const TOKEN = 'synthetic-member-token';
const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url)), gateCli = fileURLToPath(new URL('../integrations/regression-gate/cli.mjs', import.meta.url));

async function notesApp(t) {
  let connections = 0;
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    const json = (s, b) => { res.writeHead(s, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(b)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(401, {});
    if (req.url === '/me') return json(200, { user: 'member-1' });
    if (req.url === '/notes') return json(201, { id: 'n1' });
    return json(403, {});
  }); });
  server.on('connection', () => { connections++; });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return { origin: `http://127.0.0.1:${server.address().port}`, connections: () => connections };
}
const check = (id, path, assertions, extra = {}) => ({ id, title: id, category: 'object-access', severity: 'high', actorId: 'member', method: 'GET', path, evidenceRequirement: 'response', assertions, ...extra });
const NOTES = [
  check('WHOAMI', '/me', [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'member-1' }], { category: 'identity', severity: 'control' }),
  check('OWN-NOTE', '/notes', [{ kind: 'status.equals', expected: 201 }], { category: 'allowed-use', severity: 'control', method: 'POST', body: {} }),
  check('OTHER-NOTE', '/notes/n-other/edit', [{ kind: 'status.equals', expected: 403 }], { method: 'POST', body: {} }),
];
// Passes on every build: json.exists at the root holds on any JSON body, so its violation still reads pass.
const VACUOUS = check('VACUOUS', '/me', [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '', expected: true }]);
// No body satisfies both equalities, so its fails mean nothing.
const CLASH = check('CLASH', '/me', [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/role', expected: 'member' }, { kind: 'json.equals', pointer: '/role', expected: 'admin' }]);
const notesProfile = (origin, extra = []) => ({ id: 'notes', name: 'Notes app', applicationId: 'notes-app', origin, buildLabel: 'b1', contextId: 'synthetic-notes',
  actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member-1' } }, requiredControlIds: ['WHOAMI', 'OWN-NOTE'], checks: [...NOTES, ...extra] });
// The lab's own profile without BACKEND-UNVERIFIED (inconclusive on every build: no backend observer), plus extra checks.
const labProfile = (origin, extra = []) => { const p = makeLabProfile(origin, 'lab-repaired'); return { ...p, checks: [...p.checks.filter(c => c.id !== 'BACKEND-UNVERIFIED'), ...extra] }; };
async function lab(t) {
  const running = await createHttpLab({ build: 'repaired' });
  t.after(() => running.close());
  env.SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN = running.memberToken;
  return running;
}
function setup(t, profile) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven self test ')); chmodSync(dir, 0o700);
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const profiles = join(dir, 'profiles.json');
  writeFileSync(profiles, JSON.stringify({ schemaVersion: 1, targets: [profile] }));
  return { dir, profiles, record: writeTestAuthorization(join(dir, 'record.json'), profile) };
}
const spawned = (file, args) => new Promise(resolve => {
  const child = spawn(process.execPath, [file, ...args], { env: { PATH: process.env.PATH, ...env } });
  let stdout = '', stderr = ''; child.stdout.on('data', d => { stdout += d; }); child.stderr.on('data', d => { stderr += d; });
  child.on('close', code => resolve({ code, stdout, stderr }));
});
const assess = args => spawned(cli, args);
const runFiles = out => existsSync(join(out, 'runs')) ? readdirSync(join(out, 'runs')).filter(f => f.endsWith('.json')) : [];
const savedRun = out => JSON.parse(readFileSync(join(out, 'runs', runFiles(out)[0]), 'utf8')).core;
const verdicts = run => run.results.map(r => [r.id, r.status, r.assertions.map(a => a.status)]);
const env = { SCOPEHAVEN_TARGET_MEMBER: TOKEN };
const validated = profile => validateTargetFile({ schemaVersion: 1, targets: [profile] })[0];

test('selfTestReasons: one refusal per broken outcome, in a fixed order; unprovable, partial, pass-unreachable and error refuse nothing', () => {
  const report = (...outcomes) => ({ checks: outcomes.map((outcome, i) => ({ id: `C${i}`, outcome: 'x', predicates: [{ outcome }] })) });
  assert.deepEqual(SELF_TEST_REASONS.map(([, reason]) => reason), ['check-cannot-fail', 'check-always-fails']);
  assert.deepEqual(selfTestReasons(report('proven', 'unprovable', 'pass-unreachable', 'error')), []);
  assert.deepEqual(selfTestReasons(report('cannot-fail')), ['check-cannot-fail']);
  assert.deepEqual(selfTestReasons(report('always-fails')), ['check-always-fails']);
  assert.deepEqual(selfTestReasons(report('always-fails', 'proven', 'cannot-fail', 'cannot-fail')), ['check-cannot-fail', 'check-always-fails']);
  for (const malformed of [null, undefined, {}, { checks: 'x' }, { checks: [null, { predicates: 'x' }, { predicates: [null] }] }]) assert.deepEqual(selfTestReasons(malformed), []);
  assert.deepEqual(brokenChecks({ checks: [{ id: 'A', outcome: 'broken' }, { id: 'B', outcome: 'partial' }, { id: 'C', outcome: 'broken' }] }), ['A', 'C']);
});

test('selfTestFor: the known-negative report of an HTTP contract profile; any other target, or a profile of another id, is refused', () => {
  const profile = validated(notesProfile('http://127.0.0.1:4100', [VACUOUS, CLASH])), entry = { id: 'notes', kind: 'http-contract' };
  const report = selfTestFor(entry, profile);
  assert.deepEqual(report, knownNegativeTarget(profile));
  assert.equal(report.schema, KNOWN_NEGATIVE_SCHEMA);
  assert.deepEqual(report.checks.map(c => [c.id, c.outcome]), [['WHOAMI', 'proven'], ['OWN-NOTE', 'proven'], ['OTHER-NOTE', 'proven'], ['VACUOUS', 'broken'], ['CLASH', 'broken']]);
  assert.deepEqual(selfTestReasons(report), ['check-cannot-fail', 'check-always-fails']);
  assert.deepEqual(brokenChecks(report), ['VACUOUS', 'CLASH']);
  for (const [other, p] of [[{ id: 'demo-repaired', kind: 'synthetic' }, undefined], [{ id: 'notes', kind: 'owned-refund-contract' }, profile], [entry, undefined], [entry, { ...profile, id: 'other' }], [undefined, profile]]) {
    assert.throws(() => selfTestFor(other, p), error => error instanceof SelfTestError && error.code === SELF_TEST_UNSUPPORTED, JSON.stringify(other));
  }
});

test('check-config --self-test reports each HTTP target and exits 1 on a broken check, contacting nothing and needing no record', async t => {
  const app = await notesApp(t), clean = setup(t, notesProfile(app.origin)), broken = setup(t, notesProfile(app.origin, [VACUOUS]));
  const plain = await assess(['--check-config', '--config', broken.profiles]);
  assert.equal(plain.code, 0, plain.stderr);
  assert.equal(Object.hasOwn(JSON.parse(plain.stdout).targets.find(x => x.id === 'notes'), 'selfTest'), false, 'no report without the flag');
  const tested = await assess(['--check-config', '--config', broken.profiles, '--self-test']);
  assert.equal(tested.code, 1, tested.stderr);
  const listing = JSON.parse(tested.stdout), notes = listing.targets.find(x => x.id === 'notes');
  assert.equal(notes.selfTest.outcome, 'broken');
  assert.deepEqual(notes.selfTest.checks.find(c => c.id === 'VACUOUS').predicates[1], { layer: 'response', index: 1, kind: 'json.exists', outcome: 'cannot-fail', fixed: 'pass', defective: 'pass' });
  assert.match(tested.stderr, /Self-test: notes has broken checks \(check-cannot-fail\): VACUOUS/);
  // Everything else in the listing is what it is without the flag; built-in targets carry no report.
  const { selfTest: _s, ...rest } = notes;
  assert.deepEqual({ ...listing, targets: listing.targets.map(x => x.id === 'notes' ? rest : x) }, JSON.parse(plain.stdout));
  assert.ok(listing.targets.filter(x => x.kind !== 'http-contract').every(x => !Object.hasOwn(x, 'selfTest')));
  const ok = await assess(['--list', '--self-test', '--config', clean.profiles]);
  assert.equal(ok.code, 0, ok.stderr);
  assert.equal(JSON.parse(ok.stdout).targets.find(x => x.id === 'notes').selfTest.outcome, 'proven');
  assert.equal(ok.stderr, '');
  // With no HTTP contract target, nothing would be tested: refused, never a silent 0.
  const none = await assess(['--check-config', '--self-test']);
  assert.equal(none.code, 2);
  assert.match(none.stderr, /self-test refused \(self-test-unsupported-target\)/);
  assert.equal(none.stdout, '');
  const twice = await assess(['--check-config', '--self-test', '--self-test', '--config', clean.profiles]);
  assert.equal(twice.code, 2);
  assert.match(twice.stderr, /Duplicate flag/);
  assert.equal(app.connections(), 0, 'the self-test contacted nothing');
});

test('assess --self-test: the run is made with the same verdicts, the summary carries the report, and a broken check exits 1', async t => {
  const app = await lab(t), s = setup(t, labProfile(app.origin, [VACUOUS]));
  const plainOut = join(s.dir, 'plain'), testedOut = join(s.dir, 'tested');
  const plain = await assess(['--config', s.profiles, '--target', 'http-lab', '--out', plainOut, '--authorization', s.record]);
  assert.equal(plain.code, 0, `every check passes without the flag: ${plain.stderr}`);
  assert.equal(Object.hasOwn(JSON.parse(plain.stdout), 'selfTest'), false);
  const tested = await assess(['--config', s.profiles, '--target', 'http-lab', '--out', testedOut, '--authorization', s.record, '--self-test']);
  assert.equal(tested.code, 1, 'a check that cannot fail keeps the run off clean');
  const printed = JSON.parse(tested.stdout);
  assert.deepEqual(printed.counts, JSON.parse(plain.stdout).counts);
  assert.equal(printed.counts.fail + printed.counts.error + printed.counts.inconclusive, 0);
  assert.deepEqual(selfTestReasons(printed.selfTest), ['check-cannot-fail']);
  assert.deepEqual(printed.selfTest, knownNegativeTarget(validated(labProfile(app.origin, [VACUOUS]))));
  assert.match(tested.stderr, /Self-test: http-lab has broken checks \(check-cannot-fail\): VACUOUS/);
  // The saved run is the run: same verdicts and identities, and it carries no self-test field.
  const before = savedRun(plainOut), after = savedRun(testedOut);
  assert.deepEqual(verdicts(after), verdicts(before));
  assert.deepEqual([after.suiteHash, after.policyHash, after.evaluatorHash, after.profileHash], [before.suiteHash, before.policyHash, before.evaluatorHash, before.profileHash]);
  assert.equal(JSON.stringify(after).includes('known-negative'), false);
  // A clean profile with the flag exits as it does without it.
  const clean = setup(t, labProfile(app.origin)), cleanRun = await assess(['--config', clean.profiles, '--target', 'http-lab', '--out', join(clean.dir, 'out'), '--authorization', clean.record, '--self-test']);
  assert.equal(cleanRun.code, 0, cleanRun.stderr);
  assert.equal(JSON.parse(cleanRun.stdout).selfTest.outcome, 'proven');
});

test('assess --self-test reports an always-failing check beside the failure the run reads', async t => {
  const app = await lab(t), s = setup(t, labProfile(app.origin, [CLASH]));
  const tested = await assess(['--config', s.profiles, '--target', 'http-lab', '--out', join(s.dir, 'out'), '--authorization', s.record, '--self-test']);
  assert.equal(tested.code, 1);
  const printed = JSON.parse(tested.stdout);
  assert.equal(printed.counts.fail, 1);
  assert.deepEqual(selfTestReasons(printed.selfTest), ['check-always-fails']);
  assert.match(tested.stderr, /\(check-always-fails\): CLASH/);
});

test('assess --self-test on a built-in target is refused before anything runs (exit 2), and no run is saved', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven self test builtin ')); chmodSync(dir, 0o700); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const out = join(dir, 'out'), r = await assess(['--target', 'demo-repaired', '--out', out, '--self-test']);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /self-test refused \(self-test-unsupported-target\): --self-test applies to an HTTP contract target from --config\./);
  assert.equal(r.stdout, '');
  assert.deepEqual(runFiles(out), []);
});

test('gate parseArgs: --self-test is a switch, once; it is refused beside --saved-refund', () => {
  const base = ['--target', 'notes', '--out', '/private/gate'];
  assert.equal(parseArgs([...base, '--self-test']).selfTest, true);
  assert.equal(Object.hasOwn(parseArgs(base), 'selfTest'), false);
  assert.deepEqual(parseArgs(['--self-test', '--require-model-identity', ...base, '--baseline', 'b1']), { selfTest: true, requireModelIdentity: true, targetId: 'notes', outputDirectory: '/private/gate', baselineRunId: 'b1' });
  for (const args of [[...base, '--self-test', '--self-test'], [...base, '--self-test', 'yes'], [...base, '--self-tests']]) assert.throws(() => parseArgs(args), /invalid-options/, args.join(' '));
  const fingerprint = 'a'.repeat(64);
  assert.throws(() => parseArgs(['--target', 'notes', '--saved-refund', '/private/r.json', '--refund-public-key', '/private/k.pem', '--refund-key-fingerprint', fingerprint, '--expected-run', 'r1', '--self-test']), /invalid-options/);
  assert.doesNotThrow(() => parseArgs(['--target', 'notes', '--saved-refund', '/private/r.json', '--refund-public-key', '/private/k.pem', '--refund-key-fingerprint', fingerprint, '--expected-run', 'r1']));
});

test('the gate with --self-test: a broken check adds its reason and exits 1, the summary carries the report, and verdicts are unchanged', async t => {
  const app = await lab(t), s = setup(t, labProfile(app.origin, [VACUOUS]));
  const options = name => ({ targetId: 'http-lab', configFile: s.profiles, outputDirectory: join(s.dir, name), authorizationFile: s.record });
  const plain = await runGate(options('plain'), { env });
  assert.deepEqual([plain.exitCode, plain.reasons], [0, []], 'clean without the flag');
  assert.equal(Object.hasOwn(plain, 'selfTest'), false);
  const tested = await runGate({ ...options('tested'), selfTest: true }, { env });
  assert.deepEqual([tested.outcome, tested.exitCode, tested.reasons], ['assessment-failed', 1, ['check-cannot-fail']]);
  assert.deepEqual(tested.current.counts, plain.current.counts);
  assert.deepEqual(tested.selfTest, knownNegativeTarget(validated(labProfile(app.origin, [VACUOUS]))));
  // The saved summary is the returned one.
  const [file] = readdirSync(join(s.dir, 'tested', 'gate-summaries'));
  assert.deepEqual(JSON.parse(readFileSync(join(s.dir, 'tested', 'gate-summaries', file), 'utf8')), tested);
  // An always-failing check is named beside the run's own failure.
  const clash = setup(t, labProfile(app.origin, [CLASH]));
  const failed = await runGate({ targetId: 'http-lab', configFile: clash.profiles, outputDirectory: join(clash.dir, 'gate'), authorizationFile: clash.record, selfTest: true }, { env });
  assert.deepEqual([failed.exitCode, failed.reasons], [1, ['checks-failed', 'check-always-fails']]);
  // A clean profile gates as it does without the flag, with the report beside it.
  const clean = setup(t, labProfile(app.origin));
  const proven = await runGate({ targetId: 'http-lab', configFile: clean.profiles, outputDirectory: join(clean.dir, 'gate'), authorizationFile: clean.record, selfTest: true }, { env });
  assert.deepEqual([proven.exitCode, proven.reasons, proven.selfTest.outcome], [0, [], 'proven']);
});

test('the gate refuses --self-test on a built-in target before the output directory is touched (exit 2, self-test-unsupported-target)', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven self test gate ')); chmodSync(dir, 0o700); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const out = join(dir, 'gate'), summary = await runGate({ targetId: 'demo-repaired', outputDirectory: out, selfTest: true });
  assert.deepEqual([summary.outcome, summary.exitCode, summary.reasons], ['config-or-runtime-error', 2, ['self-test-unsupported-target']]);
  assert.equal(existsSync(out), false);
});

// With --report-only (integrations/regression-gate/report-only.mjs) the window relaxes only the exit: the recorded verdict is
// the one without it, and check-cannot-fail stays listed in the printed and saved summary.
test('the gate with --self-test and --report-only exits 0 in the window, keeps the verdict and still lists check-cannot-fail', async t => {
  const app = await lab(t), s = setup(t, labProfile(app.origin, [VACUOUS])), out = join(s.dir, 'gate');
  const until = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
  const args = ['--target', 'http-lab', '--config', s.profiles, '--out', out, '--authorization', s.record, '--self-test', '--report-only', '--report-only-runs', '1', '--report-only-until', until];
  const plain = await runGate({ targetId: 'http-lab', configFile: s.profiles, outputDirectory: join(s.dir, 'plain'), authorizationFile: s.record, selfTest: true }, { env });
  const r = await spawned(gateCli, args);
  assert.equal(r.code, 0, r.stderr);
  const summary = JSON.parse(r.stdout);
  assert.deepEqual([summary.outcome, summary.exitCode, summary.reasons], ['assessment-failed', 1, ['check-cannot-fail']]);
  assert.deepEqual([summary.outcome, summary.exitCode, summary.reasons, summary.current.counts], [plain.outcome, plain.exitCode, plain.reasons, plain.current.counts]);
  assert.deepEqual([summary.reportOnly.state, summary.reportOnly.exitCode], ['applied', 0]);
  assert.deepEqual(brokenChecks(summary.selfTest), ['VACUOUS']);
  const id = summary.current.runId;
  assert.deepEqual(readdirSync(join(out, 'gate-summaries')).sort(), [`${id}.json`, `${id}.report-only.html`, `${id}.report-only.sarif`]);
  assert.deepEqual(JSON.parse(readFileSync(join(out, 'gate-summaries', `${id}.json`), 'utf8')), summary);
  // The one-run window is used up: the same command exits 1 again, the reason still listed.
  const again = await spawned(gateCli, args);
  assert.equal(again.code, 1, again.stderr);
  const ended = JSON.parse(again.stdout);
  assert.deepEqual([ended.reasons, ended.reportOnly.state, ended.reportOnly.endedBy], [['check-cannot-fail'], 'ended', 'runs-used']);
});

test('scopehaven gate --self-test from the command line prints the summary with the report and exits with its code', async t => {
  const app = await lab(t), s = setup(t, labProfile(app.origin, [VACUOUS]));
  const r = await spawned(gateCli, ['--target', 'http-lab', '--config', s.profiles, '--out', join(s.dir, 'gate'), '--authorization', s.record, '--self-test']);
  assert.equal(r.code, 1, r.stderr);
  const summary = JSON.parse(r.stdout);
  assert.deepEqual(summary.reasons, ['check-cannot-fail']);
  assert.equal(summary.selfTest.outcome, 'broken');
});
