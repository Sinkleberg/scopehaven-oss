// The payments pack inside assess and the gate (assess-hook.mjs): the pack runs as the assessed target's own, under the record
// file that authorized the HTTP run, is checked before anything is sent, writes beside the HTTP evidence, and the gate's
// comparison labels rows without turning a passing run red. Owned demo app and payments double only, on 127.0.0.1.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readdir, rm, mkdir, symlink, chmod, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { onFreePorts } from '../observers/fixtures/free-port.mjs';
import { startRefundAgentApp, DEMO_TOKENS, demoPackConfig, demoAuthorization } from './demo/refund-agent-app.mjs';
import { assessPayments, preparePayments, gatePayments, runGateWithPayments, samePackTarget, combineExit, reportOnlyExit, PAYMENTS_ASSESS_SCHEMA } from './assess-hook.mjs';
import { readFile } from 'node:fs/promises';
import { checksumAuthorization } from '../../src/authorization.mjs';

const NOW = new Date();
const targetOf = config => ({ id: config.id, applicationId: config.applicationId, origin: config.origin });
async function workspace() {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven payments hook '));
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}
// One owned refund app build and its pack and record on disk, as assess would be given them.
async function scenario(t, variant, dir, run) {
  return onFreePorts(2, async (appPort, payPort) => {
    const config = demoPackConfig({ appPort, payPort });
    const app = await startRefundAgentApp({ port: appPort, payPort, variant });
    t.after(() => app.stop());
    const packPath = join(dir, `pack-${variant}.json`), authorizationFile = join(dir, `record-${variant}.json`);
    await writeFile(packPath, JSON.stringify(config), { mode: 0o600 });
    await writeFile(authorizationFile, JSON.stringify(demoAuthorization(config, { now: NOW })), { mode: 0o600 });
    return run({ config, packPath, authorizationFile });
  });
}

test('combineExit and samePackTarget: the worse exit wins, and the pack must be the assessed target\'s own', () => {
  assert.equal(combineExit(0, 0), 0); assert.equal(combineExit(0, 1), 1); assert.equal(combineExit(1, 2), 2); assert.equal(combineExit(2, 0), 2);
  const pack = { id: 'shop', applicationId: 'shop', origin: 'http://127.0.0.1:4470' };
  assert.equal(samePackTarget(pack, { ...pack }), null);
  assert.match(samePackTarget(pack, { ...pack, id: 'other' }), /pack's id must be the target's/);
  assert.match(samePackTarget(pack, { ...pack, origin: 'http://127.0.0.1:1' }), /pack's origin must be the target's \(the same app\)/);
  assert.match(samePackTarget(pack, null), /beside a target from --config/);
});

test('preparePayments refuses a pack for another target or a malformed pack before anything is sent', async () => {
  const { dir, cleanup } = await workspace();
  try {
    const config = demoPackConfig({ appPort: 40001, payPort: 40002 });
    const packPath = join(dir, 'pack.json');
    await writeFile(packPath, JSON.stringify(config), { mode: 0o600 });
    await assert.rejects(preparePayments({ packPath, target: { ...targetOf(config), id: 'another-target' } }), e => e.code === 'payments-pack-target');
    const bad = join(dir, 'bad.json');
    await writeFile(bad, JSON.stringify({ ...config, checks: config.checks.map((c, i) => (i === 2 ? { ...c, severity: 'high' } : c)) }), { mode: 0o600 });
    await assert.rejects(preparePayments({ packPath: bad, target: targetOf(config) }), /"severity" is control/);
    // The record must cover the pack now: none, or one for other test customers, is refused here, before any request.
    await assert.rejects(preparePayments({ packPath, target: targetOf(config) }), /authorization/i);
    const record = demoAuthorization(config, { now: NOW });
    const other = join(dir, 'other.json');
    await writeFile(other, JSON.stringify({ ...record, identities: ['cus_someone_else'] }), { mode: 0o600 });
    await assert.rejects(preparePayments({ packPath, target: targetOf(config), authorizationFile: other, now: NOW }), e => e.name === 'AuthorizationError');
    const authorizationFile = join(dir, 'record.json');
    await writeFile(authorizationFile, JSON.stringify(record), { mode: 0o600 });
    const prepared = await preparePayments({ packPath, target: targetOf(config), authorizationFile, now: NOW });
    assert.equal(typeof prepared.run, 'function');
    // assess prepares the pack before its HTTP run and runs it after: the run is authorized again at its own time, so a window
    // that ended during the HTTP run refuses it before the double starts or anything is written.
    await assert.rejects(prepared.run({ directory: join(dir, 'late'), env: DEMO_TOKENS, now: new Date(NOW.getTime() + 25 * 3600000) }), e => e.name === 'AuthorizationError' && e.code === 'authorization-window');
    await assert.rejects(readdir(join(dir, 'late')), /ENOENT/, 'a refused late run writes nothing');
    // The same through the call assess makes (no time passed): a record whose window ends between prepare and run.
    const shortRecord = checksumAuthorization({ ...demoAuthorization(config, { now: new Date() }), validUntil: new Date(Date.now() + 1500).toISOString() });
    const shortFile = join(dir, 'short.json');
    await writeFile(shortFile, JSON.stringify(shortRecord), { mode: 0o600 });
    const soon = await preparePayments({ packPath, target: targetOf(config), authorizationFile: shortFile });
    await new Promise(done => setTimeout(done, 1600));
    await assert.rejects(soon.run({ directory: join(dir, 'late-default'), env: DEMO_TOKENS }), e => e.name === 'AuthorizationError' && e.code === 'authorization-window');
    await assert.rejects(readdir(join(dir, 'late-default')), /ENOENT/);
  } finally { await cleanup(); }
});

test('assessPayments: the repaired build passes under the record file and writes beside the HTTP evidence; the vulnerable build exits 1', async t => {
  const { dir, cleanup } = await workspace();
  t.after(cleanup);
  const repaired = await scenario(t, 'repaired', dir, ({ config, packPath, authorizationFile }) => assessPayments({ packPath, target: targetOf(config), authorizationFile, directory: join(dir, 'evidence-repaired'), env: DEMO_TOKENS, now: NOW }));
  assert.equal(repaired.schema, PAYMENTS_ASSESS_SCHEMA);
  assert.deepEqual(repaired.summary.counts, { pass: 5, fail: 0, inconclusive: 0 });
  assert.equal(repaired.exitCode, 0);
  assert.deepEqual((await readdir(join(dir, 'evidence-repaired', 'payments'))).map(f => f.replace(/^pay-[0-9]+-[0-9a-f]+/, 'RUN')).sort(), ['RUN.html', 'RUN.json']);
  const vulnerable = await scenario(t, 'vulnerable', dir, ({ config, packPath, authorizationFile }) => assessPayments({ packPath, target: targetOf(config), authorizationFile, directory: join(dir, 'evidence-vulnerable'), env: DEMO_TOKENS, now: NOW }));
  assert.deepEqual(vulnerable.summary.counts, { pass: 2, fail: 3, inconclusive: 0 });
  assert.equal(vulnerable.exitCode, 1);
  // Without a record the pack's own rule refuses the run before the double starts.
  await scenario(t, 'repaired', dir, ({ config, packPath }) => assert.rejects(assessPayments({ packPath, target: targetOf(config), directory: join(dir, 'evidence-none'), env: DEMO_TOKENS, now: NOW }), /authorization/i));
  await assert.rejects(readFile(join(dir, 'evidence-none', 'payments')), /ENOENT/, 'a refused pack writes nothing');
});

test('gatePayments labels a verified repair against the vulnerable baseline, and runGateWithPayments adds it to the gate summary', async t => {
  const { dir, cleanup } = await workspace();
  t.after(cleanup);
  const baseline = await scenario(t, 'vulnerable', dir, ({ config, packPath, authorizationFile }) => gatePayments({ packPath, target: targetOf(config), authorizationFile, paymentsDirectory: join(dir, 'gate-payments'), env: DEMO_TOKENS, now: NOW }));
  assert.equal(baseline.comparison, null);
  const baselinePath = join(dir, 'gate-payments', `${baseline.summary.id}.json`);
  const repaired = await scenario(t, 'repaired', dir, ({ config, packPath, authorizationFile }) => gatePayments({ packPath, target: targetOf(config), authorizationFile, paymentsDirectory: join(dir, 'gate-payments'), baselinePath, env: DEMO_TOKENS, now: NOW }));
  // Ports differ between the two scenarios, and the pack digest leaves them out, so the runs compare.
  assert.equal(repaired.comparison.compatible, true);
  assert.equal(repaired.comparison.verdict, 'verified repair');
  assert.equal(repaired.exitCode, 0);
  // The wrapper's options, and the gate unchanged without --payments-pack.
  const stub = summary => ({ runGate: async () => summary, parseArgs: argv => ({ argv }) });
  await assert.rejects(runGateWithPayments(['--payments-baseline', baselinePath], stub({ exitCode: 0 })), /needs --payments-pack/);
  await assert.rejects(runGateWithPayments(['--payments-pack'], stub({ exitCode: 0 })), /needs one value/);
  assert.deepEqual(await runGateWithPayments(['--target', 'x'], stub({ exitCode: 1, outcome: 'assessment-failed' })), { exitCode: 1, outcome: 'assessment-failed' }, 'without --payments-pack the gate is unchanged');
});

test('runGateWithPayments with a real pack: checked before the gate runs, the worse exit, report-only by its own rule, the payments half written beside the gate', async t => {
  const { dir, cleanup } = await workspace();
  t.after(cleanup);
  assert.equal(reportOnlyExit({ state: 'applied' }, 1), 0); assert.equal(reportOnlyExit({ state: 'applied' }, 2), 2); assert.equal(reportOnlyExit({ state: 'ended' }, 1), 1); assert.equal(reportOnlyExit(undefined, 1), 1);
  await scenario(t, 'vulnerable', dir, async ({ config, packPath, authorizationFile }) => {
    const out = join(dir, 'gate');
    let gateRan = 0;
    const wrapper = summary => ({ parseArgs: () => ({ targetId: config.id, configFile: 'unused', outputDirectory: out, authorizationFile }), loadProfiles: async () => [targetOf(config)],
      runGate: async () => { gateRan++; return structuredClone(summary); }, env: DEMO_TOKENS, now: NOW });
    // A saved refund result sends nothing: the pack is refused with it, before the gate runs.
    await assert.rejects(runGateWithPayments(['--payments-pack', packPath], { ...wrapper({ exitCode: 0 }), parseArgs: () => ({ targetId: config.id, savedRefund: '/x' }) }), /--saved-refund/);
    // A pack the record does not cover is refused before the gate runs.
    await assert.rejects(runGateWithPayments(['--payments-pack', packPath], { ...wrapper({ exitCode: 0 }), parseArgs: () => ({ targetId: config.id, configFile: 'unused', outputDirectory: out }) }), /authorization/i);
    assert.equal(gateRan, 0, 'the gate never ran for a refused pack');
    // A clean HTTP gate under an applied report-only window: the vulnerable pack fails, so the combined exit is 1 and the
    // report-only exit stays 0 while the window applies.
    const applied = await runGateWithPayments(['--payments-pack', packPath], wrapper({ exitCode: 0, outcome: 'clean', current: { runId: 'run-applied' }, reportOnly: { mode: 'report-only', state: 'applied', exitCode: 0 } }));
    assert.equal(gateRan, 1);
    assert.equal(applied.payments.exitCode, 1);
    assert.equal(applied.exitCode, 1);
    assert.equal(applied.reportOnly.exitCode, 0);
    assert.equal(applied.outcome, 'assessment-failed', 'a failing payments half is not a clean gate');
    assert.ok(applied.reasons.includes('payments-not-clean'));
    const written = JSON.parse(await readFile(applied.payments.summaryFile, 'utf8'));
    assert.equal(written.gateRun, 'run-applied');
    assert.deepEqual(written.summary.counts, { pass: 2, fail: 3, inconclusive: 0 });
    // The same after the window ended: the payments failure is the process exit.
    const ended = await runGateWithPayments(['--payments-pack', packPath], wrapper({ exitCode: 0, outcome: 'clean', current: { runId: 'run-ended' }, reportOnly: { mode: 'report-only', state: 'ended', exitCode: 0 } }));
    assert.equal(ended.reportOnly.exitCode, 1);
    // A trailing "/" on --out still puts the payments half beside the gate's folder, never inside it.
    const slashed = await runGateWithPayments(['--payments-pack', packPath], { ...wrapper({ exitCode: 0, outcome: 'clean', current: { runId: 'run-slash' } }), parseArgs: () => ({ targetId: config.id, configFile: 'unused', outputDirectory: `${out}/`, authorizationFile }) });
    assert.equal(slashed.payments.summaryFile, join(`${await realpath(dir)}/gate-payments`, 'gate-run-slash.json'));
    // A gate run id that is not a plain id: no file is written beside it, and the summary says why.
    const oddId = await runGateWithPayments(['--payments-pack', packPath], wrapper({ exitCode: 0, outcome: 'clean', current: { runId: 'run/../odd' } }));
    assert.deepEqual([oddId.payments.summaryFile, /no plain id/.test(oddId.payments.summaryFileWhy)], [undefined, true]);
    // A gate that ended in an error runs no pack.
    const errored = await runGateWithPayments(['--payments-pack', packPath], wrapper({ exitCode: 2, outcome: 'config-or-runtime-error' }));
    assert.equal(errored.payments, undefined);
    // A payments half that throws after the gate sent its requests keeps the gate's summary and reports itself.
    const thrown = await runGateWithPayments(['--payments-pack', packPath], { ...wrapper({ exitCode: 0, outcome: 'clean', reasons: [], current: { runId: 'run-thrown' } }),
      createDouble: () => { throw Object.assign(new Error('synthetic double failure'), { code: 'double-failed' }); } });
    assert.deepEqual([thrown.exitCode, thrown.outcome, thrown.current.runId, thrown.payments.error], [2, 'config-or-runtime-error', 'run-thrown', 'double-failed']);
    assert.deepEqual(thrown.reasons, ['payments-error']);
    // The payments half is authorized at the time it runs, after the gate: a window that ends while the gate runs refuses the
    // pack (no refund is sent), with the gate's summary kept.
    let reads = 0;
    const late = await runGateWithPayments(['--payments-pack', packPath], { ...wrapper({ exitCode: 0, outcome: 'clean', reasons: [], current: { runId: 'run-late' } }), now: undefined,
      clock: () => (reads++ === 0 ? NOW : new Date(NOW.getTime() + 25 * 3600000)) });
    assert.equal(reads, 2, 'the clock is read before the gate and again after it');
    assert.deepEqual([late.exitCode, late.payments.error, late.current.runId], [2, 'authorization-window', 'run-late']);
    // The payments folder keeps the gate's own folder rules, checked before the gate runs: a link, a folder others can read,
    // or a folder holding something else is refused.
    const ran = gateRan;
    const other = join(dir, 'elsewhere'); await mkdir(other, { mode: 0o700 });
    for (const [name, make] of [['linked', p => symlink(other, p)], ['open', async p => { await mkdir(p); await chmod(p, 0o755); }], ['stray', async p => { await mkdir(p, { mode: 0o700 }); await writeFile(join(p, 'notes.txt'), 'x'); }]]) {
      await make(join(dir, `${name}-payments`));
      await assert.rejects(runGateWithPayments(['--payments-pack', packPath], { ...wrapper({ exitCode: 0 }), parseArgs: () => ({ targetId: config.id, configFile: 'unused', outputDirectory: join(dir, name), authorizationFile }) }), /private \(0700\) folder of this user, not a link|not a ScopeHaven payments folder/, name);
    }
    // A marked folder holding something that is not a payments run is refused too. (The project-data refusal mirrors the gate's
    // and is not exercised here: a clean checkout has no data folder, and a test never creates one.)
    const marked = join(dir, 'marked-payments'); await mkdir(marked, { mode: 0o700 });
    await writeFile(join(marked, '.scopehaven-gate-payments'), 'scopehaven-gate-payments/1\n', { mode: 0o600 }); await writeFile(join(marked, 'package.json'), '{}');
    await assert.rejects(runGateWithPayments(['--payments-pack', packPath], { ...wrapper({ exitCode: 0 }), parseArgs: () => ({ targetId: config.id, configFile: 'unused', outputDirectory: join(dir, 'marked'), authorizationFile }) }), /not a payments run \("package\.json"\)/);

    await assert.rejects(runGateWithPayments(['--payments-pack', packPath], { ...wrapper({ exitCode: 0 }), parseArgs: () => ({ targetId: config.id, configFile: 'unused', outputDirectory: join(dir, 'no-such-parent', 'gate'), authorizationFile }) }), /parent must exist/);
    assert.equal(gateRan, ran, 'the gate never ran for a refused payments folder');
  });
});
