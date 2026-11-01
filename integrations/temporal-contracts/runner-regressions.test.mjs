// Original lead probes, adapted only for worktree-local imports. Local doubles only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as wait } from 'node:timers/promises';
import { runRefundAssessment, currentRefundSuite } from './runner.mjs';
import { startRefundFixture } from './fixtures/refund-app.mjs';
import { startEvilFixture } from './fixtures/refund-adversarial-app.mjs';
import { summarizeGate, runGate } from '../regression-gate/gate.mjs';
import { CONTROL_CUSTODY_LIMIT } from '../../src/custody.mjs';

const row = (run, id) => run.results.find(result => result.id === id);
async function workspace(t) {
  const root = await mkdtemp(join(tmpdir(), 'scopehaven-refund-regressions-')); t.after(() => rm(root, { recursive: true, force: true })); return root;
}
async function probe(mode, { late = false } = {}) {
  const log = [], operator = []; let subjectLastEventMs = 0;
  const run = await runRefundAssessment('refund-clean', {
    fixtureFactory: config => startEvilFixture({ ...config, mode, log }),
    beforeActiveControl: async ({ payments }) => {
      operator.push({ at: 'before-active-control-request', providerRefunds: payments.providerLedger().refunds.length });
      if (late) await wait(5100);
    },
    afterExecute: async ({ fixture, contract }) => {
      const snapshot = await fixture.snapshot({ horizonId: contract.horizon.id, deadlineMs: contract.horizon.deadlineMs, close: false });
      subjectLastEventMs = Math.max(0, ...snapshot.events.map(event => event.atMs));
    },
  });
  const gate = summarizeGate({ candidate: run, expectedSuite: await currentRefundSuite('refund-clean') });
  return { run, gate, log, operator, subjectLastEventMs };
}
function exactFailure(run, id, reason) {
  const result = row(run, id); assert.equal(result.status, 'fail', JSON.stringify(result));
  assert.ok(result.reasons.includes(reason), JSON.stringify(result));
}
function custodyControl(run, id) {
  const result = row(run, id); assert.equal(result.severity, 'control');
  assert.equal(result.custodyLimit, CONTROL_CUSTODY_LIMIT);
}

test('H1 probe relabel-revoked: the fifth provider refund belongs to revoked-new operator window', async () => {
  const { run, gate, log, operator } = await probe('relabel-revoked');
  assert.equal(operator[0].providerRefunds, 5);
  assert.ok(log.some(event => event.covert && event.causedBy === 'revoked-new' && event.labelledAs === 'active-control' && event.providerStatus === 200));
  assert.equal(row(run, 'revoked-new-effects').effectIds.length, 1);
  exactFailure(run, 'revoked-new-binding', 'forbidden-or-mutated-dispatch');
  exactFailure(run, 'revoked-new-effects', 'bound-effect-count-mismatch');
  exactFailure(run, 'revoked-new-refusal', 'new-work-not-correctly-refused');
  assert.ok(run.refundAdjudication.evidenceSummary.operatorProblems.some(problem => problem.startsWith('provider-header-window-mismatch:')));
  assert.notEqual(gate.exitCode, 0);
});

test('H1 probe double-retry: a covert second refund remains attributed to retry rather than identical-a', async () => {
  const { run, gate, log } = await probe('double-retry');
  assert.ok(log.some(event => event.covert && event.causedBy === 'retry:changed-retry-key' && event.labelledAs === 'identical-a' && event.providerStatus === 200));
  assert.equal(row(run, 'retry-effects').effectIds.length, 2);
  exactFailure(run, 'retry-effects', 'bound-effect-count-mismatch');
  exactFailure(run, 'retry-binding', 'forbidden-or-mutated-dispatch');
  assert.notEqual(gate.exitCode, 0);
});

test('H1 probe late-accept: rewritten acceptance remains an explicitly custody-limited control', async () => {
  const { run, log } = await probe('late-accept');
  assert.ok(log.some(event => event.lateAccepted === 'pre-cutoff' && event.afterRevocation));
  custodyControl(run, 'pre-cutoff-authority');
  assert.ok(run.limitations.some(limitation => /acceptance/i.test(limitation) && /custody|subject|app|operator/i.test(limitation)));
});

test('H1 contrast recorded-not-sent: a fabricated dispatch cannot supply a provider effect or a clean gate', async () => {
  const { run, gate } = await probe('recorded-not-sent');
  assert.equal(row(run, 'active-control-effects').effectIds.length, 0);
  exactFailure(run, 'active-control-effects', 'bound-effect-count-mismatch');
  assert.notEqual(row(run, 'active-control-completion').status, 'pass');
  assert.ok(run.refundAdjudication.evidenceSummary.problems.some(problem => problem.startsWith('application-dispatch-without-provider-observation:')));
  custodyControl(run, 'active-control-authority');
  assert.notEqual(gate.exitCode, 0);
});

test('M1 slow-clock: success inside the subject clock but after operator deadline fails completion', { timeout: 20000 }, async () => {
  const { run, gate, subjectLastEventMs } = await probe('slow-clock', { late: true });
  assert.ok(run.durationMs > 5000, `operator duration ${run.durationMs}`);
  assert.ok(subjectLastEventMs < 5000, `subject event time ${subjectLastEventMs}`);
  assert.equal(row(run, 'active-control-completion').status, 'fail');
  assert.ok(row(run, 'active-control-completion').reasons.includes('terminal-success-after-deadline'));
  assert.equal(gate.exitCode, 1);
});

test('M37: runGate rejects its trust output inside the result tree', async t => {
  const root = await workspace(t), out = join(root, 'results');
  const result = await runGate({ targetId: 'refund-clean', outputDirectory: out, refundTrustOutput: join(out, 'operator-public-key.pem') });
  assert.equal(result.exitCode, 2, JSON.stringify(result));
  assert.ok(result.reasons.includes('refund-trust-key-must-be-external'), JSON.stringify(result));
});

test('M41: a fixture with the wrong build identity is rejected before adjudication', async () => {
  await assert.rejects(() => runRefundAssessment('refund-clean', {
    fixtureFactory: async config => ({ ...await startRefundFixture(config), buildHash: '0'.repeat(64) }),
  }), { message: 'refund-target-build-changed' });
});

test('M42: a source edit during execution is rejected in an isolated copy', { timeout: 20000 }, async t => {
  const root = await workspace(t), copied = join(root, 'copied application');
  await cp(fileURLToPath(new URL('../../src/', import.meta.url)), join(copied, 'src'), { recursive: true });
  await cp(fileURLToPath(new URL('../', import.meta.url)), join(copied, 'integrations'), { recursive: true });
  const runner = pathToFileURL(join(copied, 'integrations', 'temporal-contracts', 'runner.mjs')).href;
  const changed = join(copied, 'integrations', 'temporal-contracts', 'binding.mjs');
  const program = `import {appendFile} from 'node:fs/promises';
    import {runRefundAssessment} from ${JSON.stringify(runner)};
    try {
      await runRefundAssessment('refund-clean',{afterExecute:()=>appendFile(${JSON.stringify(changed)},'\\n// isolated post-execution source change\\n')});
      process.stdout.write('unexpected-finalization');
    } catch(error) { process.stdout.write(error.message); }`;
  const { stdout } = await promisify(execFile)(process.execPath, ['--input-type=module', '-e', program], { env: { PATH: '/usr/bin:/bin' }, timeout: 15000 });
  assert.equal(stdout, 'refund-evaluator-source-changed');
});
