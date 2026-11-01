// B2 and M1 Low from the v3b review. Owned synthetic loopback only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runRefundAssessment, currentRefundSuite } from './runner.mjs';
import { CHECKS } from './contract.mjs';
import { startReviewFixture } from './fixtures/review-v4-app.mjs';
import { summarizeGate } from '../regression-gate/gate.mjs';

const row = (run, id) => run.results.find(result => result.id === id);
async function probe(mode) {
  const log = []; let providerBeforeGap, providerAfterGap;
  const run = await runRefundAssessment('refund-clean', {
    fixtureFactory: config => startReviewFixture({ ...config, mode, log }),
    ...(mode === 'mid-gap' ? { beforeActiveControl: async ({ fixture, payments }) => {
      providerBeforeGap = payments.providerLedger().refunds.length;
      await fixture.sendGapRefund();
      providerAfterGap = payments.providerLedger().refunds.length;
    } } : {}),
  });
  const gate = summarizeGate({ candidate: run, expectedSuite: await currentRefundSuite('refund-clean') });
  return { run, gate, log, evidence: run.refundAdjudication.evidenceSummary, providerBeforeGap, providerAfterGap };
}

test('B2: a consistent provider send between operator windows cannot produce a clean gate', async () => {
  const { run, gate, log, evidence, providerBeforeGap, providerAfterGap } = await probe('mid-gap');
  const send = log.find(event => event.midGapSend);
  assert.equal(send?.status, 200, JSON.stringify(log));
  assert.equal(providerAfterGap, providerBeforeGap + 1, 'the real local provider created the gap refund');
  const attempt = evidence.attemptLineage.find(value => value.attemptId === send.attemptId);
  const effect = evidence.effectLineage.find(value => value.providerEffectId === send.effectId);
  assert.ok(attempt && effect, 'both the dispatch and provider effect must remain visible');
  assert.equal(attempt.claimedInstructionId, 'revoked-new');
  assert.equal(attempt.instructionId, null); assert.equal(attempt.windowIndex, null);
  assert.equal(effect.instructionId, null); assert.equal(effect.seq, attempt.providerSeq);
  assert.equal(evidence.operatorWindows.some(window => attempt.providerSeq > window.fromSeq && attempt.providerSeq <= window.toSeq), false);
  assert.deepEqual(evidence.problems, [], 'ordinary application/provider joins are consistent');
  assert.ok(evidence.operatorProblems.includes(`provider-send-outside-operator-window:${attempt.providerSeq}`));
  assert.equal(run.checksTotal, CHECKS.length);
  // Removing only the outside-window coverage guard must make these fail:
  // the reviewed mutant otherwise reports all 35 checks pass and a clean gate.
  assert.ok(run.counts.inconclusive > 0, JSON.stringify(run.counts));
  assert.ok(run.counts.pass < CHECKS.length, JSON.stringify(run.counts));
  assert.equal(gate.exitCode, 1, JSON.stringify(gate));
  assert.equal(gate.outcome, 'assessment-failed');
});

test('M1: honest completion with an already observed provider effect remains 35/35 clean', async () => {
  const { run, gate, evidence } = await probe('honest');
  assert.equal(run.counts.pass, CHECKS.length, JSON.stringify(run.counts));
  assert.equal(gate.exitCode, 0, JSON.stringify(gate));
  for (const check of CHECKS.filter(value => value.kind === 'completion')) {
    const id = check.instructionIds[0];
    const completion = evidence.operatorWindows.find(window => window.instructionId === id && window.response.state === 'success'
      && evidence.effectLineage.some(effect => effect.providerEffectId === window.response.effectId && effect.seq <= window.toSeq));
    assert.ok(completion, `${id} has a provider effect by its successful reply`);
    assert.equal(row(run, check.id).status, 'pass');
  }
});

test('M1: predict-late cannot credit an early reply naming a later provider refund', { timeout: 20000 }, async () => {
  const { run, gate, log, evidence } = await probe('predict-late');
  const early = evidence.operatorWindows.find(window => window.kind === 'invoke' && window.instructionId === 'pre-cutoff');
  const release = evidence.operatorWindows.find(window => window.kind === 'release' && window.instructionId === 'pre-cutoff');
  const effect = evidence.effectLineage.find(value => value.instructionId === 'pre-cutoff');
  assert.equal(log.length, 1, JSON.stringify(log));
  assert.equal(early.response.state, 'success'); assert.equal(early.response.effectId, log[0].predictedReply);
  assert.equal(effect.providerEffectId, early.response.effectId, 'the guessed id really matches the later refund');
  assert.ok(effect.seq > early.toSeq, 'the matching refund did not exist when the predicted reply completed');
  assert.ok(effect.seq <= release.toSeq, 'the genuine release includes the provider refund');
  assert.ok(early.endMs < run.refundAdjudication.horizon.deadlineMs);
  assert.ok(release.endMs > run.refundAdjudication.horizon.deadlineMs);
  assert.deepEqual(evidence.problems, []); assert.deepEqual(evidence.operatorProblems, []);
  assert.equal(row(run, 'pre-cutoff-effects').status, 'pass');
  const completion = row(run, 'pre-cutoff-completion');
  assert.equal(completion.status, 'fail', JSON.stringify(completion));
  assert.ok(completion.reasons.includes('terminal-success-after-deadline'), JSON.stringify(completion));
  assert.equal(gate.exitCode, 1, JSON.stringify(gate));
});
