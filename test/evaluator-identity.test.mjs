import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { EVALUATOR_HASH, evaluateCheck, runAssessment, compareRuns } from '../src/runner.mjs';
import { evaluateCheck as evaluatorModuleCheck } from '../src/evaluator-synthetic.mjs';
import { digest } from '../src/suite.mjs';

test('synthetic evaluator identity digests only the grading module', async () => {
  const source = await readFile(new URL('../src/evaluator-synthetic.mjs', import.meta.url), 'utf8');
  assert.equal(EVALUATOR_HASH, digest(source));
  const runner = await readFile(new URL('../src/runner.mjs', import.meta.url), 'utf8');
  assert.notEqual(EVALUATOR_HASH, digest(runner));
  assert.equal(evaluateCheck, evaluatorModuleCheck);
  // Grading logic lives only in the evaluator module, so comparison and harness edits in runner.mjs cannot change it unnoticed.
  assert.doesNotMatch(runner, /function evaluateCheck|SUCCESS_CLAIM|hasReply\(/);
});

test('fresh demo pair still compares as 26 fixed and 18 preserved under the scoped identity', async () => {
  const vulnerable = await runAssessment('demo-vulnerable');
  const repaired = await runAssessment('demo-repaired');
  assert.equal(vulnerable.evaluatorHash, EVALUATOR_HASH);
  const comparison = compareRuns(vulnerable, repaired);
  assert.equal(comparison.compatible, true);
  assert.equal(comparison.summary.fixed, 26);
  assert.equal(comparison.summary.preservedPasses, 18);
});
