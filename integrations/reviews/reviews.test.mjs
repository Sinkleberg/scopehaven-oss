import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readdir, readFile, writeFile, copyFile, mkdir, unlink } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runAssessment, compareRuns } from '../../src/runner.mjs';
import { createStore } from '../../src/store.mjs';
import { renderSarif } from '../../src/sarif.mjs';
import { comparisonDocument } from '../../src/report.mjs';
import { summarizeGate } from '../regression-gate/gate.mjs';
import { generateSigningKey } from '../attest/sign.mjs';
import { createReviewStore, makeReview, validateReview, reviewSummary, annotateGateSummary, annotateExport, ReviewError, publishExclusive } from './reviews.mjs';
import { main } from './cli.mjs';

// Owned synthetic loopback fixture only; no model, provider or hosted service.
const vulnerable = await runAssessment('demo-vulnerable');
const repaired = await runAssessment('demo-repaired');
const keys = generateSigningKey(), otherKeys = generateSigningKey();
async function setup(t) {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-reviews-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const store = createStore(dir); await store.ready;
  const baseline = await store.save(structuredClone(vulnerable)), candidate = await store.save(structuredClone(repaired));
  return { dir, store, baseline, candidate, reviews: createReviewStore(dir) };
}
const failing = run => run.results.filter(r => r.status === 'fail');

test('a review is signed when recorded, verified when read, and an edited or foreign-key review is never counted', async t => {
  const { dir, baseline, reviews } = await setup(t);
  const [a, b] = failing(baseline);
  await reviews.record(baseline, makeReview({ reviewer: 'reviewer-1', runId: baseline.id, findingId: a.id, decision: 'agree' }), { privateKey: keys.privatePem });
  await reviews.record(baseline, makeReview({ reviewer: 'reviewer-2', runId: baseline.id, findingId: b.id, decision: 'dispute', reason: 'The denial text was valid; see the request log.' }), { privateKey: keys.privatePem });
  const read = await reviews.read(baseline.id, { publicKey: keys.publicPem });
  assert.deepEqual(read.map(e => e.verified), [true, true]);
  const summary = reviewSummary(baseline, read);
  assert.deepEqual([summary.reviewed, summary.agreed, summary.disputed, summary.unverified], [2, 1, 1, 0]);
  // Another key: nothing verifies, nothing is counted.
  assert.deepEqual(reviewSummary(baseline, await reviews.read(baseline.id, { publicKey: otherKeys.publicPem })).reviewed, 0);
  // An edited review file: that review is unverified and not counted.
  const where = join(dir, 'reviews', baseline.id), file = (await readdir(where)).filter(f => f.endsWith('.review.json')).sort()[1];
  await writeFile(join(where, file), (await readFile(join(where, file), 'utf8')).replace('"dispute"', '"agree"'));
  const edited = reviewSummary(baseline, await reviews.read(baseline.id, { publicKey: keys.publicPem }));
  assert.deepEqual([edited.reviewed, edited.disputed, edited.unverified], [1, 0, 1]);
});

test('verdicts, comparison labels and gate exit codes are byte-identical with and without reviews', async t => {
  const { store, baseline, candidate, reviews } = await setup(t);
  const computed = async () => {
    const [b, c] = [await store.get(baseline.id), await store.get(candidate.id)];
    return JSON.stringify({ verdicts: [b.results, c.results], integrity: [b.integrity, c.integrity], comparison: compareRuns(b, c), gateOne: summarizeGate({ candidate: b }), gateTwo: summarizeGate({ candidate: c, baseline: b }) });
  };
  const before = await computed();
  for (const r of failing(baseline)) await reviews.record(baseline, makeReview({ reviewer: 'reviewer-1', runId: baseline.id, findingId: r.id, decision: 'dispute', reason: 'Disputed for the test.' }), { privateKey: keys.privatePem });
  for (const r of candidate.results.slice(0, 5)) await reviews.record(candidate, makeReview({ reviewer: 'reviewer-1', runId: candidate.id, findingId: r.id, decision: 'agree' }), { privateKey: keys.privatePem });
  assert.equal(await computed(), before);
});

test('a dispute on a failed check appears as "reviewer disputes" in the gate summary, with the exit code as computed', async t => {
  const { baseline, reviews } = await setup(t);
  const target = failing(baseline)[0];
  await reviews.record(baseline, makeReview({ reviewer: 'reviewer-2', runId: baseline.id, findingId: target.id, decision: 'dispute', reason: 'Reworded denial.' }), { privateKey: keys.privatePem });
  const gate = summarizeGate({ candidate: baseline });
  const annotated = annotateGateSummary(gate, reviewSummary(baseline, await reviews.read(baseline.id, { publicKey: keys.publicPem })));
  assert.deepEqual([annotated.exitCode, annotated.outcome, annotated.reasons], [gate.exitCode, gate.outcome, gate.reasons]);
  assert.equal(gate.exitCode, 1);
  const { reviews: added, ...rest } = annotated;
  assert.equal(JSON.stringify(rest), JSON.stringify(gate), 'every computed field copied as is');
  assert.deepEqual(added.lines, [`${target.id}: reviewer disputes (reviewer-2, ${added.lines[0].match(/\(reviewer-2, ([^)]+)\)/)[1]}): Reworded denial.`]);
  assert.equal(added.disputed, 1);
  // A dispute on a passing check is counted but is not a gate line.
  const passing = baseline.results.find(r => r.status === 'pass');
  await reviews.record(baseline, makeReview({ reviewer: 'reviewer-2', runId: baseline.id, findingId: passing.id, decision: 'dispute', reason: 'Should have failed.' }), { privateKey: keys.privatePem });
  const twice = annotateGateSummary(gate, reviewSummary(baseline, await reviews.read(baseline.id, { publicKey: keys.publicPem })));
  assert.deepEqual([twice.reviews.disputed, twice.reviews.lines.length], [2, 1]);
});

test('exports show reviewed and disputed counts beside the results, and the latest review of a finding decides', async t => {
  const { baseline, candidate, reviews } = await setup(t);
  const target = failing(baseline)[0];
  for (const decision of ['agree', 'dispute']) await reviews.record(baseline, makeReview({ reviewer: 'reviewer-1', runId: baseline.id, findingId: target.id, decision, reason: decision === 'dispute' ? 'Changed my mind.' : '' }), { privateKey: keys.privatePem });
  const summary = reviewSummary(baseline, await reviews.read(baseline.id, { publicKey: keys.publicPem }));
  assert.deepEqual([summary.reviewed, summary.agreed, summary.disputed], [1, 0, 1]);
  const sarif = renderSarif(baseline), withReviews = annotateExport(sarif, summary);
  assert.deepEqual([withReviews.runs[0].properties.reviews.reviewed, withReviews.runs[0].properties.reviews.disputed], [1, 1]);
  assert.deepEqual(withReviews.runs[0].results, sarif.runs[0].results, 'results unchanged');
  const doc = comparisonDocument(baseline, candidate, compareRuns(baseline, candidate)), docWith = annotateExport(doc, summary);
  assert.deepEqual([docWith.reviews.disputed, docWith.reviews.runId, docWith.reviews.role], [1, baseline.id, 'baseline']);
  assert.deepEqual(docWith.comparison, doc.comparison);
});

test('reviews are validated: a known finding of this run, a decision, a reason for a dispute, no extra fields', async t => {
  const { baseline, reviews } = await setup(t);
  const id = failing(baseline)[0].id, ok = makeReview({ reviewer: 'r', runId: baseline.id, findingId: id, decision: 'agree' });
  assert.equal(validateReview(ok, baseline), ok);
  for (const bad of [{ ...ok, findingId: 'NOT-A-CHECK' }, { ...ok, runId: 'another-run' }, { ...ok, decision: 'maybe' }, { ...ok, decision: 'dispute', reason: ' ' }, { ...ok, extra: 1 }, { ...ok, at: 'yesterday' }, { ...ok, reviewer: '' }])
    assert.throws(() => validateReview(bad, baseline), ReviewError);
  await assert.rejects(reviews.record(baseline, { ...ok, decision: 'dispute' }, { privateKey: keys.privatePem }), ReviewError);
  assert.deepEqual(await reviews.read(baseline.id, { publicKey: keys.publicPem }), []);
});

test('the CLI records a signed review and prints the counts', async t => {
  const { dir, baseline } = await setup(t);
  const key = join(dir, 'review.pem'), pub = join(dir, 'review.pub.pem');
  await writeFile(key, keys.privatePem, { mode: 0o600 }); await writeFile(pub, keys.publicPem);
  const recorded = await main(['record', '--data', dir, '--run', baseline.id, '--finding', failing(baseline)[0].id, '--decision', 'dispute', '--reason', 'Reworded denial.', '--reviewer', 'reviewer-3', '--key', key]);
  assert.equal(recorded.decision, 'dispute');
  const summary = await main(['summary', '--data', dir, '--run', baseline.id, '--pub', pub]);
  assert.deepEqual([summary.reviewed, summary.disputed], [1, 1]);
  await assert.rejects(main(['record', '--data', dir, '--run', baseline.id, '--finding', 'NOT-A-CHECK', '--decision', 'agree', '--reviewer', 'r', '--key', key]), ReviewError);
});

test('a signed review moved to another run never counts there, and published files are never replaced', async t => {
  const { dir, baseline, candidate, reviews } = await setup(t);
  await reviews.record(baseline, makeReview({ reviewer: 'reviewer-1', runId: baseline.id, findingId: failing(baseline)[0].id, decision: 'agree' }), { privateKey: keys.privatePem });
  const from = join(dir, 'reviews', baseline.id), to = join(dir, 'reviews', candidate.id);
  await mkdir(to, { recursive: true });
  for (const f of await readdir(from)) await copyFile(join(from, f), join(to, f));
  const moved = await reviews.read(candidate.id, { publicKey: keys.publicPem });
  assert.deepEqual(moved.map(e => e.verified), [false], 'the signature verifies, but the review is of another run');
  assert.equal(reviewSummary(candidate, moved).reviewed, 0);
  const file = join(dir, 'published.json');
  await publishExclusive(file, Buffer.from('first'));
  await assert.rejects(publishExclusive(file, Buffer.from('second')), /EEXIST/);
  assert.equal(await readFile(file, 'utf8'), 'first');
});

test('review counts name their run: a gate summary, SARIF log or comparison of another run is refused', async t => {
  const { baseline, candidate, reviews } = await setup(t);
  for (const r of failing(baseline)) await reviews.record(baseline, makeReview({ reviewer: 'reviewer-1', runId: baseline.id, findingId: r.id, decision: 'dispute', reason: 'Disputed.' }), { privateKey: keys.privatePem });
  const summary = reviewSummary(baseline, await reviews.read(baseline.id, { publicKey: keys.publicPem }));
  assert.equal(summary.runId, baseline.id);
  const mismatch = e => e instanceof ReviewError && e.code === 'run-mismatch';
  // The clean candidate's gate summary never shows the baseline's disputes.
  const cleanGate = summarizeGate({ candidate });
  assert.throws(() => annotateGateSummary(cleanGate, summary), mismatch);
  assert.throws(() => annotateGateSummary({ ...cleanGate, current: null }, summary), mismatch);
  assert.equal(annotateGateSummary(summarizeGate({ candidate: baseline }), summary).reviews.runId, baseline.id);
  assert.throws(() => annotateExport(renderSarif(candidate), summary), mismatch);
  const foreignSarif = renderSarif(baseline); delete foreignSarif.runs[0].properties.runId;
  assert.throws(() => annotateExport(foreignSarif, summary), mismatch, 'a log that does not name its run cannot carry them');
  // A comparison holding the run names its role; one without it is refused; other documents are refused.
  assert.equal(annotateExport(comparisonDocument(candidate, baseline, compareRuns(candidate, baseline)), summary).reviews.role, 'candidate');
  assert.throws(() => annotateExport(comparisonDocument(candidate, candidate, compareRuns(candidate, candidate)), summary), mismatch);
  assert.throws(() => annotateExport({ schema: 'something-else' }, summary), e => e.code === 'document');
  // The caller's document is never changed; the counts are the summary's.
  const sarif = renderSarif(baseline), before = JSON.stringify(sarif);
  const out = annotateExport(sarif, { ...summary, agreed: 2, disputed: 3 });
  assert.equal(JSON.stringify(sarif), before);
  assert.deepEqual([out.runs[0].properties.reviews.agreed, out.runs[0].properties.reviews.disputed], [2, 3]);
});

test('an unsigned review, a review of a check the run does not have, and a private key as the reviewer key are never counted', async t => {
  const { dir, baseline, reviews } = await setup(t);
  const [a, b] = failing(baseline);
  await reviews.record(baseline, makeReview({ reviewer: 'reviewer-1', runId: baseline.id, findingId: a.id, decision: 'agree' }), { privateKey: keys.privatePem });
  // Envelope removed, and an unsigned review planted.
  const where = join(dir, 'reviews', baseline.id);
  await unlink(join(where, '00001.dsse.json'));
  await writeFile(join(where, '00002.review.json'), `${JSON.stringify(makeReview({ reviewer: 'nobody', runId: baseline.id, findingId: b.id, decision: 'dispute', reason: 'Unsigned.' }), null, 1)}\n`);
  const read = await reviews.read(baseline.id, { publicKey: keys.publicPem });
  assert.deepEqual(read.map(e => e.verified), [false, false]);
  assert.deepEqual((({ reviewed, unverified }) => [reviewed, unverified])(reviewSummary(baseline, read)), [0, 2]);
  // A verified review of a check this run does not have is shown as outside the run, never counted.
  const { dir: dir2, baseline: base2, reviews: reviews2 } = await setup(t);
  await reviews2.record(base2, makeReview({ reviewer: 'reviewer-1', runId: base2.id, findingId: failing(base2)[0].id, decision: 'agree' }), { privateKey: keys.privatePem });
  const fewer = { ...base2, results: base2.results.filter(r => r.id !== failing(base2)[0].id) };
  assert.deepEqual((({ reviewed, outsideRun }) => [reviewed, outsideRun])(reviewSummary(fewer, await reviews2.read(base2.id, { publicKey: keys.publicPem }))), [0, 1]);
  await assert.rejects(reviews2.read(base2.id, { publicKey: keys.privatePem }), 'a private key is not a reviewer key');
  // A path that is not a run id never reaches the file system.
  await assert.rejects(reviews2.read('../../etc', { publicKey: keys.publicPem }), e => e.code === 'run-id');
  void dir2;
});

test('reviewer names and reasons cannot carry line breaks or control characters, and two reviews recorded at once get their own numbers', async t => {
  const { dir, baseline, reviews } = await setup(t);
  const id = failing(baseline)[0].id;
  for (const field of [{ reviewer: 'r\nOutcome: clean' }, { reason: 'ok\r\nexitCode: 0', decision: 'dispute' }, { reviewer: 'r\u2028x' }, { reason: 'tab\there', decision: 'dispute' }])
    assert.throws(() => validateReview(makeReview({ reviewer: 'r', runId: baseline.id, findingId: id, decision: 'agree', ...field }), baseline), ReviewError, JSON.stringify(field));
  const both = await Promise.all(['reviewer-1', 'reviewer-2'].map(reviewer => reviews.record(baseline, makeReview({ reviewer, runId: baseline.id, findingId: id, decision: 'agree' }), { privateKey: keys.privatePem })));
  assert.deepEqual(both.map(r => r.name).sort(), ['00001.review.json', '00002.review.json']);
  assert.deepEqual((await readdir(join(dir, 'reviews', baseline.id))).sort(), ['00001.dsse.json', '00001.review.json', '00002.dsse.json', '00002.review.json']);
});

test('recording continues past a gap, a planted review and a leftover envelope; outsideRun counts verified reviews of this run only; format characters are refused (R2-1, R2-2, R2-4)', async t => {
  const { dir, baseline, reviews } = await setup(t);
  const id = failing(baseline)[0].id, where = join(dir, 'reviews', baseline.id);
  const record = reviewer => reviews.record(baseline, makeReview({ reviewer, runId: baseline.id, findingId: id, decision: 'agree' }), { privateKey: keys.privatePem });
  await record('r1'); await record('r2');
  await unlink(join(where, '00001.review.json')); await unlink(join(where, '00001.dsse.json'));
  assert.equal((await record('r3')).name, '00003.review.json', 'after a gap');
  await writeFile(join(where, '00004.review.json'), '{}\n');
  assert.equal((await record('r4')).name, '00005.review.json', 'after a planted review');
  await writeFile(join(where, '00006.dsse.json'), '{}\n');
  assert.equal((await record('r5')).name, '00007.review.json', 'after a leftover envelope');
  // A long run of leftover envelopes (more than the 32 collision retries) does not block recording either.
  for (let n = 8; n <= 50; n++) await writeFile(join(where, `${String(n).padStart(5, '0')}.dsse.json`), '{}\n');
  assert.equal((await record('r6')).name, '00051.review.json', 'after 43 leftover envelopes');
  const read = await reviews.read(baseline.id, { publicKey: keys.publicPem });
  assert.deepEqual(read.map(e => [e.name, e.verified]), [['00002.review.json', true], ['00003.review.json', true], ['00004.review.json', false], ['00005.review.json', true], ['00007.review.json', true], ['00051.review.json', true]]);
  // outsideRun: verified reviews of this run whose check the run does not have, and nothing else.
  const review = (runId, findingId) => ({ runId, findingId, decision: 'agree', reviewer: 'r', at: '2026-10-07T00:00:00Z', reason: '' });
  const summary = reviewSummary(baseline, [{ verified: true, review: review(baseline.id, 'NOT-A-CHECK') }, { verified: false, review: review(baseline.id, 'NOT-A-CHECK-EITHER') }, { verified: true, review: review('00000000-0000-4000-8000-000000000000', 'NOT-A-CHECK') }]);
  assert.deepEqual([summary.outsideRun, summary.unverified, summary.reviewed], [1, 1, 0]);
  for (const text of ['a\u202Eb', 'a\u2066b\u2069', 'a\u200Bb', '\uFEFFa', 'a\u00ADb'])
    assert.throws(() => validateReview(makeReview({ reviewer: text, runId: baseline.id, findingId: id, decision: 'agree' }), baseline), ReviewError, JSON.stringify(text));
  assert.ok(validateReview(makeReview({ reviewer: 'Zo\u00EB \u00C5ngstr\u00F6m \u674E', runId: baseline.id, findingId: id, decision: 'agree' }), baseline), 'letters of any script are fine');
});

test('the CLI exits 2 on an error', () => {
  const cli = fileURLToPath(new URL('./cli.mjs', import.meta.url));
  const r = spawnSync(process.execPath, [cli, 'summary', '--data', 'relative/path', '--run', 'x', '--pub', 'y'], { encoding: 'utf8' });
  assert.equal(r.status, 2, r.stderr);
});
