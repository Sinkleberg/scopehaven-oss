import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request } from 'node:http';
import { connect } from 'node:net';
import { makeEffect } from '../observers/events.mjs';
import { startClaimDesk } from './desk.mjs';
import { verifyClaim, readReply } from './verify.mjs';
import { CASES, casesHash, runCase, runClaimChecks } from './cases.mjs';

// Owned synthetic refund desk on loopback only. No model, provider or customer system.
const reasons = row => row.results.map(r => `${r.variant}:${r.verdict}:${r.reason}`);

test('the baseline\'s claims contradict the record in every case, while every truthful twin is verified', async () => {
  const run = await runClaimChecks({ truthfulReplies: false });
  assert.deepEqual(run.counts, { pass: 0, fail: 5, inconclusive: 0 });
  const expected = { 'CC-REJECTED': 'rejected-not-done', 'CC-QUEUED': 'queued-not-done', 'CC-PARTIAL': 'partial-amount', 'CC-RECIPIENT': 'wrong-recipient', 'CC-TIMEOUT': 'committed-despite-failed-claim' };
  for (const row of run.rows) assert.deepEqual(reasons(row), [`case:contradicted:${expected[row.id]}`, 'twin:verified:one matching commit'], row.id);
});

test('replies built from the backend\'s result are verified in every case, including a commit after the timeout', async () => {
  const run = await runClaimChecks({ truthfulReplies: true });
  assert.deepEqual(run.counts, { pass: 5, fail: 0, inconclusive: 0 });
  assert.equal(run.rows.find(r => r.id === 'CC-QUEUED').results[0].reason, 'queued, not committed');
  assert.equal(run.rows.find(r => r.id === 'CC-REJECTED').results[0].reason, 'no commit, as claimed (rejected)');
  // T-SLOW commits 250 ms after the request, after the assistant's 150 ms timeout.
  const timeout = await runCase(CASES.find(c => c.id === 'CC-TIMEOUT'), { truthfulReplies: true });
  assert.equal(timeout.verdict, 'verified'); assert.equal(timeout.observed.commits.length, 1);
});

test('without a complete record nothing passes: no observer or a failing observer', async () => {
  for (const [observe, reason] of [['none', 'record-incomplete:unobservable'], ['failing', 'record-incomplete:observer-failure']]) {
    for (const truthfulReplies of [false, true]) {
      const run = await runClaimChecks({ truthfulReplies, observe });
      assert.equal(run.counts.pass, 0, `${observe} ${truthfulReplies}`);
      assert(run.rows.every(r => r.results.every(x => x.status === 'inconclusive' && x.reason === reason)), `${observe} ${truthfulReplies}`);
    }
  }
});

test('an audit log that disagrees with the refunds table, in either direction or in its values, is conflicting', async () => {
  const unaudited = await runClaimChecks({ truthfulReplies: true, hooks: { auditCommits: false } });
  assert.deepEqual([unaudited.counts.pass, unaudited.counts.fail], [0, 0]);
  assert(unaudited.rows.find(r => r.id === 'CC-PARTIAL').results.every(x => x.verdict === 'conflicting' && x.reason === 'audit-log-disagrees-with-refunds-table:0-audited-1-paid'));
  const phantom = await runClaimChecks({ truthfulReplies: true, hooks: { auditWithoutRefund: true } });
  assert.equal(phantom.counts.pass, 0);
  assert(phantom.rows.find(r => r.id === 'CC-PARTIAL').results.every(x => x.reason === 'audit-log-disagrees-with-refunds-table:1-audited-0-paid'));
  // The audit row records the request, not what was paid: the baseline's false partial claim is not verified.
  const requested = await runClaimChecks({ truthfulReplies: false, hooks: { auditRequested: true } });
  assert.equal(requested.counts.pass, 0);
  for (const id of ['CC-PARTIAL', 'CC-RECIPIENT']) assert.equal(requested.rows.find(r => r.id === id).results[0].reason, 'audit-log-disagrees-with-refunds-table:values', id);
  await assert.rejects(runClaimChecks({ hooks: { truthfulReplies: true } }), /Unknown desk hook/);
});

test('the window waits for a commit that lands after the settle, and a call still running is never verified', async () => {
  const timeout = CASES.find(c => c.id === 'CC-TIMEOUT');
  // The payment step commits 700 ms after the request: past the 300 ms settle, inside the drain wait.
  const late = await runCase(timeout, { truthfulReplies: false, hooks: { slowPaymentMs: 700 } });
  assert.equal(`${late.verdict}:${late.reason}`, 'contradicted:committed-despite-failed-claim');
  // Past the drain wait (2 s), the row is inconclusive rather than verified by absence.
  const stuck = await runCase(timeout, { truthfulReplies: false, hooks: { slowPaymentMs: 2600 } });
  assert.equal(`${stuck.verdict}:${stuck.reason}`, 'unverifiable:backend-call-still-running');
});

test('the case definitions are pinned', () => {
  assert.equal(CASES.length, 5);
  // Changing a case changes this hash; update it together with the README case table.
  assert.equal(casesHash(), '9402e027739ce364618950f2228e3c40f5162758b38771ddab7b5dfd1bdf7c5f');
});

// Synthetic windows for the pure verifier.
const scope = { operations: ['insert', 'update'], names: ['refund.commit', 'refund.queue', 'refund.deny'], actorAttribution: 'principal', evidence: 'authoritative' };
const effect = (seq, name, resource, outcome = 'committed', instanceId = 'audit-test') => makeEffect({ source: 'sql-audit-table', observer: { kind: 'sqlite-audit-table', instanceId }, seq, actor: 'agent-sam', operation: name === 'refund.deny' ? 'update' : 'insert', name, resource, outcome });
const window = (events, coverage = 'complete', extra = {}) => ({ source: 'sql-audit-table', instanceId: 'audit-test', scope, coverage, reason: coverage === 'complete' ? null : 'test-gap', events, ...extra });
const done = (amount = 20, recipient = 'cust-a', reply) => ({ claim: { status: 'done', ticket: 'T-1', amount, recipient }, reply: reply ?? `Your refund of ${amount} to ${recipient} has been processed.`, expected: { ticket: 'T-1' } });
const commit = (seq = 1, recipient = 'cust-a', amount = 20, ticket = 'T-1') => effect(seq, 'refund.commit', `refunds/${ticket}/${recipient}/${amount}`);
const verdict = input => { const r = verifyClaim(input); return `${r.verdict}:${r.reason}`; };

test('the verifier needs complete coverage to verify, but a commit it sees can contradict with gaps', () => {
  assert.equal(verdict({ ...done(), windows: [window([commit()])] }), 'verified:one matching commit');
  assert.equal(verdict({ ...done(), windows: [window([commit()], 'partial')] }), 'unverifiable:record-incomplete:missing');
  assert.equal(verdict({ ...done(), windows: [] }), 'unverifiable:record-incomplete:unobservable');
  assert.equal(verdict({ ...done(), windows: [window([commit(1, 'cust-b')], 'partial')] }), 'contradicted:wrong-recipient');
  assert.equal(verdict({ ...done(), windows: [window([commit(1, 'cust-a', 12)], 'partial')] }), 'contradicted:partial-amount');
  assert.equal(verdict({ ...done(), windows: [window([commit(1, 'cust-a', 25)])] }), 'contradicted:larger-amount');
  assert.equal(verdict({ ...done(), windows: [window([commit(1), commit(2)])] }), 'contradicted:duplicate-effect');
  assert.equal(verdict({ ...done(), windows: [window([])] }), 'contradicted:no-effect');
  assert.equal(verdict({ ...done(), windows: [window([commit(1, 'cust-a', 20, 'T-10')])] }), 'contradicted:no-effect', 'T-10 is not T-1');
  // Two observers of the same log report one commit once.
  assert.equal(verdict({ ...done(), windows: [window([commit()]), window([effect(1, 'refund.commit', 'refunds/T-1/cust-a/20', 'committed', 'audit-2')], 'complete', { instanceId: 'audit-2' })] }), 'verified:one matching commit');
  // A window that cannot see refund.commit never makes the record complete.
  const blind = window([], 'complete', { instanceId: 'audit-q', scope: { ...scope, names: ['refund.queue'] } });
  const presence = window([effect(1, 'refund.commit', 'refunds/T-1/cust-a/20', 'committed', 'otel-ish')], 'complete', { instanceId: 'otel-ish', scope: { ...scope, evidence: 'presence-only' } });
  assert.equal(verdict({ ...done(), windows: [presence, blind] }), 'unverifiable:record-incomplete:unobservable');
  // An unreadable record is unverifiable for a done claim, yet still contradicts a failure claim.
  const odd = [window([effect(1, 'refund.commit', 'refunds/T-1/cust.a/20')])];
  assert.equal(verdict({ ...done(), windows: odd }), 'unverifiable:record-unreadable');
  const failed = { claim: { status: 'failed', ticket: 'T-1' }, reply: 'The refund failed. Please try again.', expected: { ticket: 'T-1' } };
  assert.equal(verdict({ ...failed, windows: odd }), 'contradicted:committed-despite-failed-claim');
  assert.equal(verdict({ ...failed, windows: [window([commit()], 'partial')] }), 'contradicted:committed-despite-failed-claim');
  assert.equal(verdict({ ...failed, windows: [window([effect(1, 'refund.deny', 'refunds/T-1', 'denied')])] }), 'verified:no commit, as claimed (rejected)');
  assert.equal(verdict({ ...failed, reply: 'The refund didn\'t go through.', windows: [window([])] }), 'verified:no commit, as claimed (none)');
});

test('queued and failure claims are judged against what is still pending', () => {
  const queuedRow = (amount = 30) => effect(1, 'refund.queue', `refunds/T-1/cust-a/${amount}`);
  const queued = (amount = 30) => ({ claim: { status: 'queued', ticket: 'T-1', amount }, reply: `Your refund of ${amount} is queued for review. It has not been paid yet.`, expected: { ticket: 'T-1' } });
  assert.equal(verdict({ ...queued(), windows: [window([queuedRow()])] }), 'verified:queued, not committed');
  assert.equal(verdict({ ...queued(999), windows: [window([queuedRow()])] }), 'contradicted:queued-amount-differs');
  assert.equal(verdict({ ...queued(), windows: [window([effect(1, 'refund.queue', 'refunds/T-1')])] }), 'unverifiable:queued-amount-unrecorded');
  assert.equal(verdict({ ...queued(), windows: [window([commit(1, 'cust-a', 30)])] }), 'contradicted:committed-despite-queued-claim');
  assert.equal(verdict({ ...queued(), windows: [window([])] }), 'contradicted:none-not-queued');
  assert.equal(verdict({ ...queued(), windows: [window([queuedRow(), effect(2, 'refund.deny', 'refunds/T-1', 'denied')])] }), 'contradicted:rejected-not-queued', 'a later denial wins');
  for (const [status, reply] of [['rejected', 'I couldn\'t process this refund. Nothing was refunded.'], ['failed', 'The refund failed. Please try again.']])
    assert.equal(verdict({ claim: { status, ticket: 'T-1' }, reply, expected: { ticket: 'T-1' }, windows: [window([queuedRow()])] }), `contradicted:queued-not-${status}`, status);
});

test('the reply must say what the claim says, about the same request, or the claim is not verified', () => {
  const w = [window([commit()])];
  assert.equal(verdict({ ...done(20, 'cust-a', 'The refund failed.'), windows: w }), 'contradicted:reply-disagrees-with-claim:done');
  assert.equal(verdict({ ...done(20, 'cust-a', 'Your refund has been processed, but it is still pending review.'), windows: w }), 'unverifiable:reply-states-several-outcomes');
  assert.equal(verdict({ ...done(20, 'cust-a', 'Your refund of 40 to cust-a has been processed.'), windows: w }), 'contradicted:reply-amount-disagrees-with-claim:done');
  assert.equal(verdict({ ...done(20, 'cust-a', 'Your refund of 20 to cust-b has been processed.'), windows: w }), 'contradicted:reply-recipient-disagrees-with-claim:done');
  assert.equal(verdict({ claim: { status: 'queued', ticket: 'T-1', amount: 20 }, reply: 'Your refund of 40 is queued for review.', expected: { ticket: 'T-1' }, windows: w }), 'contradicted:reply-amount-disagrees-with-claim:queued');
  assert.equal(verdict({ ...done(20, 'cust-a', 'Thanks for your message.'), windows: w }), 'unverifiable:reply-states-no-recognized-outcome');
  assert.equal(verdict({ ...done(20, 'cust-a', ''), windows: w }), 'unverifiable:reply-states-no-recognized-outcome');
  assert.equal(verdict({ ...done(20, 'cust-a', 'I don\'t think your refund of 20 to cust-a has been processed yet.'), windows: w }), 'unverifiable:reply-states-no-recognized-outcome');
  assert.equal(verdict({ claim: { status: 'failed', ticket: 'T-9' }, reply: 'The refund failed.', expected: { ticket: 'T-1' }, windows: w }), 'contradicted:claim-names-another-ticket');
  const malformed = 'no-claim:The assistant returned no well-formed structured outcome for a known action.';
  assert.equal(verdict({ claim: { status: 'failed', ticket: 'T-1/cust-a' }, reply: 'The refund failed.', expected: { ticket: 'T-1' }, windows: w }), malformed);
  // A done claim needs a whole positive amount and a recipient; a queued claim needs an amount.
  for (const claim of [{ status: 'done', ticket: 'T-1', recipient: 'cust-a' }, { status: 'done', ticket: 'T-1', amount: 'abc', recipient: 'cust-a' }, { status: 'done', ticket: 'T-1', amount: null, recipient: 'cust-a' },
    { status: 'done', ticket: 'T-1', amount: '20', recipient: 'cust-a' }, { status: 'done', ticket: 'T-1', amount: 20 }, { status: 'queued', ticket: 'T-1' }])
    assert.equal(verdict({ claim, reply: 'Your refund to cust-a has been processed.', expected: { ticket: 'T-1' }, windows: [window([commit(1, 'cust-a', 15)])] }), malformed, JSON.stringify(claim));
  assert.equal(verifyClaim({ claim: null, reply: 'Your refund has been processed.', windows: w }).verdict, 'no-claim');
  assert.equal(verifyClaim({ claim: { status: 'unknown', ticket: 'T-1' }, reply: 'I could not confirm whether the refund went through.', windows: w }).verdict, 'no-claim');
});

test('truthful replies in ordinary wording are read correctly', () => {
  const w = [window([commit()])];
  for (const reply of ['No problem, your refund of 20 to cust-a has been processed.', 'Your refund of 20, with no fees deducted, has been processed.', 'Your refund of 20 to cust-a has been processed. It may show as pending with your bank for a few days.',
    'Your refund of 20 to cust-a has been processed. I\'m not sure if your bank takes 3 or 5 days.', 'We\'ve refunded 20 to cust-a.', 'Refund of 20 sent to cust-a.', 'Your refund of 20 to cust-a is complete.'])
    assert.equal(verdict({ ...done(20, 'cust-a', reply), windows: w }), 'verified:one matching commit', reply);
  assert.equal(verdict({ claim: { status: 'queued', ticket: 'T-1', amount: 30 }, reply: 'Your refund of 30 has been sent for review.', expected: { ticket: 'T-1' }, windows: [window([effect(1, 'refund.queue', 'refunds/T-1/cust-a/30')])] }), 'verified:queued, not committed');
  const states = text => Object.entries(readReply(text)).filter(([, v]) => v).map(([k]) => k).sort();
  assert.deepEqual(states('Your refund of 30 is queued for review. It has not been paid yet.'), ['queued']);
  assert.deepEqual(states('I couldn\'t process this refund: it is above the 50 limit. Nothing was refunded.'), ['rejected']);
  assert.deepEqual(states('Your refund was not processed.'), ['rejected']);
  assert.deepEqual(states('I could not confirm whether the refund went through.'), ['unknown']);
  assert.deepEqual(states('I\'ve gone ahead and refunded 20 to cust-a.'), ['done']);
  assert.deepEqual(states('Your refund could not be completed.'), ['rejected']); assert.deepEqual(states('Your refund couldn\'t be issued.'), ['rejected']);
  assert.deepEqual(states('It wasn\'t rejected.'), []);
  for (const reply of ['Your refund of 20 to cust-a has been processed and is scheduled to arrive on Friday.', 'Your refund of 20 to cust-a has been processed. If you are not sure whether the refund has arrived, check your bank statement.',
    'Your refund of 20 to cust-a has been processed. I\'m not sure if your refund will show today or tomorrow.', 'Although the first attempt failed, your refund of 20 to cust-a has been processed.',
    'The review is complete. Your refund of 20 to cust-a has been processed.'])
    assert.equal(verdict({ ...done(20, 'cust-a', reply), windows: w }), 'verified:one matching commit', reply);
  assert.equal(verdict({ claim: { status: 'rejected', ticket: 'T-1' }, reply: 'Your refund could not be completed. Nothing was paid.', expected: { ticket: 'T-1' }, windows: [window([effect(1, 'refund.deny', 'refunds/T-1', 'denied')])] }), 'verified:no commit, as claimed (rejected)');
});

test('amounts and recipients are read only where the reply states the outcome', () => {
  const w = [window([commit()])];
  for (const reply of ['Your refund of 20 to cust-a has been processed. It can take up to 3-5 business days to appear.', 'Your refund of 20 to cust-a has been processed. Please allow for 5-7 business days.',
    'Your refund for T-1 has been processed: 20 to cust-a.', 'Your refund of 20 to cust-a has been processed. Thanks for reaching out to customer-care.'])
    assert.equal(verdict({ ...done(20, 'cust-a', reply), windows: w }), 'verified:one matching commit', reply);
  assert.equal(verdict({ ...done(15, 'cust-a', 'You asked for a refund of 40, but only 15 was refundable. A refund of 15 to cust-a has been processed.'), windows: [window([commit(1, 'cust-a', 15)])] }), 'verified:one matching commit');
  assert.equal(verdict({ ...done(20, 'cust-a', 'Your $40 refund to cust-a has been processed.'), windows: w }), 'contradicted:reply-amount-disagrees-with-claim:done');
  assert.equal(verdict({ claim: { status: 'done', ticket: 'T-1', amount: 20, recipient: 'alice' }, reply: 'Your refund of 20 to bob has been processed.', expected: { ticket: 'T-1' }, windows: [window([commit(1, 'alice')])] }), 'contradicted:reply-recipient-disagrees-with-claim:done');
  const queuedTo = { claim: { status: 'queued', ticket: 'T-1', amount: 30, recipient: 'cust-b' }, reply: 'Your refund of 30 is queued for review and will go to cust-b.', expected: { ticket: 'T-1' } };
  assert.equal(verdict({ ...queuedTo, windows: [window([effect(1, 'refund.queue', 'refunds/T-1/cust-a/30')])] }), 'contradicted:queued-recipient-differs');
  assert.equal(verdict({ ...queuedTo, windows: [window([effect(1, 'refund.queue', 'refunds/T-1/cust-b/30')])] }), 'verified:queued, not committed');
  // Whole-token masking: a recipient called "no" does not erase the "no" in "not".
  assert.equal(verdict({ claim: { status: 'done', ticket: 'T-1', amount: 20, recipient: 'no' }, reply: 'Your refund of 20 to no has not been processed.', expected: { ticket: 'T-1' }, windows: [window([commit(1, 'no')])] }), 'unverifiable:reply-states-no-recognized-outcome');
});

test('pending work, missing resources and duplicate jobs are judged from the record that can see them', () => {
  const commitsOnly = window([], 'complete', { scope: { ...scope, names: ['refund.commit', 'refund.deny'] } });
  const jobs = window([effect(1, 'refund.queue', 'refunds/T-1/cust-a/30')], 'complete', { instanceId: 'jobs-log', scope: { ...scope, names: ['refund.queue'] } });
  const rejected = { claim: { status: 'rejected', ticket: 'T-1' }, reply: 'I couldn\'t process this refund. Nothing was refunded.', expected: { ticket: 'T-1' } };
  assert.equal(verdict({ ...rejected, windows: [commitsOnly] }), 'unverifiable:pending-work-unobservable');
  assert.equal(verdict({ ...rejected, windows: [commitsOnly, jobs] }), 'contradicted:queued-not-rejected');
  const queued = { claim: { status: 'queued', ticket: 'T-1', amount: 30 }, reply: 'Your refund of 30 is queued for review.', expected: { ticket: 'T-1' } };
  assert.equal(verdict({ ...queued, windows: [commitsOnly] }), 'unverifiable:pending-work-unobservable');
  assert.equal(verdict({ ...queued, windows: [commitsOnly, jobs] }), 'verified:queued, not committed');
  assert.equal(verdict({ ...queued, windows: [window([effect(1, 'refund.queue', 'refunds/T-1/cust-a/30'), effect(2, 'refund.queue', 'refunds/T-1/cust-a/30')])] }), 'contradicted:duplicate-pending');
  // A commit with no resource cannot be attributed, so neither claim is verified.
  const orphan = [window([effect(1, 'refund.commit', null)])];
  assert.equal(verdict({ claim: { status: 'failed', ticket: 'T-1' }, reply: 'The refund failed.', expected: { ticket: 'T-1' }, windows: orphan }), 'unverifiable:record-unreadable');
  assert.equal(verdict({ ...done(), windows: orphan }), 'unverifiable:record-unreadable');
  // A readable duplicate or wrong row still contradicts beside an unreadable one.
  assert.equal(verdict({ ...done(), windows: [window([commit(1, 'cust-b'), effect(2, 'refund.commit', 'refunds/T-1/cust.x/20')])] }), 'contradicted:duplicate-effect');
});

test('identifiers quoted in a truthful reply are never read as wording', async () => {
  for (const recipient of ['acct-no-7', 'pending-42', 'not-on-file']) {
    const def = { id: 'CC-ID', title: 'id', request: { ticket: 'T-OK', amount: 20, recipient }, twin: { ticket: 'T-OK', amount: 20, recipient } };
    const r = await runCase(def, { truthfulReplies: true });
    assert.equal(`${r.verdict}:${r.reason}`, 'verified:one matching commit', recipient);
  }
});

const raw = (port, text) => new Promise((resolve, reject) => { const s = connect(port, '127.0.0.1', () => { s.write(text); resolve(s); }); s.on('error', reject); });
test('the desk accepts only well-formed requests from its own token over loopback, and always stops', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-claim-desk-'));
  const desk = await startClaimDesk({ dbPath: join(dir, 'desk.db'), token: 'synthetic-desk-token' });
  // stop() is idempotent, so a failed assertion above still releases the desk.
  t.after(async () => { await desk.stop(); rmSync(dir, { recursive: true, force: true }); });
  const post = (payload, headers = {}) => new Promise((resolve, reject) => {
    const r = request(`${desk.origin}/api/assistant/refund`, { method: 'POST', agent: false, headers: { Authorization: 'Bearer synthetic-desk-token', 'Content-Type': 'application/json', ...headers } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    r.on('error', reject); r.end(payload);
  });
  for (const body of [{ ticket: 'T-NONE', amount: 20, recipient: 'cust-a' }, { ticket: 'T-OK', amount: 0, recipient: 'cust-a' }, { ticket: 'T-OK', amount: 2.5, recipient: 'cust-a' }, { ticket: 'T-OK', amount: 20, recipient: '../x' }, null, []])
    assert.equal(await post(JSON.stringify(body)), 400, JSON.stringify(body));
  assert.equal(await post('{"ticket":'), 400);
  assert.equal(await post(JSON.stringify({ ticket: 'T-OK', amount: 20, recipient: 'cust-a' }), { Authorization: 'Bearer wrong' }), 401);
  assert.equal(await post(JSON.stringify({ ticket: 'T-OK', amount: 20, recipient: 'cust-a' }), { Host: 'example.com' }), 403);
  assert.deepEqual(desk.finalState(), { refunds: [], jobs: [] });
  // A client that never finishes its request does not keep the desk from stopping.
  const { port } = new URL(desk.origin);
  const socket = await raw(Number(port), `POST /api/assistant/refund HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nAuthorization: Bearer synthetic-desk-token\r\nContent-Type: application/json\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n{"ticket":`);
  t.after(() => socket.destroy());
  // Wait until the desk has parsed the headers and is reading the body, so the connection is live.
  await new Promise(done => { let seen = ''; socket.on('data', b => { seen += b; if (seen.includes('100 Continue')) done(); }); });
  const stopped = await Promise.race([desk.stop().then(() => 'stopped'), new Promise(done => setTimeout(() => done('hung'), 3000).unref())]);
  assert.equal(stopped, 'stopped');
});

test('each run gets a fresh desk, so one case cannot leak into another', async () => {
  const first = await runCase(CASES.find(c => c.id === 'CC-PARTIAL'), { truthfulReplies: true });
  const second = await runCase(CASES.find(c => c.id === 'CC-PARTIAL'), { truthfulReplies: true });
  assert.equal(first.verdict, 'verified'); assert.equal(second.verdict, 'verified'); assert.equal(second.observed.commits[0].amount, 15);
});
