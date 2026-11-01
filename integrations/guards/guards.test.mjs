import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request } from 'node:http';
import { createAccessGuard, createClaimGuard, guardCommits, GuardDenied, CLAIM_MESSAGES } from './guards.mjs';
import { readReply } from '../claim-check/verify.mjs';
import { startGuardedApp, TASK_EFFECTS } from './guarded-app.mjs';

// Owned synthetic app on loopback only. No model, provider or customer system.
const TOKENS = { 'agent-sam': 'synthetic-sam-token-g', 'agent-tia': 'synthetic-tia-token-g', 'owner-olga': 'synthetic-olga-token-g' };

// ---------------------------------------------------------------- access guard
// A store the test moves between calls, so "reads fresh every time" is testable.
function store(initial = { active: true, grantsVersion: 1 }) {
  const state = { ...initial, reads: 0, unreadable: false };
  const currentAccess = () => { state.reads += 1; return state.unreadable ? null : { active: state.active, grantsVersion: state.grantsVersion, ...(state.allows ? { allows: state.allows } : {}) }; };
  return { state, currentAccess };
}
const denial = async (fn, reason, label = '') => { await assert.rejects(fn, error => { assert(error instanceof GuardDenied, `${label}: not a GuardDenied`); assert.equal(error.reason, reason, label); return true; }); };

test('the access guard denies a commit once the authority behind the work changed', async () => {
  for (const [label, change, reason] of [
    ['suspended mid-task', s => { s.active = false; }, 'principal-inactive'],
    ['suspended then regranted', s => { s.active = true; s.grantsVersion = 2; }, 'grants-changed'],
    ['permission removed', s => { s.allows = () => false; }, 'permission-revoked'],
    ['access no longer readable', s => { s.unreadable = true; }, 'access-unreadable'],
  ]) {
    const decisions = [];
    const { state, currentAccess } = store();
    const guard = createAccessGuard({ currentAccess, onDecision: d => decisions.push(d) });
    const turn = await guard.beginTurn('agent-sam');
    // The same commit is allowed before the change and denied after it.
    await guard.beforeCommit(turn, { action: 'note.added', resource: 'tickets/T-1' });
    change(state);
    await denial(() => guard.beforeCommit(turn, { action: 'note.added', resource: 'tickets/T-1' }), reason, label);
    assert.deepEqual(decisions.map(d => `${d.step}:${d.allowed}`), ['begin:true', 'commit:true', 'commit:false'], label);
    assert.equal(decisions.at(-1).reason, reason, label);
  }
});

test('the access guard reads the app\'s store on every commit, never a cached copy', async () => {
  const { state, currentAccess } = store();
  const guard = createAccessGuard({ currentAccess });
  const turn = await guard.beginTurn('agent-sam');
  const afterBegin = state.reads;
  for (const action of TASK_EFFECTS) await guard.beforeCommit(turn, { action });
  assert.equal(state.reads, afterBegin + TASK_EFFECTS.length, 'one fresh read per commit');
});

test('the access guard refuses to start a turn the principal cannot have', async () => {
  const { state, currentAccess } = store({ active: false, grantsVersion: 1 });
  const guard = createAccessGuard({ currentAccess });
  await denial(() => guard.beginTurn('agent-sam'), 'principal-inactive');
  state.active = true; state.unreadable = true;
  await denial(() => guard.beginTurn('agent-sam'), 'access-unreadable');
  // A store that throws is unreadable, not a pass.
  const throwing = createAccessGuard({ currentAccess: () => { throw new Error('db down'); } });
  await denial(() => throwing.beginTurn('agent-sam'), 'access-unreadable');
  // A malformed answer is unreadable too. A grants version that cannot be compared by
  // value is a contract error: null would make the check never fire, and an object or
  // NaN would deny every commit, so both are reported rather than silently applied.
  for (const bad of [null, {}, { active: true }, { grantsVersion: 1 }, 'yes',
    { active: true, grantsVersion: null }, { active: true, grantsVersion: NaN }, { active: true, grantsVersion: { v: 1 } }, { active: true, grantsVersion: [1] }]) {
    const guard2 = createAccessGuard({ currentAccess: () => bad });
    await denial(() => guard2.beginTurn('agent-sam'), 'access-unreadable');
  }
  assert.throws(() => createAccessGuard({}), TypeError);
});

test('a grants version is compared by value, and only a comparable one is accepted', async () => {
  const pair = async (begin, commit) => {
    let reads = 0;
    const guard = createAccessGuard({ currentAccess: () => ({ active: true, grantsVersion: reads++ === 0 ? begin : commit }) });
    const turn = await guard.beginTurn('agent-sam');
    return guard.beforeCommit(turn, { action: 'note.added' }).then(() => 'allowed', error => error.reason);
  };
  for (const [begin, commit, expected, label] of [[3, 3, 'allowed', 'same number'], ['v3', 'v3', 'allowed', 'same string'], [3n, 3n, 'allowed', 'same bigint'],
    [3, 4, 'grants-changed', 'moved'], [3, '3', 'grants-changed', 'number then numeric string is still a different value'], [3, 3n, 'grants-changed', 'number then bigint']])
    assert.equal(await pair(begin, commit), expected, label);
  // A version that cannot be compared is reported at the start, not silently applied later.
  for (const bad of [null, NaN, { v: 1 }]) await denial(() => pair(bad, bad), 'access-unreadable', String(bad));
});

test('an access view the guard cannot act on is unreadable, not an allowed one', async () => {
  // `allows` that is data rather than a function would skip the permission check.
  for (const allows of ['deny-everything', false, { note: false }, null, 0]) {
    const guard = createAccessGuard({ currentAccess: () => ({ active: true, grantsVersion: 1, allows }) });
    await denial(() => guard.beginTurn('agent-sam'), 'access-unreadable', JSON.stringify(allows));
  }
  // `allows` absent is fine: the app simply has no per-action rule.
  const open = createAccessGuard({ currentAccess: () => ({ active: true, grantsVersion: 1 }) });
  await open.beforeCommit(await open.beginTurn('agent-sam'), { action: 'note.added' });
  // A permission check that throws is unreadable, and the denial is still audited.
  const decisions = [];
  const throwing = createAccessGuard({ currentAccess: () => ({ active: true, grantsVersion: 1, allows: () => { throw new Error('acl store down'); } }), onDecision: d => decisions.push(d) });
  const turn = await throwing.beginTurn('agent-sam');
  await denial(() => throwing.beforeCommit(turn, { action: 'note.added' }), 'access-unreadable');
  assert.deepEqual(decisions.map(d => `${d.step}:${d.allowed}:${d.reason ?? ''}`), ['begin:true:', 'commit:false:access-unreadable']);
});

test('only the turn object beginTurn returned is accepted, so a copy cannot carry a stale version', async () => {
  const state = { active: true, grantsVersion: 1 };
  const guard = createAccessGuard({ currentAccess: () => ({ ...state }) });
  const turn = await guard.beginTurn('agent-sam');
  state.grantsVersion = 2;
  // A copy taken from the turn and refreshed would otherwise compare the live version with itself.
  await assert.rejects(() => guard.beforeCommit({ ...turn, grantsVersion: 2 }, { action: 'note.added' }), TypeError);
  await assert.rejects(() => guard.beforeCommit({ id: turn.id, principalId: turn.principalId, grantsVersion: 2 }, { action: 'note.added' }), TypeError);
  // The real turn is still judged on the version it started under.
  await denial(() => guard.beforeCommit(turn, { action: 'note.added' }), 'grants-changed');
  // A turn from another guard is not this guard's turn either.
  const other = createAccessGuard({ currentAccess: () => ({ active: true, grantsVersion: 1 }) });
  const otherTurn = await other.beginTurn('agent-sam');
  await assert.rejects(() => guard.beforeCommit(otherTurn, { action: 'note.added' }), TypeError);
});

test('guardCommits checks before the effect runs, so a denied call commits nothing', async () => {
  const { state, currentAccess } = store();
  const guard = createAccessGuard({ currentAccess });
  const ran = [];
  const turn = await guard.beginTurn('agent-sam');
  const guarded = guardCommits({ guard, turn, effects: { 'note.added': t => { ran.push(t); return true; } }, resourceOf: (_a, t) => `tickets/${t}` });
  assert.equal(await guarded['note.added']('T-1'), true);
  state.active = false;
  await denial(() => guarded['note.added']('T-2'), 'principal-inactive');
  assert.deepEqual(ran, ['T-1'], 'the denied effect never ran');
  // The audit entry names the resource the wrapper derived.
  const decisions = [];
  const guard2 = createAccessGuard({ currentAccess: store().currentAccess, onDecision: d => decisions.push(d) });
  const turn2 = await guard2.beginTurn('agent-sam');
  await guardCommits({ guard: guard2, turn: turn2, effects: { 'note.added': () => true }, resourceOf: (_a, t) => `tickets/${t}` })['note.added']('T-9');
  assert.equal(decisions.at(-1).resource, 'tickets/T-9');
  assert.throws(() => guardCommits({ guard, turn, effects: null }), TypeError);
  // An effect written as a method still reaches the object it belongs to, and a
  // non-function entry is left alone rather than wrapped into something uncallable.
  const guard3 = createAccessGuard({ currentAccess: store().currentAccess });
  const turn3 = await guard3.beginTurn('agent-sam');
  const effects = { rows: [], 'note.added'(ticket) { this.rows.push(ticket); return true; } };
  const wrapped = guardCommits({ guard: guard3, turn: turn3, effects });
  assert.equal(await wrapped['note.added']('T-7'), true);
  assert.deepEqual(effects.rows, ['T-7'], 'the effect kept its own receiver');
  assert.deepEqual(Object.keys(wrapped), ['note.added'], 'only callable entries are wrapped');
});

test('the access guard rejects a turn or action it was not given', async () => {
  const guard = createAccessGuard({ currentAccess: store().currentAccess });
  const turn = await guard.beginTurn('agent-sam');
  await assert.rejects(() => guard.beforeCommit(turn, {}), TypeError);
  for (const bad of [null, {}, { principalId: 'agent-sam' }, 'turn-1']) await assert.rejects(() => guard.beforeCommit(bad, { action: 'note.added' }), TypeError);
  await assert.rejects(() => guard.beginTurn(null), TypeError);
});

// ----------------------------------------------------------------- claim guard
const review = (reply, committed, claim = { status: 'done' }, identifiers = []) =>
  createClaimGuard().review({ claim, reply, record: committed === undefined ? null : { committed }, identifiers });
const verdictOf = (...args) => { const r = review(...args); return `${r.verdict}:${r.reason}`; };

test('the claim guard lets a true success through and replaces one the record does not show', () => {
  const done = 'All 3 steps have been completed successfully.';
  const kept = review(done, true);
  assert.equal(`${kept.verdict}:${kept.replaced}`, 'supported:false');
  assert.equal(kept.reply, done, 'a supported reply is passed through unchanged');
  const blocked = review(done, false);
  assert.equal(`${blocked.verdict}:${blocked.reason}`, 'unsupported:claimed-success-but-nothing-committed');
  assert.equal(blocked.reply, CLAIM_MESSAGES.unsupported);
  assert.equal(blocked.replaced, true);
  // An unreadable record can never support a success claim.
  const unknown = review(done, undefined);
  assert.equal(`${unknown.verdict}:${unknown.reason}`, 'unverifiable:outcome-not-readable');
  assert.equal(unknown.reply, CLAIM_MESSAGES.unverifiable);
});

test('the claim guard also catches a failure claim the record contradicts', () => {
  const failed = 'The refund failed. Please try again.';
  assert.equal(verdictOf(failed, false, { status: 'failed' }), 'supported:no-commit-recorded');
  // Telling the user it failed when it committed invites a second payment.
  const doubled = review(failed, true, { status: 'failed' });
  assert.equal(`${doubled.verdict}:${doubled.reason}`, 'unsupported:claimed-failure-but-effect-committed');
  assert.equal(doubled.reply, CLAIM_MESSAGES.unverifiable);
  assert.equal(verdictOf(failed, undefined, { status: 'failed' }), 'unverifiable:outcome-not-readable');
});

test('the claim guard reads the reply the customer will read, with negation and ids', () => {
  // A structured claim of success is caught even when the text is neutral.
  assert.equal(verdictOf('Thanks for your patience.', false, { status: 'done' }), 'unsupported:claimed-success-but-nothing-committed');
  // Neither the text nor the claim asserts anything, so there is nothing to contradict.
  assert.equal(verdictOf('Thanks for your patience.', false, null), 'no-claim:reply-asserts-no-outcome');
  assert.equal(review('Thanks for your patience.', false, null).replaced, false);
  // A negated statement is not a success claim.
  assert.equal(verdictOf('Your refund was not processed.', false, null), 'supported:no-commit-recorded');
  // Saying both leaves the user guessing. The effect did commit, so the replacement
  // must not be the "nothing was changed" wording.
  const both = review('It has been processed, but the refund failed.', true, null);
  assert.equal(`${both.verdict}:${both.reason}`, 'unsupported:reply-asserts-both-outcomes');
  assert.equal(both.reply, CLAIM_MESSAGES.unverifiable);
  // A success reply that also mentions pending follow-up work is ordinary wording.
  assert.equal(verdictOf('Your refund has been processed. The receipt is queued for approval.', true, null), 'supported:commit-recorded');
  // An id that reads like wording is masked before the reply is read. Without masking the
  // "no" inside the id reads as a negation, the success claim is missed, and a reply saying
  // the work was done would pass through to the user even though nothing committed.
  assert.equal(verdictOf('Refund for T-no-1 has been processed.', false, null, ['T-no-1']), 'unsupported:claimed-success-but-nothing-committed');
  assert.equal(review('Refund for T-no-1 has been processed.', false, null, ['T-no-1']).replaced, true);
  assert.equal(verdictOf('Refund for T-no-1 has been processed.', true, null, ['T-no-1']), 'supported:commit-recorded');
});

test('a reply that says the work is still pending is checked against the record too', () => {
  const pending = 'Your refund is queued for approval.';
  assert.equal(readReply(pending).queued, true, 'the shared reader does recognise this wording');
  // Nothing committed yet, which is what "queued" says.
  assert.equal(verdictOf(pending, false, { status: 'queued' }), 'supported:no-commit-recorded');
  // The effect did land: telling the user it is still pending invites a second request.
  const landed = review(pending, true, { status: 'queued' });
  assert.equal(`${landed.verdict}:${landed.reason}`, 'unsupported:claimed-pending-but-effect-committed');
  assert.equal(landed.reply, CLAIM_MESSAGES.unverifiable);
  assert.equal(verdictOf(pending, undefined, { status: 'queued' }), 'unverifiable:outcome-not-readable');
});

test('a partial record is never reported as nothing, whatever was claimed', () => {
  const part = { committed: false, effects: 1, expected: 3 };
  const guard = createClaimGuard();
  for (const [reply, claim, reason] of [
    ['All 3 steps have been completed.', { status: 'done' }, 'claimed-success-but-part-committed'],
    ['The refund failed.', { status: 'failed' }, 'claimed-failure-but-part-committed'],
    ['Your refund is queued for approval.', { status: 'queued' }, 'claimed-pending-but-part-committed'],
  ]) {
    const out = guard.review({ claim, reply, record: part });
    assert.equal(`${out.verdict}:${out.reason}`, `unsupported:${reason}`, reply);
    assert.equal(out.reply, CLAIM_MESSAGES.partial, reply);
    assert.equal(out.partial, true);
  }
  // Without a count the guard cannot tell partial from nothing, and says the lesser.
  assert.equal(verdictOf('All 3 steps have been completed.', false, { status: 'done' }), 'unsupported:claimed-success-but-nothing-committed');
});

test('the claim guard records every decision and accepts custom wording', () => {
  const decisions = [];
  const guard = createClaimGuard({ onDecision: d => decisions.push(d), messages: { unsupported: 'Nothing was changed.' } });
  const out = guard.review({ claim: { status: 'done' }, reply: 'It has been processed.', record: { committed: false } });
  assert.equal(out.reply, 'Nothing was changed.');
  assert.deepEqual(decisions.map(d => `${d.guard}:${d.verdict}:${d.replaced}`), ['claim:unsupported:true']);
  // An onDecision that throws must not break the guard.
  const noisy = createClaimGuard({ onDecision: () => { throw new Error('audit sink down'); } });
  assert.equal(noisy.review({ claim: { status: 'done' }, reply: 'It has been processed.', record: { committed: true } }).verdict, 'supported');
  assert.equal(createClaimGuard().review().verdict, 'no-claim');
});

// ------------------------------------------------------------- the app, loopback
const call = (origin, { method = 'POST', path, body, token }) => new Promise((resolve, reject) => {
  const payload = body === undefined ? '' : JSON.stringify(body);
  const r = request(`${origin}${path}`, { method, agent: false, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) } }, res => {
    const chunks = []; res.on('data', d => chunks.push(d));
    res.on('end', () => { let json = null; try { json = JSON.parse(Buffer.concat(chunks).toString()); } catch { /* non-JSON body */ } resolve({ status: res.statusCode, json }); });
  });
  r.on('error', reject); r.end(payload);
});
// Runs one task, pausing it between authorization and its first commit so `during`
// can change access, then returns the reply and what the app's own store holds.
async function task(t, { guards, during = null, hooks = {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-guards-'));
  const app = await startGuardedApp({ dbPath: join(dir, 'app.db'), tokens: TOKENS, guards, stepDelayMs: 20, ...hooks });
  t.after(async () => { await app.stop(); rmSync(dir, { recursive: true, force: true }); });
  const { json: { holdId } } = await call(app.origin, { path: '/control/hold' });
  const running = call(app.origin, { path: '/api/task', body: { ticket: 'T-1', holdId }, token: TOKENS['agent-sam'] });
  const { json: arrival } = await call(app.origin, { path: '/control/hold-wait', body: { holdId } });
  assert.equal(arrival.arrived, true, 'the task reached its commit boundary');
  if (during) await during(app);
  await call(app.origin, { path: '/control/hold-release', body: { holdId } });
  const out = await running;
  const state = app.finalState();
  return { app, out, state, effects: state.notes.length + state.refunds.length, actions: state.audit.map(a => a.action) };
}
const suspend = who => app => call(app.origin, { method: 'PATCH', path: `/api/admin/users/${who}`, body: { status: 'suspended' }, token: TOKENS['owner-olga'] });
const reactivate = who => app => call(app.origin, { method: 'PATCH', path: `/api/admin/users/${who}`, body: { status: 'active' }, token: TOKENS['owner-olga'] });

test('without the guards the suspended agent\'s in-flight task commits and reports success', async t => {
  const { out, effects, actions } = await task(t, { guards: false, during: suspend('agent-sam') });
  assert.equal(out.status, 200);
  assert.equal(effects, TASK_EFFECTS.length, 'every effect landed after the suspension');
  assert.deepEqual(actions, ['user.suspend', ...TASK_EFFECTS]);
  assert.match(out.json.reply, /completed successfully/);
  assert.equal(out.json.committed, TASK_EFFECTS.length);
});

test('with the guards installed the same task commits nothing and tells the agent the truth', async t => {
  const { out, effects, actions } = await task(t, { guards: true, during: suspend('agent-sam') });
  assert.equal(out.status, 200);
  assert.equal(effects, 0, 'nothing committed after the suspension');
  assert.deepEqual(actions, ['user.suspend', 'task.halted']);
  assert.equal(out.json.stopped, 'principal-inactive');
  assert.equal(out.json.reply, CLAIM_MESSAGES.unsupported);
  assert.deepEqual(out.json.review, { verdict: 'unsupported', reason: 'claimed-success-but-nothing-committed', replaced: true });
});

test('the guards do not block work they should allow', async t => {
  // No access change: every effect lands and the reply is passed through unchanged.
  const clean = await task(t, { guards: true });
  assert.equal(clean.effects, TASK_EFFECTS.length);
  assert.deepEqual(clean.actions, [...TASK_EFFECTS]);
  assert.match(clean.out.json.reply, /completed successfully/);
  assert.deepEqual(clean.out.json.review, { verdict: 'supported', reason: 'commit-recorded', replaced: false });
  // Another agent being suspended is not this agent's authority changing.
  const other = await task(t, { guards: true, during: suspend('agent-tia') });
  assert.equal(other.effects, TASK_EFFECTS.length, 'an unrelated suspension must not stop this task');
  assert.equal(other.out.json.stopped, null);
  assert.match(other.out.json.reply, /completed successfully/);
});

test('a suspension reversed while the task is paused still stops it: the authority is not the one it started under', async t => {
  const { out, effects } = await task(t, { guards: true, during: async app => { await suspend('agent-sam')(app); await reactivate('agent-sam')(app); } });
  assert.equal(effects, 0);
  assert.equal(out.json.stopped, 'grants-changed');
  assert.equal(out.json.reply, CLAIM_MESSAGES.unsupported);
});

test('a partial or unreadable outcome never reaches the agent as success', async t => {
  // The app's own commits start failing part-way through the task. One effect landed,
  // so the agent must not be told that nothing was changed.
  const partial = await task(t, { guards: true, hooks: { failCommitAfter: 1 } });
  assert.equal(partial.effects, 1, 'only the first effect landed');
  assert.deepEqual(partial.out.json.review, { verdict: 'unsupported', reason: 'claimed-success-but-part-committed', replaced: true });
  assert.equal(partial.out.json.reply, CLAIM_MESSAGES.partial);
  assert.notEqual(CLAIM_MESSAGES.partial, CLAIM_MESSAGES.unsupported);
  // Nothing at all landed: "nothing was changed" is then the true statement.
  const none = await task(t, { guards: true, hooks: { failCommitAfter: 0 } });
  assert.equal(none.effects, 0);
  assert.equal(none.out.json.review.reason, 'claimed-success-but-nothing-committed');
  assert.equal(none.out.json.reply, CLAIM_MESSAGES.unsupported);
  // The app cannot read back what it recorded.
  const blind = await task(t, { guards: true, hooks: { unreadableOutcome: true } });
  assert.equal(blind.effects, TASK_EFFECTS.length, 'the work itself still happened');
  assert.deepEqual(blind.out.json.review, { verdict: 'unverifiable', reason: 'outcome-not-readable', replaced: true });
  assert.equal(blind.out.json.reply, CLAIM_MESSAGES.unverifiable);
});

test('every guard decision is written to the app\'s own audit store, durably', async t => {
  const { app, state } = await task(t, { guards: true, during: suspend('agent-sam') });
  const steps = app.decisions.map(d => `${d.guard}:${d.step ?? 'reply'}:${d.allowed ?? d.verdict}`);
  assert.deepEqual(steps, ['access:begin:true', 'access:commit:false', 'claim:reply:unsupported']);
  assert.equal(app.decisions[1].reason, 'principal-inactive');
  assert.equal(app.decisions[1].action, TASK_EFFECTS[0]);
  // The decisions survive in the app's own table, not only in memory.
  assert.deepEqual(state.guardLog, app.decisions);
});

test('the app leaves no timer running once it has stopped', async () => {
  // The hold-wait race has a 5 s loser. If it is left ref'd it keeps the event loop
  // alive for 5 s after stop(), which is a leak in anything that embeds the app.
  const timers = () => process.getActiveResourcesInfo().filter(r => r === 'Timeout').length;
  const before = timers();
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-guards-timers-'));
  const app = await startGuardedApp({ dbPath: join(dir, 'app.db'), tokens: TOKENS, guards: true });
  const { json: { holdId } } = await call(app.origin, { path: '/control/hold' });
  const running = call(app.origin, { path: '/api/task', body: { ticket: 'T-1', holdId }, token: TOKENS['agent-sam'] });
  await call(app.origin, { path: '/control/hold-wait', body: { holdId } });
  await call(app.origin, { path: '/control/hold-release', body: { holdId } });
  await running;
  await app.stop();
  rmSync(dir, { recursive: true, force: true });
  assert.equal(timers(), before, 'a timer outlived the app');
});

test('the app enforces its own request-level rules in both builds', async t => {
  for (const guards of [false, true]) {
    const dir = mkdtempSync(join(tmpdir(), 'scopehaven-guards-rules-'));
    const app = await startGuardedApp({ dbPath: join(dir, 'app.db'), tokens: TOKENS, guards });
    t.after(async () => { await app.stop(); rmSync(dir, { recursive: true, force: true }); });
    const as = who => TOKENS[who];
    assert.equal((await call(app.origin, { path: '/api/task', body: { ticket: 'T-1' }, token: as('agent-sam') })).status, 200);
    assert.equal((await call(app.origin, { path: '/api/task', body: { ticket: 'nope' }, token: as('agent-sam') })).status, 400, 'bad ticket');
    assert.equal((await call(app.origin, { path: '/api/task', body: { ticket: 'T-1' }, token: as('owner-olga') })).status, 400, 'owners do not run agent tasks');
    assert.equal((await call(app.origin, { path: '/api/task', body: { ticket: 'T-1', holdId: 'nope' }, token: as('agent-sam') })).status, 400, 'unknown hold');
    assert.equal((await call(app.origin, { method: 'PATCH', path: '/api/admin/users/agent-sam', body: { status: 'suspended' }, token: as('agent-sam') })).status, 403, 'agents do not suspend');
    assert.equal((await call(app.origin, { method: 'PATCH', path: '/api/admin/users/agent-sam', body: { status: 'gone' }, token: as('owner-olga') })).status, 400);
    assert.equal((await call(app.origin, { method: 'PATCH', path: '/api/admin/users/agent-sam', body: { status: 'suspended' }, token: as('owner-olga') })).status, 200);
    // A fresh request from the suspended agent is refused whether or not the guards are installed.
    assert.equal((await call(app.origin, { path: '/api/task', body: { ticket: 'T-2' }, token: as('agent-sam') })).status, 401, `guards=${guards}`);
    assert.equal((await call(app.origin, { path: '/api/task', body: { ticket: 'T-2' }, token: 'wrong' })).status, 401);
  }
});
