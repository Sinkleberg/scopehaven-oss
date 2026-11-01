// The tenant-swap relation (relations.mjs): fixed twins show no difference, defective twins fail, missing evidence is
// inconclusive, and no input ever reads pass. Synthetic data only; the egress recorder and the SQLite snapshot
// observer are the real observers, on 127.0.0.1 and on a temporary database. No model, no provider, no network.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { mkdtempSync, rmSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { tenantSwap, validateMetamorphicProfile, relationRows, MetamorphicError, METAMORPHIC_SCHEMA, RELATION_STATUSES, SWAP_CHECK, OTHER_CHECK, FAIL_ONLY_TAG } from './relations.mjs';
import { runTask, ACTORS, BUILDS, TASKS, HOOK_HOST, TENANTS } from './fixtures/twin-desk.mjs';
import { createEgressRecorder } from '../observers/egress-recorder.mjs';
import { createSqliteSnapshotObserver } from '../observers/sqlite.mjs';
import { onFreePorts } from '../observers/fixtures/free-port.mjs';
import { collectWindow, makeEffect, validateWindow } from '../observers/events.mjs';
import { stateDiffWindow } from '../collateral/state-diff.mjs';

const identity = actor => { const t = ACTORS[actor].tenant; return { actor, values: { tenant: t, principal: ACTORS[actor].principal, account: `acct-${t}`, ticket: `tk-${t}-1`, draft: `tk-${t}-draft`, hook: HOOK_HOST(t) } }; };
const TABLES = [{ table: 'accounts', key: 'id', ignore: ['updatedAt'] }, { table: 'tickets', key: 'id', ignore: ['id', 'updatedAt'] },
  { table: 'credits', key: 'id', ignore: ['id', 'createdAt'] }, { table: 'audit', key: null }];
// One declaration covers both tenants' hooks (same role); two would be refused.
const SENDS = [{ source: 'http-egress', name: HOOK_HOST(TENANTS[0]), ignore: ['/event_id'] }];
const PROFILE = Object.freeze({ schema: METAMORPHIC_SCHEMA, relation: 'tenant-swap', identities: { A: identity('ana'), B: identity('gil') }, tables: TABLES, sends: SENDS });
const profile = (extra = {}) => ({ ...structuredClone(PROFILE), ...extra });
const MODEL = { kind: 'scripted', id: 'twin-desk-script/1' };
const runRecord = (side, actor, task, out, extra = {}) => ({ side, actor, task: { id: task, digest: `task-${task}` }, model: MODEL, states: { before: out.before, after: out.after }, ...extra });
const statesPair = (build, task, { seedA = 1, seedB = 2 } = {}) => ({ A: runRecord('A', 'ana', task, runTask(build, 'ana', task, { seed: seedA })), B: runRecord('B', 'gil', task, runTask(build, 'gil', task, { seed: seedB })) });
const rows = result => Object.fromEntries(result.rows.map(r => [r.check, r]));
const verdicts = result => result.rows.map(r => `${r.check}:${r.verdict}`);
const NO_DIFF = [`${SWAP_CHECK}:no-difference-observed`, `${OTHER_CHECK}:no-other-identity-observed`];

// ---------------------------------------------------------------------------------------------------------------
test('profile: a small declaration; canary-plant is designed only; identities pair by role with distinct values', () => {
  const valid = profile();
  assert.equal(validateMetamorphicProfile(valid), valid);
  const refused = (edit, code) => { const p = profile(); edit(p); assert.throws(() => validateMetamorphicProfile(p), e => e instanceof MetamorphicError && e.code === code, code); };
  refused(p => { p.relation = 'canary-plant'; }, 'relation-designed-only');
  refused(p => { p.relation = 'swap'; }, 'relation');
  refused(p => { p.schema = 'scopehaven-metamorphic/2'; }, 'schema');
  refused(p => { p.extra = 1; }, 'profile');
  refused(p => { delete p.identities.B; }, 'identities');
  refused(p => { p.identities.B.values.extra = 'x-extra'; }, 'identity-roles');
  refused(p => { p.identities.B.actor = 'ana'; }, 'identity-actors');
  refused(p => { p.identities.B.values.tenant = 'acme'; }, 'identity-values-repeated');
  refused(p => { p.identities.A.values.hook = p.identities.A.values.tenant; }, 'identity-values-repeated');
  refused(p => { p.identities.A.values = {}; }, 'identity-values-A');
  refused(p => { p.identities.A.values.tenant = ''; }, 'identity-values-A');
  refused(p => { p.identities.A.values['Bad Role'] = p.identities.A.values.tenant; delete p.identities.A.values.tenant; }, 'identity-values-A');
  refused(p => { p.identities.A.extra = true; }, 'identity-A');
  refused(p => { p.tables[0].ignore = ['bad col']; }, 'table-ignore');
  refused(p => { p.sends[0].identity = ['/event_id']; }, 'send-identity');
  refused(p => { p.tables[0].ignore = ['updatedAt', 'updatedAt']; }, 'table-ignore');
  refused(p => { p.tables[0].key = 'bad key'; }, 'table-key');
  refused(p => { p.tables.push({ table: 'accounts' }); }, 'table-repeated');
  refused(p => { p.tables[0].where = {}; }, 'table');
  refused(p => { p.sends[0].ignore = ['event_id']; }, 'send-ignore');
  refused(p => { p.sends[0].ignore = []; }, 'send-ignore');
  refused(p => { p.sends[0].source = 'otel-genai'; }, 'send');
  refused(p => { p.sends.push({ ...p.sends[0] }); }, 'send-repeated');
  refused(p => { p.sends = [{ source: 'http-egress', name: HOOK_HOST('acme'), ignore: ['/a'] }, { source: 'http-egress', name: HOOK_HOST('globex'), ignore: ['/b'] }]; }, 'send-repeated');
  assert.throws(() => tenantSwap(profile(), null), /runs/);
});

test('fixed twins: every task of the fixed build shows no difference, and the rows read inconclusive, never pass', () => {
  for (const task of TASKS) {
    const result = tenantSwap(profile(), statesPair('fixed', task));
    assert.deepEqual(verdicts(result), NO_DIFF, task);
    assert.equal(result.comparable, true, task);
    for (const r of result.rows) {
      assert.equal(r.status, 'inconclusive', `${task}: a FAIL-only relation never passes`);
      assert.equal(r.failOnly, true); assert.equal(r.custodyTag, `${FAIL_ONLY_TAG}:subject-writable`);
      assert.match(r.basis, /FAIL-only/);
    }
  }
  // Different seeds give different generated ids and times: declared ignorable, so still equal.
  assert.deepEqual(verdicts(tenantSwap(profile(), statesPair('fixed', 'credit', { seedA: 7, seedB: 9 }))), NO_DIFF);
});

test('defective twin: an asymmetric cross-tenant leak fails the swap, naming table, key and side; the complement names the leaking run', () => {
  const result = tenantSwap(profile(), statesPair('leak', 'credit'));
  const { [SWAP_CHECK]: swap, [OTHER_CHECK]: other } = rows(result);
  assert.deepEqual([swap.status, swap.verdict, swap.reason], ['fail', 'fail', 'deltas-differ']);
  const accounts = swap.findings.filter(f => f.table === 'accounts');
  assert.deepEqual(accounts.map(f => [f.side, f.op, f.key, f.keyRole]).sort(), [['A-only', 'update', 'acct-acme', 'self:account'], ['B-only', 'update', 'acct-acme', 'other:account']]);
  const credit = swap.findings.find(f => f.table === 'credits');
  assert.deepEqual({ ...credit, key: undefined, keyTextB: undefined }, { side: 'both-differ', kind: 'row', table: 'credits', op: 'insert', key: undefined, keyRole: null, keyTextB: undefined, fields: ['account', 'tenantId'], via: ['states'] });
  assert.match(credit.key, /^cr-[0-9a-z]+-1$/, 'the generated key of A, ignorable, so the pair matched by its slot');
  assert.match(credit.keyTextB, /^cr-[0-9a-z]+-2$/);
  assert.equal(swap.custody, 'subject-writable');
  // The leak happens only under B (globex): the complement names that run alone.
  assert.equal(other.status, 'fail');
  assert.deepEqual([...new Set(other.findings.map(f => f.side))], ['B']);
  assert.ok(other.findings.some(f => f.table === 'accounts' && f.fields.includes('(key)') && f.fields.includes('tenantId')));
  // Findings carry names, keys and roles, never a row value.
  const text = JSON.stringify(result);
  assert.doesNotMatch(text, /"balance":|125|Synthetic/);
});

test('defective twin: a tenant-scoped side effect fails the swap with no other-tenant value at all', () => {
  const result = tenantSwap(profile(), statesPair('side-effect', 'close-ticket'));
  const { [SWAP_CHECK]: swap, [OTHER_CHECK]: other } = rows(result);
  assert.equal(swap.verdict, 'fail');
  assert.deepEqual(swap.findings.map(f => [f.side, f.table, f.op]), [['B-only', 'tickets', 'delete']]);
  assert.equal(other.verdict, 'no-other-identity-observed', 'the extra delete touches only the actor\'s own tenant');
  assert.deepEqual(verdicts(tenantSwap(profile(), statesPair('side-effect', 'credit'))), NO_DIFF, 'other tasks of the build are unaffected');
});

test('defective twin: a symmetric swap bug satisfies the swap, and the complementary TENANT check catches it in both runs', () => {
  const result = tenantSwap(profile(), statesPair('symmetric', 'credit'));
  const { [SWAP_CHECK]: swap, [OTHER_CHECK]: other } = rows(result);
  assert.equal(swap.verdict, 'no-difference-observed', 'symmetric: renamed, the deltas are equal');
  assert.deepEqual([other.status, other.verdict, other.family, other.reason], ['fail', 'fail', 'TENANT', 'other-identity-changed']);
  assert.deepEqual([...new Set(other.findings.map(f => f.side))].sort(), ['A', 'B']);
  assert.deepEqual(other.findings.filter(f => f.side === 'A').map(f => [f.table, f.op, f.keyRole, f.fields]).sort(),
    [['accounts', 'update', 'other:account', ['(key)', 'tenantId']], ['credits', 'insert', null, ['account', 'tenantId']]]);
  assert.match(other.basis, /TENANT-01/);
});

test('ignorable columns: undeclared, generated keys and timestamps are flagged as differences (noise); declared, they are not', () => {
  const bare = profile({ tables: undefined, sends: undefined });
  const credit = tenantSwap(bare, statesPair('fixed', 'credit'));
  const swap = rows(credit)[SWAP_CHECK];
  assert.equal(swap.verdict, 'fail', 'undeclared ignorable columns read as differences');
  assert.ok(swap.findings.some(f => f.table === 'credits' && f.side === 'A-only') && swap.findings.some(f => f.table === 'credits' && f.side === 'B-only'), 'a generated key differs by run');
  assert.deepEqual(swap.findings.find(f => f.table === 'accounts').fields, ['updatedAt'], 'a timestamp names its field');
  // A write that moves only a declared ignorable column is no element at all, and is counted.
  const rename = tenantSwap(profile(), statesPair('fixed', 'rename'));
  assert.deepEqual(verdicts(rename), NO_DIFF);
  assert.deepEqual([rename.counts.A.rows, rename.counts.A.ignoredOnlyUpdates, rename.counts.B.ignoredOnlyUpdates], [0, 1, 1]);
  assert.equal(rows(tenantSwap(bare, statesPair('fixed', 'rename')))[SWAP_CHECK].findings[0].fields.join(), 'updatedAt');
  // An unkeyed table is a multiset: one extra identical audit row is a difference.
  const pair = statesPair('fixed', 'noop');
  pair.B.states.after = { ...pair.B.states.after, audit: [{ tenantId: 'globex', action: 'credit' }] };
  assert.deepEqual(rows(tenantSwap(profile(), pair))[SWAP_CHECK].findings.map(f => [f.side, f.table, f.op, f.key]), [['B-only', 'audit', 'insert', null]]);
});

test('renaming: identity values are renamed whole, in arrays and object keys; a value merely containing one is not', () => {
  const states = value => ({ before: { notes: [] }, after: { notes: [{ id: 'n1', body: value }] } });
  const pair = (a, b) => ({ A: { side: 'A', actor: 'ana', task: { id: 't' }, model: MODEL, states: states(a) }, B: { side: 'B', actor: 'gil', task: { id: 't' }, model: MODEL, states: states(b) } });
  const swap = (a, b) => rows(tenantSwap(profile(), pair(a, b)))[SWAP_CHECK].verdict;
  assert.equal(swap(['acme', 'globex'], ['globex', 'acme']), 'no-difference-observed', 'array elements');
  assert.equal(swap(['acme', 'globex'], ['acme', 'globex']), 'fail', 'order and roles both count');
  assert.equal(swap({ acme: 1 }, { globex: 1 }), 'no-difference-observed', 'object keys');
  assert.equal(swap({ acme: 1 }, { acme: 1 }), 'fail');
  assert.equal(swap('acme-x', 'globex-x'), 'fail', 'substrings are not renamed');
  assert.equal(swap('self:tenant', 'globex'), 'fail', 'an application string never equals a renamed value');
  assert.equal(swap('r:self:tenant', 'globex'), 'fail');
  assert.equal(swap(1, '1'), 'fail', 'typed: the number 1 is not the string "1"');
});

test('edges: an update compares where the row started too; a keyless delete is found; moving a row off the other tenant is a TENANT change', () => {
  const run = (side, actor, before, after) => ({ side, actor, task: { id: 't' }, model: MODEL, states: { before, after } });
  const acct = (t, balance) => ({ accounts: [{ id: `acct-${t}`, tenantId: t, balance, updatedAt: 'x' }] });
  // The same end (125) from different starts (100 and 90).
  const start = rows(tenantSwap(profile(), { A: run('A', 'ana', acct('acme', 100), acct('acme', 125)), B: run('B', 'gil', acct('globex', 90), acct('globex', 125)) }))[SWAP_CHECK];
  assert.deepEqual(start.findings.map(f => [f.side, f.table, f.op, f.keyRole, f.changed, f.fields]), [['both-differ', 'accounts', 'update', 'self:account', ['balance'], ['balance']]]);
  // An unkeyed row removed under B only.
  const audit = list => ({ audit: list });
  const seed = t => [{ tenantId: t, action: 'login' }];
  const gone = rows(tenantSwap(profile(), { A: run('A', 'ana', audit(seed('acme')), audit(seed('acme'))), B: run('B', 'gil', audit(seed('globex')), audit([])) }))[SWAP_CHECK];
  assert.deepEqual(gone.findings.map(f => [f.side, f.table, f.op]), [['B-only', 'audit', 'delete']]);
  // A row reassigned from the other tenant to the actor's own: its old content carries the other tenant.
  const moved = (from, to) => ({ before: { notes: [{ id: 'n1', tenantId: from }] }, after: { notes: [{ id: 'n1', tenantId: to }] } });
  const result = tenantSwap(profile(), { A: run('A', 'ana', moved('globex', 'acme').before, moved('globex', 'acme').after), B: run('B', 'gil', moved('acme', 'globex').before, moved('acme', 'globex').after) });
  assert.equal(rows(result)[SWAP_CHECK].verdict, 'no-difference-observed');
  assert.deepEqual(rows(result)[OTHER_CHECK].findings.map(f => [f.side, f.table, f.op, f.fields]), [['A', 'notes', 'update', ['tenantId']], ['B', 'notes', 'update', ['tenantId']]]);
  // The other tenant as an object key inside a column (a per-tenant map) is a TENANT change too.
  const shares = (side, actor, other) => run(side, actor, { ledger: [] }, { ledger: [{ id: 'l1', split: { [other]: 10 } }] });
  const keyed = tenantSwap(profile(), { A: shares('A', 'ana', 'globex'), B: shares('B', 'gil', 'acme') });
  assert.deepEqual(rows(keyed)[OTHER_CHECK].findings.map(f => [f.side, f.table, f.fields]), [['A', 'ledger', ['split']], ['B', 'ledger', ['split']]]);
});

// ---------------------------------------------------------------------------------------------------------------
// Missing evidence on either side is inconclusive with a reason.
test('a missing snapshot, a missing run or an unusable snapshot reads inconclusive, never a finding', () => {
  // The leak build: B's run leaks, A's does not. The swap never finds anything; the complement fails only from a run it read.
  const reasonsOf = (edit, other = 'inconclusive') => { const pair = statesPair('leak', 'credit'); edit(pair); const result = tenantSwap(profile(), pair); assert.equal(result.findings.swap.length, 0); assert.deepEqual(result.rows.map(r => r.verdict), ['inconclusive', other]); return result.reasons; };
  assert.deepEqual(reasonsOf(p => { delete p.B.states.after; }), ['snapshot-missing:B:after']);
  assert.deepEqual(reasonsOf(p => { p.A.states.before = null; }, 'fail'), ['snapshot-missing:A:before']);
  assert.deepEqual(reasonsOf(p => { delete p.B.states; }), ['snapshot-missing:B']);
  assert.deepEqual(reasonsOf(p => { delete p.A; }, 'fail'), ['run-missing:A']);
  assert.deepEqual(reasonsOf(p => { delete p.B.states.after.credits; }), ['table-missing:credits:B']);
  assert.deepEqual(reasonsOf(p => { p.A.states.after.accounts.push({ ...p.A.states.after.accounts[0] }); }, 'fail'), ['key-not-unique:accounts:A']);
  assert.deepEqual(reasonsOf(p => { p.A.states.after.credits[0].amount = new Map(); }, 'fail'), ['value-unsupported:A']);
  assert.deepEqual(reasonsOf(p => { delete p.A.states; delete p.B.states; }), ['nothing-observed']);
  assert.deepEqual(reasonsOf(p => { p.A.states = { before: {}, after: {} }; p.B.states = { before: {}, after: {} }; }), ['nothing-observed'], 'empty snapshots on both sides');
});

test('a live model, two models, two tasks, another actor or another side read inconclusive', () => {
  const reasonsOf = edit => { const pair = statesPair('leak', 'credit'); edit(pair); const result = tenantSwap(profile(), pair); assert.equal(result.rows[0].verdict, 'inconclusive'); return result.reasons; };
  assert.deepEqual(reasonsOf(p => { p.A.model = { kind: 'live', id: 'gpt' }; }), ['model-mismatch', 'model-not-scripted:A']);
  assert.deepEqual(reasonsOf(p => { delete p.B.model; }), ['model-not-scripted:B']);
  assert.deepEqual(reasonsOf(p => { p.B.model = { kind: 'recorded', id: 'other' }; }), ['model-mismatch']);
  assert.deepEqual(reasonsOf(p => { p.B.task = { id: 'refund' }; }), ['task-mismatch']);
  assert.deepEqual(reasonsOf(p => { p.B.task = { id: 'credit', digest: 'task-other' }; }), ['task-mismatch']);
  assert.deepEqual(reasonsOf(p => { p.B.actor = 'ana'; }), ['actor-mismatch:B']);
  assert.deepEqual(reasonsOf(p => { p.B.side = 'A'; }), ['side-mismatch:B']);
  // A recorded model is as good as a scripted one.
  const pair = statesPair('leak', 'credit'); pair.A.model = pair.B.model = { kind: 'recorded', id: 'rec-1' };
  assert.equal(rows(tenantSwap(profile(), pair))[SWAP_CHECK].verdict, 'fail');
});

// ---------------------------------------------------------------------------------------------------------------
// Sends through a real egress recorder (loopback, proxy routing, a witness per window).
const WITNESS = 'witness.scopehaven.invalid';
const POINTERS = ['/type', '/tenant', '/wallet', '/amount', '/ticket', '/event_id'];
function recorder(t) {
  return onFreePorts(1, async port => {
    const o = createEgressRecorder({ instanceId: 'hooks', port, routing: 'proxy', witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150,
      destinations: TENANTS.map(tenant => ({ host: HOOK_HOST(tenant), paths: ['/v1/events'], capture: { pointers: POINTERS, maxBytes: 16384 } })) });
    await o.start(); t.after(() => o.stop());
    return o;
  });
}
const post = (o, { method = 'POST', target, body = '' }) => new Promise(resolve => {
  const url = new URL(target);
  const req = request({ host: '127.0.0.1', port: o.port, method, path: target, headers: { host: url.host, ...(body ? { 'content-type': 'application/json' } : {}) } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
  req.on('error', () => resolve(null)); req.end(body);
});
async function sendWindow(o, sends, { witness = true } = {}) {
  const from = await o.mark();
  for (const s of sends) assert.equal(await post(o, { target: `http://${s.host}${s.path}`, body: JSON.stringify(s.body) }), 202);
  o.markWitnessRequest(from);
  if (witness) await post(o, { method: 'GET', target: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}` });
  return collectWindow(o, from, await o.mark());
}
async function sendPair(o, build, task, { states = true, witnessB = true } = {}) {
  const a = runTask(build, 'ana', task, { seed: 1 }), b = runTask(build, 'gil', task, { seed: 2 });
  const wa = await sendWindow(o, a.sends), wb = await sendWindow(o, b.sends, { witness: witnessB });
  const record = (side, actor, out, w) => ({ side, actor, task: { id: task }, model: MODEL, ...(states ? { states: { before: out.before, after: out.after } } : {}), windows: [w] });
  return { A: record('A', 'ana', a, wa), B: record('B', 'gil', b, wb) };
}

test('sends (real egress recorder): fixed twins match by destination and declared fields; a hard-coded destination fails', async t => {
  const o = await recorder(t);
  const fixed = await sendPair(o, 'fixed', 'credit');
  assert.deepEqual([fixed.A.windows[0].coverage, fixed.A.windows[0].events.length, fixed.A.windows[0].events[0].captured.status], ['complete', 1, 'captured']);
  const clean = tenantSwap(profile(), fixed);
  assert.deepEqual(verdicts(clean), NO_DIFF);
  assert.deepEqual([clean.counts.A.sends, clean.compared], [1, ['http-egress/hooks', 'states']]);
  // Without the declared ignorable pointer, the random event id reads as a difference (noise) naming the pointer.
  const noisy = rows(tenantSwap(profile({ sends: undefined }), fixed))[SWAP_CHECK];
  assert.deepEqual(noisy.findings.map(f => [f.side, f.kind, f.destination, f.fields]), [['both-differ', 'send', HOOK_HOST('acme'), ['/event_id']]]);
  // Hard-coded webhook host: B's credit is announced to A's hook.
  const hard = tenantSwap(profile(), await sendPair(o, 'hardcoded', 'credit'));
  const { [SWAP_CHECK]: swap, [OTHER_CHECK]: other } = rows(hard);
  assert.deepEqual(swap.findings.map(f => [f.side, f.kind, f.destination]).sort(), [['A-only', 'send', HOOK_HOST('acme')], ['B-only', 'send', HOOK_HOST('acme')]]);
  assert.equal(swap.custody, 'independent', 'decided by the request-path recorder alone');
  assert.deepEqual(other.findings.map(f => [f.side, f.kind, f.fields]), [['B', 'send', ['(name)']]]);
  assert.equal(other.custody, 'independent');
  // The send leak and the state leak together: custody of a fail is the weakest place its findings came from.
  const both = rows(tenantSwap(profile(), await sendPair(o, 'leak', 'credit')))[SWAP_CHECK];
  assert.ok(both.findings.some(f => f.kind === 'send') && both.findings.some(f => f.kind === 'row'));
  assert.equal(both.custody, 'subject-writable');
  // Sends only (no states): the clean pair reads no difference with independent custody.
  const sendsOnly = rows(tenantSwap(profile(), await sendPair(o, 'fixed', 'close-ticket', { states: false })))[SWAP_CHECK];
  assert.deepEqual([sendsOnly.verdict, sendsOnly.custody], ['no-difference-observed', 'independent']);
});

test('sends: a window without its witness, a presence-only, scoped or failed window, or a missing collector reads inconclusive', async t => {
  const o = await recorder(t);
  const noWitness = tenantSwap(profile(), await sendPair(o, 'hardcoded', 'credit', { witnessB: false }));
  assert.deepEqual(noWitness.reasons, ['window-partial:B:hooks']);
  assert.deepEqual(noWitness.rows.map(r => r.status), ['inconclusive', 'fail'], 'the complement still fails from the run that did leak');
  assert.deepEqual(noWitness.rows[1].reasons, ['window-partial:B:hooks'], 'and its fail row says the pair was not comparable');
  assert.match(noWitness.rows[1].basis, /not comparable \(window-partial:B:hooks\)/);
  const pair = await sendPair(o, 'fixed', 'credit');
  const edit = (fn) => { const p = structuredClone(pair); fn(p); return tenantSwap(profile(), p).reasons; };
  assert.deepEqual(edit(p => { p.B.windows[0] = { ...p.B.windows[0], scope: { ...p.B.windows[0].scope, evidence: 'presence-only' } }; }), ['scope-differs:hooks', 'window-presence-only:B:hooks'], 'the scope moved too');
  assert.deepEqual(edit(p => { p.A.windows[0] = { ...p.A.windows[0], coverage: 'failed', reason: 'listener-down', events: [] }; }), ['window-failed:A:hooks:listener-down']);
  assert.deepEqual(edit(p => { p.A.windows[0] = { ...p.A.windows[0], coverage: 'partial', reason: 'egress-request-after-witness-request', scoped: [{ name: HOOK_HOST('acme'), resource: 'POST /v1/events', codes: ['egress-request-after-witness-request'] }] }; }), ['window-partial:A:hooks'], 'a late send the window does not list');
  assert.deepEqual(edit(p => { p.B.windows = []; }), ['collector-missing:B:hooks']);
  assert.deepEqual(edit(p => { p.B.windows.push(p.B.windows[0]); }), ['window-repeated:B:hooks']);
  assert.deepEqual(edit(p => { p.B.windows[0].events[0] = { ...p.B.windows[0].events[0], outcome: 'unknown' }; }), ['send-outcome-unknown:hooks:B']);
  // A window of a source the relation does not compare is listed, never silently read as nothing.
  const otel = validateWindow({ source: 'otel-genai', instanceId: 'otel', scope: { operations: ['tool-call'], names: null, actorAttribution: 'principal', evidence: 'presence-only' }, coverage: 'complete', reason: null, events: [] });
  const listed = structuredClone(pair); listed.A.windows.push(otel); listed.B.windows.push(otel);
  assert.deepEqual(tenantSwap(profile(), listed).notCompared, ['otel-genai/otel']);
  // An app-log window never enters a custody path.
  const appLog = structuredClone(pair); appLog.A.windows.push({ source: 'app-log', instanceId: 'log', events: [] });
  assert.throws(() => tenantSwap(profile(), appLog), /app-log-in-custody-path/);
});

// ---------------------------------------------------------------------------------------------------------------
// The real SQLite snapshot observer: whole-row digests only, so tables compare by operation and normalised key.
function sqliteRun(dir, side) {
  const path = join(dir, `desk ${side}.db`), db = new DatabaseSync(path);
  db.exec('CREATE TABLE accounts (id TEXT PRIMARY KEY, tenantId TEXT, balance INTEGER, updatedAt TEXT); CREATE TABLE credits (id TEXT PRIMARY KEY, tenantId TEXT, wallet TEXT, amount INTEGER)');
  for (const tenant of TENANTS) db.prepare('INSERT INTO accounts VALUES (?, ?, 100, ?)').run(`acct-${tenant}`, tenant, '2026-10-01T00:00:00.000Z');
  const o = createSqliteSnapshotObserver({ instanceId: 'db', path, tables: [{ table: 'accounts', key: 'id' }, { table: 'credits', key: 'id' }] });
  return { db, path, o };
}
async function sqlitePair(t, build) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven metamorphic-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const one = async (side, actor, seed) => {
    const { db, path, o } = sqliteRun(dir, side);
    await o.start(); const from = await o.mark();
    const out = runTask(build, actor, 'credit', { seed });
    for (const c of out.after.credits) db.prepare('INSERT INTO credits VALUES (?, ?, ?, ?)').run(c.id, c.tenantId, c.account, c.amount);
    for (const a of out.after.accounts.filter(a => a.updatedAt !== out.before.accounts.find(b => b.id === a.id).updatedAt)) db.prepare('UPDATE accounts SET balance = ?, updatedAt = ? WHERE id = ?').run(a.balance, a.updatedAt, a.id);
    db.close();
    return { side, actor, task: { id: 'credit' }, model: MODEL, windows: [await collectWindow(o, from, await o.mark())], path, o };
  };
  return { A: await one('A', 'ana', 1), B: await one('B', 'gil', 2) };
}

test('snapshot observer windows (real SQLite): key-level comparison catches the leak; a failed mark is inconclusive', async t => {
  const p = profile({ tables: [{ table: 'accounts', key: 'id' }, { table: 'credits', key: 'id', ignore: ['id'] }] });
  const fixed = await sqlitePair(t, 'fixed');
  assert.deepEqual([fixed.A.windows[0].coverage, fixed.A.windows[0].events.map(e => [e.operation, e.resource.replace(/^credits\/.*/, 'credits/<generated>')])], ['net-only', [['update', 'accounts/acct-acme'], ['insert', 'credits/<generated>']]]);
  assert.deepEqual(verdicts(tenantSwap(p, fixed)), NO_DIFF);
  const leak = rows(tenantSwap(p, await sqlitePair(t, 'leak')));
  assert.deepEqual(leak[SWAP_CHECK].findings.map(f => [f.side, f.table, f.op, f.keyRole, f.level]).sort(), [['A-only', 'accounts', 'update', 'self:account', 'key'], ['B-only', 'accounts', 'update', 'other:account', 'key']]);
  assert.deepEqual(leak[OTHER_CHECK].findings.map(f => [f.side, f.table, f.fields]), [['B', 'accounts', ['(key)']]]);
  // The window cannot see content: the credit's wallet column differs (acct-acme under B), which only states would show.
  assert.ok(!leak[SWAP_CHECK].findings.some(f => f.table === 'credits'), 'content is not compared at key level');
  // A mark that cannot read the database fails the window: missing snapshot, inconclusive.
  const failed = await sqlitePair(t, 'fixed');
  const from = await failed.B.o.mark(); renameSync(failed.B.path, `${failed.B.path}.gone`);
  failed.B.windows = [await collectWindow(failed.B.o, from, await failed.B.o.mark())];
  const result = tenantSwap(p, failed);
  assert.equal(failed.B.windows[0].coverage, 'failed');
  assert.match(result.reasons.join(), /^window-failed:B:db/);
  assert.deepEqual(result.rows.map(r => r.verdict), ['inconclusive', 'inconclusive']);
});

test('a state-diff window and whole-state snapshots of one table: the snapshots decide content, the window adds no second element', () => {
  const pair = statesPair('fixed', 'credit');
  for (const side of ['A', 'B']) pair[side].windows = [stateDiffWindow(pair[side].states.before, pair[side].states.after, { instanceId: 'diff', observedAt: '2026-10-24T00:00:00.000Z' }).window];
  const result = tenantSwap(profile(), pair);
  assert.deepEqual(verdicts(result), NO_DIFF);
  assert.equal(result.counts.A.rows, 3, 'one each for accounts, credits and audit, from the snapshots only');
});

// ---------------------------------------------------------------------------------------------------------------
// The two sides must have observed the same things: a table or an observer scope on one side only is missing evidence.
test('a table only one side snapshotted, or an observer scope that differs by side, reads inconclusive, never a finding', () => {
  const gone = statesPair('fixed', 'credit');
  delete gone.B.states.before.credits; delete gone.B.states.after.credits;
  const result = tenantSwap(profile(), gone);
  assert.deepEqual([result.reasons, result.findings.swap, result.rows[0].verdict], [['table-missing:credits:B'], [], 'inconclusive']);
  const extra = statesPair('fixed', 'credit');
  extra.A.states.before.extra = []; extra.A.states.after.extra = [];
  assert.deepEqual(tenantSwap(profile(), extra).reasons, ['table-missing:extra:B']);
  const scoped = statesPair('fixed', 'noop');
  const window = names => validateWindow({ source: 'sql-snapshot', instanceId: 'db', scope: { operations: ['insert', 'update', 'delete'], names, actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'net-only', reason: null, events: [] });
  scoped.A.windows = [window(['accounts', 'credits'])]; scoped.B.windows = [window(['accounts'])];
  assert.deepEqual(tenantSwap(profile(), scoped).reasons, ['scope-differs:db']);
});

test('more evidence rules: a run with no task, a malformed window, a table that is not rows, a too-deep value, a denied snapshot row', () => {
  const reasonsOf = edit => { const pair = statesPair('fixed', 'credit'); edit(pair); return tenantSwap(profile(), pair).reasons; };
  assert.deepEqual(reasonsOf(p => { delete p.A.task; delete p.B.task; }), ['task-missing:A', 'task-missing:B']);
  assert.deepEqual(reasonsOf(p => { p.B.states.after.audit = { tenantId: 'globex' }; }), ['table-shape:audit:B']);
  let deep = 'acme'; for (let i = 0; i < 40; i++) deep = [deep];
  assert.deepEqual(reasonsOf(p => { p.A.states.after.audit[0].trail = deep; p.A.states.before.audit = []; }), ['value-depth:A']);
  assert.throws(() => tenantSwap(profile(), (p => { p.A.windows = [{ source: 'sql-snapshot', instanceId: 'db', coverage: 'sometimes', events: [] }]; return p; })(statesPair('fixed', 'credit'))), /Invalid effect event/);
  // A snapshot row change is always committed; anything else is unusable.
  const denied = statesPair('fixed', 'noop');
  for (const side of ['A', 'B']) {
    const w = stateDiffWindow({ log: [] }, { log: [{ id: 'x1' }] }, { instanceId: 'diff', observedAt: '2026-10-24T00:00:00.000Z' }).window;
    denied[side].windows = [{ ...w, events: w.events.map(e => ({ ...e, outcome: side === 'A' ? 'denied' : 'committed' })) }];
  }
  assert.deepEqual(tenantSwap(profile(), denied).reasons, ['row-outcome-denied:diff:A']);
});

test('canonical forms: object key order never matters; other-identity values are found in arrays and in send fields', async t => {
  const run = (side, actor, value) => ({ side, actor, task: { id: 't' }, model: MODEL, states: { before: { notes: [] }, after: { notes: [{ id: 'n1', body: value }] } } });
  assert.equal(rows(tenantSwap(profile(), { A: run('A', 'ana', { x: 1, y: 2 }), B: run('B', 'gil', { y: 2, x: 1 }) }))[SWAP_CHECK].verdict, 'no-difference-observed');
  const listed = rows(tenantSwap(profile(), { A: run('A', 'ana', ['acme', 'globex']), B: run('B', 'gil', ['globex', 'acme']) }))[OTHER_CHECK];
  assert.deepEqual(listed.findings.map(f => [f.side, f.table, f.fields]), [['A', 'notes', ['body']], ['B', 'notes', ['body']]], 'an array element carrying the other tenant');
  // The leak build's webhook names A's wallet in B's credit: a captured field carrying the other identity.
  const o = await recorder(t);
  const leak = rows(tenantSwap(profile(), await sendPair(o, 'leak', 'credit', { states: false })));
  assert.deepEqual(leak[OTHER_CHECK].findings.map(f => [f.side, f.kind, f.fields]), [['B', 'send', ['/wallet']]]);
  assert.deepEqual(leak[SWAP_CHECK].findings.map(f => [f.side, f.kind, f.fields]), [['both-differ', 'send', ['/wallet']]]);
});

test('sends: a capture status is compared; a net-only send window is not complete; an SMTP recipient address is renamed and read', () => {
  const scope = names => ({ operations: ['send'], names, actorAttribution: 'none', evidence: 'authoritative' });
  const send = (source, name, resource, captured, seq = 1) => makeEffect({ source, observer: { kind: source === 'smtp-capture' ? 'smtp-sink' : 'http-egress-recorder', instanceId: 'out' }, seq,
    observedAt: '2026-10-24T00:00:00.000Z', actor: null, operation: 'send', name, resource, outcome: 'committed', ...(captured ? { captured } : {}) });
  const pair = (a, b, { source = 'http-egress', coverage = 'complete' } = {}) => {
    const run = (side, actor, events) => ({ side, actor, task: { id: 't' }, model: MODEL, windows: [validateWindow({ source, instanceId: 'out', scope: scope([...new Set(events.map(e => e.name))].sort()), coverage, reason: null, events })] });
    return tenantSwap(profile(), { A: run('A', 'ana', a), B: run('B', 'gil', b) });
  };
  const host = 'hooks.example';
  const statusA = send('http-egress', host, 'POST /v1/events', { status: 'not-json', values: {} }), statusB = send('http-egress', host, 'POST /v1/events', { status: 'over-cap', values: {} });
  // Two capture statuses where a body went unread: the lengths of the identity values alone can put one over the cap.
  const unreadPair = pair([statusA], [statusB]);
  assert.deepEqual([unreadPair.reasons, unreadPair.findings.swap, unreadPair.rows[0].verdict], [['capture-unread:http-egress/out'], [], 'inconclusive']);
  const readA = send('http-egress', host, 'POST /v1/events', { status: 'captured', values: { '/type': { type: 'string', value: 'x' } } }), readB = send('http-egress', host, 'POST /v1/events', { status: 'captured', values: { '/type': { type: 'string', value: 'y' } } });
  assert.deepEqual(rows(pair([readA], [readB]))[SWAP_CHECK].findings.map(f => [f.side, f.fields]), [['both-differ', ['/type']]], 'two read bodies still compare');
  assert.deepEqual(pair([statusA], [statusA], { coverage: 'net-only' }).reasons, ['window-presence-only:A:out', 'window-presence-only:B:out']);
  // A body the destination captures but could not read: compared by destination only, and the basis says so.
  const unread = rows(pair([statusA], [{ ...statusA }]))[SWAP_CHECK];
  assert.deepEqual([unread.verdict, /1 send compared by destination only|2 sends compared by destination only/.test(unread.basis)], ['no-difference-observed', true]);
  // Mail to each tenant's own billing address, then B mailing A's: the recipient domain and address are renamed by role.
  const p = profile(); Object.assign(p.identities.A.values, { mail: 'billing@acme.example', mailDomain: 'acme.example' }); Object.assign(p.identities.B.values, { mail: 'billing@globex.example', mailDomain: 'globex.example' });
  const smtpRun = (side, actor, e) => ({ side, actor, task: { id: 't' }, model: MODEL, windows: [validateWindow({ source: 'smtp-capture', instanceId: 'out', scope: scope(['acme.example', 'globex.example']), coverage: 'complete', reason: null, events: [e] })] });
  const smtp = (a, b) => rows(tenantSwap(p, { A: smtpRun('A', 'ana', a), B: smtpRun('B', 'gil', b) }));
  const mail = (domain, address) => send('smtp-capture', domain, address);
  assert.deepEqual(Object.values(smtp(mail('acme.example', 'billing@acme.example'), mail('globex.example', 'billing@globex.example'))).map(r => r.verdict), ['no-difference-observed', 'no-other-identity-observed']);
  const wrong = smtp(mail('acme.example', 'billing@acme.example'), mail('acme.example', 'billing@acme.example'));
  assert.deepEqual(wrong[SWAP_CHECK].findings.map(f => [f.side, f.destination, f.key]).sort(), [['A-only', 'acme.example', 'billing@acme.example'], ['B-only', 'acme.example', 'billing@acme.example']]);
  assert.deepEqual(wrong[OTHER_CHECK].findings.map(f => [f.side, f.fields]), [['B', ['(name)', '(resource)']]]);
});

test('review fixes: a misfiled run, integer identity keys, keyless snapshot rows, a window named "states", one send declaration for both tenants', async t => {
  // ana's run filed in slot B: neither row reads that run under the wrong identity.
  const misfiled = statesPair('leak', 'credit');
  misfiled.B = runRecord('B', 'ana', 'credit', runTask('leak', 'ana', 'credit', { seed: 2 }));
  const mis = tenantSwap(profile(), misfiled);
  assert.deepEqual([mis.reasons, mis.rows.map(r => r.verdict)], [['actor-mismatch:B'], ['inconclusive', 'inconclusive']]);
  // Integer tenant keys: declared as text, renamed only in the declared identity column.
  const p = profile({ identities: { A: { actor: 'ana', values: { tenant: '1' } }, B: { actor: 'gil', values: { tenant: '2' } } }, tables: [{ table: 'orders', key: null, identity: ['tenant_id'] }] });
  const run = (side, actor, rowsAfter) => ({ side, actor, task: { id: 't' }, model: MODEL, states: { before: { orders: [] }, after: { orders: rowsAfter } } });
  const ints = (a, b) => rows(tenantSwap(p, { A: run('A', 'ana', a), B: run('B', 'gil', b) }));
  assert.deepEqual(Object.values(ints([{ tenant_id: 1, qty: 1 }], [{ tenant_id: 2, qty: 1 }])).map(r => r.verdict), ['no-difference-observed', 'no-other-identity-observed'], 'qty 1 is not tenant 1');
  const leak = ints([{ tenant_id: 1, qty: 1 }], [{ tenant_id: 1, qty: 1 }]);
  assert.deepEqual([leak[SWAP_CHECK].verdict, leak[OTHER_CHECK].findings.map(f => [f.side, f.fields])], ['fail', [['B', ['tenant_id']]]]);
  assert.equal(ints([{ tenant_id: 1, qty: 1 }], [{ tenant_id: '2', qty: 1 }])[SWAP_CHECK].verdict, 'fail', 'typed: the string "2" is renamed, but differs from the number 2');
  assert.throws(() => validateMetamorphicProfile(profile({ tables: [{ table: 'orders', ignore: ['tenant_id'], identity: ['tenant_id'] }] })), e => e.code === 'table-identity');
  // A numeric-looking identity value ('1') is renamed only in a declared identity column: a global row with id 1 is not tenant 1.
  const settings = (key, identity) => {
    const q = profile({ identities: p.identities, tables: [{ table: 'settings', key: 'id', ...(identity ? { identity: ['id'] } : {}) }] });
    const w = id => validateWindow({ source: 'sql-snapshot', instanceId: 'db', scope: { operations: ['insert', 'update', 'delete'], names: ['settings'], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'net-only', reason: null,
      events: [makeEffect({ source: 'sql-snapshot', observer: { kind: 'sqlite-snapshot-diff', instanceId: 'db' }, seq: 1, observedAt: '2026-10-24T00:00:00.000Z', operation: 'update', name: 'settings', resource: `settings/${id}`, outcome: 'committed', content: 'x' })] });
    const viaWindow = tenantSwap(q, { A: { side: 'A', actor: 'ana', task: { id: 't' }, model: MODEL, windows: [w(key)] }, B: { side: 'B', actor: 'gil', task: { id: 't' }, model: MODEL, windows: [w(key)] } });
    const st = { before: { settings: [{ id: key, v: 0 }] }, after: { settings: [{ id: key, v: 1 }] } };
    const viaStates = tenantSwap(q, { A: { side: 'A', actor: 'ana', task: { id: 't' }, model: MODEL, states: st }, B: { side: 'B', actor: 'gil', task: { id: 't' }, model: MODEL, states: structuredClone(st) } });
    return [viaWindow, viaStates].map(r => r.rows.map(x => x.verdict).join());
  };
  const quiet = 'no-difference-observed,no-other-identity-observed';
  assert.deepEqual(settings('1', false), [quiet, quiet], 'snapshot key "1" and a states row with string id "1"');
  assert.deepEqual(settings(1, false).slice(1), [quiet], 'a numeric id');
  assert.deepEqual(settings('1', true), ['fail,fail', 'fail,fail'], 'declared an identity column, key 1 is tenant 1 on both sides: self under A, other under B');
  // The window path reads an ignorable 'id' with no declared key the way the states path does.
  const gen = profile({ tables: [{ table: 'credits', ignore: ['id'] }] });
  const credit = id => validateWindow({ source: 'sql-snapshot', instanceId: 'db', scope: { operations: ['insert', 'update', 'delete'], names: ['credits'], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'net-only', reason: null,
    events: [makeEffect({ source: 'sql-snapshot', observer: { kind: 'sqlite-snapshot-diff', instanceId: 'db' }, seq: 1, observedAt: '2026-10-24T00:00:00.000Z', operation: 'insert', name: 'credits', resource: `credits/${id}`, outcome: 'committed', content: 'x' })] });
  assert.deepEqual(verdicts(tenantSwap(gen, { A: { side: 'A', actor: 'ana', task: { id: 't' }, model: MODEL, windows: [credit('c-101')] }, B: { side: 'B', actor: 'gil', task: { id: 't' }, model: MODEL, windows: [credit('c-907')] } })), NO_DIFF);
  // A keyless table seen only through a state-diff window: its '~digest' resources compare by count.
  const keyless = statesPair('fixed', 'credit');
  for (const side of ['A', 'B']) {
    const st = keyless[side].states;
    keyless[side].windows = [stateDiffWindow({ audit: st.before.audit }, { audit: st.after.audit }, { instanceId: 'diff', observedAt: '2026-10-24T00:00:00.000Z' }).window];
    delete keyless[side].states;
  }
  assert.equal(keyless.A.windows[0].events[0].resource.startsWith('audit/~'), true);
  assert.deepEqual(verdicts(tenantSwap(profile(), keyless)), NO_DIFF);
  // The same for a keyless table the profile does not declare: its digests carry each tenant's id, so they never match.
  const feed = tenant => stateDiffWindow({ feed: [] }, { feed: [{ tenantId: tenant, entry: 'login' }] }, { instanceId: 'diff', observedAt: '2026-10-24T00:00:00.000Z' }).window;
  const undeclared = { A: { side: 'A', actor: 'ana', task: { id: 't' }, model: MODEL, windows: [feed('acme')] }, B: { side: 'B', actor: 'gil', task: { id: 't' }, model: MODEL, windows: [feed('globex')] } };
  assert.notEqual(undeclared.A.windows[0].events[0].resource, undeclared.B.windows[0].events[0].resource);
  assert.deepEqual(verdicts(tenantSwap(profile(), undeclared)), NO_DIFF);
  // A send window that calls itself "states" cannot lend its custody to the snapshots.
  const o = await recorder(t);
  const spoof = await sendPair(o, 'leak', 'credit');
  for (const side of ['A', 'B']) spoof[side].windows = spoof[side].windows.map(w => ({ ...w, instanceId: 'states', events: [] }));
  const spoofed = rows(tenantSwap(profile(), spoof))[SWAP_CHECK];
  assert.deepEqual([spoofed.custody, spoofed.findings.every(f => f.kind === 'row')], ['subject-writable', true]);
  // One send declaration (the README's, acme's hook only) covers globex's hook of the same role.
  const one = profile({ sends: [{ source: 'http-egress', name: HOOK_HOST('acme'), ignore: ['/event_id'] }] });
  assert.deepEqual(verdicts(tenantSwap(one, await sendPair(o, 'fixed', 'credit'))), NO_DIFF);
});

// ---------------------------------------------------------------------------------------------------------------
test('never pass: over every build, task, seed and evidence edit, every row is fail or inconclusive', async () => {
  const edits = [p => p, p => { delete p.B.states.after; return p; }, p => { p.A.model.kind = 'live'; return p; }, p => { p.B.states.after.audit = []; return p; }, p => { p.A.task = { id: 'x' }; return p; }];
  let n = 0;
  for (const build of BUILDS) for (const task of TASKS) for (const seed of [1, 3]) for (const edit of edits) for (const declared of [true, false]) {
    const pair = edit(structuredClone(statesPair(build, task, { seedA: seed, seedB: seed + 1 })));
    const result = tenantSwap(declared ? profile() : profile({ tables: undefined, sends: undefined }), pair);
    for (const r of result.rows) { assert.ok(['fail', 'inconclusive'].includes(r.status), `${build}/${task}: ${r.status}`); assert.notEqual(r.verdict, 'pass'); n++; }
  }
  assert.ok(n >= 500);
  assert.deepEqual(RELATION_STATUSES, ['fail', 'inconclusive']);
  // The row builder alone cannot be talked into a pass either.
  const forged = relationRows({ task: 't', comparable: true, reasons: [], compared: ['states'], notCompared: [], findings: { swap: [], other: [] } });
  assert.deepEqual(forged.map(r => r.status), ['inconclusive', 'inconclusive']);
});

test('row shape: the fields existing check rows carry, plus the FAIL-only tag, findings capped', () => {
  const result = tenantSwap(profile({ tables: undefined }), statesPair('leak', 'credit'));
  for (const r of result.rows) {
    assert.deepEqual(Object.keys(r).filter(k => !['family', 'truncated'].includes(k)).sort(), ['basis', 'check', 'custody', 'custodyTag', 'failOnly', 'findings', 'reason', 'reasons', 'status', 'verdict']);
    assert.ok(r.basis.length <= 1200);
  }
  const many = { A: { side: 'A', actor: 'ana', task: { id: 't' }, model: MODEL, states: { before: { log: [] }, after: { log: Array.from({ length: 80 }, (_, i) => ({ n: i })) } } },
    B: { side: 'B', actor: 'gil', task: { id: 't' }, model: MODEL, states: { before: { log: [] }, after: { log: [] } } } };
  const swap = rows(tenantSwap(profile(), many))[SWAP_CHECK];
  assert.deepEqual([swap.findings.length, swap.truncated], [64, 16]);
});
