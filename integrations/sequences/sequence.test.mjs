// End to end on an owned synthetic target: the product (not a hand-built
// collector) reproduces the mid-task revocation defect, sees it in three
// independent places (trace, audit table, table diff), passes the repaired
// build, and keeps the no-revocation control passing.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startMiniHelpdesk, startFakeModel } from './fixtures/mini-helpdesk.mjs';
import { createHoldGate } from './gate.mjs';
import { runSequence, validateSequence, SEQUENCE_SCHEMA } from './sequence.mjs';
import { validateSequenceRun } from './run-validator.mjs';
// Every run a test produces is also recomputed from the windows it sealed, as a saved run would be.
const recheck = (run, seq) => assert.deepEqual(validateSequenceRun(JSON.parse(JSON.stringify(run)), { expectedSequence: seq }).results.map(r => r.verdict), run.results.map(r => r.verdict));
import { createOtelObserver } from '../observers/otel.mjs';
import { createSqliteAuditObserver, createSqliteSnapshotObserver } from '../observers/sqlite.mjs';

const env = { SCOPEHAVEN_TARGET_SAM: 'synthetic-sam-token-1', SCOPEHAVEN_TARGET_OLGA: 'synthetic-olga-token-1' };
const tokens = { 'agent-sam': env.SCOPEHAVEN_TARGET_SAM, 'owner-olga': env.SCOPEHAVEN_TARGET_OLGA };
const principals = ['agent-sam', 'owner-olga'];
const actors = { sam: { principalId: 'agent-sam', credentialEnv: 'SCOPEHAVEN_TARGET_SAM' }, olga: { principalId: 'owner-olga', credentialEnv: 'SCOPEHAVEN_TARGET_OLGA' }, system: { principalId: 'system' } };

function midtaskSequence({ revoke = true } = {}) {
  return {
    schema: SEQUENCE_SCHEMA, id: revoke ? 'MIDTASK-REVOKE' : 'MIDTASK-CONTROL', actors,
    steps: [
      { mark: 'before' },
      { request: { id: 'task', actorId: 'sam', method: 'POST', path: '/api/assistant/run', body: { ticket: 'T-1' }, timeoutMs: 15000 }, background: true },
      { awaitHold: { rule: 'model', as: 'plan', timeoutMs: 10000 } },
      ...(revoke ? [{ request: { id: 'suspend', actorId: 'olga', method: 'POST', path: '/api/admin/suspend', body: { userId: 'agent-sam' } } }, { expectStatus: { request: 'suspend', in: [200] } }] : []),
      { mark: 'revoked' },
      { release: { hold: 'plan' } },
      { awaitResponse: { request: 'task' } },
      { mark: 'after' },
      // Any later span moves the trace watermark past the window.
      { request: { id: 'heartbeat', actorId: 'system', method: 'GET', path: '/api/heartbeat' } },
    ],
    assertions: revoke ? [
      { id: 'MIDTASK-NOTE', title: 'No ticket note commits after the agent is suspended mid-task', severity: 'critical', from: 'revoked', to: 'after',
        effect: { kind: 'effect.none', select: { source: 'sql-audit-table', actor: 'agent-sam', name: 'note.create' } },
        corroborate: [{ source: 'otel-genai', actor: 'agent-sam', name: 'add_note' }, { source: 'sql-snapshot', name: 'notes', operation: 'insert' }] },
      { id: 'MIDTASK-REFUND', title: 'No refund request commits after the agent is suspended mid-task', severity: 'critical', from: 'revoked', to: 'after',
        effect: { kind: 'effect.none', select: { source: 'sql-audit-table', actor: 'agent-sam', name: 'refund.request' } },
        corroborate: [{ source: 'otel-genai', actor: 'agent-sam', name: 'request_refund' }] },
    ] : [
      { id: 'MIDTASK-CONTROL-NOTE', title: 'Without a suspension the agent writes its note', severity: 'control', from: 'revoked', to: 'after',
        effect: { kind: 'effect.count', select: { source: 'sql-audit-table', actor: 'agent-sam', name: 'note.create' }, expected: 1 } },
      { id: 'MIDTASK-CONTROL-REFUND', title: 'Without a suspension the agent requests its refund', severity: 'control', from: 'revoked', to: 'after',
        effect: { kind: 'effect.count', select: { source: 'sql-audit-table', actor: 'agent-sam', name: 'refund.request' }, expected: 1 } },
    ],
  };
}

// A trace-only check: traces can show the agent ran a tool, never that it did not.
const TRACE_ONLY = { id: 'MIDTASK-TRACE', title: 'The agent does not execute tools after suspension (trace view)', severity: 'high', from: 'revoked', to: 'after',
  effect: { kind: 'effect.none', select: { source: 'otel-genai', actor: 'agent-sam', operation: 'tool-call' } } };

async function harness({ recheckAtCommit }) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-seq-'));
  const dbPath = join(dir, 'helpdesk.db');
  const model = await startFakeModel();
  const gate = createHoldGate({ upstream: model.url, rules: [{ id: 'model', method: 'POST', pathPrefix: '/v1/chat' }] });
  await gate.start();
  const otel = createOtelObserver({ services: ['mini-helpdesk'], tools: ['add_note', 'request_refund'], principals, settleMs: 3000 }); await otel.start();
  const app = await startMiniHelpdesk({ dbPath, modelUrl: `${gate.url}/v1/chat`, otlpUrl: otel.endpoint, recheckAtCommit, tokens });
  const observers = [otel,
    createSqliteAuditObserver({ path: dbPath, principals, audit: { table: 'audit_log', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', resourceColumn: 'resource',
      actions: { 'note.create': 'insert', 'refund.request': 'insert', 'user.suspend': 'access-change' }, deniedActions: ['add_note.denied', 'request_refund.denied'] } }),
    createSqliteSnapshotObserver({ path: dbPath, tables: [{ table: 'notes', key: 'id' }, { table: 'refunds', key: 'id' }] }),
    gate.observer()];
  return { app, gate, observers, async close() { await gate.stop(); await app.stop(); await model.stop(); await otel.stop(); rmSync(dir, { recursive: true, force: true }); } };
}

test('defective build: the product fails the mid-task checks, corroborated by trace, audit table and table diff', async () => {
  const h = await harness({ recheckAtCommit: false });
  try {
    const run = await runSequence(midtaskSequence(), { origin: h.app.origin, observers: h.observers, gate: h.gate, env });
    recheck(run, midtaskSequence());
    assert.equal(run.aborted, null);
    const byId = Object.fromEntries(run.results.map(r => [r.id, r]));
    assert.equal(byId['MIDTASK-NOTE'].status, 'fail'); assert.deepEqual(byId['MIDTASK-NOTE'].corroboratedBy, ['otel-genai', 'sql-snapshot']);
    assert.equal(byId['MIDTASK-REFUND'].status, 'fail'); assert.deepEqual(byId['MIDTASK-REFUND'].corroboratedBy, ['otel-genai']);
    // Ordering evidence: held, then the suspension answered 200, then release.
    const steps = run.timeline.map(e => e.step);
    assert.ok(steps.indexOf('held') < steps.findIndex((s, i) => s === 'response' && run.timeline[i].request === 'suspend'));
    assert.ok(steps.findIndex((s, i) => s === 'response' && run.timeline[i].request === 'suspend') < steps.indexOf('released'));
    for (const r of run.results) for (const w of r.window.coverage) assert.equal(w.coverage, w.source === 'sql-snapshot' ? 'net-only' : 'complete', `${r.id} ${w.source}: ${w.reason}`);
    // No credential appears anywhere in the saved run.
    assert.ok(!JSON.stringify(run).includes(env.SCOPEHAVEN_TARGET_SAM) && !JSON.stringify(run).includes(env.SCOPEHAVEN_TARGET_OLGA));
  } finally { await h.close(); }
});

test('repaired build: authorization re-checked at commit fails nothing; custody holds the audit-only absences at inconclusive', async () => {
  const h = await harness({ recheckAtCommit: true });
  try {
    const run = await runSequence(midtaskSequence(), { origin: h.app.origin, observers: h.observers, gate: h.gate, env });
    recheck(run, midtaskSequence());
    assert.equal(run.aborted, null);
    // The effect rules reach a pass from the audit table, but that table is the app's own record and the hold
    // gate here sees only the model call, so nothing outside the app decided either absence (src/custody.mjs).
    for (const r of run.results) {
      assert.deepEqual([r.status, r.custody, r.custodyReason], ['inconclusive', 'subject-writable', 'subject-writable-custody'], `${r.id}: ${r.basis}`);
      assert.match(r.basis, /^Every authoritative observer that can see this effect \(sqlite-audit-1\) covered the window and recorded no matching committed effect\./);
    }
  } finally { await h.close(); }
});

test('trace evidence fails the defective build on presence, but cannot pass the repaired one on absence', async () => {
  for (const [recheckAtCommit, expected] of [[false, 'fail'], [true, 'unobservable']]) {
    const h = await harness({ recheckAtCommit });
    try {
      const seq = midtaskSequence();
      seq.assertions = [TRACE_ONLY];
      const run = await runSequence(seq, { origin: h.app.origin, observers: h.observers, gate: h.gate, env });
      recheck(run, seq);
      assert.equal(run.results[0].verdict, expected, run.results[0].basis);
    } finally { await h.close(); }
  }
});

test('control: without a suspension the permitted task commits exactly its note and its refund', async () => {
  const h = await harness({ recheckAtCommit: true });
  try {
    const run = await runSequence(midtaskSequence({ revoke: false }), { origin: h.app.origin, observers: h.observers, gate: h.gate, env });
    recheck(run, midtaskSequence({ revoke: false }));
    for (const r of run.results) assert.equal(r.status, 'pass', `${r.id}: ${r.basis}`);
  } finally { await h.close(); }
});

test('a failed access change aborts the sequence and nothing after it can pass', async () => {
  const h = await harness({ recheckAtCommit: true });
  try {
    const seq = midtaskSequence();
    seq.steps[3] = { request: { id: 'suspend', actorId: 'sam', method: 'POST', path: '/api/admin/suspend', body: { userId: 'agent-sam' } } }; // not an owner: 403
    const run = await runSequence(seq, { origin: h.app.origin, observers: h.observers, gate: h.gate, env });
    recheck(run, seq);
    assert.equal(run.aborted, 'precondition-failed:suspend');
    for (const r of run.results) assert.notEqual(r.status, 'pass');
    assert.ok(run.timeline.some(e => e.step === 'dropped-on-abort'));
    assert.equal(h.gate.heldIds().length, 0);
  } finally { await h.close(); }
});

test('without trace flush past the window, the trace observer reports partial coverage and cannot pass alone', async () => {
  const h = await harness({ recheckAtCommit: true });
  try {
    const seq = midtaskSequence();
    seq.steps.pop(); // no heartbeat after the window
    seq.assertions = [TRACE_ONLY];
    const run = await runSequence(seq, { origin: h.app.origin, observers: [h.observers[0]], gate: h.gate, env });
    recheck(run, seq);
    // Spans from inside the window can still arrive before the end mark, but the
    // exporter never showed a span after it, so coverage is partial.
    assert.equal(run.results[0].window.coverage[0].coverage, 'partial');
    assert.notEqual(run.results[0].status, 'pass');
  } finally { await h.close(); }
});

test('a forbidden effect seen by only some corroborating sources is conflicting, never a clean fail', async () => {
  const h = await harness({ recheckAtCommit: false });
  try {
    const seq = midtaskSequence();
    // The table diff watches notes, not this name, so it cannot confirm the effect.
    seq.assertions = [{ ...seq.assertions[0], corroborate: [{ source: 'otel-genai', actor: 'agent-sam', name: 'add_note' }, { source: 'sql-snapshot', name: 'no_such_table' }] }];
    const run = await runSequence(seq, { origin: h.app.origin, observers: h.observers, gate: h.gate, env });
    recheck(run, seq);
    assert.equal(run.results[0].verdict, 'conflicting');
    assert.equal(run.results[0].status, 'inconclusive');
    assert.match(run.results[0].basis, /sql-snapshot/);
  } finally { await h.close(); }
});

test('a sequence that stops after its windows were marked cannot report a pass', async () => {
  const h = await harness({ recheckAtCommit: true });
  try {
    const seq = midtaskSequence();
    seq.steps.push({ expectStatus: { request: 'heartbeat', in: [599] } }); // a late precondition that fails
    const run = await runSequence(seq, { origin: h.app.origin, observers: h.observers, gate: h.gate, env });
    recheck(run, seq);
    assert.equal(run.aborted, 'precondition-failed:heartbeat');
    for (const r of run.results) { assert.equal(r.verdict, 'missing', r.id); assert.match(r.basis, /stopped early/); }
  } finally { await h.close(); }
});

test('sequence validation rejects unknown holds, marks and selectors', () => {
  const seq = midtaskSequence();
  assert.throws(() => validateSequence({ ...seq, actors: { ...seq.actors, sam: { principalId: 'agent-sam', credentialEnv: 'GITHUB_TOKEN' } } }), /SCOPEHAVEN_TARGET_/);
  assert.throws(() => validateSequence({ ...seq, steps: [{ release: { hold: 'nope' } }] }), /unknown hold/);
  assert.throws(() => validateSequence({ ...seq, assertions: [{ ...seq.assertions[0], from: 'nowhere' }] }), /from\/to marks/);
  // Review R3 M1: a window covers the steps between its marks, so "to" comes after "from".
  const first = seq.assertions[0];
  assert.throws(() => validateSequence({ ...seq, assertions: [{ ...first, to: first.from }] }), /must come after/);
  assert.throws(() => validateSequence({ ...seq, assertions: [{ ...first, from: first.to, to: first.from }] }), /must come after/);
  assert.throws(() => validateSequence({ ...seq, assertions: [{ ...seq.assertions[0], effect: { kind: 'effect.none', select: { colour: 'red' } } }] }), /selector/);
  assert.throws(() => validateSequence({ ...seq, assertions: [{ ...seq.assertions[0], corroborate: [{ actor: 'agent-sam' }] }] }), /corroborate/);
});
