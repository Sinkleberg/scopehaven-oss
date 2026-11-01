import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { request, createServer } from 'node:http';
import { gzipSync } from 'node:zlib';
import { digest } from '../../src/domain.mjs';
import { createDecisionLogSink } from './decision-log.mjs';
import { startStandIn, startOpa, startGateFault, readGateRequest, GATE_FAULT_MODES, GATE_FAULT_SCHEMA, GATE_JSON_DEPTH } from './engines.mjs';
import { startDecisionDesk, deskPolicy } from './desk.mjs';
import { AUDIT_INSTANCE, SNAPSHOT_INSTANCE } from './decision-effect.mjs';
import { runGateOutage, judgeGateOutage, validateGateOutageRun, outageScenario, OUTAGE_TICKETS } from './gate-outage.mjs';

const TOKENS = { 'desk-viewer': 'synthetic-desk-viewer', 'desk-agent': 'synthetic-desk-agent' };
const ENV = { SCOPEHAVEN_TARGET_DESK_VIEWER: TOKENS['desk-viewer'], SCOPEHAVEN_TARGET_DESK_AGENT: TOKENS['desk-agent'] };
const ACTORS = { viewer: { principalId: 'desk-viewer', credentialEnv: 'SCOPEHAVEN_TARGET_DESK_VIEWER' }, agent: { principalId: 'desk-agent', credentialEnv: 'SCOPEHAVEN_TARGET_DESK_AGENT' } };
const POLICY_DIR = fileURLToPath(new URL('./policy/', import.meta.url));
const OPA = process.env.SCOPEHAVEN_OPA_BIN;
const FAULT = `tickets/${OUTAGE_TICKETS.outage}`;

// engineTimeoutMs bounds every engine call the desk makes, healthy ones included. Only timeout mode
// needs it short: the gate holds the drill's four calls until the desk gives up. In every other mode the
// gate answers a failed call at once, so the bound can only cut a healthy call short, which a loaded
// host does at 250 ms (a fifth call around the gate, a breaker tripped before the outage); there the desk
// keeps its own default (undefined: 3000 ms).
async function drill(t, { build = 'checked', mode = 'error', engine = 'stand-in', engineTimeoutMs = mode === 'timeout' ? 250 : undefined } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven gate outage '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const sink = createDecisionLogSink(); await sink.start(); t.after(() => sink.stop());
  const eng = engine === 'opa'
    ? await startOpa({ bin: OPA, policyFiles: [join(POLICY_DIR, 'desk.rego'), join(POLICY_DIR, 'data.json')], sinkUrl: sink.url, sinkToken: sink.token, dir })
    : await startStandIn({ policy: deskPolicy, sinkUrl: sink.url, sinkToken: sink.token });
  t.after(() => eng.stop());
  const gate = await startGateFault({ engineOrigin: eng.origin, faultResource: FAULT, mode }); t.after(() => gate.stop());
  const desk = await startDecisionDesk({ dbPath: join(dir, 'desk.db'), tokens: TOKENS, engineOrigin: gate.origin, build, engineTimeoutMs, ...(build === 'fallback-engine' ? { fallbackOrigin: eng.origin } : {}) });
  t.after(() => desk.stop());
  return runGateOutage({ deskOrigin: desk.origin, dbPath: join(dir, 'desk.db'), engine: eng, gate, sink, actors: ACTORS, env: ENV, target: { app: 'practice-desk', build } });
}
const statuses = record => Object.fromEntries([...record.run.results, ...record.results].map(r => [r.id, r.status]));
const row = (record, id) => record.results.find(r => r.id === id);
const outageReplies = record => record.run.timeline.filter(e => e.step === 'response' && /-outage$/.test(e.request)).map(e => [e.request, e.status]);
const storedInputs = record => ({ run: record.run, decisions: record.decisions, refunds: record.refunds, issued: record.refundsIssued });
const reseal = record => { const { recordDigest: _d, ...rest } = record; return { ...rest, recordDigest: digest(rest) }; };
const validate = record => validateGateOutageRun(record, { actors: ACTORS });

test('the checked desk fails closed in every mode: nothing on the drill ticket, the gate failed all four outage calls, the controls before and after land, DE-03 passes', async t => {
  for (const mode of GATE_FAULT_MODES) {
    const record = await drill(t, { mode });
    assert.deepEqual(statuses(record), { 'DE-C1': 'pass', 'DE-C2': 'pass', 'DE-C3': 'pass', 'DE-C4': 'pass', 'DE-R2': 'inconclusive', 'DE-01': 'pass', 'DE-02': 'pass', 'DE-03': 'pass' }, mode);
    assert.equal(row(record, 'DE-03').reason, 'acted-on-nothing-the-gate-failed-to-answer', mode);
    assert.deepEqual([record.gate.faulted, record.gate.errors], [4, []], mode);
    assert.equal(record.gate.forwarded, record.decisions.served - 1, `${mode}: every decision the engine served came through the gate, but the sentinel`);
    assert.ok(record.refunds.every(r => r.ticket !== OUTAGE_TICKETS.outage), mode);
    assert.deepEqual([row(record, 'DE-03').unanswered, row(record, 'DE-03').leaked, record.decisions.events.filter(d => d.resource === FAULT)], [[], [], []], `${mode}: the engine saw nothing about the drill ticket`);
    assert.deepEqual(record.scenario.mode, mode);
    assert.equal(validate(record).valid, true, mode);
  }
});

test('fail-open builds act on calls their gate never answered: DE-03 fails as effect-during-gate-fault in exactly the modes each build fails open on', async t => {
  const checked = {};
  for (const mode of GATE_FAULT_MODES) checked[mode] = await drill(t, { mode });
  const errorModes = ['unreachable', 'timeout', 'error', 'rate-limited'];
  const cases = [
    ...GATE_FAULT_MODES.map(mode => ['fail-open', mode, errorModes.includes(mode) ? 4 : 0]),
    ['fail-open-timeout', 'timeout', 4], ['fail-open-timeout', 'error', 0],
    ['lenient-parse', 'malformed', 4], ['lenient-parse', 'error', 0],
    // The cache holds the viewer's read and the agent's refund allows from before the outage, so
    // the viewer's refund (never allowed) still fails closed: three effects, not four.
    ['cached-on-outage', 'error', 3], ['cached-on-outage', 'malformed', 0],
  ];
  for (const [build, mode, effects] of cases) {
    const record = await drill(t, { build, mode }), de03 = row(record, 'DE-03'), label = `${build} ${mode}`;
    assert.deepEqual([de03.status, de03.reason], effects ? ['fail', 'effect-during-gate-fault'] : ['pass', 'acted-on-nothing-the-gate-failed-to-answer'], label);
    assert.equal(de03.duringFault.length, effects, label);
    assert.ok(de03.duringFault.every(e => e.askedGate && e.resource === FAULT), `${label}: each effect is one the desk asked the gate about`);
    // DE-01 sees the same effects without a decision; the application's records alone show the agent's refund.
    assert.deepEqual([row(record, 'DE-01').status, statuses(record)['DE-R2']], effects ? ['fail', 'fail'] : ['pass', 'inconclusive'], label);
    assert.deepEqual([statuses(record)['DE-C3'], statuses(record)['DE-C4']], ['pass', 'pass'], `${label}: the desk recovered`);
    // fail-open still answers 503, as the checked desk does: the replies cannot tell them apart.
    if (build.startsWith('fail-open')) assert.deepEqual(outageReplies(record), outageReplies(checked[mode]), `${label}: the replies are the checked desk's`);
    validate(record);
  }
  const open = row(await drill(t, { build: 'fail-open', mode: 'error' }), 'DE-03').duringFault;
  assert.deepEqual(open.map(e => [e.principal, e.action, e.amount ?? null]).sort(), [['desk-agent', 'refund', 20], ['desk-agent', 'refund', 500], ['desk-viewer', 'read_ticket', null], ['desk-viewer', 'refund', 20]]);
});

test('non-vacuity: a desk that stops asking and never recovers, or one that reaches the engine around the gate, never passes', async t => {
  // After its first engine failure the breaker refuses without asking, so the drill could fail only
  // that first call; the record also shows the controls after the outage never landed.
  const dead = await drill(t, { build: 'breaker-stays-open', mode: 'error' }), d3 = row(dead, 'DE-03');
  assert.deepEqual([d3.status, d3.reason, d3.notInduced.length, d3.controlsNotLanded], ['inconclusive', 'fault-not-induced', 3, ['DE-C3', 'DE-C4']]);
  assert.equal(row(dead, 'DE-01').status, 'pass', 'it acted on nothing it was not allowed');
  const scenario = outageScenario({ actors: ACTORS, mode: 'error' }), induced = scenario.outageAttempts.map((i, n) => ({ seq: n + 1, resource: i.resource, inputDigest: digest(i) }));
  assert.equal(judgeGateOutage({ ...storedInputs(dead), gate: { ...dead.gate, faults: induced, faulted: 4 }, scenario })[2].reason, 'controls-not-landed', 'with every fault induced, the dead desk reads controls-not-landed');
  // A reply with no result is not an engine failure to this desk, so its breaker never trips.
  assert.equal(row(await drill(t, { build: 'breaker-stays-open', mode: 'malformed' }), 'DE-03').status, 'pass');
  const around = await drill(t, { build: 'fallback-engine', mode: 'error' });
  // The engine decided about the drill ticket: the fault leaked, whatever the counters say.
  assert.deepEqual([row(around, 'DE-03').status, row(around, 'DE-03').reason, row(around, 'DE-03').leaked.length], ['inconclusive', 'fault-leaked', 4]);
  assert.equal(row(around, 'DE-03').served - 1 - row(around, 'DE-03').forwarded, 4, 'the four outage calls reached the engine directly');
  assert.deepEqual([row(around, 'DE-01').status, row(around, 'DE-03').duringFault], ['pass', []], 'the engine did answer them');
  validate(dead); validate(around);
});

test('a retry in another URL form is failed too: the retry-query desk asks again with ?pretty=true, the gate fails both, and nothing about the drill ticket reaches the engine (review finding 2)', async t => {
  for (const mode of ['error', 'unreachable']) {
    const record = await drill(t, { build: 'retry-query', mode }), d3 = row(record, 'DE-03');
    assert.deepEqual([d3.status, d3.reason, record.gate.faulted], ['pass', 'acted-on-nothing-the-gate-failed-to-answer', 8], mode);
    assert.deepEqual(record.gate.faults.map(f => f.path).filter((p, i, a) => a.indexOf(p) === i), ['/v1/data/desk/allow'], `${mode}: the query is not part of the logged path`);
    assert.deepEqual([record.decisions.events.filter(d => d.resource === FAULT), record.refunds.filter(r => r.ticket === OUTAGE_TICKETS.outage)], [[], []], mode);
    validate(record);
  }
});

test('records on the drill ticket that bind to no decision never read pass: denied-audit and unaudited fail, a row inserted and deleted reads effect-unbound (review finding 1, live)', async t => {
  // In malformed mode the checked parse reads every drill-ticket reply as a deny, and these builds
  // act on a deny the planted way: a refund row beside a refund.denied audit row, a refund row with
  // no audit row, a refund row written and deleted.
  for (const [build, status, reason] of [['denied-audit', 'fail', 'effect-during-gate-fault'], ['unaudited', 'fail', 'effect-during-gate-fault'], ['transient-row', 'inconclusive', 'effect-unbound']]) {
    const record = await drill(t, { build, mode: 'malformed' }), d3 = row(record, 'DE-03');
    assert.deepEqual([d3.status, d3.reason, d3.duringFault], [status, reason, []], build);
    if (status === 'fail') assert.deepEqual(d3.unanswered.map(u => [u.record, u.amount]).sort(), [['refund-row', 20], ['refund-row', 20], ['refund-row', 500]], `${build}: the three drill-ticket refunds`);
    validate(record);
  }
});

test('timeout mode is decidable for an application that gives up on its gate at 3 s, the desk default (review finding 3)', async t => {
  const record = await drill(t, { mode: 'timeout', engineTimeoutMs: 3000 });
  assert.deepEqual([row(record, 'DE-03').status, record.run.aborted, record.gate.faulted], ['pass', null, 4]);
});

test('the judge: an effect on the drill ticket fails only on a complete log; a gate that failed nothing, a partial gate log or a partial decision log never passes', () => {
  const scenario = outageScenario({ actors: ACTORS, mode: 'error' });
  const sealed = 'a'.repeat(64);
  const audit = (seq, actor, name, ticket, outcome = 'committed') => ({ source: 'sql-audit-table', seq, actor, name, resource: `tickets/${ticket}`, outcome });
  const created = id => ({ source: 'sql-snapshot', name: 'refunds', operation: 'insert', resource: `refunds/${id}`, outcome: 'committed', contentDigest: sealed });
  const refundRow = (id, auditId, amount, ticket, actor = 'desk-agent') => ({ id, auditId, actor, ticket, amount, contentDigest: sealed });
  const input = (principal, action, ticket, amount) => ({ principal, action, resource: `tickets/${ticket}`, ...(amount === undefined ? {} : { amount }) });
  const dec = (i, result) => ({ path: 'desk/allow', result, inputDigest: digest(i), principal: i.principal, action: i.action, resource: i.resource, engine: { id: 'e' } });
  const fault = (i, seq) => ({ seq, path: 'desk/allow', principal: i.principal, action: i.action, resource: i.resource, inputDigest: digest(i) });
  const controls = ['DE-C1', 'DE-C2', 'DE-C3', 'DE-C4'].map(id => ({ id, status: 'pass' }));
  const before = [audit(1, 'desk-viewer', 'read_ticket', 'T-2'), audit(2, 'desk-agent', 'refund', 'T-2'), audit(3, 'desk-viewer', 'read_ticket', 'T-3'), audit(4, 'desk-agent', 'refund', 'T-3')];
  const healthy = [input('desk-viewer', 'read_ticket', 'T-2'), input('desk-agent', 'refund', 'T-2', 20), input('desk-viewer', 'read_ticket', 'T-3'), input('desk-agent', 'refund', 'T-3', 20)].map(i => dec(i, 'allow'))
    .concat([input('desk-agent', 'refund', 'T-3', 500), input('desk-viewer', 'refund', 'T-3', 20)].map(i => dec(i, 'deny')));
  const allFaults = scenario.outageAttempts.map((i, n) => fault(i, n + 1));
  const judge = ({ auditEvents = before, snap = [created(1), created(2)], refunds = [refundRow(1, 2, 20, 'T-2'), refundRow(2, 4, 20, 'T-3')], issuedEnd, decisions = healthy, coverage = 'complete', faults = allFaults, gateErrors = [], forwarded = 6, served = 7, results = controls, auditCov = 'complete', snapCov = 'net-only', aborted = null }) =>
    judgeGateOutage({ run: { aborted, results, windows: { 'start>end': [{ instanceId: AUDIT_INSTANCE, coverage: auditCov, events: auditEvents }, { instanceId: SNAPSHOT_INSTANCE, coverage: snapCov, events: snap }] } },
      decisions: { coverage, served, events: decisions, sentinel: { logged: true, engineId: 'e' } }, refunds, issued: { start: 0, end: issuedEnd ?? Math.max(0, ...refunds.map(r => r.id)) },
      gate: { schema: GATE_FAULT_SCHEMA, mode: 'error', faultResource: FAULT, forwarded, faulted: faults.length, errors: gateErrors, faults }, scenario })[2];
  const read = r => [r.status, r.reason];
  assert.deepEqual(read(judge({})), ['pass', 'acted-on-nothing-the-gate-failed-to-answer']);
  // The agent's 500 on the drill ticket: a refund row and its audit row, with no allow.
  const open = { auditEvents: [...before, audit(5, 'desk-agent', 'refund', 'T-1')], snap: [created(1), created(2), created(3)], refunds: [refundRow(1, 2, 20, 'T-2'), refundRow(2, 4, 20, 'T-3'), refundRow(3, 5, 500, 'T-1')] };
  assert.deepEqual(read(judge(open)), ['fail', 'effect-during-gate-fault']);
  assert.deepEqual(judge(open).duringFault.map(e => [e.amount, e.askedGate]), [[500, true]]);
  assert.deepEqual(read(judge({ ...open, faults: allFaults.filter(f => f.inputDigest !== digest(input('desk-agent', 'refund', 'T-1', 500))) })), ['fail', 'effect-during-gate-fault'], 'an effect there fails whether or not the desk asked the gate about it');
  assert.equal(judge({ ...open, faults: [] }).duringFault[0].askedGate, false);
  assert.deepEqual(read(judge({ ...open, coverage: 'partial' })), ['inconclusive', 'decision-log-partial'], 'a partial log might hold the allow');
  assert.deepEqual(read(judge({ ...open, decisions: [...healthy, dec(input('desk-agent', 'refund', 'T-1', 500), 'allow')], served: 8 })), ['inconclusive', 'fault-leaked'], 'an engine allow on the drill ticket covers the effect, and it leaked past the gate or went around it');
  // Review finding 1: records on the drill ticket that bind to no decision. The engine made no decision
  // about the drill ticket, so each was done without an answer: fail, and never a pass.
  const rows3 = [refundRow(1, 2, 20, 'T-2'), refundRow(2, 4, 20, 'T-3')], snap3 = [created(1), created(2), created(3)];
  const shapes = {
    A: { auditEvents: [...before, audit(5, 'desk-agent', 'refund', 'T-1')] },
    A2: { auditEvents: [...before, audit(5, 'desk-viewer', 'refund', 'T-1')] },
    B: { snap: snap3, refunds: [...rows3, refundRow(3, null, 500, 'T-1')] },
    C: { auditEvents: [...before, audit(5, 'desk-agent', 'refund.denied', 'T-1', 'denied')], snap: snap3, refunds: [...rows3, refundRow(3, 5, 500, 'T-1')] },
    read: { auditEvents: [...before, audit(5, 'desk-viewer', 'read_ticket', 'T-1')] },
  };
  for (const [name, shape] of Object.entries(shapes)) {
    const r = judge(shape);
    assert.deepEqual([...read(r), r.duringFault.length > 0 || r.unanswered.length > 0], ['fail', 'effect-during-gate-fault', true], name);
    assert.deepEqual(read(judge({ ...shape, coverage: 'partial' })), ['inconclusive', 'decision-log-partial'], `${name}: a partial log might hold a decision`);
  }
  assert.deepEqual(judge(shapes.A).unanswered, [{ record: 'audit-row', seq: 5, principal: 'desk-agent', action: 'refund' }]);
  assert.deepEqual(judge(shapes.B).unanswered, [{ record: 'refund-row', refund: 3, amount: 500, reason: 'no-audit-row' }]);
  // D: a refund id issued in the window and gone. Its ticket went with it: never a pass, not a fail on the drill ticket.
  assert.deepEqual(read(judge({ issuedEnd: 3 })), ['inconclusive', 'effect-unbound'], 'D');
  // Unbound or unknown effects off the drill ticket are DE-01's to fail, and still keep DE-03 from passing.
  assert.deepEqual(read(judge({ snap: snap3, refunds: [...rows3, refundRow(3, null, 500, 'T-3')] })), ['inconclusive', 'effect-unbound']);
  assert.deepEqual(read(judge({ auditEvents: [...before, audit(5, 'desk-agent', 'refund', 'T-3')] })), ['inconclusive', 'effect-input-unknown']);
  // Review finding 2: an engine decision about the drill ticket means a leak past the gate or a route
  // around it. Never a pass; a bound effect with no allow on its own input still fails.
  const leak = [...healthy, dec(input('desk-viewer', 'read_ticket', 'T-1'), 'allow')];
  assert.deepEqual([...read(judge({ decisions: leak, served: 8 })), judge({ decisions: leak, served: 8 }).leaked], ['inconclusive', 'fault-leaked', [{ principal: 'desk-viewer', action: 'read_ticket', result: 'allow' }]]);
  assert.deepEqual(read(judge({ decisions: leak, forwarded: 7, served: 8 })), ['inconclusive', 'fault-leaked'], 'even when the counters agree');
  assert.deepEqual(read(judge({ ...open, decisions: leak, served: 8 })), ['fail', 'effect-during-gate-fault'], 'the 500 refund has no allow on its own input');
  assert.deepEqual(read(judge({ ...shapes.A, decisions: [...healthy, dec(input('desk-agent', 'refund', 'T-1', 20), 'allow')], served: 8 })), ['inconclusive', 'fault-leaked'], 'with a leaked allow, an unbound refund audit row cannot be judged');
  // Final review nit 2: the judge matches the drill ticket as the gate does, case-insensitively, so a
  // case-shifted route around the gate cannot read pass in a hand-built record.
  const shifted = { principal: 'desk-viewer', action: 'read_ticket', resource: 'TICKETS/t-1' };
  const shiftedAudit = { source: 'sql-audit-table', seq: 5, actor: 'desk-viewer', name: 'read_ticket', resource: 'TICKETS/t-1', outcome: 'committed' };
  assert.deepEqual(read(judge({ auditEvents: [...before, shiftedAudit], decisions: [...healthy, dec(shifted, 'allow')], forwarded: 7, served: 8 })), ['inconclusive', 'fault-leaked'], 'an engine allow and an audit row, both on TICKETS/t-1');
  assert.deepEqual(read(judge({ auditEvents: [...before, shiftedAudit] })), ['fail', 'effect-during-gate-fault'], 'an audit row on TICKETS/t-1 with no decision');
  assert.deepEqual(read(judge({ auditEvents: [...before, { ...shiftedAudit, actor: 'desk-agent', name: 'refund' }] })), ['fail', 'effect-during-gate-fault'], 'a refund audit row on TICKETS/t-1 with no refund row and no decision (shape A, case-shifted)');
  assert.deepEqual(read(judge({ snap: snap3, refunds: [...rows3, refundRow(3, null, 500, 't-1')] })), ['fail', 'effect-during-gate-fault'], 'an unbound refund row on ticket t-1');
  assert.deepEqual(read(judge({ auditEvents: [...before, { ...shiftedAudit, resource: 'tickets/T-10' }], decisions: [...healthy, dec({ ...shifted, resource: 'tickets/T-10' }, 'allow')], forwarded: 7, served: 8 })), ['pass', 'acted-on-nothing-the-gate-failed-to-answer'], 'T-10 is another ticket');
  // Review finding 3: an aborted run reads aborted, not as faults the application never asked for.
  assert.deepEqual(read(judge({ aborted: 'transport-failed:viewer-read-outage', faults: allFaults.slice(0, 1) })), ['inconclusive', 'sequence-aborted:transport-failed:viewer-read-outage']);
  // Never a pass without the drill having happened, a whole gate log, a complete decision log and the controls.
  assert.deepEqual(read(judge({ faults: allFaults.slice(1) })), ['inconclusive', 'fault-not-induced']);
  assert.deepEqual(judge({ faults: allFaults.slice(1) }).notInduced, [scenario.outageAttempts[0]]);
  assert.deepEqual(read(judge({ gateErrors: ['forward-failed'] })), ['inconclusive', 'gate-log-partial']);
  assert.deepEqual(read(judge({ coverage: 'partial' })), ['inconclusive', 'decision-log-partial']);
  assert.deepEqual(read(judge({ forwarded: 5 })), ['inconclusive', 'gate-bypassed'], 'the engine served a call the gate did not forward');
  assert.deepEqual(read(judge({ forwarded: 7 })), ['inconclusive', 'gate-bypassed'], 'the gate forwarded a call the engine did not count');
  assert.deepEqual(read(judge({ results: controls.slice(0, 3) })), ['inconclusive', 'controls-not-landed']);
  assert.deepEqual(read(judge({ auditCov: 'partial' })), ['inconclusive', 'audit-partial']);
  assert.deepEqual(read(judge({ snapCov: 'failed' })), ['inconclusive', 'snapshot-failed']);
  assert.deepEqual(read(judge({ aborted: 'precondition-failed:viewer-read-before' })), ['inconclusive', 'sequence-aborted:precondition-failed:viewer-read-before']);
  // An effect off the drill ticket without an allow is DE-01's to fail, not the outage's.
  const offTicket = { auditEvents: [...before, audit(5, 'desk-agent', 'refund', 'T-3')], snap: [created(1), created(2), created(3)], refunds: [refundRow(1, 2, 20, 'T-2'), refundRow(2, 4, 20, 'T-3'), refundRow(3, 5, 500, 'T-3')] };
  assert.deepEqual([...read(judge(offTicket)), judge(offTicket).duringFault], ['pass', 'acted-on-nothing-the-gate-failed-to-answer', []]);
  assert.deepEqual(read(judge({ results: [...controls.slice(0, 3), { id: 'DE-C4', status: 'fail' }] })), ['inconclusive', 'controls-not-landed']);
});

test('the validator recomputes the verdicts from the stored gate log and pins the scenario to the mode the gate ran in', async t => {
  const record = await drill(t, { build: 'fail-open', mode: 'error' });
  assert.equal(validate(record).valid, true);
  assert.throws(() => validate({ ...record, results: record.results.map(r => ({ ...r, status: 'pass' })) }), { code: 'record-digest' });
  assert.throws(() => validate(reseal({ ...record, results: record.results.map(r => ({ ...r, status: 'pass' })) })), { code: 'verdicts' });
  assert.throws(() => validate(reseal({ ...record, gate: { ...record.gate, faults: [], faulted: 0 } })), { code: 'verdicts' }, 'the faults removed: DE-03 would read fault-not-induced');
  assert.throws(() => validate(reseal({ ...record, gate: { ...record.gate, faulted: 3 } })), { code: 'gate-log' });
  for (const forwarded of ['6', -1, 1.5, null]) assert.throws(() => validate(reseal({ ...record, gate: { ...record.gate, forwarded } })), { code: 'gate-log' }, `forwarded ${forwarded}`);
  assert.throws(() => validate(reseal({ ...record, gate: { ...record.gate, mode: 'timeout' } })), { code: 'gate-log' });
  assert.throws(() => validate(reseal({ ...record, gate: { ...record.gate, errors: ['made-up'] } })), { code: 'gate-log' });
  assert.throws(() => validate(reseal({ ...record, gate: { ...record.gate, faults: record.gate.faults.map(f => ({ ...f, resource: 'tickets/T-2' })) } })), { code: 'gate-log' });
  assert.throws(() => validate(reseal({ ...record, scenario: { ...record.scenario, mode: 'nope' } })), { code: 'scenario' });
  assert.throws(() => validate(reseal({ ...record, scenario: { ...record.scenario, outageAttempts: [] } })), { code: 'scenario' }, 'nothing to induce would pass DE-03');
  assert.throws(() => validate(reseal({ ...record, scenario: { ...record.scenario, mode: 'timeout' } })), 'another mode\'s scenario does not match the run');
  assert.throws(() => validate(reseal({ ...record, schema: 'scopehaven-gate-outage-run/0' })), { code: 'schema' });
});

test('the fault gate: fails every request that names its resource, in its mode, whatever the form; forwards the rest with three headers; loopback only; logs what it could not read', async t => {
  const sink = createDecisionLogSink(); await sink.start(); t.after(() => sink.stop());
  const eng = await startStandIn({ policy: deskPolicy, sinkUrl: sink.url, sinkToken: sink.token }); t.after(() => eng.stop());
  const ask = (origin, input, timeout = 400) => fetch(`${origin}/v1/data/desk/allow`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ input }), signal: AbortSignal.timeout(timeout) });
  const healthyInput = { principal: 'desk-agent', action: 'refund', resource: 'tickets/T-2', amount: 20 }, faultInput = { ...healthyInput, resource: FAULT };
  const expect = { error: 503, 'rate-limited': 429, malformed: 200 };
  for (const mode of GATE_FAULT_MODES) {
    const gate = await startGateFault({ engineOrigin: eng.origin, faultResource: FAULT, mode }); t.after(() => gate.stop());
    const ok = await ask(gate.origin, healthyInput);
    assert.deepEqual([ok.status, (await ok.json()).result], [200, true], `${mode}: forwarded`);
    if (mode in expect) {
      const r = await ask(gate.origin, faultInput);
      assert.equal(r.status, expect[mode], mode);
      if (mode === 'malformed') assert.equal('result' in await r.json(), false);
      if (mode === 'rate-limited') assert.equal(r.headers.get('retry-after'), '1');
    } else await assert.rejects(ask(gate.origin, faultInput, 300), e => (mode === 'timeout' ? e.name === 'TimeoutError' : e.name === 'TypeError'), mode);
    const log = gate.since({ faults: 0, forwarded: 0, errors: 0 });
    assert.deepEqual([log.forwarded, log.faulted, log.faults[0].inputDigest, log.faults[0].resource], [1, 1, digest(faultInput), FAULT], mode);
    assert.equal('amount' in log.faults[0], false, `${mode}: the input is kept as a digest only`);
  }
  const gate = await startGateFault({ engineOrigin: eng.origin, faultResource: FAULT, mode: 'error' }); t.after(() => gate.stop());
  const notJson = await fetch(`${gate.origin}/v1/data/desk/allow`, { method: 'POST', body: 'not json' });
  assert.equal(notJson.status, 400, 'its raw text names nothing, so it is forwarded to the engine, which refuses it');
  const unreadable = await fetch(`${gate.origin}/v1/data/desk/allow`, { method: 'POST', headers: { 'Content-Encoding': 'gzip' }, body: 'not gzip' });
  assert.equal(unreadable.status, 503, 'a body the gate cannot inflate might name the resource: it is failed (fail closed)');
  assert.deepEqual(gate.since({ faults: 0, forwarded: 0, errors: 0 }).errors, ['unreadable-request'], 'and the log reads partial');
  // Final review finding 1: a deeply nested JSON body neither crashes the gate nor gets through it.
  const nested = (depth, leaf) => '['.repeat(depth) + JSON.stringify(leaf) + ']'.repeat(depth);
  const deepGate = await startGateFault({ engineOrigin: eng.origin, faultResource: FAULT, mode: 'error' }); t.after(() => deepGate.stop());
  for (const depth of [5000, 30000]) assert.equal((await fetch(`${deepGate.origin}/v1/data/desk/allow`, { method: 'POST', body: nested(depth, 'tickets/T-2') })).status, 503, `nested ${depth} deep: failed, the gate still serves`);
  assert.equal((await fetch(`${deepGate.origin}/v1/data/desk/allow?input=${encodeURIComponent(nested(1000, 'x'))}`)).status, 503, 'nested in a query value (1000 deep fits Node\'s 16 KB header limit)');
  assert.equal((await fetch(`${deepGate.origin}/v1/data/desk/allow`, { method: 'POST', body: nested(GATE_JSON_DEPTH - 1, 'tickets/T-2') })).status, 200, 'within the cap, a body that does not name the drill ticket is forwarded');
  assert.equal((await fetch(`${deepGate.origin}/v1/data/desk/allow`, { method: 'POST', body: nested(GATE_JSON_DEPTH - 1, FAULT) })).status, 503, 'within the cap, a nested name is found');
  assert.deepEqual([deepGate.since({ faults: 0, forwarded: 0, errors: 0 }).faulted, deepGate.since({ faults: 0, forwarded: 0, errors: 0 }).errors], [4, ['unreadable-request']]);
  assert.deepEqual([readGateRequest('/', {}, Buffer.from(nested(30000, 'x'))).readable, readGateRequest('/', {}, Buffer.from(nested(GATE_JSON_DEPTH + 1, 'x'))).readable, readGateRequest('/', {}, Buffer.from(nested(GATE_JSON_DEPTH, 'x'))).readable], [false, false, true], 'up to GATE_JSON_DEPTH arrays or objects deep is readable');
  const big = await fetch(`${gate.origin}/v1/data/desk/allow`, { method: 'POST', body: 'x'.repeat(70 * 1024) }).then(r => r.status, () => 'reset');
  assert.ok([413, 'reset'].includes(big), String(big));
  const foreign = await new Promise((resolve, reject) => { const u = new URL(gate.origin); request({ host: '127.0.0.1', port: u.port, path: '/v1/data/desk/allow', method: 'POST', headers: { Host: 'example.com' } }, res => { res.resume(); resolve(res.statusCode); }).on('error', reject).end('{}'); });
  assert.equal(foreign, 403);
  // Review finding 2: every form that names the drill ticket is failed, whatever the method, path,
  // query, case or encoding; a longer name or another ticket is forwarded.
  const enc = encodeURIComponent, bs = String.fromCharCode(92), asInput = r => ({ principal: 'desk-agent', action: 'refund', resource: r, amount: 20 }), body = r => JSON.stringify({ input: asInput(r) });
  const forms = [
    ['POST', '/v1/data/desk/allow?pretty=true', body(FAULT)],
    ['POST', '/v1/data/desk/allow/', body(FAULT)],
    ['POST', '/V1/DATA/desk/allow', body(FAULT)],
    ['GET', `/v1/data/desk/allow?input=${enc(JSON.stringify(asInput(FAULT)))}`, undefined],
    ['POST', '/v0/data/desk/allow', JSON.stringify(asInput(FAULT))],
    ['POST', '/', JSON.stringify({ resource: FAULT })],
    ['PUT', '/v1/data/desk/allow', body(FAULT)],
    ['POST', '/v1/data/desk/allow', body('TICKETS/t-1')],
    ['POST', '/v1/data/desk/allow', `{"input":{"resource":"tickets${bs}/T-1"}}`],
    ['POST', '/v1/data/desk/allow', `{"input":{"resource":"tickets/${bs}u0054-1"}}`],
    ['POST', `/v1/data/desk/allow?resource=${enc(FAULT)}`, body('tickets/T-2')],
    ['POST', `/v1/data/${enc(FAULT)}`, '{}'],
    ['GET', `/v1/data/desk/allow?input=${enc(`{"resource":"tickets${bs}/T-1"}`)}`, undefined],
  ];
  const formGate = await startGateFault({ engineOrigin: eng.origin, faultResource: FAULT, mode: 'error' }); t.after(() => formGate.stop());
  for (const [method, path, b] of forms) assert.equal((await fetch(`${formGate.origin}${path}`, { method, ...(b === undefined ? {} : { body: b, headers: { 'Content-Type': 'application/json' } }) })).status, 503, `${method} ${path} ${b ?? ''}`);
  assert.equal((await fetch(`${formGate.origin}/v1/data/desk/allow`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }, body: gzipSync(body(FAULT)) })).status, 503, 'a gzip body naming the drill ticket');
  for (const r of ['tickets/T-10', 'tickets/T-2']) assert.equal((await fetch(`${formGate.origin}/v1/data/desk/allow?pretty=true`, { method: 'POST', body: body(r) })).status, 200, `${r} is forwarded`);
  // Health and metrics, with any subpath, are not counted as forwarded: the engine does not count them either.
  for (const path of ['/health', '/health/live', '/health?bundles', '/metrics', '/metrics/x']) await (await fetch(`${formGate.origin}${path}`)).arrayBuffer();
  const formLog = formGate.since({ faults: 0, forwarded: 0, errors: 0 });
  assert.deepEqual([formLog.faulted, formLog.forwarded, formLog.errors], [forms.length + 1, 2, []]);
  assert.deepEqual([formLog.faults[3].method, formLog.faults[3].path, formLog.faults[3].inputDigest], ['GET', '/v1/data/desk/allow', digest(asInput(FAULT))], 'a GET input is read from its query');
  assert.ok(formLog.faults.every(f => f.resource === FAULT));
  // Only Content-Type, Content-Encoding and Accept reach the engine.
  const echo = createServer((req, res) => { req.resume(); res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(req.headers)); });
  await new Promise(resolve => echo.listen(0, '127.0.0.1', resolve)); t.after(() => echo.close());
  const echoGate = await startGateFault({ engineOrigin: `http://127.0.0.1:${echo.address().port}`, faultResource: FAULT, mode: 'error' }); t.after(() => echoGate.stop());
  const seen = await (await fetch(`${echoGate.origin}/v1/data/desk/allow`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: 'Bearer synthetic', Cookie: 'a=b' }, body: body('tickets/T-2') })).json();
  assert.deepEqual([seen['content-type'], seen.accept, seen.authorization, seen.cookie], ['application/json', 'application/json', undefined, undefined]);
  await assert.rejects(startGateFault({ engineOrigin: 'http://example.com/', faultResource: FAULT, mode: 'error' }), /loopback/);
  await assert.rejects(startGateFault({ engineOrigin: eng.origin, faultResource: FAULT, mode: 'flaky' }), /mode is/);
  await assert.rejects(startGateFault({ engineOrigin: eng.origin, faultResource: '', mode: 'error' }), /resource/);
  await assert.rejects(startDecisionDesk({ dbPath: join(tmpdir(), 'unused.db'), tokens: TOKENS, engineOrigin: eng.origin, build: 'fallback-engine' }), /fallbackOrigin/);
});

test('the real engine (OPA): the checked desk passes DE-03 and fail-open fails it, behind the same fault gate', { skip: !(OPA && existsSync(OPA)) && 'set SCOPEHAVEN_OPA_BIN to run against OPA' }, async t => {
  assert.deepEqual([row(await drill(t, { engine: 'opa' }), 'DE-03').status, row(await drill(t, { engine: 'opa', build: 'fail-open' }), 'DE-03').reason], ['pass', 'effect-during-gate-fault']);
});
