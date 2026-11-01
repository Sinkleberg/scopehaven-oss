// DECISION-EFFECT-01: reconcile what an external policy engine decided with what the
// application recorded doing. Two records, two custodians:
//   - the engine's decision log, uploaded by the engine to a loopback sink (decision-log.mjs),
//     complete only when it holds every decision the engine says it served;
//   - the application's own audit table (the sqlite audit observer), through an ordinary
//     sequence run (scopehaven-sequence-run/2) with paired allowed-use controls.
// The checks never restate the policy: the engine owns it. They ask whether the application
// acted only where the engine allowed it, on the very input it acted with.
//   DE-01  every effect the engine governs was allowed by it, on the same input. A read is its
//          committed audit row. A refund is a row the refunds table snapshot shows created in the
//          window; it must be the row the snapshot sealed (its content digest) and name exactly one
//          committed 'refund' audit row that no other refund row names, by the same principal on the
//          same ticket, or DE-01 fails (effect-unbound: no audit row, a denied or missing one, one
//          shared with another row, or another principal's or ticket's). A refund row updated or
//          deleted in the window, or one whose id the table issued in the window and no longer
//          holds (inserted and deleted between the marks), is effect-unbound too.
//          Each effect's input is rebuilt ({ principal, action, resource } from the audit row and,
//          for a refund, the amount from its refund row) and digested; the effects with one
//          input digest must not outnumber the engine's allow decisions on that digest, on the
//          declared decision path. More effects than allows is a fail: effect-after-deny when the
//          engine denied that input, else effect-without-decision (an allow for another input, a
//          pre-flight question or a replayed old input does not cover it). A pass needs a complete
//          decision log, a complete audit window, every effect's input known and the whole run;
//          with a partial log an unmatched effect reads inconclusive.
//   DE-02  the engine was asked about every forbidden attempt's input and denied it. An allow on a
//          forbidden input fails it first (the engine's own record); a pass needs the denies and a
//          complete log; anything else reads inconclusive.
import { digest } from '../../src/domain.mjs';
import { validateSequence, runSequence, SEQUENCE_SCHEMA } from '../sequences/sequence.mjs';
import { validateSequenceRun } from '../sequences/run-validator.mjs';
import { createSqliteAuditObserver, createSqliteSnapshotObserver } from '../observers/sqlite.mjs';
import { decisionWindow, coverageOf, DECISION_LOG_SCHEMA, SINK_REASONS } from './decision-log.mjs';
import { DESK_ACTIONS, DESK_DECISION_PATH, deskRefunds } from './desk.mjs';

export const DECISION_EFFECT_SCHEMA = 'scopehaven-decision-effect-run/2';
export const AUDIT_INSTANCE = 'sqlite-audit-desk', SNAPSHOT_INSTANCE = 'sqlite-snapshot-desk';
export const SETTLE_MS = 300;
export const DECISION_EFFECT_LIMITATIONS = Object.freeze([
  'The practice desk, its policy and its data are synthetic and run on loopback; this measures the method, not a production application.',
  'An effect is bound to a decision by its input: { principal, action, resource } from its audit row and, for a refund, the amount its refund row holds. An engine input carrying other fields does not match, and an application that asks the engine after acting, with the same input, is matched.',
  'The refund rows and the audit rows are the application\'s own records (subject-writable); the table snapshot seals which refund rows were created and what they held at the end mark.',
  'The refunds table is compared at the start and end marks (net change). A row inserted and deleted in the window is seen only through the gap it leaves in the table\'s AUTOINCREMENT sequence, which the application could reset; a row inserted and then edited in the window is judged by its end state (the edit-in-window build reads pass).',
  'The decision log is complete only when it holds as many decisions as the engine says it served (its own request counter, which also counts calls that are not decisions) and every decision carries the engine label of the window\'s sentinel; any gap reads partial, never pass.',
  `A refund the app commits more than ${SETTLE_MS} ms after its last reply is outside the audit window: the desk's 202 "received" reply does not wait for the refund.`,
  'The record is sealed with an unkeyed digest: the validator recomputes every verdict from the stored events, but a forgery consistent in every field is outside its scope.',
]);

// The standard desk scenario. actors: { viewer, agent } with principalId and credentialEnv.
export function deskScenario({ actors }) {
  const v = actors.viewer.principalId, a = actors.agent.principalId, T = 'tickets/T-1';
  const req = (id, actorId, path, body) => ({ request: { id, actorId, method: 'POST', path, ...(body ? { body } : {}) } });
  const audited = (actor, name) => ({ source: 'sql-audit-table', actor, name, operation: DESK_ACTIONS[name] });
  const input = (principal, action, amount) => ({ principal, action, resource: T, ...(amount === undefined ? {} : { amount }) });
  const sequence = validateSequence({ schema: SEQUENCE_SCHEMA, id: 'decision-effect-desk', actors: { viewer: actors.viewer, agent: actors.agent },
    steps: [
      { mark: 'start' },
      req('viewer-read', 'viewer', '/tickets/T-1/read'), { expectStatus: { request: 'viewer-read', in: [200, 404] } },
      req('agent-refund', 'agent', '/tickets/T-1/refund', { amount: 20 }), { expectStatus: { request: 'agent-refund', in: [202] } },
      req('agent-over-limit', 'agent', '/tickets/T-1/refund', { amount: 500 }), { expectStatus: { request: 'agent-over-limit', in: [202] } },
      req('viewer-refund', 'viewer', '/tickets/T-1/refund', { amount: 20 }), { expectStatus: { request: 'viewer-refund', in: [202] } },
      { sleep: SETTLE_MS },
      { mark: 'end' },
    ],
    assertions: [
      { id: 'DE-C1', title: 'The viewer reads a ticket', severity: 'control', from: 'start', to: 'end', effect: { kind: 'effect.exists', select: audited(v, 'read_ticket') } },
      { id: 'DE-C2', title: 'The agent issues a refund within the limit', severity: 'control', from: 'start', to: 'end', effect: { kind: 'effect.exists', select: audited(a, 'refund') } },
      { id: 'DE-R1', title: 'The viewer issues no refund (the application\'s records alone)', severity: 'high', from: 'start', to: 'end', effect: { kind: 'effect.none', select: audited(v, 'refund') } },
    ] });
  return { sequence, governed: Object.keys(DESK_ACTIONS), decisionPath: DESK_DECISION_PATH,
    allowed: [input(v, 'read_ticket'), input(a, 'refund', 20)], forbidden: [input(a, 'refund', 500), input(v, 'refund', 20)] };
}
// The scenario as a record stores it (the sequence is bound through the run's sequence hash).
const stored = scenario => ({ governed: scenario.governed, decisionPath: scenario.decisionPath, allowed: scenario.allowed, forbidden: scenario.forbidden });

const tally = list => { const m = new Map(); for (const k of list) m.set(k, (m.get(k) ?? 0) + 1); return m; };

// The effects in a run, each with the input it acted with (or why it has none).
// issued: { start, end }, the refund ids the table had issued before and after the run.
export function effectsOf(run, refunds, issued, governed) {
  const ws = run.windows?.['start>end'] ?? [];
  const audit = ws.find(w => w.instanceId === AUDIT_INSTANCE) ?? null, snap = ws.find(w => w.instanceId === SNAPSHOT_INSTANCE) ?? null;
  const committed = (audit?.events ?? []).filter(e => e.outcome === 'committed' && governed.includes(e.name));
  const refundAudits = new Map(committed.filter(e => e.name === 'refund').map(e => [e.seq, e]));
  const rows = new Map(refunds.map(r => [r.id, r]));
  const created = (snap?.events ?? []).filter(e => e.outcome === 'committed' && e.name === 'refunds' && e.operation === 'insert').map(e => ({ e, row: rows.get(Number(String(e.resource).split('/')[1])) ?? null }));
  const naming = new Map();
  for (const { row } of created) if (row?.auditId !== null && row?.auditId !== undefined) naming.set(row.auditId, (naming.get(row.auditId) ?? 0) + 1);
  const effects = [], unbound = [];
  let unknown = 0;
  // A refund row changed or removed in the window is an effect no audit row accounts for.
  const idOf = e => Number(String(e.resource).split('/')[1]);
  for (const e of (snap?.events ?? []).filter(x => x.outcome === 'committed' && x.name === 'refunds' && x.operation !== 'insert')) unbound.push({ refund: idOf(e), auditId: rows.get(idOf(e))?.auditId ?? null, amount: rows.get(idOf(e))?.amount ?? null, reason: `refund-row-${e.operation}` });
  for (let id = issued.start + 1; id <= issued.end; id++) if (!rows.has(id)) unbound.push({ refund: id, auditId: null, amount: null, reason: 'refund-row-vanished' });
  for (const e of committed.filter(x => x.name !== 'refund')) effects.push({ principal: e.actor, action: e.name, resource: e.resource });
  for (const { e, row } of created) {
    if (!row || row.contentDigest !== e.contentDigest) { unknown++; continue; }
    const named = row.auditId === null ? null : refundAudits.get(row.auditId) ?? null;
    const why = row.auditId === null ? 'no-audit-row' : !named ? 'audit-row-not-a-committed-refund' : naming.get(row.auditId) > 1 ? 'audit-row-shared'
      : row.actor !== named.actor || `tickets/${row.ticket}` !== named.resource ? 'refund-row-not-its-audit-row' : null;
    if (why) unbound.push({ refund: row.id, auditId: row.auditId, amount: row.amount, reason: why });
    else effects.push({ principal: named.actor, action: 'refund', resource: named.resource, amount: row.amount });
  }
  // A committed refund audit row that no created refund row names: its amount is unknown.
  unknown += [...refundAudits.keys()].filter(id => !naming.has(id)).length;
  return { effects, unbound, unknown, auditCoverage: audit?.coverage ?? 'missing', snapshotCoverage: snap?.coverage ?? 'missing' };
}

// The decisions that count: on the declared path, and only from the engine that answered the window's
// sentinel (a forged allow with a leaked token does not).
export function decisionsOnPath(decisions, decisionPath) {
  const engineId = decisions.sentinel?.engineId ?? null;
  return decisions.events.filter(d => d.path === decisionPath && (engineId === null || d.engine?.id === engineId));
}

// The two DE rows from a sequence run, a decision window and the app's refund rows.
export function judgeDecisionEffect({ run, decisions, refunds, issued, governed, decisionPath, forbidden }) {
  const { effects, unbound, unknown, auditCoverage, snapshotCoverage } = effectsOf(run, refunds, issued, governed);
  const acted = effects.map(input => ({ input }));
  const onPath = decisionsOnPath(decisions, decisionPath);
  const allows = tally(onPath.filter(d => d.result === 'allow').map(d => d.inputDigest)), denies = tally(onPath.filter(d => d.result === 'deny').map(d => d.inputDigest));
  const logComplete = decisions.coverage === 'complete', auditComplete = auditCoverage === 'complete', snapshotHealthy = ['complete', 'net-only'].includes(snapshotCoverage);
  const byInput = new Map();
  for (const { input } of acted.filter(x => x.input)) { const k = digest(input); byInput.set(k, { input, n: (byInput.get(k)?.n ?? 0) + 1 }); }
  const unmatched = [...byInput].filter(([k, { n }]) => n > (allows.get(k) ?? 0))
    .map(([k, { input, n }]) => ({ ...input, effects: n, allows: allows.get(k) ?? 0, denies: denies.get(k) ?? 0, reason: (denies.get(k) ?? 0) > 0 ? 'effect-after-deny' : 'effect-without-decision' }));
  const de01 = unbound.length ? { status: 'fail', reason: 'effect-unbound' }
    : unmatched.length
    ? (logComplete ? { status: 'fail', reason: unmatched[0].reason } : { status: 'inconclusive', reason: `decision-log-${decisions.coverage}` })
    : unknown ? { status: 'inconclusive', reason: 'effect-input-unknown' }
      : !logComplete ? { status: 'inconclusive', reason: `decision-log-${decisions.coverage}` }
        : !auditComplete ? { status: 'inconclusive', reason: `audit-${auditCoverage}` }
          : !snapshotHealthy ? { status: 'inconclusive', reason: `snapshot-${snapshotCoverage}` }
          : run.aborted ? { status: 'inconclusive', reason: `sequence-aborted:${run.aborted}` } : { status: 'pass', reason: 'every-effect-allowed-on-its-input' };
  const attempts = [...forbidden.reduce((m, f) => { const k = digest(f); return m.set(k, { input: f, n: (m.get(k)?.n ?? 0) + 1 }); }, new Map())].map(([k, { input, n }]) => {
    const a = allows.get(k) ?? 0, d = denies.get(k) ?? 0;
    // An allow on a forbidden input is the engine's own record: it fails first, whatever else the log holds.
    const status = a > 0 ? 'fail' : d >= n && logComplete ? 'pass' : 'inconclusive';
    return { ...input, forbidden: n, denies: d, allows: a, status, reason: status === 'fail' ? 'engine-allowed-a-forbidden-attempt' : status === 'pass' ? 'denied' : d >= n ? `decision-log-${decisions.coverage}` : 'not-reached' };
  });
  const de02 = attempts.some(t => t.status === 'fail') ? { status: 'fail', reason: 'engine-allowed-a-forbidden-attempt' } : attempts.every(t => t.status === 'pass') ? { status: 'pass', reason: 'denied' } : { status: 'inconclusive', reason: attempts.find(t => t.status !== 'pass').reason };
  return [
    { id: 'DE-01', title: 'Every effect the engine governs was allowed by the engine, on its own input', severity: 'high', ...de01, unbound, unmatched, unknownInputs: unknown, decisionCoverage: decisions.coverage, auditCoverage, snapshotCoverage },
    { id: 'DE-02', title: 'The engine was asked about every forbidden attempt and denied it', severity: 'high', ...de02, attempts },
  ];
}

const sealed = record => { const { recordDigest: _d, ...rest } = record; return digest(rest); };

export function wrapDecisionEffectRun({ run, decisions, refunds, issued, scenario, engine, target }) {
  const record = { schema: DECISION_EFFECT_SCHEMA, run, decisions, refunds, refundsIssued: issued, scenario: stored(scenario),
    engine: { kind: engine.kind, version: decisions.events.find(e => e.engine?.version)?.engine.version ?? null }, target, limitations: [...DECISION_EFFECT_LIMITATIONS],
    results: judgeDecisionEffect({ run, decisions, refunds, issued, ...scenario }) };
  return { ...record, recordDigest: sealed(record) };
}

export class DecisionEffectError extends Error { constructor(code) { super(code); this.name = 'DecisionEffectError'; this.code = code; } }

// Refuses a record whose verdicts, coverage, scenario or seal do not follow from what it stores
// and from the scenario as written here. actors: as the run used them.
export function validateDecisionEffectRun(record, { actors }) {
  const no = code => { throw new DecisionEffectError(code); };
  if (record?.schema !== DECISION_EFFECT_SCHEMA) no('schema');
  if (record.recordDigest !== sealed(record)) no('record-digest');
  const scenario = deskScenario({ actors });
  if (digest(record.scenario) !== digest(stored(scenario))) no('scenario');
  validateSequenceRun(record.run, { expectedSequence: scenario.sequence });
  validateStoredEvidence(record, no);
  if (digest(judgeDecisionEffect({ run: record.run, decisions: record.decisions, refunds: record.refunds, issued: record.refundsIssued, ...scenario })) !== digest(record.results)) no('verdicts');
  return { valid: true, results: record.results };
}

// The decision log, refund rows and issued ids a record stores, checked for shape and for the counts
// and coverage that follow from them. no(code) throws.
export function validateStoredEvidence(record, no) {
  const d = record.decisions;
  if (d?.schema !== DECISION_LOG_SCHEMA || !Array.isArray(d.events) || !Array.isArray(d.sinkErrors) || !d.sinkErrors.every(r => SINK_REASONS.includes(r)) || typeof d.sentinelAnswered !== 'boolean') no('decision-log');
  if (d.logged !== d.events.length + (d.sentinel?.logged ? 1 : 0)) no('decision-count');
  const c = coverageOf(d);
  if (c.coverage !== d.coverage || digest(c.reasons) !== digest(d.reasons)) no('decision-coverage');
  const r = record.refunds;
  if (!Array.isArray(r) || !r.every(x => Number.isInteger(x?.id) && (x.auditId === null || Number.isInteger(x.auditId)) && typeof x.actor === 'string' && typeof x.ticket === 'string' && typeof x.amount === 'number' && /^[a-f0-9]{64}$/.test(x.contentDigest ?? '')) || new Set(r.map(x => x.id)).size !== r.length) no('refunds');
  const i = record.refundsIssued;
  if (!Number.isInteger(i?.start) || !Number.isInteger(i.end) || i.start < 0 || i.end < i.start || r.some(x => x.id > i.end)) no('refunds-issued');
}

// The desk's two observers: its audit table, and a snapshot of its refunds table.
export function deskObservers({ dbPath, actors }) {
  return [createSqliteAuditObserver({ instanceId: AUDIT_INSTANCE, path: dbPath, principals: [actors.viewer.principalId, actors.agent.principalId],
    audit: { table: 'audit', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', resourceColumn: 'resource', actions: { ...DESK_ACTIONS }, deniedActions: Object.keys(DESK_ACTIONS).map(a => `${a}.denied`) } }),
  createSqliteSnapshotObserver({ instanceId: SNAPSHOT_INSTANCE, path: dbPath, tables: [{ table: 'refunds', key: 'id' }] })];
}

// One run: the desk's audit observer through the sequence, and the decision window around it.
// The window opens before the sequence's first mark and closes after its last.
export async function runDecisionEffect({ deskOrigin, dbPath, engine, sink, actors, env, target, flushTimeoutMs }) {
  const scenario = deskScenario({ actors });
  const observers = deskObservers({ dbPath, actors });
  const window = decisionWindow({ sink, engineOrigin: engine.origin, decisionPath: DESK_DECISION_PATH, ...(flushTimeoutMs ? { flushTimeoutMs } : {}) });
  const start = deskRefunds(dbPath).issued;
  await window.begin();
  const run = await runSequence(scenario.sequence, { origin: deskOrigin, observers, env });
  const decisions = await window.end();
  const end = deskRefunds(dbPath);
  return wrapDecisionEffectRun({ run, decisions, refunds: end.rows, issued: { start, end: end.issued }, scenario, engine, target });
}
