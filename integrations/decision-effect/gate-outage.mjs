// The gate-outage drill (DE-03): does the application fail closed when its policy gate fails?
// A fault gate (engines.mjs startGateFault) sits between the application and its policy engine. It
// fails every decision about one drill ticket in one mode (unreachable, timeout, an error or rate-limit
// status, a reply with no result) and forwards the rest. The run is judged from three records with
// three custodians:
//   - the fault gate's log (the harness): the calls it failed, and how many it forwarded;
//   - the engine's decision log (the engine, through the sink), complete only when it holds every
//     decision the engine served;
//   - the application's audit table and refunds snapshot (the application), through a sequence run.
// The sequence has three phases on three tickets: before (the gate works, T-2), the outage (every
// decision about T-1 fails), after (the gate works, T-3).
//   DE-03  the application did nothing on the drill ticket that the engine did not allow. It fails as
//          effect-during-gate-fault, on a complete decision log, when:
//            - a governed effect there has no engine allow on its own input (each listed with whether
//              the application had asked the gate for that very input); or
//            - the engine made no decision about the drill ticket at all, and the application still
//              committed a governed audit row there or left a refund row there that binds to no audit
//              row (listed as unanswered).
//          An engine decision about the drill ticket means the call leaked past the gate or went
//          around it (fault-leaked): never a pass. Neither is an unbound effect elsewhere or an effect
//          whose input is unknown. A pass also needs: the whole run; the fault induced on every attempt
//          in the outage; every decision the engine served routed through the gate (otherwise
//          gate-bypassed); the complete logs DE-01 needs; and the controls before and after the
//          outage landed, so an application that refuses everything cannot pass by being dead.
// DE-01 and DE-02 are judged on the same run, as in decision-effect.mjs.
import { digest } from '../../src/domain.mjs';
import { validateSequence, runSequence, SEQUENCE_SCHEMA } from '../sequences/sequence.mjs';
import { validateSequenceRun } from '../sequences/run-validator.mjs';
import { decisionWindow } from './decision-log.mjs';
import { DESK_ACTIONS, DESK_DECISION_PATH, deskRefunds } from './desk.mjs';
import { GATE_FAULT_SCHEMA, GATE_FAULT_MODES, GATE_ERRORS, namesResource } from './engines.mjs';
import { judgeDecisionEffect, effectsOf, decisionsOnPath, deskObservers, validateStoredEvidence, DecisionEffectError, DECISION_EFFECT_LIMITATIONS, SETTLE_MS, AUDIT_INSTANCE } from './decision-effect.mjs';

export const GATE_OUTAGE_SCHEMA = 'scopehaven-gate-outage-run/1';
export const OUTAGE_TICKETS = Object.freeze({ before: 'T-2', outage: 'T-1', after: 'T-3' });
// Each outage request waits this long for the application's reply, so an application that gives up on its
// gate within it (the desk's default is 3000 ms) is still decidable in timeout mode.
export const OUTAGE_REQUEST_TIMEOUT_MS = 10000;
export const GATE_OUTAGE_LIMITATIONS = Object.freeze([
  ...DECISION_EFFECT_LIMITATIONS,
  'The outage is scoped by input, not by time: the gate fails every decision about the drill ticket and forwards every other, so the run is deterministic. An application whose behaviour depends on how long its gate has been down (a breaker that opens after some number of failures and then fails open) is exercised only as far as the outage phase\'s four calls.',
  'The drill reaches only a gate the application asks over HTTP at an origin the harness can point at the fault gate. A policy library inside the application\'s process, or a gate reached by another route, is out of its reach; an engine decision about the drill ticket reads fault-leaked, and a route around the gate that reaches the same engine for other calls reads gate-bypassed.',
  `In timeout mode the application must give up on its gate within ${OUTAGE_REQUEST_TIMEOUT_MS} ms; otherwise the outage request times out, the run aborts and DE-03 reads sequence-aborted.`,
  'The fault gate forwards only the Content-Type, Content-Encoding and Accept headers. An engine that needs a token refuses every forwarded call, so the controls never land and DE-03 reads inconclusive.',
  'A refund row inserted and deleted inside the window leaves only a gap in the table\'s sequence, not its ticket, so it reads effect-unbound (inconclusive), not a fail on the drill ticket.',
  'The gate fails each call in one mode per run. Modes are judged in separate runs; a mixed outage (a timeout, then a 503) is not exercised.',
]);

// The drill's scenario. actors: { viewer, agent } with principalId and credentialEnv; mode: one of GATE_FAULT_MODES.
export function outageScenario({ actors, mode }) {
  if (!GATE_FAULT_MODES.includes(mode)) throw new Error(`mode is ${GATE_FAULT_MODES.join(', ')}.`);
  const v = actors.viewer.principalId, a = actors.agent.principalId, { before, outage, after } = OUTAGE_TICKETS;
  const req = (id, actorId, ticket, verb, body, timeoutMs) => ({ request: { id, actorId, method: 'POST', path: `/tickets/${ticket}/${verb}`, ...(body ? { body } : {}), ...(timeoutMs ? { timeoutMs } : {}) } });
  const audited = (actor, name, ticket) => ({ source: 'sql-audit-table', actor, name, operation: DESK_ACTIONS[name], resource: `tickets/${ticket}` });
  const input = (principal, action, ticket, amount) => ({ principal, action, resource: `tickets/${ticket}`, ...(amount === undefined ? {} : { amount }) });
  const sequence = validateSequence({ schema: SEQUENCE_SCHEMA, id: `gate-outage-${mode}`, actors: { viewer: actors.viewer, agent: actors.agent },
    steps: [
      { mark: 'start' },
      // Before: the gate works. These are preconditions: a desk whose gate fails here is not under test.
      req('viewer-read-before', 'viewer', before, 'read'), { expectStatus: { request: 'viewer-read-before', in: [200] } },
      req('agent-refund-before', 'agent', before, 'refund', { amount: 20 }), { expectStatus: { request: 'agent-refund-before', in: [202] } },
      // The outage: every decision about the drill ticket fails. Any reply is accepted; the records judge.
      req('viewer-read-outage', 'viewer', outage, 'read', undefined, OUTAGE_REQUEST_TIMEOUT_MS),
      req('agent-refund-outage', 'agent', outage, 'refund', { amount: 20 }, OUTAGE_REQUEST_TIMEOUT_MS),
      req('agent-over-limit-outage', 'agent', outage, 'refund', { amount: 500 }, OUTAGE_REQUEST_TIMEOUT_MS),
      req('viewer-refund-outage', 'viewer', outage, 'refund', { amount: 20 }, OUTAGE_REQUEST_TIMEOUT_MS),
      // After: the gate works again.
      req('viewer-read-after', 'viewer', after, 'read'),
      req('agent-refund-after', 'agent', after, 'refund', { amount: 20 }),
      req('agent-over-limit-after', 'agent', after, 'refund', { amount: 500 }),
      req('viewer-refund-after', 'viewer', after, 'refund', { amount: 20 }),
      { sleep: SETTLE_MS },
      { mark: 'end' },
    ],
    assertions: [
      { id: 'DE-C1', title: 'Before the outage, the viewer reads a ticket', severity: 'control', from: 'start', to: 'end', effect: { kind: 'effect.exists', select: audited(v, 'read_ticket', before) } },
      { id: 'DE-C2', title: 'Before the outage, the agent issues a refund within the limit', severity: 'control', from: 'start', to: 'end', effect: { kind: 'effect.exists', select: audited(a, 'refund', before) } },
      { id: 'DE-C3', title: 'After the outage, the viewer reads a ticket', severity: 'control', from: 'start', to: 'end', effect: { kind: 'effect.exists', select: audited(v, 'read_ticket', after) } },
      { id: 'DE-C4', title: 'After the outage, the agent issues a refund within the limit', severity: 'control', from: 'start', to: 'end', effect: { kind: 'effect.exists', select: audited(a, 'refund', after) } },
      { id: 'DE-R2', title: 'During the outage, the agent issues no refund (the application\'s records alone)', severity: 'high', from: 'start', to: 'end', effect: { kind: 'effect.none', select: audited(a, 'refund', outage) } },
    ] });
  return { sequence, mode, governed: Object.keys(DESK_ACTIONS), decisionPath: DESK_DECISION_PATH, faultResource: `tickets/${outage}`,
    controls: ['DE-C1', 'DE-C2', 'DE-C3', 'DE-C4'],
    outageAttempts: [input(v, 'read_ticket', outage), input(a, 'refund', outage, 20), input(a, 'refund', outage, 500), input(v, 'refund', outage, 20)],
    allowed: [input(v, 'read_ticket', before), input(a, 'refund', before, 20), input(v, 'read_ticket', after), input(a, 'refund', after, 20)],
    forbidden: [input(a, 'refund', after, 500), input(v, 'refund', after, 20)] };
}
const stored = s => ({ mode: s.mode, governed: s.governed, decisionPath: s.decisionPath, faultResource: s.faultResource, controls: s.controls, outageAttempts: s.outageAttempts, allowed: s.allowed, forbidden: s.forbidden });

// The three rows from a sequence run, the decision window, the app's refund rows and the gate's log.
export function judgeGateOutage({ run, decisions, refunds, issued, gate, scenario }) {
  const [de01, de02] = judgeDecisionEffect({ run, decisions, refunds, issued, governed: scenario.governed, decisionPath: scenario.decisionPath, forbidden: scenario.forbidden });
  const { effects, unbound, unknown, auditCoverage, snapshotCoverage } = effectsOf(run, refunds, issued, scenario.governed);
  // The drill ticket, matched as the gate matches it: case-insensitive, not as part of a longer name.
  const fault = scenario.faultResource, onDrill = resource => typeof resource === 'string' && namesResource([resource], fault);
  const ticketOf = id => refunds.find(r => r.id === id)?.ticket ?? null;
  const allowed = new Set(decisionsOnPath(decisions, scenario.decisionPath).filter(d => d.result === 'allow').map(d => d.inputDigest));
  const asked = new Set(gate.faults.map(f => f.inputDigest));
  const duringFault = effects.filter(e => onDrill(e.resource) && !allowed.has(digest(e))).map(e => ({ ...e, askedGate: asked.has(digest(e)) }));
  // The engine's own decisions about the drill ticket. The gate forwards none, so each leaked past it or went around it.
  const leaked = decisions.events.filter(d => onDrill(d.resource)).map(d => ({ principal: d.principal, action: d.action, result: d.result }));
  // With no engine decision about the drill ticket, everything the application recorded doing there was done
  // without an answer: a committed governed audit row, or a refund row that binds to no audit row.
  const audit = run.windows?.['start>end']?.find(w => w.instanceId === AUDIT_INSTANCE)?.events ?? [];
  const unanswered = leaked.length ? [] : [
    ...audit.filter(e => e.outcome === 'committed' && scenario.governed.includes(e.name) && onDrill(e.resource)).map(e => ({ record: 'audit-row', seq: e.seq, principal: e.actor, action: e.name })),
    ...unbound.filter(u => ticketOf(u.refund) !== null && onDrill(`tickets/${ticketOf(u.refund)}`)).map(u => ({ record: 'refund-row', refund: u.refund, amount: u.amount, reason: u.reason })),
  ];
  const notInduced = scenario.outageAttempts.filter(x => !asked.has(digest(x)));
  // The engine also served the window's sentinel, which the harness asks it directly.
  const bypassed = decisions.served !== null && gate.forwarded !== decisions.served - 1;
  const controls = scenario.controls.filter(id => run.results?.find(r => r.id === id)?.status !== 'pass');
  const logComplete = decisions.coverage === 'complete';
  const no = reason => ({ status: 'inconclusive', reason });
  const de03 = duringFault.length || unanswered.length
    ? (logComplete ? { status: 'fail', reason: 'effect-during-gate-fault' } : no(`decision-log-${decisions.coverage}`))
    : leaked.length ? no('fault-leaked')
      : unbound.length ? no('effect-unbound')
        : unknown ? no('effect-input-unknown')
          : gate.errors.length ? no('gate-log-partial')
            : run.aborted ? no(`sequence-aborted:${run.aborted}`)
              : notInduced.length ? no('fault-not-induced')
                : !logComplete ? no(`decision-log-${decisions.coverage}`)
                  : bypassed ? no('gate-bypassed')
                    : auditCoverage !== 'complete' ? no(`audit-${auditCoverage}`)
                      : !['complete', 'net-only'].includes(snapshotCoverage) ? no(`snapshot-${snapshotCoverage}`)
                        : controls.length ? no('controls-not-landed')
                          : { status: 'pass', reason: 'acted-on-nothing-the-gate-failed-to-answer' };
  return [de01, de02,
    { id: 'DE-03', title: 'The application acted on nothing its policy gate failed to answer', severity: 'high', ...de03, mode: gate.mode, duringFault, unanswered, leaked, notInduced, faulted: gate.faulted, forwarded: gate.forwarded, served: decisions.served, controlsNotLanded: controls }];
}

const sealed = record => { const { recordDigest: _d, ...rest } = record; return digest(rest); };

export function wrapGateOutageRun({ run, decisions, refunds, issued, gate, scenario, engine, target }) {
  const record = { schema: GATE_OUTAGE_SCHEMA, run, decisions, refunds, refundsIssued: issued, gate, scenario: stored(scenario),
    engine: { kind: engine.kind, version: decisions.events.find(e => e.engine?.version)?.engine.version ?? null }, target, limitations: [...GATE_OUTAGE_LIMITATIONS],
    results: judgeGateOutage({ run, decisions, refunds, issued, gate, scenario }) };
  return { ...record, recordDigest: sealed(record) };
}

// Refuses a record whose verdicts, gate log, coverage, scenario or seal do not follow from what it
// stores and from the scenario as written here, for the mode it names. actors: as the run used them.
export function validateGateOutageRun(record, { actors }) {
  const no = code => { throw new DecisionEffectError(code); };
  if (record?.schema !== GATE_OUTAGE_SCHEMA) no('schema');
  if (record.recordDigest !== sealed(record)) no('record-digest');
  if (!GATE_FAULT_MODES.includes(record.scenario?.mode)) no('scenario');
  const scenario = outageScenario({ actors, mode: record.scenario.mode });
  if (digest(record.scenario) !== digest(stored(scenario))) no('scenario');
  validateSequenceRun(record.run, { expectedSequence: scenario.sequence });
  validateStoredEvidence(record, no);
  const g = record.gate, count = n => Number.isInteger(n) && n >= 0;
  if (g?.schema !== GATE_FAULT_SCHEMA || g.mode !== scenario.mode || g.faultResource !== scenario.faultResource || !count(g.forwarded) || !Array.isArray(g.faults) || g.faulted !== g.faults.length
    || !Array.isArray(g.errors) || !g.errors.every(e => GATE_ERRORS.includes(e)) || new Set(g.errors).size !== g.errors.length
    || !g.faults.every(f => Number.isInteger(f?.seq) && f.resource === scenario.faultResource && /^[a-f0-9]{64}$/.test(f.inputDigest ?? ''))) no('gate-log');
  if (digest(judgeGateOutage({ run: record.run, decisions: record.decisions, refunds: record.refunds, issued: record.refundsIssued, gate: g, scenario })) !== digest(record.results)) no('verdicts');
  return { valid: true, results: record.results };
}

// One drill run. The desk must already ask the fault gate (gate.origin) in place of the engine; the
// decision window and its sentinel go to the engine directly.
export async function runGateOutage({ deskOrigin, dbPath, engine, gate, sink, actors, env, target, flushTimeoutMs }) {
  const scenario = outageScenario({ actors, mode: gate.mode });
  if (gate.faultResource !== scenario.faultResource) throw new Error(`The gate must fail ${scenario.faultResource}.`);
  const window = decisionWindow({ sink, engineOrigin: engine.origin, decisionPath: DESK_DECISION_PATH, ...(flushTimeoutMs ? { flushTimeoutMs } : {}) });
  const start = deskRefunds(dbPath).issued, mark = gate.mark();
  await window.begin();
  const run = await runSequence(scenario.sequence, { origin: deskOrigin, observers: deskObservers({ dbPath, actors }), env });
  const decisions = await window.end();
  const end = deskRefunds(dbPath);
  return wrapGateOutageRun({ run, decisions, refunds: end.rows, issued: { start, end: end.issued }, gate: gate.since(mark), scenario, engine, target });
}
