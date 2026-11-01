// Boundary sweep runner: the baseline, then every planned execution, each a ScopeHaven sequence run (the same
// runSequence and hold gate as `./scopehaven sequence`) against a fresh world, then the case verdict.
//
// startWorld(gateFor) starts one fresh copy of the application and resolves { origin, credentials, stop }:
//   gateFor(upstream) is called once with the application's upstream base URL (model, tools, deliveries), starts a
//   hold gate in front of it on a port the OS picks, and resolves the gate's URL, which the world points the
//   application at before it starts it. credentials maps SCOPEHAVEN_TARGET_ names to values for this world only;
//   they reach the sequence as its environment and are never written.
// Each run is saved as the sequences CLI saves it (<sequence id>-<12 digest characters>.json, mode 0600, beside its
// seq.json and gate.json), re-validated from its sealed windows at once, and can be re-checked later with
// `./scopehaven sequence --validate RUN --sequence seq.json` (recheckRun below also binds the gate's scope).
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { runSequence } from '../sequence.mjs';
import { createHoldGate } from '../gate.mjs';
import { buildObservers, declaredObservers } from '../cli.mjs';
import { validateSequenceRun } from '../run-validator.mjs';
import { CREDENTIAL_ENV } from '../../observers/events.mjs';
import { validateSweepSpec, passiveOf } from './spec.mjs';
import { baselineSequence, baselineGate, observeBaseline, planSweep, executionSequence, executionGate } from './plan.mjs';
import { executionOutcome, caseVerdict, passiveCalls } from './aggregate.mjs';

export const SWEEP_REPORT_SCHEMA = 'scopehaven-sweep-report/1';
export const SWEEP_LIMITATIONS = Object.freeze([
  'Boundaries are the upstream calls one baseline turn made. A turn that makes different calls on another run can have boundaries the baseline did not show.',
  'Only declared actions are judged. A call on a path the spec declares neither as an action nor as passive makes the case abstain; an action the application applies without reaching the hold gate is not seen.',
  'The spec\'s observers are recorded and sealed with every run, but no row selects them: they are never judged.',
  'A pass rests on the calls that reach the upstream through the hold gate. An action the application applies by another route is not observed: the gate shows a live route, not an exclusive one.',
  'A declared refusal (actions[].rejected) is the operator\'s statement that the upstream never answers that status after applying the call.',
  'A passive path is the operator\'s statement that the route applies nothing. A passive call that wrote is caught by its answer (201, 202 or 204), its method, or a method override it carries in an X-HTTP-Method-Override, X-HTTP-Method or X-Method-Override header or a _method parameter (anything but GET, HEAD, OPTIONS, TRACE or POST); a write answered 200 and sent as POST with no override, or as a safe method misused for a write, is not.',
  'Each run starts a fresh world from the world launcher; state kept outside the world is not reset.',
]);
const writeJson = (path, value) => writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
const credentialsOnly = credentials => {
  const entries = Object.entries(credentials ?? {});
  if (!entries.every(([name, value]) => CREDENTIAL_ENV.test(name) && typeof value === 'string')) throw new Error('A world\'s credentials must map SCOPEHAVEN_TARGET_ names to strings.');
  return Object.fromEntries(entries);
};

// The observers a saved run must have been recorded by: the spec's (built, never started) and then the gate's.
export function expectedObserversFor(observerConfigs, gateConfig) {
  if (observerConfigs?.length) return declaredObservers(observerConfigs, gateConfig);
  const { instanceId, source, kind, scope } = createHoldGate(gateConfig).observer();
  return [{ instanceId, source, kind, scope }];
}
// Re-check a saved run from its sealed windows, bound to its sequence and to the gate configuration that recorded it.
export function recheckRun({ run, sequence, gateConfig, observerConfigs = [] }) {
  validateSequenceRun(run, { expectedSequence: sequence, expectedObservers: expectedObserversFor(observerConfigs, gateConfig) });
  return true;
}

// Before the access change, every request the gate has forwarded must have been answered: one sent before the change
// and answered after it could have been applied on either side, and the gate cannot tell which. The drain also waits
// until the gate has recorded nothing new for DRAIN_QUIET_MS, so a call sent at the same moment as the held one (a
// parallel tool call) is forwarded and answered first instead of starting during the change. The sequence holds the
// target as the k-th awaitHold of its rule; this wrapper drains right after that hold, and a drain that does not
// finish within the hold timeout stops the run (inconclusive). A call that still starts during the change lands in
// the execution's change window and keeps it from passing.
export const DRAIN_POLL_MS = 10, DRAIN_QUIET_MS = 100;
export function drainingGate(gate, target) {
  let holds = 0;
  const drained = async timeoutMs => {
    const until = Date.now() + timeoutMs;
    let seen = gate.timeline.length, quietSince = Date.now();
    for (;;) {
      if (gate.timeline.length !== seen) { seen = gate.timeline.length; quietSince = Date.now(); }
      const answered = new Set(gate.timeline.filter(e => e.type === 'response' || e.type === 'upstream-error').map(e => e.reqId));
      if (gate.timeline.every(e => e.type !== 'forwarded' || answered.has(e.reqId)) && Date.now() - quietSince >= DRAIN_QUIET_MS) return;
      if (Date.now() > until) throw Object.assign(new Error('A request forwarded before the access change was still unanswered.'), { code: 'drain-timeout' });
      await new Promise(resolve => setTimeout(resolve, DRAIN_POLL_MS));
    }
  };
  return {
    get timeline() { return gate.timeline; },
    heldIds: () => gate.heldIds(), release: holdId => gate.release(holdId), drop: holdId => gate.drop(holdId),
    async awaitHold(ruleId, timeoutMs) {
      const holdId = await gate.awaitHold(ruleId, timeoutMs);
      if (target && ruleId === target.rule && ++holds === target.k) await drained(timeoutMs);
      return holdId;
    },
  };
}

// One sequence run against a fresh world. Resolves { run, runFile, validated }. `target` ({ rule, k }) is the request
// an execution holds (none for the baseline). `recheck` is recheckRun unless a test replaces it.
export async function runOnFreshWorld({ spec, sequence, rules, startWorld, dir, target = null, recheck = recheckRun }) {
  let gate = null, gateConfig = null, world;
  try {
    world = await startWorld(async upstream => {
      if (gate) throw new Error('A world asks for one hold gate.');
      gate = createHoldGate({ upstream, rules });
      await gate.start();
      gateConfig = { upstream, port: Number(new URL(gate.url).port), rules };
      return gate.url;
    });
  } catch (error) { if (gate) await gate.stop().catch(() => {}); throw error; }
  try {
    if (!gate) throw new Error('The world never asked for a hold gate, so its upstream calls cannot be observed.');
    const env = credentialsOnly(world.credentials);
    const observerConfigs = spec.observers ?? [];
    const watchedResources = [...new Set(sequence.assertions.map(a => a.effect.select.resource).filter(r => typeof r === 'string'))];
    const built = observerConfigs.length ? buildObservers(observerConfigs, { env, watchedResources }) : [];
    const run = await runSequence(sequence, { origin: world.origin, observers: [...built, gate.observer()], gate: drainingGate(gate, target), env });
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeJson(join(dir, 'seq.json'), sequence);
    writeJson(join(dir, 'gate.json'), gateConfig);
    if (observerConfigs.length) writeJson(join(dir, 'observers.json'), observerConfigs);
    const runFile = join(dir, `${run.sequenceId}-${run.runDigest.slice(0, 12)}.json`);
    writeJson(runFile, run);
    let validated = false;
    try { validated = recheck({ run, sequence, gateConfig, observerConfigs }) === true; } catch { validated = false; }
    return { run, runFile, validated };
  } finally {
    // The world first: stopping it ends any request still open through the gate, which the gate's close would wait for.
    try { await world.stop(); }
    finally { if (gate) await Promise.race([gate.stop().catch(() => {}), new Promise(resolve => setTimeout(resolve, 5000).unref())]); }
  }
}

async function pool(items, limit, work) {
  const queue = [...items], workers = [];
  for (let i = 0; i < Math.max(1, Math.min(limit, queue.length)); i++) workers.push((async () => { while (queue.length) await work(queue.shift()); })());
  await Promise.all(workers);
}

export async function runSweep({ spec, startWorld, outDir, concurrency = 1, log = () => {}, recheck = recheckRun }) {
  validateSweepSpec(spec);
  const startedAt = new Date().toISOString();
  mkdirSync(outDir, { recursive: true, mode: 0o700 });
  let baseline = null, baselineError = null;
  try { baseline = await runOnFreshWorld({ spec, sequence: baselineSequence(spec), rules: baselineGate(spec).rules, startWorld, dir: join(outDir, 'baseline'), recheck }); }
  catch (error) { baselineError = String(error?.message ?? error).slice(0, 200); }
  const observation = baseline?.validated ? observeBaseline(baseline.run, spec)
    : { observed: false, allowedUse: false, allowedActions: [], calls: [], counts: {}, reasons: [baseline ? 'baseline-not-revalidated' : 'baseline-error'] };
  const plan = planSweep(spec, observation);
  log(`${spec.id}: baseline ${observation.observed ? `observed ${observation.calls.length} calls` : `not observed (${observation.reasons.join(', ')})`}${observation.allowedUse ? ', allowed use shown' : ''}`);
  const outcomes = [];
  await pool(plan.executions.filter(e => e.runnable), concurrency, async e => {
    let outcome;
    try {
      const done = await runOnFreshWorld({ spec, sequence: executionSequence(spec, e), rules: executionGate(spec, e).rules, startWorld, dir: join(outDir, 'executions', e.id), target: e, recheck });
      outcome = done.validated ? { id: e.id, ...executionOutcome(done.run, spec, e), passiveCalls: passiveCalls(done.run, spec), runFile: done.runFile, validated: true }
        : { id: e.id, result: 'INCONCLUSIVE', fired: false, reason: 'run-not-revalidated', runFile: done.runFile, validated: false };
    } catch (error) { outcome = { id: e.id, result: 'INCONCLUSIVE', fired: false, reason: `error:${String(error?.message ?? error).slice(0, 200)}`, runFile: null, validated: false }; }
    outcomes.push(outcome);
    log(`${spec.id}: ${e.id} ${outcome.result}${outcome.reason ? ` (${outcome.reason})` : ''}`);
  });
  const order = new Map(plan.executions.map((e, i) => [e.id, i]));
  outcomes.sort((a, b) => order.get(a.id) - order.get(b.id));
  const { verdict, reasons } = caseVerdict({ observation, plan, outcomes });
  const report = { schema: SWEEP_REPORT_SCHEMA, specId: spec.id, applicationId: spec.applicationId ?? null, contextId: spec.contextId ?? null, startedAt, finishedAt: new Date().toISOString(),
    baseline: { runFile: baseline?.runFile ?? null, validated: baseline?.validated ?? false, error: baselineError, observed: observation.observed, allowedUse: observation.allowedUse, allowedActions: observation.allowedActions, reasons: observation.reasons,
      calls: observation.calls.map(({ rule, k, method, overrides, status }) => ({ rule, k, method, overrides, status })),
      // Every passive call, listed so a reader can see what the spec declared read-only, how it was sent and what it answered.
      passiveCalls: observation.calls.filter(c => passiveOf(spec).some(p => p.id === c.rule)).map(({ rule, k, method, overrides, status }) => ({ rule, k, method, overrides, status })) },
    plan: { executions: plan.executions, unreachable: plan.unreachable }, outcomes, verdict, reasons, limitations: [...SWEEP_LIMITATIONS] };
  writeJson(join(outDir, 'report.json'), report);
  log(`${spec.id}: ${verdict}${reasons.length ? ` (${reasons.join(', ')})` : ''}`);
  return report;
}
