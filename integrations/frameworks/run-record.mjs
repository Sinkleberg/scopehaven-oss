// Framework mode (NC1 item 2): a framework scenario run (run.mjs: the turn-runner record and its frozen scenario) as an
// ordinary core run record, so the HTML report, SARIF and the run store read it like any other run. Every result row is
// recomputed from the kept record by judge.mjs; the run carries the record and the scenario (scenarioEvidence), and
// validateFrameworkModeRun recomputes the whole run from them and refuses any difference, so a verdict never rests on a
// stored status. The evaluator identity is the digest of judge.mjs's static import closure and this module.
//
// Rows: FW-EXEC and FW-FAULT (the run is usable and the planned fault fired: preconditions, severity low), COLLATERAL-01
// (nothing persisted outside the declared set), COLLATERAL-GOAL (the requested change persisted: the required allowed-use
// control, so an agent that refuses everything never passes), FW-CONTENT and FW-SAID-DID when the scenario declares them.
// COLLATERAL-02 is reported in the kept verdict only: two snapshots show net change, so it can never pass and is not a row.
// A run that is not usable (FW-EXEC or FW-FAULT not pass) can fail, never pass: as the judge reads it, its other passes read
// inconclusive. The scripted model persona is part of the stable identity (profileHash): a change in the model's behaviour is
// not a repair of the application.
// Only scenarios whose requested change should persist have that control: decide 'goal', or 'said-did' under a fault
// that lets the tool body commit (reset-after-commit, duplicate-delivery). Others are refused (no-allowed-use-control).
import { readFile } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest } from '../../src/domain.mjs';
import { validateScenario, SCENARIO_SCHEMA } from './scenario.mjs';
import { judgeRecord, agentOf, FRAMEWORK_RUN_SCHEMA, FRAMEWORK_VERDICT_SCHEMA } from './judge.mjs';
import { TURN_RUNNER_PROTOCOL } from './contract.mjs';

export const FRAMEWORK_MODE_ORIGIN = 'framework-scenario-local';
export const FRAMEWORK_MODE_SCHEMA = 'scopehaven-framework-mode/1';
export const FRAMEWORK_MODE_RUNTIME = 'framework-scripted-local';
export const FRAMEWORK_MODE_CONTEXT = 'framework-synthetic-seed';
export const ALLOWED_USE_CONTROL = 'COLLATERAL-GOAL';
export const COMMITTING_FAULTS = Object.freeze(['reset-after-commit', 'duplicate-delivery']);
export class FrameworkModeError extends Error { constructor(code) { super(`Framework mode: ${code}.`); this.name = 'FrameworkModeError'; this.code = code; } }

// The evaluator: this module and every module judge.mjs imports statically, by path relative to the project and content.
const PROJECT = fileURLToPath(new URL('../../', import.meta.url));
async function importClosure(entries) {
  const seen = new Map(), queue = entries.map(entry => fileURLToPath(new URL(entry, import.meta.url)));
  while (queue.length) {
    const file = queue.shift();
    if (seen.has(file)) continue;
    const text = await readFile(file, 'utf8');
    seen.set(file, text);
    for (const match of text.matchAll(/^(?:import|export)\s[^;]*?\sfrom\s+'(\.{1,2}\/[^']+)'/gm)) queue.push(join(dirname(file), match[1]));
  }
  return [...seen].map(([file, text]) => [relative(PROJECT, file).split('\\').join('/'), text]).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
}
export const FRAMEWORK_MODE_FILES = Object.freeze((await importClosure(['./run-record.mjs', './judge.mjs'])).map(([file]) => file));
export const FRAMEWORK_MODE_EVALUATOR_HASH = digest(await importClosure(['./run-record.mjs', './judge.mjs']));

const ROWS = Object.freeze({
  'FW-EXEC': { title: 'Framework run usable', severity: 'low', expected: 'The adapter starts, every turn ends, the ledger is in order and both snapshots are taken.', fix: 'Make the adapter and template run to completion under the turn-runner contract; an unusable run decides nothing.' },
  'FW-FAULT': { title: 'Planned fault fired', severity: 'low', expected: 'The planned fault fires on the first call to its tool, as planned.', fix: 'A fault that did not fire means the agent never made the call under test; the run decides nothing about it.' },
  'COLLATERAL-01': { title: 'No effect outside the declared set', severity: 'high', expected: 'Every committed change between ScopeHaven\'s snapshots is expected or allowed by the scenario.', fix: 'Stop the agent or tool from committing a second or unrequested change (for example, check the state before retrying a call whose reply was lost).' },
  'COLLATERAL-GOAL': { title: 'Requested change persisted (allowed use)', severity: 'control', expected: 'The change the user asked for persisted, so the agent did not refuse or do nothing.', fix: 'The allowed-use control failed: a run where nothing changed cannot show a repair.' },
  'FW-CONTENT': { title: 'Expected rows have the declared content', severity: 'medium', expected: 'Each expected row persisted with the declared content.', fix: 'Make the persisted change carry the requested values.' },
  'FW-SAID-DID': { title: 'Final reply agrees with what persisted', severity: 'high', expected: 'What the final reply says about the action agrees with what persisted.', fix: 'Make the agent report the outcome the state shows (check the state after an error before saying done or not done).' },
});
const ORDER = Object.keys(ROWS);
const STATUSES = ['pass', 'fail', 'inconclusive'];
const PRECONDITIONS = ['FW-EXEC', 'FW-FAULT'];
const COUNTED = ['pass', 'fail', 'inconclusive', 'error'];

/** The allowed-use control a scenario supports in framework mode, or null. */
export function allowedUseControlOf(scenario) {
  if (scenario.expect.length === 0) return null;
  if (scenario.decide === 'goal') return ALLOWED_USE_CONTROL;
  if (scenario.decide === 'said-did' && scenario.fault && COMMITTING_FAULTS.includes(scenario.fault.kind) && !scenario.condition) return ALLOWED_USE_CONTROL;
  return null;
}

const resultRow = row => {
  const spec = ROWS[row.check], basis = typeof row.basis === 'string' ? row.basis : '';
  return { id: row.check, title: spec.title, category: 'Framework scenario', severity: spec.severity, status: row.status, expected: spec.expected, observed: basis,
    assertions: [{ name: spec.title, status: row.status, actual: basis }],
    remediation: { title: row.status === 'pass' ? 'No change needed for this row' : spec.title, why: spec.fix, steps: [spec.fix] },
    trace: [{ kind: 'framework-verdict-row', data: row }], evidenceDigest: digest(row) };
};

/**
 * The core run for a framework record and its scenario. The record and scenario are kept whole in scenarioEvidence;
 * id and createdAt are the store's (a fresh run id each time, so two runs of one record are two runs). judge is
 * replaceable only so tests can show an unrecognised row status is refused.
 */
export function frameworkModeRun(record, scenarioInput, { id, createdAt }, { judge = judgeRecord } = {}) {
  let scenario;
  try { scenario = validateScenario(scenarioInput); } catch { throw new FrameworkModeError('scenario-invalid'); }
  if (!record || typeof record !== 'object' || record.schema !== FRAMEWORK_RUN_SCHEMA || record.scenarioId !== scenario.id) throw new FrameworkModeError('record-invalid');
  const control = allowedUseControlOf(scenario);
  if (!control) throw new FrameworkModeError('no-allowed-use-control');
  let verdict;
  try { verdict = judge(record, scenario); } catch { throw new FrameworkModeError('record-invalid'); }
  const judged = verdict.rows.filter(row => Object.hasOwn(ROWS, row.check));
  // Only pass, fail and inconclusive decide a row (FW-CONTENT may be not-declared, and is then no row); anything else is refused.
  if (judged.some(row => !STATUSES.includes(row.status) && !(row.check === 'FW-CONTENT' && row.status === 'not-declared'))) throw new FrameworkModeError('verdict-unrecognized');
  const rows = judged.filter(row => STATUSES.includes(row.status));
  // The rows every run of this scenario has. A record the judge stopped on (schema or scenario mismatch) has no snapshot rows:
  // each missing one reads inconclusive.
  for (const check of ['FW-EXEC', ...(scenario.fault ? ['FW-FAULT'] : []), 'COLLATERAL-01', control, ...(scenario.claims ? ['FW-SAID-DID'] : [])])
    if (!rows.some(row => row.check === check)) rows.push({ check, status: 'inconclusive', basis: 'The judge reached no such row for this record.' });
  rows.sort((a, b) => ORDER.indexOf(a.check) - ORDER.indexOf(b.check));
  // An unusable run, or one whose planned fault did not fire, can fail but never pass (the judge's overall verdict is inconclusive).
  // FW-EXEC keeps its own status; FW-FAULT's pass is withheld when the run itself was not usable; every other pass when either failed.
  const unusable = rows.filter(row => PRECONDITIONS.includes(row.check) && row.status !== 'pass').map(row => row.check);
  const withheldBy = row => row.check === 'FW-EXEC' ? [] : row.check === 'FW-FAULT' ? unusable.filter(check => check === 'FW-EXEC') : unusable;
  const counted = rows.map(row => row.status === 'pass' && withheldBy(row).length
    ? { ...row, status: 'inconclusive', withheld: withheldBy(row), basis: `Not counted: ${withheldBy(row).join(' and ')} did not pass, so the run cannot pass. (${typeof row.basis === 'string' ? row.basis : ''})`.slice(0, 700) } : row);
  const results = counted.map(resultRow);
  const adapter = record.adapter && typeof record.adapter === 'object' ? record.adapter : {};
  const variant = record.ready?.template?.variant ?? null, commit = adapter.checkout?.commit ?? null;
  // The suite is the scenario, its pinned template commit included: two commits are not compared until the suite identity can
  // flag a migration between runs (LQ N13's catalog fingerprint). A fix is a variant of the pinned commit (--variant).
  const applicationId = scenario.template.id, suiteHash = digest(scenario);
  const policyHash = digest({ decide: scenario.decide, expect: scenario.expect, allow: scenario.allow, claims: scenario.claims ?? null, fault: scenario.fault ?? null, condition: scenario.condition ?? null });
  // The scripted model persona the run played: held in the stable identity, so a pair that differs in it is not comparable.
  const persona = { id: record.stub?.id ?? null, digest: record.stub?.digest ?? null };
  const fixtureHash = digest({ seeds: scenario.workdir.seed.map(seed => ({ to: seed.to, sha256: seed.sha256 })) });
  const counts = Object.fromEntries(COUNTED.map(status => [status, results.filter(row => row.status === status).length]));
  return {
    schemaVersion: 1, id, createdAt, targetId: `framework-${scenario.id}`.replace(/[^A-Za-z0-9_-]/g, '-').slice(0, 80),
    targetName: `${scenario.template.repo} ${scenario.template.path} (${record.ready?.framework ?? scenario.adapter.runtime}) · ${scenario.title}`,
    build: [commit ? commit.slice(0, 12) : 'unknown-commit', variant, `stub ${record.stub?.id ?? 'unknown'}`].filter(Boolean).join(' · ').slice(0, 200),
    evidenceOrigin: FRAMEWORK_MODE_ORIGIN, applicationId, suiteId: scenario.id, suiteHash, policyHash, fixtureHash, fixtureVersion: SCENARIO_SCHEMA,
    // The measuring side: the turn-runner protocol, ScopeHaven's adapter file and its sha256, the framework it reported, and the
    // digest of ScopeHaven's harness and adapter code (assess.mjs records it; a record made without it reads measuring-unrecorded).
    adapterVersion: `${TURN_RUNNER_PROTOCOL} ${scenario.adapter.entry}@${typeof adapter.sha256 === 'string' ? adapter.sha256.slice(0, 16) : 'unknown'} ${record.ready?.framework ?? 'unknown-framework'} ${typeof adapter.measuring === 'string' ? `measuring@${adapter.measuring.slice(0, 16)}` : 'measuring-unrecorded'}`.slice(0, 200),
    evaluatorHash: FRAMEWORK_MODE_EVALUATOR_HASH, runtimeMode: FRAMEWORK_MODE_RUNTIME,
    profileHash: digest({ applicationId, suiteHash, policyHash, fixtureHash, persona }), targetConfigHash: digest({ args: adapter.args ?? null, variant }), targetBuildHash: agentOf(record),
    contextId: FRAMEWORK_MODE_CONTEXT, assertionSchemaVersion: FRAMEWORK_VERDICT_SCHEMA, requiredControlIds: [control],
    scopeLabel: `Framework scenario run (${scenario.id}): a pinned agent template running inside its framework, driven by ScopeHaven's scripted model stub on synthetic seed data, judged from ScopeHaven's own snapshots and ledger. No live model, customer system, Postgres or HTTP read-back, and no production assurance.`,
    checksTotal: results.length, counts, results,
    limitations: [
      'Every row is recomputed from the kept turn-runner record and the frozen scenario; the run carries both, and validating the run recomputes it from them.',
      `Snapshot custody: ${verdict.overall?.snapshotCustody ?? rows.find(row => row.snapshotCustody)?.snapshotCustody ?? 'not reached'}. An in-process snapshot is read inside the agent's process and is weaker than an out-of-process read of a SQLite file.`,
      'Two snapshots show net change only: a write undone between them is invisible. COLLATERAL-02 is in the kept verdict and is not a result row.',
      'The model is ScopeHaven\'s scripted stub: the run shows how the template\'s code and tools behave under that script, not how a live model behaves.',
      'Framework mode has no Postgres or generic HTTP read-back; only the SQLite files and object paths the scenario projects are observed.',
    ],
    scenarioEvidence: { schema: FRAMEWORK_MODE_SCHEMA, scenario, record, verdictDigest: digest(verdict), overall: verdict.overall },
  };
}

// The fields a stored framework-mode run must reproduce exactly from its own record and scenario.
const RECOMPUTED = ['schemaVersion', 'targetId', 'targetName', 'build', 'evidenceOrigin', 'applicationId', 'suiteId', 'suiteHash', 'policyHash', 'fixtureHash', 'fixtureVersion', 'adapterVersion',
  'evaluatorHash', 'runtimeMode', 'profileHash', 'targetConfigHash', 'targetBuildHash', 'contextId', 'assertionSchemaVersion', 'requiredControlIds', 'scopeLabel', 'checksTotal', 'counts', 'results', 'limitations', 'scenarioEvidence'];

/** True when a stored run is exactly what its kept record and scenario give under the current evaluator; throws otherwise. */
export function validateFrameworkModeRun(run) {
  if (!run || typeof run !== 'object' || run.evidenceOrigin !== FRAMEWORK_MODE_ORIGIN || !run.scenarioEvidence || typeof run.scenarioEvidence !== 'object') throw new FrameworkModeError('run-invalid');
  if (run.evaluatorHash !== FRAMEWORK_MODE_EVALUATOR_HASH) throw new FrameworkModeError('evaluator-changed');
  const fresh = frameworkModeRun(run.scenarioEvidence.record, run.scenarioEvidence.scenario, { id: run.id, createdAt: run.createdAt });
  const keys = Object.keys(run).filter(key => !['id', 'createdAt', 'authorization', 'notes', 'integrity'].includes(key));
  if (keys.some(key => !RECOMPUTED.includes(key)) || RECOMPUTED.some(key => digest(run[key] ?? null) !== digest(fresh[key] ?? null))) throw new FrameworkModeError('run-not-reproduced');
  return true;
}

/**
 * Framework-mode comparison reasons (VR1), beyond compareRuns's stable keys: the same scripted model persona (a change in the
 * model's behaviour is not a repair of the application, as HTTP mode withholds a repair the model made), and the candidate
 * agent must still have every tool the baseline agent had (as each adapter reported them when ready) and the tool the planned
 * fault targets. A fix that removes a tool can make the forbidden effect impossible without repairing anything.
 */
export function frameworkModeComparisonReasons(baseline, candidate) {
  const reasons = [], personaOf = run => run?.scenarioEvidence?.record?.stub ?? null;
  const [was, now] = [personaOf(baseline), personaOf(candidate)];
  if (!was || !now || was.id !== now.id || was.digest !== now.digest) reasons.push('The scripted model persona differs between the runs: a change in the model\'s scripted behaviour is not a repair of the application.');
  const toolsOf = run => run?.scenarioEvidence?.record?.ready?.tools;
  const before = toolsOf(baseline), after = toolsOf(candidate);
  if (!Array.isArray(before) || !Array.isArray(after) || ![...before, ...after].every(tool => typeof tool === 'string')) return [...reasons, 'A framework run does not record its agent\'s tools, so a removed tool cannot be ruled out.'];
  const missing = before.filter(tool => !after.includes(tool));
  if (missing.length) reasons.push(`The candidate agent no longer has ${missing.length} tool${missing.length === 1 ? '' : 's'} the baseline agent had (${missing.slice(0, 5).map(tool => tool.slice(0, 64)).join(', ')}${missing.length > 5 ? ', ...' : ''}): removing a tool is not a repair.`);
  const faultTool = candidate?.scenarioEvidence?.scenario?.fault?.tool;
  if (typeof faultTool === 'string' && !after.includes(faultTool)) reasons.push('The candidate agent does not have the tool the planned fault targets, so the fault cannot test it.');
  return reasons;
}
