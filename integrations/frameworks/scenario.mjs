// A frozen framework scenario (scopehaven-framework-scenario/1). Pure: no I/O.
//
// One file names the template (repository, path, pinned commit, licence), the
// adapter that loads it, the seed files the run needs (each pinned by sha256),
// what state ScopeHaven reads, the user turns, the stub-model scripts, an
// optional fault, and what the run must show:
//   decide 'goal'      the requested change persisted, with the declared content,
//                      and nothing else changed (COLLATERAL-01, the goal, FW-CONTENT)
//   decide 'said-did'  the final reply's claim agrees with what persisted
//                      (COLLATERAL-01, FW-SAID-DID), under a ScopeHaven-planned
//                      fault (which must fire) or a declared condition:
//                      'environment' (set outside ScopeHaven, which neither plans
//                      nor sees it) or 'none' (the template as it ships). An honest
//                      "I could not do it" with nothing persisted then agrees.
//   decide 'no-change' nothing may change (expect: []): COLLATERAL-01 decides, and
//                      the scenario names its guard: an allowed-use control of the
//                      same agent (a goal scenario) and the tools that make the
//                      forbidden change (guard.tools). The control's stored run must
//                      show the agent making that kind of change through one of them;
//                      a call to one in this run fails (FW-GUARD), so an agent that
//                      does nothing never passes and a forbidden call never does
// Claims (claim-reader.mjs) are declared exact sentences, compared after
// normalisation, and optionally declared patterns (claims.read) that name the
// bound action from the task text. Whatever the reader is unsure of leaves the
// row inconclusive, never a pass.
import { digest } from '../../src/domain.mjs';
import { validateFaultPlan } from './fault.mjs';
import { validateStateSpec, validateExpectations } from './state.mjs';
import { validateSteps, bounded, CONTRACT_LIMITS } from './contract.mjs';
import { validateClaims } from './claim-reader.mjs';

export const SCENARIO_SCHEMA = 'scopehaven-framework-scenario/1';
export const DECIDE_MODES = Object.freeze(['goal', 'said-did', 'no-change']);
export const CONDITIONS = Object.freeze(['environment', 'none']);
export const RUNTIMES = Object.freeze(['python', 'tsx']);
export class ScenarioError extends Error { constructor(code) { super(`Framework scenario: ${code}.`); this.name = 'ScenarioError'; this.code = code; } }
const fail = code => { throw new ScenarioError(code); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const onlyKeys = (value, keys) => Reflect.ownKeys(value).every(key => keys.includes(key));
const SHA256 = /^[0-9a-f]{64}$/;
const RELATIVE = /^(?!\/)(?!.*(^|\/)\.\.(\/|$))[A-Za-z0-9_./-]{1,200}$/;

export function validateScenario(s) {
  if (!plain(s) || s.schema !== SCENARIO_SCHEMA) fail('schema');
  if (!onlyKeys(s, ['schema', 'id', 'title', 'template', 'adapter', 'workdir', 'state', 'turns', 'stubs', 'fault', 'condition', 'decide', 'guard', 'expect', 'allow', 'claims', 'limits'])) fail('field');
  if (!/^[a-z0-9][a-z0-9.-]{0,79}$/.test(s.id ?? '') || !bounded(s.title, 200)) fail('id');
  const t = s.template;
  if (!plain(t) || !onlyKeys(t, ['id', 'repo', 'path', 'commit', 'license']) || !bounded(t.id, 64) || !bounded(t.repo, 200) || !bounded(t.path, 300) || !/^[0-9a-f]{40}$/.test(t.commit ?? '') || !bounded(t.license, 120)) fail('template');
  if (!plain(s.adapter) || !onlyKeys(s.adapter, ['runtime', 'entry', 'args']) || !RUNTIMES.includes(s.adapter.runtime) || !RELATIVE.test(s.adapter.entry ?? '')) fail('adapter');
  if (s.adapter.args !== undefined && !(Array.isArray(s.adapter.args) && s.adapter.args.length <= 16 && s.adapter.args.every(a => bounded(a, 200)))) fail('adapter-args');
  if (!plain(s.workdir) || !onlyKeys(s.workdir, ['seed']) || !Array.isArray(s.workdir.seed) || s.workdir.seed.length > 8) fail('workdir');
  for (const seed of s.workdir.seed) if (!plain(seed) || !onlyKeys(seed, ['from', 'to', 'sha256']) || !RELATIVE.test(seed.from ?? '') || !/^[A-Za-z0-9_.-]{1,128}$/.test(seed.to ?? '') || !SHA256.test(seed.sha256 ?? '')) fail('seed');
  validateStateSpec(s.state);
  if (!Array.isArray(s.turns) || !s.turns.length || s.turns.length > CONTRACT_LIMITS.turns || !s.turns.every(x => bounded(x, CONTRACT_LIMITS.text))) fail('turns');
  if (!plain(s.stubs) || !Object.keys(s.stubs).length) fail('stubs');
  for (const [id, script] of Object.entries(s.stubs)) {
    if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(id) || !Array.isArray(script) || script.length !== s.turns.length) fail('stub-turns');
    script.forEach((steps, i) => validateSteps(steps, `stub-${id}-turn-${i + 1}`));
  }
  if (!Object.hasOwn(s, 'fault')) fail('fault-missing');
  try { validateFaultPlan(s.fault); } catch { fail('fault'); }
  if (!DECIDE_MODES.includes(s.decide)) fail('decide');
  validateExpectations(s.expect, s.state.projections, 'expect');
  validateExpectations(s.allow, s.state.projections, 'allow');
  // A no-change scenario expects nothing, by declaration; every other mode needs an expected change.
  if (s.decide === 'no-change' ? s.expect.length : !s.expect.length) fail(s.decide === 'no-change' ? 'no-change-expects-nothing' : 'expect-empty');
  if ((s.guard !== undefined) !== (s.decide === 'no-change') || (s.guard !== undefined && !(plain(s.guard) && onlyKeys(s.guard, ['scenario', 'tools', 'reads']) && /^[a-z0-9][a-z0-9.-]{0,79}$/.test(s.guard.scenario ?? '') && s.guard.scenario !== s.id))) fail('guard');
  // The guard names the tools that make the forbidden change and, optionally, the reads the request needs.
  const toolList = list => Array.isArray(list) && list.length >= 1 && list.length <= 16 && list.every(x => bounded(x, 128));
  if (s.guard !== undefined && (!toolList(s.guard.tools) || (s.guard.reads !== undefined && !toolList(s.guard.reads)))) fail('guard-tools');
  // A no-change scenario plans no fault and reads no claim: it decides on persisted state alone.
  if (s.decide === 'no-change' && (s.fault !== null || s.claims !== undefined)) fail('no-change-state-only');
  if (s.claims !== undefined) try { validateClaims(s.claims); } catch (error) { fail(error.code ?? 'claims'); }
  // A condition is declared only where no fault is planned, and only for said-did and no-change.
  if (s.condition !== undefined && !(CONDITIONS.includes(s.condition) && s.fault === null && ['said-did', 'no-change'].includes(s.decide))) fail('condition');
  if (s.decide === 'said-did' && (s.claims === undefined || (s.fault === null && s.condition === undefined))) fail('said-did-needs-claims-and-a-fault-or-condition');
  if (s.limits !== undefined && !(plain(s.limits) && onlyKeys(s.limits, ['readyMs', 'turnMs', 'settleMs']) && Object.entries(s.limits).every(([k, v]) => Number.isSafeInteger(v) && (k === 'settleMs' ? v >= 50 && v <= 60000 : v >= 1000 && v <= 900000)))) fail('limits');
  return s;
}

// A guard is tied to the change the no-change scenario forbids: the control expects a change in a
// collection both scenarios project the same way, which this scenario does not allow. An allowance
// covers the control's change unless a field both their `where`s name holds no value in common (a
// value list is any of its values): COLLATERAL-01 resolves the `where` on the rows before the turn, so
// a field the control's expectation does not name can still select the row the control changes. Its
// `after` is not read, because COLLATERAL-01 allows whatever the `where` selects: an `after` that excludes
// the control's change must not make the guard related. The collections a control covers are the ones its pass can speak for.
export function guardCovers(s, control) {
  // The same data, whoever reports it: custody is the snapshots' question (an app report never passes).
  const projection = (sc, name) => sc.state.projections.find(p => p.collection === name);
  const data = p => digest({ ...p, source: p.source === 'app-report' ? 'object-path' : p.source });
  // An allowance covers the control's change unless a field both name keeps them apart (no value in common):
  // COLLATERAL-01 allows whatever its `where` selects, and a field only one of them names does not separate them.
  const covered = (want, got) => want === undefined || got === undefined || Object.entries(want).every(([f, v]) => !Object.hasOwn(got, f) || [].concat(got[f]).some(x => [].concat(v).some(y => digest(x) === digest(y))));
  const allows = (a, e) => covered(a.where, e.where);
  const related = control.expect.filter(e => {
    const mine = projection(s, e.collection), theirs = projection(control, e.collection);
    return mine && theirs && data(mine) === data(theirs) && (mine.source !== 'sqlite-file' || s.state.sqliteFile === control.state.sqliteFile)
      && !s.allow.some(a => a.collection === e.collection && a.op === e.op && allows(a, e));
  });
  return [...new Set(related.map(e => e.collection))];
}

// Refused by name when the control covers nothing ('guard-unrelated'): a control of another
// capability, or of a change this scenario allows, shows nothing here. Coverage reads the control's
// expectation as the row its change hits, so both must start from the same seed files
// ('guard-other-workdir'): from other data an allowance kept apart from that row by its declared
// values can select the very row a forbidden change hits on this run's BEFORE.
export function validateGuard(s, control) {
  validateScenario(s);
  validateScenario(control);
  const seeded = sc => digest(sc.workdir.seed.map(x => [x.to, x.sha256]));
  if (seeded(s) !== seeded(control)) fail('guard-other-workdir');
  if (!guardCovers(s, control).length) fail('guard-unrelated');
  return s;
}

export const scenarioDigest = s => digest(validateScenario(s));
export const stubDigest = (s, id) => digest(s.stubs[id]);
