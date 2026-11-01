// Evidence contract scopehaven-observation/1: shared vocabulary and strict
// validation for derived, read-only views over saved runs. Pure: no I/O, no
// per-family logic. Views are computed when read and never persisted.
import { digest } from './domain.mjs';
import { SHAPES as READING_SHAPES } from '../integrations/groundedness/groundedness.mjs';

export const CONTRACT_VERSION = 'scopehaven-observation/1';
export const STAGES = Object.freeze(['proposal', 'approval', 'authorization', 'dispatch', 'access', 'commitment', 'disclosure', 'completionTruth', 'requiredReporting']);
export const DIMENSIONS = Object.freeze(['actor', 'task', 'action', 'resource', 'recipient', 'state']);
export const OBSERVATION_STATES = Object.freeze(['observed', 'missing', 'conflicting', 'observer-failure']);
export const STAGE_STATES = Object.freeze(['observed', 'not-exercised', 'unobservable', 'not-derived', 'missing', 'conflicting', 'observer-failure']);
export const CHECK_VERDICTS = Object.freeze(['pass', 'fail', 'missing', 'conflicting', 'not-exercised', 'observer-failure', 'unobservable']);
export const V1_STATUSES = Object.freeze(['pass', 'fail', 'inconclusive', 'error', 'not_applicable']);
export const UNSUPPORTED_REASONS = Object.freeze(['external-attributed', 'not-native-run', 'adapter-not-migrated', 'invalid-family', 'http-version', 'http-version-pending', 'http-version-downgrade',
  'unknown-suite', 'unknown-policy', 'unknown-fixture', 'invalid-view']);
export const LIMITS = Object.freeze({ checks: 1000, observationsPerCheck: 10, eventsPerObservation: 64, assertionsPerCheck: 100, nodes: 250000, depth: 16, stringLength: 512 });

const LINEAGE = Object.freeze({
  observer: ['fixture-control-endpoint', 'workbench-http-transport',
    // Effect observers (integrations/observers), as recorded on sealed HTTP v3 windows.
    'sqlite-snapshot-diff', 'sqlite-audit-table', 'http-audit-endpoint', 'otlp-http-json-receiver', 'mcp-stdio-recorder', 'mcp-http-proxy', 'hold-gate', 'audit-log-file', 'postgres-snapshot-diff'],
  independence: ['self-reported-by-target', 'response-only-connector', 'application-store', 'request-path', 'target-instrumentation'],
  actorTransport: ['complete', 'lost', 'incomplete', 'not-attempted', 'unknown'],
  adapterEmission: ['scopehaven-observation/1', 'derived-from-v1-trace', 'mixed'],
});
// Invariant between a contract verdict and the v1 status it is allowed to refine.
const REFINES = Object.freeze({
  pass: ['pass'], fail: ['fail'], conflicting: ['fail', 'inconclusive', 'error'],
  missing: ['inconclusive', 'error', 'not_applicable'], 'not-exercised': ['inconclusive', 'error', 'not_applicable'],
  'observer-failure': ['inconclusive', 'error', 'not_applicable'], unobservable: ['inconclusive', 'error', 'not_applicable'],
});

export class ContractError extends Error {
  constructor(code, detail) { super(`Invalid evidence contract value: ${code}${detail ? ` at ${detail}` : ''}.`); this.name = 'ContractError'; this.code = code; }
}
const fail = (code, where) => { throw new ContractError(code, where); };
const plainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const text = value => typeof value === 'string' && value.length > 0 && value.length <= LIMITS.stringLength;

// JSON-safe, bounded data: no undefined members, holes, Date/Map/class instances,
// accessors, non-finite numbers or prototype-polluting keys.
function jsonSafe(value, where, budget = { nodes: 0 }, depth = 0) {
  if (++budget.nodes > LIMITS.nodes) fail('bounds', 'node budget');
  if (depth > LIMITS.depth) fail('bounds', where);
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'number') { if (!Number.isFinite(value)) fail('non-json', where); return; }
  if (typeof value === 'string') { if (value.length > LIMITS.stringLength) fail('bounds', where); return; }
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype || Reflect.ownKeys(value).length !== value.length + 1) fail('non-json', where);
    for (let i = 0; i < value.length; i++) {
      if (!Object.hasOwn(value, i)) fail('non-json', `${where}/${i}`);
      jsonSafe(value[i], `${where}/${i}`, budget, depth + 1);
    }
    return;
  }
  if (typeof value === 'object') {
    if (!plainObject(value)) fail('non-json', where);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string' || ['__proto__', 'prototype', 'constructor'].includes(key) || key.length > LIMITS.stringLength) fail('non-json', where);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) fail('non-json', `${where}/${key}`);
      if (descriptor.value === undefined) fail('undefined-member', `${where}/${key}`);
      jsonSafe(descriptor.value, `${where}/${key}`, budget, depth + 1);
    }
    return;
  }
  fail(value === undefined ? 'undefined-member' : 'non-json', where);
}
function shape(value, required, optional, where) {
  if (!plainObject(value)) fail('shape', where);
  const allowed = [...required, ...optional];
  for (const key of Reflect.ownKeys(value)) if (typeof key !== 'string' || !allowed.includes(key)) fail('unknown-key', `${where}/${String(key)}`);
  for (const key of required) if (!Object.hasOwn(value, key)) fail('missing-key', `${where}/${key}`);
}
const oneOf = (value, list, where) => { if (!list.includes(value)) fail('vocabulary', where); };

// A stage or dimension record: a value only when observed, a basis otherwise.
function validateRecord(record, where) {
  shape(record, ['state'], ['value', 'basis', 'granularity'], where);
  oneOf(record.state, STAGE_STATES, `${where}/state`);
  if (record.state === 'observed') {
    if (!Object.hasOwn(record, 'value') || Object.hasOwn(record, 'basis')) fail('observed-record', where);
  } else {
    if (Object.hasOwn(record, 'value')) fail('value-on-non-observed', where);
    if (!text(record.basis)) fail('missing-basis', where);
  }
  if (Object.hasOwn(record, 'granularity') && !text(record.granularity)) fail('shape', `${where}/granularity`);
}

// Readings sit beside the evidence and never decide anything: no verdict, status or
// outcome vocabulary, `prohibition: false`, and no reply text (ungrounded values are
// digests). Counts must agree with each other so a reader cannot be shown a summary
// the details do not support.
export const READING_SCHEMA = 'scopehaven-groundedness-reading/1';
export const GROUNDEDNESS_READINGS = Object.freeze(['ungrounded-data-present', 'all-extracted-data-grounded', 'no-data-extracted', 'inconclusive', 'not-derived']);
export const GROUNDING_SOURCES = Object.freeze(['own', 'foreign', 'neutral', 'request', 'policy', 'none']);
const READING_TOKEN_LIMIT = 200;
const count = (value, max) => Number.isInteger(value) && value >= 0 && value <= max;
export function validateReadings(readings, where = 'readings') {
  shape(readings, ['groundedness'], [], where);
  const g = readings.groundedness, at = `${where}/groundedness`;
  if (!plainObject(g)) fail('shape', at);
  for (const key of ['verdict', 'status', 'outcome', 'pass', 'fail', 'violated', 'held']) if (Object.hasOwn(g, key)) fail('reading-not-prohibition', `${at}/${key}`);
  const settled = ['inconclusive', 'not-derived'].includes(g.reading);
  if (settled) shape(g, ['schema', 'prohibition', 'reading', 'reason', 'shapesChecked'], [], at);
  else shape(g, ['schema', 'prohibition', 'reading', 'shapesChecked', 'extracted', 'bySource', 'ungrounded', 'contextDigest', 'entries', 'lineage'], [], at);
  if (g.schema !== READING_SCHEMA) fail('vocabulary', `${at}/schema`);
  if (g.prohibition !== false) fail('reading-not-prohibition', `${at}/prohibition`);
  oneOf(g.reading, GROUNDEDNESS_READINGS, `${at}/reading`);
  if (!Array.isArray(g.shapesChecked) || g.shapesChecked.join(',') !== READING_SHAPES.join(',')) fail('vocabulary', `${at}/shapesChecked`);
  if (settled) { if (!text(g.reason)) fail('missing-basis', `${at}/reason`); jsonSafe(g, at); return true; }
  if (!count(g.extracted, READING_TOKEN_LIMIT)) fail('bounds', `${at}/extracted`);
  shape(g.bySource, GROUNDING_SOURCES, [], `${at}/bySource`);
  for (const key of GROUNDING_SOURCES) if (!count(g.bySource[key], READING_TOKEN_LIMIT)) fail('bounds', `${at}/bySource/${key}`);
  if (GROUNDING_SOURCES.reduce((sum, key) => sum + g.bySource[key], 0) !== g.extracted) fail('invariant', `${at}/bySource`);
  if (!Array.isArray(g.ungrounded) || g.ungrounded.length !== g.bySource.none) fail('invariant', `${at}/ungrounded`);
  g.ungrounded.forEach((item, i) => {
    shape(item, ['shape', 'canonicalDigest'], [], `${at}/ungrounded/${i}`);
    oneOf(item.shape, READING_SHAPES, `${at}/ungrounded/${i}/shape`);
    if (typeof item.canonicalDigest !== 'string' || !/^[0-9a-f]{64}$/.test(item.canonicalDigest)) fail('shape', `${at}/ungrounded/${i}/canonicalDigest`);
  });
  const expected = g.extracted === 0 ? 'no-data-extracted' : g.bySource.none > 0 ? 'ungrounded-data-present' : 'all-extracted-data-grounded';
  if (g.reading !== expected) fail('invariant', `${at}/reading`);
  if (typeof g.contextDigest !== 'string' || !/^[0-9a-f]{64}$/.test(g.contextDigest)) fail('shape', `${at}/contextDigest`);
  if (!count(g.entries, 64)) fail('bounds', `${at}/entries`);
  shape(g.lineage, ['observer', 'independence', 'source'], [], `${at}/lineage`);
  oneOf(g.lineage.observer, LINEAGE.observer, `${at}/lineage/observer`);
  oneOf(g.lineage.independence, LINEAGE.independence, `${at}/lineage/independence`);
  if (!text(g.lineage.source)) fail('shape', `${at}/lineage/source`);
  jsonSafe(g, at);
  return true;
}

export function validateObservation(observation, where = 'observation') {
  shape(observation, ['observationId', 'checkId', 'index', 'requestId', 'evidenceState', 'dimensions', 'stages', 'lineage'], ['basis', 'readings'], where);
  if (Object.hasOwn(observation, 'readings')) validateReadings(observation.readings, `${where}/readings`);
  jsonSafe(observation, where);
  if (!text(observation.observationId) || !text(observation.checkId)) fail('shape', `${where}/id`);
  if (!Number.isInteger(observation.index) || observation.index < 0 || observation.index >= LIMITS.observationsPerCheck) fail('bounds', `${where}/index`);
  if (observation.requestId !== null && !text(observation.requestId)) fail('shape', `${where}/requestId`);
  oneOf(observation.evidenceState, OBSERVATION_STATES, `${where}/evidenceState`);
  if (observation.evidenceState === 'observed' ? Object.hasOwn(observation, 'basis') : !text(observation.basis)) fail('missing-basis', `${where}/basis`);
  shape(observation.dimensions, DIMENSIONS, [], `${where}/dimensions`);
  for (const name of DIMENSIONS) validateRecord(observation.dimensions[name], `${where}/dimensions/${name}`);
  shape(observation.stages, STAGES, [], `${where}/stages`);
  for (const name of STAGES) validateRecord(observation.stages[name], `${where}/stages/${name}`);
  shape(observation.lineage, ['observer', 'independence', 'source', 'instanceId', 'buildHash', 'actorTransport', 'adapterEmission'], [], `${where}/lineage`);
  for (const [key, list] of Object.entries(LINEAGE)) oneOf(observation.lineage[key], list, `${where}/lineage/${key}`);
  if (!text(observation.lineage.source)) fail('shape', `${where}/lineage/source`);
  for (const key of ['instanceId', 'buildHash']) if (observation.lineage[key] !== null && !text(observation.lineage[key])) fail('shape', `${where}/lineage/${key}`);
  return true;
}

export function refines(verdict, contractStatus) {
  return typeof verdict === 'string' && Object.hasOwn(REFINES, verdict) && REFINES[verdict].includes(contractStatus);
}

export function validateCheck(check, where = 'check') {
  shape(check, ['checkId', 'kind', 'role', 'stagesUnderTest', 'storedStatus', 'recomputedStatus', 'contractStatus', 'verdict', 'basis', 'ruleAgreement',
    'storedAgrees', 'evidenceDigestCheck', 'scenario', 'security', 'completionTruth', 'recomputedAssertions', 'usefulSuccess', 'observations'], ['readings'], where);
  if (Object.hasOwn(check, 'readings')) validateReadings(check.readings, `${where}/readings`);
  if (!text(check.checkId)) fail('shape', `${where}/checkId`);
  if (check.kind !== null && !text(check.kind)) fail('shape', `${where}/kind`);
  oneOf(check.role, ['prohibited', 'allowed-control', 'response-contract'], `${where}/role`);
  if (!Array.isArray(check.stagesUnderTest) || !check.stagesUnderTest.every(name => STAGES.includes(name))) fail('vocabulary', `${where}/stagesUnderTest`);
  if (check.storedStatus !== null && !text(check.storedStatus)) fail('shape', `${where}/storedStatus`);
  if (check.recomputedStatus !== null) oneOf(check.recomputedStatus, V1_STATUSES, `${where}/recomputedStatus`);
  oneOf(check.contractStatus, V1_STATUSES, `${where}/contractStatus`);
  oneOf(check.verdict, CHECK_VERDICTS, `${where}/verdict`);
  if (!refines(check.verdict, check.contractStatus)) fail('invariant', `${where}/contractStatus`);
  if (check.verdict === 'pass' ? check.basis !== null : !text(check.basis)) fail('missing-basis', `${where}/basis`);
  if (![true, false, null].includes(check.ruleAgreement) || typeof check.storedAgrees !== 'boolean') fail('shape', `${where}/agreement`);
  oneOf(check.evidenceDigestCheck, ['valid', 'invalid'], `${where}/evidenceDigestCheck`);
  oneOf(check.scenario, ['matched', 'shortfall', 'mismatch', 'not-declared'], `${where}/scenario`);
  oneOf(check.security, ['held', 'violated', 'unproven', 'not-tested'], `${where}/security`);
  validateRecord(check.completionTruth, `${where}/completionTruth`);
  if (!Array.isArray(check.recomputedAssertions) || check.recomputedAssertions.length > LIMITS.assertionsPerCheck) fail('bounds', `${where}/recomputedAssertions`);
  check.recomputedAssertions.forEach((assertion, i) => {
    shape(assertion, ['name', 'status'], ['expected'], `${where}/recomputedAssertions/${i}`);
    oneOf(assertion.status, ['pass', 'fail', 'inconclusive', 'not_applicable'], `${where}/recomputedAssertions/${i}/status`);
  });
  shape(check.usefulSuccess, ['state'], ['achieved', 'basis'], `${where}/usefulSuccess`);
  oneOf(check.usefulSuccess.state, STAGE_STATES, `${where}/usefulSuccess/state`);
  if (check.usefulSuccess.state === 'observed' ? typeof check.usefulSuccess.achieved !== 'boolean' || Object.hasOwn(check.usefulSuccess, 'basis') : Object.hasOwn(check.usefulSuccess, 'achieved') || !text(check.usefulSuccess.basis)) fail('shape', `${where}/usefulSuccess`);
  if (!Array.isArray(check.observations) || check.observations.length > LIMITS.observationsPerCheck) fail('bounds', `${where}/observations`);
  check.observations.forEach((observation, i) => {
    validateObservation(observation, `${where}/observations/${i}`);
    if (observation.checkId !== check.checkId || observation.index !== i) fail('shape', `${where}/observations/${i}`);
  });
  // A pass needs sealed, fully observed evidence; stage summaries need the same basis.
  const sealedAndObserved = check.evidenceDigestCheck === 'valid' && check.observations.length > 0 && check.observations.every(o => o.evidenceState === 'observed');
  if (check.verdict === 'pass' && !sealedAndObserved) fail('pass-without-observed-evidence', `${where}/verdict`);
  if (check.security === 'held' && !(sealedAndObserved && check.scenario === 'matched')) fail('stage-summary-unsupported', `${where}/security`);
  if (check.security === 'violated' && (check.evidenceDigestCheck !== 'valid' || check.scenario === 'mismatch')) fail('stage-summary-unsupported', `${where}/security`);
  if (check.completionTruth.state === 'observed' && !(sealedAndObserved && ['matched', 'not-declared'].includes(check.scenario))) fail('stage-summary-unsupported', `${where}/completionTruth`);
  jsonSafe(check, where);
  return true;
}

export function unsupported(reason, origin = null, detail) {
  return { contractVersion: CONTRACT_VERSION, supported: false, origin: text(origin) ? origin : null, reason, ...(detail === undefined ? {} : { detail }) };
}

export function viewDigest(view) {
  const { viewDigest: ignored, gradedWith: excluded, ...rest } = view;
  return digest(rest);
}

const IDENTITY_KEYS = ['applicationId', 'suiteId', 'suiteHash', 'policyHash', 'fixtureVersion', 'fixtureHash', 'profileHash', 'targetConfigHash', 'targetBuildHash', 'adapterVersion',
  'assertionSchemaVersion', 'contextId', 'runtimeMode', 'evidenceOrigin', 'backfilled', 'model', 'context', 'toolDescriptor', 'runtime', 'tools'];
export function validateView(view) {
  if (plainObject(view) && view.supported === false) {
    shape(view, ['contractVersion', 'supported', 'origin', 'reason'], ['detail'], 'view');
    jsonSafe(view, 'view');
    if (view.contractVersion !== CONTRACT_VERSION) fail('contract-version', 'view');
    oneOf(view.reason, UNSUPPORTED_REASONS, 'view/reason');
    return true;
  }
  shape(view, ['contractVersion', 'supported', 'origin', 'runId', 'adapter', 'adapterEmission', 'identity', 'pins', 'checks', 'counts', 'verdictCounts', 'countsAgree', 'viewDigest', 'gradedWith'], [], 'view');
  if (view.contractVersion !== CONTRACT_VERSION) fail('contract-version', 'view');
  if (view.supported !== true || !text(view.origin) || !text(view.runId)) fail('shape', 'view');
  oneOf(view.adapter, ['synthetic-fixture/1', 'http-response/1'], 'view/adapter');
  oneOf(view.adapterEmission, LINEAGE.adapterEmission, 'view/adapterEmission');
  if (!Array.isArray(view.checks) || view.checks.length > LIMITS.checks) fail('bounds', 'view/checks');
  shape(view.identity, IDENTITY_KEYS, [], 'view/identity');
  for (const key of ['model', 'toolDescriptor', 'runtime']) validateRecord(view.identity[key], `view/identity/${key}`);
  if (!Array.isArray(view.identity.backfilled) || !Array.isArray(view.identity.tools)) fail('shape', 'view/identity');
  shape(view.pins, ['config', 'reset', 'grader'], [], 'view/pins');
  shape(view.pins.config, ['targetConfigHash', 'profileHash'], ['policyHash'], 'view/pins/config');
  shape(view.pins.reset, ['mode', 'verified', 'violations'], [], 'view/pins/reset');
  oneOf(view.pins.reset.mode, ['fresh-fixture-instance-per-check', 'none-declared'], 'view/pins/reset/mode');
  if (typeof view.pins.reset.verified !== 'boolean' || !Array.isArray(view.pins.reset.violations)) fail('shape', 'view/pins/reset');
  view.pins.reset.violations.forEach((violation, i) => shape(violation, ['checkId', 'reason'], [], `view/pins/reset/violations/${i}`));
  shape(view.pins.grader, ['storedEvaluatorHash', 'currentEvaluatorHash', 'sameEvaluator', 'contractEvaluatorHash', 'ruleVersion', 'recomputeBasis'], [], 'view/pins/grader');
  oneOf(view.pins.grader.sameEvaluator, [true, false, 'not-checked'], 'view/pins/grader/sameEvaluator');
  oneOf(view.pins.grader.recomputeBasis, ['evaluateCheck', 'retained-evidence-recompute'], 'view/pins/grader/recomputeBasis');
  if (!text(view.pins.grader.contractEvaluatorHash) || !text(view.pins.grader.ruleVersion)) fail('shape', 'view/pins/grader');
  view.checks.forEach((check, i) => validateCheck(check, `view/checks/${i}`));
  if (new Set(view.checks.map(check => check.checkId)).size !== view.checks.length) fail('duplicate-check', 'view/checks');
  if (!plainObject(view.counts) || !Object.keys(view.counts).every(key => V1_STATUSES.includes(key) && Number.isSafeInteger(view.counts[key]) && view.counts[key] >= 0)) fail('shape', 'view/counts');
  shape(view.verdictCounts, CHECK_VERDICTS, [], 'view/verdictCounts');
  if (typeof view.countsAgree !== 'boolean') fail('shape', 'view/countsAgree');
  shape(view.gradedWith, ['node'], [], 'view/gradedWith');
  jsonSafe(view, 'view');
  if (view.viewDigest !== viewDigest(view)) fail('view-digest', 'view/viewDigest');
  return true;
}

// Imported previews stay attributed whatever schemaVersion or results they carry.
export function isExternalAttributed(input) {
  const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  if (!record(input)) return false;
  const inner = record(input.record) ? input.record : null;
  return input.kind === 'external-evaluation-preview' || inner?.kind === 'external-evaluation-preview' ||
    (record(input.trust) && input.trust.nativeAssessment === false) || (record(inner?.trust) && inner.trust.nativeAssessment === false);
}
