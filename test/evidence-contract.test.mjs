import test from 'node:test';
import assert from 'node:assert/strict';
import { CONTRACT_VERSION, STAGES, DIMENSIONS, OBSERVATION_STATES, STAGE_STATES, CHECK_VERDICTS, V1_STATUSES, UNSUPPORTED_REASONS, LIMITS,
  ContractError, validateObservation, validateCheck, validateView, refines, viewDigest, isExternalAttributed, unsupported } from '../src/evidence-contract.mjs';

// Pure schema tests: hand-built values only. No fixture, store, network or model.
const record = (state, payload) => state === 'observed' ? { state, value: payload ?? { n: 1 } } : { state, basis: payload ?? 'test-basis' };
function observation(checkId, index = 0, evidenceState = 'observed', stageState = 'observed') {
  return { observationId: `run-1:${checkId}:${index}`, checkId, index, requestId: `request-${index}`, evidenceState, ...(evidenceState === 'observed' ? {} : { basis: 'test-basis' }),
    dimensions: Object.fromEntries(DIMENSIONS.map(name => [name, record('observed')])),
    stages: Object.fromEntries(STAGES.map(name => [name, record(stageState)])),
    lineage: { observer: 'fixture-control-endpoint', independence: 'self-reported-by-target', source: '/results/0/attempts/0/evidence', instanceId: null, buildHash: null, actorTransport: 'complete', adapterEmission: 'derived-from-v1-trace' } };
}
function check(checkId, verdict = 'pass', contractStatus = 'pass', observations = [observation(checkId)]) {
  return { checkId, kind: 'own-record', role: 'allowed-control', stagesUnderTest: ['access'], storedStatus: contractStatus, recomputedStatus: contractStatus, contractStatus, verdict,
    basis: verdict === 'pass' ? null : 'test-basis', ruleAgreement: true, storedAgrees: true, evidenceDigestCheck: 'valid', scenario: 'matched', security: 'not-tested',
    completionTruth: record('not-exercised', 'no-completion-claim'), recomputedAssertions: [{ name: 'Own record returned', status: 'pass', expected: 'Own record' }],
    usefulSuccess: verdict === 'pass' ? { state: 'observed', achieved: true } : { state: 'not-exercised', basis: 'test-basis' }, observations };
}
function seal(view) { delete view.viewDigest; delete view.gradedWith; view.viewDigest = viewDigest(view); view.gradedWith = { node: '24.21.0' }; return view; }
function view(checks = [check('CHECK-1')]) {
  return seal({ contractVersion: CONTRACT_VERSION, supported: true, origin: 'synthetic-local-http', runId: 'run-1', adapter: 'synthetic-fixture/1', adapterEmission: 'derived-from-v1-trace',
    identity: { applicationId: 'app', suiteId: 'suite', suiteHash: 'a', policyHash: 'b', fixtureVersion: 'f', fixtureHash: 'c', profileHash: 'd', targetConfigHash: 'e', targetBuildHash: null,
      adapterVersion: 'adapter', assertionSchemaVersion: 'schema', contextId: 'context', runtimeMode: 'mode', evidenceOrigin: 'synthetic-local-http', backfilled: [],
      model: record('not-exercised', 'deterministic-model-free'), context: { contextId: 'context', fixtureHash: 'c' }, toolDescriptor: record('unobservable', 'no-tool-descriptor-registry'),
      runtime: record('unobservable', 'not-recorded-by-adapter-version'), tools: [] },
    pins: { config: { targetConfigHash: 'e', policyHash: 'b', profileHash: 'd' }, reset: { mode: 'fresh-fixture-instance-per-check', verified: true, violations: [] },
      grader: { storedEvaluatorHash: 'x', currentEvaluatorHash: 'x', sameEvaluator: true, contractEvaluatorHash: 'y', ruleVersion: 'synthetic-stage-rules/1', recomputeBasis: 'evaluateCheck' } },
    checks, counts: { pass: checks.filter(c => c.contractStatus === 'pass').length, fail: 0, inconclusive: 0, error: 0 },
    verdictCounts: Object.fromEntries(CHECK_VERDICTS.map(v => [v, checks.filter(c => c.verdict === v).length])), countsAgree: true });
}
const rejects = (fn, code) => assert.throws(fn, error => error instanceof ContractError && error.code === code, `expected ContractError ${code}`);

test('AC1: the vocabularies are fixed and every state validates in a hand-built observation, check and view', () => {
  assert.equal(CONTRACT_VERSION, 'scopehaven-observation/1');
  assert.deepEqual([...STAGES], ['proposal', 'approval', 'authorization', 'dispatch', 'access', 'commitment', 'disclosure', 'completionTruth', 'requiredReporting']);
  assert.deepEqual([...DIMENSIONS], ['actor', 'task', 'action', 'resource', 'recipient', 'state']);
  assert.deepEqual([...V1_STATUSES], ['pass', 'fail', 'inconclusive', 'error', 'not_applicable']);
  for (const state of OBSERVATION_STATES) assert.equal(validateObservation(observation('CHECK-1', 0, state)), true, state);
  for (const state of STAGE_STATES) assert.equal(validateObservation(observation('CHECK-1', 0, 'observed', state)), true, state);
  const statusFor = { pass: 'pass', fail: 'fail', conflicting: 'inconclusive', missing: 'inconclusive', 'not-exercised': 'not_applicable', 'observer-failure': 'error', unobservable: 'inconclusive' };
  const checks = CHECK_VERDICTS.map((verdict, i) => check(`CHECK-${i}`, verdict, statusFor[verdict]));
  for (const value of checks) assert.equal(validateCheck(value), true, value.verdict);
  assert.equal(validateView(view(checks)), true);
});

test('AC1: malformed values throw ContractError with a specific code', () => {
  const stageMutations = [
    [o => { o.stages.unknownStage = { state: 'observed', value: 1 }; }, 'unknown-key'],
    [o => { delete o.stages.approval; }, 'missing-key'],
    [o => { o.stages.access = { state: 'bogus', basis: 'x' }; }, 'vocabulary'],
    [o => { o.stages.access = { state: 'missing', basis: 'x', value: 1 }; }, 'value-on-non-observed'],
    [o => { o.stages.access = { state: 'missing' }; }, 'missing-basis'],
    [o => { o.stages.access = { state: 'observed', value: { a: undefined } }; }, 'undefined-member'],
    [o => { o.stages.access = { state: 'observed', value: new Date(0) }; }, 'non-json'],
    [o => { o.stages.access = { state: 'observed', value: new Map([['a', 1]]) }; }, 'non-json'],
    [o => { o.stages.access = { state: 'observed', value: new (class Box { constructor() { this.a = 1; } })() }; }, 'non-json'],
    [o => { o.stages.access = { state: 'observed', value: [1, , 3] }; }, 'non-json'],
    [o => { o.stages.access = { state: 'observed', value: Number.NaN }; }, 'non-json'],
    [o => { o.evidenceState = 'missing'; }, 'missing-basis'],
    [o => { o.lineage.independence = 'independent'; }, 'vocabulary'],
  ];
  for (const [mutate, code] of stageMutations) {
    const value = view(); mutate(value.checks[0].observations[0]); seal(value);
    rejects(() => validateView(value), code);
  }
  const viewMutations = [
    [v => { v.extra = true; }, 'unknown-key'],
    [v => { v.contractVersion = 'scopehaven-observation/0'; }, 'contract-version'],
    [v => { v.checks[0].contractStatus = 'inconclusive'; }, 'invariant'],
    [v => { v.checks[0].observations = Array.from({ length: LIMITS.observationsPerCheck + 1 }, (_, i) => observation('CHECK-1', i)); }, 'bounds'],
    [v => { v.checks = Array.from({ length: 1001 }, (_, i) => check(`CHECK-${i}`)); }, 'bounds'],
  ];
  for (const [mutate, code] of viewMutations) { const value = view(); mutate(value); seal(value); rejects(() => validateView(value), code); }
  const tampered = view(); tampered.runId = 'run-2';
  rejects(() => validateView(tampered), 'view-digest');
});

test('fix 3/4: a pass and the stage summaries require sealed, fully observed evidence', () => {
  for (const state of ['conflicting', 'missing', 'observer-failure']) {
    rejects(() => validateCheck(check('CHECK-1', 'pass', 'pass', [observation('CHECK-1', 0, state)])), 'pass-without-observed-evidence');
    rejects(() => validateCheck({ ...check('CHECK-1', 'fail', 'fail', [observation('CHECK-1', 0, state)]), security: 'held' }), 'stage-summary-unsupported');
  }
  rejects(() => validateCheck(check('CHECK-1', 'pass', 'pass', [])), 'pass-without-observed-evidence');
  rejects(() => validateCheck({ ...check('CHECK-1'), evidenceDigestCheck: 'invalid' }), 'pass-without-observed-evidence');
  rejects(() => validateCheck({ ...check('CHECK-1', 'missing', 'inconclusive'), scenario: 'shortfall', security: 'held' }), 'stage-summary-unsupported');
  rejects(() => validateCheck({ ...check('CHECK-1', 'conflicting', 'inconclusive'), evidenceDigestCheck: 'invalid', security: 'violated' }), 'stage-summary-unsupported');
  rejects(() => validateCheck({ ...check('CHECK-1', 'conflicting', 'inconclusive'), scenario: 'mismatch', completionTruth: { state: 'observed', value: { value: 'truthful' } } }), 'stage-summary-unsupported');
  assert.equal(validateCheck({ ...check('CHECK-1', 'fail', 'fail'), security: 'held', completionTruth: { state: 'observed', value: { value: 'false-claim' } } }), true);
  assert.equal(validateCheck({ ...check('CHECK-1', 'fail', 'fail'), scenario: 'shortfall', security: 'violated' }), true);
});

test('AC1: viewDigest ignores key order and the reader runtime', () => {
  const a = view(), b = JSON.parse(JSON.stringify(a), (key, value) => value && typeof value === 'object' && !Array.isArray(value) ? Object.fromEntries(Object.entries(value).reverse()) : value);
  assert.notEqual(JSON.stringify(a), JSON.stringify(b));
  assert.equal(viewDigest(a), viewDigest(b));
  const c = structuredClone(a); c.gradedWith = { node: '99.0.0' };
  assert.equal(viewDigest(c), viewDigest(a));
  c.runId = 'run-2'; assert.notEqual(viewDigest(c), viewDigest(a));
});

test('AC1: refines encodes the verdict and v1 status invariant', () => {
  const valid = [['pass', 'pass'], ['fail', 'fail'], ['conflicting', 'fail'], ['conflicting', 'inconclusive'], ['conflicting', 'error'],
    ...['missing', 'not-exercised', 'observer-failure', 'unobservable'].flatMap(verdict => ['inconclusive', 'error', 'not_applicable'].map(status => [verdict, status]))];
  for (const [verdict, status] of valid) assert.equal(refines(verdict, status), true, `${verdict}/${status}`);
  for (const [verdict, status] of [['pass', 'inconclusive'], ['conflicting', 'pass'], ['fail', 'inconclusive'], ['missing', 'pass'], ['observer-failure', 'fail'], ['pass', 'not_applicable'], ['unknown', 'pass'], ['__proto__', 'pass']])
    assert.equal(refines(verdict, status), false, `${verdict}/${status}`);
});

test('AC13 shape: unsupported results carry no checks, counts, verdicts or statuses', () => {
  for (const reason of UNSUPPORTED_REASONS) {
    const value = unsupported(reason, 'reviewed-real-application-staging');
    assert.deepEqual(Object.keys(value).sort(), ['contractVersion', 'origin', 'reason', 'supported']);
    assert.equal(value.supported, false); assert.equal(validateView(value), true);
    for (const key of ['checks', 'counts', 'verdictCounts', 'status', 'results']) assert.equal(Object.hasOwn(value, key), false);
  }
  assert.equal(unsupported('not-native-run', 42).origin, null);
  rejects(() => validateView({ ...unsupported('external-attributed'), checks: [] }), 'unknown-key');
  rejects(() => validateView({ ...unsupported('external-attributed'), reason: 'trusted' }), 'vocabulary');
});

test('AC13 shape: external attribution is detected on the preview and its record, without dereferencing non-objects', () => {
  for (const value of [null, undefined, 0, 'x', [], [{ kind: 'external-evaluation-preview' }]]) assert.equal(isExternalAttributed(value), false);
  assert.equal(isExternalAttributed({ kind: 'external-evaluation-preview' }), true);
  assert.equal(isExternalAttributed({ ok: true, record: { kind: 'external-evaluation-preview' } }), true);
  assert.equal(isExternalAttributed({ schemaVersion: 1, results: [], trust: { nativeAssessment: false } }), true);
  assert.equal(isExternalAttributed({ record: { trust: { nativeAssessment: false } } }), true);
  assert.equal(isExternalAttributed({ schemaVersion: 1, results: [], trust: { nativeAssessment: true } }), false);
});
