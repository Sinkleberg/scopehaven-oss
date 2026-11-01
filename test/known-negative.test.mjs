// Known-negative self-test (src/known-negative.mjs): every check must prove it can fail. Each predicate kind has a
// fixed twin that passes and a defective twin that fails, judged by the connector's own evaluators, and each way a check
// can be broken (cannot fail, always fails), unconfirmable (pass unreachable) or not shown at all (unprovable, error) is
// shown on a case that produces it. Effect plants come from the declared observers, so a clause no observer can record
// is never proven, and pass through attribution as a run applies it, so a plant a background source or an earlier check's
// late send absorbs cannot fail. Synthetic profiles only: no target is contacted, no observer is started, nothing is saved.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { validateTargetFile } from '../src/contracts.mjs';
import { OBSERVER_TYPES } from '../src/http-effects.mjs';
import { EFFECT_ASSERTIONS } from '../src/effect-events.mjs';
import { FOREIGN_VALUES_KIND } from '../src/tenant-values.mjs';
import { CANARY_CHANNELS, drawCanaryValue } from '../src/canary.mjs';
import { ONLY_KIND } from '../integrations/collateral/only.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';
import { knownNegativeCheck, knownNegativeTarget, knownNegativeCanary, observerScopes, KNOWN_NEGATIVE_SCHEMA, PREDICATE_OUTCOMES, CHECK_OUTCOMES, PLANTED_KINDS, MODELLED_OBSERVER_TYPES, CANARY_FORMS } from '../src/known-negative.mjs';

const WITNESS = { actorId: 'member', method: 'GET', path: '/healthz' };
const EGRESS = { id: 'egress', type: 'egress-recorder', port: 4199, routing: 'proxy', witness: { ...WITNESS, host: 'witness.example.test' }, settleMs: 500, destinations: [{ host: 'billing.example.test', paths: ['/refunds'] }] };
const LAB = Object.freeze({
  id: 'kn-lab', name: 'Known-negative lab', applicationId: 'kn-app', origin: 'http://127.0.0.1:4100', buildLabel: 'synthetic', contextId: 'kn-context',
  actors: { member: { principalId: 'member-1', tenantId: 'acme', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member-1@acme.test' } },
  requiredControlIds: ['WHOAMI'],
  observers: [
    EGRESS,
    { id: 'mail', type: 'smtp-sink', port: 4198, routing: 'smtp-host', witness: { ...WITNESS, domain: 'witness-mail.example.test' }, settleMs: 500, domains: [{ domain: 'mail.example.test' }] },
    { id: 'audit', type: 'sqlite-audit', path: 'kn-app.db', audit: { table: 'audit', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', actions: { 'refund.issue': 'insert', 'note.update': 'update' } }, principals: ['member-1'], settleMs: 500 },
    { id: 'traces', type: 'otel', port: 4318, services: ['kn-app'], tools: ['issue_refund'], principals: ['member-1'] },
    { id: 'rows', type: 'sqlite-snapshot', path: 'kn-app.db', tables: [{ table: 'notes', key: 'id' }], settleMs: 500 },
  ],
  tenantValues: { tenants: { acme: { identifiers: ['ORD-1001'] }, globex: { identifiers: ['ORD-2002', 'ORD-2003'] } } },
  checks: [
    { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response',
      assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'member-1@acme.test' }] },
    { id: 'OTHER-ORDER', title: 'Cannot read another tenant order', category: 'object-access', severity: 'high', actorId: 'member', method: 'GET', path: '/orders/latest', evidenceRequirement: 'response',
      assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: '/reply' }] },
    { id: 'REFUND-OTHER', title: 'Cannot refund another tenant', category: 'action', severity: 'high', actorId: 'member', method: 'POST', path: '/refunds', body: { order: 'ORD-2002' }, evidenceRequirement: 'backend',
      assertions: [{ kind: 'status.in', expected: [403, 404] }], effects: [{ kind: 'effect.none', select: { source: 'http-egress', name: 'billing.example.test' } }] },
  ],
});
const validated = target => validateTargetFile({ schemaVersion: 1, targets: [structuredClone(target)] })[0];
const lab = validated(LAB);
const base = { title: 't', category: 'c', severity: 'high', actorId: 'member', method: 'GET', path: '/x', evidenceRequirement: 'response' };
const run = (check, target = lab) => knownNegativeCheck({ ...base, ...check }, target);
const outcomes = result => result.predicates.map(p => p.outcome);
const deepFreeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(deepFreeze); Object.freeze(value); } return value; };
const effectCheck = (effects, extra = {}, target = lab) => run({ id: 'E', method: 'POST', evidenceRequirement: 'backend', assertions: [{ kind: 'status.in', expected: [403, 404] }], effects, ...extra }, target);
const clause = result => result.predicates.find(p => p.layer === 'effect');

test('a validated profile: every predicate of every check is proven', () => {
  const report = knownNegativeTarget(lab);
  assert.equal(report.schema, KNOWN_NEGATIVE_SCHEMA);
  assert.equal(report.targetId, 'kn-lab');
  assert.equal(report.outcome, 'proven');
  assert.deepEqual(report.checks.map(c => [c.id, c.outcome]), [['WHOAMI', 'proven'], ['OTHER-ORDER', 'proven'], ['REFUND-OTHER', 'proven']]);
  for (const c of report.checks) for (const p of c.predicates) assert.deepEqual([p.fixed, p.defective], ['pass', 'fail'], `${c.id} ${p.layer} ${p.index}`);
  assert.deepEqual(report.counts.checks, { proven: 3, broken: 0, partial: 0, unprovable: 0, error: 0 });
  assert.deepEqual(report.counts.predicates, { proven: 6, 'cannot-fail': 0, 'always-fails': 0, 'pass-unreachable': 0, unprovable: 0, error: 0 });
  assert.deepEqual(Object.keys(report.counts.checks), [...CHECK_OUTCOMES]);
  assert.deepEqual(Object.keys(report.counts.predicates), [...PREDICATE_OUTCOMES]);
});

test('the report names positions, kinds, statuses and reason codes, never an expected, planted or declared value', () => {
  const bare = validated({ ...LAB, observers: [{ id: 'egress', type: 'egress-recorder', port: 4199, destinations: [{ host: 'billing.example.test' }] }] });
  for (const target of [lab, bare]) {
    const text = JSON.stringify(knownNegativeTarget(target));
    for (const value of ['member-1@acme.test', 'ORD-1001', 'ORD-2002', 'ORD-2003', 'billing.example.test', 'clean', '/refunds']) assert.ok(!text.includes(value), value);
  }
});

test('the self-test is pure: inputs are not changed and a second run is identical', () => {
  const frozen = deepFreeze(structuredClone(lab));
  assert.deepEqual(knownNegativeTarget(frozen), knownNegativeTarget(lab));
});

test('status: a refusal set and an exact success are each violated by the other answer', () => {
  assert.deepEqual(outcomes(run({ id: 'S1', assertions: [{ kind: 'status.in', expected: [403, 404] }] })), ['proven']);
  assert.deepEqual(outcomes(run({ id: 'S2', assertions: [{ kind: 'status.equals', expected: 200 }] })), ['proven']);
  assert.deepEqual(outcomes(run({ id: 'S3', assertions: [{ kind: 'status.equals', expected: 403 }] })), ['proven']);
  assert.deepEqual(outcomes(run({ id: 'S4', assertions: [{ kind: 'status.equals', expected: 404 }, { kind: 'status.in', expected: [403, 404] }] })), ['proven', 'proven'], 'a status both accept is found');
  assert.deepEqual(outcomes(run({ id: 'S6', assertions: [{ kind: 'status.in', expected: [403, 404] }, { kind: 'status.equals', expected: 404 }] })), ['proven', 'proven'], 'whichever is listed first');
  const clash = run({ id: 'S5', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'status.in', expected: [403, 404] }] });
  assert.equal(clash.outcome, 'broken');
  assert.deepEqual(outcomes(clash), ['proven', 'always-fails'], 'no status satisfies both: the refusal set always fails');
});

test('json.equals, json.exists and json.notContains: fixed and defective twins', () => {
  assert.deepEqual(outcomes(run({ id: 'J1', assertions: [{ kind: 'json.equals', pointer: '/a/b', expected: 7 }, { kind: 'json.equals', pointer: '/n', expected: null }, { kind: 'json.equals', pointer: '/t', expected: false }] })), ['proven', 'proven', 'proven']);
  assert.deepEqual(outcomes(run({ id: 'J2', assertions: [{ kind: 'json.equals', pointer: '/x', expected: 'known-negative' }] })), ['proven'], 'an expected value equal to the planted text');
  assert.deepEqual(outcomes(run({ id: 'J3', assertions: [{ kind: 'json.exists', pointer: '/items/0/id', expected: true }, { kind: 'json.exists', pointer: '/secret', expected: false }] })), ['proven', 'proven']);
  for (const expected of ['secret', 'clean', 'lea', '0', 'o']) assert.deepEqual(outcomes(run({ id: 'J4', assertions: [{ kind: 'json.notContains', pointer: '/note', expected }] })), ['proven'], expected);
  assert.deepEqual(outcomes(run({ id: 'J5', assertions: [{ kind: 'json.equals', pointer: '', expected: 'whole body' }] })), ['proven'], 'the root pointer');
});

test('cannot-fail: a predicate that holds on every body is broken', () => {
  const vacuous = run({ id: 'V1', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '', expected: true }] });
  assert.equal(vacuous.outcome, 'broken');
  assert.deepEqual(vacuous.predicates[1], { layer: 'response', index: 1, kind: 'json.exists', outcome: 'cannot-fail', fixed: 'pass', defective: 'pass' });
});

test('always-fails: contradictory predicates are broken, and the report says which', () => {
  const twice = run({ id: 'A1', assertions: [{ kind: 'json.equals', pointer: '/a', expected: 1 }, { kind: 'json.equals', pointer: '/a', expected: 2 }] });
  assert.equal(twice.outcome, 'broken');
  assert.deepEqual(outcomes(twice), ['always-fails', 'proven']);
  const gone = run({ id: 'A2', assertions: [{ kind: 'json.equals', pointer: '/a', expected: 'v' }, { kind: 'json.exists', pointer: '/a', expected: false }] });
  assert.deepEqual(outcomes(gone), ['always-fails', 'proven'], 'an absence declared after an equality removes the field');
});

test('M2: predicates on one pointer give the same result in either order, and a satisfiable pair is never broken', () => {
  const pairs = [
    [{ kind: 'json.equals', pointer: '/a', expected: 'hello' }, { kind: 'json.exists', pointer: '/a', expected: true }],
    [{ kind: 'json.equals', pointer: '/a', expected: 'hello' }, { kind: 'json.notContains', pointer: '/a', expected: 'zz' }],
    [{ kind: 'json.equals', pointer: '/r', expected: 'fine' }, { kind: 'json.noForeignValues', pointer: '/r' }],
  ];
  for (const pair of pairs) {
    const byKind = result => Object.fromEntries(result.predicates.filter(p => p.layer === 'response' && p.kind !== 'status.equals').map(p => [p.kind, p.outcome]));
    const forward = run({ id: 'M2', assertions: [{ kind: 'status.equals', expected: 200 }, ...pair] });
    const reversed = run({ id: 'M2', assertions: [{ kind: 'status.equals', expected: 200 }, ...[...pair].reverse()] });
    assert.equal(forward.outcome, 'proven', pair.map(a => a.kind).join(' then '));
    assert.equal(reversed.outcome, 'proven', pair.map(a => a.kind).reverse().join(' then '));
    assert.deepEqual(byKind(forward), byKind(reversed));
  }
});

test('L5: json.notContains beside a predicate that writes a non-string reads the same in either order, partial and never broken', () => {
  // The evaluator reads notContains over a non-string as inconclusive, so the pair can never both pass and neither always fails.
  const pairs = [
    [{ kind: 'json.exists', pointer: '/a/b', expected: true }, { kind: 'json.notContains', pointer: '/a', expected: 'zz' }],
    [{ kind: 'json.equals', pointer: '/a', expected: 5 }, { kind: 'json.notContains', pointer: '/a', expected: 'zz' }],
    [{ kind: 'json.equals', pointer: '/a', expected: true }, { kind: 'json.notContains', pointer: '/a', expected: 'zz' }],
  ];
  const byKind = result => Object.fromEntries(result.predicates.filter(p => p.kind !== 'status.equals').map(p => [p.kind, [p.outcome, p.fixed]]));
  for (const pair of pairs) for (const order of [pair, [...pair].reverse()]) {
    const result = run({ id: 'L5', assertions: [{ kind: 'status.equals', expected: 200 }, ...order] });
    const label = order.map(a => `${a.kind} ${JSON.stringify(a.expected)}`).join(' then ');
    assert.equal(result.outcome, 'partial', label);
    assert.deepEqual(byKind(result), { [pair[0].kind]: ['proven', 'pass'], 'json.notContains': ['pass-unreachable', 'inconclusive'] }, label);
  }
  // A body no predicate wrote is still planted: a notContains at the root replaces the empty object.
  assert.deepEqual(outcomes(run({ id: 'L5R', assertions: [{ kind: 'json.exists', pointer: '/x', expected: false }, { kind: 'json.notContains', pointer: '', expected: 'zz' }] })), ['proven', 'proven']);
});

test('json.noForeignValues: proven with another tenant\'s identifier; cannot fail without one', () => {
  const check = { id: 'F1', assertions: [{ kind: 'json.noForeignValues', pointer: '/reply' }] };
  assert.deepEqual(outcomes(run(check)), ['proven']);
  const shared = { ...lab, tenantValues: { tenants: { acme: { identifiers: ['ORD-1001', 'SHARED-77'] }, globex: { identifiers: ['SHARED-77'], attributes: ['Globex Corp'] } } } };
  const none = run(check, shared);
  assert.equal(none.outcome, 'broken');
  assert.deepEqual(none.predicates[0], { layer: 'response', index: 0, kind: 'json.noForeignValues', outcome: 'cannot-fail', fixed: 'pass', defective: 'not-planted', reason: 'no-foreign-identifier' });
});

test('json.noForeignValues: an identifier the request itself carries is skipped for the next one', () => {
  // The first foreign identifier is echoed by the request path (an echo is never a leak); the second still proves it.
  assert.deepEqual(outcomes(run({ id: 'F2', path: '/orders/ORD-2002', assertions: [{ kind: 'json.noForeignValues', pointer: '/reply' }] })), ['proven']);
  const onlyEchoed = { ...lab, tenantValues: { tenants: { acme: { identifiers: ['ORD-1001'] }, globex: { identifiers: ['ORD-2002'] } } } };
  assert.deepEqual(outcomes(run({ id: 'F3', path: '/orders/ORD-2002', assertions: [{ kind: 'json.noForeignValues', pointer: '/reply' }] }, onlyEchoed)), ['cannot-fail'],
    'a check whose own request carries the only foreign identifier cannot catch that identifier');
});

test('effects: absence, presence and exact counts the declared observers record are proven', () => {
  const result = effectCheck([
    { kind: 'effect.none', select: { source: 'http-egress', name: 'billing.example.test' } },
    { kind: 'effect.count', expected: 2, select: { source: 'http-egress', name: 'billing.example.test' } },
    { kind: 'effect.count', expected: 0, select: { source: 'smtp-capture', name: 'mail.example.test' } },
  ]);
  assert.equal(result.outcome, 'proven');
  assert.deepEqual(result.predicates.slice(1).map(p => [p.layer, p.index, p.kind, p.outcome, p.fixed, p.defective]), [['effect', 0, 'effect.none', 'proven', 'pass', 'fail'],
    ['effect', 1, 'effect.count', 'proven', 'pass', 'fail'], ['effect', 2, 'effect.count', 'proven', 'pass', 'fail']]);
  const control = run({ id: 'C', severity: 'control', method: 'POST', assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select: { source: 'sql-audit-table', operation: 'insert', name: 'refund.issue', actor: 'member-1' } }] });
  assert.deepEqual(outcomes(control), ['proven', 'proven'], 'an allowed-use control may rest on the application\'s own records');
});

test('H1: a clause no declared observer can record is unprovable, named, never proven', () => {
  const egressOnly = validated({ ...LAB, observers: [EGRESS] });
  const cases = [
    // The reviewer's second and third inputs: an undeclared host, and a source no observer provides.
    [{ kind: 'effect.none', select: { source: 'http-egress', name: 'other.example.test' } }, 'name-not-declared', lab],
    [{ kind: 'effect.none', select: { source: 'sql-audit-table', name: 'refund.issue' } }, 'no-observer', egressOnly],
    [{ kind: 'effect.none', select: { source: 'sql-audit-table', operation: 'update', name: 'refund.issue' } }, 'operation-not-recorded', lab],
    [{ kind: 'effect.none', select: { source: 'http-egress', name: 'billing.example.test', actor: 'member-1' } }, 'actor-not-recorded', lab],
    [{ kind: 'effect.none', select: { source: 'sql-audit-table', name: 'refund.issue', actor: 'someone-else' } }, 'actor-not-recorded', lab],
    // A send is recorded as "METHOD <declared path>" or "METHOD *": a bare resource or an undeclared path is never recorded.
    [{ kind: 'effect.none', select: { source: 'http-egress', name: 'billing.example.test', resource: 'refund-1' } }, 'resource-not-recorded', lab],
    [{ kind: 'effect.none', select: { source: 'http-egress', name: 'billing.example.test', resource: { prefix: 'POST /orders' } } }, 'resource-not-recorded', lab],
    [{ kind: 'effect.none', select: { source: 'sql-audit-table', name: 'refund.issue', resource: 'r-1' } }, 'resource-not-recorded', lab],
    // The recorder writes no trace id, so an egress selector pinned to one never matches a send.
    [{ kind: 'effect.none', select: { source: 'http-egress', name: 'billing.example.test', traceId: 'trace-1' } }, 'trace-not-recorded', lab],
  ];
  for (const [effect, reason, target] of cases) {
    const result = effectCheck([effect], {}, target);
    assert.deepEqual(clause(result), { layer: 'effect', index: 0, kind: 'effect.none', outcome: 'unprovable', fixed: null, defective: null, reason }, reason);
    assert.equal(result.outcome, 'partial', `${reason}: the proven status keeps it partial, never proven`);
  }
  const alone = effectCheck([{ kind: 'effect.exists', select: { source: 'sql-audit-table', name: 'refund.issue' } }], {}, egressOnly);
  const report = knownNegativeTarget({ ...egressOnly, checks: [{ ...base, id: 'U', method: 'POST', evidenceRequirement: 'backend', assertions: [{ kind: 'status.in', expected: [403, 404] }], effects: [{ kind: 'effect.none', select: { source: 'sql-audit-table', name: 'refund.issue' } }] }] });
  assert.equal(clause(alone).outcome, 'unprovable');
  assert.deepEqual([report.outcome, report.counts.predicates.unprovable], ['partial', 1]);
});

test('H1: the observer\'s evidence and settle decide, so a never-passing absence is pass-unreachable, not proven', () => {
  // The reviewer's first input: the PR's own REFUND-OTHER on an egress recorder without routing (presence-only).
  const bare = validated({ ...LAB, observers: [{ id: 'egress', type: 'egress-recorder', port: 4199, destinations: [{ host: 'billing.example.test' }] }] });
  const refund = knownNegativeTarget(bare).checks.find(c => c.id === 'REFUND-OTHER');
  assert.equal(refund.outcome, 'partial');
  assert.deepEqual(clause(refund), { layer: 'effect', index: 0, kind: 'effect.none', outcome: 'pass-unreachable', fixed: 'unobservable', defective: 'fail', reason: 'presence-only' });
  assert.equal(knownNegativeTarget(bare).outcome, 'partial');
  // A presence-only observer can show a send, never its absence: an exists clause there cannot fail.
  assert.deepEqual(clause(effectCheck([{ kind: 'effect.exists', select: { source: 'http-egress', name: 'billing.example.test' } }], {}, bare)),
    { layer: 'effect', index: 0, kind: 'effect.exists', outcome: 'cannot-fail', fixed: 'pass', defective: 'unobservable', reason: 'presence-only' });
  // Routed but without a declared settle: the run caps the window at partial, so an absence never passes.
  const { settleMs: _settle, ...unsettledEgress } = EGRESS, unsettled = validated({ ...LAB, observers: [unsettledEgress] });
  assert.deepEqual(clause(knownNegativeTarget(unsettled).checks.find(c => c.id === 'REFUND-OTHER')),
    { layer: 'effect', index: 0, kind: 'effect.none', outcome: 'pass-unreachable', fixed: 'missing', defective: 'fail', reason: 'no-post-response-settle' });
  // A snapshot is net-only: an absence it alone sees never passes; one exact coverage could decide is not planted.
  assert.deepEqual(clause(effectCheck([{ kind: 'effect.none', select: { source: 'sql-snapshot', operation: 'insert', name: 'notes' } }])),
    { layer: 'effect', index: 0, kind: 'effect.none', outcome: 'pass-unreachable', fixed: 'missing', defective: 'fail', reason: 'net-change-between-snapshots' });
  const audited = { ...lab, observers: [{ id: 'rows', type: 'sqlite-snapshot', path: 'kn-app.db', tables: [{ table: 'notes', key: 'id', changeColumn: { column: 'updated_at', audit: 'audit.md' } }], settleMs: 500 }] };
  assert.deepEqual(clause(effectCheck([{ kind: 'effect.exists', select: { source: 'sql-snapshot', operation: 'update', name: 'notes' } }], {}, audited)),
    { layer: 'effect', index: 0, kind: 'effect.exists', outcome: 'unprovable', fixed: 'inconclusive', defective: 'missing', reason: 'exact-coverage-not-planted' });
});

test('H1: a provider feed is planted with its feed record, so its declared key source decides custody as in a run', () => {
  // The test's own key pair; the self-test reads only the public key's digest.
  const publicKey = generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  const feed = extra => ({ id: 'feed', type: 'provider-feed', feedId: 'mail', feed: { endpoint: { port: 4471, path: '/feed' } }, publicKey, domains: [{ domain: 'customers.example' }],
    routing: 'provider', witness: { ...WITNESS, domain: 'witness-feed.example' }, settleMs: 500, ...extra });
  const none = [{ kind: 'effect.none', select: { source: 'provider-feed', name: 'customers.example' } }];
  const undeclared = { ...lab, observers: [feed()] }, stub = { ...lab, observers: [feed({ keySource: 'stub' })] };
  assert.deepEqual(clause(effectCheck(none, {}, undeclared)), { layer: 'effect', index: 0, kind: 'effect.none', outcome: 'pass-unreachable', fixed: 'inconclusive', defective: 'fail', reason: 'custody' });
  assert.deepEqual(clause(effectCheck(none, {}, stub)), { layer: 'effect', index: 0, kind: 'effect.none', outcome: 'proven', fixed: 'pass', defective: 'fail' });
  for (const target of [undeclared, stub]) assert.deepEqual(observerScopes(target)[0].scope.feed, buildObservers(target.observers, { env: {} })[0].scope.feed);
});

test('H1: the pairing stage applies as in a run, so an absence its profile never pairs or guards is pass-unreachable', () => {
  const pinned = { kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: 'billing.example.test', resource: { prefix: 'POST /refunds' } } };
  const twin = select => ({ ...base, id: 'ALLOWED', severity: 'control', method: 'POST', path: '/refunds/mine', assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select }] });
  // A resource pin with no allowed-use twin: a typo in it would read the same, so the run withholds the pass.
  assert.deepEqual(clause(effectCheck([pinned])), { layer: 'effect', index: 0, kind: 'effect.none', outcome: 'pass-unreachable', fixed: 'inconclusive', defective: 'fail', reason: 'selector-unpaired' });
  assert.deepEqual(clause(effectCheck([pinned], {}, { ...lab, checks: [...lab.checks, twin(pinned.select)] })), { layer: 'effect', index: 0, kind: 'effect.none', outcome: 'proven', fixed: 'pass', defective: 'fail' });
  // A twin that also pins an actor the egress recorder never records can never match in a deciding window.
  assert.equal(clause(effectCheck([pinned], {}, { ...lab, checks: [...lab.checks, twin({ ...pinned.select, actor: 'member-1' })] })).reason, 'selector-not-shown-to-match');
  // An unpinned absence in a check that accepts a success, beside no required allowed-use control with a positive effect.
  const success = effectCheck([{ kind: 'effect.none', select: { source: 'http-egress', name: 'billing.example.test' } }], { assertions: [{ kind: 'status.equals', expected: 200 }] });
  assert.deepEqual(clause(success), { layer: 'effect', index: 0, kind: 'effect.none', outcome: 'pass-unreachable', fixed: 'inconclusive', defective: 'fail', reason: 'allowed-use-not-declared' });
});

const BILLING = { source: 'http-egress', name: 'billing.example.test' };
const effectRow = (kind, outcome, fixed, defective, reason) => ({ layer: 'effect', index: 0, kind, outcome, fixed, defective, ...(reason ? { reason } : {}) });
const refundClause = report => clause(report.checks.find(c => c.id === 'REFUND-OTHER'));

test('H2: attribution applies as in a run, so a plant a declared background source absorbs cannot fail', () => {
  const background = select => validated({ ...LAB, attribution: { background: [{ id: 'billing-sync', select }] } });
  // The reviewer's first input: every send to the host may be the sync job's, so a run never charges REFUND-OTHER a fail.
  const synced = background({ operation: 'send', name: 'billing.example.test' });
  const report = knownNegativeTarget(synced);
  assert.equal(report.outcome, 'broken');
  assert.equal(report.checks.find(c => c.id === 'REFUND-OTHER').outcome, 'broken');
  assert.deepEqual(refundClause(report), effectRow('effect.none', 'cannot-fail', 'pass', 'inconclusive', 'background-unattributed'));
  assert.deepEqual(knownNegativeTarget(deepFreeze(structuredClone(synced))), report, 'still pure');
  // A source that cannot be the clause's effect absorbs nothing.
  assert.equal(knownNegativeTarget(background({ operation: 'send', name: 'mail.example.test' })).outcome, 'proven');
  // The pass side: a send the job may have made never credits a presence clause, so the run withholds the pass.
  assert.deepEqual(clause(effectCheck([{ kind: 'effect.exists', select: BILLING }], {}, synced)), effectRow('effect.exists', 'pass-unreachable', 'inconclusive', 'fail', 'background-unattributed'));
  // An allowed-use control keeps a fail as a tag, so its count still fails; its positive pass is withheld.
  const control = run({ id: 'C', severity: 'control', method: 'POST', assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.count', expected: 1, select: BILLING }] }, synced);
  assert.deepEqual(clause(control), effectRow('effect.count', 'pass-unreachable', 'inconclusive', 'fail', 'background-unattributed'));
  // Exact coverage could change a coverage reason, never a send the job may have made: that clause cannot fail, not "not planted".
  const rows = { id: 'rows', type: 'sqlite-snapshot', path: 'kn-app.db', tables: [{ table: 'notes', key: 'id', changeColumn: { column: 'updated_at', audit: 'audit.md' } }], settleMs: 500 };
  const notes = [{ kind: 'effect.none', select: { source: 'sql-snapshot', operation: 'update', name: 'notes' } }];
  assert.deepEqual(clause(effectCheck(notes, {}, { ...lab, observers: [rows] })), effectRow('effect.none', 'unprovable', 'missing', 'fail', 'exact-coverage-not-planted'));
  assert.deepEqual(clause(effectCheck(notes, {}, { ...lab, observers: [rows], attribution: { background: [{ id: 'notes-sync', select: { operation: 'update', name: 'notes' } }] } })),
    effectRow('effect.none', 'cannot-fail', 'missing', 'inconclusive', 'background-unattributed'));
});

test('H2: with late fails withheld, a plant an earlier check\'s selector explains cannot fail', () => {
  const timing = { timing: { effectHorizonMs: 500, runBudgetMs: 7200000, lateFails: 'withhold' } };
  const [whoami, order, refund] = LAB.checks;
  const allowed = extra => ({ ...base, id: 'ALLOWED', severity: 'control', method: 'POST', path: '/refunds/mine', assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select: BILLING }], ...extra });
  const profile = (checks, extra = timing) => knownNegativeTarget(validated({ ...LAB, ...extra, checks }));
  // The reviewer's second input: the allowed-use twin listed first, so any send in REFUND-OTHER's window may be its late one.
  const late = profile([whoami, order, allowed(), refund]);
  assert.deepEqual(refundClause(late), effectRow('effect.none', 'cannot-fail', 'pass', 'inconclusive', 'late-unattributed'));
  assert.deepEqual([late.outcome, late.checks.find(c => c.id === 'ALLOWED').outcome], ['broken', 'proven']);
  // An earlier claim rule's selector explains it the same way.
  const claims = { ...base, id: 'CLAIMS', method: 'POST', path: '/refunds/ask', evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 200 }],
    claims: [{ trigger: { field: { pointer: '/refund/status', success: ['issued'], refusal: ['declined'] } }, select: BILLING }] };
  assert.deepEqual(refundClause(profile([whoami, order, claims, refund])), effectRow('effect.none', 'cannot-fail', 'pass', 'inconclusive', 'late-unattributed'));
  // Proven again: the twin listed after it, an earlier twin a run never sends, or no late-fail declaration.
  const proven = effectRow('effect.none', 'proven', 'pass', 'fail');
  assert.deepEqual(refundClause(profile([whoami, order, refund, allowed()])), proven, 'listed after');
  assert.deepEqual(refundClause(profile([whoami, order, allowed({ applicability: { applies: false, reason: 'Refunds are not offered in this build.' } }), refund])), proven, 'not applicable');
  assert.deepEqual(refundClause(profile([whoami, order, allowed(), refund], {})), proven, 'not declared');
});

test('M3: a plant carries the actor and resource a real event would, so a pinned background source or earlier selector absorbs only what it names', () => {
  const audit = principals => ({ id: 'audit', type: 'sqlite-audit', path: 'kn-app.db', audit: { table: 'audit', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', actions: { 'order.update': 'update', 'refund.issue': 'insert' } },
    ...(principals ? { principals } : {}), settleMs: 500 });
  const sync = select => ({ attribution: { background: [{ id: 'sync', select }] } });
  const syncWorker = sync({ actor: 'svc-sync', operation: 'update', name: 'order.update' });
  const updates = [{ kind: 'effect.none', select: { source: 'sql-audit-table', operation: 'update', name: 'order.update' } }];
  const control = (id, effects) => ({ ...base, id, severity: 'control', method: 'POST', path: `/${id.toLowerCase()}`, assertions: [{ kind: 'status.equals', expected: 200 }], effects });
  const profile = (extra, observers, checks) => validated({ ...LAB, ...extra, observers, checks: [...LAB.checks.slice(0, 2), ...checks] });
  const row = (target, id = 'T') => clause(knownNegativeTarget(target).checks.find(c => c.id === id));
  const T = (effects, extra = {}) => ({ ...base, id: 'T', method: 'POST', evidenceRequirement: 'backend', assertions: [{ kind: 'status.in', expected: [403, 404] }], effects, ...extra });
  // A: the attribution module's own example, the worker declared first. An update by the member is not the worker's, so a plant
  // fails the absence as a run does; custody still holds the boundary pass on the application's own table.
  // The worker's own plant still cannot fail; the member's stands, in either order.
  for (const principals of [['svc-sync', 'member-1'], ['member-1', 'svc-sync']]) assert.deepEqual(row(profile(syncWorker, [audit(principals)], [T(updates)])), effectRow('effect.none', 'pass-unreachable', 'inconclusive', 'fail', 'custody'), principals.join());
  // The presence side and a count, as allowed-use controls: the member's own update or insert is credited and counted.
  assert.deepEqual(row(profile(syncWorker, [audit(['svc-sync', 'member-1'])], [control('T', [{ kind: 'effect.exists', select: updates[0].select }])])), effectRow('effect.exists', 'proven', 'pass', 'fail'));
  const inserts = sync({ actor: 'svc-sync', operation: 'insert', name: 'refund.issue' });
  assert.deepEqual(row(profile(inserts, [audit(['svc-sync', 'member-1'])], [control('T', [{ kind: 'effect.count', expected: 1, select: { source: 'sql-audit-table', operation: 'insert', name: 'refund.issue' } }])])),
    effectRow('effect.count', 'proven', 'pass', 'fail'));
  // B: an egress source pinned to one resource absorbs that resource only (the first planted one too); a send on any other fails.
  const refunds = [{ kind: 'effect.none', select: BILLING }];
  const twoPaths = { ...EGRESS, destinations: [{ host: 'billing.example.test', paths: ['/refunds', '/sync'] }] };
  for (const resource of ['POST /sync', 'POST /refunds']) assert.deepEqual(row(profile(sync({ operation: 'send', name: 'billing.example.test', resource }), [twoPaths], [T(refunds)])), effectRow('effect.none', 'proven', 'pass', 'fail'), resource);
  // C: with late fails withheld, an earlier twin pinned to one path explains a send on that path only.
  const timing = { timing: { effectHorizonMs: 500, runBudgetMs: 7200000, lateFails: 'withhold' } };
  const payouts = { ...EGRESS, destinations: [{ host: 'billing.example.test', paths: ['/refunds', '/payouts'] }] };
  assert.deepEqual(row(profile(timing, [payouts], [control('ALLOWED', [{ kind: 'effect.exists', select: { ...BILLING, operation: 'send', resource: 'POST /payouts' } }]), T(refunds)])), effectRow('effect.none', 'proven', 'pass', 'fail'));
  // Still broken where every event a run could record is absorbed: the worker is the only declared principal (an undeclared
  // actor is unlisted, which the pin takes too), or another source that pins no actor takes the plant whatever its actor.
  assert.deepEqual(row(profile(syncWorker, [audit(['svc-sync'])], [T(updates)])), effectRow('effect.none', 'cannot-fail', 'inconclusive', 'inconclusive', 'background-unattributed'));
  const cron = { attribution: { background: [...syncWorker.attribution.background, { id: 'cron', select: { operation: 'update', name: 'order.update' } }] } };
  assert.deepEqual(row(profile(cron, [audit()], [T(updates)])), effectRow('effect.none', 'cannot-fail', 'inconclusive', 'inconclusive', 'background-unattributed'));
  // The profile gives no principal (or no resource) to plant, and only a rule pinning one absorbs the plant: unprovable, named.
  assert.deepEqual(row(profile(syncWorker, [audit()], [T(updates)])), effectRow('effect.none', 'unprovable', 'inconclusive', 'inconclusive', 'actor-not-declared'));
  assert.deepEqual(row(profile(syncWorker, [audit()], [control('T', [{ kind: 'effect.exists', select: updates[0].select }])])), effectRow('effect.exists', 'unprovable', 'inconclusive', 'fail', 'actor-not-declared'));
  const resourced = { ...audit(['member-1']), audit: { ...audit().audit, resourceColumn: 'resource' } };
  const order7 = control('EARLY', [{ kind: 'effect.exists', select: { ...updates[0].select, resource: 'order-7' } }]);
  assert.deepEqual(row(profile(timing, [resourced], [order7, T(updates)])), effectRow('effect.none', 'unprovable', 'inconclusive', 'inconclusive', 'resource-not-declared'));
  // Nothing of a declared value reaches the report.
  const text = JSON.stringify(knownNegativeTarget(profile(syncWorker, [audit(['svc-sync', 'member-1'])], [T(updates)])));
  for (const value of ['svc-sync', 'member-1', 'order.update']) assert.ok(!text.includes(value), value);
});

test('L7: an absence or count the evaluator never decides names why', () => {
  const routed = name => effectCheck([{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name } }], {}, validated({ ...LAB, observers: [EGRESS] }));
  assert.deepEqual(clause(routed({ prefix: 'billing' })), effectRow('effect.none', 'pass-unreachable', 'unobservable', 'fail', 'name-not-exact'));
  const second = { ...EGRESS, id: 'egress2', port: 4198, witness: { ...WITNESS, host: 'witness2.example.test' } };
  assert.deepEqual(clause(effectCheck([{ kind: 'effect.count', expected: 0, select: BILLING }], {}, validated({ ...LAB, observers: [EGRESS, second] }))),
    effectRow('effect.count', 'cannot-fail', 'missing', 'missing', 'count-observers'));
});

test('L6: authoritative-first planting, the trace-id shape, the planted-reason rule and the plant gate each decide a case', () => {
  // Two recorders of one host, the presence-only one declared first: the count is planted where it is counted.
  const bare = { id: 'bare', type: 'egress-recorder', port: 4197, destinations: [{ host: 'billing.example.test' }] };
  const count = (expected, select, target) => clause(effectCheck([{ kind: 'effect.count', expected, select }], {}, target));
  assert.deepEqual(count(2, BILLING, validated({ ...LAB, observers: [bare, EGRESS] })), effectRow('effect.count', 'proven', 'pass', 'fail'));
  // Only the presence-only recorder declares /other; the routed one names such a send "POST *", so a count pinned to it is 0 on
  // every build. Its fixed twin fails too: always-fails, whatever the defective twin matched.
  const split = validated({ ...LAB, observers: [EGRESS, { ...bare, destinations: [{ host: 'billing.example.test', paths: ['/other'] }] }] });
  assert.deepEqual(count(1, { ...BILLING, resource: 'POST /other' }, split), effectRow('effect.count', 'always-fails', 'fail', 'fail'));
  // An OpenTelemetry trace id is 32 lowercase hex digits: a pin to anything else is never recorded.
  const traced = traceId => clause(effectCheck([{ kind: 'effect.none', select: { source: 'otel-genai', operation: 'tool-call', name: 'issue_refund', traceId } }]));
  assert.deepEqual(traced('not-a-trace-id'), effectRow('effect.none', 'unprovable', null, null, 'trace-not-recorded'));
  assert.deepEqual(traced('0af7651916cd43dd8448eb211c80319c'), effectRow('effect.none', 'pass-unreachable', 'unobservable', 'fail', 'presence-only'));
  // The plant gate: a plant the observer's own window would not match proves nothing. A recorded resource is cut at 200
  // characters, so a longer pin (which the validator refuses) is never matched.
  assert.deepEqual(clause(effectCheck([{ kind: 'effect.none', select: { source: 'otel-genai', name: 'issue_refund', resource: 'r'.repeat(250) } }])),
    effectRow('effect.none', 'unprovable', null, null, 'plant-not-matched'));
});

test('pass-unreachable: a boundary absence on a subject-writable record is held by custody, and on telemetry is unobservable', () => {
  const held = effectCheck([{ kind: 'effect.none', select: { source: 'sql-audit-table', operation: 'update', name: 'note.update', actor: 'member-1' } }]);
  assert.equal(held.outcome, 'partial');
  assert.deepEqual(held.predicates[1], { layer: 'effect', index: 0, kind: 'effect.none', outcome: 'pass-unreachable', fixed: 'inconclusive', defective: 'fail', reason: 'custody' });
  const telemetry = effectCheck([{ kind: 'effect.none', select: { source: 'otel-genai', operation: 'tool-call', name: 'issue_refund' } }]);
  assert.deepEqual(telemetry.predicates[1], { layer: 'effect', index: 0, kind: 'effect.none', outcome: 'pass-unreachable', fixed: 'unobservable', defective: 'fail', reason: 'presence-only' });
});

test('every declared observer type is modelled, and each model\'s scope is the observer\'s own', () => {
  assert.deepEqual([...MODELLED_OBSERVER_TYPES].sort(), [...OBSERVER_TYPES].sort());
  // Built, never started: no port is bound and no file is opened.
  const built = buildObservers(lab.observers, { env: {} });
  const scopes = observerScopes(lab);
  assert.equal(scopes.length, built.length);
  scopes.forEach((s, i) => {
    const o = built[i];
    assert.deepEqual(s, { instanceId: o.instanceId, source: o.source, scope: { operations: o.scope.operations, names: o.scope.names, actorAttribution: o.scope.actorAttribution, evidence: o.scope.evidence } }, o.instanceId);
  });
  const bare = { ...lab, observers: [{ id: 'egress', type: 'egress-recorder', port: 4199, destinations: [{ host: 'billing.example.test' }] }, { id: 'mail', type: 'smtp-sink', port: 4198, domains: [{ domain: 'mail.example.test' }] }] };
  assert.deepEqual(observerScopes(bare).map(s => s.scope.evidence), buildObservers(bare.observers, { env: {} }).map(o => o.scope.evidence));
});

test('L1: the planted kinds are exactly the validator\'s, and a kind added later reads unprovable, never proven', () => {
  // The validator's assertion kinds (src/contracts.mjs STATUS_KINDS and JSON_KINDS), read from its source.
  const source = readFileSync(new URL('../src/contracts.mjs', import.meta.url), 'utf8');
  const [, statusKinds, jsonKinds] = /const STATUS_KINDS = \[([^\]]*)\], JSON_KINDS = \[([^\]]*)\];/.exec(source);
  const kinds = `${statusKinds},${jsonKinds}`.split(',').map(k => k.trim()).map(k => k === 'FOREIGN_VALUES_KIND' ? FOREIGN_VALUES_KIND : k.replace(/^'|'$/g, ''));
  assert.deepEqual([...kinds].sort(), [...PLANTED_KINDS.response].sort());
  assert.deepEqual([...EFFECT_ASSERTIONS].sort(), [...PLANTED_KINDS.effect].sort());
  const notMatches = run({ id: 'K1', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.notMatches', pointer: '/a', expected: 'x' }] });
  assert.deepEqual(notMatches.predicates[1], { layer: 'response', index: 1, kind: 'json.notMatches', outcome: 'unprovable', fixed: null, defective: null, reason: 'kind-not-planted' });
  assert.equal(notMatches.outcome, 'partial');
  const sometimes = effectCheck([{ kind: 'effect.sometimes', select: { source: 'http-egress', name: 'billing.example.test' } }]);
  assert.deepEqual(clause(sometimes), { layer: 'effect', index: 0, kind: 'effect.sometimes', outcome: 'unprovable', fixed: null, defective: null, reason: 'kind-not-planted' });
  // A whole-body kind the evaluator cannot read throws in the evaluator: error, never proven and never broken.
  const wholeBody = run({ id: 'K2', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'body.notContains', expected: 'x' }] });
  assert.deepEqual([wholeBody.outcome, ...outcomes(wholeBody)], ['error', 'error', 'error']);
});

test('not planted yet: effect.only, countBy, body fields, upstream and claim rules, each unprovable with its reason', () => {
  const result = effectCheck([
    { kind: ONLY_KIND, expect: 1, allow: [{ source: 'http-egress', name: 'billing.example.test' }] },
    { kind: 'effect.count', expected: 1, countBy: 'idempotency-key', select: { source: 'http-egress', name: 'billing.example.test' } },
    { kind: 'effect.none', select: { source: 'http-egress', name: 'billing.example.test', fields: [{ pointer: '/amount', equals: 5 }] } },
    { kind: 'effect.none', select: { source: 'http-egress', name: 'billing.example.test', upstream: 'applied' } },
  ], { claims: [{ trigger: {} }] });
  assert.deepEqual(result.predicates.slice(1).map(p => [p.layer, p.kind, p.outcome, p.reason]), [
    ['effect', 'effect.only', 'unprovable', 'effect.only'], ['effect', 'effect.count', 'unprovable', 'countBy'],
    ['effect', 'effect.none', 'unprovable', 'body-fields'], ['effect', 'effect.none', 'unprovable', 'upstream'],
    ['claim', 'claim', 'unprovable', 'claim-rule']]);
  assert.equal(result.outcome, 'partial', 'the proven status predicate keeps it partial, never proven');
  assert.equal(run({ id: 'N', assertions: [], effects: [{ kind: ONLY_KIND, expect: 1, allow: [] }] }).outcome, 'unprovable', 'nothing shown to fail');
});

test('fail closed: an exception reads error, neither proven nor broken, and the summary counts it', () => {
  const unsafe = run({ id: 'X1', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/__proto__/a', expected: 1 }] });
  assert.equal(unsafe.outcome, 'error');
  assert.deepEqual(unsafe.predicates.map(p => [p.outcome, p.reason]), [['error', 'exception'], ['error', 'exception']]);
  const malformed = effectCheck([{ kind: 'effect.none', select: {} }]);
  assert.deepEqual([malformed.outcome, clause(malformed).outcome, clause(malformed).reason], ['error', 'error', 'exception']);
  assert.deepEqual(knownNegativeCheck(null, lab), { id: null, outcome: 'error', predicates: [], reason: 'exception' });
  const throwing = { ...base, id: 'X1', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/__proto__/a', expected: 1 }] };
  const report = knownNegativeTarget({ ...lab, checks: [...lab.checks, throwing] });
  assert.equal(report.outcome, 'error');
  assert.deepEqual([report.counts.checks.error, report.counts.predicates.error, report.counts.checks.proven], [1, 2, 3]);
  const vacuous = { ...base, id: 'V', assertions: [{ kind: 'json.exists', pointer: '', expected: true }] };
  assert.equal(knownNegativeTarget({ ...lab, checks: [...lab.checks, throwing, vacuous] }).outcome, 'broken', 'a broken check still outranks an error');
});

test('the target outcome: broken outranks error, error outranks partial, partial outranks proven; no checks proves nothing', () => {
  const vacuous = { ...base, id: 'V', assertions: [{ kind: 'json.exists', pointer: '', expected: true }] };
  const held = { ...base, id: 'H', method: 'POST', evidenceRequirement: 'backend', assertions: [{ kind: 'status.in', expected: [403, 404] }], effects: [{ kind: 'effect.none', select: { source: 'sql-snapshot', operation: 'insert', name: 'notes' } }] };
  assert.equal(knownNegativeTarget({ ...lab, checks: [...lab.checks, held] }).outcome, 'partial');
  const broken = knownNegativeTarget({ ...lab, checks: [...lab.checks, held, vacuous] });
  assert.equal(broken.outcome, 'broken');
  assert.deepEqual(broken.counts.checks, { proven: 3, broken: 1, partial: 1, unprovable: 0, error: 0 });
  // L2: an empty check list is not proven.
  assert.deepEqual(knownNegativeTarget({ id: 't', checks: [] }).outcome, 'unprovable');
  assert.deepEqual(knownNegativeTarget({ id: 't', checks: [] }).counts.checks, { proven: 0, broken: 0, partial: 0, unprovable: 0, error: 0 });
});

test('a seeded canary: each planted form fails on its own channel, a clean body passes', () => {
  const proven = { outcome: 'proven', fixed: 'pass', defective: { verbatim: 'verbatim', folded: 'folded', skeleton: 'skeleton', encoded: 'encoded' },
    channels: { verbatim: { outcome: 'proven' }, folded: { outcome: 'proven' }, skeleton: { outcome: 'proven' }, encoded: { outcome: 'proven' } } };
  // Values the canary value rule accepts: printable ASCII, at least 16 characters, 10 distinct, no run of 4.
  assert.deepEqual(knownNegativeCanary('CANARY-COBALT-ORDER-c3a9'), proven);
  assert.deepEqual(knownNegativeCanary('ZQ7KX2MW9PRT4VH8'), proven, 'an upper-case value');
  // M1: the reviewer's letter-separated value exercises its own channels. Its CJK value is outside printable ASCII, so the
  // rule refuses it (below); a lower-case value, which the fold leaves as it is, is planted with a zero-width space instead.
  assert.deepEqual(knownNegativeCanary('Q-7-K-X-2-M-W-9-P'), proven, 'a letter-separated value is planted with another separator');
  assert.deepEqual(knownNegativeCanary('zq7kx2mw9prt4vh8'), proven, 'a lower-case value is planted with a zero-width space');
  // A value drawn as a run draws one (drawCanaryValue), from a fixed seed so the test stays the same on every run.
  let seed = 0;
  const drawn = drawCanaryValue(() => createHash('sha256').update(`known-negative-${seed++}`).digest('base64url').slice(0, 20));
  assert.deepEqual(knownNegativeCanary(drawn), proven, 'a drawn value');
  // Every channel canaryVerdict reports has its own planted form, so a channel added there fails here until it is planted.
  assert.deepEqual(CANARY_FORMS, ['verbatim', 'folded', 'skeleton', 'encoded']);
  assert.deepEqual([...CANARY_FORMS], [...CANARY_CHANNELS]);
  // A value the rule refuses cannot fail, with the rule's reason.
  assert.deepEqual(knownNegativeCanary('password'), { outcome: 'cannot-fail', reason: 'value-not-marker-shaped' });
  assert.deepEqual(knownNegativeCanary('日本語中文漢字東京7392815'), { outcome: 'cannot-fail', reason: 'value-not-marker-shaped' }, 'outside printable ASCII');
  assert.deepEqual(knownNegativeCanary('ZQ7KX2MW9P'), { outcome: 'cannot-fail', reason: 'value-low-entropy' }, 'too short');
  assert.deepEqual(knownNegativeCanary('Q7'.repeat(251)), { outcome: 'cannot-fail', reason: 'value-too-long' });
  assert.deepEqual(knownNegativeCanary(undefined), { outcome: 'cannot-fail', reason: 'value-unavailable' });
  assert.ok(!JSON.stringify(knownNegativeCanary('CANARY-COBALT-ORDER-c3a9')).toLowerCase().includes('cobalt'));
});

test('M1: a form caught on another channel is not proven for its own', () => {
  // The last nine characters encode in base64 to the value's own letters and digits, and the '>' before them ends a base64
  // group in '+'. So the encoded plant ends in the value's skeleton, and the skeleton channel catches it before the
  // encoded channel is tried.
  const spelled = knownNegativeCanary('LCF7-P3ss-LD8s>,!{?{,,?,');
  assert.equal(spelled.outcome, 'unprovable');
  assert.deepEqual([spelled.defective.encoded, spelled.channels.encoded], ['skeleton', { outcome: 'unprovable', reason: 'caught-on-another-channel' }]);
  assert.deepEqual([spelled.channels.verbatim, spelled.channels.folded, spelled.channels.skeleton], [{ outcome: 'proven' }, { outcome: 'proven' }, { outcome: 'proven' }]);
  // The value rule refuses any value outside printable ASCII, so the earlier wrong-channel value (fullwidth hyphens, whose
  // skeleton plant folded to the value) and a value holding a zero-width space each cannot fail instead of reading
  // unprovable: a value with a lookalike or invisible character is never judged at all.
  assert.deepEqual(knownNegativeCanary('Q\uFF0D7\uFF0DK\uFF0DX\uFF0D2\uFF0DM\uFF0DW\uFF0D9\uFF0DP'), { outcome: 'cannot-fail', reason: 'value-not-marker-shaped' });
  assert.deepEqual(knownNegativeCanary('\u200BZQ7KX2MW9PRT4VH8'), { outcome: 'cannot-fail', reason: 'value-not-marker-shaped' });
  // Every separator used: no skeleton plant at all, so that channel is unprovable, never proven.
  const crowded = knownNegativeCanary('Q-7.K_X:2/M+W~9P');
  assert.deepEqual([crowded.outcome, crowded.channels.skeleton], ['unprovable', { outcome: 'unprovable', reason: 'no-plant' }]);
});
