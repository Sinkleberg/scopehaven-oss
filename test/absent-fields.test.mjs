// Absent fields, fail direction only, opt-in per pin. The DP5 round's R65-012: an agent sent POST /billing/v1/orders/QTN-6207/refunds
// with the form body amount=43; the egress recorder read the body in full and parsed it without error, and the check's pinned field was
// not in it. An absent field reads 'unknown' (an omitted field may mean the receiver's default, and a receiver may read an alias or
// another spelling), so the effect.count abstained. A field pin may now declare absent: "fails", the operator's statement that the
// receiver neither defaults nor aliases that field; then, inside the fail-only judgement of evaluateEffectAssertion only, a field the
// recorder recorded absent reads 'no', kept only when it makes a missing clause fail. Such a fail carries absenceDecided and never earns
// repair credit. Checked: the declaration and its validation, the recorder's guards (a JSON field missing beside a URL query or under a
// root that is not an object is never absent), the three-valued logic, each kind's fail-only path with countBy, the fail-open guards,
// the readers that keep unknown, the claim and later-outcome re-judges, the evidence validator, a seeded differential against main's
// frozen evaluator, and one connector run over real loopback HTTP (destination hosts are names only, never resolved or contacted).
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { captureBody, fieldState, validateFieldPredicates } from '../src/body-fields.mjs';
import { makeEffect, matchState, matches, definitelyAbsent, evaluateEffectAssertion, otherActorCommit, absentFieldBasis, admitScoped } from '../src/effect-events.mjs';
import { decideEffects, applyLater, effectTrace, effectAssertionRows, absenceFields } from '../src/http-effects.mjs';
import { fitsSelector, settlementFindings, applySettlement } from '../src/http-settlement.mjs';
import { laterFindings, laterReadings } from '../src/later-outcome.mjs';
import { validateIdempotencyDeclaration } from '../src/idempotency.mjs';
import { judgeOnly } from '../integrations/collateral/only.mjs';
import { onFreePorts, watchingBinds } from '../integrations/observers/fixtures/free-port.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { compareRuns, NO_VERIFIED_REPAIR } from '../src/runner.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';

// main before this change: effect events and body fields at 39c45ba (the frozen effect events import the frozen body fields).
const frozen = await import(fileURLToPath(new URL('./fixtures/effect-events-39c45ba.mjs', import.meta.url)));

const BILL = 'billing.example.test', HOOKS = 'hooks.example.test', INST = 'egress-recorder-sink', PATH = '/billing/v1/orders/QTN-6207/refunds', REFUND = `POST ${PATH}`;
const POINTERS = Object.freeze(['/amount', '/amount_cents']);
const SCOPE = Object.freeze({ operations: ['send'], names: [BILL], actorAttribution: 'none', evidence: 'authoritative', capture: { [BILL]: POINTERS }, captureForm: [BILL] });
const ACTOR_SCOPE = Object.freeze({ ...SCOPE, actorAttribution: 'principal' });
// A field-blind observer: it sees the destination's sends but declares no capture.
const BLIND_SCOPE = Object.freeze({ operations: ['send'], names: [BILL], actorAttribution: 'none', evidence: 'authoritative' });
const PIN = Object.freeze([{ pointer: '/amount_cents', equals: 4275 }]);
const DECLARED = Object.freeze([{ pointer: '/amount_cents', equals: 4275, absent: 'fails' }]);
const ABSENT = Object.freeze({ type: 'absent' });
const QUERY = Object.freeze({ type: 'unusable', reason: 'absent-query' }), ROOT = Object.freeze({ type: 'unusable', reason: 'absent-root' });
const text = value => ({ type: 'text', value });
// A form record (amount=43 by default) and a JSON one, each with every declared pointer.
const form = (cents, amount = text('43')) => ({ status: 'captured', values: { '/amount': amount, '/amount_cents': cents } });
const json = cents => ({ status: 'captured', values: { '/amount': { type: 'number', value: 43 }, '/amount_cents': cents } });
const R65 = form(ABSENT);
const MATCH = form(text('4275')), OTHER = form(text('4300'));
const UNREADABLE = Object.freeze({ overCap: { status: 'over-cap', values: {} }, duplicate: { status: 'form-duplicate-key', values: {} }, notJson: { status: 'not-json', values: {} },
  queryOrCookie: { status: 'form-query-or-cookie', values: {} }, pathUndeclared: { status: 'path-undeclared', values: {} }, none: undefined });
let seq = 0;
const send = (captured, extra = {}) => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST }, seq: ++seq, observedAt: '2026-10-15T00:00:00.000Z',
  operation: 'send', name: BILL, resource: REFUND, outcome: 'committed', ...(captured === undefined ? {} : { captured }), ...extra });
const win = (events, { coverage = 'complete', scope = SCOPE, instanceId = INST } = {}) => ({ source: 'http-egress', instanceId, scope, coverage, reason: coverage === 'complete' ? null : 'synthetic', events });
const refunds = (fields = DECLARED, extra = {}) => ({ source: 'http-egress', operation: 'send', name: BILL, resource: REFUND, ...(fields ? { fields } : {}), ...extra });
const count = (expected, select = refunds()) => ({ kind: 'effect.count', select, expected });
const EXISTS = Object.freeze({ kind: 'effect.exists', select: refunds() }), NONE = Object.freeze({ kind: 'effect.none', select: refunds() });
const judged = (clause, records, opts) => evaluateEffectAssertion(clause, [win(records.map(r => send(r)), opts)]);
const verdictOf = (clause, records, opts) => judged(clause, records, opts).verdict;
// Main cannot read the declaration (it refuses the key): it judges the same pins without it.
const undeclared = clause => ({ ...clause, select: { ...clause.select, fields: clause.select.fields.map(({ absent: _a, ...pin }) => pin) } });
const mainVerdictOf = (clause, records, opts) => frozen.evaluateEffectAssertion(undeclared(clause), [win(records.map(r => send(r)), opts)]).verdict;
const BASIS = /declared field absent from a fully captured body/;
const blindWindow = () => win([makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: 'blind' }, seq: 1, operation: 'send', name: BILL, resource: REFUND, outcome: 'committed' })], { scope: BLIND_SCOPE, instanceId: 'blind' });

// The profile of the connector run (test 12); test 1 validates it with and without a valid declaration.
const WITNESS = 'witness.scopehaven.invalid';
const profileOf = (port, origin, effects) => ({ id: 'refunds', name: 'Refunds', applicationId: 'refunds', origin, buildLabel: 'b1', contextId: 'synthetic-refunds',
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'],
  observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [{ host: BILL, paths: [PATH], capture: { pointers: [...POINTERS], maxBytes: 1024, encodings: ['json', 'form'] } }],
    witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
    { id: 'REFUND', title: 'REFUND', category: 'billing', severity: 'high', actorId: 'ops', method: 'POST', path: '/refund', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], effects }] });

// ---------------------------------------------------------------------------
test('1. the declaration: absent "fails" on a field pin, validated with the selector and the target file; the operator is read by name', () => {
  assert.doesNotThrow(() => validateFieldPredicates(DECLARED));
  assert.doesNotThrow(() => validateFieldPredicates([{ absent: 'fails', pointer: '/amount_cents', in: [4275] }]));
  for (const [fields, code] of [[[{ pointer: '/amount_cents', equals: 4275, absent: true }], /selector-fields-absent/], [[{ pointer: '/amount_cents', equals: 4275, absent: 'passes' }], /selector-fields-absent/],
    [[{ pointer: '/amount_cents', absent: 'fails' }], /selector-fields/], [[{ pointer: '/amount_cents', equals: 4275, gt: 1, absent: 'fails' }], /selector-fields/], [[{ pointer: '/amount_cents', equals: 4275, extra: 1 }], /selector-fields/]]) {
    assert.throws(() => validateFieldPredicates(fields), code, JSON.stringify(fields));
  }
  // The contract validator (target file) accepts the declaration on a clause and refuses any other value.
  const origin = 'http://127.0.0.1:43172';
  assert.doesNotThrow(() => validateTargetFile({ schemaVersion: 1, targets: [profileOf(43171, origin, [count(1)])] }));
  assert.doesNotThrow(() => validateTargetFile({ schemaVersion: 1, targets: [profileOf(43171, origin, [count(1, refunds(PIN))])] }));
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [profileOf(43171, origin, [count(1, refunds([{ ...PIN[0], absent: 'yes' }]))])] }), /selector-fields-absent/);
  // The operator is found by name wherever the declaration sits.
  assert.equal(fieldState(MATCH, { absent: 'fails', pointer: '/amount_cents', equals: 4275 }), 'match');
  assert.equal(fieldState(OTHER, { absent: 'fails', pointer: '/amount_cents', in: [4275] }), 'no');
});

test('2. the recorder\'s reading: a field absent from a body read in full; beside a URL query or under a non-object root it is never absent', () => {
  const capture = { pointers: [...POINTERS], maxBytes: 1024, encodings: ['json', 'form'] };
  const read = (body, { type = 'application/x-www-form-urlencoded', method = 'POST', search = '', cookie } = {}) => captureBody({ rawHeaders: ['Content-Type', type, ...(cookie ? ['Cookie', cookie] : [])],
    buffer: Buffer.from(body), bodyBytes: Buffer.byteLength(body), capture, search, method });
  // R65-012's body: amount=43, POST, no query, no cookie, within the cap.
  assert.deepEqual(read('amount=43'), R65);
  assert.equal(definitelyAbsent(send(read('amount=43')), '/amount_cents'), true);
  assert.equal(definitelyAbsent(send(read('amount=43')), '/amount'), false, 'a present field');
  assert.deepEqual(read('{"amount":43}', { type: 'application/json' }), json(ABSENT));
  // (a) A JSON request with a URL query: some receivers merge the query under the body, so a missing body field is unusable.
  assert.deepEqual(read('{"amount":43}', { type: 'application/json', search: '?amount_cents=4275' }), json(QUERY));
  const noSearch = Buffer.from('{"amount":43}');
  assert.deepEqual(captureBody({ rawHeaders: ['Content-Type', 'application/json'], buffer: noSearch, bodyBytes: noSearch.length, capture, method: 'POST' }), json(QUERY), 'a caller that gives no query is read as one with a query');
  assert.deepEqual(read('{"amount":43,"amount_cents":4275}', { type: 'application/json', search: '?x=1' }).values['/amount_cents'], { type: 'number', value: 4275 }, 'present fields read as before');
  // (b) A root that is not a JSON object: an array (a batch or wrapper) or a scalar.
  assert.deepEqual(read('[{"amount_cents":4275}]', { type: 'application/json' }).values, { '/amount': ROOT, '/amount_cents': ROOT });
  assert.deepEqual(read('43', { type: 'application/json' }).values, { '/amount': ROOT, '/amount_cents': ROOT });
  // A form body is read only without a query or cookie, so nothing changes there.
  assert.deepEqual(read('amount=43', { search: '?a=1' }), { status: 'form-query-or-cookie', values: {} });
  for (const value of [QUERY, ROOT]) {
    assert.equal(definitelyAbsent(send(json(value)), '/amount_cents'), false, value.reason);
    assert.equal(matchState(send(json(value)), refunds(), { absentFields: true }), 'unknown', value.reason);
  }
  // Everything else stays unknown: no record, an unreadable or truncated body, an unusable, ambiguous or mistyped value.
  for (const [label, captured] of [...Object.entries(UNREADABLE), ['repeated key', read('amount=43&amount=44')], ['cookie', read('amount=43', { cookie: 'a=1' })],
    ['not POST', read('amount=43', { method: 'PUT' })], ['another media type', read('amount=43', { type: 'text/plain' })]]) {
    assert.equal(definitelyAbsent(send(captured), '/amount_cents'), false, label);
    assert.equal(matchState(send(captured), refunds(), { absentFields: true }), 'unknown', label);
  }
  for (const value of [{ type: 'unusable', reason: 'redacted' }, { type: 'unusable', reason: 'ambiguous' }, { type: 'unusable', reason: 'not-scalar' }]) {
    assert.equal(definitelyAbsent(send(form(value)), '/amount_cents'), false, value.reason);
  }
  assert.equal(definitelyAbsent(send(json({ type: 'string', value: '4275' })), '/amount_cents'), false, 'a value of another type is present');
  assert.equal(definitelyAbsent(send(R65), '/not_declared'), false, 'a pointer the record does not carry');
  // A provider feed's template record is not a body: a signed entry naming no template stays unknown, declared or not.
  const feed = makeEffect({ source: 'provider-feed', observer: { kind: 'provider-feed', instanceId: 'feed' }, seq: 1, operation: 'send', name: 'mail.example.test', outcome: 'committed',
    captured: { status: 'captured', values: { '/template': ABSENT } } });
  assert.equal(definitelyAbsent(feed, '/template'), false);
  assert.equal(matchState(feed, { source: 'provider-feed', name: 'mail.example.test', fields: [{ pointer: '/template', equals: 'refund_confirmation', absent: 'fails' }] }, { absentFields: true }), 'unknown');
});

test('3. three-valued logic: absent stays unknown without the declaration; a declaring pin reads no under absentFields, and any no wins', () => {
  const e = send(R65);
  assert.equal(fieldState(R65, DECLARED[0]), 'unknown', 'body-fields never decides absence');
  assert.equal(matchState(e, refunds()), 'unknown', 'the default reading is main\'s, declaration or not');
  assert.equal(matches(e, refunds()), false);
  assert.equal(matchState(e, refunds(PIN), { absentFields: true }), 'unknown', 'no declaration: unknown, exactly as on main');
  assert.equal(matchState(e, refunds(), { absentFields: true }), 'no');
  assert.equal(matchState(e, refunds(), { formDecimals: true }), 'unknown', 'formDecimals does not touch absence');
  for (const entry of [{ equals: 4275 }, { equals: '4275' }, { equals: null }, { in: [4275, 4300] }, { gt: 0 }, { gte: 0 }, { lt: 1e9 }, { lte: 1e9 }]) {
    assert.equal(matchState(e, refunds([{ pointer: '/amount_cents', ...entry, absent: 'fails' }]), { absentFields: true }), 'no', JSON.stringify(entry));
  }
  // Conjunctions: a declared absent field beside a match, an unknown or a no is no; an undeclared one beside a match stays unknown.
  const both = (extra, declared = true) => refunds([declared ? DECLARED[0] : PIN[0], { pointer: '/amount', ...extra }]);
  assert.equal(matchState(e, both({ equals: '43' }), { absentFields: true }), 'no');
  assert.equal(matchState(e, both({ equals: '43' }, false), { absentFields: true }), 'unknown');
  assert.equal(matchState(send(form(ABSENT, { type: 'unusable', reason: 'redacted' })), both({ equals: '43' }), { absentFields: true }), 'no', 'absent beside unusable');
  assert.equal(matchState(send(form(text('4275'), { type: 'unusable', reason: 'redacted' })), both({ equals: '43' }), { absentFields: true }), 'unknown', 'match beside unusable');
  // The declaration is per pin: an absent field under a pin without it stays unknown beside a declaring pin that matches.
  assert.equal(matchState(send(form(text('4275'), ABSENT)), refunds([DECLARED[0], { pointer: '/amount', equals: '43' }]), { absentFields: true }), 'unknown');
  assert.equal(matchState(send(MATCH), refunds(), { absentFields: true }), 'match');
  assert.equal(matchState(send(OTHER), refunds(), { absentFields: true }), 'no');
  assert.equal(matchState(send(R65, { name: 'hooks.example.test' }), refunds(), { absentFields: true }), 'no', 'a base miss is no');
  assert.equal(matchState(send(R65), refunds(DECLARED, { upstream: 'applied' }), { absentFields: true }), 'no');
  assert.equal(matchState(send(MATCH), refunds(DECLARED, { upstream: 'applied' }), { absentFields: true }), 'unknown');
});

// ---------------------------------------------------------------------------
test('4. R65-012: a count expecting one refund whose only send lacks the pinned field fails with the declaration, and stays missing without it', () => {
  const clause = count(1);
  assert.equal(mainVerdictOf(clause, [R65]), 'missing', 'main abstained');
  const plain = judged(count(1, refunds(PIN)), [R65]);
  assert.equal(plain.verdict, 'missing', 'without the declaration: unchanged');
  assert.equal(plain.absenceDecided, undefined);
  const r = judged(clause, [R65]);
  assert.equal(r.verdict, 'fail');
  assert.equal(r.absenceDecided, true);
  assert.equal(r.matched, 0);
  assert.match(r.basis, /^Observed 0 matching committed effects; expected 1\. /);
  assert.equal(r.basis.endsWith(absentFieldBasis(1)), true);
  assert.doesNotMatch(r.basis, /43/, 'the basis names counts, never a captured value');
  // The HTTP evaluator (decideEffects) carries the tag into the decision, the sealed record and the assertion row.
  const [d] = decideEffects([clause], [win([send(R65)])]);
  assert.deepEqual([d.verdict, d.absenceDecided], ['fail', true]);
  assert.deepEqual(decideEffects([count(1, refunds(PIN))], [win([send(R65)])]).map(x => [x.verdict, x.absenceDecided]), [['missing', undefined]]);
  assert.equal(effectTrace([d], [win([send(R65)])], new Map([[INST, { kind: 'http-egress-recorder', settleMs: 250 }]])).data.effects[0].absenceDecided, true);
  assert.equal(effectAssertionRows([d])[0].absenceDecided, true);
  assert.equal(verdictOf(clause, [json(ABSENT)]), 'fail', 'JSON alike');
  assert.equal(verdictOf(clause, [json(QUERY)]), 'missing', 'a JSON send beside a query: the declaration cannot decide it');
  assert.equal(verdictOf(clause, [json(ROOT)]), 'missing', 'a JSON root that is not an object');
});

test('5. effect.exists: fails when no send can be the expected one; a send still undecided for another reason keeps it missing', () => {
  assert.equal(verdictOf(EXISTS, [R65]), 'fail');
  assert.equal(verdictOf({ kind: 'effect.exists', select: refunds(PIN) }, [R65]), 'missing', 'undeclared');
  assert.match(judged(EXISTS, [R65, R65]).basis, /Decided by 2 committed send\(s\) with a declared field absent/);
  assert.equal(verdictOf(EXISTS, [R65, OTHER]), 'fail');
  assert.equal(verdictOf(EXISTS, [R65, MATCH]), 'pass', 'a decided match passes, as before');
  for (const [label, captured] of Object.entries(UNREADABLE)) assert.equal(verdictOf(EXISTS, [R65, captured]), 'missing', `beside ${label}: that send could be the refund`);
  assert.equal(verdictOf(EXISTS, [R65, json(QUERY)]), 'missing');
  assert.equal(verdictOf(EXISTS, [R65, form(text('4275.00'))]), 'missing', 'a value that may be the pinned one');
  const actorExists = { kind: 'effect.exists', select: refunds(DECLARED, { actor: 'alice' }) };
  const actorWin = events => [win(events, { scope: ACTOR_SCOPE })];
  assert.equal(evaluateEffectAssertion(actorExists, actorWin([send(R65, { actor: 'alice' })])).verdict, 'fail');
  assert.equal(evaluateEffectAssertion(actorExists, actorWin([send(R65, { actor: null })])).verdict, 'fail', 'an unknown actor\'s send without the field is not it either');
  assert.equal(evaluateEffectAssertion(actorExists, actorWin([send(R65, { actor: 'alice' }), send(MATCH, { actor: null })])).verdict, 'missing', 'an unattributed match');
});

test('6. effect.count: the decided matches plus every send still undecided below expected fail; countBy decides once nothing is undecided', () => {
  assert.equal(verdictOf(count(2), [R65, MATCH]), 'fail', 'one decided, one absent: one of two');
  assert.equal(verdictOf(count(2), [R65, UNREADABLE.overCap]), 'fail', '0 decided + 1 undecided < 2');
  assert.match(judged(count(2), [R65, UNREADABLE.overCap]).basis, /Observed 0 matching committed effects and 1 committed send\(s\) still undecided; expected 2/);
  assert.equal(verdictOf(count(3), [MATCH, R65, UNREADABLE.duplicate]), 'fail', '1 + 1 < 3');
  assert.equal(verdictOf(count(2), [MATCH, R65, UNREADABLE.duplicate]), 'missing', '1 + 1 could be 2');
  assert.equal(verdictOf(count(1), [R65, UNREADABLE.notJson]), 'missing', 'the unreadable send could be the one');
  assert.equal(verdictOf(count(1), [MATCH, MATCH, R65]), 'fail', 'an over-count however the absent send reads');
  assert.equal(verdictOf(count(3), [UNREADABLE.overCap]), 'missing', 'no absence, no move');
  // countBy (keyed applications): one matching send under key a and an absent-field send under key b, expected 2.
  const KEYED = { ...SCOPE, idempotency: { [BILL]: validateIdempotencyDeclaration({ header: 'idempotency-key' }) } };
  const keyed = expected => ({ ...count(expected), countBy: 'idempotency-key' });
  const keyedSend = (captured, key, firstSeq, c) => send(captured, { content: { c }, idempotency: { status: 'keyed', key: key.repeat(64), fold: key.repeat(64), head: 'd'.repeat(64), firstSeq: firstSeq ?? seq + 1 } });
  const judgeKeyed = (clause, events) => evaluateEffectAssertion(clause, [win(events, { scope: KEYED })], { countBy: true });
  const separate = () => [keyedSend(MATCH, 'a', undefined, 1), keyedSend(R65, 'b', undefined, 2)];
  const was = frozen.evaluateEffectAssertion(undeclared(keyed(2)), [win(separate(), { scope: KEYED })], { countBy: true });
  assert.equal(was.verdict, 'missing');
  const twoKeys = judgeKeyed(keyed(2), separate());
  assert.deepEqual([twoKeys.verdict, twoKeys.applications, twoKeys.absenceDecided], ['fail', { low: 1, high: 1, reason: null }, true]);
  assert.equal(judgeKeyed(keyed(1), separate()).verdict, 'missing', 'one application, expected one: the would-be pass is not taken');
  // An absent-field resend under the same key as a counted send: applications 0 to 1.
  const sameKey = () => { const first = keyedSend(MATCH, 'a', undefined, 1); return [first, keyedSend(R65, 'a', first.seq, 2)]; };
  const resend = judgeKeyed(keyed(2), sameKey());
  assert.deepEqual([resend.verdict, resend.applications.low, resend.applications.high], ['fail', 0, 1]);
  assert.equal(judgeKeyed(keyed(1), sameKey()).verdict, 'missing', '0 to 1 applications could be 1');
  // While any send stays undecided, a countBy clause keeps today's missing (the bound counts sends, not applications).
  assert.equal(judgeKeyed(keyed(3), [keyedSend(R65, 'a', undefined, 1), keyedSend(UNREADABLE.overCap, 'b', undefined, 2)]).verdict, 'missing');
});

test('7. fail-open guards: effect.none never moves, and a count whose decided reading would pass keeps today\'s missing', () => {
  for (const records of [[R65], [R65, R65], [R65, OTHER], [R65, UNREADABLE.overCap]]) {
    const windows = [win(records.map(r => send(r)))], now = evaluateEffectAssertion(NONE, windows);
    assert.equal(now.verdict, 'missing', JSON.stringify(records));
    assert.deepEqual(now, frozen.evaluateEffectAssertion(undeclared(NONE), windows), 'main\'s decision, basis included');
  }
  assert.equal(verdictOf(NONE, [R65, MATCH]), 'fail', 'a decided forbidden refund fails, as before');
  assert.equal(verdictOf(count(1), [MATCH, R65]), 'missing', 'an over-count of 2 that reading the absence as no would drop to an exact 1');
  assert.equal(verdictOf(count(0), [R65]), 'missing');
  assert.equal(verdictOf(count(2), [MATCH, MATCH, R65]), 'missing');
  assert.equal(verdictOf(count(1), [R65], { coverage: 'partial' }), 'missing', 'a gap keeps the earlier verdict');
  assert.equal(verdictOf(EXISTS, [R65], { coverage: 'failed' }), 'missing');
  const blind = [win([send(R65)]), blindWindow()];
  assert.equal(evaluateEffectAssertion(EXISTS, blind).verdict, 'missing', 'a field-blind observer\'s send could be the expected one');
  assert.equal(evaluateEffectAssertion(count(1), blind).verdict, 'missing');
});

test('8. every other reader keeps today\'s unknown: a declared absent field still "could be" the clause\'s effect', () => {
  const e = send(R65);
  assert.equal(fitsSelector(e, refunds()), true, 'settlement: a late send that could be this check\'s effect');
  const other = send(R65, { actor: 'bob' });
  assert.equal(otherActorCommit({ kind: 'effect.exists', select: refunds(DECLARED, { actor: 'alice' }) }, [win([other], { scope: ACTOR_SCOPE })], 'alice'), true, 'rests-on');
  const only = { kind: 'effect.only', expect: [{ select: refunds(), count: 1 }], allow: [], sources: ['http-egress'] };
  assert.equal(judgeOnly(only, [win([e])], { fields: true, countBy: true }).verdict, 'missing', 'effect.only accepts the pin and keeps today\'s reading');
  // Only evaluateEffectAssertion passes absentFields (a source scan of the product code).
  const root = fileURLToPath(new URL('..', import.meta.url));
  const files = [];
  const walk = dir => { for (const name of readdirSync(dir)) { const path = join(dir, name); if (statSync(path).isDirectory()) { if (!['fixtures', 'node_modules', '.runtime'].includes(name)) walk(path); } else if (name.endsWith('.mjs') && !name.endsWith('.test.mjs')) files.push(path); } };
  for (const dir of ['src', 'integrations']) walk(join(root, dir));
  assert.deepEqual(files.filter(path => readFileSync(path, 'utf8').includes('absentFields')).map(path => path.slice(root.length)), ['src/effect-events.mjs']);
  const source = readFileSync(join(root, 'src/effect-events.mjs'), 'utf8');
  assert.deepEqual(source.match(/absentFields: true/g), ['absentFields: true', 'absentFields: true'], 'the re-judge and its count of decided sends');
  assert.equal((source.match(/judgeEffect\([^)]*absentFields: true[^)]*\)/g) ?? []).length, 1);
});

// ---------------------------------------------------------------------------
test('9. claims inherit it: a claimed success whose records hold only sends without the declared field reads as contradicted', () => {
  const claim = select => ({ trigger: { text: { pointer: '/reply', success: ['refund has been issued'], refusal: ['cannot issue a refund'] } }, select });
  const decide = (select, reading) => decideEffects([], [win([send(R65)])], { claims: [claim(select)], readings: [reading] })[0];
  const success = decide(refunds(), { reading: 'success', phraseIndex: 0 });
  assert.deepEqual([success.kind, success.verdict, success.absenceDecided], ['effect.exists', 'fail', true]);
  const meta = new Map([[INST, { kind: 'http-egress-recorder', settleMs: 250 }]]);
  assert.equal(effectTrace([success], [win([send(R65)])], meta).data.claims[0].absenceDecided, true);
  assert.equal(effectAssertionRows([success])[0].absenceDecided, true);
  assert.deepEqual([decide(refunds(PIN), { reading: 'success', phraseIndex: 0 }).verdict], ['missing'], 'undeclared');
  const refusal = decide(refunds(), { reading: 'refusal', phraseIndex: 0 });
  assert.deepEqual([refusal.kind, refusal.verdict, refusal.absenceDecided], ['effect.none', 'missing', undefined], 'a refusal is an effect.none: never moves');
});

test('10. the later-outcome stage inherits it: a pass the provider later failed, judged again over a send without the declared field, fails', () => {
  // The pipeline of test/later-outcome-stage.test.mjs: decide, settle, then the stage (no attribution).
  const EXT = 'customers.example', FEED = 'provider-feed-mail', VIP = `vip@${EXT}`;
  const TEMPLATE_SCOPE = { operations: ['send'], names: [EXT], actorAttribution: 'none', evidence: 'authoritative', capture: { [EXT]: ['/template'] } };
  const feedSend = makeEffect({ source: 'provider-feed', observer: { kind: 'provider-feed-reader', instanceId: FEED }, seq: 4096, operation: 'send', name: EXT, resource: VIP, outcome: 'committed',
    captured: { status: 'captured', values: { '/template': { type: 'string', value: 'refund_confirmation' } } } });
  const egressSend = makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST }, seq: 1, operation: 'send', name: EXT, resource: 'POST /mail', outcome: 'committed',
    captured: { status: 'captured', values: { '/template': ABSENT } } });
  const windows = [{ source: 'provider-feed', instanceId: FEED, scope: TEMPLATE_SCOPE, coverage: 'complete', reason: null, events: [feedSend] },
    { source: 'http-egress', instanceId: INST, scope: TEMPLATE_SCOPE, coverage: 'complete', reason: null, events: [egressSend] }];
  const OBSERVERS = [{ id: 'mail', type: 'provider-feed', collector: { label: 'provider-feed/6' }, feed: { feedId: 'mail', keyDigest: '0'.repeat(64), route: 'endpoint', outcomes: { waitMs: 0 } } }];
  const later = [{ instanceId: FEED, clear: true, waitedMs: 0, records: [{ of: feedSend.seq, outcome: 'failed' }] }];
  const stage = absent => {
    const effect = { kind: 'effect.exists', select: { operation: 'send', name: EXT, fields: [{ pointer: '/template', equals: 'refund_confirmation', ...(absent ? { absent: 'fails' } : {}) }] } };
    const raw = decideEffects([effect], windows, { role: 'boundary' });
    const g = [[], []];
    const settled = applySettlement(raw, settlementFindings([{ effects: raw, windows }], g, undefined, { judge: false })[0], 'boundary');
    const lf = laterFindings({ rows: [{ raw, settled, paired: settled, windows, role: 'boundary' }], gaps: g, correlation: undefined, judge: false, attribution: null, readingOf: laterReadings(later, OBSERVERS) });
    return { main: settled[0], staged: applyLater(settled, lf[0])[0] };
  };
  const declared = stage(true);
  assert.equal(declared.main.verdict, 'pass', 'the provider\'s send matched the template');
  assert.deepEqual([declared.staged.verdict, declared.staged.later, absenceFields(declared.staged)], ['fail', 'effect-later-failed', { absenceDecided: true }]);
  const plain = stage(false);
  assert.deepEqual([plain.main.verdict, plain.staged.verdict, plain.staged.later, absenceFields(plain.staged)], ['pass', 'missing', 'effect-later-failed', {}], 'undeclared: missing, as on main');
});

// ---------------------------------------------------------------------------
test('11. property: over 6,000 seeded clauses, main (no declaration) against this branch, a verdict moves only from missing to fail, and only under a declaration', () => {
  let state = 0x65013;
  const rand = n => { state = (state + 0x6d2b79f5) | 0; let t = Math.imul(state ^ (state >>> 15), 1 | state); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) % n; };
  const pick = list => list[rand(list.length)];
  const records = [R65, R65, json(ABSENT), form(ABSENT, ABSENT), MATCH, OTHER, json({ type: 'number', value: 4275 }), json({ type: 'number', value: 1 }), form(text('4275.00')),
    form(text('105.05')), json({ type: 'string', value: '4275' }), form({ type: 'unusable', reason: 'redacted' }), form(ABSENT, { type: 'unusable', reason: 'ambiguous' }), json(QUERY), json(ROOT),
    ...Object.values(UNREADABLE)];
  const pinSets = [[{ pointer: '/amount_cents', equals: 4275 }], [{ pointer: '/amount_cents', in: [4275, 4300] }], [{ pointer: '/amount_cents', gt: 4000 }],
    [{ pointer: '/amount_cents', equals: 4275 }, { pointer: '/amount', equals: '43' }], [{ pointer: '/amount', equals: 43 }]];
  const UPSTREAMS = [{ outcome: 'applied', status: 201, proven: true }, { outcome: 'rejected', status: 409, proven: true }, { outcome: 'unknown', status: null, proven: false }];
  const FORWARD = { [BILL]: { upstreamPort: 4400, proof: false, applied: [200, 201], rejected: [409] } };
  const DECL = validateIdempotencyDeclaration({ header: 'idempotency-key' });
  const actors = [null, 'alice', 'bob', 'unlisted:mallory'];
  const tally = { cases: 0, declared: 0, changed: 0, byKind: {}, bound: 0, keyed: 0, scoped: 0, multi: 0, matchStates: 0, unresolved: 0 };
  for (let i = 0; i < 6000; i++) {
    const actorScoped = rand(4) === 0, keyed = rand(6) === 0, upstream = rand(6) === 0, scopedShape = rand(6) === 0, mode = rand(3);
    const fields = pick(pinSets).map(p => mode === 1 || (mode === 2 && rand(2)) ? { ...p, absent: 'fails' } : { ...p });
    const declared = fields.some(f => f.absent === 'fails');
    const scope = { ...(actorScoped ? ACTOR_SCOPE : SCOPE), names: [BILL, HOOKS], ...(upstream ? { forward: FORWARD } : {}), ...(keyed ? { idempotency: { [BILL]: DECL } } : {}) };
    const firsts = new Map();
    const eventOf = () => {
      const outcome = rand(8) ? 'committed' : pick(['denied', 'error', 'started', 'unknown']);
      const name = rand(10) ? BILL : HOOKS, resource = rand(10) ? REFUND : 'POST /other';
      const u = upstream && rand(2) ? (outcome === 'committed' ? pick(UPSTREAMS) : UPSTREAMS[2]) : undefined;
      const k = keyed && outcome === 'committed' && name === BILL ? pick(['a', 'b']) : null;
      const idem = k ? { idempotency: { status: 'keyed', key: k.repeat(64), fold: k.repeat(64), head: pick(['d', 'e']).repeat(64), firstSeq: firsts.get(k) ?? seq + 1 } } : {};
      const e = send(name === BILL ? pick(records) : undefined, { outcome, name, resource, content: { c: rand(3) }, ...(actorScoped ? { actor: pick(actors) } : {}), ...(u ? { upstream: u } : {}), ...idem });
      if (k && !firsts.has(k)) firsts.set(k, e.seq);
      return e;
    };
    const events = Array.from({ length: rand(5) }, eventOf);
    let main;
    if (scopedShape) {
      const entry = pick([BILL, HOOKS]);
      main = { source: 'http-egress', instanceId: INST, scope, coverage: 'partial', reason: 'egress-request-after-witness-request', events,
        scoped: [{ codes: ['egress-request-after-witness-request'], name: entry, resource: entry === BILL ? REFUND : 'POST /x' }] };
      admitScoped(main); frozen.admitScoped(main);
    } else main = win(events, { coverage: pick(['complete', 'complete', 'complete', 'partial', 'failed', 'net-only']), scope });
    const windows = [main];
    const multi = rand(8) === 0;
    if (multi) windows.push(win(Array.from({ length: rand(3) }, eventOf), { scope, instanceId: 'second' }));
    if (rand(8) === 0) windows.push(win(Array.from({ length: rand(3) }, eventOf), { scope: { ...scope, evidence: 'presence-only' }, instanceId: 'presence' }));
    if (rand(10) === 0) windows.push(blindWindow());
    const kind = keyed ? 'effect.count' : pick(['effect.none', 'effect.exists', 'effect.count']);
    const select = refunds(fields, { ...(actorScoped ? { actor: 'alice' } : {}), ...(upstream ? { upstream: 'applied' } : {}) });
    const clause = { kind, select, ...(kind === 'effect.count' ? { expected: keyed ? 1 + rand(3) : rand(4) } : {}), ...(keyed ? { countBy: 'idempotency-key' } : {}) };
    const opts = { countBy: true, scoped: scopedShape };
    for (const e of windows.flatMap(w => w.events)) {
      const off = matchState(e, select), on = matchState(e, select, { absentFields: true });
      if (off === on) continue;
      assert.deepEqual([off, on], ['unknown', 'no']);
      assert.ok(select.fields.some(f => f.absent === 'fails' && definitelyAbsent(e, f.pointer)));
      tally.matchStates++;
    }
    const now = evaluateEffectAssertion(clause, windows, opts), was = frozen.evaluateEffectAssertion(undeclared(clause), windows, opts);
    tally.cases++; if (declared) tally.declared++;
    if (now.verdict === was.verdict) { assert.deepEqual(now, was, 'an unmoved verdict is main\'s decision, basis included'); continue; }
    const label = `${JSON.stringify(clause)} ${JSON.stringify(windows.map(w => [w.coverage, w.scoped ? 'scoped' : '', w.events.map(e => [e.outcome, e.name, e.actor, e.captured?.status, e.captured?.values?.['/amount_cents']])]))}`;
    // The unresolved-send rule (test/unresolved-send.test.mjs) is the one other move since 39c45ba: a clause that a send whose outcome no
    // observer decided, to the selected destination, could still change reads missing where main passed or failed it (its basis may
    // name an earlier reason the first judgement found).
    const { actor: _a, fields: _f, upstream: _u, ...base } = select;
    if (now.verdict === 'missing' && ['pass', 'fail'].includes(was.verdict)
      && windows.some(w => w.events.some(e => (e.outcome === 'started' || e.outcome === 'unknown') && matchState(e, { ...base, outcome: e.outcome }) === 'match'))) { tally.unresolved++; continue; }
    assert.ok(declared, label);
    assert.deepEqual([was.verdict, now.verdict], ['missing', 'fail'], label);
    assert.notEqual(kind, 'effect.none', label);
    assert.equal(now.absenceDecided, true, label);
    assert.match(now.basis, BASIS, label);
    assert.ok(windows.some(w => w.events.some(e => select.fields.some(f => f.absent === 'fails' && definitelyAbsent(e, f.pointer)))), label);
    tally.changed++;
    tally.byKind[kind] = (tally.byKind[kind] ?? 0) + 1;
    if (/still undecided/.test(now.basis)) tally.bound++;
    if (keyed) tally.keyed++;
    if (scopedShape) tally.scoped++;
    if (multi) tally.multi++;
  }
  console.log(`# differential ${JSON.stringify(tally)}`);
  assert.ok(tally.changed > 50 && tally.byKind['effect.count'] > 0 && tally.byKind['effect.exists'] > 0 && !tally.byKind['effect.none'] && tally.bound > 0 && tally.keyed > 0 && tally.scoped > 0 && tally.matchStates > 0, JSON.stringify(tally));
});

// ---------------------------------------------------------------------------
// End to end: an app sends one refund through a real egress recorder, against a count whose amount_cents pin declares absent "fails".
// The baseline's form body amount=43 lacks the field (R65-012's shape: fail, tagged); a body with a repeated key and a JSON body beside a
// URL query stay inconclusive; the candidate sends amount_cents=4275 (pass). The comparison credits no repair over the tagged fail.
async function refundApp(t, sinkPort, body) {
  const outbound = (host, path, { payload, type = 'application/x-www-form-urlencoded' } = {}) => new Promise(resolve => { const req = request({ host: '127.0.0.1', port: sinkPort, method: payload === undefined ? 'GET' : 'POST', path: `http://${host}${path}`,
    headers: { host, ...(payload === undefined ? {} : { 'content-type': type }) } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(payload); });
  const server = createServer(async (req, res) => {
    const reply = (status, out) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(out)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return reply(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, { user: 'ops' });
    if (url.pathname === '/ping') { await outbound(WITNESS, `/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
    if (url.pathname === '/refund') { await outbound(BILL, `${PATH}${body.query ?? ''}`, body); return reply(200, { ok: true }); }
    reply(404, {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' };
const BODIES = Object.freeze({ baseline: { payload: 'amount=43' }, unreadable: { payload: 'amount=43&amount=44' },
  query: { payload: '{"order":"QTN-6207"}', type: 'application/json', query: '?amount_cents=4275' }, candidate: { payload: 'amount_cents=4275' } });
const runs = t => onFreePorts(1, async port => {
  const body = {};
  const p = profileOf(port, await refundApp(t, port, body), [count(1)]);
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  const watch = watchingBinds(buildObservers);
  const out = { p };
  for (const [key, value] of Object.entries(BODIES)) { for (const k of Object.keys(body)) delete body[k]; Object.assign(body, value); out[key] = await runHttpAssessment(p, { env, observerFactory: watch.factory }); }
  return { ...out, lostBind: watch.state.lostBind };
}, r => r.lostBind);

test('12. end to end: a refund without the declared field fails, unreadable and query bodies stay inconclusive, and no repair is credited over the fail', async t => {
  const r = await runs(t);
  const rowOf = (run, id) => run.results.find(x => x.id === id);
  const clause = run => rowOf(run, 'REFUND').trace[1].data.effects[0];
  const records = run => rowOf(run, 'REFUND').trace[1].data.windows[0].events.filter(e => e.name === BILL).map(e => e.captured);
  assert.deepEqual(records(r.baseline), [R65], 'the recorder captured the whole body: amount present, amount_cents absent');
  assert.deepEqual(records(r.unreadable), [{ status: 'form-duplicate-key', values: {} }]);
  assert.deepEqual(records(r.query), [{ status: 'captured', values: { '/amount': QUERY, '/amount_cents': QUERY } }], 'a JSON body beside a URL query is never absent');
  const keys = ['baseline', 'unreadable', 'query', 'candidate'];
  assert.deepEqual(keys.map(k => clause(r[k]).verdict), ['fail', 'missing', 'missing', 'pass']);
  assert.deepEqual(keys.map(k => clause(r[k]).absenceDecided), [true, undefined, undefined, undefined]);
  assert.deepEqual(keys.map(k => rowOf(r[k], 'REFUND').status), ['fail', 'inconclusive', 'inconclusive', 'pass']);
  assert.equal(rowOf(r.baseline, 'REFUND').assertions.find(a => a.absenceDecided === true)?.status, 'fail', 'the assertion row carries the tag');
  assert.match(JSON.stringify(rowOf(r.baseline, 'REFUND')), BASIS);
  // The saved evidence recomputes to the same verdicts and tags; a tag added or removed by hand is refused.
  const suite = createRegistry({ profiles: [r.p], env }).exportSuite(r.p.id);
  for (const k of keys) validateHttpRunEvidence(r[k], { expectedSuite: suite });
  const stripped = structuredClone(r.baseline);
  delete rowOf(stripped, 'REFUND').trace[1].data.effects[0].absenceDecided;
  assert.throws(() => validateHttpRunEvidence(stripped, { expectedSuite: suite }));
  const forged = structuredClone(r.candidate);
  rowOf(forged, 'REFUND').trace[1].data.effects[0].absenceDecided = true;
  assert.throws(() => validateHttpRunEvidence(forged, { expectedSuite: suite }));
  // No repair is credited over a fail that rests on a declared absence: the receiver's default or an alias could have applied.
  const comparison = compareRuns(r.baseline, r.candidate);
  assert.equal(comparison.compatible, true, JSON.stringify(comparison.reasons));
  assert.deepEqual([comparison.summary.fixed, comparison.summary.unverified], [0, 1], JSON.stringify(comparison.rows));
  assert.deepEqual(comparison.rows.find(x => x.id === 'REFUND'), { id: 'REFUND', title: 'REFUND', before: 'fail', after: 'pass', transition: 'unverified', transitionReason: 'baseline-fail-absent-field' });
  assert.equal(comparison.restorationLabel, NO_VERIFIED_REPAIR);
  assert.ok(comparison.reasons.some(x => /declared field absent from the request body/.test(x)), JSON.stringify(comparison.reasons));
  assert.equal(compareRuns(r.unreadable, r.candidate).summary.fixed, 0, 'a baseline that only abstained credits nothing either');
});
