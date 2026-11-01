// Identity option B (actor-identity/6, src/http-rests-on.mjs): a boundary check that declares restsOn is released from
// control-not-passed only when its listed allowed-use controls showed a served record on its route at another record, every
// failed required control of its actor showed a served record and failed only on positive readings coverage gaps alone left
// missing (or whose pass background attribution withheld), no failed control is related to it, and a listed control was
// sent after it and after every failed control. Injected transport and injected observers only: no socket, no database.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile, IDENTITY_ASSERTION, IDENTITY_REASONS, IDENTITY_UNPROVEN_DECISION, withheldSummary, rowIdentityReason } from '../src/contracts.mjs';
import { failureAdmitted, recordPredicates, restsOnProblem, staticRestsOnRelated, restsOnReleases, routeSegments, sentRoute } from '../src/http-rests-on.mjs';
import { makeEffect, decidedByGaps, evaluateEffectAssertion, otherActorCommit } from '../src/effect-events.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';

const HOST = 'api.ledger.example', env = { SCOPEHAVEN_TARGET_MEMBER: 'tok-member', SCOPEHAVEN_TARGET_OTHER: 'tok-other' };
const TITLE = { I1: 'Alpha ledger', I2: 'Bravo ledger', N3: 'Charlie folder', N4: 'Delta folder', N5: 'Echo folder' };
const sel = extra => ({ source: 'http-egress', operation: 'send', name: HOST, ...extra });
const control = (id, path, extra = {}) => ({ id, title: id, category: 'Allowed use', severity: 'control', actorId: 'member', method: 'GET', path, evidenceRequirement: 'response',
  assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/title', expected: TITLE[id] }], ...extra });
// The member's identity control WHOAMI; two records of /api/invoices read by POST with no body (I1 and I2, partners; not
// surface controls, so they are not re-sent at probe points and a failure of theirs reaches the restsOn rule alone) and two
// of /api/notes (N3 and N4, partners, surface GETs); and the boundary check X, a GET of another note, which rests on N4 (sent
// after it). I1 declares an effect, so it can fail on a reading alone while still serving its record.
const OBSERVED = { effects: [{ kind: 'effect.exists', select: sel({ actor: 'member' }) }] };
function profile({ order = ['WHOAMI', 'I1', 'I2', 'N3', 'X', 'N4'], restsOn = ['N4'], x = {}, i1 = OBSERVED, n3 = {}, extra = [], required = [], actors = {} } = {}) {
  const all = {
    WHOAMI: control('WHOAMI', '/api/me', { assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'member' }] }),
    I1: control('I1', '/api/invoices/1', { method: 'POST', ...i1 }), I2: control('I2', '/api/invoices/2', { method: 'POST' }),
    N3: control('N3', '/api/notes/3', n3), N4: control('N4', '/api/notes/4'),
    X: { id: 'X', title: 'X', category: 'Object access', severity: 'high', actorId: 'member', method: 'GET', path: '/api/notes/9', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 404 }], ...(restsOn ? { restsOn } : {}), ...x },
  };
  return { id: 'rests-app', name: 'Rests app', applicationId: 'rests-app', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { member: { principalId: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member' }, ...actors },
    observers: [{ id: 'gate', type: 'egress-recorder', port: 40998, routing: 'proxy', destinations: [{ host: HOST }], witness: { actorId: 'member', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250, quietMs: 150 }],
    requiredControlIds: ['WHOAMI', 'I1', 'I2', 'N3', 'N4', ...required], checks: [...order.map(id => all[id]), ...extra] };
}
// A fake request-path gate: every window partial (so a positive clause reads missing from the gap alone), its events from
// `events` (a list for every window).
let seq = 0;
const factory = ({ events = [], coverage = 'partial' } = {}) => configs => configs.map(c => {
  const instanceId = `${c.type}-${c.id}`;
  let mark = 0;
  return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope: { operations: ['send'], names: [HOST], actorAttribution: 'principal', evidence: 'authoritative' }, witnessRequest: null,
    async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
    async collect() { return { events: events.map(s => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: ++seq, operation: 'send', name: HOST, outcome: 'committed', ...s })), coverage, reason: coverage === 'complete' ? null : 'synthetic' }; } };
});
// Answers by check id: controls 200 with their record, X 404; state[id] overrides with a status or { status, json }; state.me
// maps the n-th /api/me call with the member's credential to a status (probe points).
function app(state = {}) {
  let me = 0;
  return async (_origin, check, { credential }) => {
    const reply = (status, json = {}) => ({ status, complete: true, jsonParsed: true, json, bytes: 2 });
    if (credential !== 'tok-member') return reply(401);
    if (check.id === 'WHOAMI') { const s = state.me?.[++me]; return s === undefined ? reply(200, { user: 'member' }) : reply(s); }
    const s = state[check.id];
    if (typeof s === 'number') return reply(s);
    if (s && typeof s === 'object') return reply(s.status, s.json);
    return check.severity === 'control' ? reply(200, { title: TITLE[check.id] }) : reply(404);
  };
}
const assess = (p, state, observers) => runHttpAssessment(p, { env, transport: app(state), observerFactory: factory(observers) });
const row = (run, id) => run.results.find(r => r.id === id);
const identityOf = r => r.assertions.find(a => a.name === IDENTITY_ASSERTION)?.actual;
const codeOf = text => text === undefined ? null : Object.keys(IDENTITY_REASONS).find(code => IDENTITY_REASONS[code] === text);
const reading = r => [r.status, r.decision, codeOf(identityOf(r))];
const suiteOf = p => createRegistry({ profiles: [p], env }).exportSuite(p.id);
const reseal = r => { r.evidenceDigest = digest(r.trace.length === 2 ? { evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions } : { evidence: r.trace[0].data, assertions: r.assertions }); };
const RELEASED = ['pass', 'pass', null], WITHHELD = ['inconclusive', IDENTITY_UNPROVEN_DECISION, 'control-not-passed'];

test('the fixture: every listed and failed control has a record predicate and a declared partner', () => {
  const p = profile();
  for (const id of ['I1', 'I2', 'N3', 'N4']) assert.equal(recordPredicates(p.checks.find(c => c.id === id), p).length, 1, id);
  assert.doesNotThrow(() => validateTargetFile({ schemaVersion: 1, targets: [p] }));
  assert.deepEqual([...staticRestsOnRelated(p)], [['X', ['N3', 'N4']]], 'only the notes controls share the check\'s stem keys');
});

test('allowed: a failed control that served its record and failed only on a gap-only positive reading releases a check resting on a later same-route anchor', async () => {
  const p = profile(), run = await assess(p);
  assert.deepEqual(reading(row(run, 'I1')), ['inconclusive', 'inconclusive', null], 'I1 failed on its effect alone (missing over a partial window)');
  assert.deepEqual(reading(row(run, 'X')), RELEASED);
  assert.deepEqual(row(run, 'X').trace[0].data.restsOn, ['N4']);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  // Without the exported suite nothing binds the recorded segments, ranks or ids: a run that rests on a release is refused.
  assert.throws(() => validateHttpRunEvidence(run), e => e.code === 'invalid-run-evidence' && e.detail === 'rests-on-needs-suite');
  // The same profile without restsOn keeps today's actor-wide withholding, and the summary names the failed control.
  const plain = profile({ restsOn: null }), base = await assess(plain);
  assert.deepEqual(reading(row(base, 'X')), WITHHELD);
  assert.equal(row(base, 'X').summary, withheldSummary('control-not-passed', ['I1'], true));
  validateHttpRunEvidence(base, { expectedSuite: suiteOf(plain) }); validateHttpRunEvidence(base);
});

test('forbidden, the failed control: a 500, a failed predicate, another 2xx, a commit under another actor or an unknown one, or no partner keeps control-not-passed', async () => {
  for (const [state, observers, why] of [[{ I1: 500 }, undefined, 'a 500 serves no record'], [{ I1: { status: 200, json: { title: 'Wrong record' } } }, undefined, 'a failed record predicate'],
    [{ I1: { status: 200, json: { title: TITLE.I1, error: 'locked' } } }, undefined, 'an outcome key: no clean object'],
    [{}, { events: [{ actor: 'other' }] }, 'a commit under another principal over the gap'], [{}, { events: [{ actor: null }] }, 'a commit under an unknown actor'],
    [{ I2: { status: 200, json: { title: TITLE.I1 } } }, undefined, 'the partner answered the same value: no served record'], [{ I1: 403 }, undefined, 'refused']]) {
    const p = profile({ actors: { other: { principalId: 'other' } } }), run = await assess(p, state, observers);
    assert.deepEqual(reading(row(run, 'X')), WITHHELD, why);
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  }
  // A failed control whose effect read fail (a complete window and no send) is never admitted.
  const p = profile(), run = await assess(p, {}, { coverage: 'complete' });
  assert.equal(row(run, 'I1').status, 'fail');
  assert.deepEqual(reading(row(run, 'X')), ['inconclusive', IDENTITY_UNPROVEN_DECISION, 'control-not-passed']);
});

test('forbidden, the listed side: a failing anchor, an anchor sent before the check, and a probe point that did not pass', async () => {
  const p = profile();
  assert.notDeepEqual(reading(row(await assess(p, { N4: 500 }), 'X')), RELEASED, 'the anchor failed (a surface GET: its probes fail too)');
  const before = profile({ order: ['WHOAMI', 'I1', 'I2', 'N3', 'N4', 'X'] });
  assert.deepEqual(reading(row(await assess(before), 'X')), WITHHELD, '(d): no listed control after the check');
  const early = profile({ order: ['WHOAMI', 'I2', 'N3', 'X', 'N4', 'I1'] });
  assert.deepEqual(reading(row(await assess(early), 'X')), WITHHELD, '(d): the failed control was sent after the anchor');
  // An identity probe at an inner point answers 500: no control of the actor shows a served record.
  const run = await assess(p, { me: { 4: 500 } });
  assert.notDeepEqual(reading(row(run, 'X')), RELEASED, 'a probe point that did not pass');
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
});

test('forbidden, relation (c): the anchor\'s own partner failing, or a failed control sharing the check\'s route words', async () => {
  // F2 of the check note: N3, the anchor's partner, fails gap-only. It is on the check's route, so it is related.
  const p = profile({ i1: {}, n3: OBSERVED });
  const run = await assess(p);
  assert.equal(row(run, 'N3').status, 'inconclusive');
  assert.deepEqual(reading(row(run, 'X')), WITHHELD);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
});

test('every later step still runs for a released row: an undeclared 401 reads unauthenticated-401', async () => {
  const p = profile({ x: { assertions: [{ kind: 'status.equals', expected: 401 }] } }), run = await assess(p, { X: 401 });
  assert.deepEqual(reading(row(run, 'X')), ['inconclusive', IDENTITY_UNPROVEN_DECISION, 'unauthenticated-401']);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  // Pure: the release only lifts control-not-passed, at its own step.
  const entry = { refusalStatuses: [401, 403], surfaceControlIds: ['N4'], refusesWith401: false, before: [], between: [], after: [] };
  const judge = released => rowIdentityReason({ credentialed: true, required: false, control: false, entry, httpStatus: 403, controlFailed: false, rules: 6, route: 'control-not-passed', points: [[], []], released });
  assert.deepEqual([judge(false), judge(true)], ['control-not-passed', null]);
  assert.equal(rowIdentityReason({ credentialed: true, required: false, control: false, entry, httpStatus: 403, controlFailed: false, rules: 5, route: 'control-not-passed', points: [[], []], released: true }), 'control-not-passed', 'never under rules 5');
  assert.equal(rowIdentityReason({ credentialed: true, required: false, control: false, entry: { ...entry, surfaceControlIds: [] }, httpStatus: 403, controlFailed: false, rules: 6, route: 'control-not-passed', points: [[], []], released: true }), 'surface-unproven');
});

test('the suite binds what a release reads: an edited restsOn, record rank or route segment is refused', async () => {
  const p = profile(), run = await assess(p), suite = suiteOf(p);
  const edited = change => { const copy = structuredClone(run); change(copy); return copy; };
  for (const [change, why] of [[r => { row(r, 'X').trace[0].data.restsOn = ['N3']; reseal(row(r, 'X')); }, 'another restsOn list'],
    [r => { row(r, 'I1').trace[0].data.routeSegments = row(r, 'N3').trace[0].data.routeSegments; reseal(row(r, 'I1')); }, 'a failed control moved onto another route'],
    [r => { const s = row(r, 'N4').trace[0].data.controlScope; s.recordPredicates = [[0, 1, 9]]; reseal(row(r, 'N4')); }, 'another record rank']])
    assert.throws(() => validateHttpRunEvidence(edited(change), { expectedSuite: suite }), e => ['unexpected-suite-evidence', 'invalid-run-evidence'].includes(e.code), why);
  // The rows are the suite's checks in the suite's order (review of B): a row moved after the anchor, or a failed control dropped, is refused.
  const moved = edited(r => { const i = r.results.findIndex(x => x.id === 'X'); r.results.push(...r.results.splice(i, 1)); });
  assert.throws(() => validateHttpRunEvidence(moved, { expectedSuite: suite }), e => ['unexpected-suite-evidence', 'invalid-run-evidence'].includes(e.code), 'a moved row');
  // An order edit nothing else reads (a not-applicable row moved) is refused by the order binding itself.
  const na = profile({ extra: [{ ...control('N5', '/api/notes/5'), applicability: { applies: false, reason: 'Synthetic: not applicable here.' } }] });
  const naRun = await assess(na), naSuite = suiteOf(na);
  validateHttpRunEvidence(naRun, { expectedSuite: naSuite });
  const reordered = structuredClone(naRun); reordered.results.unshift(reordered.results.pop());
  assert.throws(() => validateHttpRunEvidence(reordered, { expectedSuite: naSuite }), e => e.code === 'unexpected-suite-evidence', 'a moved not-applicable row');
  const dropped = edited(r => { r.results = r.results.filter(x => x.id !== 'I1'); });
  assert.throws(() => validateHttpRunEvidence(dropped, { expectedSuite: suite }), e => ['unexpected-suite-evidence', 'invalid-run-evidence'].includes(e.code), 'a dropped failed control');
  // A listed control added that still anchors: the release does not change, so only the suite's restsOn binding refuses it.
  const widened = edited(r => { row(r, 'X').trace[0].data.restsOn = ['N4', 'N3']; reseal(row(r, 'X')); });
  assert.throws(() => validateHttpRunEvidence(widened, { expectedSuite: suite }), e => e.code === 'unexpected-suite-evidence', 'a widened restsOn list');
  // A suite that cannot bind them is a configuration error.
  const bare = structuredClone(suite); delete bare.checks.find(c => c.id === 'X').restsOnRelated;
  assert.throws(() => validateHttpRunEvidence(run, { expectedSuite: bare }), e => e.code === 'unexpected-suite-evidence');
  // A saved actor-identity/5 run never carries the /6 fields.
  const old = edited(r => { r.identityEvidence.schema = 'actor-identity/5'; });
  assert.throws(() => validateHttpRunEvidence(old), e => e.code === 'invalid-run-evidence');
});

test('load (B2): each listed control can anchor the check, beside an accepted neighbour', () => {
  const load = p => validateTargetFile({ schemaVersion: 1, targets: [p] });
  assert.doesNotThrow(() => load(profile()));
  const other = { other: { principalId: 'other', credentialEnv: 'SCOPEHAVEN_TARGET_OTHER', identityValue: 'other' } };
  for (const [p, pattern, why] of [
    [profile({ restsOn: [] }), /1 to 8 distinct/, 'no ids'], [profile({ restsOn: Array(9).fill('N4').map((id, i) => `${id}${i}`) }), /1 to 8 distinct/, 'nine ids'],
    [profile({ restsOn: ['N4', 'N4'] }), /distinct/, 'a repeated id'], [profile({ restsOn: ['WHOAMI'] }), /identity control|another method|record predicate|partner|route/, 'the identity control'],
    [profile({ restsOn: ['I1'] }), /another method/, 'another method and route'], [profile({ restsOn: ['GONE'] }), /not an applicable required control/, 'an unknown id'],
    [profile({ x: { method: 'DELETE' } }), /another method/, 'another method'], [profile({ x: { method: 'POST', body: { op: 'read' } } }), /sends a body/, 'a body on the check'],
    [profile({ x: { path: '/api/notes/9?view=full' } }), /cannot be anchored/, 'a query'], [profile({ x: { path: '/api/notes/4' } }), /not on the check's route at another record/, 'the identical route'],
    [profile({ x: { severity: 'control', assertions: [{ kind: 'status.equals', expected: 200 }] }, required: [] }), /boundary check/, 'a control'],
    [profile({ extra: [{ ...control('N5', '/api/notes/5'), actorId: 'other', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/title', expected: TITLE.N5 }] }], restsOn: ['N5'], required: ['N5'], actors: other }), /another actor|not an applicable/, 'another actor\'s control'],
    [profile({ extra: [control('N5', '/api/notes/5')], restsOn: ['N5'] }), /not an applicable required control/, 'a control that is not required']])
    assert.throws(() => load(p), e => pattern.test(e.message), `${why}: ${(() => { try { load(p); return 'accepted'; } catch (e) { return e.message; } })()}`);
  // A listed control without a partner (the only record of its route) can never show a served record.
  const lone = profile({ order: ['WHOAMI', 'I1', 'I2', 'X', 'N4'], restsOn: ['N4'] }); lone.requiredControlIds = lone.requiredControlIds.filter(id => id !== 'N3');
  assert.throws(() => load(lone), /no declared partner/);
  // Only a credentialed actor's check rests on controls (check note F4).
  const anon = profile({ x: { actorId: 'guest' }, actors: { guest: { principalId: 'guest' } } });
  assert.throws(() => load(anon), /credentialed/);
});

test('failureAdmitted (B4(b)(ii) and (iv)): only gap-only positive readings and attribution-withheld positive passes, with no commit under another actor', () => {
  const scope = { operations: ['send'], names: [HOST], actorAttribution: 'principal', evidence: 'authoritative' };
  const ev = (actor, n = 1) => makeEffect({ source: 'http-egress', observer: { kind: 'test', instanceId: 'g' }, seq: n, operation: 'send', name: HOST, actor, outcome: 'committed' });
  const win = (coverage, events = []) => [{ source: 'http-egress', instanceId: 'g', scope, coverage, reason: coverage === 'complete' ? null : 'synthetic', events }];
  const exists = { kind: 'effect.exists', select: sel({ actor: 'member' }) };
  const rowOf = (decision, assertions = [{ name: 'Observed effect 1 (effect.exists)', status: 'inconclusive' }], claims) => ({ assertions: [{ name: 'HTTP status matches contract', status: 'pass' }, ...assertions],
    trace: [{}, { data: { effects: [{ ...exists, ...decision }], ...(claims ? { claims } : {}) } }] });
  // Gap-only missing: admitted; the same reading recomputed from a complete window (fail) or from an unknown actor (unattributed) is not.
  assert.equal(failureAdmitted(rowOf({ verdict: 'missing' }), win('partial'), 'member'), true);
  assert.equal(decidedByGaps(evaluateEffectAssertion(exists, win('partial'))), true);
  assert.equal(failureAdmitted(rowOf({ verdict: 'missing' }), win('complete'), 'member'), false, 'the recompute reads fail');
  assert.equal(failureAdmitted(rowOf({ verdict: 'missing' }), win('partial', [ev(null)]), 'member'), false, 'unattributed, not a gap');
  assert.equal(failureAdmitted(rowOf({ verdict: 'missing' }), win('partial', [ev('other')]), 'member'), false, 'a commit under another principal');
  assert.equal(otherActorCommit(exists, win('partial', [ev('member')]), 'member'), false);
  assert.equal(failureAdmitted(rowOf({ verdict: 'observer-failure' }), win('failed'), 'member'), true, 'observer-failure from a failed window');
  // An attribution-withheld positive pass: admitted, unless another actor committed a matching send too (check note F7).
  assert.equal(failureAdmitted(rowOf({ verdict: 'inconclusive', attribution: 'background-overlap' }), win('complete', [ev('member')]), 'member'), true);
  assert.equal(failureAdmitted(rowOf({ verdict: 'inconclusive', attribution: 'background-overlap' }), win('complete', [ev('member'), ev('other', 2)]), 'member'), false, 'F7');
  assert.equal(failureAdmitted(rowOf({ verdict: 'inconclusive' }), win('complete', [ev('member')]), 'member'), false, 'inconclusive without an attribution tag');
  assert.equal(failureAdmitted(rowOf({ verdict: 'missing', settlement: 'effect-outside-window' }), win('partial'), 'member'), false, 'a settlement tag');
  assert.equal(failureAdmitted(rowOf({ verdict: 'missing', attribution: 'x' }), win('partial'), 'member'), false, 'a tag on a gap reading');
  // Not positive: an absence, a count of zero, a fail, unobservable; and any other failed assertion.
  for (const decision of [{ kind: 'effect.none', verdict: 'missing' }, { kind: 'effect.count', expected: 0, verdict: 'missing' }, { verdict: 'fail' }, { verdict: 'unobservable' }])
    assert.equal(failureAdmitted(rowOf(decision), win('partial'), 'member'), false, JSON.stringify(decision));
  assert.equal(failureAdmitted(rowOf({ kind: 'effect.count', expected: 2, verdict: 'missing' }), win('partial'), 'member'), true, 'a count of at least one');
  assert.equal(failureAdmitted(rowOf({ verdict: 'missing' }, [{ name: 'json.equals predicate 1', status: 'fail' }]), win('partial'), 'member'), false, 'a failed predicate');
  assert.equal(failureAdmitted(rowOf({ verdict: 'missing' }, [{ name: 'Trusted backend observation available', status: 'inconclusive' }]), win('partial'), 'member'), false, 'a backend assertion');
  // Claims: only a success reading over a gap; refusal, ambiguous, unreadable and untriggered readings never.
  const claim = reading => ({ trigger: { field: '/applied' }, select: sel({ actor: 'member' }), reading, clause: reading === 'success' ? 'effect.exists' : reading === 'refusal' ? 'effect.none' : null, verdict: reading === 'success' || reading === 'refusal' ? 'missing' : 'inconclusive', matched: 0 });
  const withClaim = reading => rowOf({ verdict: 'pass' }, [{ name: 'Observed effect 1 (effect.exists)', status: 'pass' }, { name: `Observed claim 1 (${reading})`, status: 'inconclusive' }], [claim(reading)]);
  assert.equal(failureAdmitted(withClaim('success'), win('partial'), 'member'), true);
  for (const r of ['refusal', 'ambiguous', 'unreadable', 'untriggered']) assert.equal(failureAdmitted(withClaim(r), win('partial'), 'member'), false, r);
  assert.equal(failureAdmitted(rowOf({ verdict: 'missing' }), null, 'member'), false, 'no windows');
  assert.equal(failureAdmitted(rowOf({ verdict: 'missing' }), win('partial'), undefined), false, 'no principal');
});

test('restsOnProblem refuses a declaration on a lifecycle post-change check', () => {
  const p = profile();
  assert.match(restsOnProblem(p.checks.find(c => c.id === 'X'), p, { postChange: true }), /post-change/);
  assert.equal(restsOnProblem(p.checks.find(c => c.id === 'X'), p, { identityIds: ['WHOAMI'] }), null);
});

test('restsOnReleases (pure): each condition of (a) and (c) alone keeps the row withheld', () => {
  const key = 'k', seg = path => routeSegments(path, key);
  const base = (id, path, index, extra = {}) => ({ id, index, actorId: 'member', severity: 'control', required: true, failed: false, method: 'POST', httpStatus: 200, transportOutcome: 'complete', jsonParsed: true,
    routeSegments: seg(path), sentRoute: sentRoute(path, key), effects: [], claims: [], captureUses: undefined, accepts: [200], recordDeclared: true, cleanObject: true, bodyKeys: 'keys', identityProven: true,
    credentialed: true, restsOn: null, untagged: true, successOnly: true, admitted: false, ...extra });
  const rows = over => [
    base('I1', '/api/invoices/1', 0, { failed: true, admitted: true, recordRanks: [[0, 1]], recordPassed: [[0, 1]], ...over.I1 }),
    base('I2', '/api/invoices/2', 1, { recordRanks: [[0, 2]], recordPassed: [[0, 2]], ...over.I2 }),
    base('N3', '/api/notes/3', 2, { recordRanks: [[0, 3]], recordPassed: [[0, 3]], ...over.N3 }),
    base('X', '/api/notes/9', 3, { severity: 'high', required: false, accepts: [404], httpStatus: 404, recordDeclared: false, recordRanks: [], recordPassed: [], cleanObject: false, bodyKeys: null, identityProven: false, restsOn: ['N4'], ...over.X }),
    base('N4', '/api/notes/4', 4, { recordRanks: [[0, 4]], recordPassed: [[0, 4]], ...over.N4 })];
  const released = (over = {}) => restsOnReleases({ rows: rows(over), refusalStatuses: new Map([['member', [401, 403]]]), principals: { member: 'member' } }).has('X');
  assert.equal(released(), true, 'the adjacent allowed case');
  for (const [over, why] of [[{ N4: { failed: true } }, 'the anchor failed'], [{ N4: { bodyKeys: 'other' } }, 'the anchor served no record (its partner answered other keys)'],
    [{ N4: { untagged: false } }, 'a tagged anchor'], [{ N4: { successOnly: false } }, 'an anchor with a refusal claim reading'], [{ N4: { method: 'GET' } }, 'an anchor with another method'],
    [{ N4: { sentRoute: sentRoute('/api/notes/9', key) } }, 'an anchor sent to the check\'s own record'], [{ N4: { identityProven: false } }, 'an anchor whose identity was not proven at every point'],
    [{ I1: { admitted: false } }, '(b) a failure outside the allowlist'], [{ I1: { cleanObject: false } }, '(b) a failed control that served no record'], [{ X: { credentialed: false } }, 'an uncredentialed check'],
    [{ X: { effects: [{ kind: 'effect.none', select: { source: 'http-egress', name: 'ledger.example' } }] }, I1: { effects: [{ kind: 'effect.exists', select: { source: 'http-egress', name: 'ledger.example' } }] } }, '(c) a shared selector name'],
    [{ X: { claims: [{ source: 'http-egress', name: 'ledger.example' }] }, I1: { effects: [{ kind: 'effect.exists', select: { source: 'http-egress', name: 'ledger.example' } }] } }, '(c) a claim rule of the check'],
    [{ X: { effects: [{ kind: 'effect.only', expect: [] }] }, I1: { effects: [{ kind: 'effect.exists', select: { source: 'http-egress', name: 'other.example' } }] } }, '(c) an effect.only clause of the check'],
    [{ X: { captureUses: [{ name: 'inv', captureCheckId: 'I1' }] } }, '(c) a value the failed control created'], [{ X: { restsOn: ['N4', 'GONE'] } }, 'a listed id the run does not hold']])
    assert.equal(released(over), false, why);
  assert.equal(released({ X: { effects: [{ kind: 'effect.none', select: { source: 'http-egress', name: 'ledger.example' } }] }, I1: { effects: [{ kind: 'effect.exists', select: { source: 'http-egress', name: 'other.example' } }] } }), true, 'another selector name: not related');
});

test('failureAdmitted: a missing reading that coverage gaps did not decide (two authoritative counters) is not admitted', () => {
  const scope = { operations: ['send'], names: [HOST], actorAttribution: 'principal', evidence: 'authoritative' };
  const win = id => ({ source: 'http-egress', instanceId: id, scope, coverage: 'complete', reason: null, events: [] });
  const count = { kind: 'effect.count', select: sel({ actor: 'member' }), expected: 1 };
  const raw = evaluateEffectAssertion(count, [win('a'), win('b')]);
  assert.deepEqual([raw.verdict, decidedByGaps(raw)], ['missing', false]);
  const r = { assertions: [{ name: 'Observed effect 1 (effect.count)', status: 'inconclusive' }], trace: [{}, { data: { effects: [{ ...count, verdict: 'missing', matched: 0 }] } }] };
  assert.equal(failureAdmitted(r, [win('a'), win('b')], 'member'), false);
});
