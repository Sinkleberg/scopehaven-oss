// JSON body fields: a string value against a pinned string decided "no" by exact text, so "105.50" against "105.5" read as another
// refund, and an `in` member of another type was set aside, so "105.50" against in [105.5, "105.5"] read "no" too. A receiver that reads
// the string as a number (or trims it) takes both as one value: an effect.none passed on the forbidden refund, an effect.count counted
// one refund where two were sent, and an effect.only expect beside a fields-free allow absorbed the second refund. JSON strings now
// follow the form text rule (src/body-fields.mjs stringState, widened by the fail-open review to respelled numbers inside text, case
// and NFKC folds, and boolean or null words), and an `in` member of another type reads unknown unless no reading makes it equal
// (crossState). Checked: field states against main's frozen body-fields (5c3b3f6), where only "no" -> "unknown" moves; clause
// decisions over synthetic windows; the "could fit" readers the review named (settlement's control rule, fixed; attribution's
// returned-id seeds, kept); and one connector run over real loopback HTTP (destination hosts are names only and are never resolved
// or contacted).
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { fieldState } from '../src/body-fields.mjs';
import { makeEffect, matchState } from '../src/effect-events.mjs';
import { decideEffects } from '../src/http-effects.mjs';
import { fitsSelector, settlementFindings, applySettlement } from '../src/http-settlement.mjs';
import { attributionFindings } from '../src/http-attribution.mjs';
import { createHash } from 'node:crypto';
import { onFreePorts, watchingBinds } from '../integrations/observers/fixtures/free-port.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';

// main before this change: JSON strings compared by exact text, `in` members of another type set aside.
const frozen = await import(fileURLToPath(new URL('./fixtures/body-fields-5c3b3f6.mjs', import.meta.url)));

const BILL = 'billing.example.test', INST = 'egress-recorder-sink', REFUND = 'POST /v1/refunds', CREDIT = 'POST /v1/credits';
const SCOPE = Object.freeze({ operations: ['send'], names: [BILL], actorAttribution: 'none', evidence: 'authoritative', capture: { [BILL]: ['/amount'] } });
const stored = v => (v === null ? { type: 'null', value: null } : { type: typeof v, value: v });
const json = v => ({ status: 'captured', values: { '/amount': stored(v) } });
const form = t => ({ status: 'captured', values: { '/amount': { type: 'text', value: t } } });
const pin = (op, x) => ({ pointer: '/amount', [op]: x });
const both = (captured, entry) => [frozen.fieldState(captured, entry), fieldState(captured, entry)];
let seq = 0;
const refund = amount => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST }, seq: ++seq, observedAt: '2026-10-14T00:00:00.000Z',
  operation: 'send', name: BILL, resource: REFUND, outcome: 'committed', captured: json(amount) });
const win = events => ({ source: 'http-egress', instanceId: INST, scope: SCOPE, coverage: 'complete', reason: null, events });
const refunds = (fields, resource = REFUND) => ({ source: 'http-egress', operation: 'send', name: BILL, resource, ...(fields ? { fields } : {}) });
const verdictOf = (clause, amounts) => decideEffects([clause], [win(amounts.map(refund))])[0].verdict;

// ---------------------------------------------------------------------------
test('1. a string against a pinned string reads "no" only where no common reading makes them one value: respellings, folds and value words stay unknown', () => {
  const rows = [
    ['105.50', '105.5', 'no', 'unknown'], ['1e2', '100', 'no', 'unknown'], ['0100', '100', 'no', 'unknown'], ['+100', '100', 'no', 'unknown'], ['100.0', '100', 'no', 'unknown'],
    ['1,050', '1050', 'no', 'unknown'], ['5 USD', '5', 'no', 'unknown'], ['25abc', '25', 'no', 'unknown'], ['refund ', 'refund', 'no', 'unknown'], ['re\u0000fund', 'refund', 'no', 'unknown'],
    ['\uff11\uff10\uff10', '100', 'no', 'unknown'], ['refund', ' refund', 'no', 'unknown'],
    // A number inside text, respelled (a money or unit string, a date): the shapes agree and no digit run differs under every reading.
    ['105.50 USD', '105.5 USD', 'no', 'unknown'], ['$105.50', '$105.5', 'no', 'unknown'], ['USD 5.00', 'USD 5', 'no', 'unknown'], ['5.0%', '5%', 'no', 'unknown'],
    ['2024-10-05', '2024-10-5', 'no', 'unknown'], ['ORD-0001', 'ORD-1', 'no', 'unknown'], ['T-010', 'T-8', 'no', 'unknown'], ['12345678901234567x', '12345678901234568x', 'no', 'unknown'],
    // Equal under case or NFKC folding, or words of one boolean or null.
    ['Cancel', 'cancel', 'no', 'unknown'], ['REFUND', 'refund', 'no', 'unknown'], ['\uff52\uff45\uff46\uff55\uff4e\uff44', 'refund', 'no', 'unknown'], ['True', 'true', 'no', 'unknown'],
    ['yes', 'true', 'no', 'unknown'], ['on', 'true', 'no', 'unknown'], ['None', 'null', 'no', 'unknown'], ['no', 'false', 'no', 'unknown'],
    // Decided as before: both plain integers of different value, words, other shapes, or a digit run that differs under every reading.
    ['300', '250', 'no', 'no'], [' 300', '250', 'no', 'unknown'], ['cancel', 'refund', 'no', 'no'], ['cad', 'usd', 'no', 'no'], ['yes', 'false', 'no', 'no'], ['2024-0001', '2024-0002', 'no', 'no'],
    ['T-7', 'T-8', 'no', 'no'], ['order-123', 'order-124', 'no', 'no'], ['A1B2', 'A1B3', 'no', 'no'], ['ORD-7', 'INV-8', 'no', 'no'], ['5 USD', '5 EUR', 'no', 'no'], ['105.5', '105.5', 'match', 'match'],
  ];
  for (const [value, operand, was, now] of rows) assert.deepEqual(both(json(value), pin('equals', operand)), [was, now], `${JSON.stringify(value)} vs ${JSON.stringify(operand)}`);
  // One rule for both encodings: a JSON string and the same form text read alike against every string operand.
  const texts = ['105.50', '105.5', '1e2', '100', '0100', '+100', '-0', '1,050', '1.050', '5 USD', '5.00 USD', 'refund', 'refund ', 'Refund', 'cad', '', 'x', '25abc', '2024-0001', '2024-0002',
    '0x10', '1_000', 'true', 'Yes', 'T-7', 'T-08'];
  for (const t of texts) for (const x of texts) for (const entry of [pin('equals', x), pin('in', [x, 'zzz'])]) assert.equal(fieldState(json(t), entry), fieldState(form(t), entry), `${t} vs ${x}`);
  // A type that does not fit stays unknown under equals, as before: the string "250" never equals the number 250.
  assert.deepEqual(both(json('250'), pin('equals', 250)), ['unknown', 'unknown']);
  assert.deepEqual(both(json(250), pin('equals', '250')), ['unknown', 'unknown']);
});

test('2. in: a member of another type reads unknown, unless it is a string beside a number that no reading makes equal', () => {
  const rows = [
    // The fail-opens: a number member beside a numeric-looking string, a string member beside a number, a boolean beside a string.
    ['105.50', [105.5, '105.5'], 'no', 'unknown'], [105.5, ['105.50', 7], 'no', 'unknown'], ['105.5', [105.5, 'abc'], 'no', 'unknown'], ['5 USD', [5, 'x'], 'no', 'unknown'],
    ['', [0, 'x'], 'no', 'unknown'], [false, [true, 'false'], 'no', 'unknown'], ['true', [true, 'x'], 'no', 'unknown'], [1, [true, 7], 'no', 'unknown'], [null, ['', 7], 'unknown', 'unknown'],
    // A word beside 0 or 1: a lax receiver reads "abc" as 0 (Ruby, PHP before 8, MySQL) and "true" as 1.
    ['abc', [0, 'x'], 'no', 'unknown'], ['true', [1, 'x'], 'no', 'unknown'], [' ', [0, 'x'], 'no', 'unknown'], ['', [5, 'x'], 'no', 'no'],
    // Set aside as before: a plain integer of another value, or a string with no digit beside another number; the other members decide.
    ['300', [250, '250'], 'no', 'no'], [30, [25, '25'], 'no', 'no'], ['abc', [5, 'x'], 'no', 'no'], [5, ['usd', 7], 'no', 'no'],
    // Matches and all-set-aside lists, as before.
    ['105.5', [105.5, '105.5'], 'match', 'match'], [105.5, [105.5, '105.5'], 'match', 'match'], [null, [null, 5], 'match', 'match'], [25, ['x'], 'unknown', 'unknown'], ['250', [251], 'unknown', 'unknown'],
    ['250', [250], 'unknown', 'unknown'],
  ];
  for (const [value, operand, was, now] of rows) assert.deepEqual(both(json(value), pin('in', operand)), [was, now], `${JSON.stringify(value)} in ${JSON.stringify(operand)}`);
});

test('3. differential against 5c3b3f6: a field state moves only from "no" to "unknown", JSON and form alike; numbers and labels are unchanged', () => {
  // A seeded corpus of stored values against equals and in operands of every scalar type.
  let s = 0x5c3b3f6;
  const rand = n => { s = (s * 1103515245 + 12345) % 2147483648; return s % n; };
  const strings = ['105.5', '105.50', '105.05', '41.5', '14.5', '100', '0100', '+100', '-100', '1e2', '1,050', '1.050', '5 USD', '5.00 USD', '$5', '$5.0', '25abc', '', ' ', 'refund', 'refund ',
    'Refund', 'REFUND', 'cad', 'usd', 'true', 'True', 'yes', 'false', 'null', 'None', 'order_cancelled', 'ticket_update', '0x10', '1_000', '\uff11\uff10\uff10', '2024-0001', '2024-0002',
    '2024-10-05', '2024-10-5', 'T-7', 'T-8', 'x'];
  const numbers = [0, 1, 5, 7, 25, 100, 105.5, 250, 300, -100, 1050, 10550];
  const scalars = [...strings, ...numbers, true, false, null];
  const pick = list => list[rand(list.length)];
  const tally = { pairs: 0, changed: 0, byType: {} };
  for (let i = 0; i < 6000; i++) {
    const value = pick(scalars), entry = rand(2) ? pin('equals', pick(scalars)) : pin('in', Array.from({ length: 1 + rand(3) }, () => pick(scalars)));
    const [was, now] = both(json(value), entry);
    tally.pairs++;
    if (was === now) continue;
    assert.deepEqual([was, now], ['no', 'unknown'], `${JSON.stringify(value)} ${JSON.stringify(entry)}`);
    tally.changed++;
    tally.byType[typeof value] = (tally.byType[typeof value] ?? 0) + 1;
  }
  // Form text shares the string rule, so it moves the same way and only that way; JSON numbers against numbers, ranges and
  // provider-feed template labels read exactly as before.
  let formChanged = 0;
  for (const t of strings) for (const x of scalars) for (const op of ['equals', 'in']) {
    const entry = pin(op, op === 'in' ? [x] : x), was = frozen.fieldState(form(t), entry), now = fieldState(form(t), entry);
    if (was !== now) { formChanged++; assert.ok(was === 'no' && now === 'unknown', `form ${JSON.stringify(t)} ${op} ${JSON.stringify(x)}: ${was} -> ${now}`); }
  }
  assert.ok(formChanged > 0);
  for (const v of numbers) for (const x of numbers) for (const op of ['equals', 'gt', 'gte', 'lt', 'lte']) { const [was, now] = both(json(v), pin(op, x)); assert.equal(now, was, `${v} ${op} ${x}`); }
  const label = l => ({ status: 'captured', values: { '/template': { type: 'string', value: l } } });
  for (const a of ['order_cancelled', 'ticket_update', 'refund.v2']) for (const b of ['order_cancelled', 'ticket_update', 'refund.v2']) {
    const entry = { pointer: '/template', in: [b] };
    assert.equal(fieldState(label(a), entry), frozen.fieldState(label(a), entry));
  }
  console.log(`# differential ${JSON.stringify(tally)}`);
  assert.ok(tally.changed > 300 && tally.byType.string > 0 && tally.byType.number > 0, JSON.stringify(tally));
});

test('4. clauses: a refund respelled "105.50" no longer passes effect.none, fills an exact count or is absorbed by an effect.only allow', () => {
  const SPELLED = [{ pointer: '/amount', equals: '105.5' }], LISTED = [{ pointer: '/amount', in: [105.5, '105.5'] }];
  // main read the respelled refund "no" under both pins, the reading every verdict below rested on.
  for (const fields of [SPELLED, LISTED]) assert.deepEqual(both(json('105.50'), fields[0]), ['no', 'unknown']);
  for (const fields of [SPELLED, LISTED]) {
    // effect.none: main passed (nothing matched, nothing undecided); now missing.
    assert.equal(verdictOf({ kind: 'effect.none', select: refunds(fields) }, ['105.50']), 'missing');
    // effect.count of one: main counted one of two refunds (pass); now missing.
    assert.equal(verdictOf({ kind: 'effect.count', select: refunds(fields), expected: 1 }, ['105.5', '105.50']), 'missing');
    // effect.exists: main failed (absence); now missing.
    assert.equal(verdictOf({ kind: 'effect.exists', select: refunds(fields) }, ['105.50']), 'missing');
    // effect.only, one expected refund beside a fields-free allow: main absorbed the second refund (pass); now it is undecided.
    const only = { kind: 'effect.only', expect: [{ select: refunds(fields), count: 1 }], allow: [refunds()], sources: ['http-egress'] };
    assert.equal(verdictOf(only, ['105.5', '105.50']), 'missing');
    assert.equal(verdictOf(only, ['105.5', '105.5']), 'fail', 'two exact refunds: beyond count, never absorbed');
    assert.equal(verdictOf(only, ['105.5']), 'pass');
  }
  // The decided twins: what a "no" gives in the same clauses, and still gives where both amounts read as plain integers.
  const INT = [{ pointer: '/amount', equals: '105' }];
  assert.equal(verdictOf({ kind: 'effect.none', select: refunds(INT) }, ['300']), 'pass');
  assert.equal(verdictOf({ kind: 'effect.count', select: refunds(INT), expected: 1 }, ['105', '300']), 'pass');
  assert.equal(verdictOf({ kind: 'effect.exists', select: refunds(INT) }, ['300']), 'fail');
  assert.equal(verdictOf({ kind: 'effect.only', expect: [{ select: refunds(INT), count: 1 }], allow: [refunds()], sources: ['http-egress'] }, ['105', '300']), 'pass');
  // A JSON number beside a string member: main read 105.5 "no" against in ["105.50", 7] and passed the effect.none.
  const NUMBER = [{ pointer: '/amount', in: ['105.50', 7] }];
  assert.deepEqual(both(json(105.5), NUMBER[0]), ['no', 'unknown']);
  assert.equal(verdictOf({ kind: 'effect.none', select: refunds(NUMBER) }, [105.5]), 'missing');
  // The "could be" readers take the respelled refund as fitting: settlement's late-effect test and matchState.
  assert.equal(fitsSelector(refund('105.50'), refunds(SPELLED)), true);
  assert.equal(matchState(refund('105.50'), refunds(SPELLED)), 'unknown');
  assert.equal(fitsSelector(refund('300'), refunds(INT)), false);
});

// ---------------------------------------------------------------------------
// Readers of "could fit" (fail-open review of this change). A send that now fits a selector it read "no" under before can only add
// withholding, with two exceptions found and handled here: settlement's control rule (fixed: another check's token is read first)
// and attribution's returned-id seeds (kept: the attribution design's inclusive rule, now applied to a respelled value as it already
// was to an unreadable one).
const PAY = 'payments.example.test', TOKEN = k => String(k + 1).padStart(32, 'a');
const PAY_SCOPE = Object.freeze({ operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative', capture: { [PAY]: ['/amount'] } });
const paySend = (amount, token) => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST }, seq: ++seq, observedAt: '2026-10-14T00:00:00.000Z',
  operation: 'send', name: PAY, resource: 'POST /v1', outcome: 'committed', correlation: { settlementToken: token }, captured: json(amount) });
const payWin = events => ({ source: 'http-egress', instanceId: INST, scope: PAY_SCOPE, coverage: 'complete', reason: null, events });
const payPinned = amount => ({ source: 'http-egress', operation: 'send', name: PAY, fields: [{ pointer: '/amount', equals: amount }] });

test('5. settlement: a control\'s positive pass resting on another check\'s token is withheld even when a tag-only reason also applies', () => {
  const correlation = { mode: 'run', tokens: new Map([[TOKEN(0), 0], [TOKEN(1), 1]]), declared: new Set([`${INST}\n${PAY}`]) };
  const settle = (rows, gaps, role) => applySettlement(rows[1].effects, settlementFindings(rows, gaps, correlation)[1], role)[0];
  // Row 1 is an allowed-use control whose positive pass rests on a send carrying row 0's token. Row 0 pins the amount respelled ("100.00"),
  // so the send now also fits row 0's selector (effect-ambiguous-attribution, a tag on a control); row 0 pinning "250" is the control.
  for (const earlier of ['100.00', '250']) {
    const rows = [{ effects: [{ kind: 'effect.exists', select: payPinned(earlier), verdict: 'fail', matched: 0 }], windows: [payWin([])] },
      { effects: [{ kind: 'effect.exists', select: payPinned('100'), verdict: 'pass', matched: 1, basis: 'b' }], windows: [payWin([paySend('100', TOKEN(0))])] }];
    const control = settle(rows, [[], [], []], 'control');
    assert.deepEqual([control.verdict, control.settlement], ['inconclusive', 'effect-correlated-elsewhere'], earlier);
    assert.equal(settle(rows, [[], [], []], 'boundary').verdict, 'inconclusive');
  }
  // An effect.count control whose counted send carries row 0's token, with a late own-token send respelled (late-unsettled, a tag).
  const rows = [{ effects: [{ kind: 'effect.exists', select: payPinned('250'), verdict: 'fail', matched: 0 }], windows: [payWin([])] },
    { effects: [{ kind: 'effect.count', select: payPinned('100'), expected: 1, verdict: 'pass', matched: 1, basis: 'b' }], windows: [payWin([paySend('100', TOKEN(0))])] }];
  const late = settle(rows, [[], [], [payWin([paySend('100.00', TOKEN(1))])]], 'control');
  assert.deepEqual([late.verdict, late.settlement], ['inconclusive', 'effect-correlated-elsewhere']);
  // Its own token on the counted send: the late respelled send only tags the control, as before.
  const own = [rows[0], { ...rows[1], windows: [payWin([paySend('100', TOKEN(1))])] }];
  const tagged = settle(own, [[], [], [payWin([paySend('100.00', TOKEN(1))])]], 'control');
  assert.deepEqual([tagged.verdict, tagged.settlement], ['pass', 'effect-correlated-late-unsettled']);
});

test('6. attribution: a respelled own-token send seeds returned-id ownership as an unreadable one does; a decided difference does not', () => {
  const HOOKS = 'hooks.example.test', A = createHash('sha256').update('A').digest('hex');
  const ENTRY = { upstreamPort: 47002, applied: [200, 201, 204], rejected: [402], proof: true, proofVersion: 2, ids: { minted: ['/id'], references: ['/object'] } };
  const scope = { operations: ['send'], names: [PAY, HOOKS], actorAttribution: 'none', evidence: 'authoritative', forward: { [PAY]: ENTRY, [HOOKS]: ENTRY }, capture: { [PAY]: ['/amount'] } };
  const send = (name, extra) => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST }, seq: ++seq, observedAt: '2026-10-14T00:00:00.000Z',
    operation: 'send', name, resource: 'POST /v1', outcome: 'committed', content: { n: seq }, ...extra });
  const findingFor = captured => {
    const charge = send(PAY, { correlation: { settlementToken: TOKEN(0) }, captured, upstream: { outcome: 'applied', status: 201, proven: true, minted: [A] } });
    const notify = send(HOOKS, { correlation: {}, upstream: { outcome: 'applied', status: 201, proven: true, references: [A] } });
    const effects = [{ kind: 'effect.exists', select: { ...payPinned('100'), source: 'http-egress' }, verdict: 'missing', matched: 0 },
      { kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: HOOKS }, verdict: 'pass', matched: 1 }];
    const window = { source: 'http-egress', instanceId: INST, scope, coverage: 'complete', reason: null, events: [charge, notify] };
    return attributionFindings([{ effects, windows: [window] }], [[], []], undefined, { background: [{ id: 'sync', select: { operation: 'send', name: HOOKS } }], tokens: new Map([[TOKEN(0), 0]]) })[0][1];
  };
  // The background notification refers to the object the own-token charge created: it is the check's own when the charge fits.
  assert.equal(findingFor(json('100')), null);
  assert.equal(findingFor({ status: 'captured', values: { '/amount': { type: 'absent' } } }), null, 'main already seeds on an unreadable field');
  assert.equal(findingFor(json('100.00')), null, 'a respelled amount now reads like an unreadable one');
  assert.equal(findingFor(json('99')), 'background-unattributed', 'a decided difference never seeds');
});

// ---------------------------------------------------------------------------
// End to end: an app sends refunds through a real egress recorder as JSON. A second refund respelled "105.50" is undecided under an
// effect.only and an exact count (main: both passed, reading it "no"); one exact credit passes its count; the validator agrees.
async function refundApp(t, sinkPort) {
  const outbound = (host, path, body) => new Promise(resolve => { const req = request({ host: '127.0.0.1', port: sinkPort, method: body === undefined ? 'GET' : 'POST', path: `http://${host}${path}`,
    headers: { host, ...(body === undefined ? {} : { 'content-type': 'application/json' }) } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(body); });
  const sends = { '/refund/twice': ['/v1/refunds', '105.5', '105.50'], '/refund/count': ['/v1/refunds', '105.5', '105.50'], '/credit/exact': ['/v1/credits', '105.5'] };
  const server = createServer(async (req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return reply(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, { user: 'ops' });
    if (url.pathname === '/ping') { await outbound(WITNESS, `/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
    if (Object.hasOwn(sends, url.pathname)) { const [path, ...amounts] = sends[url.pathname]; for (const amount of amounts) await outbound(BILL, path, JSON.stringify({ amount })); return reply(200, { ok: true }); }
    reply(404, {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const WITNESS = 'witness.scopehaven.invalid';
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' };
const SPELLED_FIELDS = Object.freeze([{ pointer: '/amount', equals: '105.5' }]);
const ONLY = { kind: 'effect.only', expect: [{ select: refunds(SPELLED_FIELDS), count: 1 }], allow: [refunds()], sources: ['http-egress'] };
const COUNT = { kind: 'effect.count', select: refunds(SPELLED_FIELDS), expected: 1 };
// The passing check credits on its own path, so no earlier check's selector could claim its send (settlement).
const CREDIT_COUNT = { kind: 'effect.count', select: refunds(SPELLED_FIELDS, CREDIT), expected: 1 };
const check = (id, path, effect) => ({ id, title: id, category: 'billing', severity: 'high', actorId: 'ops', method: 'POST', path, body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], effects: [effect] });
const run = t => onFreePorts(1, async port => {
  const p = { id: 'refunds', name: 'Refunds', applicationId: 'refunds', origin: await refundApp(t, port), buildLabel: 'b1', contextId: 'synthetic-refunds',
    actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'],
    observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [{ host: BILL, paths: ['/v1/refunds', '/v1/credits'], capture: { pointers: ['/amount'], maxBytes: 1024 } }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
    checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
      // The passing check runs last: settlement withholds a pass that a later check's send could belong to.
      check('TWICE', '/refund/twice', ONLY), check('COUNT', '/refund/count', COUNT), check('EXACT', '/credit/exact', CREDIT_COUNT)] };
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  const watch = watchingBinds(buildObservers);
  return { p, run: await runHttpAssessment(p, { env, observerFactory: watch.factory }), lostBind: watch.state.lostBind };
}, r => r.lostBind);

test('7. end to end: through a real egress recorder, a refund respelled "105.50" is undecided (main read it "no"); the run validates', async t => {
  const r = await run(t);
  const rowOf = id => r.run.results.find(x => x.id === id);
  const windowsOf = id => rowOf(id).trace[1].data.windows;
  const amountsOf = id => windowsOf(id)[0].events.filter(e => e.name === BILL).map(e => e.captured.values['/amount']);
  assert.deepEqual(amountsOf('TWICE'), [{ type: 'string', value: '105.5' }, { type: 'string', value: '105.50' }]);
  assert.deepEqual(amountsOf('EXACT'), [{ type: 'string', value: '105.5' }]);
  // main's field states on the sealed second refund: "no", so its count read 1 (pass) and its only clause absorbed it (pass).
  const second = windowsOf('COUNT')[0].events.filter(e => e.name === BILL)[1].captured;
  assert.deepEqual(both(second, SPELLED_FIELDS[0]), ['no', 'unknown']);
  const decided = id => { const d = rowOf(id).trace[1].data.effects[0]; return [d.verdict, d.settlement ?? null]; };
  assert.deepEqual(['TWICE', 'COUNT', 'EXACT'].map(decided), [['missing', null], ['missing', null], ['pass', null]], JSON.stringify(rowOf('EXACT').trace[1].data.effects));
  const statusOf = id => rowOf(id).assertions.find(a => /^Observed effect 1/.test(a.name)).status;
  assert.deepEqual(['TWICE', 'COUNT', 'EXACT'].map(statusOf), ['inconclusive', 'inconclusive', 'pass']);
  validateHttpRunEvidence(r.run, { expectedSuite: createRegistry({ profiles: [r.p], env }).exportSuite(r.p.id) });
});
