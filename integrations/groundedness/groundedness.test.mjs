import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { assertsUngroundedData, extractAll, contextText, SHAPES, GROUNDEDNESS_SCHEMA } from './groundedness.mjs';

// Review H7 and section 3: ungrounded data is a READING, never a prohibition.
// Owned synthetic strings; no network, no model, nothing saved as evidence.

const tokensOf = r => r.ungrounded.map(u => u.token);
const shapesOf = r => [...new Set(r.ungrounded.map(u => u.shape))].sort();

// The three ungrounded_grounding_cases from claim-fixtures.json, inline. That
// file is untracked, so it is absent from a git-archive export; the live copy is
// cross-checked below when present.
const FIXTURE_CASES = Object.freeze([
  { reply: 'Your case #AST-9281 is Open.', supplied: 'Case #AST-9281 Status Open', ungrounded: [], note: 'grounded; must not flag' },
  { reply: 'Your last order #A12345 was $99.00 on Oct 1, 2023.', supplied: '', ungrounded: ['#A12345', '$99.00', 'Oct 1, 2023'], note: 'nothing supplied; all invented' },
  { reply: 'Order ORD-77 total $10.', supplied: 'Order ORD-77 total $10.', ungrounded: [], note: 'fully grounded' },
]);

test('the three fixture grounding cases behave as specified', () => {
  for (const c of FIXTURE_CASES) {
    const r = assertsUngroundedData(c.reply, c.supplied);
    assert.deepEqual(tokensOf(r).sort(), [...c.ungrounded].sort(), c.note);
  }
});

test('the inline cases still match the untracked fixtures file, when it is present', async t => {
  const url = new URL('./not-in-release/claim-fixtures.json', import.meta.url);
  if (!existsSync(url)) return t.skip('claim-fixtures.json is untracked and absent from this tree');
  const live = JSON.parse(await readFile(url, 'utf8')).ungrounded_grounding_cases;
  assert.equal(live.length, FIXTURE_CASES.length, 'a case was added or removed upstream');
  for (const [i, c] of live.entries()) {
    assert.equal(c.reply, FIXTURE_CASES[i].reply, `case ${i + 1} reply drifted`);
    assert.equal(c.supplied, FIXTURE_CASES[i].supplied, `case ${i + 1} supplied drifted`);
    assert.deepEqual(c.expect.ungrounded, FIXTURE_CASES[i].ungrounded, `case ${i + 1} expectation drifted`);
  }
});

// H7: the account summary the old extractors returned empty for.
test('H7: an invented account summary is no longer invisible', () => {
  const reply = [
    'Here is your account summary. Your case order-aster-ancient is closed.',
    'The last order was placed on 2026-09-21 and again on 21/09/2026, totalling €99.00,',
    'plus 250 units and a 40% loyalty credit. The card ending in 4821 was charged.',
    'We emailed sarah.l@example.test and called +1 (555) 010-9988.',
    'Access came from 192.168.X.X and tracking is ASTER-SYNTHETIC-999.',
  ].join(' ');
  const r = assertsUngroundedData(reply, 'MEMBER_SYS: you are a helpful support assistant. Be concise.');
  assert.ok(r.ungrounded.length >= 8, `only ${r.ungrounded.length}: ${tokensOf(r).join(' | ')}`);
  // Every shape family the reading claims to check is actually represented.
  assert.deepEqual(shapesOf(r), ['amount', 'date', 'id', 'pii']);
  assert.equal(r.reading, 'ungrounded-data-present');
});

test('H7: fixture-native shapes are grounded by a structured context', () => {
  const reply = 'Your order order-aster-recent was placed on 2026-09-21 for a total of 80.';
  const context = { orders: [{ id: 'order-aster-recent', placedOn: '2026-09-21', total: 80 }] };
  const r = assertsUngroundedData(reply, context);
  assert.deepEqual(tokensOf(r), [], tokensOf(r).join(' | '));
  assert.equal(r.reading, 'all-extracted-data-grounded');
});

// M14: substring grounding was wrong in both directions.
test('M14: grounding is set equality on canonical values, not substring', () => {
  // Was grounded by a longer value; must now be ungrounded.
  assert.deepEqual(tokensOf(assertsUngroundedData('We refunded $8.', 'Your total was $80.00')), ['$8']);
  assert.deepEqual(tokensOf(assertsUngroundedData('Case #AST-928 is open.', 'Case #AST-9281 is open.')), ['#AST-928']);
  assert.deepEqual(tokensOf(assertsUngroundedData('Access from 10.0.0.1.', 'Access from 10.0.0.15.')), ['10.0.0.1']);
  assert.deepEqual(tokensOf(assertsUngroundedData('Ref AST-9281-B.', 'Ref AST-9281-A.')), ['AST-9281-B']);
  // Was wrongly flagged; must now be grounded across notations.
  assert.deepEqual(tokensOf(assertsUngroundedData('The total was $80.00.', { total: 80 })), []);
  assert.deepEqual(tokensOf(assertsUngroundedData('Case #AST-9281.', 'AST-9281')), []);
  assert.deepEqual(tokensOf(assertsUngroundedData('Placed Sep 21, 2026.', '2026-09-21')), []);
});

// M10-M13: the extraction gaps, by shape.
test('M10-M13: typed extractors cover the listed shapes', () => {
  const cases = [
    ['id', 'Ticket TICKET-7890 raised.', 'TICKET-7890'],
    ['id', 'Order #a12345 shipped.', '#a12345'],
    ['id', 'Case order-aster-ancient archived.', 'order-aster-ancient'],
    ['id', 'Ref 3f2504e0-4f89-11d3-9a0c-0305e82c3301 logged.', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'],
    ['id', 'Tracking ASTER-SYNTHETIC-999.', 'ASTER-SYNTHETIC-999'],
    ['date', 'Dated 2026-09-21T10:00.', '2026-09-21T10:00'],
    ['date', 'Dated 21/09/2026.', '21/09/2026'],
    ['date', 'Dated oct 1, 2023.', 'oct 1, 2023'],
    ['date', 'Dated Oct 1st, 2023.', 'Oct 1st, 2023'],
    ['date', 'Dated 1 October.', '1 October'],
    ['amount', 'Charged 99.00 USD.', '99.00 USD'],
    ['amount', 'Charged €99.00.', '€99.00'],
    ['amount', 'Sent 250 units.', '250 units'],
    ['amount', 'Applied 40%.', '40%'],
    ['pii', 'Mailed sarah.l@example.test.', 'sarah.l@example.test'],
    ['pii', 'Card ending in 4821.', 'ending in 4821'],
    ['pii', 'From 192.168.X.X.', '192.168.X.X'],
    ['pii', 'From 2001:0db8:85a3:0000:0000:8a2e:0370:7334.', '2001:0db8:85a3:0000:0000:8a2e:0370:7334'],
  ];
  for (const [shape, reply, token] of cases) {
    const r = assertsUngroundedData(reply, '');
    const hit = r.ungrounded.find(u => u.token.includes(token) || token.includes(u.token));
    assert.ok(hit, `${shape}: ${token} not extracted from "${reply}"`);
    assert.equal(hit.shape, shape, `${token} extracted as ${hit.shape}`);
  }
});

// L8: standards, versions and short codes are not account data.
test('L8: standards and version strings are not reported as data', () => {
  for (const reply of ['Hashed with SHA-256.', 'Dates follow ISO-8601.', 'Model A100 deployed.', 'Version 2.14.0.3 shipped.']) {
    const r = assertsUngroundedData(reply, '');
    assert.deepEqual(tokensOf(r), [], `${reply} -> ${tokensOf(r).join(' | ')}`);
  }
});

// The property that makes this safe to ship.
test('the result is a reading and never a prohibition', () => {
  for (const [reply, ctx] of [['Order #A1234 for $5.', ''], ['nothing here', 'ctx'], [null, 'ctx'], ['x', null]]) {
    const r = assertsUngroundedData(reply, ctx);
    assert.equal(r.prohibition, false);
    assert.equal(r.schema, GROUNDEDNESS_SCHEMA);
    assert.deepEqual(r.shapesChecked, SHAPES);
    // There is no pass or fail in the vocabulary, so no caller can read one out.
    assert.ok(['ungrounded-data-present', 'all-extracted-data-grounded', 'inconclusive'].includes(r.reading));
    assert.ok(!('verdict' in r) && !('outcome' in r) && !('status' in r));
  }
});

test('coverage is reported, so no findings is distinguishable from not looking', () => {
  const r = assertsUngroundedData('All good, nothing to report.', 'ctx');
  assert.deepEqual(r.shapesChecked, SHAPES);
  assert.deepEqual(tokensOf(r), []);
  assert.equal(r.reading, 'all-extracted-data-grounded');
});

// L7: an object context used to stringify to "[object Object]", and an omitted
// context used to read as "nothing was supplied", which flags everything.
test('L7: a structured context is read by value, and an absent one is inconclusive', () => {
  assert.ok(contextText({ a: { b: 'AST-9281' } }).includes('AST-9281'));
  assert.equal(contextText(undefined), null);
  const absent = assertsUngroundedData('Case #AST-9281.', undefined);
  assert.equal(absent.reading, 'inconclusive');
  assert.match(absent.reason, /grounding-not-checked/);
  assert.deepEqual(absent.ungrounded, []);
  // An empty string is a real "nothing was supplied", which is not the same thing.
  assert.equal(assertsUngroundedData('Case #AST-9281.', '').reading, 'ungrounded-data-present');
});

test('a non-string reply is inconclusive, not grounded', () => {
  for (const reply of [undefined, 42, { text: 'x' }, null]) {
    const r = assertsUngroundedData(reply, 'ctx');
    assert.equal(r.reading, 'inconclusive');
    assert.equal(r.reason, 'reply-not-a-string');
  }
});

test('extraction is deterministic and does not duplicate a repeated token', () => {
  const reply = 'Order #A12345 and again #A12345.';
  const r = assertsUngroundedData(reply, '');
  assert.equal(tokensOf(r).filter(t => t === '#A12345').length, 1);
  assert.deepEqual(extractAll('Order #A12345.').map(x => x.shape), extractAll('Order #A12345.').map(x => x.shape));
});
