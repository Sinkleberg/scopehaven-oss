// src/pg-readback.mjs on its own: the declaration, the canonical values, the key range and the judge over hand-built
// records. The observer's reads are in integrations/observers/pg-readback.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { decimalOf, canonicalValue, canonicalExpected, canonicalJson, looksSensitive, validateReadBack, inRange, kindOfColumn, keyKindOfColumn, canonicalKey, placerOf, judgeReadBack, sealWith, ReadBackError, PG_READBACK_SCHEMA } from '../src/pg-readback.mjs';

test('pg-readback: decimals are read exactly, without exponent, leading or trailing zeros; NaN, infinity and hex are not decimals', () => {
  for (const [text, want] of [['40', '40'], ['40.00', '40'], ['040.50', '40.5'], ['-0', '0'], ['-0.000', '0'], ['0.1', '0.1'], ['-7', '-7'], ['1e+21', '1000000000000000000000'], ['1.5e-07', '0.00000015'],
    ['1E2', '100'], ['12345678901234567890', '12345678901234567890'], ['9.99e2', '999'], ['-1.25e1', '-12.5']]) assert.equal(decimalOf(text), want, text);
  for (const text of ['NaN', 'Infinity', '-Infinity', '0x10', '', '.5', '5.', '1e99999', '+1', ' 1', '1 ', '1,5']) assert.equal(decimalOf(text), null, text);
});

test('pg-readback: each kind reads the server text as one canonical value, or refuses it', () => {
  const ok = (kind, text, value) => assert.deepEqual(canonicalValue(kind, text), { value }, `${kind} ${text}`);
  const bad = (kind, text, error) => assert.deepEqual(canonicalValue(kind, text), { error }, `${kind} ${text}`);
  ok('text', 'a b', 'a b'); ok('text', '', ''); ok('char', 'ab', 'ab'); bad('char', 'a\uFFFD', 'value-not-canonical'); bad('text', 'x\uFFFD', 'value-not-canonical'); bad('text', 'x'.repeat(4097), 'value-too-long');
  ok('numeric', '40.00', '40'); bad('numeric', 'NaN', 'value-not-decimal'); bad('numeric', 'Infinity', 'value-not-decimal');
  ok('boolean', 'true', true); ok('boolean', 'f', false); bad('boolean', 'yes', 'value-not-canonical');
  ok('timestamp', '2026-10-18 06:07:35', '2026-10-18T06:07:35'); ok('timestamp', '2026-10-18 06:07:35.000120', '2026-10-18T06:07:35.00012');
  bad('timestamp', '2026-10-18 06:07:35+00', 'value-not-canonical'); bad('timestamp', 'infinity', 'value-not-canonical'); bad('timestamp', '10000-01-01 00:00:00', 'value-not-canonical');
  ok('timestamptz', '2026-10-18 06:07:35.5+00', '2026-10-18T06:07:35.5Z'); bad('timestamptz', '2026-10-18 06:07:35+02', 'value-not-canonical'); bad('timestamptz', '2026-10-18 06:07:35', 'value-not-canonical');
  ok('date', '2024-02-29', '2024-02-29'); bad('date', '2026-02-29', 'value-not-canonical'); bad('date', '2026-01-01 BC', 'value-not-canonical'); bad('date', '-infinity', 'value-not-canonical');
  ok('json', '{"b": 2, "a": [1.0, null]}', '{"a":[1,null],"b":2}'); ok('json', '"s"', '"s"'); ok('json', '1e2', '100');
  // Each number is kept as the exact decimal of its text, never through a double.
  ok('json', '{"n": 12345678901234567890}', '{"n":12345678901234567890}'); ok('json', '{"n": 0.1000000000000000055511151231257827}', '{"n":0.1000000000000000055511151231257827}');
  ok('json', '[1e21, 1.5e-7, -0, 1.10]', '[1000000000000000000000,0.00000015,0,1.1]'); bad('json', '[1e99999]', 'value-not-canonical');
  bad('json', `[${Array(5).fill('1e999').join(',')}]`, 'value-not-canonical'); bad('json', '{', 'value-not-canonical');
  ok('uuid', '6f1c2a3e-0000-4000-8000-00000000abcd', '6f1c2a3e-0000-4000-8000-00000000abcd'); bad('uuid', '6F1C2A3E-0000-4000-8000-00000000ABCD', 'value-not-canonical');
  bad('json', `${'['.repeat(40)}${']'.repeat(40)}`, 'value-not-canonical'); bad('json', '"a\uFFFD"', 'value-not-canonical');
  ok('json', '{"a": 1, "a": 2}', '{"a":2}'); ok('json', '"\\u0000"', '"\\u0000"');
  for (const kind of ['text', 'char', 'uuid', 'numeric', 'boolean', 'timestamp', 'timestamptz', 'date', 'json']) ok(kind, null, null);
  bad('interval', '1 day', 'type-refused'); bad('numeric', 7, 'value-unreadable');
});

test('pg-readback: an expected value is read as the column kind; anything else is not canonical, never a guess', () => {
  const ok = (kind, value, want) => assert.deepEqual(canonicalExpected(kind, value), { value: want }, `${kind} ${JSON.stringify(value)}`);
  const bad = (kind, value) => assert.deepEqual(canonicalExpected(kind, value), { error: 'expectation-not-canonical' }, `${kind} ${JSON.stringify(value)}`);
  ok('numeric', 40, '40'); ok('numeric', '40.0', '40'); ok('numeric', '0.1', '0.1'); bad('numeric', 'forty'); bad('numeric', true);
  // A JSON number is taken only as a safe integer: past 2^53, or with a fraction, it may already have been rounded.
  bad('numeric', 0.1); bad('numeric', 2 ** 53 + 2); ok('numeric', '9007199254740993', '9007199254740993');
  ok('char', 'ab  ', 'ab'); bad('char', 1);
  ok('text', 'paid', 'paid'); bad('text', 1); ok('boolean', false, false); bad('boolean', 'false');
  ok('timestamptz', '2026-10-18T06:07:35Z', '2026-10-18T06:07:35Z'); ok('timestamptz', '2026-10-18 06:07:35.10+00:00', '2026-10-18T06:07:35.1Z');
  bad('timestamptz', '2026-10-18T08:07:35+02:00'); bad('timestamptz', '2026-10-18T06:07:35'); bad('timestamp', '2026-10-18T06:07:35Z'); bad('date', '2026-13-01'); bad('timestamp', '2026-10-18T24:00:00');
  // A json expectation is JSON text, read as a stored value is read; a JavaScript value has already passed its numbers
  // through a double, so it is not canonical.
  ok('json', '{"b": [1.0, "x"], "a": null}', '{"a":null,"b":[1,"x"]}'); ok('json', '"text"', '"text"'); bad('json', 'text'); bad('json', { b: [1, 'x'] }); bad('json', 1); bad('json', true);
  // Review F1: a 64-bit id and 2^53 + 1 stay apart from what a double makes of them.
  ok('json', '{"order_id": 1234567890123456789}', '{"order_id":1234567890123456789}');
  assert.notEqual(canonicalExpected('json', '{"order_id": 1234567890123456789}').value, canonicalValue('json', '{"order_id": 1234567890123456800}').value);
  assert.notEqual(canonicalExpected('json', '{"n": 9007199254740993}').value, canonicalValue('json', '{"n": 9007199254740992}').value);
  bad('json', JSON.parse('{"order_id": 1234567890123456789}'));
  // Review m1: null is SQL NULL; the JSON value null is the JSON text 'null', and the two never compare equal.
  ok('json', 'null', 'null'); assert.deepEqual([canonicalValue('json', 'null'), canonicalValue('json', null)], [{ value: 'null' }, { value: null }]);
  // Review m2: a uuid expectation in either case reads as PostgreSQL prints it; any other spelling is refused.
  ok('uuid', '6F1C2A3E-0000-4000-8000-00000000ABCD', '6f1c2a3e-0000-4000-8000-00000000abcd'); bad('uuid', '{6f1c2a3e-0000-4000-8000-00000000abcd}'); bad('uuid', '6f1c2a3e00004000800000000000abcd'); bad('uuid', 1);
  assert.equal(canonicalJson('{"a": 1, "a": 2}'), '{"a":2}'); assert.equal(canonicalJson(1), null);
  for (const kind of ['text', 'uuid', 'numeric', 'boolean', 'json']) ok(kind, null, null);
});

test('pg-readback: names that read as secrets or personal data are flagged by word; others are not', () => {
  for (const name of ['password_hash', 'apiKey', 'api_key', 'access_key', 'customerEmail', 'phone', 'card_last4', 'ssn', 'date_of_birth', 'first_name', 'ip_addr', 'session_token', 'billing_address',
    'useremail', 'emailaddress', 'pwhash', 'hashed_pw', 'creditcard', 'cc_number', 'social_security_number', 'dateofbirth', 'apitoken', 'refresh_tok', 'bank_acct'])
    assert.ok(looksSensitive(name), name);
  for (const name of ['refund_amount', 'status', 'seat', 'flight_number', 'total', 'note', 'created_at', 'keyword', 'passenger_count', 'sort_key']) assert.ok(!looksSensitive(name), name);
});

test('pg-readback: each malformed declaration is refused with its own code', () => {
  const code = (rb, want) => assert.throws(() => validateReadBack(rb, { key: 'id' }), e => e instanceof ReadBackError && e.code === want, want);
  code(null, 'readback-shape'); code([], 'readback-shape'); code({ columns: ['a'], other: 1 }, 'readback-shape');
  code({ columns: 'a' }, 'column-identifier'); code({ columns: ['a b'] }, 'column-identifier'); code({ columns: Array.from({ length: 17 }, (_, i) => `c${i}`) }, 'column-identifier');
  code({ columns: ['a', 'a'] }, 'column-repeated'); code({ columns: ['id'] }, 'column-is-key');
  code({ columns: ['a'], sensitive: ['b'] }, 'sensitive-not-column'); code({ columns: ['email'], sensitive: ['email'], reveal: ['a'] }, 'reveal-not-sensitive');
  code({ columns: ['email'] }, 'sensitive-undeclared'); code({ columns: ['email'], sensitive: ['email', 'email'] }, 'sensitive-not-column');
  code({ columns: ['a'], remainder: 'ignore' }, 'remainder-policy');
  for (const range of [{}, { prefix: '' }, { min: 1 }, { min: '01' }, { min: '5', max: '4' }, { prefix: 'a', min: '1' }, { max: '1.5' }, 'a', { keys: [] }, { keys: 'a' }, { keys: [''] }, { keys: [1] },
    { keys: ['a', 'a'] }, { keys: ['a'], prefix: 'a' }, { keys: Array.from({ length: 101 }, (_, i) => `k${i}`) }]) code({ columns: ['a'], range }, 'range-shape');
  assert.deepEqual(validateReadBack({ columns: ['a'], range: { keys: ['A100'] }, deletes: 1 }, { key: 'id' }).range, { keys: ['A100'] });
  for (const n of [-1, 1.5, '1', 100001]) code({ columns: ['a'], inserts: n }, 'count-shape');
  code({ columns: ['a'], expect: {} }, 'expect-shape'); code({ columns: ['a'], expect: [{ key: 'k' }] }, 'expect-shape'); code({ columns: ['a'], expect: [{ key: 'k', values: {} }] }, 'expect-shape');
  code({ columns: ['a'], expect: [{ key: 'k', values: { a: 1 }, extra: 1 }] }, 'expect-shape'); code({ columns: ['a'], expect: Array.from({ length: 101 }, (_, i) => ({ key: `k${i}`, values: { a: 1 } })) }, 'expect-shape');
  code({ columns: ['a'], expect: [{ key: '', values: { a: 1 } }] }, 'expect-key'); code({ columns: ['a'], expect: [{ key: 7, values: { a: 1 } }] }, 'expect-key');
  code({ columns: ['a'], expect: [{ key: 'k', values: { a: 1 } }, { key: 'k', values: { a: 2 } }] }, 'expect-key-repeated');
  code({ columns: ['a'], expect: [{ key: 'k', values: { b: 1 } }] }, 'column-undeclared');
  code({ columns: ['a'], expect: [{ key: 'k', values: { a: 1 }, change: { a: { from: 0, to: 1 } } }] }, 'expect-column-repeated');
  code({ columns: ['a'], expect: [{ key: 'k', values: { a: undefined } }] }, 'expect-value'); code({ columns: ['a'], expect: [{ key: 'k', change: { a: { to: 1 } } }] }, 'expect-value');
  code({ columns: ['a'], expect: [{ key: 'k', change: { a: { from: 0, to: Infinity } } }] }, 'expect-value');
  code({}, 'nothing-declared'); code({ columns: [] }, 'nothing-declared');
  const ok = validateReadBack({ columns: ['email', 'a'], sensitive: ['email'], range: { min: '-5' }, deletes: 0, expect: [{ key: 'k', values: { a: 1 }, change: { email: { from: null, to: 'x' } } }] }, { key: 'id' });
  assert.deepEqual([ok.remainder, ok.inserts, ok.deletes, ok.expect.map(e => [e.column, e.mode])], ['unchanged', null, 0, [['a', 'value'], ['email', 'change']]]);
  assert.ok(Object.isFrozen(ok) && Object.isFrozen(ok.expect[0]));
});

test('pg-readback: key ranges place text keys by prefix and integer keys by value; an integer range cannot place a text key', () => {
  assert.equal(inRange(null, 'x'), true);
  assert.equal(inRange({ prefix: 'cart-' }, 'cart-1'), true); assert.equal(inRange({ prefix: 'cart-' }, 'Cart-1'), false);
  assert.equal(inRange({ min: '9' }, '10'), true, 'compared as numbers, not text'); assert.equal(inRange({ max: '9' }, '10'), false);
  assert.equal(inRange({ min: '-5', max: '5' }, '-5'), true); assert.equal(inRange({ min: '1' }, '9223372036854775807'), true);
  assert.equal(inRange({ min: '1' }, 'x1'), null); assert.equal(inRange({ min: '1' }, '01'), null);
  // Review m4: an exact-key range places only its own keys, compared as text.
  assert.equal(inRange({ keys: ['A100'] }, 'A100'), true); assert.equal(inRange({ keys: ['A100'] }, 'A101'), false); assert.equal(inRange({ keys: ['A100'] }, 'A1000'), false); assert.equal(inRange({ keys: ['7'] }, '07'), false);
});

test('pg-readback review m5: an exact key is compared as the key column reads it; a key its kind cannot read, or a key column of another kind, is refused', () => {
  const uuid = '6f1c2a3e-0000-4000-8000-00000000abcd';
  const ok = (kind, text, want) => assert.equal(canonicalKey(kind, text), want, `${kind} ${text}`);
  const bad = (kind, text) => assert.equal(canonicalKey(kind, text), null, `${kind} ${text}`);
  ok('text', 'A100', 'A100'); ok('text', 'a100 ', 'a100 '); ok('char', 'A1  ', 'A1'); ok('char', 'A1', 'A1');
  ok('uuid', uuid.toUpperCase(), uuid); ok('uuid', uuid, uuid); bad('uuid', `{${uuid}}`); bad('uuid', uuid.replace(/-/g, '')); bad('uuid', 'A100');
  ok('integer', '42', '42'); ok('integer', '-7', '-7'); for (const text of ['042', '+42', '-0', '42.0', '4e1', ' 42', 'x']) bad('integer', text);
  ok('numeric', '1.50', '1.5'); ok('numeric', '042', '42'); ok('numeric', '1e2', '100'); bad('numeric', 'NaN'); bad('numeric', 'Infinity');
  ok('timestamp', '2026-10-18T06:07:35.500', '2026-10-18T06:07:35.5'); ok('timestamp', '2026-10-18 06:07:35.5', '2026-10-18T06:07:35.5'); bad('timestamp', 'infinity');
  ok('timestamptz', '2026-10-18 06:07:35+00', '2026-10-18T06:07:35Z'); ok('timestamptz', '2026-10-18T06:07:35Z', '2026-10-18T06:07:35Z'); ok('date', '2024-02-29', '2024-02-29');
  for (const kind of [null, 'json', 'boolean', 'float']) bad(kind, '1'); bad('text', 7);
  // The key column's kind: integers apart from numeric; floats, boolean, json and other types refused; a domain by its base.
  assert.equal(keyKindOfColumn({ typid: '20', typtype: 'b' }), 'integer'); assert.equal(keyKindOfColumn({ typid: '1700', typtype: 'b' }), 'numeric');
  assert.equal(keyKindOfColumn({ typid: '90001', typtype: 'd', basetype: '2950' }), 'uuid'); assert.equal(keyKindOfColumn({ typid: '1042', typtype: 'b' }), 'char');
  for (const typid of ['700', '701', '16', '114', '3802', '869', '90000']) assert.equal(keyKindOfColumn({ typid, typtype: 'b' }), null, typid);
  // Placement: both sides canonical, so an upper-case uuid names the lower-case row; a refused range places nothing.
  assert.equal(placerOf({ keys: [uuid.toUpperCase()] }, 'uuid').place(uuid), true); assert.equal(placerOf({ keys: [uuid.toUpperCase()] }, 'uuid').refused, null);
  assert.equal(placerOf({ keys: ['A1  '] }, 'char').place('A1'), true); assert.equal(placerOf({ keys: ['1.5'] }, 'numeric').place('1.50'), true);
  assert.equal(placerOf({ keys: ['1.5'] }, 'numeric').place('NaN'), null, 'a changed key the kind cannot read is not placed');
  assert.equal(placerOf({ keys: ['A100'] }, 'text').place('a100'), false, 'text is compared exactly');
  for (const [keys, kind, refused] of [[['042'], 'integer', 'range-key-not-canonical'], [['A100'], 'uuid', 'range-key-not-canonical'], [['0.1'], null, 'range-key-type-refused']]) {
    const p = placerOf({ keys }, kind);
    assert.deepEqual([p.refused, p.place('42'), p.place('0.1')], [refused, null, null], `${kind} ${keys}`);
  }
  assert.equal(placerOf({ prefix: 'A' }, null).place('A1'), true, 'other ranges are placed as before'); assert.equal(placerOf(null, null).place('x'), true);
});

test('pg-readback: a column kind comes from its base type or a one-level domain; anything else is refused', () => {
  assert.equal(kindOfColumn({ typid: '1700', typtype: 'b' }), 'numeric'); assert.equal(kindOfColumn({ typid: '2950', typtype: 'b' }), 'uuid');
  assert.equal(kindOfColumn({ typid: '90001', typtype: 'd', basetype: '1184' }), 'timestamptz');
  assert.equal(kindOfColumn({ typid: '90001', typtype: 'd', basetype: '90000' }), null);
  for (const typtype of ['e', 'c', 'r', 'm', 'p']) assert.equal(kindOfColumn({ typid: '25', typtype }), null, typtype);
  assert.equal(kindOfColumn({ typid: '1009', typtype: 'b' }), null);
});

test('pg-readback: the judge never passes on nothing, on an unreadable record or on a blocked table, and seals compare only as seals', () => {
  assert.deepEqual([judgeReadBack(null).verdict, judgeReadBack(null).reasons], ['inconclusive', ['record-unreadable']]);
  assert.deepEqual([judgeReadBack({ schema: 'other', tables: [] }).verdict], ['inconclusive']);
  const empty = judgeReadBack({ schema: PG_READBACK_SCHEMA, status: 'ok', tables: [] });
  assert.deepEqual([empty.verdict, empty.reasons], ['inconclusive', ['no-expectation']]);
  const table = (over = {}) => ({ name: 'orders', status: 'ok', remainderPolicy: 'unchanged', expected: { inserts: null, deletes: null }, counts: { status: 'ok', inserted: 0, deleted: 0 },
    remainder: { before: 'a', after: 'a', unnamed: 'same' }, rows: [{ key: 'k', before: { v: '1' }, after: { v: '2' } }], expect: [{ key: 'k', column: 'v', mode: 'value', to: '2' }], ...over });
  const judge = (over, status = 'ok') => judgeReadBack({ schema: PG_READBACK_SCHEMA, status, tables: [table(over)] });
  assert.equal(judge({}).verdict, 'pass');
  assert.deepEqual(judge({}, 'duplicate-key').reasons, ['duplicate-key']);
  assert.deepEqual(judge({ status: 'type-refused' }).reasons, ['type-refused']);
  assert.deepEqual(judge({ remainder: { before: 'a', after: 'a', unnamed: 'unreadable' } }).reasons, ['remainder-unreadable']);
  assert.equal(judge({ remainder: { before: 'a', after: 'b', unnamed: 'same' }, remainderPolicy: 'may-change' }).verdict, 'pass');
  // A sealed value equals only the same seal; a clear value never equals a seal, whatever it holds.
  const seal = sealWith(Buffer.alloc(32, 7));
  assert.equal(judge({ rows: [{ key: 'k', before: null, after: { v: seal('text', 'x') } }], expect: [{ key: 'k', column: 'v', mode: 'value', to: seal('text', 'x') }] }).verdict, 'pass');
  assert.equal(judge({ rows: [{ key: 'k', before: null, after: { v: seal('text', 'x') } }], expect: [{ key: 'k', column: 'v', mode: 'value', to: seal('text', 'y') }] }).verdict, 'fail');
  assert.equal(judge({ rows: [{ key: 'k', before: null, after: { v: seal('text', 'x') } }], expect: [{ key: 'k', column: 'v', mode: 'value', to: 'x' }] }).verdict, 'fail');
  assert.notDeepEqual(seal('text', '1'), seal('numeric', '1'), 'the kind is sealed with the value');
  // A guarded table has its own remainder check; a blocked table with no check of its own still gets one.
  assert.deepEqual(judge({ expect: [] }).checks, [{ table: 'orders', check: 'remainder', status: 'pass', reason: null }]);
  assert.deepEqual(judge({ expect: [], status: 'table-violated' }).checks, [{ table: 'orders', check: 'table', status: 'inconclusive', reason: 'table-violated' }]);
  assert.equal(judge({ expect: [], remainderPolicy: 'may-change' }).verdict, 'inconclusive', 'nothing to decide never passes');
  // A malformed stored record reads unreadable, never a throw.
  for (const bent of [{ expect: null }, { rows: 'x' }, { remainderPolicy: 'other' }, { counts: null }, { expected: null }, { expect: [null] }])
    assert.deepEqual(judge(bent).reasons, ['record-unreadable'], JSON.stringify(bent));
  assert.deepEqual(judgeReadBack({ schema: PG_READBACK_SCHEMA, status: 'ok', tables: [null] }).reasons, ['record-unreadable']);
  assert.deepEqual(judgeReadBack({ schema: PG_READBACK_SCHEMA, tables: [] }).reasons, ['record-unreadable']);
});
