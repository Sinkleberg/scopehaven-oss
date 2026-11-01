// Gap 4: declared body fields read from application/x-www-form-urlencoded bodies (opt-in, capture.encodings).
import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { captureBody, validateCaptureDeclaration, validateCaptured, fieldState, captureEncodingOf, validCaptureForm, formEnabled, formNumber, validateFormPointer, FORM_STATUSES, CAPTURE_STATUSES } from '../src/body-fields.mjs';

const frozen = await import(fileURLToPath(new URL('./fixtures/body-fields-b83051d.mjs', import.meta.url)));
const FORM = 'application/x-www-form-urlencoded';
const pointers = ['/amount', '/currency', '/metadata/order_id', '/items/0/price', '/items/1/amount', '/items/1/a', '/items/0/a', '/items/0', '/items/x', '/items/5/amount', '/tags/0', '/metadata', '/metadata/a', '/note'];
const capture = { pointers: ['/amount', '/currency', '/metadata/order_id', '/note'], maxBytes: 4096, encodings: ['json', 'form'] };
const jsonOnly = { pointers: capture.pointers, maxBytes: 4096 };
const send = (body, opts = {}) => {
  const { type, headers = [], search, method, cap = capture } = { type: FORM, search: '', method: 'POST', ...opts };
  const buffer = Buffer.from(body, 'latin1');
  return captureBody({ rawHeaders: [...(type === undefined ? [] : ['Content-Type', type]), ...headers], buffer, bodyBytes: buffer.length, capture: cap, search, method });
};
const status = (body, opts) => send(body, opts).status;
const at = (body, pointer, opts = {}) => send(body, { ...opts, cap: { ...capture, pointers: [pointer] } }).values[pointer];
const text = value => ({ type: 'text', value });
const ambiguous = { type: 'unusable', reason: 'ambiguous' };
const rec = value => ({ status: 'captured', values: { '/amount': value } });
const judge = (t, op, operand) => fieldState(rec(text(t)), { pointer: '/amount', [op]: operand });

test('form opt-in normalizes: absent and ["json"] give the JSON-only declaration', () => {
  assert.deepEqual(validateCaptureDeclaration({ pointers: ['/a'] }, 1 << 20), { pointers: ['/a'], maxBytes: 16384 });
  assert.deepEqual(validateCaptureDeclaration({ pointers: ['/a'], encodings: ['json'] }, 1 << 20), { pointers: ['/a'], maxBytes: 16384 });
  for (const encodings of [['json', 'form'], ['form', 'json']]) assert.deepEqual(validateCaptureDeclaration({ pointers: ['/a'], encodings }, 1 << 20), { pointers: ['/a'], maxBytes: 16384, encodings: ['json', 'form'] });
  assert.equal(formEnabled(validateCaptureDeclaration({ pointers: ['/a'] }, 1 << 20)), false);
  assert.equal(formEnabled(validateCaptureDeclaration({ pointers: ['/a'], encodings: ['form', 'json'] }, 1 << 20)), true);
  assert.equal(formEnabled(undefined), false);
});

test('encodings bounds refuse at load; unknown keys keep the old message', () => {
  for (const encodings of [[], ['form'], ['json', 'json'], ['json', 'xml'], 'form', ['json', 'form', 'form'], undefined, null]) assert.throws(() => validateCaptureDeclaration({ pointers: ['/a'], encodings }, 1 << 20), /capture\.encodings/, JSON.stringify(encodings));
  assert.throws(() => validateCaptureDeclaration({ pointers: ['/a'], whole: true }, 1 << 20), /\{ pointers, maxBytes\? \}/);
});

test('form pointer grammar, depth and prototype names: refused with form, accepted JSON-only', () => {
  const decl = (p, form) => validateCaptureDeclaration({ pointers: [p], ...(form ? { encodings: ['json', 'form'] } : {}) }, 1 << 20);
  for (const p of ['/a.b', '/a%41', '/a+b', '/items/01', '/items/0123456789', '/a/b/c/d/e/f/g', '/toString', '/meta/valueOf', '/HasOwnProperty', '/a]b', '/a b']) {
    assert.throws(() => decl(p, true), /form bodies/, p);
    assert.doesNotThrow(() => decl(p, false), p);
  }
  for (const p of ['/a/b/c/d/e/f', '/metadata/order_id', '/items/0/price', '/To', '/o:tag', '/to_string']) assert.doesNotThrow(() => decl(p, true), p);
});

test('flattened deny-list applies only with form', () => {
  for (const p of ['/se/cret', '/to/ken']) {
    assert.throws(() => validateCaptureDeclaration({ pointers: [p], encodings: ['json', 'form'] }, 1 << 20), /secret-like key/, p);
    assert.doesNotThrow(() => validateCaptureDeclaration({ pointers: [p] }, 1 << 20), p);
  }
  for (const form of [true, false]) assert.throws(() => validateCaptureDeclaration({ pointers: ['/card/last4'], ...(form ? { encodings: ['json', 'form'] } : {}) }, 1 << 20), /secret-like key/);
});

test('media type allowlist', () => {
  for (const type of [FORM, 'Application/X-WWW-Form-Urlencoded; charset=UTF-8', `${FORM}; charset="utf-8"`, `${FORM} ; charset=utf-8`]) assert.equal(status('amount=25', { type }), 'captured', type);
  for (const type of [`${FORM}; charset=utf8`, `${FORM}; charset=iso-8859-1`, `${FORM}; foo=bar`, `${FORM};`, `${FORM}; charset=utf-8; charset=utf-8`]) assert.equal(status('amount=25', { type }), 'form-media-type', type);
  for (const type of ['multipart/form-data; boundary=x', 'text/plain', undefined]) assert.equal(status('amount=25', { type }), 'not-json-or-form', String(type));
  assert.equal(status('amount=25', { headers: ['content-type', FORM] }), 'content-type-ambiguous');
  for (const type of [FORM, 'multipart/form-data', 'text/plain', undefined]) assert.equal(status('amount=25', { type, cap: jsonOnly }), 'not-json', String(type));
});

test('query and cookie refusal precedes parsing; JSON bodies ignore the query', () => {
  for (const search of ['?amount=50000', '?x=1', '?&', undefined]) assert.deepEqual(send('amount=5', { search }), { status: 'form-query-or-cookie', values: {} }, String(search));
  for (const name of ['Cookie', 'cookie', 'COOKIE']) for (const value of ['amount=50000', '']) assert.equal(status('amount=5', { headers: [name, value] }), 'form-query-or-cookie');
  assert.equal(status('amount=5'), 'captured');
  assert.equal(status('a=%zz', { search: '?x=1' }), 'form-query-or-cookie');
  const json = send('{"amount":5}', { type: 'application/json', search: '?amount=50000' });
  assert.equal(json.status, 'captured');
  assert.deepEqual(json.values['/amount'], { type: 'number', value: 5 });
});

test('compressed and oversized form bodies', () => {
  for (const headers of [['Content-Encoding', 'gzip'], ['Content-Encoding', 'br'], ['Content-Encoding', 'identity', 'Content-Encoding', 'identity']]) assert.equal(status('amount=25', { headers }), 'encoded');
  assert.equal(status('amount=25', { headers: ['Content-Encoding', 'identity'] }), 'captured');
  const fill = n => 'amount=25&note=' + 'x'.repeat(n - 'amount=25&note='.length);
  assert.equal(status(fill(4096)), 'captured');
  assert.equal(status(fill(4097)), 'over-cap');
  const buffer = Buffer.from('amount=25');
  assert.equal(captureBody({ rawHeaders: ['Content-Type', FORM], buffer, bodyBytes: buffer.length + 1, capture, search: '', method: 'POST' }).status, 'over-cap');
});

test('raw byte allowlist next to its forbidden neighbours', () => {
  assert.equal(status("amount=25&note=a-b._~*!'()[x]"), 'captured');
  for (const body of ['amount=25;x=1', 'note=a;b', 'amount=2 5', 'amount=2\t5', 'amount=2\r5', 'amount=2\n5', '{"amount":25}', 'to=a@b', 'u=a/b', 'x=a,b', 'x=é', 'x=\u0080']) assert.equal(status(body), 'form-invalid', JSON.stringify(body));
  assert.deepEqual(at('note=a%40b', '/note'), text('a@b'));
});

test('pair structure', () => {
  assert.equal(status('a=1&b=2'), 'captured');
  assert.deepEqual(at('note=', '/note'), text(''));
  for (const body of ['a=1&&b=2', '&a=1', 'a=1&', 'a', '=1', 'a=1=2']) assert.equal(status(body), 'form-invalid', body);
});

test('percent decoding strictness', () => {
  assert.deepEqual(at('note=%41%4a%4A', '/note'), text('AJJ'));
  assert.deepEqual(at('note=a%20b+c', '/note'), text('a b c'));
  assert.deepEqual(at('note=%2B1555', '/note'), text('+1555'));
  assert.deepEqual(at('note=%C3%A9', '/note', { type: `${FORM}; charset=utf-8` }), text('é'));
  for (const bad of ['%', '%4', '%zz', '%4g', '%C3', '%C0%AF', '%ED%A0%80', '%FF', '%F4%90%80%80']) assert.equal(status(`note=${bad}`), 'form-invalid', bad);
});

test('BOM never stripped', () => {
  assert.equal(status('%EF%BB%BFamount=1'), 'form-key-ambiguous');
  const v = at('amount=%EF%BB%BF25', '/amount', { type: `${FORM}; charset=utf-8` });
  assert.deepEqual(v, text('﻿25'));
  assert.equal(fieldState(rec(v), { pointer: '/amount', equals: 25 }), 'unknown');
  assert.equal(fieldState(rec(v), { pointer: '/amount', gt: 1 }), 'unknown');
  assert.equal(fieldState(rec(v), { pointer: '/amount', equals: '﻿25' }), 'match');
});

test('duplicate keys, exact, decoded and case-folded', () => {
  for (const body of ['amount=1&amount=2', 'amount=1&am%6Funt=2', 'amount=1&Amount=2', 'meta[a]=1&meta%5Ba%5D=2', 'tags[]=a&TAGS[]=b']) assert.equal(status(body), 'form-duplicate-key', body);
  assert.equal(status('amount=1&amounts=2'), 'captured');
  assert.deepEqual(at('tags[]=a&tags[]=b&amount=1', '/amount'), text('1'));
});

test('key grammar', () => {
  for (const body of ['order.id=1', 'a+b=1', 'a%20b=1', '%E2%80%8Bamount=1', 'a%00=1', 'a[b=1', 'a]b=1', 'a[b]c=1', 'a[[b]]=1', 'items[01][x]=1', 'a%25=1', 'a%2B=1', '01=1']) assert.equal(status(body), 'form-key-ambiguous', body);
  assert.equal(status('order_id=1'), 'captured');
  assert.deepEqual(at('metadata[order_id]=1', '/metadata/order_id'), text('1'));
  assert.deepEqual(at('metadata%5Border_id%5D=1', '/metadata/order_id'), text('1'));
  assert.deepEqual(at('items[0][amount]=1', '/items/0/amount'), text('1'));
});

test('prototype-named segments refused, no pollution', () => {
  for (const body of ['__proto__[0]=a&amount=5', 'toString=1&amount=5', 'meta[hasOwnProperty]=1&amount=5', 'constructor[x]=1&amount=5', 'ValueOf=1&amount=5', '__proto__[max]=1&amount=5']) {
    assert.equal(status(body), 'form-key-ambiguous', body);
    for (const name of ['size', 'max', 'distinct']) assert.equal(Object.hasOwn(Object.prototype, name), false);
    assert.equal(({}).max, undefined);
  }
  assert.deepEqual(at('to_string=1&amount=5', '/amount'), text('5'));
});

test('bracket path mapping and distinct-index contiguity', () => {
  assert.deepEqual(at('metadata[order_id]=A-1', '/metadata/order_id'), text('A-1'));
  assert.deepEqual(at('items[0][amount]=1&items[1][amount]=2', '/items/1/amount'), text('2'));
  assert.deepEqual(at('items[1][amount]=2', '/items/1/amount'), ambiguous);
  assert.deepEqual(at('items[1][a]=1&items[1][b]=2', '/items/1/a'), ambiguous);
  assert.deepEqual(at('items[0][a]=1&items[0][b]=2', '/items/0/a'), text('1'));
  assert.deepEqual(at('items[1][amount]=5&items[1][q]=1&items[2][amount]=50000', '/items/1/amount'), ambiguous);
  assert.deepEqual(at('items[0]=a&items[x]=b', '/items/0'), ambiguous);
  assert.deepEqual(at('items[0]=a&items[x]=b', '/items/x'), text('b'));
  assert.deepEqual(at('items[0][amount]=1&items[1][amount]=2', '/items/5/amount'), { type: 'absent' });
  assert.deepEqual(at('items[x]=1', '/items/0'), { type: 'absent' });
});

test('push and mixed nesting read unknown', () => {
  const cases = [['amount[]=5', '/amount', ambiguous], ['tags[]=a', '/tags/0', ambiguous], ['amount=1&amount[x]=2', '/amount', ambiguous], ['amount=1&amount[x]=2', '/amount/x', ambiguous],
    ['metadata[a]=1', '/metadata', { type: 'unusable', reason: 'not-scalar' }], ['metadata=1', '/metadata/a', { type: 'absent' }]];
  for (const [body, pointer, want] of cases) {
    const v = at(body, pointer);
    assert.deepEqual(v, want, `${body} ${pointer}`);
    assert.equal(fieldState({ status: 'captured', values: { [pointer]: v } }, { pointer, equals: '1' }), 'unknown');
  }
});

test('value caps and redaction on text', () => {
  for (const raw of ['4242424242424242', '4242+4242+4242+4242', '123-45-6789', '123456789', '%D9%A3']) {
    const r = send(`note=${raw}`, { type: `${FORM}; charset=utf-8` });
    assert.deepEqual(r.values['/note'], { type: 'unusable', reason: 'redacted' }, raw);
    assert.equal(JSON.stringify(r).includes('4242'), false);
  }
  assert.deepEqual(at(`note=${'a+'.repeat(100)}`, '/note'), text('a '.repeat(100)));
  assert.deepEqual(at(`note=${'a+'.repeat(100)}a`, '/note'), { type: 'unusable', reason: 'value-over-cap' });
  assert.equal(JSON.stringify(send('pass%77ord=hunter2&amount=5')).includes('hunter2'), false);
});

test('numeric operands read canonical integers only', () => {
  assert.equal(judge('2500', 'equals', 2500), 'match');
  assert.equal(judge('2500', 'equals', 2501), 'no');
  assert.equal(judge('2500', 'gt', 1000), 'match');
  assert.equal(judge('2500', 'lt', 1000), 'no');
  assert.equal(judge('2500', 'equals', true), 'unknown');
  assert.equal(judge('2500', 'equals', null), 'unknown');
  assert.equal(judge('-5', 'lt', 0), 'match');
  for (const t of ['02500', '2500.50', '1.000', '-0', '+5', ' 5']) for (const [op, x] of [['equals', 2500], ['gt', 0], ['lte', 1e9]]) assert.equal(judge(t, op, x), 'unknown', `${t} ${op}`);
  assert.equal(fieldState({ status: 'captured', values: { '/amount': { type: 'string', value: '2500' } } }, { pointer: '/amount', equals: 2500 }), 'unknown');
});

test('integer reading bounds', () => {
  assert.equal(formNumber('123456789012345'), 123456789012345);
  assert.equal(judge('123456789012345', 'equals', 123456789012345), 'match');
  for (const t of ['1000000000000000', '9007199254740993', '1e3', '0x10', '1_000', '5.']) assert.equal(judge(t, 'gte', 0), 'unknown', t);
});

test('string operands across numeric spellings', () => {
  const cases = [['2500', '2500', 'match'], ['02500', '2500', 'unknown'], ['2501', '2500', 'no'], ['+15551234567', '+15559999999', 'no'], [' 15551234567', '+15551234567', 'unknown'],
    ['0123', '83', 'unknown'], ['12345678901234567', '12345678901234568', 'unknown'], ['25abc', '25', 'unknown'], ['２５', '25', 'unknown'], ['1.5', '1,5', 'unknown'],
    ['cad', 'usd', 'no'], ['T-7', 'T-8', 'no'], ['2024-0001', '2024-0002', 'no']];
  for (const [t, x, want] of cases) assert.equal(judge(t, 'equals', x), want, `${t} vs ${x}`);
});

test('in is a three-valued OR over text', () => {
  assert.equal(judge('25', 'in', [25, 30]), 'match');
  assert.equal(judge('025', 'in', ['25', 25]), 'unknown');
  assert.equal(judge('b', 'in', ['a', 'c']), 'no');
  assert.equal(judge('b', 'in', ['a', true]), 'unknown');
  assert.equal(judge('', 'in', [null]), 'unknown');
});

test('form size bounds', () => {
  const big = { ...capture, maxBytes: 65536 };
  const pairs = n => Array.from({ length: n - 1 }, (_, i) => `k${i}=1`).concat('amount=5').join('&');
  assert.equal(status(pairs(1000), { cap: big }), 'captured');
  assert.equal(status(pairs(1001), { cap: big }), 'form-over-cap');
  assert.equal(status(`${'k'.repeat(512)}=1&amount=5`), 'captured');
  assert.equal(status(`${'k'.repeat(513)}=1&amount=5`), 'form-over-cap');
  assert.equal(status(`a${'[b]'.repeat(31)}=1`), 'captured');
  assert.equal(status(`a${'[b]'.repeat(32)}=1`), 'form-too-deep');
  const worst = 'note=' + 'a%20'.repeat((65536 - 5) / 4 | 0);
  assert.equal(status(worst.padEnd(65536, 'a'), { cap: big }), 'captured');
});

test('first failing pair decides, values always empty', () => {
  for (const [body, want] of [['a=%zz&b.c=1', 'form-invalid'], ['b.c=1&a=%zz', 'form-key-ambiguous']]) {
    const r = send(body);
    assert.deepEqual(r, { status: want, values: {} });
    assert.doesNotThrow(() => validateCaptured(r));
  }
});

test('captureBody never throws (seeded fuzz)', () => {
  let seed = 0x5eed;
  const rand = n => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  const alphabet = "abAB09-._~*!'()[]%+=&;% é\n{\"";
  const types = [FORM, `${FORM}; charset=utf-8`, 'application/json', 'text/plain', undefined, 42];
  for (let i = 0; i < 5000; i++) {
    const body = Array.from({ length: 1 + rand(40) }, () => alphabet[rand(alphabet.length)]).join('');
    const buffer = Buffer.from(body, 'utf8');
    const type = types[rand(types.length)];
    const rawHeaders = [...(type === undefined ? [] : ['Content-Type', type]), ...(rand(8) === 0 ? ['Cookie', 'x'] : [])];
    const search = ['', '?a=1', undefined][rand(3)];
    let r;
    assert.doesNotThrow(() => { r = captureBody({ rawHeaders, buffer, bodyBytes: buffer.length, capture: { ...capture, pointers }, search, method: 'POST' }); }, body);
    assert.doesNotThrow(() => validateCaptured(r), JSON.stringify(r));
    if (r.status !== 'captured') assert.deepEqual(r.values, {});
  }
});

test('validateCaptured form records', () => {
  assert.doesNotThrow(() => validateCaptured({ status: 'captured', values: { '/a': text('1'), '/b': { type: 'absent' }, '/c': ambiguous } }));
  for (const s of FORM_STATUSES) assert.doesNotThrow(() => validateCaptured({ status: s, values: {} }));
  for (const s of FORM_STATUSES) assert.throws(() => validateCaptured({ status: s, values: { '/a': text('1') } }), /captured-values/);
  for (const values of [{ '/a': text('1'), '/b': { type: 'number', value: 1 } }, { '/a': ambiguous, '/b': { type: 'string', value: 'x' } }, { '/a': text('a'.repeat(201)) }, { '/a': text('4242424242424242') },
    { '/a': { type: 'unusable', reason: 'odd' } }, { '/a': { type: 'text', value: 5 } }, { '/a': { type: 'text', value: 'x', extra: 1 } }]) assert.throws(() => validateCaptured({ status: 'captured', values }), /captured-value/, JSON.stringify(values));
  for (const s of CAPTURE_STATUSES.filter(x => x !== 'captured')) assert.doesNotThrow(() => validateCaptured({ status: s, values: {} }));
  assert.doesNotThrow(() => validateCaptured({ status: 'captured', values: { '/a': { type: 'number', value: 1 }, '/b': { type: 'string', value: 'x' }, '/c': { type: 'unusable', reason: 'not-scalar' } } }));
});

test('captureEncodingOf and validCaptureForm', () => {
  assert.equal(captureEncodingOf({ status: 'form-query-or-cookie', values: {} }), 'form');
  assert.equal(captureEncodingOf({ status: 'captured', values: { '/a': text('1') } }), 'form');
  assert.equal(captureEncodingOf({ status: 'captured', values: { '/a': ambiguous } }), 'form');
  assert.equal(captureEncodingOf({ status: 'not-json', values: {} }), 'json-only');
  assert.equal(captureEncodingOf({ status: 'captured', values: { '/a': { type: 'number', value: 1 } } }), null);
  assert.equal(captureEncodingOf(undefined), null);
  const map = { 'pay.test': ['/amount'], 'mail.test': ['/a.b'] };
  assert.equal(validCaptureForm(['pay.test'], map), true);
  for (const list of [[], ['pay.test', 'pay.test'], ['other.test'], ['mail.test'], 'pay.test', [1]]) assert.equal(validCaptureForm(list, map), false, JSON.stringify(list));
  assert.equal(validCaptureForm(['pay.test'], null), false);
  assert.throws(() => validateFormPointer('/a.b'));
});

test('differential compat against b83051d', () => {
  const corpus = [['application/json', '{"amount":25,"currency":"cad"}'], ['application/vnd.x+json', '{"amount":25}'], ['application/json; charset=utf-8', '{"note":"x"}'], ['application/json; charset=latin1', '{"amount":1}'],
    ['application/json', '{"amount":1,"amount":2}'], ['application/json', '[' .repeat(40) + ']'.repeat(40)], ['application/json', '{"amount":'], ['application/json', '\xff\xfe'], ['application/json', '{"metadata":{"order_id":"A-1"}}'],
    ['application/json', '{"items":[{"price":3}]}'], ['application/json', 'amount=25'], [FORM, 'amount=25'], [FORM, '{"amount":25}'], ['text/plain', '{"amount":25}'], [undefined, '{"amount":25}'], ['multipart/form-data', 'x'],
    ['application/json', '{"note":"4242424242424242"}'], ['application/json', '{"amount":9007199254740993}'], ['application/json', `{"note":"${'a'.repeat(300)}"}`], ['application/json', '']];
  const caps = [jsonOnly, { pointers: capture.pointers, maxBytes: 1024 }];
  for (const [type, body] of corpus) for (const headers of [[], ['Content-Encoding', 'gzip']]) for (const cap of caps) {
    const buffer = Buffer.from(body, 'latin1');
    const input = { rawHeaders: [...(type === undefined ? [] : ['Content-Type', type]), ...headers], buffer, bodyBytes: buffer.length, capture: cap };
    const old = frozen.captureBody(input);
    // Absent fields (test/absent-fields.test.mjs): JSON reads as before for a request without a query (search ''); beside a query, or
    // when the caller gives none, a field missing from the body is recorded unusable ("absent-query"), never absent. Nothing else moves.
    const besideQuery = r => r.status !== 'captured' ? r : { ...r, values: Object.fromEntries(Object.entries(r.values).map(([p, v]) => [p, v.type === 'absent' ? { type: 'unusable', reason: 'absent-query' } : v])) };
    assert.deepEqual(captureBody({ ...input, search: '' }), old, `${type} ${body}`);
    assert.deepEqual(captureBody(input), besideQuery(old), `${type} ${body}`);
    assert.deepEqual(captureBody({ ...input, search: '?a=1' }), besideQuery(old));
    if (old.status !== 'not-json') assert.deepEqual(captureBody({ ...input, capture: { ...cap, encodings: ['json', 'form'] }, search: '?a=1' }), besideQuery(old), `form-enabled ${type} ${body}`);
  }
  const values = [{ type: 'number', value: 25 }, { type: 'string', value: '25' }, { type: 'boolean', value: true }, { type: 'null', value: null }, { type: 'absent' }, { type: 'unusable', reason: 'redacted' }];
  const operands = [['equals', 25], ['equals', '25'], ['equals', true], ['equals', null], ['in', [25, '25']], ['in', ['x']], ['gt', 10], ['gte', 25], ['lt', 30], ['lte', 1]];
  for (const v of values) for (const [op, x] of operands) for (const st of ['captured', 'not-json']) {
    const c = { status: st, values: st === 'captured' ? { '/amount': v } : {} };
    const now = fieldState(c, { pointer: '/amount', [op]: x }), was = frozen.fieldState(c, { pointer: '/amount', [op]: x });
    // The one intended change since (test/json-decimal-failopen.test.mjs): a JSON string now follows the form text rule, so the
    // numeric-looking "25" beside the string member "x" reads unknown, no longer "no". Every other reading is unchanged.
    if (st === 'captured' && v.type === 'string' && op === 'in' && x.includes('x')) assert.deepEqual([was, now], ['no', 'unknown']);
    else assert.equal(now, was, `${JSON.stringify(v)} ${op}`);
  }
});

test('scope captureForm: a subset of capture, validated by validateScope', async () => {
  const { validateScope } = await import('../src/effect-events.mjs');
  const base = { operations: ['send'], names: ['pay.test', 'mail.test'], actorAttribution: 'none', evidence: 'authoritative', capture: { 'pay.test': ['/amount'], 'mail.test': ['/to_name'] } };
  assert.doesNotThrow(() => validateScope(base));
  assert.doesNotThrow(() => validateScope({ ...base, captureForm: ['pay.test'] }));
  for (const captureForm of [[], ['pay.test', 'pay.test'], ['other.test'], 'pay.test']) assert.throws(() => validateScope({ ...base, captureForm }), /scope-capture-form/, JSON.stringify(captureForm));
  const { capture, ...noCapture } = base;
  assert.throws(() => validateScope({ ...noCapture, captureForm: ['pay.test'] }), /scope-capture-form/);
});

test('review hardening: POST only, non-ASCII needs charset=utf-8, controls and edge whitespace never decide a difference', () => {
  for (const method of ['GET', 'PUT', 'PATCH', 'DELETE', 'post', undefined]) assert.deepEqual(send('amount=5', { method }), { status: 'form-method', values: {} }, String(method));
  assert.equal(status('amount=5', { method: 'POST' }), 'captured');
  assert.equal(send('{"amount":5}', { type: 'application/json', method: 'GET' }).status, 'captured', 'the JSON path ignores the method');
  assert.deepEqual(at('note=%C3%A9', '/note'), ambiguous, 'no charset: a receiver may read the bytes as ISO-8859-1');
  assert.deepEqual(at('note=%C3%A9', '/note', { type: `${FORM}; charset="utf-8"` }), text('\u00e9'));
  assert.deepEqual(at('note=plain', '/note'), text('plain'), 'ASCII reads the same under either charset');
  for (const t of ['approved\u0000', 'approved\r', 'approved ', ' approved', 'approved\t']) {
    assert.equal(judge(t, 'equals', 'approved'), 'unknown', JSON.stringify(t));
    assert.equal(judge(t, 'in', ['approved', 'denied']), 'unknown', JSON.stringify(t));
    assert.equal(judge(t, 'equals', t), 'match');
  }
  assert.equal(judge('denied', 'equals', 'approved'), 'no');
});
