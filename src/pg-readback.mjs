// Postgres read-back (roadmap v2 item 2): what a pg-snapshot table's declared columns held at each mark, and the
// judgement of declared expectations over them. Pure: no I/O. integrations/observers/pg-snapshot.mjs reads the values
// inside its existing mark transaction and calls buildReadBackRecord at collect; judgeReadBack decides from that record
// alone, so a stored record can be judged again.
//
// Declaration (a pg-snapshot table's `readBack`):
//   columns    the value columns read back, by name: the allowlist. Nothing else is read as a value. 0 to 16 plain
//              identifiers, never the key column.
//   sensitive  each value column whose name reads as a secret or personal data (SENSITIVE below) must be listed here,
//              or the declaration is refused. Its values are kept only as digests salted by the observer (sealed)...
//   reveal     ...unless the operator lists it here too, which keeps them in clear.
//   remainder  'unchanged' (the default) or 'may-change': whether anything outside the declared values may change.
//   range      the key range the counts cover: { prefix } (text keys), { min?, max? } (integer keys, inclusive), or
//              { keys } (1 to 100 exact keys, so a count can name the very row it is about). An exact key is compared
//              as the key column's kind reads it (canonicalKey below): a uuid in either case, a char without trailing
//              spaces, an integer by its exact digits, a numeric as its exact decimal, a time in ISO 8601 UTC, text
//              exactly. A key column of any other kind, or a declared key its kind cannot read, leaves the counts
//              inconclusive: a key that can never equal what the column prints would make a count over it vacuous.
//   inserts, deletes
//              the exact number of keys inserted, and deleted, within the range between the two marks.
//   expect     per row key: { key, values: { column: value } } (the value at the end mark), and/or
//              { key, change: { column: { from, to } } } (the value at the start mark, and at the end mark).
//
// Values are read as text (no cast that could raise an error) and typed by the column's type (a domain reads as its base
// type): text (text, varchar), char (bpchar, compared without trailing spaces, as the type compares), uuid (as PostgreSQL
// prints it, lower case; an expectation in the 8-4-4-4-12 form, either case), numeric (int2, int4, int8, numeric, float4,
// float8; an exact decimal string, so 40.00 and 40 are equal; NaN and infinities are not decimals), boolean, timestamp,
// timestamptz and date (ISO 8601: 'T', and 'Z' for timestamptz; no infinity, no BC, four-digit years), and json (json and
// jsonb, parsed here; canonical JSON, the last of a repeated key kept as jsonb keeps it, and each number written as the
// exact decimal of its own text, never through a double). Any other type, or a virtual generated column, is refused. A
// declared numeric expectation written as a JSON number must be a safe integer; any other is a decimal string. A declared
// json expectation is JSON text (a string), read exactly as a stored value is read, so a 64-bit id is compared digit for
// digit; any other declared value on a json column is not canonical. An expected null is SQL NULL for every kind; the
// JSON value null is the JSON text 'null'.
//
// The remainder is one digest per table (sealed under the observer's salt) of everything not read as a value: for an
// expected row, its columns outside the declared ones; for each other row, its whole row (each a sha256 the database
// computes); rows inserted or deleted within the range are left to the counts. An expected row's declared columns that
// no expectation names are compared too. Under remainder 'unchanged' the table has a remainder check of its own, and a
// change there also leaves each pass of the table inconclusive. A table with an inheritance child holding a column its
// parent lacks is unusable ('descendant-columns'): a parent scan cannot see that column.
//
// Fail closed: a refused declaration never builds an observer. A missing column, a refused type, a virtual column, a
// table the window could not follow (identity, a violated table, a failed mark), a transaction in flight at the end
// mark, an unreadable value or expectation, or a forbidden remainder change makes the checks it touches inconclusive,
// never pass; a table that has no check of its own then gets one, inconclusive. A mismatch read from a usable row is a
// fail, and a fail stands.
//
// Memory: a mark keeps the values of the expected rows, and those of the other rows only within a small budget
// (otherValueChars); past it, counted rows are recorded without their values (rowValues 'over-budget'). The budget bounds
// what a mark keeps, not what it reads: the scan returns every declared value of every row (each cut at valueChars + 1
// characters) and the wire client holds the whole result, so a large table with wide declared columns can reach the
// statement timeout or the process memory. That fails the mark, and with it the window: never a pass.
//
// Custody: the database is one the application can write, so each reading is custody 'subject-writable'. A pass says
// so in its basis; a fail stands, as everywhere else.
import { createHmac } from 'node:crypto';
import { stable } from './domain.mjs';

export const PG_READBACK_SCHEMA = 'scopehaven-pg-readback/1';
export const PG_READBACK_VERDICT_SCHEMA = 'scopehaven-pg-readback-verdict/1';
export const READBACK_CUSTODY = 'subject-writable';
export const PG_READBACK_LIMITS = Object.freeze({ columns: 16, expectations: 100, valueChars: 4096, keyChars: 200, count: 100000, rangeKeys: 100, recordedRows: 20, jsonDepth: 32, jsonNodes: 1000, otherValueChars: 65536 });
const SEAL_LABEL = 'scopehaven-pg-readback-seal/1\n';

export class ReadBackError extends Error { constructor(code, where) { super(`Invalid pg read-back declaration: ${code}${where ? ` at ${where}` : ''}.`); this.name = 'ReadBackError'; this.code = code; } }
const fail = (code, where) => { throw new ReadBackError(code, where); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const own = (value, key) => Object.hasOwn(value, key);

// Built-in type oids (fixed across PostgreSQL versions) and the kind each reads as.
export const KIND_OF_TYPE = Object.freeze({ 25: 'text', 1043: 'text', 1042: 'char', 2950: 'uuid', 21: 'numeric', 23: 'numeric', 20: 'numeric', 1700: 'numeric', 700: 'numeric', 701: 'numeric',
  16: 'boolean', 1114: 'timestamp', 1184: 'timestamptz', 1082: 'date', 114: 'json', 3802: 'json' });
export const KINDS = Object.freeze(['text', 'char', 'uuid', 'numeric', 'boolean', 'timestamp', 'timestamptz', 'date', 'json']);
// A column's kind from its catalog row: a base type by oid, a domain by its base type (one level), anything else null.
export const kindOfColumn = ({ typid, typtype, basetype }) => typtype === 'b' ? KIND_OF_TYPE[typid] ?? null : typtype === 'd' ? KIND_OF_TYPE[basetype] ?? null : null;

// Column names that read as secrets or personal data, by word (snake_case and camelCase split) or, for the strongest
// words, anywhere in the name (useremail, dateofbirth). A false positive costs one line in the declaration; a miss
// would store a secret in clear.
const SENSITIVE_WORDS = new Set(['password', 'passwd', 'pwd', 'passcode', 'passphrase', 'pass', 'secret', 'secrets', 'token', 'tokens', 'apikey', 'credential', 'credentials',
  'auth', 'cookie', 'session', 'jwt', 'bearer', 'otp', 'mfa', 'totp', 'pin', 'salt', 'hash', 'hmac', 'signature', 'ssn', 'sin', 'nin', 'tin', 'taxid', 'passport', 'license', 'licence',
  'email', 'mail', 'phone', 'mobile', 'tel', 'telephone', 'fax', 'address', 'addr', 'street', 'city', 'zip', 'zipcode', 'postal', 'postcode', 'birth', 'birthday', 'birthdate', 'dob',
  'gender', 'ethnicity', 'race', 'religion', 'health', 'medical', 'diagnosis', 'card', 'pan', 'cvv', 'cvc', 'ccv', 'iban', 'bic', 'swift', 'routing', 'account', 'name', 'firstname',
  'lastname', 'surname', 'fullname', 'givenname', 'ip', 'ipaddr', 'latitude', 'longitude', 'lat', 'lng', 'geo', 'location', 'pw', 'hashed', 'cc', 'tok', 'acct']);
const SENSITIVE_PARTS = ['password', 'passwd', 'passcode', 'passphrase', 'secret', 'token', 'apikey', 'credential', 'email', 'phone', 'birth', 'creditcard', 'cardnumber', 'iban', 'cvv',
  'socialsecurity', 'passport', 'address', 'hash', 'salary'];
export const wordsOf = name => String(name).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
export const looksSensitive = name => { const words = wordsOf(name); return words.some(w => SENSITIVE_WORDS.has(w)) || SENSITIVE_PARTS.some(part => words.join('').includes(part)) || (words.includes('key') && words.some(w => ['api', 'private', 'secret', 'signing', 'access', 'encryption'].includes(w))); };

// An exact decimal string, or null: digits with an optional fraction and exponent (as float8out and JSON write them),
// written without exponent, leading zeros or trailing fraction zeros; -0 is 0. No NaN, infinity or hex.
export function decimalOf(text) {
  const m = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d{1,4}))?$/.exec(String(text));
  if (!m) return null;
  const digits = m[2] + (m[3] ?? ''), point = m[2].length + Number(m[4] ?? 0);
  if (point > 1000 || point < -1000) return null;
  let int, frac;
  if (point <= 0) { int = '0'; frac = '0'.repeat(-point) + digits; }
  else if (point >= digits.length) { int = digits + '0'.repeat(point - digits.length); frac = ''; }
  else { int = digits.slice(0, point); frac = digits.slice(point); }
  int = int.replace(/^0+(?=\d)/, ''); frac = frac.replace(/0+$/, '');
  const body = frac ? `${int}.${frac}` : int;
  return body === '0' ? '0' : `${m[1]}${body}`;
}

const validDate = (y, mo, d) => { const at = new Date(0); at.setUTCFullYear(y, mo - 1, d); return at.getUTCFullYear() === y && at.getUTCMonth() === mo - 1 && at.getUTCDate() === d; };
// Calendar and clock checked; the fraction loses its trailing zeros (PostgreSQL prints none).
function isoOf(date, time, fraction) {
  const [y, mo, d] = date.split('-').map(Number), [h, mi, s] = time ? time.split(':').map(Number) : [0, 0, 0];
  if (!validDate(y, mo, d) || h > 23 || mi > 59 || s > 59) return null;
  if (!time) return date;
  const f = (fraction ?? '').replace(/0+$/, '');
  return `${date}T${time}${f ? `.${f}` : ''}`;
}
// Read: as the mark's pinned DateStyle ISO and TimeZone UTC print them. Expected: ISO 8601 ('T' or a space), UTC only.
const READ_TIME = { timestamp: /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?$/, timestamptz: /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?\+00$/, date: /^(\d{4}-\d{2}-\d{2})$/ };
const EXPECTED_TIME = { timestamp: /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?$/, timestamptz: /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(?:Z|\+00:00|\+00)$/, date: /^(\d{4}-\d{2}-\d{2})$/ };

// JSON text -> canonical JSON, or null: keys sorted (as stable sorts them), the last of a repeated key kept (as jsonb keeps
// it), and each number written as the exact decimal of its own source text, never through a double, so 1234567890123456789
// and the 1234567890123456800 a double makes of it stay apart. Built bottom-up by the reviver; null past the node or
// depth limit, or longer than a value may be. The stored value and a declared json expectation are both read here.
class Canon { constructor(text, depth) { this.text = text; this.depth = depth; } }
export function canonicalJson(text) {
  if (typeof text !== 'string') return null;
  let nodes = 0, ok = true;
  const canon = (_, v, context) => {
    if (++nodes > PG_READBACK_LIMITS.jsonNodes || !ok) { ok = false; return new Canon('', 0); }
    let out;
    if (typeof v === 'number') { const d = typeof context?.source === 'string' ? decimalOf(context.source) : null; if (d === null) ok = false; out = new Canon(d ?? '', 0); }
    else if (v === null || typeof v !== 'object') out = new Canon(JSON.stringify(v), 0);
    else {
      const keys = Array.isArray(v) ? null : Object.keys(v).sort(), children = keys ? keys.map(k => v[k]) : v;
      if (!children.every(c => c instanceof Canon)) { ok = false; return new Canon('', 0); }
      const body = keys ? keys.map((k, i) => `${JSON.stringify(k)}:${children[i].text}`) : children.map(c => c.text);
      out = new Canon(keys ? `{${body.join(',')}}` : `[${body.join(',')}]`, 1 + children.reduce((n, c) => Math.max(n, c.depth), 0));
    }
    if (out.depth > PG_READBACK_LIMITS.jsonDepth || out.text.length > PG_READBACK_LIMITS.valueChars) ok = false;
    return out;
  };
  let root;
  try { root = JSON.parse(text, canon); } catch { return null; }
  return ok && root instanceof Canon ? root.text : null;
}
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, UUID_EXPECTED = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const jsonValue = value => {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(jsonValue);
  return plain(value) && Object.values(value).every(jsonValue);
};

// A value as read (the column's text output, or null for SQL NULL) -> { value } (string, boolean or null) or { error }.
// Each text arrived through pg-wire as UTF-8; a U+FFFD could stand for bytes that were not, so it is refused.
export function canonicalValue(kind, text) {
  if (text === null) return { value: null };
  if (typeof text !== 'string') return { error: 'value-unreadable' };
  if (text.length > PG_READBACK_LIMITS.valueChars) return { error: 'value-too-long' };
  if (['text', 'char', 'json'].includes(kind) && text.includes('\uFFFD')) return { error: 'value-not-canonical' };
  if (kind === 'text' || kind === 'char') return { value: text };
  if (kind === 'uuid') return UUID.test(text) ? { value: text } : { error: 'value-not-canonical' };
  if (kind === 'numeric') { const d = decimalOf(text); return d === null ? { error: 'value-not-decimal' } : { value: d }; }
  if (kind === 'boolean') return text === 'true' || text === 't' ? { value: true } : text === 'false' || text === 'f' ? { value: false } : { error: 'value-not-canonical' };
  if (READ_TIME[kind]) { const m = READ_TIME[kind].exec(text), iso = m && isoOf(m[1], m[2], m[3]); return iso ? { value: kind === 'timestamptz' ? `${iso}Z` : iso } : { error: 'value-not-canonical' }; }
  if (kind === 'json') { const c = canonicalJson(text); return c === null ? { error: 'value-not-canonical' } : { value: c }; }
  return { error: 'type-refused' };
}
// A declared expected value, read as the column's kind -> { value } or { error: 'expectation-not-canonical' }. null is
// SQL NULL for every kind.
export function canonicalExpected(kind, value) {
  const bad = { error: 'expectation-not-canonical' };
  if (value === null) return { value: null };
  // JSON text, read as the stored value is read: a JavaScript value has already passed its numbers through a double.
  if (kind === 'json') { const c = typeof value === 'string' ? canonicalJson(value) : null; return c === null ? bad : { value: c }; }
  if (kind === 'uuid') return typeof value === 'string' && UUID_EXPECTED.test(value) ? { value: value.toLowerCase() } : bad;
  if (kind === 'text') return typeof value === 'string' ? { value } : bad;
  if (kind === 'char') return typeof value === 'string' ? { value: value.replace(/ +$/, '') } : bad;
  // A JSON number past 2^53 has already been rounded, so only a safe integer is taken as a number.
  if (kind === 'numeric') { const d = typeof value === 'string' ? decimalOf(value) : Number.isSafeInteger(value) ? String(value) : null; return d === null ? bad : { value: d }; }
  if (kind === 'boolean') return typeof value === 'boolean' ? { value } : bad;
  if (EXPECTED_TIME[kind]) { const m = typeof value === 'string' && EXPECTED_TIME[kind].exec(value), iso = m && isoOf(m[1], m[2], m[3]); return iso ? { value: kind === 'timestamptz' ? `${iso}Z` : iso } : bad; }
  return bad;
}
// A sealed value: an HMAC under the observer's salt, so equal values compare equal within one observer and the value
// itself is never kept. The salt never leaves the observer.
export const sealWith = salt => (kind, value) => ({ sealed: createHmac('sha256', salt).update(`${SEAL_LABEL}${kind}\n${stable(value)}`).digest('hex') });
const sameValue = (a, b) => plain(a) || plain(b) ? plain(a) && plain(b) && typeof a.sealed === 'string' && a.sealed === b.sealed : a === b;
const errorOf = v => plain(v) && typeof v.error === 'string' ? v.error : null;

const keyText = k => typeof k === 'string' && k.length >= 1 && k.length <= PG_READBACK_LIMITS.keyChars && !/[\u0000]/.test(k);
const INTEGER = /^-?(0|[1-9]\d{0,18})$/;

// A key column's kind for an exact-key range (review m5): as kindOfColumn, with the integer types apart from numeric.
// float4 and float8 are refused (two spellings of one float can print differently), and so are boolean, json and every
// type outside this list (citext or inet, say, can hold keys that print differently but are one value).
const KEY_KIND_OF_TYPE = Object.freeze({ 25: 'text', 1043: 'text', 1042: 'char', 2950: 'uuid', 21: 'integer', 23: 'integer', 20: 'integer', 1700: 'numeric', 1114: 'timestamp', 1184: 'timestamptz', 1082: 'date' });
const KEY_KINDS = new Set(Object.values(KEY_KIND_OF_TYPE));
export const keyKindOfColumn = ({ typid, typtype, basetype }) => typtype === 'b' ? KEY_KIND_OF_TYPE[typid] ?? null : typtype === 'd' ? KEY_KIND_OF_TYPE[basetype] ?? null : null;
// A key, declared or as the key column prints it, in its kind's canonical form, or null when the kind cannot read it:
// text exactly, char without trailing spaces (as the type compares), a uuid in lower case (8-4-4-4-12, either case), an
// integer by its exact digits (no leading zero, plus sign or -0), a numeric as its exact decimal, and a time as ISO 8601
// in UTC (as an expected value is read).
export function canonicalKey(kind, text) {
  if (typeof text !== 'string') return null;
  if (kind === 'text') return text;
  if (kind === 'char') return text.replace(/ +$/, '');
  if (kind === 'uuid') return UUID_EXPECTED.test(text) ? text.toLowerCase() : null;
  if (kind === 'integer') return INTEGER.test(text) && text !== '-0' ? text : null;
  if (kind === 'numeric') return decimalOf(text);
  if (EXPECTED_TIME[kind]) return canonicalExpected(kind, text).value ?? null;
  return null;
}
// The declaration, checked and normalized; key is the table's key column.
export function validateReadBack(rb, { key, where = 'readBack' } = {}) {
  if (!plain(rb) || Object.keys(rb).some(k => !['columns', 'sensitive', 'reveal', 'remainder', 'range', 'inserts', 'deletes', 'expect'].includes(k))) fail('readback-shape', where);
  const columns = rb.columns ?? [];
  if (!Array.isArray(columns) || columns.length > PG_READBACK_LIMITS.columns || !columns.every(c => typeof c === 'string' && IDENT.test(c))) fail('column-identifier', where);
  if (new Set(columns).size !== columns.length) fail('column-repeated', where);
  if (columns.includes(key)) fail('column-is-key', where);
  const list = (name, within, code) => {
    const v = rb[name] ?? [];
    if (!Array.isArray(v) || new Set(v).size !== v.length || !v.every(c => within.includes(c))) fail(code, where);
    return v;
  };
  const sensitive = list('sensitive', columns, 'sensitive-not-column'), reveal = list('reveal', sensitive, 'reveal-not-sensitive');
  const undeclared = columns.find(c => looksSensitive(c) && !sensitive.includes(c));
  if (undeclared !== undefined) fail('sensitive-undeclared', `${where} > ${undeclared}`);
  const remainder = rb.remainder ?? 'unchanged';
  if (!['unchanged', 'may-change'].includes(remainder)) fail('remainder-policy', where);
  let range = null;
  if (own(rb, 'range')) {
    const r = rb.range;
    if (plain(r) && Object.keys(r).length === 1 && typeof r.prefix === 'string' && r.prefix.length >= 1 && r.prefix.length <= PG_READBACK_LIMITS.keyChars) range = { prefix: r.prefix };
    else if (plain(r) && Object.keys(r).length === 1 && Array.isArray(r.keys) && r.keys.length >= 1 && r.keys.length <= PG_READBACK_LIMITS.rangeKeys && r.keys.every(keyText)
      && new Set(r.keys).size === r.keys.length) range = { keys: Object.freeze([...r.keys]) };
    else if (plain(r) && Object.keys(r).length >= 1 && Object.keys(r).every(k => ['min', 'max'].includes(k)) && Object.values(r).every(v => typeof v === 'string' && INTEGER.test(v))
      && !(r.min !== undefined && r.max !== undefined && BigInt(r.min) > BigInt(r.max))) range = { ...(r.min === undefined ? {} : { min: r.min }), ...(r.max === undefined ? {} : { max: r.max }) };
    else fail('range-shape', where);
  }
  const count = name => { if (!own(rb, name)) return null; const n = rb[name]; if (!Number.isSafeInteger(n) || n < 0 || n > PG_READBACK_LIMITS.count) fail('count-shape', `${where} > ${name}`); return n; };
  const inserts = count('inserts'), deletes = count('deletes');
  const expect = rb.expect ?? [];
  if (!Array.isArray(expect) || expect.length > PG_READBACK_LIMITS.expectations) fail('expect-shape', where);
  const keys = new Set(), entries = [];
  expect.forEach((e, i) => {
    const at = `${where} > expect ${i + 1}`;
    if (!plain(e) || Object.keys(e).some(k => !['key', 'values', 'change'].includes(k)) || (!own(e, 'values') && !own(e, 'change'))) fail('expect-shape', at);
    if (!keyText(e.key)) fail('expect-key', at);
    if (keys.has(e.key)) fail('expect-key-repeated', at);
    keys.add(e.key);
    const named = new Set();
    const name = c => { if (!columns.includes(c)) fail('column-undeclared', `${at} > ${c}`); if (named.has(c)) fail('expect-column-repeated', `${at} > ${c}`); named.add(c); };
    for (const part of ['values', 'change']) if (own(e, part) && (!plain(e[part]) || !Object.keys(e[part]).length)) fail('expect-shape', at);
    for (const [c, v] of Object.entries(e.values ?? {})) { name(c); if (!jsonValue(v)) fail('expect-value', `${at} > ${c}`); entries.push({ key: e.key, column: c, mode: 'value', to: v }); }
    for (const [c, ch] of Object.entries(e.change ?? {})) {
      name(c);
      if (!plain(ch) || Object.keys(ch).sort().join(',') !== 'from,to' || !jsonValue(ch.from) || !jsonValue(ch.to)) fail('expect-value', `${at} > ${c}`);
      entries.push({ key: e.key, column: c, mode: 'change', from: ch.from, to: ch.to });
    }
  });
  if (!columns.length && inserts === null && deletes === null) fail('nothing-declared', where);
  return Object.freeze({ columns: Object.freeze([...columns]), sensitive: Object.freeze([...sensitive]), reveal: Object.freeze([...reveal]), remainder, range: range && Object.freeze(range), inserts, deletes, expect: Object.freeze(entries.map(Object.freeze)) });
}

// true, false, or null when an integer range meets a key that is not an integer. An exact-key range compares the key
// text; placerOf gives it keys already canonical for the key column's kind.
export function inRange(range, key) {
  if (range === null) return true;
  if (range.prefix !== undefined) return key.startsWith(range.prefix);
  if (range.keys !== undefined) return range.keys.includes(key);
  if (!INTEGER.test(key)) return null;
  const k = BigInt(key);
  return (range.min === undefined || k >= BigInt(range.min)) && (range.max === undefined || k <= BigInt(range.max));
}
// Where a changed key falls (true, false, or null when it cannot be placed), and why no key can be placed. An exact-key
// range is compared as the key column's kind reads both sides (review m5), so an upper-case uuid names the row
// PostgreSQL prints in lower case. A key column of another kind, or a declared key its kind cannot read, is refused.
export function placerOf(range, keyKind) {
  if (range?.keys === undefined) return { place: k => inRange(range, k), refused: null };
  if (!KEY_KINDS.has(keyKind)) return { place: () => null, refused: 'range-key-type-refused' };
  const keys = range.keys.map(k => canonicalKey(keyKind, k));
  if (keys.includes(null)) return { place: () => null, refused: 'range-key-not-canonical' };
  return { place: k => { const c = canonicalKey(keyKind, k); return c === null ? null : inRange({ keys }, c); }, refused: null };
}

// The record of one window for each declared read-back table.
//   status: 'ok', or the reason the window decides nothing (a failed mark, identity, an in-flight transaction).
//   tables: [{ name, schema, decl, violated, before, after }]: before/after are the marks' table maps (key -> { hash }) with
//           .readBack = { status, columns: [{ name, kind, sealed }], keyKind (keyKindOfColumn of the key column), rows: Map key -> { values: { column: value | { sealed } | { error } }, rest },
//           shas: Map key -> the row's sha256, othersKept } (value: the canonical string, boolean or null; rows holds the
//           expected rows, and the others only when othersKept).
//   seal:   the observer's seal function, for sealed columns' expectations and the remainder.
export function buildReadBackRecord({ status, tables, seal }) {
  return { schema: PG_READBACK_SCHEMA, custody: READBACK_CUSTODY, status, tables: tables.map(t => tableRecord(t, status, seal)) };
}
function tableRecord({ name, schema, decl, violated, before, after }, status, seal) {
  const base = { name, schema, remainderPolicy: decl.remainder, range: decl.range, expected: { inserts: decl.inserts, deletes: decl.deletes } };
  const pending = decl.expect.map(e => ({ key: e.key, column: e.column, mode: e.mode }));
  const unusable = reason => ({ ...base, status: reason, columns: decl.columns.map(c => ({ name: c, kind: null, sealed: !decl.reveal.includes(c) && decl.sensitive.includes(c) })), counts: null, remainder: null, rows: [], rowsOmitted: 0, expect: pending });
  if (status !== 'ok') return unusable(status);
  if (violated) return unusable('table-violated');
  const a = before.readBack, b = after.readBack;
  if (!a || !b) return unusable('read-back-missing');
  if (a.status !== 'ok') return unusable(a.status);
  if (b.status !== 'ok') return unusable(b.status);
  if (stable(a.columns) !== stable(b.columns)) return unusable('columns-changed');
  const kinds = new Map(b.columns.map(c => [c.name, c]));
  const expectedKeys = new Set(decl.expect.map(e => e.key));
  // Counts: keys inserted and deleted within the range. A refused exact-key range, or a changed key the range cannot
  // place, makes the counts unusable.
  const inserted = [...after.keys()].filter(k => !before.has(k)), deleted = [...before.keys()].filter(k => !after.has(k));
  const { place, refused } = placerOf(decl.range, a.keyKind === b.keyKind ? b.keyKind : null);
  const placed = k => place(k) === true;
  const counts = refused ? { status: refused, inserted: null, deleted: null }
    : [...inserted, ...deleted].some(k => place(k) === null) ? { status: decl.range?.keys ? 'range-key-not-canonical' : 'range-key-not-integer', inserted: null, deleted: null }
    : { status: 'ok', inserted: inserted.filter(placed).length, deleted: deleted.filter(placed).length };
  // Rows a declared count decides leave the remainder; any other insert or delete stays in it.
  const countedOut = new Set([...(decl.inserts === null ? [] : inserted), ...(decl.deletes === null ? [] : deleted)].filter(placed));
  // The remainder: per mark, each row outside the expectations whole, each expected row by its undeclared columns. Sealed
  // like a sensitive value, so a small table's remainder cannot be guessed back to an undeclared column's value.
  const remainderOf = (map, rb) => seal('remainder', [...map.keys()].filter(k => !countedOut.has(k)).sort((x, y) => (x < y ? -1 : x > y ? 1 : 0))
    .map(k => (expectedKeys.has(k) ? [k, 'rest', rb.rows.get(k)?.rest ?? null] : [k, 'row', rb.shas.get(k) ?? null]))).sealed;
  // An expected row's declared columns that no expectation names: compared like the remainder.
  const namedBy = new Map();
  for (const e of decl.expect) namedBy.set(e.key, new Set([...(namedBy.get(e.key) ?? []), e.column]));
  let unnamed = 'same';
  for (const k of expectedKeys) {
    const x = a.rows.get(k), y = b.rows.get(k);
    if (!x || !y) continue;
    for (const c of decl.columns) {
      if (namedBy.get(k).has(c)) continue;
      if (errorOf(x.values[c]) || errorOf(y.values[c])) { if (unnamed === 'same') unnamed = 'unreadable'; }
      else if (!sameValue(x.values[c], y.values[c])) unnamed = 'changed';
    }
  }
  const valuesOf = row => (row ? Object.fromEntries(decl.columns.map(c => [c, row.values[c]])) : null);
  const recorded = [...expectedKeys, ...[...countedOut].sort()].filter((k, i, all) => all.indexOf(k) === i);
  // Each expected row is recorded; counted rows up to the limit.
  const rows = recorded.slice(0, expectedKeys.size + PG_READBACK_LIMITS.recordedRows).map(k => ({ key: k, before: valuesOf(a.rows.get(k)), after: valuesOf(b.rows.get(k)) }));
  const expect = decl.expect.map(e => {
    const col = kinds.get(e.column);
    const read = v => { const c = canonicalExpected(col.kind, v); return c.error ? c : col.sealed ? seal(col.kind, c.value) : c.value; };
    return { key: e.key, column: e.column, mode: e.mode, ...(e.mode === 'change' ? { from: read(e.from) } : {}), to: read(e.to) };
  });
  return { ...base, status: 'ok', columns: b.columns, counts, remainder: { before: remainderOf(before, a), after: remainderOf(after, b), unnamed }, rows, rowsOmitted: recorded.length - rows.length,
    rowValues: a.othersKept && b.othersKept ? 'kept' : 'over-budget', expect };
}

// A stored record's shape, before anything in it is read.
const readableTable = t => plain(t) && typeof t.name === 'string' && typeof t.status === 'string' && ['unchanged', 'may-change'].includes(t.remainderPolicy) && plain(t.expected)
  && Array.isArray(t.expect) && t.expect.every(plain) && Array.isArray(t.rows) && t.rows.every(plain) && (t.status !== 'ok' || (plain(t.counts) && plain(t.remainder)));
// The verdict over one record: each expectation, each declared count and each guarded remainder, each pass, fail or
// inconclusive with its reason. A table that cannot be decided always contributes a check, so it can never be skipped.
export function judgeReadBack(record) {
  if (!plain(record) || record.schema !== PG_READBACK_SCHEMA || typeof record.status !== 'string' || !Array.isArray(record.tables) || !record.tables.every(readableTable))
    return verdictOf([{ check: 'record', status: 'inconclusive', reason: 'record-unreadable' }]);
  const checks = [];
  for (const t of record.tables) {
    const blocked = record.status !== 'ok' ? record.status : t.status !== 'ok' ? t.status : null;
    let tableChecks = [];
    for (const e of t.expect) {
      const c = { table: t.name, check: e.mode, key: e.key, column: e.column };
      if (blocked) { tableChecks.push({ ...c, status: 'inconclusive', reason: blocked }); continue; }
      const row = t.rows.find(r => r.key === e.key);
      const at = (side, column) => (row?.[side] ? row[side][column] : undefined);
      const before = at('before', e.column), after = at('after', e.column);
      if (e.mode === 'change') {
        if (before === undefined) { tableChecks.push({ ...c, status: 'inconclusive', reason: 'precondition-row-absent' }); continue; }
        const problem = errorOf(before) ?? errorOf(e.from);
        if (problem) { tableChecks.push({ ...c, status: 'inconclusive', reason: problem }); continue; }
        if (!sameValue(before, e.from)) { tableChecks.push({ ...c, status: 'inconclusive', reason: 'precondition-not-held' }); continue; }
      }
      if (after === undefined) { tableChecks.push({ ...c, status: 'fail', reason: 'row-absent' }); continue; }
      const problem = errorOf(after) ?? errorOf(e.to);
      if (problem) { tableChecks.push({ ...c, status: 'inconclusive', reason: problem }); continue; }
      tableChecks.push(sameValue(after, e.to) ? { ...c, status: 'pass', reason: null } : { ...c, status: 'fail', reason: e.mode === 'change' ? 'change-mismatch' : 'value-mismatch' });
    }
    for (const kind of ['inserts', 'deletes']) {
      const want = t.expected[kind];
      if (want === null) continue;
      const c = { table: t.name, check: kind, expected: want };
      if (blocked) { tableChecks.push({ ...c, status: 'inconclusive', reason: blocked }); continue; }
      if (t.counts.status !== 'ok') { tableChecks.push({ ...c, status: 'inconclusive', reason: t.counts.status }); continue; }
      const seen = kind === 'inserts' ? t.counts.inserted : t.counts.deleted;
      tableChecks.push(seen === want ? { ...c, observed: seen, status: 'pass', reason: null } : { ...c, observed: seen, status: 'fail', reason: `${kind}-mismatch` });
    }
    if (blocked) { if (!tableChecks.length) tableChecks.push({ table: t.name, check: 'table', status: 'inconclusive', reason: blocked }); }
    else if (t.remainderPolicy === 'unchanged') {
      // Anything outside the declared values that moved, or could not be read: the remainder check, and each pass of the
      // table, read inconclusive; a fail stands.
      const moved = t.remainder.before !== t.remainder.after || t.remainder.unnamed === 'changed' ? 'remainder-changed' : t.remainder.unnamed !== 'same' ? 'remainder-unreadable' : null;
      tableChecks = tableChecks.map(c => (moved && c.status === 'pass' ? { ...c, status: 'inconclusive', reason: moved } : c));
      tableChecks.push({ table: t.name, check: 'remainder', status: moved ? 'inconclusive' : 'pass', reason: moved });
    }
    checks.push(...tableChecks);
  }
  return verdictOf(checks);
}
function verdictOf(checks) {
  const verdict = !checks.length ? 'inconclusive' : checks.some(c => c.status === 'fail') ? 'fail' : checks.every(c => c.status === 'pass') ? 'pass' : 'inconclusive';
  const reasons = checks.length ? [...new Set(checks.filter(c => c.status !== 'pass').map(c => c.reason))].sort() : ['no-expectation'];
  const basis = verdict === 'pass'
    ? `each declared check held in the database read inside each mark's snapshot transaction; the application can write that database (custody ${READBACK_CUSTODY})`
    : verdict === 'fail' ? 'a declared check did not hold in the database read inside each mark\'s snapshot transaction; a fail stands whatever the custody'
      : 'some declared check could not be decided from the database read';
  return { schema: PG_READBACK_VERDICT_SCHEMA, verdict, custody: READBACK_CUSTODY, reasons, checks, basis };
}
