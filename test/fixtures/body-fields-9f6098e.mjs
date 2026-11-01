// Frozen copy of scopehaven/src/body-fields.mjs at 9f6098e (main before form decimals), for test/form-decimals.test.mjs. Not in any identity list.
// Declared body-field capture for the egress recorder (W1). Pure: no I/O.
//
// By default an egress sink keeps a request body only as a salted digest, so a check cannot tell a
// refund of 25 from one of 250. A destination may declare `capture`: a short list of JSON pointers
// to scalar fields of its JSON request bodies. Only those fields are read, only for that destination,
// and only as typed scalars; the whole body is never kept. Nothing is captured without a declaration.
//
// Privacy rules, enforced at validation so a profile fails loudly instead of capturing quietly:
//   - a pointer whose tokens name a secret-like key is refused, also as an interior token (/card/last4
//     is refused). A token is first folded with NFKC (fullwidth letters become ASCII); a token that still
//     holds a character outside printable ASCII (a Cyrillic or Greek lookalike) is refused outright. A
//     token is refused when, lowercased with everything outside [a-z0-9] dropped, it contains one of
//     DENIED_KEY_PARTS; or when one of its words (split at separators, camelCase humps
//     and letter/digit boundaries) equals one of DENIED_KEY_WORDS, or equals, starts with or ends with
//     one of DENIED_KEY_WORD_EDGES (customer_ssn, ssnLast4, pinCode, user_pin, cc_number, acctNo), unless
//     the word is one of the ordinary words in DENIED_WORD_EXCEPTIONS (single, since, span, ping).
//     Refusing too much is accepted.
//   - a captured string over CAPTURE_BOUNDS.stringChars is unusable (never truncated), and a value shaped
//     like a secret or a personal identifier (a JWT, a provider key, an AWS access key id, a bearer, basic
//     or token authorization value, a PEM block, a long hex/base64 run, a Luhn-valid 13 to 19 digit run
//     (any one separator between digit groups) that may be a card number, or a nine-digit NNN-NN-NNNN identifier, with any one separator character
//     between digit groups or none) is unusable with reason "redacted" and is not stored. Strings are
//     checked after NFKC folding, and one holding a decimal digit outside 0-9 is redacted. An integer of
//     13 to 19 digits that passes the Luhn check is redacted too.
//   - objects and arrays are never captured; a number outside the safe integer range (beyond
//     Number.MAX_SAFE_INTEGER in magnitude, where JSON numbers silently round) is unusable.
// Capture applies only to requests on one of the destination's declared paths (a destination that declares
// capture must declare paths); a send on any other path of that host records status "path-undeclared".
// What cannot be read reads unknown, never absent: a body that is not JSON, compressed, over the
// capture cap, invalid, too deep or with a repeated key leaves every declared field unknown.
//
// Matching: a selector's `fields` entries ({ pointer, equals | in | gt | gte | lt | lte }) are judged
// three-valued by fieldState: match, no, or unknown (the field could not be read, or its type does not
// fit the operand: the string "250" never equals the number 250, and never reads as "no").
// A string, JSON or form, matches a string operand only as exact text, and differs ('no') only where no common receiver reading makes
// the two one value (stringState): "105.50" against "105.5", "1e2" against "100", "refund " or "Refund" against "refund", "yes"
// against "true" and "105.50 USD" against "105.5 USD" stay unknown.
// An `in` member of another type reads unknown (a receiver that coerces may read "105.50" as 105.5, or "true" as true), except a
// string beside a number that no reading makes equal, which is set aside (crossState).
//
// Form bodies (opt-in per destination with capture.encodings ["json", "form"]): a destination may also have
// its declared fields read from application/x-www-form-urlencoded bodies, as exact text. A field is read only
// when the request has no URL query and no Cookie header (some receivers merge them over body fields) and the
// whole body parses with no ambiguity a mainstream server parser could resolve differently (see captureForm).
// Every other case leaves every declared field unknown. A text value reads as a number only when it is a
// canonical integer of at most 15 digits, and never as a boolean or null (see textState).

export const CAPTURE_BOUNDS = Object.freeze({ pointersPerDestination: 16, pointersPerRecorder: 64, pointerChars: 256, pointerTokens: 8,
  maxBytes: Object.freeze([1024, 65536]), defaultMaxBytes: 16384, stringChars: 200, depth: 32, fieldsPerSelector: 8, inValues: 32 });
export const CAPTURE_STATUSES = Object.freeze(['path-undeclared', 'no-body', 'content-type-ambiguous', 'not-json', 'encoded', 'over-cap', 'json-invalid', 'json-too-deep', 'json-duplicate-key', 'captured']);
export const UNUSABLE_REASONS = Object.freeze(['not-scalar', 'value-over-cap', 'number-unsafe', 'redacted']);
export const FIELD_OPERATORS = Object.freeze(['equals', 'in', 'gt', 'gte', 'lt', 'lte']);
// A token containing any of these (after normalisation) is refused.
export const DENIED_KEY_PARTS = Object.freeze(['password', 'passwd', 'passphrase', 'passcode', 'passport', 'pwd', 'pswd', 'pword', 'secret', 'token', 'authorization', 'bearer', 'cookie', 'session', 'csrf', 'xsrf', 'jwt', 'hmac', 'signature', 'apikey', 'accesskey', 'privatekey', 'privkey', 'signingkey', 'credential', 'card', 'cvv', 'cvc', 'ccnum', 'securitycode', 'securityanswer', 'securityquestion', 'iban', 'accountnum', 'accountno', 'acctnum', 'acctno', 'bankaccount', 'routingnum', 'sortcode', 'ssn', 'socialsecurity', 'socialinsurance', 'nationalid', 'nationalinsurance', 'taxid', 'taxpayer', 'dateofbirth', 'birthdate', 'birthday', 'driverslicense', 'driverlicense', 'mfa', '2fa', 'twofactor', 'totp', 'hotp', 'onetimepass', 'onetimecode', 'recoverycode', 'backupcode', 'seedphrase', 'mnemonic']);
// A word of a token equal to any of these is refused.
export const DENIED_KEY_WORDS = Object.freeze(['cc', 'ccn', 'pass', 'pw', 'key', 'keys', 'sid', 'sig', 'dob', 'tin', 'ein', 'nin', 'tfa', 'otc']);
// A word of a token equal to, starting with or ending with any of these is refused (unless it is an excepted word).
export const DENIED_KEY_WORD_EDGES = Object.freeze(['pan', 'pin', 'ssn', 'sin', 'cvv', 'cvc', 'otp', 'auth', 'acct']);
// Ordinary words an edge would otherwise catch.
export const DENIED_WORD_EXCEPTIONS = Object.freeze(['span', 'spin', 'japan', 'ping', 'pinned', 'pinyin', 'pane', 'panel', 'panels', 'pantry', 'pandas', 'single', 'since', 'sink', 'basin', 'cousin', 'raisin', 'casino', 'author', 'authors', 'authority', 'authored']);
const UNSAFE_TOKENS = ['__proto__', 'prototype', 'constructor'];
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

// Form-encoded bodies. Bounds: 1000 pairs (qs/body-parser parameterLimit and PHP max_input_vars, past which
// receivers truncate), 512-character keys, 32 key segments, 6 pointer tokens (qs keeps brackets past depth 5
// as one literal key) and 15-digit integers (exact below 2^53).
export const CAPTURE_ENCODINGS = Object.freeze(['json', 'form']);
export const FORM_BOUNDS = Object.freeze({ pairs: 1000, keyChars: 512, segments: 32, tokens: 6, integerDigits: 15 });
export const FORM_STATUSES = Object.freeze(['not-json-or-form', 'form-media-type', 'form-method', 'form-query-or-cookie', 'form-invalid', 'form-key-ambiguous', 'form-duplicate-key', 'form-too-deep', 'form-over-cap']);
export const FORM_UNUSABLE_REASONS = Object.freeze(['ambiguous']);
// Object.prototype's own names plus 'prototype', compared lowercased: qs drops such keys, shifting array siblings.
const PROTO_NAMES = ['__proto__', 'prototype', 'constructor', '__definegetter__', '__definesetter__', '__lookupgetter__', '__lookupsetter__', 'hasownproperty', 'isprototypeof', 'propertyisenumerable', 'tolocalestring', 'tostring', 'valueof'];
// The raw bytes a serializer may leave unescaped, plus the % + = & syntax. Raw ';', space, controls and non-ASCII are refused.
const FORM_RAW = /^[A-Za-z0-9\-._~*!'()[\]%+=&]*$/;
const FORM_KEY = /^([^[\]]+)((?:\[[^[\]]*\])*)$/;
const FORM_KEY_CHARS = /^[!-~]+$/;
const FORM_KEY_DENIED = /[.%+]/;
const INDEX = /^(0|[1-9][0-9]{0,8})$/;
const DIGITS = /^[0-9]+$/;
const FORM_INTEGER = /^(0|-?[1-9][0-9]{0,14})$/;
const INT_READING = /^\s*([+-]?)(0|[1-9][0-9]{0,14})\s*$/;
const LOOSE_NUMERIC = /^[+-]?(?:0[xXoObB][0-9a-fA-F_]+|(?=[0-9.,_']*[0-9])[0-9.,_']+(?:[eE][+-]?[0-9]+)?)$/;
export const formEnabled = capture => Array.isArray(capture?.encodings) && capture.encodings.includes('form');

const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const folded = token => token.normalize('NFKC');
const normalised = token => folded(token).toLowerCase().replace(/[^a-z0-9]/g, '');
// The words of a key: split at anything outside [A-Za-z0-9], at camelCase humps and at letter/digit boundaries.
export const keyWords = token => token.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/([A-Z])([A-Z][a-z])/g, '$1 $2').replace(/([A-Za-z])([0-9])/g, '$1 $2').replace(/([0-9])([A-Za-z])/g, '$1 $2')
  .toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
const deniedWord = word => DENIED_KEY_WORDS.includes(word) || (!DENIED_WORD_EXCEPTIONS.includes(word) && DENIED_KEY_WORD_EDGES.some(edge => word.startsWith(edge) || word.endsWith(edge)));
// A token is folded with NFKC first; one still holding a character outside printable ASCII cannot be vetted and is refused.
export const deniedToken = token => { const f = folded(token); if (/[^\x20-\x7e]/.test(f)) return true; const n = normalised(token); return DENIED_KEY_PARTS.some(part => n.includes(part)) || keyWords(f).some(deniedWord); };

// The tokens of a declared capture pointer (RFC 6901), or a thrown Error naming the rule.
export function pointerTokens(pointer) {
  if (typeof pointer !== 'string' || pointer === '' || !pointer.startsWith('/') || pointer.length > CAPTURE_BOUNDS.pointerChars || /[\u0000-\u001f\u007f]/.test(pointer) || /~(?![01])/.test(pointer)) throw new Error('a capture pointer is a JSON pointer of 1 to 256 characters starting with "/" (the whole body is never captured)');
  const tokens = pointer.slice(1).split('/').map(token => token.replaceAll('~1', '/').replaceAll('~0', '~'));
  if (tokens.length > CAPTURE_BOUNDS.pointerTokens) throw new Error('a capture pointer has at most 8 tokens');
  if (tokens.some(token => UNSAFE_TOKENS.includes(token))) throw new Error('a capture pointer cannot name __proto__, prototype or constructor');
  return tokens;
}
const SECRET_POINTER = 'a capture pointer names a secret-like key (password, passcode, pw or pwd, token, secret, authorization or auth, cookie, session or sid, csrf, jwt, hmac or signature, key, credential, card or cc, cvv, iban, account or routing number, pan, pin, otp, mfa or 2fa, ssn, sin, tax or national id, date of birth, passport) or holds a character outside ASCII after NFKC folding; such fields are never captured';
// A declared pointer: valid, and naming no secret-like key at any depth.
export function validatePointer(pointer) {
  const tokens = pointerTokens(pointer);
  if (tokens.some(deniedToken)) throw new Error(SECRET_POINTER);
  return tokens;
}
// A declared pointer that is also read from form bodies: at most 6 tokens, each a form key segment (printable
// ASCII without . [ ] % +, a canonical index when all digits, no Object.prototype name), and the flattened key
// t0[t1]..[tn] passes the deny-list too (so /se/cret is refused).
export function validateFormPointer(pointer) {
  const tokens = validatePointer(pointer);
  if (tokens.length > FORM_BOUNDS.tokens) throw new Error('a capture pointer read from form bodies has at most 6 tokens');
  if (!tokens.every(t => FORM_KEY_CHARS.test(t) && !/[.[\]%+]/.test(t) && (!DIGITS.test(t) || INDEX.test(t)) && !PROTO_NAMES.includes(t.toLowerCase()))) throw new Error('a capture pointer read from form bodies uses keys of printable ASCII without ".", "[", "]", "%" or "+", indices without leading zeros, and no Object.prototype member name');
  if (deniedToken(tokens[0] + tokens.slice(1).map(t => `[${t}]`).join(''))) throw new Error(SECRET_POINTER);
  return tokens;
}
// A destination's `capture`: { pointers, maxBytes?, encodings? }. Returns the normalized declaration:
// { pointers, maxBytes }, plus encodings ['json', 'form'] when form bodies are read too.
export function validateCaptureDeclaration(capture, maxBodyBytes) {
  if (!plain(capture) || Object.keys(capture).some(key => !['pointers', 'maxBytes', 'encodings'].includes(key))) throw new Error('a destination\'s "capture" is { pointers, maxBytes? }, optionally with "encodings": ["json", "form"]');
  const { pointers, encodings } = capture;
  if (!Array.isArray(pointers) || pointers.length < 1 || pointers.length > CAPTURE_BOUNDS.pointersPerDestination || new Set(pointers).size !== pointers.length) throw new Error('"capture.pointers" lists 1 to 16 distinct JSON pointers');
  if (Object.hasOwn(capture, 'encodings') && !(Array.isArray(encodings) && encodings.length >= 1 && encodings.length <= 2 && new Set(encodings).size === encodings.length && encodings.every(e => CAPTURE_ENCODINGS.includes(e)) && encodings.includes('json'))) throw new Error('"capture.encodings" lists "json" and optionally "form" (JSON bodies are always read)');
  const form = Array.isArray(encodings) && encodings.includes('form');
  pointers.forEach(validatePointer);
  if (form) pointers.forEach(validateFormPointer);
  const maxBytes = capture.maxBytes ?? Math.min(CAPTURE_BOUNDS.defaultMaxBytes, maxBodyBytes);
  if (!Number.isInteger(maxBytes) || maxBytes < CAPTURE_BOUNDS.maxBytes[0] || maxBytes > CAPTURE_BOUNDS.maxBytes[1] || maxBytes > maxBodyBytes) throw new Error('"capture.maxBytes" is an integer from 1024 to 65536 and no more than the recorder\'s maxBodyBytes');
  return form ? { pointers: [...pointers], maxBytes, encodings: ['json', 'form'] } : { pointers: [...pointers], maxBytes };
}

// A published capture map { [name]: [pointer, ...] } (an observer scope, or a run's declared observer record):
// 1 to 64 names, each with 1 to 16 distinct valid pointers, at most 64 pointers in all.
export function validCaptureMap(map) {
  if (!plain(map)) return false;
  const entries = Object.entries(map);
  if (entries.length < 1 || entries.length > CAPTURE_BOUNDS.pointersPerRecorder || entries.reduce((n, [, list]) => n + (Array.isArray(list) ? list.length : 0), 0) > CAPTURE_BOUNDS.pointersPerRecorder) return false;
  return entries.every(([name, list]) => typeof name === 'string' && name.length >= 1 && name.length <= 253 && Array.isArray(list) && list.length >= 1 && list.length <= CAPTURE_BOUNDS.pointersPerDestination
    && new Set(list).size === list.length && list.every(p => { try { validatePointer(p); return true; } catch { return false; } }));
}

// The number of keys a JSON text names at any depth: each string token followed by a colon (the same
// counter as integrations/observers/payments-double.mjs). JSON.parse keeps only the last of a repeated
// key, and the receiving service may keep the first, so a repeated key makes the body unreadable.
const COLON = /\s*:/y;
export function countKeyTokens(text) {
  let keys = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== '"') continue;
    let j = i + 1;
    while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
    COLON.lastIndex = j + 1;
    if (COLON.test(text)) keys++;
    i = j;
  }
  return keys;
}
// Keys and nesting depth of a parsed tree, without recursion.
function treeShape(root) {
  let keys = 0, depth = 0;
  const stack = [[root, 0]];
  while (stack.length) {
    const [value, level] = stack.pop();
    if (value === null || typeof value !== 'object') continue;
    if (level + 1 > depth) depth = level + 1;
    if (depth > CAPTURE_BOUNDS.depth) return { keys, depth };
    const children = Array.isArray(value) ? value : Object.values(value);
    if (!Array.isArray(value)) keys += Object.keys(value).length;
    for (const child of children) stack.push([child, level + 1]);
  }
  return { keys, depth };
}
// A value shaped like a secret or a personal identifier: a JWT, a provider key, an AWS access key id, a
// bearer, basic or token authorization value, a PEM block, a long run of hex, base64 or base64url
// characters, a Luhn-valid run of 13 to 19 digits (any one separator character allowed between digit
// groups: a possible card number, see cardLike), or a nine-digit NNN-NN-NNNN identifier (NINE_DIGIT_ID).
// Such a value is never stored. A Luhn-valid integer of 13 to 19 digits is redacted too; a nine-digit
// JSON number is not (amounts in cents reach nine digits), so name such fields so the deny-list refuses them. A 16-digit order id passes the Luhn check about one time in ten and is
// then unusable: refusing too much is accepted.
// A canonical UUID (an order or ticket id) is not a secret run: it is set aside before the run test.
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
export function luhnValid(digits) {
  if (!/^[0-9]{13,19}$/.test(digits)) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) { let d = digits.charCodeAt(digits.length - 1 - i) - 48; if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; } sum += d; }
  return sum % 10 === 0;
}
// A possible card number: in every maximal digit run of the string (any one separator character, not a letter
// or digit, allowed between digits: 4242 4242 4242 4242, 4242.4242.4242.4242, 4242/4242/4242/4242), some run
// of consecutive digit groups that joins to a Luhn-valid 13 to 19 digits, so a card next to another number
// ("order 12 4242 4242 4242 4242") is still found; or a single unbroken group of more than 19 digits.
const cardLike = value => (value.match(/[0-9](?:[^\p{L}\p{N}]?[0-9])*/gu) ?? []).some(run => {
  const groups = run.split(/[^0-9]/);
  if (groups.some(group => group.length > 19)) return true;
  for (let i = 0; i < groups.length; i++) for (let j = i, digits = ''; j < groups.length && digits.length < 19; j++) { digits += groups[j]; if (luhnValid(digits)) return true; }
  return false;
});
// A nine-digit identifier NNN-NN-NNNN with any one separator character (or none) between groups, not inside a longer digit run.
const NINE_DIGIT_ID = /(?:^|[^0-9])[0-9]{3}[^\p{L}\p{N}]?[0-9]{2}[^\p{L}\p{N}]?[0-9]{4}(?:[^0-9]|$)/u;
export const secretShaped = value => {
  if (typeof value === 'number') return Number.isInteger(value) && luhnValid(String(Math.abs(value)));
  if (typeof value !== 'string') return false;
  value = value.normalize('NFKC');
  // A decimal digit outside 0-9 (Arabic-Indic, Devanagari and others) could spell any number: redacted.
  if (/(?![0-9])\p{Nd}/u.test(value)) return true;
  if (/eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}/.test(value) || /[srp]k_(live|test)_/i.test(value) || /^\s*(bearer|basic|token)\s/i.test(value) || /-----BEGIN /.test(value)) return true;
  if (/\b(AKIA|ASIA)[0-9A-Z]{16}\b/.test(value) || NINE_DIGIT_ID.test(value) || cardLike(value)) return true;
  const rest = value.replace(UUID, ' ');
  return /[A-Za-z0-9_-]{32,}/.test(rest) || /[A-Za-z0-9+/]{32,}/.test(rest);
};
// One declared field of a parsed body.
function readField(root, tokens) {
  let value = root;
  for (const token of tokens) {
    if (Array.isArray(value)) {
      if (!/^(0|[1-9][0-9]{0,8})$/.test(token) || Number(token) >= value.length) return { type: 'absent' };
      value = value[Number(token)];
    } else if (value !== null && typeof value === 'object') {
      if (!Object.hasOwn(value, token)) return { type: 'absent' };
      value = value[token];
    } else return { type: 'absent' };
  }
  if (value === null) return { type: 'null', value: null };
  if (typeof value === 'object') return { type: 'unusable', reason: 'not-scalar' };
  if (typeof value === 'boolean') return { type: 'boolean', value };
  if (typeof value === 'number') return !(Number.isFinite(value) && Math.abs(value) <= MAX_SAFE) ? { type: 'unusable', reason: 'number-unsafe' } : secretShaped(value) ? { type: 'unusable', reason: 'redacted' } : { type: 'number', value };
  if (value.length > CAPTURE_BOUNDS.stringChars) return { type: 'unusable', reason: 'value-over-cap' };
  if (secretShaped(value)) return { type: 'unusable', reason: 'redacted' };
  return { type: 'string', value };
}
// Every value of one header in the raw header list (name, value, name, value, ...), in order.
const headerValues = (rawHeaders, name) => (Array.isArray(rawHeaders) ? rawHeaders : []).flatMap((value, i) => i % 2 === 1 && String(rawHeaders[i - 1]).toLowerCase() === name ? [String(value)] : []);
// Is this Content-Type JSON in UTF-8: application/json or */*+json, with no charset or charset utf-8?
function jsonMediaType(value) {
  const [type, ...params] = value.split(';').map(part => part.trim());
  if (!/^(application\/json|[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+\+json)$/i.test(type)) return false;
  for (const param of params) {
    const m = /^charset\s*=\s*"?([^"]*)"?$/i.exec(param);
    if (m && !/^utf-?8$/i.test(m[1].trim())) return false;
  }
  return true;
}
// Is this Content-Type a form in UTF-8: application/x-www-form-urlencoded with no parameter or exactly charset=utf-8?
function formMediaType(value) {
  if (typeof value !== 'string') return 'other';
  const [type, ...params] = value.split(';').map(part => part.trim());
  if (!/^application\/x-www-form-urlencoded$/i.test(type)) return 'other';
  return params.length === 0 ? 'form' : params.length === 1 && /^charset=(?:utf-8|"utf-8")$/i.test(params[0]) ? 'form-utf8' : 'bad-params';
}
const FORM_DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
// One form-encoded component: '+' is a space, '%' takes exactly two hex digits, the bytes are strict UTF-8 (BOM kept). null when invalid.
function formDecode(raw) {
  const bytes = new Uint8Array(raw.length);
  let n = 0;
  for (let i = 0; i < raw.length; i++) {
    if (raw[i] === '+') bytes[n++] = 0x20;
    else if (raw[i] === '%') { const hex = raw.slice(i + 1, i + 3); if (!/^[0-9A-Fa-f]{2}$/.test(hex)) return null; bytes[n++] = parseInt(hex, 16); i += 2; }
    else bytes[n++] = raw.charCodeAt(i);
  }
  try { return FORM_DECODER.decode(bytes.subarray(0, n)); } catch { return null; }
}
// Index a form body (Map and Set only, so no body key reaches Object.prototype), or the status naming why it cannot be read.
// Paths join key segments with '\n', which no segment holds. The first failing pair decides.
function parseForm(text, utf8) {
  if (!FORM_RAW.test(text)) return 'form-invalid';
  const pairs = text.split('&');
  if (pairs.length > FORM_BOUNDS.pairs) return 'form-over-cap';
  const seen = new Map(), leaves = new Map(), prefixes = new Set(), pushRoots = new Set(), named = new Set(), indices = new Map();
  for (const pair of pairs) {
    const eq = pair.indexOf('=');
    if (eq < 1 || pair.indexOf('=', eq + 1) !== -1) return 'form-invalid';
    const key = formDecode(pair.slice(0, eq)), value = formDecode(pair.slice(eq + 1));
    if (key === null || value === null) return 'form-invalid';
    if (key.length > FORM_BOUNDS.keyChars) return 'form-over-cap';
    const m = FORM_KEY_CHARS.test(key) && !FORM_KEY_DENIED.test(key) ? FORM_KEY.exec(key) : null;
    if (!m) return 'form-key-ambiguous';
    const segs = [m[1], ...(m[2] === '' ? [] : m[2].slice(1, -1).split(']['))];
    if (segs.some(seg => (DIGITS.test(seg) && !INDEX.test(seg)) || PROTO_NAMES.includes(seg.toLowerCase()))) return 'form-key-ambiguous';
    if (segs.length > FORM_BOUNDS.segments) return 'form-too-deep';
    const push = segs.indexOf('');
    const lower = key.toLowerCase(), prior = seen.get(lower);
    if (prior !== undefined && (prior !== key || push === -1)) return 'form-duplicate-key';
    seen.set(lower, key);
    for (let i = 1; i <= Math.min(push === -1 ? segs.length - 1 : push, FORM_BOUNDS.tokens); i++) {
      const parent = segs.slice(0, i).join('\n');
      prefixes.add(parent);
      if (i === push) { pushRoots.add(parent); break; }
      if (INDEX.test(segs[i])) {
        const e = indices.get(parent) ?? { distinct: new Set(), max: -1 };
        e.distinct.add(segs[i]);
        e.max = Math.max(e.max, Number(segs[i]));
        indices.set(parent, e);
      } else named.add(parent);
    }
    if (push === -1 && segs.length <= FORM_BOUNDS.tokens) leaves.set(segs.join('\n'), value);
  }
  return { leaves, prefixes, pushRoots, named, indices, utf8 };
}
// One declared field of an indexed form body. Ambiguous when a receiver could bind it differently: under a
// key[] push, under sparse or mixed indices, or both a value and a container.
function resolveFormField(index, tokens) {
  const ambiguous = { type: 'unusable', reason: 'ambiguous' };
  const L = tokens.length, P = j => tokens.slice(0, j).join('\n');
  for (let j = 1; j <= L; j++) if (index.pushRoots.has(P(j))) return ambiguous;
  for (let i = 1; i < L; i++) {
    if (!INDEX.test(tokens[i])) continue;
    const e = index.indices.get(P(i));
    if (e && (index.named.has(P(i)) || e.max !== e.distinct.size - 1)) return ambiguous;
  }
  const exact = index.leaves.has(P(L)), container = index.prefixes.has(P(L));
  let prefixLeaf = false;
  for (let j = 1; j < L; j++) if (index.leaves.has(P(j))) prefixLeaf = true;
  if (exact && (container || prefixLeaf)) return ambiguous;
  if (exact) {
    const value = index.leaves.get(P(L));
    // Without an explicit charset=utf-8 some receivers (Servlet containers) read the bytes as ISO-8859-1.
    if (!index.utf8 && /[^\x00-\x7f]/.test(value)) return ambiguous;
    return value.length > CAPTURE_BOUNDS.stringChars ? { type: 'unusable', reason: 'value-over-cap' } : secretShaped(value) ? { type: 'unusable', reason: 'redacted' } : { type: 'text', value };
  }
  if (container) return prefixLeaf ? ambiguous : { type: 'unusable', reason: 'not-scalar' };
  return { type: 'absent' };
}
// The captured fields of a form body on a form-enabled destination. Never throws; never partial.
function captureForm({ type, rawHeaders, buffer, bodyBytes, capture, search, method }) {
  const empty = status => ({ status, values: {} });
  try {
    const media = formMediaType(type);
    if (media === 'other') return empty('not-json-or-form');
    if (media === 'bad-params') return empty('form-media-type');
    const encodings = headerValues(rawHeaders, 'content-encoding');
    if (encodings.length > 1 || (encodings.length === 1 && encodings[0].trim().toLowerCase() !== 'identity')) return empty('encoded');
    if (bodyBytes > capture.maxBytes || !buffer || buffer.length !== bodyBytes) return empty('over-cap');
    // PHP and Servlet read a form body only on POST (Go also on PUT and PATCH): any other method, or none, is refused.
    if (method !== 'POST') return empty('form-method');
    // Servlet, Symfony, Flask and Rails prefer a query value over the body; PHP's $_REQUEST can let a cookie override it.
    if (typeof search !== 'string' || search !== '' || headerValues(rawHeaders, 'cookie').length > 0) return empty('form-query-or-cookie');
    let text = '';
    for (const byte of buffer) text += String.fromCharCode(byte);
    const index = parseForm(text, media === 'form-utf8');
    if (typeof index === 'string') return empty(index);
    return { status: 'captured', values: Object.fromEntries(capture.pointers.map(pointer => [pointer, resolveFormField(index, pointerTokens(pointer))])) };
  } catch { return empty('form-invalid'); }
}
// The captured fields of one request: { status, values }. `buffer` holds at most capture.maxBytes bytes
// of the body; bodyBytes is the body's full length. values is keyed by every declared pointer when the
// status is "captured", and empty otherwise. `search` is the request URL's raw search string and `method` its
// method; only form bodies read them (a form-enabled caller that omits either is refused).
// One JSON request body, read under the capture rules: { status, root } with status "parsed", or the reason it cannot be
// read (no-body, content-type-ambiguous, not-json, encoded, over-cap, json-invalid, json-too-deep, json-duplicate-key).
// A not-json result carries the single Content-Type it saw (type), or undefined. Shared by captureBody and the keyed-retry
// body key (src/idempotency.mjs), so both read a body the same way.
export function readJsonBody({ rawHeaders, buffer, bodyBytes, maxBytes }) {
  if (!bodyBytes) return { status: 'no-body' };
  const types = headerValues(rawHeaders, 'content-type');
  if (types.length > 1) return { status: 'content-type-ambiguous' };
  if (types.length !== 1 || !jsonMediaType(types[0])) return { status: 'not-json', type: types[0] };
  const encodings = headerValues(rawHeaders, 'content-encoding');
  if (encodings.length > 1 || (encodings.length === 1 && encodings[0].trim().toLowerCase() !== 'identity')) return { status: 'encoded' };
  if (bodyBytes > maxBytes || !buffer || buffer.length !== bodyBytes) return { status: 'over-cap' };
  let text, root;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(buffer); root = JSON.parse(text); } catch { return { status: 'json-invalid' }; }
  const shape = treeShape(root);
  if (shape.depth > CAPTURE_BOUNDS.depth) return { status: 'json-too-deep' };
  if (countKeyTokens(text) !== shape.keys) return { status: 'json-duplicate-key' };
  return { status: 'parsed', root };
}
export function captureBody({ rawHeaders, buffer, bodyBytes, capture, search, method }) {
  const empty = status => ({ status, values: {} });
  const body = readJsonBody({ rawHeaders, buffer, bodyBytes, maxBytes: capture.maxBytes });
  if (body.status === 'not-json' && formEnabled(capture)) return captureForm({ type: body.type, rawHeaders, buffer, bodyBytes, capture, search, method });
  if (body.status !== 'parsed') return empty(body.status);
  return { status: 'captured', values: Object.fromEntries(capture.pointers.map(pointer => [pointer, readField(body.root, pointerTokens(pointer))])) };
}

const scalar = value => value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value) && Math.abs(value) <= MAX_SAFE) || (typeof value === 'string' && value.length <= CAPTURE_BOUNDS.stringChars);
const typeOf = value => value === null ? 'null' : typeof value;
// A stored `captured` record on an effect event: the shape and caps above, re-checked. Throws a code.
const formValue = v => v.type === 'text' || (v.type === 'unusable' && v.reason === 'ambiguous');
const jsonValue = v => ['string', 'number', 'boolean', 'null'].includes(v.type);
export function validateCaptured(captured) {
  if (!plain(captured) || Object.keys(captured).length !== 2 || !(CAPTURE_STATUSES.includes(captured.status) || FORM_STATUSES.includes(captured.status)) || !plain(captured.values)) throw new Error('captured');
  const entries = Object.entries(captured.values);
  if (captured.status !== 'captured' ? entries.length !== 0 : entries.length < 1 || entries.length > CAPTURE_BOUNDS.pointersPerDestination) throw new Error('captured-values');
  for (const [pointer, v] of entries) {
    try { validatePointer(pointer); } catch { throw new Error('captured-pointer'); }
    if (!plain(v)) throw new Error('captured-value');
    const keys = Object.keys(v).sort().join(',');
    const ok = v.type === 'absent' ? keys === 'type'
      : v.type === 'unusable' ? keys === 'reason,type' && (UNUSABLE_REASONS.includes(v.reason) || FORM_UNUSABLE_REASONS.includes(v.reason))
      : v.type === 'text' ? keys === 'type,value' && typeof v.value === 'string' && v.value.length <= CAPTURE_BOUNDS.stringChars && !secretShaped(v.value)
      : jsonValue(v) && keys === 'type,value' && scalar(v.value) && typeOf(v.value) === v.type && !secretShaped(v.value);
    if (!ok) throw new Error('captured-value');
  }
  // One record is read as JSON or as a form, never both.
  if (entries.some(([, v]) => formValue(v)) && entries.some(([, v]) => jsonValue(v))) throw new Error('captured-value');
  return captured;
}
// Which reading a stored record came from: 'form', 'json-only' (a non-JSON body on a JSON-only destination) or null (either).
export function captureEncodingOf(captured) {
  if (!plain(captured) || !plain(captured.values)) return null;
  if (FORM_STATUSES.includes(captured.status) || Object.values(captured.values).some(v => plain(v) && formValue(v))) return 'form';
  return captured.status === 'not-json' ? 'json-only' : null;
}
// A published captureForm list: 1 to 64 distinct names, each a key of the capture map whose pointers are all valid form pointers.
export function validCaptureForm(list, captureMap) {
  if (!Array.isArray(list) || list.length < 1 || list.length > CAPTURE_BOUNDS.pointersPerRecorder || new Set(list).size !== list.length || !plain(captureMap)) return false;
  return list.every(name => typeof name === 'string' && Object.hasOwn(captureMap, name) && Array.isArray(captureMap[name])
    && captureMap[name].every(p => { try { validateFormPointer(p); return true; } catch { return false; } }));
}
// A selector's `fields`: 1 to 8 entries { pointer, <one operator> }. Throws a code.
export function validateFieldPredicates(fields) {
  if (!Array.isArray(fields) || fields.length < 1 || fields.length > CAPTURE_BOUNDS.fieldsPerSelector) throw new Error('selector-fields');
  for (const entry of fields) {
    if (!plain(entry) || Object.keys(entry).length !== 2 || !Object.hasOwn(entry, 'pointer')) throw new Error('selector-fields');
    try { validatePointer(entry.pointer); } catch { throw new Error('selector-fields-pointer'); }
    const op = Object.keys(entry).find(key => key !== 'pointer');
    if (!FIELD_OPERATORS.includes(op)) throw new Error('selector-fields');
    const operand = entry[op];
    const ok = op === 'equals' ? scalar(operand)
      : op === 'in' ? Array.isArray(operand) && operand.length >= 1 && operand.length <= CAPTURE_BOUNDS.inValues && operand.every(scalar)
      : typeof operand === 'number' && Number.isFinite(operand);
    if (!ok) throw new Error('selector-fields');
  }
  return fields;
}
export const fieldPointers = fields => fields.map(entry => entry.pointer);
// A form value as a number: a canonical integer of at most 15 digits, else null (decimals are culture-dependent on some receivers).
export const formNumber = text => FORM_INTEGER.test(text) ? Number(text) : null;
// A lenient integer reading (sign, surrounding space and NFKC digits allowed, no leading zero), used only to decide 'no'.
const intReading = s => { const m = INT_READING.exec(s.normalize('NFKC')); return m ? (m[1] === '-' && m[2] !== '0' ? '-' : '') + m[2] : null; };
const looseNumeric = s => LOOSE_NUMERIC.test(s.normalize('NFKC').replace(/\s+/g, ''));
// Words a lax receiver reads as one boolean or null (Pydantic lax mode, Django and Rails casts, Go ParseBool), compared folded.
const VALUE_WORDS = Object.freeze([['true', 't', 'yes', 'y', 'on'], ['false', 'f', 'no', 'n', 'off'], ['null', 'none', 'nil', '']]);
// A run of digits with any . , _ ' separators inside it: one number as a receiver may write or parse it.
const DIGIT_RUN = /\p{Nd}(?:[\p{Nd}.,_']*\p{Nd})?/gu;
// Two digit runs that differ under every reading: ASCII digits only, at most 15 (exact as a double), both without a leading zero
// (an octal reading) or of one length, and of different value.
const runsDiffer = (p, q) => /^[0-9]{1,15}$/.test(p) && /^[0-9]{1,15}$/.test(q) && (p.length === q.length || (!/^0[0-9]/.test(p) && !/^0[0-9]/.test(q)))
  && BigInt(p) !== BigInt(q);
// One string value (form text or a JSON string) against one string operand. It matches only on exact text. A difference is 'no'
// only where no common receiver reading makes the two one value:
//   - a control character or edge whitespace on either side may be stripped: unknown;
//   - a bare number on either side (looseNumeric): 'no' only when both read as plain integers of different value;
//   - equal under NFKC and case folding, or words of one boolean or null (VALUE_WORDS): unknown;
//   - otherwise 'no' when neither has a digit, or when their shapes (each digit run as '#', whitespace dropped, folded) differ, or
//     when the shapes agree and some pair of digit runs differs under every reading (runsDiffer); else unknown. So "105.50 USD"
//     against "105.5 USD", "$105.50" against "$105.5" or "2024-10-05" against "2024-10-5" stay unknown, and "T-7" against "T-8",
//     "2024-0001" against "2024-0002" or "cad" against "usd" read 'no'.
function stringState(text, x) {
  if (x === text) return 'match';
  if ([text, x].some(t => /[\x00-\x1f\x7f]/.test(t) || t !== t.trim())) return 'unknown';
  if (looseNumeric(x) || looseNumeric(text)) { const a = intReading(x), b = intReading(text); return a !== null && b !== null && a !== b ? 'no' : 'unknown'; }
  const [p, q] = [text, x].map(t => t.normalize('NFKC').toLowerCase());
  if (p === q || VALUE_WORDS.some(words => words.includes(p) && words.includes(q))) return 'unknown';
  if (!/\p{Nd}/u.test(p) && !/\p{Nd}/u.test(q)) return 'no';
  const shape = t => t.replace(DIGIT_RUN, '#').replace(/\s+/g, '');
  if (shape(p) !== shape(q)) return 'no';
  const runsP = p.match(DIGIT_RUN), runsQ = q.match(DIGIT_RUN);
  return runsP.some((run, i) => runsDiffer(run, runsQ[i])) ? 'no' : 'unknown';
}
// An `in` member of another type than the JSON value. A receiver that coerces may read one as the other ("105.50" or "5 USD" as a
// number, "true" or 1 as a boolean, "" as null, "" or "abc" as 0), so it reads unknown. Set aside (null) only for a string beside a
// number that no reading makes equal: a string with no decimal digit beside a number other than 0 and 1, or a plain integer of
// another value.
function crossState(value, member) {
  const pair = [value, member], s = pair.find(x => typeof x === 'string'), n = pair.find(x => typeof x === 'number');
  if (s === undefined || n === undefined) return 'unknown';
  if (!/\p{Nd}/u.test(s)) return n === 0 || n === 1 ? 'unknown' : null;
  const a = intReading(s);
  return a !== null && Number(a) !== n ? null : 'unknown';
}
// One field predicate over a form text value. String operands follow stringState. Numeric operands need formNumber.
function textState(text, entry) {
  const op = Object.keys(entry).find(key => key !== 'pointer'), operand = entry[op];
  const one = x => {
    if (typeof x === 'string') return stringState(text, x);
    if (typeof x === 'number') { const n = formNumber(text); return n === null ? 'unknown' : n === x ? 'match' : 'no'; }
    return 'unknown';
  };
  if (op === 'equals') return one(operand);
  if (op === 'in') { const states = operand.map(one); return states.includes('match') ? 'match' : states.includes('unknown') ? 'unknown' : 'no'; }
  const n = formNumber(text);
  if (n === null) return 'unknown';
  const holds = op === 'gt' ? n > operand : op === 'gte' ? n >= operand : op === 'lt' ? n < operand : n <= operand;
  return holds ? 'match' : 'no';
}
// One field predicate over an event's captured record: 'match', 'no' or 'unknown'.
export function fieldState(captured, entry) {
  if (!plain(captured) || captured.status !== 'captured' || !plain(captured.values)) return 'unknown';
  const v = captured.values[entry.pointer];
  if (plain(v) && v.type === 'text') return typeof v.value === 'string' ? textState(v.value, entry) : 'unknown';
  if (!plain(v) || !['string', 'number', 'boolean', 'null'].includes(v.type)) return 'unknown';
  const op = Object.keys(entry).find(key => key !== 'pointer'), operand = entry[op];
  // A member of the value's own type is decided (strings by stringState); one of another type is unknown under equals, and under
  // in reads crossState (unknown, or set aside as null).
  const one = x => typeOf(x) !== v.type ? crossState(v.value, x) : v.type === 'string' ? stringState(v.value, x) : x === v.value ? 'match' : 'no';
  if (op === 'equals') return typeOf(operand) !== v.type ? 'unknown' : one(operand);
  if (op === 'in') { const states = operand.map(one).filter(state => state !== null); return !states.length ? 'unknown' : states.includes('match') ? 'match' : states.includes('unknown') ? 'unknown' : 'no'; }
  if (v.type !== 'number') return 'unknown';
  const holds = op === 'gt' ? v.value > operand : op === 'gte' ? v.value >= operand : op === 'lt' ? v.value < operand : v.value <= operand;
  return holds ? 'match' : 'no';
}

// Provider-feed template records (src/provider-feed-rules.mjs, integrations/observers/provider-feed.mjs). A feed that declares a
// template vocabulary (operator label -> provider template id) gives each event to a declared domain one captured field,
// /template: the label of the declared id the signed entry names exactly, { type: 'absent' } when the entry names no template,
// or { type: 'unusable', reason: 'undeclared' } for anything else (another id, a case or space variant, a value that is not a
// string). Only labels are stored, never a provider id. fieldState reads a label like any string, and absent or undeclared as
// unknown, so a template pin never passes on a template the vocabulary does not name exactly.
export const TEMPLATE_POINTER = '/template';
// A label: 1 to 31 characters (a 32-character [a-z_] run would read secret-shaped), a lowercase letter first.
export const TEMPLATE_LABEL = /^[a-z][a-z0-9_.-]{0,30}$/;
export const templateLabelValid = label => typeof label === 'string' && TEMPLATE_LABEL.test(label) && !secretShaped(label);
export function validateTemplateRecord(captured) {
  if (!plain(captured) || Object.keys(captured).sort().join(',') !== 'status,values' || captured.status !== 'captured' || !plain(captured.values)
    || Object.keys(captured.values).join(',') !== TEMPLATE_POINTER) throw new Error('captured-value');
  const v = captured.values[TEMPLATE_POINTER], keys = plain(v) ? Object.keys(v).sort().join(',') : '';
  const ok = v?.type === 'absent' ? keys === 'type' : v?.type === 'unusable' ? keys === 'reason,type' && v.reason === 'undeclared'
    : v?.type === 'string' && keys === 'type,value' && templateLabelValid(v.value);
  if (!ok) throw new Error('captured-value');
  return captured;
}
