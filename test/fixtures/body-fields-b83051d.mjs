// Frozen copy of scopehaven/src/body-fields.mjs at b83051d, for the form-capture differential compat test. Not in any identity list.
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
// A declared pointer: valid, and naming no secret-like key at any depth.
export function validatePointer(pointer) {
  const tokens = pointerTokens(pointer);
  if (tokens.some(deniedToken)) throw new Error('a capture pointer names a secret-like key (password, passcode, pw or pwd, token, secret, authorization or auth, cookie, session or sid, csrf, jwt, hmac or signature, key, credential, card or cc, cvv, iban, account or routing number, pan, pin, otp, mfa or 2fa, ssn, sin, tax or national id, date of birth, passport) or holds a character outside ASCII after NFKC folding; such fields are never captured');
  return tokens;
}
// A destination's `capture`: { pointers, maxBytes? }. Returns the normalized declaration.
export function validateCaptureDeclaration(capture, maxBodyBytes) {
  if (!plain(capture) || Object.keys(capture).some(key => !['pointers', 'maxBytes'].includes(key))) throw new Error('a destination\'s "capture" is { pointers, maxBytes? }');
  const { pointers } = capture;
  if (!Array.isArray(pointers) || pointers.length < 1 || pointers.length > CAPTURE_BOUNDS.pointersPerDestination || new Set(pointers).size !== pointers.length) throw new Error('"capture.pointers" lists 1 to 16 distinct JSON pointers');
  pointers.forEach(validatePointer);
  const maxBytes = capture.maxBytes ?? Math.min(CAPTURE_BOUNDS.defaultMaxBytes, maxBodyBytes);
  if (!Number.isInteger(maxBytes) || maxBytes < CAPTURE_BOUNDS.maxBytes[0] || maxBytes > CAPTURE_BOUNDS.maxBytes[1] || maxBytes > maxBodyBytes) throw new Error('"capture.maxBytes" is an integer from 1024 to 65536 and no more than the recorder\'s maxBodyBytes');
  return { pointers: [...pointers], maxBytes };
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
// The captured fields of one request: { status, values }. `buffer` holds at most capture.maxBytes bytes
// of the body; bodyBytes is the body's full length. values is keyed by every declared pointer when the
// status is "captured", and empty otherwise.
export function captureBody({ rawHeaders, buffer, bodyBytes, capture }) {
  const empty = status => ({ status, values: {} });
  if (!bodyBytes) return empty('no-body');
  const types = headerValues(rawHeaders, 'content-type');
  if (types.length > 1) return empty('content-type-ambiguous');
  if (types.length !== 1 || !jsonMediaType(types[0])) return empty('not-json');
  const encodings = headerValues(rawHeaders, 'content-encoding');
  if (encodings.length > 1 || (encodings.length === 1 && encodings[0].trim().toLowerCase() !== 'identity')) return empty('encoded');
  if (bodyBytes > capture.maxBytes || !buffer || buffer.length !== bodyBytes) return empty('over-cap');
  let text, root;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(buffer); root = JSON.parse(text); } catch { return empty('json-invalid'); }
  const shape = treeShape(root);
  if (shape.depth > CAPTURE_BOUNDS.depth) return empty('json-too-deep');
  if (countKeyTokens(text) !== shape.keys) return empty('json-duplicate-key');
  return { status: 'captured', values: Object.fromEntries(capture.pointers.map(pointer => [pointer, readField(root, pointerTokens(pointer))])) };
}

const scalar = value => value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value) && Math.abs(value) <= MAX_SAFE) || (typeof value === 'string' && value.length <= CAPTURE_BOUNDS.stringChars);
const typeOf = value => value === null ? 'null' : typeof value;
// A stored `captured` record on an effect event: the shape and caps above, re-checked. Throws a code.
export function validateCaptured(captured) {
  if (!plain(captured) || Object.keys(captured).length !== 2 || !CAPTURE_STATUSES.includes(captured.status) || !plain(captured.values)) throw new Error('captured');
  const entries = Object.entries(captured.values);
  if (captured.status !== 'captured' ? entries.length !== 0 : entries.length < 1 || entries.length > CAPTURE_BOUNDS.pointersPerDestination) throw new Error('captured-values');
  for (const [pointer, v] of entries) {
    try { validatePointer(pointer); } catch { throw new Error('captured-pointer'); }
    if (!plain(v)) throw new Error('captured-value');
    const keys = Object.keys(v).sort().join(',');
    const ok = v.type === 'absent' ? keys === 'type'
      : v.type === 'unusable' ? keys === 'reason,type' && UNUSABLE_REASONS.includes(v.reason)
      : ['string', 'number', 'boolean', 'null'].includes(v.type) && keys === 'type,value' && scalar(v.value) && typeOf(v.value) === v.type && !secretShaped(v.value);
    if (!ok) throw new Error('captured-value');
  }
  return captured;
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
// One field predicate over an event's captured record: 'match', 'no' or 'unknown'.
export function fieldState(captured, entry) {
  if (!plain(captured) || captured.status !== 'captured' || !plain(captured.values)) return 'unknown';
  const v = captured.values[entry.pointer];
  if (!plain(v) || !['string', 'number', 'boolean', 'null'].includes(v.type)) return 'unknown';
  const op = Object.keys(entry).find(key => key !== 'pointer'), operand = entry[op];
  if (op === 'equals') return typeOf(operand) !== v.type ? 'unknown' : operand === v.value ? 'match' : 'no';
  if (op === 'in') { const typed = operand.filter(x => typeOf(x) === v.type); return !typed.length ? 'unknown' : typed.includes(v.value) ? 'match' : 'no'; }
  if (v.type !== 'number') return 'unknown';
  const holds = op === 'gt' ? v.value > operand : op === 'gte' ? v.value >= operand : op === 'lt' ? v.value < operand : v.value <= operand;
  return holds ? 'match' : 'no';
}
