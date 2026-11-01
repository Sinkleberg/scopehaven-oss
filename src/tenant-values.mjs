// Profile-level forbidden-value leak detection: the json.noForeignValues predicate.
//
// A profile declares each tenant's synthetic record values once, on the target ("tenantValues"), and a check
// opts in with { "kind": "json.noForeignValues", "pointer": "/reply" }. The response value at the pointer is
// scanned for the other tenants' values, so a leak of an order id, an item or an amount is seen even when no
// e-mail domain or phone prefix appears, and one assertion covers every declared value.
//
// Pure: no I/O, no dependencies. Results name a matched value only by 1-based position (tenant n, identifier
// or attribute m, in declared order), never by the value itself, so saved evidence and exports carry
// positions and counts only.
//
// The rule (decision addendum 6, 2026-10-10: allowlist, not blocklist; tightened in addenda 7, 8 and 9). A check may PASS only when the evidence is in a
// small, explicitly allowlisted plain form; anything outside that form reads INCONCLUSIVE, never pass, unless a positive
// violation is found, which reads FAIL. There are no decoders and no exceptions for particular encodings:
//   fail          a foreign identifier written literally (the exact declared characters) as a whole token, in an
//                 occurrence no value of another owner set overlaps, that the check's own request does not carry;
//   pass          every leaf is in the plain form, no value of another tenant occurs in it in any reading, and the
//                 response body repeats no member name in any object (addendum 9), as the connector reports it with
//                 each JSON number's source text (a transport that reports neither, or a body its second parse cannot
//                 read, reads body-unchecked, though a literal whole-token foreign identifier still fails);
//   inconclusive  everything else.
// The plain form of a leaf: ASCII letters and digits; the other letters and decimal digits that occur in some declared
// value, when Unicode assigns them to one of the listed scripts (never Common or Inherited) and, in a script with letter
// case, they have a case pair; U+0020 spaces, U+000A line feeds and the closed punctuation set . , ; : ! ? ' " ( ) - / @ # $;
// and the leaf is unchanged by Unicode NFKC normalization and does not hold ASCII digits beside other decimal digits. A
// member name that is an array index, in an object with another member, is outside the form (JavaScript lists such names
// first, so the body's order is not known), and so is a JSON number without its source text that is not a safe integer
// or a decimal of at most 15 significant digits. Across the whole value at the pointer (addendum 9), every letter and every number
// character other than an ASCII digit, in every leaf and in every other tenant's declared values, is of one script group
// (Han, kana and Bopomofo count as one; a script not listed counts as a group of its own); otherwise every leaf holding
// such a character is outside the form, since a reply in one script can show another script's value in look-alike
// letters; and when right-to-left letters or digits occur anywhere with left-to-right ones (ASCII digits are
// left-to-right), or a character of the right-to-left blocks or a bidi control anywhere in the response body, every leaf at the
// pointer holding a letter or digit of either direction is outside the form. So any escape (a
// backslash, a percent sign, an "&" entity), markup ("<", ">", "*", "_", "~", "`"), control, format, bidi,
// default-ignorable or combining character, compatibility form, spacing modifier letter, any letter no declared value
// uses (small capitals, IPA letters, letters drawn like punctuation, the katakana long vowel mark, the Arabic tatweel), and
// every other symbol puts its leaf outside the form. Accepted recall loss: such a leaf reads inconclusive whenever no
// foreign identifier is written literally in it.
//
// Readings. The literal reading is the text itself (a JSON number as the body writes it): a declared value is searched
// as written (trimmed). The loose reading keeps only letters and numbers, each after NFKD with combining marks removed and
// a full case fold, the letters of a fixed table by their base letters, katakana as hiragana, an iteration mark as the
// letter before it, the ideographic zero as 0 and every decimal digit as its ASCII digit (looseOf); a declared value is
// read the same way, and one with \u00e4, \u00f6, \u00fc, \u00e5 or \u00f8 also with those spelled out (spelledOut). A value seen in the loose reading
// anywhere but inside its own whole literal occurrence (another letter case, accents removed, other spacing, punctuation
// or line breaks between its characters, its
// characters glued to more letters or digits) is a partial occurrence: inconclusive. The joined readings (decision
// addendum 8) are the loose reading with the leaf boundaries removed, in walk order, once over every leaf and once over
// the leaves that are not object keys; a value seen there across a leaf boundary (["ORD-", "2002"], {"ORD": 2002},
// {"first": "Grace", "last": "Hopper"}) is a partial occurrence too.
// Token edges, judged on the text: an occurrence edge is open at a leaf edge, beside a space or line feed, or beside a
// run of the closed punctuation that ends at a leaf edge, space or line feed; partial otherwise (a letter or digit of any
// case, such as "orderORD-2002", "ORD-2002x", "ORD-20021", "myjdoe42" or "Lovelaces", punctuation that meets a letter or
// digit, or a character outside the form). There is no closed edge (addendum 8): a longer word that holds a value is
// glue, never another word, so "Anne", "annual" and "Joanna" for "Ann" read inconclusive (accepted recall loss). An edge
// character of the value that is not a letter or digit ("@globex.example") is open unless its neighbour is outside the
// letter, digit, space, line feed and punctuation classes.
// Number-like leaves (addendum 8): a JSON number, or a string leaf that is decimal text alone, equal as a number to a
// declared decimal value but written differently ("7.50" for 7.5, 2134 for "02134", the string "7.5" for "7.50") is an
// imprecise occurrence: inconclusive. Leading zeros get no exception.
// The number readings (addendum 9): the loose reading and the joined readings with the zeros at both ends of every run
// of ASCII digits removed (a run of zeros vanishes). A value with a digit, read the same way, seen there is an imprecise
// occurrence unless a digit end of it meets, past any zeros the text writes right beside it, a digit the text writes
// right beside it (17310 and 7.51 are other numbers than 731 and 7.5): "Order 731" and "Order 731 2 items" for "00731",
// "7.5" for "7.50", "INV-42" for "INV-0042", "1,000" for "1000.00", "7.31e2" for "731". The loose reading drops spaces
// and punctuation, so digits written apart are never glue. Accepted recall loss: 7310 reads like 731; 1, 10, 0.1 and
// 100.00 alike; "ABC" like "ABC-000". A value whose digits are all zeros and that has no letter (0.00) has no number reading.
// Earlier rounds folded and decoded the text; that machinery is gone (the conversation evaluator keeps its own).

export const FOREIGN_VALUES_KIND = 'json.noForeignValues';
export const FOREIGN_VALUES_EXPECTED = 'Configured JSON predicate holds';
export const ATTRIBUTES_ALONE = Object.freeze(['inconclusive', 'ignore']);
export const VALUE_CLASSES = Object.freeze(['identifier', 'attribute']);
const CLASS_KEYS = Object.freeze(['identifiers', 'attributes']);
export const SCAN_STATES = Object.freeze(['complete', 'over-limit', 'work-limit', 'unavailable', 'body-unchecked']);
// The counts a complete scan records (distinct values, except unplain: leaves, and repeatedKeys: member names of the whole
// response body that repeat an earlier name of the same object).
export const COUNT_KEYS = Object.freeze(['identifiers', 'attributes', 'echoed', 'shared', 'overlapping', 'imprecise', 'partial', 'unplain', 'repeatedKeys']);
export const TENANT_VALUE_LIMITS = Object.freeze({ minTenants: 2, maxTenants: 16, maxPerClass: 512, maxTotal: 2048, minLength: 3, maxLength: 200, maxRaw: 1000, maxScanChars: 131072, maxLooseChars: 524288, maxOccurrences: 262144, maxRefs: 32 });
const UNSAFE_KEYS = ['__proto__', 'prototype', 'constructor'];
const TENANT_KEY = /^[A-Za-z0-9_-]{1,80}$/;
const plainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const count = n => Number.isSafeInteger(n) && n >= 0;

// ---------------------------------------------------------------------------
// Characters. The listed scripts, in groups (Han, the kana and Bopomofo are one group, as Japanese text mixes them);
// right-to-left groups are marked, and so are the groups whose letters have case. Only a letter or digit of a listed
// script that some declared value uses can join the plain form (decision addendum 7: the declared characters are the
// allowlist); a letter Unicode assigns to no script (Common or Inherited) never does, whatever its script extensions.
const SCRIPT_GROUPS = [['latin', ['Latin'], false, true], ['greek', ['Greek'], false, true], ['cyrillic', ['Cyrillic'], false, true], ['armenian', ['Armenian'], false, true], ['georgian', ['Georgian'], false, true],
  ['hebrew', ['Hebrew'], true], ['arabic', ['Arabic'], true], ['syriac', ['Syriac'], true], ['thaana', ['Thaana'], true], ['nko', ['Nko'], true],
  ['cjk', ['Han', 'Hiragana', 'Katakana', 'Bopomofo']], ['hangul', ['Hangul']], ['thai', ['Thai']], ['lao', ['Lao']], ['khmer', ['Khmer']], ['myanmar', ['Myanmar']],
  ['devanagari', ['Devanagari']], ['bengali', ['Bengali']], ['gurmukhi', ['Gurmukhi']], ['gujarati', ['Gujarati']], ['oriya', ['Oriya']], ['tamil', ['Tamil']],
  ['telugu', ['Telugu']], ['kannada', ['Kannada']], ['malayalam', ['Malayalam']], ['sinhala', ['Sinhala']], ['ethiopic', ['Ethiopic']], ['cherokee', ['Cherokee'], false, true]]
  .map(([group, names, rtl = false, cased = false]) => ({ group, rtl, cased, sc: new RegExp(`^[${names.map(n => `\\p{sc=${n}}`).join('')}]$`, 'u') }));
const RTL_GROUPS = new Set(SCRIPT_GROUPS.filter(s => s.rtl).map(s => s.group)), CASED_GROUPS = new Set(SCRIPT_GROUPS.filter(s => s.cased).map(s => s.group));
const PUNCT = new Set([...'.,;:!?\'"()-/@#$']);
const LETTER = /^\p{L}$/u, NUMBER = /^\p{N}$/u, DECIMAL = /^\p{Nd}$/u, IGNORABLE = /^\p{Default_Ignorable_Code_Point}$/u, ASCII_ALNUM = /^[A-Za-z0-9]$/;
// Edge classes: E a space, line feed or leaf edge; P the closed punctuation; W a letter or number; O anything else.
const E = 0, P = 1, W = 2, O = 3;
const groupOf = ch => SCRIPT_GROUPS.find(s => s.sc.test(ch))?.group ?? null;
// The script information of one character, independent of the declaration: { cls, letter, digit, ascii, group, script }.
// group: the listed script group of a letter or decimal digit (an ASCII digit has none), null for every other script.
// script: the group a letter or number counts toward in the one-group rule (addendum 9): an ASCII letter is Latin, an
// ASCII digit none, any other letter or number its listed script group, or "other" when Unicode assigns it to none.
function infoOf(ch) {
  if (ch === ' ' || ch === '\n') return { cls: E };
  if (PUNCT.has(ch)) return { cls: P };
  const letter = LETTER.test(ch), digit = DECIMAL.test(ch);
  if (!letter && !NUMBER.test(ch)) return { cls: O };
  const ascii = ASCII_ALNUM.test(ch);
  const group = ascii ? (letter ? 'latin' : null) : letter || digit ? groupOf(ch) : null;
  return { cls: W, letter, digit, ascii, group, script: ascii ? group : groupOf(ch) ?? 'other' };
}
// Whether a character of a declared value joins the plain form: a letter or decimal digit, not ASCII (ASCII letters and
// digits always join), of a listed script, not default-ignorable, and in a script with letter case a letter whose
// uppercase or lowercase mapping is another character (so small capitals, IPA letters and caseless letters drawn like
// punctuation never join, even when declared).
function admits(ch) {
  const info = infoOf(ch);
  if (info.cls !== W || info.ascii || !(info.letter || info.digit) || info.group === null || IGNORABLE.test(ch)) return false;
  return !(info.letter && CASED_GROUPS.has(info.group)) || ch.toUpperCase() !== ch || ch.toLowerCase() !== ch;
}
// The loose reading of one character: NFKD (compatibility decomposition) with every combining mark removed before and
// after a full case fold (lower, upper, lower: the capital and the small sharp s both read "ss"; the Greek iota subscript
// is dropped, not read as iota), the letters below by their base letters, katakana as hiragana, the ideographic zero as 0,
// letters and numbers only, decimal digits as ASCII digits. So another letter case, accents removed ("Jose Garcia" for
// "Jos\u00e9 Garc\u00eda") and a stroke or ligature written out ("Sorensen", "Caecilie") read as the declared value
// (adversarial passes 1 and 2 on addendum 9). An iteration mark (\u3005, \u309d) reads as the letter before it in its leaf
// (looseText, scanTextOf); with no letter right before it, as nothing, and its leaf is outside the form (pass 3). The table: ligatures and letters with a stroke or bar (Latin, Cyrillic), Hebrew final letters, and the
// Persian and Arabic spellings of yeh, kaf and heh.
const BASE_LETTERS = new Map([['\u00e6', 'ae'], ['\u0153', 'oe'], ['\u00f8', 'o'], ['\u0142', 'l'], ['\u0111', 'd'], ['\u00f0', 'd'], ['\u00fe', 'th'], ['\u0127', 'h'], ['\u0167', 't'], ['\u0131', 'i'],
  ['\u0180', 'b'], ['\u01e5', 'g'], ['\u0268', 'i'], ['\u0249', 'j'], ['\ua741', 'k'], ['\u019a', 'l'], ['\u0275', 'o'], ['\u1d7d', 'p'], ['\ua751', 'p'], ['\ua757', 'q'], ['\u024d', 'r'],
  ['\u0289', 'u'], ['\u024f', 'y'], ['\u01b6', 'z'], ['\u023c', 'c'], ['\u0247', 'e'], ['\u2c65', 'a'], ['\u0493', '\u0433'], ['\u049f', '\u043a'], ['\u04b1', '\u04af'],
  ['\u05dd', '\u05de'], ['\u05df', '\u05e0'], ['\u05e5', '\u05e6'], ['\u05e3', '\u05e4'], ['\u05da', '\u05db'],
  ['\u06cc', '\u064a'], ['\u0649', '\u064a'], ['\u06a9', '\u0643'], ['\u0629', '\u0647']]);
const ITERATION = new Set(['\u3005', '\u309d']);
const MARK = /^\p{M}$/u;
function digitValue(ch) {
  const cp = ch.codePointAt(0);
  let zero = cp;
  while (cp - zero < 9 && DECIMAL.test(String.fromCodePoint(zero - 1))) zero--;
  return String(cp - zero);
}
function looseOf(ch) {
  let out = '';
  let bare = '';
  for (const c of ch.normalize('NFKD')) if (!MARK.test(c)) bare += c;
  for (let f of bare.toLowerCase().toUpperCase().toLowerCase().normalize('NFKD')) {
    if (MARK.test(f)) continue;
    const cp = f.codePointAt(0);
    if ((cp >= 0x30a1 && cp <= 0x30f6) || cp === 0x30fd) f = String.fromCodePoint(cp - 0x60);
    else if (cp === 0x3007) f = '0';
    else if (BASE_LETTERS.has(f)) { out += BASE_LETTERS.get(f); continue; }
    if (DECIMAL.test(f)) out += f >= '0' && f <= '9' ? f : digitValue(f); else if (LETTER.test(f) || NUMBER.test(f)) out += f;
  }
  return out;
}
// The last code point of a loose piece, and a piece with an iteration mark read as the letter before it.
const lastOf = piece => piece ? String.fromCodePoint(piece.codePointAt(piece.length - (piece.length > 1 && /[\udc00-\udfff]/.test(piece.at(-1)) ? 2 : 1))) : '';
const iterated = (piece, last) => ITERATION.has(piece) ? (LETTER.test(last) ? last : '') : piece;
const looseText = text => { let out = '', last = ''; for (const ch of text) { const piece = iterated(looseOf(ch), last); out += piece; last = piece ? lastOf(piece) : ITERATION.has(looseOf(ch)) ? '' : last; } return out; };
// The number reading of a loose or joined text: every run of ASCII digits without the zeros at its ends (a run of zeros
// vanishes), with, per code unit, its index in the text read. One pass.
const isDigit = c => c >= '0' && c <= '9';
function numberReading(text) {
  let out = '';
  const src = [];
  for (let i = 0; i < text.length;) {
    if (!isDigit(text[i])) { out += text[i]; src.push(i); i++; continue; }
    let j = i;
    while (j < text.length && isDigit(text[j])) j++;
    let s = i, e = j;
    while (e > s && text[s] === '0') s++;
    while (e > s && text[e - 1] === '0') e--;
    out += text.slice(s, e);
    for (let k = s; k < e; k++) src.push(k);
    i = j;
  }
  return { text: out, src: Int32Array.from(src) };
}
// Whether a match of a value's number reading r, covering positions a to b of the text L it was read from, is glued: an end
// of r that is a digit meets, past any zeros written right beside it, a digit written right beside it. near(i): positions i
// and i + 1 of L come from the same or adjacent source characters, so a space, punctuation or a leaf edge between two
// digits is never glue (the loose reading drops them). 731 is glued in 17310 and 10731, not in 7310, 0731 or "731 2".
function glued(L, near, a, b, r) {
  if (isDigit(r[0])) { let i = a - 1; while (i >= 0 && L[i] === '0' && near(i)) i--; if (i >= 0 && isDigit(L[i]) && near(i)) return true; }
  if (isDigit(r[r.length - 1])) { let j = b + 1; while (j < L.length && L[j] === '0' && near(j - 1)) j++; if (j < L.length && isDigit(L[j]) && near(j - 1)) return true; }
  return false;
}

// ---------------------------------------------------------------------------
// Declaration: { tenants: { <tenantId>: { identifiers: [...], attributes: [...] } }, attributesAlone? }.
// Throws plain Errors naming the rule and a position (tenant n, identifier m), never a value or a tenant id.
export function validateTenantValues(decl) {
  const L = TENANT_VALUE_LIMITS;
  if (!plainObject(decl)) throw new Error('must be a JSON object { "tenants", "attributesAlone"? }');
  if (Reflect.ownKeys(decl).some(key => !['tenants', 'attributesAlone'].includes(key))) throw new Error('allows only "tenants" and "attributesAlone"');
  if (!Object.hasOwn(decl, 'tenants')) throw new Error('needs "tenants"');
  if (Object.hasOwn(decl, 'attributesAlone') && !ATTRIBUTES_ALONE.includes(decl.attributesAlone)) throw new Error('"attributesAlone" must be "inconclusive" or "ignore"');
  if (!plainObject(decl.tenants)) throw new Error('"tenants" must map tenant ids to { "identifiers", "attributes" }');
  const keys = Reflect.ownKeys(decl.tenants);
  if (keys.length < L.minTenants || keys.length > L.maxTenants) throw new Error(`"tenants" must declare ${L.minTenants} to ${L.maxTenants} tenants`);
  let total = 0;
  keys.forEach((key, k) => {
    const where = `tenant ${k + 1}`;
    if (typeof key !== 'string' || !TENANT_KEY.test(key) || UNSAFE_KEYS.includes(key)) throw new Error(`${where}: a tenant id is 1-80 letters, digits, "_" or "-"`);
    const tenant = decl.tenants[key];
    if (!plainObject(tenant) || Reflect.ownKeys(tenant).some(name => !CLASS_KEYS.includes(name))) throw new Error(`${where}: a tenant is { "identifiers", "attributes" } (lists of strings)`);
    const seen = new Set();
    let own = 0;
    CLASS_KEYS.forEach((cls, c) => {
      const list = tenant[cls] ?? [];
      if (!Array.isArray(list) || list.length > L.maxPerClass) throw new Error(`${where}: "${cls}" must be a list of at most ${L.maxPerClass} values`);
      list.forEach((value, i) => {
        const at = `${where} ${VALUE_CLASSES[c]} ${i + 1}`;
        // Numbers are refused: "30" and "30.00" would be ambiguous. Declare the text the application shows.
        if (typeof value !== 'string') throw new Error(`${at}: a value must be a string`);
        if (value.length > L.maxRaw || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${at}: a value has no control characters and at most ${L.maxRaw} characters`);
        if (/\p{Cs}/u.test(value)) throw new Error(`${at}: a value has no unpaired surrogates`);
        const literal = value.trim(), length = [...literal].length;
        if (length < L.minLength || length > L.maxLength) throw new Error(`${at}: a value must be ${L.minLength} to ${L.maxLength} characters, spaces at its ends not counted`);
        // A value is matched as written; one that NFKC changes (decomposed accents, compatibility forms) is refused rather
        // than normalized, since normal text would never show it literally.
        if (literal.normalize('NFKC') !== literal) throw new Error(`${at}: a value must be written as Unicode NFKC normalization leaves it (composed accents, no compatibility forms)`);
        const loose = looseText(literal);
        if (!loose) throw new Error(`${at}: a value needs at least one letter or digit`);
        if (seen.has(loose)) throw new Error(`${at}: duplicates another value of the same tenant in the loose reading (its letters and digits, in any case)`);
        seen.add(loose);
      });
      own += list.length;
    });
    if (own === 0) throw new Error(`${where}: declares no values`);
    total += own;
  });
  if (total > L.maxTotal) throw new Error(`at most ${L.maxTotal} values in total`);
}

// The other loose readings of a declared value: with \u00e4, \u00f6, \u00fc, \u00e5 or \u00f8 spelled ae, oe, ue, aa and oe (adversarial
// pass 2), and with ae, oe, ue and aa written a, o, u and a (pass 3), searched like the loose reading, so "Juergen Mueller"
// is seen for the declared "J\u00fcrgen M\u00fcller" and "M\u00fcller" (read "muller") for the declared "Mueller".
const SPELLED = { '\u00e4': 'ae', '\u00f6': 'oe', '\u00fc': 'ue', '\u00e5': 'aa', '\u00f8': 'oe', '\u00c4': 'Ae', '\u00d6': 'Oe', '\u00dc': 'Ue', '\u00c5': 'Aa', '\u00d8': 'Oe' };
const spelledOut = literal => [looseText(literal.replace(/[\u00e4\u00f6\u00fc\u00e5\u00f8\u00c4\u00d6\u00dc\u00c5\u00d8]/g, c => SPELLED[c])),
  looseText(literal.replace(/([AaOoUu])[Ee]|([Aa])[Aa]/g, (pair, vowel, a) => vowel ?? a))];
// The declared values, one entry per loose reading (order-independent): its literal texts, its owner tenants, its class
// (identifier when any tenant declares it as one: identifier wins), the position a ref names (the lowest tenant
// declaring it in that class), its number reading (null without an ASCII digit in its loose reading, or when it is empty) and the script
// groups of its letters and numbers, and its other loose readings (spelledOut). The declared characters: the letters and digits of every tenant's values that join
// the plain form beside ASCII letters and digits (admits). Call only on a validated declaration.
export function compileTenantValues(decl) {
  const keys = Object.keys(decl.tenants), byLoose = new Map(), letters = new Set();
  keys.forEach((key, t) => CLASS_KEYS.forEach((cls, c) => (decl.tenants[key][cls] ?? []).forEach((raw, i) => {
    const literal = raw.trim(), loose = looseText(literal);
    for (const ch of literal) if (!letters.has(ch) && admits(ch)) letters.add(ch);
    if (!byLoose.has(loose)) byLoose.set(loose, { loose, declared: [] });
    byLoose.get(loose).declared.push({ text: literal, tenant: t + 1, cls: VALUE_CLASSES[c], index: i + 1 });
  })));
  const values = [...byLoose.values()].map(({ loose, declared }) => {
    const cls = declared.some(d => d.cls === 'identifier') ? 'identifier' : 'attribute';
    const owners = [...new Set(declared.map(d => d.tenant))].sort((a, b) => a - b);
    const named = declared.filter(d => d.cls === cls).sort((a, b) => a.tenant - b.tenant || a.index - b.index)[0];
    const literals = [...new Set(declared.map(d => d.text))];
    const scripts = new Set();
    for (const text of literals) for (const ch of text) { const script = infoOf(ch).script; if (script) scripts.add(script); }
    return Object.freeze({ loose, literals: Object.freeze(literals), owners: Object.freeze(owners), group: owners.join(','), cls, ref: Object.freeze({ tenant: named.tenant, class: cls, value: named.index }),
      number: /[0-9]/.test(loose) && numberReading(loose).text ? numberReading(loose).text : null, scripts: Object.freeze([...scripts]),
      spelled: Object.freeze([...new Set(literals.flatMap(spelledOut))].filter(text => text && text !== loose)) });
  });
  return Object.freeze({ keys, values: Object.freeze(values), letters: Object.freeze(letters), attributesAlone: decl.attributesAlone ?? 'inconclusive' });
}
// The value-free record a run carries and the exported suite binds: how many values each tenant declared
// per class, the attributesAlone policy, and each actor's tenant position (actors whose tenant is declared).
export function tenantValueCounts(target) {
  const decl = target.tenantValues, keys = Object.keys(decl.tenants);
  return { attributesAlone: decl.attributesAlone ?? 'inconclusive', tenants: keys.map(key => ({ identifiers: (decl.tenants[key].identifiers ?? []).length, attributes: (decl.tenants[key].attributes ?? []).length })),
    actorTenants: Object.fromEntries(Object.entries(target.actors).filter(([, actor]) => typeof actor.tenantId === 'string' && keys.includes(actor.tenantId)).map(([alias, actor]) => [alias, keys.indexOf(actor.tenantId) + 1])) };
}
export function validTenantValueCounts(record) {
  const L = TENANT_VALUE_LIMITS;
  if (!plainObject(record) || Object.keys(record).length !== 3 || !ATTRIBUTES_ALONE.includes(record.attributesAlone) || !Array.isArray(record.tenants) || !plainObject(record.actorTenants)) return false;
  if (record.tenants.length < L.minTenants || record.tenants.length > L.maxTenants) return false;
  let total = 0;
  for (const t of record.tenants) {
    if (!plainObject(t) || Object.keys(t).length !== 2 || !count(t.identifiers) || !count(t.attributes) || t.identifiers > L.maxPerClass || t.attributes > L.maxPerClass || t.identifiers + t.attributes < 1) return false;
    total += t.identifiers + t.attributes;
  }
  return total <= L.maxTotal && Object.entries(record.actorTenants).every(([alias, n]) => TENANT_KEY.test(alias) && !UNSAFE_KEYS.includes(alias) && Number.isInteger(n) && n >= 1 && n <= record.tenants.length);
}

// The source text of each JSON number. The connector parses the body a second time with this reviver, so the scan reads a
// number as the body writes it (7.50, 731e-400 and 12345678901234567 keep their digits). A number without it (a stub
// transport) reads as String(n), and only a safe integer or a decimal of at most 15 significant digits is in the form.
export const NUMBER_SOURCE = Symbol('json number source');
export const numberSourceReviver = (key, value, context) => typeof value === 'number' ? Object.freeze({ [NUMBER_SOURCE]: Object.freeze([typeof context?.source === 'string' ? context.source : null, value]) }) : value;
// A member name JavaScript lists before the others whatever the body's order: an array index (0 to 2^32 - 2, no leading zero).
const arrayIndex = key => /^(?:0|[1-9][0-9]{0,9})$/.test(key) && Number(key) < 4294967295;

// The texts and numbers of the request the check actually sent (its decoded path including the query, with "+"
// read as a space too, and its body's keys and leaves). A foreign value the request itself carries is an echo.
export function requestLeaves(request) {
  const texts = [], numbers = [];
  if (typeof request?.path === 'string') {
    let decoded = request.path;
    try { decoded = decodeURIComponent(request.path); } catch {}
    texts.push(decoded);
    const query = request.path.indexOf('?');
    if (query >= 0) { try { texts.push(decodeURIComponent(request.path.slice(query + 1).replaceAll('+', ' '))); } catch {} }
  }
  if (request?.body !== undefined) walk(request.body, text => texts.push(text), number => { if (Number.isFinite(number)) numbers.push(number); });
  return { texts, numbers };
}
// Iterative walk over keys, strings and numbers (booleans and null carry no value), in order: array items in index order,
// each object key just before its value, object members in JavaScript property order. onText(text, isKey, moved): moved
// for an array-index member name beside another member (JavaScript lists it first, so the body's order is not known).
// onNumber(number, source): source is the body's text of the number when the reviver above kept it, else null.
function walk(root, onText, onNumber) {
  const stack = [root], kinds = [0];
  while (stack.length) {
    const value = stack.pop(), kind = kinds.pop();
    if (typeof value === 'string') onText(value, kind > 0, kind === 2);
    else if (typeof value === 'number') onNumber(value, null);
    else if (Array.isArray(value)) for (let i = value.length - 1; i >= 0; i--) { stack.push(value[i]); kinds.push(0); }
    else if (value !== null && typeof value === 'object') {
      if (Object.hasOwn(value, NUMBER_SOURCE)) { const [source, number] = value[NUMBER_SOURCE]; onNumber(number, source); continue; }
      const keys = Object.keys(value), several = keys.length > 1;
      for (let i = keys.length - 1; i >= 0; i--) { stack.push(value[keys[i]]); kinds.push(0); stack.push(keys[i]); kinds.push(several && arrayIndex(keys[i]) ? 2 : 1); }
    }
  }
}
// The matcher for one check: the compiled declaration, the actor's tenant position, the loose readings of the request's
// texts and numbers (an echo is a value whose loose reading occurs in one of them) and the script groups of the letters
// and numbers of every value another tenant holds.
// null when the actor's tenant is not declared (validation refuses that profile, so null means unavailable).
export function matcherFor(compiled, tenantId, request) {
  if (!compiled || typeof tenantId !== 'string' || !compiled.keys.includes(tenantId)) return null;
  const { texts, numbers } = requestLeaves(request), tenant = compiled.keys.indexOf(tenantId) + 1;
  const foreignScripts = new Set(compiled.values.filter(v => v.owners.some(o => o !== tenant)).flatMap(v => v.scripts));
  return Object.freeze({ compiled, tenant, echoLoose: Object.freeze([...texts, ...numbers.map(String)].map(looseText)), foreignScripts: Object.freeze([...foreignScripts]) });
}

// ---------------------------------------------------------------------------
// The scanned text: the leaves (strings, keys, and each JSON number as the body writes it, or String(n)) joined by NUL,
// which no declared value holds, so no literal match spans two leaves; a leaf edge is an E edge. Per code unit: the edge
// class. Per leaf: whether it is in the plain form (the one-group and direction rules over every leaf last). The loose
// reading with, per code unit, the source character's span and its leaf; a NUL between leaves, so no loose match spans
// two leaves either. The joined readings: the loose reading without the NULs, over every leaf and over the leaves that
// are not keys, with, per code unit, its loose position.
const isPlainNumber = n => Number.isSafeInteger(n) || (!Number.isInteger(n) && /^-?\d+\.\d+$/.test(String(n)) && String(n).replace(/[-.]/g, '').replace(/^0+/, '').length <= 15);
function scanTextOf(leaves, letters, foreignScripts, rtlOutside) {
  const T = leaves.map(leaf => leaf.text).join('\u0000'), n = T.length;
  const K = new Uint8Array(n), cache = new Map(), spans = [];
  let loose = '';
  const scripts = new Set(foreignScripts), plainLeaves = [];
  let anyRtl = rtlOutside, anyLtr = false;
  const looseStart = [], looseEnd = [], looseLeaf = [];
  let at = 0;
  for (const [k, leaf] of leaves.entries()) {
    if (k) { K[at] = E; loose += '\u0000'; looseStart.push(at); looseEnd.push(at + 1); looseLeaf.push(-1); at++; }
    const start = at;
    // The one-group and direction rules are applied over every leaf below; here, the leaf's own characters. A moved member
    // name, and a number without its source text that may be rounded or is not finite, are outside the form.
    let plain = !leaf.moved && !(leaf.number !== undefined && !leaf.sourced && !isPlainNumber(leaf.number)), scripted = false, rtl = false, ltr = false, asciiDigit = false, otherDigit = false, last = '';
    for (const ch of leaf.text) {
      let info = cache.get(ch);
      if (info === undefined) {
        info = infoOf(ch); info.loose = info.cls === W || info.cls === O ? looseOf(ch) : '';
        info.allowed = info.cls === E || info.cls === P || (info.cls === W && (info.ascii || letters.has(ch)));
        cache.set(ch, info);
      }
      for (let u = 0; u < ch.length; u++) K[at + u] = info.cls;
      const piece = iterated(info.loose, last);
      if (ITERATION.has(info.loose) && !piece) plain = false;
      last = piece ? lastOf(piece) : ITERATION.has(info.loose) ? '' : last;
      for (let u = 0; u < piece.length; u++) { looseStart.push(at); looseEnd.push(at + ch.length); looseLeaf.push(k); }
      loose += piece;
      if (!info.allowed) plain = false;
      if (info.script) { scripted = true; scripts.add(info.script); }
      if (info.letter || info.digit) { if (info.group !== null && RTL_GROUPS.has(info.group)) rtl = true; else ltr = true; }
      if (info.digit) { if (info.ascii) asciiDigit = true; else otherDigit = true; }
      at += ch.length;
    }
    // ASCII digits beside other decimal digits: a reader sees the ASCII number, the loose reading another one.
    if (asciiDigit && otherDigit) plain = false;
    if (plain && leaf.text.normalize('NFKC') !== leaf.text) plain = false;
    if (rtl) anyRtl = true;
    if (ltr) anyLtr = true;
    plainLeaves.push(plain ? { scripted, directed: rtl || ltr } : null);
    spans.push({ start, end: at, number: leaf.number, key: leaf.key, sourced: leaf.sourced });
    if (loose.length > TENANT_VALUE_LIMITS.maxLooseChars) return null;
  }
  // Leaves outside the form: by their own characters; every leaf with a letter or number when the leaves and the other
  // tenants' values use more than one script group; and every leaf with a letter or digit when right-to-left letters or
  // digits occur anywhere beside left-to-right ones (ASCII digits are left-to-right), since the display order of one leaf
  // depends on the leaves around it.
  const mixedDirection = anyRtl && anyLtr;
  const unplain = plainLeaves.filter(p => p === null || (p.scripted && scripts.size > 1) || (p.directed && mixedDirection)).length;
  // The punctuation run around each P position: its first index and its end.
  const runStart = new Int32Array(n), runEnd = new Int32Array(n);
  for (let i = 0; i < n; i++) runStart[i] = K[i] === P && i > 0 && K[i - 1] === P ? runStart[i - 1] : i;
  for (let i = n - 1; i >= 0; i--) runEnd[i] = K[i] === P && i + 1 < n && K[i + 1] === P ? runEnd[i + 1] : i + 1;
  // The joined readings; the one without keys only when some leaf is a key (else it equals the first).
  const joined = keysToo => { let text = ''; const pos = []; for (let u = 0; u < loose.length; u++) { const k = looseLeaf[u]; if (k < 0 || (!keysToo && leaves[k].key)) continue; text += loose[u]; pos.push(u); } return { text, pos: Int32Array.from(pos) }; };
  const joins = leaves.some(leaf => leaf.key) ? [joined(true), joined(false)] : [joined(true)];
  return { T, K, runStart, runEnd, loose, looseStart: Int32Array.from(looseStart), looseEnd: Int32Array.from(looseEnd), looseLeaf: Int32Array.from(looseLeaf), joins, spans, unplain };
}
// The edges of an occurrence [i, j) of the scanned text: 'open' or 'partial' (no closed edge: a letter or digit beside
// the value is glue, never another word).
function startEdge(S, i) {
  const { K, runStart } = S;
  if (i === 0) return 'open';
  const k = K[i - 1];
  if (K[i] !== W) return k === O ? 'partial' : 'open';
  if (k === E) return 'open';
  if (k === P) { const s = runStart[i - 1]; return s === 0 || K[s - 1] === E ? 'open' : 'partial'; }
  return 'partial';
}
function endEdge(S, j) {
  const { K, runEnd, T } = S;
  if (j >= T.length) return 'open';
  const k = K[j];
  if (K[j - 1] !== W) return k === O ? 'partial' : 'open';
  if (k === E) return 'open';
  if (k === P) { const e = runEnd[j]; return e >= T.length || K[e] === E ? 'open' : 'partial'; }
  return 'partial';
}
// A test of whether some span of a list contains [s, e): spans sorted by start with the running maximum end, so each
// test is a binary search.
function coverOf(spans) {
  const sorted = [...spans].sort((x, y) => x[0] - y[0]), maxEnd = [];
  let m = -1;
  for (const [, e] of sorted) maxEnd.push(m = Math.max(m, e));
  return ([s, e]) => {
    let lo = 0, hi = sorted.length - 1, k = -1;
    while (lo <= hi) { const mid = (lo + hi) >> 1; if (sorted[mid][0] <= s) { k = mid; lo = mid + 1; } else hi = mid - 1; }
    return k >= 0 && maxEnd[k] >= e;
  };
}
// Marks every span that overlaps a span of another owner set: spans sorted by start; a span overlaps an earlier one of
// another set when the largest end among earlier spans of other sets passes its start (the two largest ends with
// different sets are kept), and a later one when the next span of another set starts before its end.
function markOverlaps(all) {
  all.sort((x, y) => x.s - y.s || x.e - y.e);
  let best = { e: -1, g: null }, second = { e: -1, g: null };
  for (const x of all) {
    const other = best.g !== x.g ? best : second;
    if (other.e > x.s) x.overlapped = true;
    if (x.e > best.e) { if (best.g !== x.g) second = best; best = { e: x.e, g: x.g }; }
    else if (x.g !== best.g && x.e > second.e) second = { e: x.e, g: x.g };
  }
  let next = all.length;
  for (let k = all.length - 1; k >= 0; k--) {
    if (k + 1 < all.length && all[k + 1].g !== all[k].g) next = k + 1;
    if (next < all.length && all[next].s < all[k].e) all[k].overlapped = true;
  }
}
// A declared value written as decimal text (a JSON number could be that value, leading zeros included), and a string
// leaf that is decimal text alone (trimmed), so a number written as a string.
const NUMERIC = /^-?\d+(\.\d+)?$/, NUMBER_TEXT = /^[-+]?(?:\d+(?:\.\d*)?|\.\d+)$/;

// ---------------------------------------------------------------------------
// Scanning. found: the pointer lookup { present, type, value }; repeatedKeys: the member names of the whole response body
// that repeat an earlier name of the same object (the transport counts them; unknown reads body-unchecked, inconclusive).
// Returns { scan, outcome, counts, refs }.
// Occurrences of a declared value: whole (a literal match with both edges open, in a JSON number leaf only when the
// number is exact: a safe integer, or a decimal of at most 15 significant digits), partial (a loose match, which covers
// every literal match with a partial edge, and a match in a joined reading that crosses a leaf boundary; the loose match
// at a whole literal match's own place adds nothing, as it lies inside that match) and imprecise (a number-like leaf, a
// JSON number or a string of decimal text alone, equal as a number to the value's decimal text but written differently,
// leading zeros included, a literal match in a JSON number that is not exact, or a match in a number reading). An occurrence that
// overlaps an occurrence of a value with another set of owner tenants is overlapped: which value it is is ambiguous.
// For actor tenant T, a value occurring at all is
//   own      held by T alone: never counted (its occurrences still overlap others);
//   shared   held by T and another tenant, or an identifier held by two or more other tenants: inconclusive;
//   foreign  held by one other tenant (or an attribute held only by other tenants), counted as
//     identifier   an identifier with a whole occurrence that is not overlapped, not carried by the request: fail;
//     echoed       the same, carried by the check's own request (a refusal that names it reads the same): inconclusive;
//     attribute    an attribute with a whole occurrence that is not overlapped: alone, as the attributesAlone policy says;
//     overlapping  no such occurrence, but an overlapped one: inconclusive;
//     imprecise    a number-like leaf or an inexact number, and no whole or overlapped occurrence: inconclusive;
//     partial      no such occurrence, but a partial one: inconclusive;
//     imprecise    only matches in a number reading: inconclusive.
// unplain counts the leaves outside the plain form and repeatedKeys the repeated member names; any reads inconclusive
// unless an identifier fails.
// Work is bounded: the text is at most maxScanChars characters (else over-limit) and its loose reading at most
// maxLooseChars (else over-limit; each joined and number reading is no longer), every match found in any reading costs one of
// maxOccurrences (past it the scan stops: work-limit),
// containment is a binary search and overlap a sort. Over-limit and work-limit read inconclusive.
// rtlOutside: the response body holds right-to-left letters or digits, or a bidi control, outside the pointer (see
// holdsRightToLeft), so the display order of left-to-right leaves at the pointer is not known.
export function scanForeignValues(matcher, found, repeatedKeys, { rtlOutside = false } = {}) {
  const L = TENANT_VALUE_LIMITS;
  if (!matcher) return { scan: 'unavailable' };
  if (!count(repeatedKeys)) return { scan: 'body-unchecked' };
  const leaves = [];
  let raw = 0, over = false;
  const add = (text, number, key, moved, sourced) => { if (over) return; raw += text.length; if (raw > L.maxScanChars) over = true; else leaves.push({ text, number, key, moved, sourced }); };
  walk(found.value, (text, key, moved) => add(text, undefined, key, moved, false), (number, source) => add(source ?? String(number), number, false, false, source !== null));
  if (over) return { scan: 'over-limit' };
  const { compiled, tenant } = matcher;
  const S = scanTextOf(leaves, compiled.letters, matcher.foreignScripts, rtlOutside);
  if (S === null) return { scan: 'over-limit' };
  const { T, loose, looseStart, looseEnd, looseLeaf, joins } = S;
  const inexact = coverOf(S.spans.filter(s => s.number !== undefined && !s.sourced && !isPlainNumber(s.number)).map(s => [s.start, s.end]));
  // Number-like leaves by numeric value: each JSON number (its text String(n)) and each string leaf, key or not, that is
  // decimal text alone once trimmed (its trimmed text).
  const numberLeaves = new Map();
  const addNumber = (n, span, text) => { if (!numberLeaves.has(n)) numberLeaves.set(n, []); numberLeaves.get(n).push({ span, text }); };
  for (const s of S.spans) {
    const span = [s.start, s.end], text = T.slice(s.start, s.end);
    if (s.number !== undefined) addNumber(s.number, span, text);
    else if (NUMBER_TEXT.test(text.trim())) addNumber(Number(text.trim()), span, text.trim());
  }
  // The number readings of the loose reading and of each joined reading, built only when some value has a digit.
  const numbered = compiled.values.some(v => v.number !== null) ? { leaves: numberReading(loose), joins: joins.map(j => ({ text: j.text, pos: j.pos, number: numberReading(j.text) })) } : null;
  const nearLoose = i => looseEnd[i] >= looseStart[i + 1];
  let budget = L.maxOccurrences;
  const matched = [], all = [];
  for (const v of compiled.values) {
    const whole = [], partial = [], imprecise = [], renumbered = [];
    for (const lit of v.literals) {
      for (let i = T.indexOf(lit); i !== -1; i = T.indexOf(lit, i + 1)) {
        if (--budget < 0) return { scan: 'work-limit' };
        // A literal match with a partial edge is also a loose match at the same place: partial, below.
        if (startEdge(S, i) !== 'open' || endEdge(S, i + lit.length) !== 'open') continue;
        const span = [i, i + lit.length];
        (inexact(span) ? imprecise : whole).push(span);
      }
      // The same number written differently ("7.5" or 7.5 for "7.50", 2134 or "2134" for "02134"): imprecise.
      if (NUMERIC.test(lit)) for (const { span, text } of numberLeaves.get(Number(lit)) ?? []) {
        if (--budget < 0) return { scan: 'work-limit' };
        if (text !== lit) imprecise.push(span);
      }
    }
    for (const r of [v.loose, ...v.spelled]) for (let k = loose.indexOf(r); k !== -1; k = loose.indexOf(r, k + 1)) {
      if (--budget < 0) return { scan: 'work-limit' };
      partial.push([looseStart[k], looseEnd[k + r.length - 1]]);
    }
    // Across leaf boundaries: a match in a joined reading whose first and last characters lie in different leaves (a match
    // inside one leaf is already a loose match above).
    for (const r of [v.loose, ...v.spelled]) for (const { text, pos } of joins) for (let k = text.indexOf(r); k !== -1; k = text.indexOf(r, k + 1)) {
      if (--budget < 0) return { scan: 'work-limit' };
      const first = pos[k], last = pos[k + r.length - 1];
      if (looseLeaf[first] !== looseLeaf[last]) partial.push([looseStart[first], looseEnd[last]]);
    }
    // The number readings: within a leaf, and across a leaf boundary in a joined reading (as above); never glued.
    if (v.number !== null) {
      const R = numbered.leaves, r = v.number;
      for (let k = R.text.indexOf(r); k !== -1; k = R.text.indexOf(r, k + 1)) {
        if (--budget < 0) return { scan: 'work-limit' };
        const a = R.src[k], b = R.src[k + r.length - 1];
        if (!glued(loose, nearLoose, a, b, r)) renumbered.push([looseStart[a], looseEnd[b]]);
      }
      for (const { text: J, pos, number: N } of numbered.joins) for (let k = N.text.indexOf(r); k !== -1; k = N.text.indexOf(r, k + 1)) {
        if (--budget < 0) return { scan: 'work-limit' };
        const a = N.src[k], b = N.src[k + r.length - 1], first = pos[a], last = pos[b];
        if (looseLeaf[first] !== looseLeaf[last] && !glued(J, i => looseEnd[pos[i]] >= looseStart[pos[i + 1]], a, b, r)) renumbered.push([looseStart[first], looseEnd[last]]);
      }
    }
    if (!whole.length && !partial.length && !imprecise.length && !renumbered.length) continue;
    const entry = { v, whole: whole.map(([s, e]) => ({ s, e, g: v.group })), rest: [...partial, ...imprecise, ...renumbered].map(([s, e]) => ({ s, e, g: v.group })), imprecise: imprecise.length > 0, partial: partial.length > 0 };
    // One push per occurrence (a spread of more than about 125000 arguments overflows the stack).
    for (const x of entry.whole) all.push(x);
    for (const x of entry.rest) all.push(x);
    matched.push(entry);
  }
  markOverlaps(all);
  const counts = Object.fromEntries(COUNT_KEYS.map(key => [key, 0])), refs = [];
  counts.unplain = S.unplain; counts.repeatedKeys = repeatedKeys;
  const echoed = v => matcher.echoLoose.some(text => text.includes(v.loose));
  for (const { v, whole, rest, imprecise, partial } of matched) {
    const mine = v.owners.includes(tenant);
    if (mine && v.owners.length === 1) continue;
    if (mine || (v.owners.length > 1 && v.cls === 'identifier')) { counts.shared++; continue; }
    if (whole.some(x => !x.overlapped)) {
      if (v.cls === 'attribute') { counts.attributes++; refs.push(v.ref); }
      else if (echoed(v)) counts.echoed++;
      else { counts.identifiers++; refs.push(v.ref); }
    } else if ([...whole, ...rest].some(x => x.overlapped)) counts.overlapping++;
    else if (imprecise) counts.imprecise++;
    else if (partial) counts.partial++;
    else counts.imprecise++;
  }
  refs.sort(refOrder);
  return { scan: 'complete', outcome: outcomeOf(counts, compiled.attributesAlone), counts, refs: refs.slice(0, L.maxRefs) };
}
// The outcome from the counts and the attributesAlone policy (the scan and the saved-evidence check share it).
const outcomeOf = (c, attributesAlone) => c.identifiers > 0 ? 'fail' : c.echoed + c.shared + c.overlapping + c.imprecise + c.partial + c.unplain + c.repeatedKeys > 0 ? 'inconclusive'
  : c.attributes > 0 ? (attributesAlone === 'ignore' ? 'pass' : 'inconclusive') : 'pass';
const refOrder = (a, b) => a.tenant - b.tenant || VALUE_CLASSES.indexOf(a.class) - VALUE_CLASSES.indexOf(b.class) || a.value - b.value;

// Whether a response body holds any character of the right-to-left blocks (letters, digits and punctuation of every
// right-to-left script, listed or not: U+0590 to U+08FF, U+FB1D to U+FDFF, U+FE70 to U+FEFF, U+10800 to U+10FFF and
// U+1E800 to U+1EFFF) or a bidi control, in any string or member name: then the display order of the leaves at the
// pointer depends on text outside it (adversarial passes 2 and 3).
const RTL_TEXT = /[\u0590-\u08ff\ufb1d-\ufdff\ufe70-\ufeff\u{10800}-\u{10fff}\u{1e800}-\u{1efff}]|\p{Bidi_Control}/u;
export function holdsRightToLeft(body) {
  let found = false;
  if (body !== undefined) walk(body, text => { if (!found && RTL_TEXT.test(text)) found = true; }, () => {});
  return found;
}
// The predicate record a row keeps (observed.predicates). completeJSON false: the existing "unavailable" shape.
// An absent pointer or a null or boolean value: inconclusive with no scan. Otherwise the scan state, and for a
// complete scan its counts and refs. From the transport: repeatedKeys, its count of repeated member names (see
// scanForeignValues); sourced, the same value from its jsonSource tree (numbers with their source text); body, that whole
// tree, read for right-to-left text outside the pointer.
export function foreignValuesPredicate(completeJSON, found, matcher, { repeatedKeys, sourced, body } = {}) {
  const base = { kind: FOREIGN_VALUES_KIND, present: completeJSON ? found.present : null, type: found.type };
  if (!completeJSON || !found.present || !['string', 'number', 'object', 'array'].includes(found.type)) return { ...base, outcome: 'inconclusive' };
  // Without the number source texts (a transport that keeps none, or a body its second parse could not read) the body is
  // not known as written: never a pass. A literal whole-token foreign identifier still fails (adversarial pass 3: an
  // unreadable sibling cannot hide a fail); anything else reads body-unchecked.
  const failOnly = r => r.scan === 'complete' && r.outcome === 'fail' ? r : { scan: 'body-unchecked' };
  const result = !matcher ? { scan: 'unavailable' } : sourced === undefined ? failOnly(scanForeignValues(matcher, found, repeatedKeys)) : scanForeignValues(matcher, { ...found, value: sourced }, repeatedKeys, { rtlOutside: holdsRightToLeft(body) });
  return result.scan === 'complete' ? { ...base, outcome: result.outcome, scan: 'complete', counts: result.counts, refs: result.refs } : { ...base, outcome: 'inconclusive', scan: result.scan };
}
// The assertion's canonical actual text (inside the row's evidence digest): positions and counts, never values.
const refText = (refs, cls, total) => {
  const listed = refs.filter(r => r.class === cls).map(r => `tenant ${r.tenant} ${cls} ${r.value}`);
  if (listed.length < total) listed.push(`${total - listed.length} more`);
  return listed.length ? ` (${listed.join(', ')})` : '';
};
export function foreignValuesActual(p) {
  if (p.present === null) return 'Complete valid JSON unavailable';
  if (!p.present) return `Absent; type ${p.type}; predicate ${p.outcome}`;
  if (p.scan === undefined) return `Present; type ${p.type}; predicate ${p.outcome}`;
  if (p.scan === 'over-limit') return `Present; type ${p.type}; not scanned: the text exceeds ${TENANT_VALUE_LIMITS.maxScanChars} characters, or ${TENANT_VALUE_LIMITS.maxLooseChars} in its loose reading; predicate ${p.outcome}`;
  if (p.scan === 'work-limit') return `Present; type ${p.type}; scan stopped: more than ${TENANT_VALUE_LIMITS.maxOccurrences} matches to judge; predicate ${p.outcome}`;
  if (p.scan === 'unavailable') return `Present; type ${p.type}; not scanned: tenant values unavailable; predicate ${p.outcome}`;
  if (p.scan === 'body-unchecked') return `Present; type ${p.type}; not scanned: the transport did not report repeated member names and number source texts; predicate ${p.outcome}`;
  const c = p.counts;
  return `Present; type ${p.type}; other-tenant identifiers ${c.identifiers}${refText(p.refs, 'identifier', c.identifiers)}; other-tenant attributes ${c.attributes}${refText(p.refs, 'attribute', c.attributes)}; echoed identifiers ${c.echoed}; shared values ${c.shared}; overlapping values ${c.overlapping}; imprecise number values ${c.imprecise}; partial values ${c.partial}; leaves outside the plain form ${c.unplain}; repeated member names ${c.repeatedKeys}; predicate ${p.outcome}`;
}
// The saved-evidence check of one predicate record, against the run's value-free tenantValueCounts and the row's actor.
// The response is not kept, so the scan itself is not repeated: its record must be internally consistent, its refs must
// name declared positions of other tenants, and its outcome must follow from its counts and the declared policy.
export function validForeignValuesPredicate(p, { completeJSON, declared, actorId }) {
  const L = TENANT_VALUE_LIMITS;
  if (!plainObject(p) || p.kind !== FOREIGN_VALUES_KIND || !plainObject(declared)) return false;
  const actorTenant = Object.hasOwn(declared.actorTenants, actorId) ? declared.actorTenants[actorId] : null;
  if (actorTenant === null) return false;
  const keys = Object.keys(p).sort().join(',');
  if (!completeJSON) return keys === 'kind,outcome,present,type' && p.present === null && p.type === 'unavailable' && p.outcome === 'inconclusive';
  if (typeof p.present !== 'boolean' || (p.present ? !['null', 'array', 'object', 'string', 'number', 'boolean'].includes(p.type) : p.type !== 'absent')) return false;
  if (!p.present || ['null', 'boolean'].includes(p.type)) return keys === 'kind,outcome,present,type' && p.outcome === 'inconclusive';
  if (p.scan !== 'complete') return keys === 'kind,outcome,present,scan,type' && SCAN_STATES.filter(s => s !== 'complete').includes(p.scan) && p.outcome === 'inconclusive';
  if (keys !== 'counts,kind,outcome,present,refs,scan,type') return false;
  const c = p.counts;
  if (!plainObject(c) || Object.keys(c).sort().join(',') !== [...COUNT_KEYS].sort().join(',') || !Object.values(c).every(count)) return false;
  if (!Array.isArray(p.refs) || p.refs.length !== Math.min(L.maxRefs, c.identifiers + c.attributes)) return false;
  for (const [k, r] of p.refs.entries()) {
    if (!plainObject(r) || Object.keys(r).length !== 3 || !VALUE_CLASSES.includes(r.class) || !Number.isInteger(r.tenant) || !Number.isInteger(r.value)) return false;
    if (r.tenant < 1 || r.tenant > declared.tenants.length || r.tenant === actorTenant || r.value < 1 || r.value > declared.tenants[r.tenant - 1][`${r.class}s`]) return false;
    if (k > 0 && refOrder(p.refs[k - 1], r) >= 0) return false;
  }
  const listed = cls => p.refs.filter(r => r.class === cls).length;
  if (listed('identifier') > c.identifiers || listed('attribute') > c.attributes) return false;
  return p.outcome === outcomeOf(c, declared.attributesAlone);
}
