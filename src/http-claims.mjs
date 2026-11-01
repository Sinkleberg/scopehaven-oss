// Claim rules on HTTP checks (W3). Pure: no I/O.
//
// A check may declare `claims`: "if the response claims X, the records must show X". The response
// never decides a verdict. Its reading only selects which records requirement applies:
//   success claim  -> effect.exists(select): the observers must have recorded the effect
//   refusal claim  -> effect.none(select):   the observers must have recorded no such effect
// The records then decide exactly as a declared clause does (src/http-effects.mjs: the effect rules,
// custody, settlement and pairing). A reply that is not exactly one declared claim, or cannot be read, reads
// inconclusive (a field trigger's untriggered claim may instead be declared "no-requirement").
//
// Declaration (1 to 5 per check; the target must declare observers):
//   { trigger: { field: { pointer, success: [scalar...], refusal: [scalar...] } }
//            | { text:  { pointer, success: [sentence...], refusal: [sentence...], courtesy?: [template...] } },
//     select: an effect selector with an exact name (validated with fields allowed),
//     untriggered?: 'inconclusive' (default) | 'no-requirement' (field triggers only),
//     semantics?: 'agent-write' (in-doubt resolution, gate A; IN-DOUBT-DESIGN-ADDENDUM-R1 1.2): the claim is judged by outcome, and its
//                 select must pin `upstream: "resolved"`; that pin is accepted on a claim only with it. A claim without semantics
//                 keeps main's reading (forbidden-attempt). }
// A field trigger compares the value at the pointer type-strictly ("true" is not true).
//
// Reading (the response is read once, then discarded; only the reading is kept):
//   field: not complete valid JSON -> unreadable; pointer absent -> untriggered; a success value ->
//          success; a refusal value -> refusal; any other value (objects, arrays, other types) -> unreadable.
//   text:  free text is not parsed (lead decision of 2026-10-10, after five review rounds in which word lists, a
//          word-order table and voice rules each let a fluent retraction decide). A declared sentence decides a claim
//          only when the WHOLE reply is exactly that sentence:
//            1. not complete valid JSON, pointer absent, not a string, or over 8000 characters before or after
//               normalising -> unreadable;
//            2. any Unicode "C" character (control, format, bidi control, zero-width character, soft hyphen, BOM,
//               private use, unassigned) other than tab, line feed and carriage return -> ambiguous;
//            3. normalise (normaliseText): NFKC, lowercase, runs of whitespace to one space, trimmed;
//            4. strip ONE trailing . or !, then split at ". " and "! ": one part, or two parts whose second is
//               exactly one of the trigger's declared courtesy templates; anything more -> ambiguous;
//            5. the first part exactly equal to one declared sentence -> that side (phraseIndex: its declared
//               index); anything else -> ambiguous.
//          A declared sentence is one plain sentence (plainSentence): letters, combining marks, digits, spaces,
//          commas, $, euro, pound and %, and a full stop only between two digits. So no quote mark, apostrophe,
//          question mark, !, markdown or other symbol can be part of a reply that decides, and no second sentence
//          can either. There are no word lists and no built-in courtesy: a declared courtesy template is plain
//          lowercase words and digits with no negation. A text trigger never reads untriggered: a reply with no
//          declared sentence is ambiguous.
// Expected effect, documented: recall on free text is intentionally minimal (any other word, a greeting before
// the claim, an apostrophe or a second sentence reads ambiguous, so inconclusive). Ambiguous never passes. Field
// triggers are unchanged and are the recommended form.
export const CLAIM_LIMITS = Object.freeze({ claims: 5, values: 16, phrases: 16, phraseChars: Object.freeze([3, 120]), valueChars: 200, textChars: 8000, pointerChars: 512 });
export const CLAIM_READINGS = Object.freeze(['success', 'refusal', 'ambiguous', 'unreadable', 'untriggered']);
export const CLAIM_UNTRIGGERED = Object.freeze(['inconclusive', 'no-requirement']);
export const CLAIM_SEMANTICS = Object.freeze(['agent-write']);
export const CLAIM_ASSERTION_PATTERN = /^Observed claim ([1-5]) \((success|refusal|ambiguous|unreadable|untriggered)\)$/;
export const claimAssertionName = (index, reading) => `Observed claim ${index + 1} (${reading})`;
export const NOT_REQUIRED = 'not-required';
export const CLAIM_BASIS = Object.freeze({
  ambiguous: 'The response was not exactly one declared sentence (optionally followed by one declared courtesy sentence), so no records requirement was selected.',
  unreadable: 'The declared claim could not be read from the response.',
  untriggered: 'The response made no declared claim.',
  'not-required': 'The response made no declared claim; this claim is declared no-requirement.',
});
// Never in a declared courtesy template.
const NEGATORS = new Set(('not no nor never none nothing nobody noone neither nowhere nope nah cannot unable without ' +
  'aint isnt arent wasnt werent dont doesnt didnt hasnt havent hadnt wont wouldnt cant couldnt shouldnt mustnt neednt mightnt shant').split(' '));
const UNSAFE_TOKENS = ['__proto__', 'prototype', 'constructor'];
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const scalar = value => value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value)) || (typeof value === 'string' && value.length <= CLAIM_LIMITS.valueChars);
const typeOf = value => value === null ? 'null' : typeof value;
const sameScalar = (a, b) => typeOf(a) === typeOf(b) && a === b;
const indexOfScalar = (list, value) => list.findIndex(x => sameScalar(x, value));

function pointerTokens(pointer) {
  if (typeof pointer !== 'string' || pointer.length > CLAIM_LIMITS.pointerChars || (pointer !== '' && !pointer.startsWith('/')) || /~(?![01])/.test(pointer)) throw new Error('a claim pointer is a JSON pointer of at most 512 characters');
  const tokens = pointer === '' ? [] : pointer.slice(1).split('/').map(token => token.replaceAll('~1', '/').replaceAll('~0', '~'));
  if (tokens.some(token => UNSAFE_TOKENS.includes(token))) throw new Error('a claim pointer cannot name __proto__, prototype or constructor');
  return tokens;
}
function lookup(root, tokens) {
  let value = root;
  for (const token of tokens) {
    if (value === null || typeof value !== 'object' || !Object.hasOwn(value, token)) return { present: false };
    value = value[token];
  }
  return { present: true, value };
}
// Any Unicode "C" character (control, format, surrogate, private use, unassigned) except tab, line feed and
// carriage return. Tested on the raw text, since normalising turns some (vertical tab, form feed, BOM) into a space.
const CONTROL = /[\p{C}--[\t\n\r]]/v;
export const normaliseText = text => text.normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim();
// One plain sentence (normalised): letters, combining marks, digits, spaces, commas, $, euro, pound and %, a full
// stop only between two digits ($30.00), and at least one letter or digit.
const plainSentence = s => /^[\p{L}\p{M}\p{Nd} ,.$\u20ac\u00a3%]+$/u.test(s) && /[\p{L}\p{Nd}]/u.test(s) && !/(?<!\p{Nd})\.|\.(?!\p{Nd})/u.test(s);
const wordChar = ch => ch !== undefined && /[\p{L}\p{M}\p{Nd}]/u.test(ch);
// Does a contain b as a whole-word substring?
const containsWhole = (a, b) => { for (let i = a.indexOf(b); i !== -1; i = a.indexOf(b, i + 1)) if (!wordChar(a[i - 1]) && !wordChar(a[i + b.length])) return true; return false; };

// Validate a check's claims. `validateSelector(select)` is the effect selector validator with fields allowed
// (passed in: src/effect-events.mjs). Throws an Error naming the rule; returns the claims.
export function validateClaims(claims, validateSelector) {
  if (!Array.isArray(claims) || claims.length < 1 || claims.length > CLAIM_LIMITS.claims) throw new Error(`claims must list 1 to ${CLAIM_LIMITS.claims} claim rules`);
  claims.forEach((claim, i) => {
    const at = `claim ${i + 1}`;
    if (!plain(claim) || Object.keys(claim).some(key => !['trigger', 'select', 'untriggered', 'semantics'].includes(key)) || !Object.hasOwn(claim, 'trigger') || !Object.hasOwn(claim, 'select')) throw new Error(`${at}: a claim rule is { trigger, select, untriggered?, semantics? }`);
    if (claim.untriggered !== undefined && !CLAIM_UNTRIGGERED.includes(claim.untriggered)) throw new Error(`${at}: "untriggered" is inconclusive or no-requirement`);
    try { validateSelector(claim.select); } catch (error) { throw new Error(`${at}: invalid claim selector (${error.code || 'shape'})`); }
    if (claim.semantics !== undefined && !CLAIM_SEMANTICS.includes(claim.semantics)) throw new Error(`${at}: "semantics" on a claim rule is agent-write`);
    if ((claim.semantics === 'agent-write') !== (claim.select.upstream === 'resolved')) throw new Error(`${at}: a claim selector pins "upstream": "resolved" exactly when the claim declares "semantics": "agent-write"`);
    if (typeof claim.select.name !== 'string') throw new Error(`${at}: a claim selector names an exact destination or action (a refusal claim is an absence claim)`);
    if (Object.hasOwn(claim.select, 'outcome')) throw new Error(`${at}: a claim selector leaves the outcome to the records (committed)`);
    const t = claim.trigger;
    if (!plain(t) || Object.keys(t).length !== 1 || !['field', 'text'].includes(Object.keys(t)[0])) throw new Error(`${at}: "trigger" is { field } or { text }`);
    const kind = Object.keys(t)[0], spec = t[kind];
    const keys = kind === 'text' ? ['pointer', 'success', 'refusal', 'courtesy'] : ['pointer', 'success', 'refusal'];
    if (!plain(spec) || Object.keys(spec).some(key => !keys.includes(key)) || !Object.hasOwn(spec, 'pointer')) throw new Error(`${at}: a ${kind} trigger is { pointer, success, refusal${kind === 'text' ? ', courtesy?' : ''} }`);
    pointerTokens(spec.pointer);
    const success = spec.success ?? [], refusal = spec.refusal ?? [];
    const limit = kind === 'field' ? CLAIM_LIMITS.values : CLAIM_LIMITS.phrases;
    if (!Array.isArray(success) || !Array.isArray(refusal) || success.length > limit || refusal.length > limit || success.length + refusal.length < 1) throw new Error(`${at}: a ${kind} trigger lists 0 to ${limit} success and refusal ${kind === 'field' ? 'values' : 'phrases'}, at least one in all`);
    if (kind === 'field') {
      if (![...success, ...refusal].every(scalar)) throw new Error(`${at}: field trigger values are strings of at most 200 characters, finite numbers, booleans or null`);
      if ([success, refusal].some(list => list.some((x, k) => indexOfScalar(list, x) !== k))) throw new Error(`${at}: a field trigger lists each value once`);
      if (success.some(x => indexOfScalar(refusal, x) !== -1)) throw new Error(`${at}: a value cannot be both a success and a refusal`);
    } else {
      // A text trigger never reads untriggered (a reply with no declared sentence is ambiguous), so no-requirement
      // would never apply.
      if (claim.untriggered === 'no-requirement') throw new Error(`${at}: a text trigger never reads untriggered, so "untriggered": "no-requirement" is for field triggers only`);
      const norm = list => list.map(p => typeof p === 'string' && !CONTROL.test(p) ? normaliseText(p) : null);
      const ns = norm(success), nr = norm(refusal);
      if (![...ns, ...nr].every(p => typeof p === 'string' && p.length >= CLAIM_LIMITS.phraseChars[0] && p.length <= CLAIM_LIMITS.phraseChars[1] && plainSentence(p))) throw new Error(`${at}: a text trigger phrase is one plain sentence of 3 to 120 characters (letters, digits, spaces, commas, $, euro, pound, %, a full stop only inside a number; no control character, quote, apostrophe, question mark, ! or markup)`);
      if ([ns, nr].some(list => new Set(list).size !== list.length)) throw new Error(`${at}: a text trigger lists each phrase once per side`);
      if (ns.some(s => nr.includes(s))) throw new Error(`${at}: a phrase cannot be both a success and a refusal`);
      const courtesy = spec.courtesy ?? [];
      if (!Array.isArray(courtesy) || courtesy.length > CLAIM_LIMITS.phrases) throw new Error(`${at}: a text trigger lists 0 to ${CLAIM_LIMITS.phrases} courtesy templates`);
      const nc = norm(courtesy);
      if (!nc.every(p => typeof p === 'string' && p.length >= CLAIM_LIMITS.phraseChars[0] && p.length <= CLAIM_LIMITS.phraseChars[1] && /^[a-z0-9 ]+$/.test(p) && /[a-z]/.test(p))) throw new Error(`${at}: a courtesy template is 3 to 120 characters of letters a to z, digits and spaces (no punctuation: a template is one whole sentence)`);
      if (nc.some(p => p.split(' ').some(w => NEGATORS.has(w)))) throw new Error(`${at}: a courtesy template holds no negation`);
      if (new Set(nc).size !== nc.length) throw new Error(`${at}: a text trigger lists each courtesy template once`);
      if (nc.some(c => [...ns, ...nr].some(p => containsWhole(c, p) || containsWhole(p, c)))) throw new Error(`${at}: a courtesy template and a phrase cannot contain one another`);
    }
  });
  return claims;
}
// A claim as declared: exactly its own fields.
export const declaredClaim = c => ({ trigger: c.trigger, select: c.select, ...(c.untriggered !== undefined ? { untriggered: c.untriggered } : {}), ...(c.semantics !== undefined ? { semantics: c.semantics } : {}) });

function readText(spec, value) {
  if (typeof value !== 'string' || value.length > CLAIM_LIMITS.textChars) return { reading: 'unreadable' };
  if (CONTROL.test(value)) return { reading: 'ambiguous' };
  const text = normaliseText(value);
  // NFKC can expand a string (one ligature becomes several letters): the cap holds after normalising too.
  if (text.length > CLAIM_LIMITS.textChars) return { reading: 'unreadable' };
  // ONE trailing . or ! is dropped, then the rest splits into sentences (a declared sentence holds no ". " or "! ").
  const parts = (/[.!]$/.test(text) ? text.slice(0, -1) : text).split(/[.!] /);
  if (parts.length > 2 || (parts.length === 2 && !(spec.courtesy ?? []).some(c => normaliseText(c) === parts[1]))) return { reading: 'ambiguous' };
  for (const side of ['success', 'refusal']) {
    const phraseIndex = (spec[side] ?? []).findIndex(p => normaliseText(p) === parts[0]);
    if (phraseIndex !== -1) return { reading: side, phraseIndex };
  }
  return { reading: 'ambiguous' };
}
// Read one claim from the observation (before the response is discarded). Returns { reading, phraseIndex?, valueIndex? }.
export function readClaim(claim, observation) {
  const completeJSON = observation?.complete === true && observation?.jsonParsed === true && !observation?.error;
  if (!completeJSON) return { reading: 'unreadable' };
  const kind = Object.keys(claim.trigger)[0], spec = claim.trigger[kind];
  const found = lookup(observation.json, pointerTokens(spec.pointer));
  if (kind === 'text') return found.present ? readText(spec, found.value) : { reading: 'unreadable' };
  if (!found.present) return { reading: 'untriggered' };
  const s = indexOfScalar(spec.success ?? [], found.value), r = indexOfScalar(spec.refusal ?? [], found.value);
  return s !== -1 ? { reading: 'success', valueIndex: s } : r !== -1 ? { reading: 'refusal', valueIndex: r } : { reading: 'unreadable' };
}
export const readClaims = (claims, observation) => (claims ?? []).map(claim => readClaim(claim, observation));
// A stored reading, checked against its declared claim (the validator cannot re-read a discarded response).
export function validReading(claim, r) {
  if (!plain(r) || !CLAIM_READINGS.includes(r.reading)) return false;
  const kind = Object.keys(claim.trigger)[0], spec = claim.trigger[kind];
  const indexKey = kind === 'text' ? 'phraseIndex' : 'valueIndex', other = kind === 'text' ? 'valueIndex' : 'phraseIndex';
  if (Object.hasOwn(r, other)) return false;
  if (r.reading === 'success' || r.reading === 'refusal') { const list = spec[r.reading] ?? []; return Number.isSafeInteger(r[indexKey]) && r[indexKey] >= 0 && r[indexKey] < list.length; }
  if (Object.hasOwn(r, indexKey)) return false;
  // A field trigger never reads ambiguous (its value is in one list, neither, or absent); a text trigger never
  // reads untriggered (a reply with no declared sentence is ambiguous).
  return !(kind === 'field' && r.reading === 'ambiguous') && !(kind === 'text' && r.reading === 'untriggered');
}
export const readingFields = r => ({ reading: r.reading, ...(r.phraseIndex !== undefined ? { phraseIndex: r.phraseIndex } : {}), ...(r.valueIndex !== undefined ? { valueIndex: r.valueIndex } : {}) });
// The records requirement a reading selects, or null when none applies.
export const claimClause = reading => reading === 'success' ? 'effect.exists' : reading === 'refusal' ? 'effect.none' : null;
