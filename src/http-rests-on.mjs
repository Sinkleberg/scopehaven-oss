// Identity option B (actor-identity/6): a boundary check may declare `restsOn`, the required allowed-use controls of
// its own actor whose served record on the check's own route, at another record, shows that the allowed use of the same
// kind was accepted. Pure: no I/O. src/contracts.mjs validates the declaration at load (restsOnProblem) and calls
// restsOnReleases on both sides, the connector's identityJudge and the validator's httpIdentity, from the same run rows.
//
// Under actor-identity/5 one failed required control withholds every other check of its actor ('control-not-passed').
// Under actor-identity/6 a credentialed check X that declares restsOn drops control-not-passed only when all of these hold
// (IDENTITY-OPTIONS.md section 5.3 as tightened by the lead's rulings of 2026-10-11 and the builder's check note,
// outputs/scopehaven-step1-2026-10-11/IDENTITY-B-CHECK.md). Anything else keeps today's actor-wide withholding, and every
// later step of the row's identity reason still runs (src/contracts.mjs rowIdentityReason).
//   (a) every listed control L passed, showed a served record (below; its own identity proven, so every probe at every
//       probe point of the actor passed), carries no settlement or attribution tag on any clause, has no claim reading
//       other than success, and is on X's route at another record with another path as sent (anchors);
//   (b) every failed required control F of the actor showed a served record, answered no refusal-like status, passed every
//       assertion other than its effect and claim rows, and each of its effect or claim decisions that did not pass is a
//       positive reading (effect.exists, effect.count of at least one, a success claim) that coverage gaps alone decided,
//       or a positive pass that background attribution withheld, with no committed send fitting the clause under another
//       actor in either case (failureAdmitted);
//   (c) no failed control F is related to X: their routes share a stem key, or either route is unreadable, has no stem key
//       or a record position that is not right after a word (route); F is a positive pairing twin of one of X's absence
//       pins; an absence clause, an effect.only clause or a claim rule of X and a positive clause or a claim rule of F share
//       a selector name (a clause without a name matches any name) and source; or a captured value links them;
//   (d) at least one listed control was sent after X and after every failed control (run order).
// Only an anchor that shows a served record releases (lead ruling Q1: R-B1 rejected), and a refused failed control never
// releases (Q2). Release happens only for a credentialed actor (check note F4): an uncredentialed actor has no probe points,
// so it keeps its own rule. Without an exported suite to bind the route segments, record predicates, partners, restsOn
// lists and related controls, nothing is released (the validator refuses a run whose rows rest on a release:
// rests-on-needs-suite).
//
// Lifted from PR #275 (branch claude/fix-allowed-use-scope-2026-10-10 at e364c02, src/http-control-scope.mjs, parked by the
// lead's decision of 2026-10-11): the path reader, the route rule's anchor conditions, the served-record code and the
// relations, with their readings unchanged. #275's own reach rule (control-refused, control-unbounded,
// paired-control-not-passed) is not taken. Its documentation of the lifted parts follows.
//
// The allowlisted form, a served record (servedRecords below). One answer cannot show that a record was served: an
// answer that echoes the request (the record id, the path, the body, a header, an actor's value) or one that every
// answer carries (an envelope constant, such as an empty success envelope) passes any predicate written on it, and
// which field of a body belongs to the record cannot be checked. Two answers can. A required control R showed a served
// record only beside a partner P, another required control of the same actor, when all of these hold for R and for P:
//   - its own identity was proven for it (src/contracts.mjs recordIdentityProven, called by the connector and the
//     validator with the same arguments): the row's identity reason, computed by rowIdentityReason with no
//     control-scope finding, is null and, for a credentialed actor, the actor's login was proven and every probe at
//     every probe point of the actor passed (an identity probe or a surface probe, a 500 as much as a refusal, before,
//     between or after);
//   - it declares exactly one status, a 2xx (status.equals), and answered exactly that status, which is not
//     refusal-like for the actor, with transport outcome complete and a JSON body that parsed;
//   - the body is a JSON object (not an array, null or a scalar) with no top-level key and no top-level string value
//     that names an outcome (cleanObject, outcomeText: error, errors, status, success, ok or message in any letter
//     case, a key such as statusCode or error_message, an access-decision key such as allowed or authorized, a value
//     such as "forbidden"), so an error, status or refusal envelope is never read as a record;
//   - one of its record predicates passed on a present value;
// and R and P are two records of one route that answered alike in shape and differently on one field: the same method;
// the same route (sameRoute below: the same segments, the same raw text at every literal and at every record position
// but the last, and a last record position that is an identifier literal or a placeholder whose capture is declared
// "integer" in both, with different raw text there); different paths as sent (controlScope.sentRoute); the same
// top-level key set (controlScope.bodyKeys, a keyed digest of the sorted keys); P among R's declared partners
// (declaredPartners: from declarations alone, bound by the exported suite); and a record predicate of R and one of P
// that passed on the same top-level field with different expected values. An envelope constant is the same in both
// answers, so it can never pass both; a refusal shaped unlike the record is not a partner; an echo of the request never
// passes the value rule below. What is left is a value the application holds for each record, which no request carries,
// and which it answered for both.
// A record predicate (recordClasses): a json.equals whose pointer is exactly one reference token (a top-level field,
// never the root or a nested pointer) and whose expected value is a string that, after NFKC normalization, holds no
// digit (of any script) and at least two runs of three or more letters, names no outcome (outcomeText, as a key is
// read: Access denied, Request failed), and that no request of the profile carries (requestTexts, carriedByRequest), on
// a check that sends no body, or an empty object or array (any key or value of a body can carry text), and whose own
// path holds no {{name}} placeholder (a captured value, which could be anything). So the only text that differs between
// the requests of two partners is their record identifier, which holds a digit or is hexadecimal. The texts a request
// can carry: every check's method, its path (raw, percent-decoded, and each part between "/", "?", "#", "&", "=" and
// ";", decoded), every key and every string or number value of its body (raw and percent-decoded) and its body as JSON;
// the profile's origin as written, its host, host name and port; every actor's alias and every string or number an
// actor declares (principal, identity value, tenant, role, credential reference and cookie names, sign-in redirect
// status); every observer's witness request (its method and path, tagged scopehaven_witness); and every header name and
// constant header value the connector sends (Accept: application/json, Connection: close, Authorization: Bearer,
// Cookie, Content-Type: application/json, Content-Length, Host, and the declared correlation header's name). Each text
// and the expected value are read folded (NFKD normalization, combining marks dropped, upper-cased then lower-cased, so
// a spelling without accents or a full case fold of a text reads as the text) and with each run of white space read as
// one space. The value is carried when it is part of any text, when it contains a text of three characters or more,
// when its letters and digits alone are part of those of a text or contain those of one that has three or more (so
// cafe-creme reads as Cafe creme), or when one of its words (runs of letters) equals a word of a text (a run of letters
// or digits), has the same singular form, contains such a word of three characters or more, or has three characters or
// more and is part of one. So no number, no record id, no single word (true, false, null, yes, granted), no echo of the
// path, a header, the host or an actor (folded or not), and no value one request of the profile sends (a title a POST
// wrote, or its accent-free slug) ever counts. json.exists, json.notContains and every other json.equals never count.
// Each record predicate is recorded as [index, field, value]: its index among the check's JSON predicates (the order of
// the row's observed predicates), and the rank of its pointer and of its expected value among those of every record
// predicate of the profile (so two predicates on one field, or with one value, have the same rank; neither is readable
// from it). Each row records its check's (controlScope.recordPredicates) and the exported suite binds them (each suite
// check's recordPredicates) and each required control's declared partners (recordPartners), which the validator
// recomputes from the recorded route segments and ranks, so a run cannot add a partner by editing a route.
// Cost: an allowed use shows a served record only beside a second required control of the same actor and method on
// another record of the same route, sending no body (or an empty one), answering the same top-level keys, both
// declaring the same top-level field equal to different text values of two words or more without a digit or an outcome
// word that no request of the profile, header or actor carries (declare, say, /title "Alpha ledger" on GET
// /api/invoices/3 and /title "Bravo ledger" on GET /api/invoices/4). A route with a single allowed use, a write that
// sends a body, a nested field, a number, an identifier, a single word, a captured value in the control's own request,
// a value the profile writes, records whose key sets differ, and any record field whose name or text value holds an
// outcome word (status, statusCode, ok, message, access, "Request failed"), never show one. The rule reads only these
// texts under these readings: an application that derives text from a record identifier in a way no reading above
// undoes (a translation, such as a number written as a word) and that answers it on both records is not seen; nor is
// one that refuses an allowed use but still answers, for both records and in the record's own shape, the field values
// the profile declares for them (it has then served those values). A forger who edits a saved run's observations (its
// predicates' outcomes, its clean object flag, its key set or sent route digests, or rows it deletes) is outside this
// rule, as for every row: saved evidence is not signed.
//
// Reading a path: a path that does not start with "/", or holds "?" or "#" (a query or fragment may select the
// resource), is opaque. So is one over 2048 characters or 64 segments, with an empty segment other than one trailing
// slash, a "." or ".." segment, a segment that still holds "%" after three rounds of percent-decoding or does not decode,
// a decoded character outside the ASCII path characters (letters, digits and . _ ~ ! $ & ' ( ) * + , = : @ -, so a
// decoded slash, backslash, semicolon, question mark, hash, space or non-ASCII letter), a segment over 128 characters,
// a {{name}} that is not a whole segment, or more than 256 stem keys in all. An opaque path reads as one record position
// at the root with no stem key, so a check on it is never released and a control on it is never separated from anything.
// Each other segment is a record position (a {{name}} placeholder, or an identifier literal: an all-digit, UUID or long
// hexadecimal segment), a namespace ("api", "apis", or a version such as "v1" or "v2.1": no stem keys), or a literal (a
// trailing slash is a literal with no text and no stem keys). A literal's stem keys come from its decoded, lower-cased
// text: split into runs of letters at every other character, each run gives every four-letter window in it (the whole
// run when it is shorter), its first three letters, and the first three letters of its consonant outline (its first
// letter, then its other letters without a, e, i, o and u, with a letter repeated in a row then read once), and the same again
// for its singular form (people, mice, geese, teeth, feet, data, media, indices, children, men, women and criteria by
// name; -ies to -y in a run over four letters; -ches, -shes, -sses, -xes and -zes drop -es; any other -s is dropped,
// except -ss, -us and -is). So an abbreviation shares a key with the word it shortens (orgs and organizations share org,
// docs and documents doc, msgs and messages msg). Lower-casing first means case never hides a shared key (customerNotes,
// customernotes and CUSTOMERNOTES give the same keys). So with GET /api/invoices/3 and GET /api/invoices/4 as required
// controls that answered their declared 200 with clean JSON objects whose /title equals "Alpha ledger" and "Bravo ledger"
// (each a served record beside the other), a GET /api/invoices/{{other}} refusal (other captured as an integer) is
// released from a failed control that showed a served record on /api/notes/{{id}}, and stays paired with one on /api/invoices/{{id}}/notes, /api/userInvoiceNotes/{{c}} or
// /api/{{coll}}/{{id}}/history. Without such an anchor every failed control pairs with B by route: different names, an
// owner or tenant slug, an alias or a query never release on their own. The rule withholds more than it needs to (a
// shared short key, such as ment in comments and payments, or inv in invoices and inventory, keeps two routes paired).
import { digest } from './domain.mjs';
import { selectorPairs, absenceClause, positiveClause } from './http-pairing.mjs';
import { evaluateEffectAssertion, decidedByGaps, otherActorCommit, custodyWindows } from './effect-events.mjs';
import { EFFECT_ASSERTION_PATTERN } from './http-effects.mjs';
import { CLAIM_ASSERTION_PATTERN, NOT_REQUIRED } from './http-claims.mjs';

export const ROUTE_LIMITS = Object.freeze({ pathChars: 2048, segments: 64, segmentChars: 128, keys: 256, decodeRounds: 3 });
export const MAX_ROUTE_SEGMENTS = ROUTE_LIMITS.segments;
// The one predicate kind that can be a record predicate, and the one capture type that can fill the last record position
// of an anchored route (see the header).
export const RECORD_PREDICATE_KIND = 'json.equals';
export const RECORD_CAPTURE_TYPE = 'integer';
// A text that names an outcome or an access decision rather than a record (outcomeText): read folded (fold below), it
// contains one of OUTCOME_WORDS anywhere, or has one of SHORT_OUTCOME_WORDS as a word (words split at every character that
// is not a letter and at each lower-to-upper case change, so isOk, is_ok and OK all hold ok). A top-level key that names
// an outcome, or a top-level string value that does, makes a JSON object unclean (error, errors, status, success, ok and
// message in any letter case, statusCode, error_message, isError or HTTPStatus, and access "denied", detail "forbidden",
// allowed false or authorized false); a record predicate's value never names one (Access denied).
export const OUTCOME_WORDS = Object.freeze(['error', 'status', 'success', 'message', 'fault', 'failure', 'failed', 'denied', 'deny', 'forbidden', 'unauthorized', 'unauthorised', 'unauthenticated', 'refused', 'rejected', 'invalid',
  'access', 'allowed', 'permission', 'permitted', 'authorized', 'authorised', 'granted', 'insufficient', 'restricted', 'blocked', 'locked', 'redacted', 'unavailable']);
export const SHORT_OUTCOME_WORDS = Object.freeze(['ok', 'err', 'msg', 'fail']);
const caseWords = text => text.normalize('NFKC').replace(/([\p{Ll}\p{N}])(\p{Lu})/gu, '$1 $2').replace(/(\p{Lu})(\p{Lu}\p{Ll})/gu, '$1 $2').toLowerCase().match(/\p{L}+/gu) ?? [];
export const outcomeText = value => {
  const text = String(value), lower = fold(text);
  return OUTCOME_WORDS.some(word => lower.includes(word)) || caseWords(text).some(word => SHORT_OUTCOME_WORDS.includes(word));
};
// The header names and constant header values the connector sends (src/http-connector.mjs observeHttp, and the Host
// header Node adds); the declared correlation header's name is added per profile. The credential, the content length and
// the correlation token vary and are not listed: no digit can count, and a value that only a credential carries is the
// same in both answers of a served record.
export const SENT_HEADER_TEXTS = Object.freeze(['Accept', 'application/json', 'Connection', 'close', 'Authorization', 'Bearer', 'Cookie', 'Content-Type', 'Content-Length', 'Host']);
// The bound on a recorded field or value rank: every JSON predicate of a full profile (50 checks of at most 10 predicates).
export const RECORD_RANK_LIMIT = 500;
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
// One text folded: compatibility-decomposed (NFKD), its combining marks dropped, case-folded (upper-cased then
// lower-cased, so the German sharp s reads ss), so a spelling without accents or another letter case of a text reads
// as the text. Folding can only find more echoes and more outcome words, which withholds.
const fold = value => String(value).normalize('NFKD').replace(/\p{M}/gu, '').toUpperCase().toLowerCase();
// One text as the echo comparison reads it: folded, each run of white space read as one space, trimmed; and its skeleton,
// its letters and digits alone (so cafe-creme and Cafe creme read the same).
const echoText = value => fold(value).replace(/\s+/gu, ' ').trim();
const skeleton = text => text.replace(/[^\p{L}\p{N}]/gu, '');
// The words of a text: runs of letters and digits, any script.
const WORD = /[\p{L}\p{N}]+/gu;
const wordsOf = text => text.match(WORD) ?? [];
const decoded = part => { let text = part; for (let round = 0; round < ROUTE_LIMITS.decodeRounds && text.includes('%'); round++) { try { text = decodeURIComponent(text); } catch { break; } } return text; };
const hasPlaceholder = text => text.includes('{{') || text.includes('}}');
// Does a check send a body other than none, an empty object or an empty array? Any key or value can carry text.
const sendsBody = body => body !== undefined && !(Array.isArray(body) && body.length === 0) && !(plain(body) && Object.keys(body).length === 0);
// The texts a request of the profile can carry (see the header): every check's method, path (raw, decoded, and each part
// between / ? # & = and ; decoded) and body (every key and string or number value, raw and decoded, and the body as JSON),
// the origin as written with its host, host name and port, every actor's alias and declared string or number, every
// observer's witness request, and every header name and constant value the connector sends. { whole, words }: whole the texts as echoText reads them, words
// their words. null (so no predicate counts) when the profile has no actors object, no origin string or no checks array.
export function requestTexts(target) {
  if (!plain(target) || !plain(target.actors) || typeof target.origin !== 'string' || target.origin === '' || !Array.isArray(target.checks)) return null;
  const carried = [target.origin, ...SENT_HEADER_TEXTS];
  try { const url = new URL(target.origin); carried.push(url.host, url.hostname, url.port); } catch { /* the origin as written still counts */ }
  if (plain(target.correlation) && typeof target.correlation.header === 'string') carried.push(target.correlation.header);
  // An observer's witness request (src/http-connector.mjs sendWitness: its method and path, tagged scopehaven_witness).
  for (const observer of Array.isArray(target.observers) ? target.observers : []) if (plain(observer?.witness)) {
    for (const value of Object.values(observer.witness)) if (typeof value === 'string') carried.push(value, decoded(value), ...value.split(/[/?#&=;]/).map(decoded));
    carried.push('scopehaven_witness');
  }
  for (const [alias, actor] of Object.entries(target.actors)) {
    carried.push(alias);
    for (const value of plain(actor) ? Object.values(actor) : []) if (typeof value === 'string' || typeof value === 'number') carried.push(String(value));
  }
  const walk = (value, depth) => {
    if (depth > 32) return;
    if (typeof value === 'string') carried.push(value, decoded(value));
    else if (typeof value === 'number') carried.push(String(value));
    else if (Array.isArray(value)) for (const item of value) walk(item, depth + 1);
    else if (plain(value)) for (const [key, item] of Object.entries(value)) { carried.push(key, decoded(key)); walk(item, depth + 1); }
  };
  for (const check of target.checks) {
    if (!plain(check)) continue;
    const path = String(check.path ?? '');
    carried.push(String(check.method ?? ''), path, decoded(path), ...path.split(/[/?#&=;]/).map(decoded));
    walk(check.body, 0);
    if (check.body !== undefined) carried.push(JSON.stringify(check.body) ?? '');
  }
  const whole = carried.map(echoText).filter(text => text !== '');
  return { whole, words: new Set(whole.flatMap(wordsOf)), skeletons: [...new Set(whole.map(skeleton).filter(text => text.length >= 3))] };
}
// Is a value in the text form a record predicate needs (see the header)? A string that, after NFKC, holds no digit of
// any script and at least two runs of three or more letters, and that names no outcome (outcomeText).
export const recordText = value => {
  if (typeof value !== 'string') return false;
  const text = value.normalize('NFKC');
  return !/\p{N}/u.test(text) && (text.match(/\p{L}{3,}/gu) ?? []).length >= 2 && !outcomeText(text);
};
// Does a request of the profile carry an expected value (see the header)? Read as echoText: it is part of a text; it
// contains a text of three characters or more; its skeleton is part of a text's skeleton or contains one of three
// characters or more; or one of its words equals a word of a text, has the same singular form, contains one of three
// characters or more or is one of three characters or more contained in one.
export function carriedByRequest(expected, texts) {
  const text = echoText(expected), words = wordsOf(text), bare = skeleton(text);
  if (words.length === 0 || texts.whole.some(t => t.includes(text) || (t.length >= 3 && text.includes(t)))) return true;
  if (bare.length >= 3 && texts.skeletons.some(t => t.includes(bare) || bare.includes(t))) return true;
  for (const word of words) for (const other of texts.words) {
    if (word === other || singular(word) === singular(other) || (other.length >= 3 && word.includes(other)) || (word.length >= 3 && other.includes(word))) return true;
  }
  return false;
}
// Is an assertion a record predicate (see the header)? A json.equals whose pointer is exactly one reference token, whose
// expected value is in the record text form, and which no request of the profile carries (texts: requestTexts of the
// profile; null means unknown, so never).
export const recordPredicate = (a, texts) => plain(a) && a.kind === RECORD_PREDICATE_KIND && typeof a.pointer === 'string' && /^\/[^/]+$/.test(a.pointer) && recordText(a.expected)
  && plain(texts) && Array.isArray(texts.whole) && texts.words instanceof Set && Array.isArray(texts.skeletons) && !carriedByRequest(a.expected, texts);
// The record predicates of every check of a profile: check id -> [[index, field, value]] (see the header), index among the
// check's JSON predicates, field and value the ranks of its pointer and its expected value among those of every record
// predicate of the profile. A check whose own path holds a {{name}} placeholder, or that sends a body other than an
// empty object or array, has none.
export function recordClasses(target) {
  const texts = requestTexts(target), found = new Map();
  for (const check of Array.isArray(target?.checks) ? target.checks : []) {
    if (!plain(check) || typeof check.id !== 'string') continue;
    const own = hasPlaceholder(String(check.path ?? '')) || sendsBody(check.body) ? []
      : (Array.isArray(check.assertions) ? check.assertions : []).filter(a => typeof a?.kind === 'string' && a.kind.startsWith('json.')).flatMap((a, i) => recordPredicate(a, texts) ? [[i, a.pointer, a.expected]] : []);
    found.set(check.id, own);
  }
  const all = [...found.values()].flat(), rank = list => [...new Set(list)].sort();
  const fields = rank(all.map(([, pointer]) => pointer)), values = rank(all.map(([, , expected]) => expected));
  return new Map([...found].map(([id, own]) => [id, own.map(([i, pointer, expected]) => [i, fields.indexOf(pointer), values.indexOf(expected)])]));
}
// The record predicates of one check of a profile (recordClasses), or none when the profile does not hold it.
export const recordPredicates = (check, target) => Array.isArray(target?.checks) && target.checks.includes(check) ? recordClasses(target).get(check.id) ?? [] : [];
// Is a response a clean JSON object? Complete, parsed, an object (not an array, null or a scalar) and without a top-level
// key or top-level string value that names an outcome (outcomeText). Read by the connector before the body is discarded.
export const cleanObject = observation => plain(observation) && observation.complete === true && observation.jsonParsed === true && !observation.error
  && plain(observation.json) && !Object.entries(observation.json).some(([key, value]) => outcomeText(key) || (typeof value === 'string' && outcomeText(value)));
// The path as sent, read for one comparison only (another record, see the header): each segment percent-decoded (at most
// three rounds, kept as it is when it does not decode), lower-cased, an identifier literal (all-digit, UUID or long
// hexadecimal) without dashes and without leading zeros, and trailing slashes dropped, as a digest keyed with the run's route key. Normalizing here can only make two paths read the
// same, which withholds. Linear in the path's length.
export function sentRoute(path, key) {
  const parts = String(path ?? '').split('/').map(part => {
    let text = part;
    for (let round = 0; round < ROUTE_LIMITS.decodeRounds && text.includes('%'); round++) { try { text = decodeURIComponent(text); } catch { break; } }
    text = text.toLowerCase();
    // An identifier literal (all-digit, UUID or long hexadecimal) in one canonical spelling: without dashes and without
    // leading zeros.
    if (IDENTIFIER_LIKE.test(text)) text = text.replace(/-/g, '').replace(/^0+(?=[0-9a-f])/, '');
    return text;
  });
  while (parts.length > 1 && parts.at(-1) === '') parts.pop();
  return digest({ key, sent: parts.join('/') });
}
// What a row records for this rule (evidence.controlScope): whether the response was a clean JSON object, the check's
// record predicates ([index, field, value], from classes: recordClasses of the profile, read once per run), the keyed
// sent route, and for a clean object its top-level key set as a digest keyed the same way (bodyKeys: partners answer the
// same key set; null otherwise). sentPath: the path as sent, or null for a row that was not sent.
export function controlScopeEvidence(check, observation, sentPath, key, classes) {
  const clean = sentPath !== null && cleanObject(observation);
  return { cleanObject: clean, recordPredicates: classes instanceof Map ? classes.get(check?.id) ?? [] : [], sentRoute: sentPath === null ? null : sentRoute(sentPath, key),
    bodyKeys: clean ? digest({ key, bodyKeys: Object.keys(observation.json).sort() }) : null };
}
// One recorded record predicate: [index, field, value], three integers, the index among predicates (a json.equals), the
// two ranks below RECORD_RANK_LIMIT.
const rank = value => Number.isInteger(value) && value >= 0 && value < RECORD_RANK_LIMIT;
export const recordEntryShape = (entry, predicates) => Array.isArray(entry) && entry.length === 3 && entry.every(rank) && entry[0] < predicates.length && predicates[entry[0]]?.kind === RECORD_PREDICATE_KIND;
// The shape of a recorded controlScope (the validator): exactly those four fields; cleanObject true only on a complete
// parsed body; recordPredicates [index, field, value] entries with indices of json.equals predicates of the row, sorted and
// unique; sentRoute a digest exactly when the row was sent; bodyKeys a digest exactly when cleanObject is true.
// predicates: the row's observed JSON predicates.
export function controlScopeShape(value, predicates, { isDigest = v => typeof v === 'string', completeJSON = false, sent = true } = {}) {
  if (!plain(value) || Object.keys(value).length !== 4 || typeof value.cleanObject !== 'boolean' || !Array.isArray(value.recordPredicates) || !Array.isArray(predicates)) return false;
  if (value.cleanObject && !completeJSON) return false;
  if (sent ? !isDigest(value.sentRoute) : value.sentRoute !== null) return false;
  if (value.cleanObject ? !isDigest(value.bodyKeys) : value.bodyKeys !== null) return false;
  return value.recordPredicates.every((entry, k) => recordEntryShape(entry, predicates) && (k === 0 || value.recordPredicates[k - 1][0] < entry[0]));
}
// An identifier-like literal (all digits, a UUID, or a long hexadecimal string) names one record, not a route family,
// so it reads as a record position like a {{name}} placeholder.
const IDENTIFIER_LIKE = /^(?:[0-9]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})$/;
const PLACEHOLDER = /^\{\{[A-Za-z][A-Za-z0-9_]{0,31}\}\}$/;
const PATH_CHARS = /^[A-Za-z0-9._~!$&'()*+,=:@-]+$/;
const NAMESPACE = /^(?:api|apis|v[0-9]{1,3}(?:\.[0-9]{1,3}){0,2})$/;
const IRREGULAR = new Map([['people', 'person'], ['mice', 'mouse'], ['geese', 'goose'], ['teeth', 'tooth'], ['feet', 'foot'], ['data', 'datum'], ['media', 'medium'],
  ['indices', 'index'], ['children', 'child'], ['men', 'man'], ['women', 'woman'], ['criteria', 'criterion']]);
// A route that cannot be read without guessing: a single record position at the root with no stem key.
const OPAQUE = Object.freeze([Object.freeze({ record: '', id: false })]);
export function singular(word) {
  if (IRREGULAR.has(word)) return IRREGULAR.get(word);
  if (word.length > 4 && word.endsWith('ies')) return `${word.slice(0, -3)}y`;
  if (/(?:ss|us|is)$/.test(word)) return word;
  if (/(?:ches|shes|sses|xes|zes)$/.test(word)) return word.slice(0, -2);
  return word.endsWith('s') ? word.slice(0, -1) : word;
}
// Every four-letter window of a run of letters (the whole run when it is shorter).
const windows = run => run.length < 4 ? [run] : Array.from({ length: run.length - 3 }, (_, i) => run.slice(i, i + 4));
// The first three letters of a run, and of its consonant outline (first letter, then the others without a, e, i, o and u,
// with a letter repeated in a row then read once), each only when there are three.
const prefix = run => run.length >= 3 ? [run.slice(0, 3)] : [];
const outline = run => prefix(`${run[0]}${run.slice(1).replace(/[aeiou]/g, '')}`.replace(/(.)\1+/g, '$1'));
const runKeys = run => [...windows(run), ...prefix(run), ...outline(run)];
// The stem keys of a decoded, lower-cased literal (see the header), sorted and unique. Linear in its length.
export const stemKeys = lower => [...new Set(lower.split(/[^a-z]+/).filter(Boolean).flatMap(run => [...runKeys(run), ...runKeys(singular(run))]))].sort();
// The declared capture types of a profile (name -> type), which decide whether a placeholder can be an anchored record.
export const captureTypes = target => new Map((Array.isArray(target?.checks) ? target.checks : []).flatMap(c => Object.entries(plain(c?.capture) ? c.capture : {}).map(([name, spec]) => [name, spec?.type])));
const typeOf = (types, name) => types instanceof Map ? types.get(name) : plain(types) && Object.hasOwn(types, name) ? types[name] : undefined;
// One segment: a { record, id } record position (record: the raw segment text; id: an identifier literal or an integer
// capture), a { exact, keys } literal (exact: the raw segment text), or undefined (opaque).
function readSegment(part, types) {
  if (PLACEHOLDER.test(part)) return { record: part, id: typeOf(types, part.slice(2, -2)) === RECORD_CAPTURE_TYPE };
  if (part === '') return { exact: '', keys: [] };
  if (part.includes('{{') || part.includes('}}')) return undefined;
  let text = part;
  for (let round = 0; text.includes('%'); round++) {
    if (round === ROUTE_LIMITS.decodeRounds) return undefined;
    try { text = decodeURIComponent(text); } catch { return undefined; }
  }
  if (text.length > ROUTE_LIMITS.segmentChars || !PATH_CHARS.test(text) || text === '.' || text === '..') return undefined;
  const lower = text.toLowerCase();
  if (IDENTIFIER_LIKE.test(lower)) return { record: part, id: true };
  return { exact: part, keys: NAMESPACE.test(lower) ? [] : stemKeys(lower) };
}
// A path template's segments in plain text. types: the profile's capture types (captureTypes). See the header.
export function pathSegments(pathTemplate, types = new Map()) {
  const path = String(pathTemplate ?? '');
  if (path.length > ROUTE_LIMITS.pathChars || !path.startsWith('/') || path.includes('?') || path.includes('#')) return OPAQUE;
  const parts = path.slice(1).split('/');
  if (parts.length > ROUTE_LIMITS.segments || parts.slice(0, -1).includes('')) return OPAQUE;
  const segments = [];
  let keys = 0;
  for (const part of parts) {
    const segment = readSegment(part, types);
    if (segment === undefined || (keys += segment.keys?.length ?? 0) > ROUTE_LIMITS.keys) return OPAQUE;
    segments.push(segment);
  }
  return segments;
}
// The segments a run records: each record position's raw text, and each literal's raw text and stem keys, are digests
// keyed with a per-run secret the run does not keep (the pattern of captureValueDigest), so two rows' segments can be
// compared within the run and the path cannot be read back from them. A record position keeps its id flag.
export const routeSegments = (pathTemplate, key, types = new Map()) => pathSegments(pathTemplate, types).map(segment => Object.hasOwn(segment, 'record')
  ? { record: digest({ key, record: segment.record }), id: segment.id }
  : { exact: digest({ key, segment: segment.exact }), keys: [...new Set(segment.keys.map(stem => digest({ key, stem })))].sort() });
// The shape of recorded segments (isDigest: the validator passes its 64-hex check): at least one, at most 64, each a
// { record, id } record position or a { exact, keys } literal with keys sorted and unique, and at most 256 keys in all.
export function recordedRouteShape(segments, isDigest = value => typeof value === 'string') {
  if (!Array.isArray(segments) || segments.length < 1 || segments.length > ROUTE_LIMITS.segments) return false;
  let keys = 0;
  return segments.every(segment => plain(segment) && Object.keys(segment).length === 2 && (Object.hasOwn(segment, 'record')
    ? isDigest(segment.record) && typeof segment.id === 'boolean'
    : isDigest(segment.exact) && Array.isArray(segment.keys) && (keys += segment.keys.length) <= ROUTE_LIMITS.keys && segment.keys.every((k, i) => isDigest(k) && (i === 0 || segment.keys[i - 1] < k))));
}
const isRecord = segment => Object.hasOwn(segment, 'record');
// A route read once: its shape, its stem keys, whether every record position comes right after a literal with stem keys
// (bounded), the index of its last record position, and whether it can be anchored at all. Anything malformed is invalid.
function routeInfo(segments) {
  if (!recordedRouteShape(segments)) return { valid: false, anchorable: false };
  const stems = new Set();
  let bounded = true, last = -1;
  segments.forEach((segment, i) => {
    if (!isRecord(segment)) { for (const k of segment.keys) stems.add(k); return; }
    last = i;
    if (i === 0 || isRecord(segments[i - 1]) || segments[i - 1].keys.length === 0) bounded = false;
  });
  return { valid: true, segments, stems, bounded, last, anchorable: last >= 0 && bounded && segments[last].id === true };
}
// Is anchor route a check route b's on another record (see the header)? Both read by routeInfo; b anchorable. The last
// record position holds different raw text, every other record position the same, every literal the same.
function sameRoute(b, a) {
  if (!a.valid || a.segments.length !== b.segments.length) return false;
  return b.segments.every((segment, i) => {
    const other = a.segments[i];
    if (!isRecord(segment)) return !isRecord(other) && other.exact === segment.exact;
    return isRecord(other) && (i === b.last ? other.id === true && other.record !== segment.record : other.record === segment.record);
  });
}
// Do two read routes share no stem key, each having at least one and each bounded? Anything malformed shares.
function separatedInfo(a, b) {
  if (!a.valid || !b.valid || !a.bounded || !b.bounded || a.stems.size === 0 || b.stems.size === 0) return false;
  for (const k of b.stems) if (a.stems.has(k)) return false;
  return true;
}
export const separated = (a, b) => separatedInfo(routeInfo(a), routeInfo(b));
// The paths as sent differ (both recorded, as keyed digests).
const sentApart = (b, a) => typeof b?.sentRoute === 'string' && typeof a?.sentRoute === 'string' && b.sentRoute !== a.sentRoute;
// Does anchor a (with its read route aInfo) anchor check b (bInfo)? The same method, b's route on another record, and
// another path as sent.
const anchors = (b, bInfo, a, aInfo) => bInfo.anchorable && plain(a) && a.method === b.method && sameRoute(bInfo, aInfo) && sentApart(b, a);
// Is check b anchored (see the header)? b and each anchor: { method, routeSegments, sentRoute }; anchors: the required
// controls of b's actor that showed a served record and passed (the caller decides that: anchorProven).
export function anchored(b, anchorRows = []) {
  if (!plain(b) || typeof b.method !== 'string') return false;
  const info = routeInfo(b.routeSegments);
  return (Array.isArray(anchorRows) ? anchorRows : []).some(r => plain(r) && anchors(b, info, r, routeInfo(r.routeSegments)));
}
// Can a required control show a served record at all, from its declarations (a view row: required, accepts,
// recordDeclared)? It declares exactly one status, a 2xx, and at least one record predicate. The suite binds this part.
export const anchorCandidate = row => plain(row) && row.required === true && Array.isArray(row.accepts) && row.accepts.length === 1 && Number.isInteger(row.accepts[0])
  && row.accepts[0] >= 200 && row.accepts[0] <= 299 && row.recordDeclared === true;
// A required control's own part of the served-record form in this run (see the header): its identity proven for it (its
// reason null and every probe point of its actor passed), exactly its declared 2xx, a complete parsed body that is a clean
// JSON object, and at least one record predicate that passed on a present value (recordPassed: the [field, value] ranks
// of those that passed). It shows a served record only beside a partner (servedRecords).
export const recordForm = row => anchorCandidate(row) && row.identityProven === true && row.httpStatus === row.accepts[0] && row.transportOutcome === 'complete'
  && row.jsonParsed === true && row.cleanObject === true && Array.isArray(row.recordPassed) && row.recordPassed.length > 0;
// Do two record predicates that passed differ on one field? Each a [field, value] pair of ranks.
const differOnAField = (a, b) => a.recordPassed.some(([field, value]) => b.recordPassed.some(([other, otherValue]) => field === other && value !== otherValue));
// Are r and p partners (see the header)? Both in the record form, the same actor and method, r's route anchorable and p's
// route the same on another record (rInfo and pInfo: routeInfo of each), other paths as sent, the same top-level key set
// (bodyKeys), and a record predicate of each that passed on the same field with different values.
const partners = (r, rInfo, p, pInfo) => r !== p && r.actorId === p.actorId && r.method === p.method && rInfo.anchorable && sameRoute(rInfo, pInfo) && sentApart(r, p)
  && typeof r.bodyKeys === 'string' && r.bodyKeys === p.bodyKeys && differOnAField(r, p);
// The partners a profile declares, bound by the exported suite: for each required control that can show a served record
// from its declarations (anchorCandidate), the required controls of the same actor and method, each a candidate too, on
// another record of its route (sameRoute), with a declared record predicate on one of its fields at another value. rows:
// { id, actorId, method, routeSegments, required, accepts, recordDeclared, recordRanks } (recordRanks: the [field,
// value] ranks of every declared record predicate). Returns id -> sorted ids, for every candidate.
export function declaredPartners(rows) {
  const candidates = rows.filter(anchorCandidate), info = new Map(candidates.map(row => [row, routeInfo(row.routeSegments)]));
  const ranks = row => Array.isArray(row.recordRanks) ? row.recordRanks : [];
  const declared = (r, p) => r !== p && r.actorId === p.actorId && r.method === p.method && info.get(r).anchorable && sameRoute(info.get(r), info.get(p))
    && ranks(r).some(([field, value]) => ranks(p).some(([other, otherValue]) => field === other && value !== otherValue));
  return new Map(candidates.map(r => [r.id, candidates.filter(p => declared(r, p)).map(p => p.id).sort()]));
}
// The required controls that showed a served record (see the header): those in the record form, whose status is not
// refusal-like for the actor, with a partner among them. rows: the view rows of one actor's required controls; infoOf:
// a row's routeInfo (read once by the caller). Rows are grouped by method and route with the last record position left
// out (partners always share both), and each pair within a group is checked in full, so the work is quadratic in the
// largest group at most.
export function servedRecords(rows, refused = () => false, infoOf = row => routeInfo(row.routeSegments)) {
  const groups = new Map(), served = new Set();
  for (const row of rows) {
    const info = infoOf(row);
    if (!recordForm(row) || refused(row.httpStatus) || !info.anchorable) continue;
    const key = JSON.stringify([row.actorId, row.method, info.segments.map((segment, i) => i === info.last ? null : segment)]);
    const group = groups.get(key);
    if (group) group.push([row, info]); else groups.set(key, [[row, info]]);
  }
  for (const group of groups.values()) for (const [r, rInfo] of group) for (const [p, pInfo] of group) if (partners(r, rInfo, p, pInfo)) { served.add(r); served.add(p); }
  return served;
}
// The statuses that count as a refusal of an actor's allowed use: its refusal statuses, every 3xx, and every status
// outside 2xx that one of its boundary checks accepts as the expected refusal.
export function refusalLike(refusalStatuses, boundaryAccepts = []) {
  const set = new Set(Array.isArray(refusalStatuses) && refusalStatuses.length ? refusalStatuses : [401, 403]);
  for (const codes of boundaryAccepts) for (const code of Array.isArray(codes) ? codes : []) if (Number.isInteger(code) && (code < 200 || code > 299)) set.add(code);
  return code => Number.isInteger(code) && (set.has(code) || (code >= 300 && code <= 399));
}
const names = list => (Array.isArray(list) ? list : []).filter(plain).map(entry => entry.name).filter(name => typeof name === 'string');
const sameOrMissing = (a, b) => a === undefined || b === undefined || a === b;
// Links (b) to (d) in the header: twins is b's selectorPairs entries.
function otherLinks(b, c, twins) {
  if (twins.some(entry => plain(entry?.pins) && Object.values(entry.pins).some(list => Array.isArray(list) && list.some(t => t?.checkId === c.id)))) return true;
  const absences = (b.effects ?? []).filter(e => absenceClause(e) && plain(e.select)), positives = (c.effects ?? []).filter(e => positiveClause(e) && plain(e.select));
  if (absences.some(x => positives.some(y => sameOrMissing(x.select.name, y.select.name) && sameOrMissing(x.select.source, y.select.source)))) return true;
  const bUses = (Array.isArray(b.captureUses) ? b.captureUses : []).filter(plain), cUses = (Array.isArray(c.captureUses) ? c.captureUses : []).filter(plain);
  if (bUses.some(u => u.captureCheckId === c.id) || cUses.some(u => u.captureCheckId === b.id)) return true;
  const cNames = new Set(names(cUses));
  return names(bUses).some(name => cNames.has(name));
}
// The static key route segments are read under for declarations alone (the suite's lists), never a run's key.
const STATIC_KEY = 'static-route-pairs';
// The declared partners of a profile's applicable required controls (bound by the exported suite: each required control's
// recordPartners), from declarations only (declaredPartners), under the same fixed key; a required control that cannot
// show a served record has none.
export function staticRecordPartners(target) {
  const applicable = (target.checks ?? []).filter(c => c?.applicability?.applies !== false), types = captureTypes(target), classes = recordClasses(target);
  const requiredIds = target.requiredControlIds ?? [];
  const rows = applicable.filter(c => requiredIds.includes(c.id)).map(c => {
    const status = (c.assertions ?? []).find(a => a?.kind === 'status.equals' || a?.kind === 'status.in'), own = classes.get(c.id) ?? [];
    return { id: c.id, actorId: c.actorId, method: c.method, routeSegments: routeSegments(c.path, STATIC_KEY, types), required: true,
      accepts: status ? (status.kind === 'status.in' ? status.expected : [status.expected]) : null, recordDeclared: own.length > 0, recordRanks: own.map(([, field, value]) => [field, value]) };
  });
  const partners = declaredPartners(rows);
  return new Map(rows.map(row => [row.id, partners.get(row.id) ?? []]));
}

// ---------------------------------------------------------------------------
// Option B (see the header).
export const RESTS_ON_LIMITS = Object.freeze({ ids: 8 });
const ONLY_KIND = 'effect.only';
const statusAssertions = check => (Array.isArray(check?.assertions) ? check.assertions : []).filter(a => typeof a?.kind === 'string' && a.kind.startsWith('status.'));
// Load (B2): why a check's restsOn is refused, or null. identityIds: the actor's identity control ids (src/contracts.mjs
// identityControlPlan); postChange: whether the check is a lifecycle post-change check. Each listed control is a required,
// applicable allowed-use control of the check's actor, not an identity control, with the check's method, exactly one
// declared status (a 2xx status.equals), no body on either, a record predicate and a declared partner (so it can show a
// served record), on the check's route at another record (#275's anchor rule: the check's route anchorable, the same
// literals and parent record positions, a different last record position).
export function restsOnProblem(check, target, { identityIds = [], postChange = false } = {}) {
  const ids = check?.restsOn;
  if (!Array.isArray(ids) || ids.length < 1 || ids.length > RESTS_ON_LIMITS.ids || !ids.every(id => typeof id === 'string') || new Set(ids).size !== ids.length) return `must list 1 to ${RESTS_ON_LIMITS.ids} distinct control ids`;
  if (check.severity === 'control' || postChange) return 'only a boundary check that is not a lifecycle post-change check rests on controls';
  if (!plain(target?.actors?.[check.actorId]) || typeof target.actors[check.actorId].credentialEnv !== 'string') return 'only a credentialed actor\'s check rests on controls';
  if (sendsBody(check.body)) return 'a check that sends a body cannot rest on a served record (only a check with no body has one)';
  const types = captureTypes(target), classes = recordClasses(target), partners = staticRecordPartners(target);
  const info = routeInfo(routeSegments(check.path, STATIC_KEY, types));
  if (!info.anchorable) return 'the check\'s route cannot be anchored (no query or fragment; each record position right after a word; the last an identifier literal or an integer capture)';
  const required = Array.isArray(target.requiredControlIds) ? target.requiredControlIds : [];
  for (const id of ids) {
    const control = target.checks.find(c => c?.id === id), status = statusAssertions(control);
    const why = !control || !required.includes(id) || control.severity !== 'control' || control.applicability?.applies === false ? 'is not an applicable required control'
      : id === check.id ? 'is the check itself'
      : control.actorId !== check.actorId ? 'belongs to another actor'
      : identityIds.includes(id) ? 'is an identity control'
      : control.method !== check.method ? 'has another method'
      : status.length !== 1 || status[0].kind !== 'status.equals' || !Number.isInteger(status[0].expected) || status[0].expected < 200 || status[0].expected > 299 ? 'does not declare exactly one 2xx status.equals'
      : sendsBody(control.body) ? 'sends a body'
      : !(classes.get(id) ?? []).length ? 'has no record predicate (a json.equals on one top-level field to two words of text no request carries)'
      : !(partners.get(id) ?? []).length ? 'has no declared partner (another required control on another record of its route with a record predicate on the same field at another value)'
      : !sameRoute(info, routeInfo(routeSegments(control.path, STATIC_KEY, types))) ? 'is not on the check\'s route at another record'
      : null;
    if (why) return `control "${id}" ${why}`;
  }
  return null;
}
// The required controls (view rows) that check x's route relation (c) relates it to: every one whose route is not
// separated from x's. From declarations (staticRestsOnRelated) or from a run's recorded segments (the validator); sorted ids.
export const relatedByRoute = (x, controls) => controls.filter(c => !separatedInfo(routeInfo(x?.routeSegments), routeInfo(c.routeSegments))).map(c => c.id).sort();
// The suite's restsOnRelated lists: for each applicable check that declares restsOn, the applicable required controls of its
// actor that relation (c) relates to it by route, from declarations only (under the fixed key).
export function staticRestsOnRelated(target) {
  const types = captureTypes(target), required = Array.isArray(target?.requiredControlIds) ? target.requiredControlIds : [];
  const applicable = (Array.isArray(target?.checks) ? target.checks : []).filter(c => c?.applicability?.applies !== false);
  const view = c => ({ id: c.id, actorId: c.actorId, routeSegments: routeSegments(c.path, STATIC_KEY, types) });
  const controls = applicable.filter(c => required.includes(c.id)).map(view);
  return new Map(applicable.filter(c => Array.isArray(c.restsOn)).map(c => { const x = view(c); return [c.id, relatedByRoute(x, controls.filter(r => r.actorId === c.actorId))]; }));
}
// Claim rules and effect.only clauses in relation (c): a claim rule of either side, and an effect.only clause of the check,
// relate by selector name and source as an absence or positive clause does. An effect.only clause has no one selector, so
// any positive clause or claim rule of the failed control relates to it.
const selectorsShare = (a, b) => sameOrMissing(a?.name, b?.name) && sameOrMissing(a?.source, b?.source);
function claimLinks(x, f) {
  const fPositive = [...(f.effects ?? []).filter(e => positiveClause(e) && plain(e.select)).map(e => e.select), ...(f.claims ?? []).filter(plain)];
  if ((x.effects ?? []).some(e => e?.kind === ONLY_KIND) && fPositive.length) return true;
  const xAbsent = [...(x.effects ?? []).filter(e => absenceClause(e) && plain(e.select)).map(e => e.select), ...(x.claims ?? []).filter(plain)];
  return xAbsent.some(a => fPositive.some(b => selectorsShare(a, b))) || (x.claims ?? []).filter(plain).some(a => fPositive.some(b => selectorsShare(a, b)));
}
// B4(b)(ii) and (iv): is a failed allowed-use control's failure inside the allowlist? Every assertion other than its effect
// and claim rows passed, and each effect or claim decision that did not pass is a positive reading that coverage gaps alone
// decided, or a positive pass that background attribution withheld; in both cases no committed send fits the clause under
// another actor (otherActorCommit). windows: the row's own check windows as its decisions read them (the connector's, or
// the validator's sealed windows bound again with the run's follow rule); principal: the principal of the row's actor.
export function failureAdmitted(row, windows, principal) {
  custodyWindows(windows, 'failureAdmitted');
  if (!Array.isArray(row?.assertions) || !row.assertions.every(a => EFFECT_ASSERTION_PATTERN.test(a?.name ?? '') || CLAIM_ASSERTION_PATTERN.test(a?.name ?? '') || a?.status === 'pass')) return false;
  const data = row.trace?.[1]?.data;
  if (!plain(data) || !Array.isArray(data.effects) || !Array.isArray(windows) || typeof principal !== 'string') return false;
  const clauseOf = e => ({ kind: e.kind, select: e.select, ...(Object.hasOwn(e, 'expected') ? { expected: e.expected } : {}), ...(Object.hasOwn(e, 'countBy') ? { countBy: e.countBy } : {}) });
  const decisions = [...data.effects.map(e => [e, e?.kind === ONLY_KIND ? null : clauseOf(e)]),
    ...(Array.isArray(data.claims) ? data.claims : []).map(c => [c, c?.reading === 'success' && c?.clause === 'effect.exists' ? { kind: 'effect.exists', select: c.select } : null])];
  return decisions.every(([d, clause]) => {
    if (!plain(d)) return false;
    if (d.verdict === 'pass' || d.verdict === NOT_REQUIRED) return true;
    if (clause === null || !positiveClause(clause) || Object.hasOwn(d, 'settlement')) return false;
    if (otherActorCommit(clause, windows, principal)) return false;
    const raw = evaluateEffectAssertion(clause, windows, { countBy: true, scoped: true });
    if (d.verdict === 'missing' || d.verdict === 'observer-failure') return !Object.hasOwn(d, 'attribution') && raw.verdict === d.verdict && decidedByGaps(raw);
    return d.verdict === 'inconclusive' && Object.hasOwn(d, 'attribution') && raw.verdict === 'pass';
  });
}
// The view rows, read from run rows (the connector's results, or a saved run's). #275's scopeView, plus for option B: index
// (the row's place in run order), credentialed, restsOn (the ids the row records), claims (its claim rules' selectors),
// untagged (no settlement, attribution or later-outcome tag on any clause), successOnly (every claim read success or was not required)
// and admitted (failureAdmitted, for a failed required control). Every argument is a reading the caller already holds:
// required, failed(row) (did this required control fail, before the identity assertion), identityProven(row)
// (src/contracts.mjs recordIdentityProven), refusalStatusesOf(actorId), codesOf(label), principals, credentialed(actorId)
// and admitted(row).
export function restsOnView(results, { required, failed, identityProven = () => false, refusalStatusesOf, codesOf, principals, credentialed = () => false, admitted = () => false }) {
  const rows = [], refusalStatuses = new Map();
  results.forEach((row, index) => {
    const evidence = row?.status !== 'not_applicable' && row?.trace?.[0]?.type === 'http-observation' ? row.trace[0].data : null;
    if (!plain(evidence)) return;
    const isRequired = required.includes(row.id), data = Array.isArray(row.trace) && row.trace.length === 2 && plain(row.trace[1]?.data) ? row.trace[1].data : null;
    const declared = Array.isArray(data?.effects) ? data.effects.filter(plain) : [], claims = Array.isArray(data?.claims) ? data.claims.filter(plain) : [];
    const effects = declared.map(e => ({ kind: e.kind, select: e.select, ...(Object.hasOwn(e, 'expected') ? { expected: e.expected } : {}) }));
    const label = Array.isArray(row.assertions) ? row.assertions.find(a => a?.name === 'HTTP status matches contract')?.expected : undefined;
    const predicates = Array.isArray(row.observed?.predicates) ? row.observed.predicates : [];
    const scope = plain(evidence.controlScope) ? evidence.controlScope : {}, record = Array.isArray(scope.recordPredicates) ? scope.recordPredicates.filter(e => Array.isArray(e) && e.length === 3 && e.every(Number.isInteger)) : [];
    const isFailed = isRequired && failed(row);
    rows.push({ id: row.id, index, actorId: evidence.actorId, severity: row.severity, required: isRequired, failed: isFailed, method: evidence.method, httpStatus: evidence.httpStatus, transportOutcome: evidence.transportOutcome,
      jsonParsed: evidence.jsonParsed, routeSegments: Array.isArray(evidence.routeSegments) ? evidence.routeSegments : [], effects, claims: claims.map(c => c.select), captureUses: evidence.captureUses, accepts: typeof label === 'string' ? codesOf(label) : null,
      recordDeclared: record.length > 0, recordRanks: record.map(([, field, value]) => [field, value]),
      recordPassed: record.filter(([i]) => plain(predicates[i]) && predicates[i].kind === RECORD_PREDICATE_KIND && predicates[i].outcome === 'pass' && predicates[i].present === true).map(([, field, value]) => [field, value]),
      cleanObject: scope.cleanObject === true, sentRoute: typeof scope.sentRoute === 'string' ? scope.sentRoute : null, bodyKeys: typeof scope.bodyKeys === 'string' ? scope.bodyKeys : null,
      identityProven: isRequired && identityProven(row) === true, credentialed: credentialed(evidence.actorId) === true,
      restsOn: Array.isArray(evidence.restsOn) ? evidence.restsOn : null,
      untagged: [...declared, ...claims].every(d => !Object.hasOwn(d, 'settlement') && !Object.hasOwn(d, 'attribution') && !Object.hasOwn(d, 'later')),
      successOnly: claims.every(c => c.reading === 'success' || c.verdict === NOT_REQUIRED),
      admitted: isFailed && admitted(row) === true });
    if (!refusalStatuses.has(evidence.actorId)) refusalStatuses.set(evidence.actorId, refusalStatusesOf(evidence.actorId));
  });
  return { rows, refusalStatuses, principals };
}
// The released checks (ids): every credentialed check that declares restsOn and meets (a) to (d) in the header. release
// false: none (the validator without an exported suite). Work: the served records once per actor (quadratic in the
// largest route group), then for each released candidate its listed controls and the actor's failed controls.
export function restsOnReleases({ rows, refusalStatuses = new Map(), principals = {} }, { release = true } = {}) {
  const released = new Set();
  if (!release) return released;
  const twins = selectorPairs({ actors: Object.fromEntries(Object.entries(principals ?? {}).map(([alias, principalId]) => [alias, { principalId }])),
    checks: rows.map(row => ({ id: row.id, severity: row.severity, actorId: row.actorId, effects: row.effects ?? [] })) });
  const byActor = new Map(), info = new Map();
  for (const row of rows) {
    const own = byActor.get(row.actorId);
    if (own) own.push(row); else byActor.set(row.actorId, [row]);
    info.set(row, routeInfo(row.routeSegments));
  }
  for (const [actorId, own] of byActor) {
    const candidates = own.filter(row => !row.required && row.credentialed && Array.isArray(row.restsOn) && row.restsOn.length > 0);
    if (!candidates.length) continue;
    const refused = refusalLike(refusalStatuses.get(actorId), own.filter(row => row.severity !== 'control').map(row => row.accepts));
    const served = servedRecords(own.filter(row => row.required), refused, row => info.get(row));
    const failed = own.filter(row => row.required && row.failed);
    // (b): every failed required control of the actor.
    if (!failed.every(f => served.has(f) && !refused(f.httpStatus) && f.admitted === true)) continue;
    const byId = new Map(own.map(row => [row.id, row]));
    for (const x of candidates) {
      const listed = x.restsOn.map(id => byId.get(id));
      // (a): every listed control.
      if (!listed.every(l => l !== undefined && l.required && l.failed === false && served.has(l) && !refused(l.httpStatus) && l.untagged && l.successOnly && anchors(x, info.get(x), l, info.get(l)))) continue;
      // (c): no failed control related to the check.
      if (failed.some(f => !separatedInfo(info.get(x), info.get(f)) || otherLinks(x, f, twins.get(x.id) ?? []) || claimLinks(x, f))) continue;
      // (d): a listed control sent after the check and after every failed control.
      if (!listed.some(l => l.index > x.index && failed.every(f => l.index > f.index))) continue;
      released.add(x.id);
    }
  }
  return released;
}
