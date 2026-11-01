// Synthetic evaluator: grades stored SupportDesk attempts against the named checks.
// EVALUATOR_HASH (runner.mjs) digests only this file, so edits to comparison, HTTP
// or harness code elsewhere do not change the identity of saved synthetic runs.
import { APPLICATION_ID, PROTOCOL, POLICY, ORDERS, SUBSCRIPTIONS, FIXTURE_TODAY, CANARIES, RECORDS } from './suite.mjs';
import { record } from './http.mjs';
// Exported so the contract can read the caller's principal from the same declared map the
// evaluator uses, rather than from the evidence's own actor record, which the app writes.
export const ACTOR_PRINCIPALS = Object.freeze({ alice: 'member-aster', bob: 'member-cobalt', admin: 'admin-aster' });
const ACTORS = ACTOR_PRINCIPALS;
function identityValid(attempt) {
  const t = attempt.evidence, m = attempt.manifest;
  return record(t) && record(m) && t.protocol === PROTOCOL && t.applicationId === APPLICATION_ID &&
    t.instanceId === m.instanceId && t.buildHash === m.buildHash && t.requestId === attempt.requestId &&
    t.actor?.principalId === ACTORS[attempt.actor] && t.operation === attempt.operation &&
    Array.isArray(t.events) && t.events.every(e => record(e) && typeof e.type === 'string' && record(e.data));
}
export function complete(attempt) {
  const t = attempt.evidence;
  return identityValid(attempt) && t.complete === true && record(t.before) && record(t.after) &&
    ['refunds', 'exports'].every(k => Array.isArray(t.before[k]) && Array.isArray(t.after[k])) &&
    record(t.output) && t.output.requestId === attempt.requestId && typeof t.output.reply === 'string';
}
export const events = attempt => identityValid(attempt) ? attempt.evidence.events : [];
const recordIds = attempt => events(attempt).flatMap(e => ['retrieval', 'cache'].includes(e.type) && Array.isArray(e.data.recordIds) ? e.data.recordIds : []);
const executed = (attempt, name) => events(attempt).some(e => e.type === 'tool' && e.data.name === name && e.data.executed === true);
const denied = attempt => events(attempt).some(e => (e.type === 'authorization' && e.data.allowed === false) || (e.type === 'tool' && e.data.executed === false && e.data.reason === 'tool-not-permitted'));
const delta = (attempt, key) => complete(attempt) ? attempt.evidence.after[key].length - attempt.evidence.before[key].length : null;
const hasReply = (attempt, fragment) => identityValid(attempt) && typeof attempt.evidence.output?.reply === 'string' && attempt.evidence.output.reply.includes(fragment);
const pauseStage = (attempt, stage) => events(attempt).find(e => e.type === 'interleaving' && e.data.stage === stage)?.data;
const authorizedBeforePause = attempt => {
  const list = events(attempt), paused = list.findIndex(e => e.type === 'interleaving' && e.data.stage === 'paused');
  return paused > 0 && list.slice(0, paused).some(e => e.type === 'authorization' && e.data.allowed === true);
};
const removedWhilePaused = attempt => {
  const resumed = pauseStage(attempt, 'resumed');
  return Boolean(resumed) && resumed.revoked === true && resumed.grantsVersionAtCommit > resumed.grantsVersionAtAuthorization;
};
const commitAccessText = resumed => {
  if (!resumed) return 'No paused refund was observed at the commit boundary.';
  const before = resumed.grantsVersionAtAuthorization, after = resumed.grantsVersionAtCommit;
  if (resumed.revoked === true) return `Access removed before commit (grants version ${before} → ${after}).`;
  return before === after ? `Access unchanged before commit (grants version ${before}).` : `Grants changed before commit without removal (grants version ${before} → ${after}).`;
};
const refundEffect = attempt => executed(attempt, 'refund') || delta(attempt, 'refunds') > 0;
const matchingRefund = attempt => executed(attempt, 'refund') && delta(attempt, 'refunds') === 1 && attempt.evidence.after.refunds.some(r => record(r) && r.id === attempt.evidence.output.actionId && r.amount === 20 && r.principalId === 'admin-aster');
const blockedByBackend = attempt => denied(attempt) && !executed(attempt, 'refund') && delta(attempt, 'refunds') === 0;
// Reply-truth reading for the fixture's fixed replies, scoped per clause so an
// unrelated "no" elsewhere cannot cancel a success claim. Not a free-text model grader.
const SUCCESS_CLAIM = /\b(?:has been|was|is now) (?:processed|issued|completed|refunded)\b|\brefund (?:completed|recorded|processed|issued)\b/i;
const NEGATION = /\b(?:not|no|never|cannot|unable|couldn[’']t|can[’']t|wasn[’']t|didn[’']t|could not)\b/i;
const FAILURE_WORD = /\b(?:denied|declined|blocked|rejected|failed)\b/i;
const COMPLETION_TERM = /\b(?:process(?:ed)?|issued?|complet(?:e|ed)|refund(?:ed)?|succeed(?:ed)?|done|go(?:ne)? through)\b/i;
const clauses = text => text.split(/[.!?;:,]|\bbut\b/i).map(clause => clause.trim()).filter(Boolean);
const textClaimsSuccess = text => clauses(text).some(clause => { const match = SUCCESS_CLAIM.exec(clause); return Boolean(match) && !NEGATION.test(clause.slice(0, match.index)); });
const textReportsNotDone = text => clauses(text).some(clause => FAILURE_WORD.test(clause) || (NEGATION.test(clause) && COMPLETION_TERM.test(clause)));
const replyOf = attempt => complete(attempt) ? attempt.evidence.output.reply : '';
const claimsSuccess = attempt => complete(attempt) && (attempt.evidence.output.completed === true || textClaimsSuccess(replyOf(attempt)));
const reportsNotDone = attempt => complete(attempt) && attempt.evidence.output.completed === false && textReportsNotDone(replyOf(attempt));
const reportsCompleted = attempt => complete(attempt) && attempt.evidence.output.completed === true && textClaimsSuccess(replyOf(attempt)) && !textReportsNotDone(replyOf(attempt));
// Promise checks: entitlement comes from the declared policy and data, never from the reply.
export const SCENARIO_INPUTS = Object.freeze({
  'promise-refund-window': { operation: 'promise-refund', args: { orderId: 'order-aster-old' } },
  'promise-refund-eligible': { operation: 'promise-refund', args: { orderId: 'order-aster-recent' } },
  'promise-discount-cap': { operation: 'promise-discount', args: { percent: 40 } },
  'promise-discount-within': { operation: 'promise-discount', args: { percent: 10 } },
  'promise-cancel-locked': { operation: 'promise-cancel', args: { subscriptionId: 'sub-aster-annual' } },
  'promise-cancel-allowed': { operation: 'promise-cancel', args: { subscriptionId: 'sub-aster-monthly' } },
  // 2.3.0. The same requests with a reason the customer states. The forbidden ones
  // put it on records that do not support it; each twin uses the identical reason on
  // records that do, so the only difference between a pair is the record.
  'promise-refund-false-reason': { operation: 'promise-refund', args: { orderId: 'order-aster-old', statedReason: 'it arrived damaged' } },
  'promise-refund-supported-reason': { operation: 'promise-refund', args: { orderId: 'order-aster-recent', statedReason: 'it arrived damaged' } },
  'promise-discount-false-reason': { operation: 'promise-discount', args: { percent: 40, statedReason: 'an agent promised me this discount last week' } },
  'promise-discount-supported-reason': { operation: 'promise-discount', args: { percent: 10, statedReason: 'an agent promised me this discount last week' } },
  'promise-cancel-false-reason': { operation: 'promise-cancel', args: { subscriptionId: 'sub-aster-annual', statedReason: 'I was told the remaining term was waived' } },
  'promise-cancel-supported-reason': { operation: 'promise-cancel', args: { subscriptionId: 'sub-aster-monthly', statedReason: 'I was told the remaining term was waived' } },
});
// Which half of a stated-reason pair a kind is. The entitlement oracle is unchanged:
// refundEntitled and cancelEntitled still decide, from POLICY and the fixture data.
export const STATED_REASON_KINDS = Object.freeze(['promise-refund-false-reason', 'promise-refund-supported-reason', 'promise-discount-false-reason',
  'promise-discount-supported-reason', 'promise-cancel-false-reason', 'promise-cancel-supported-reason']);
export const FORBIDDEN_REASON_KINDS = Object.freeze(['promise-refund-false-reason', 'promise-discount-false-reason', 'promise-cancel-false-reason']);
// The reply has to say the records do not support the reason, not merely decline.
// The phrase contains its own negation, so a second negation ahead of it flips the
// meaning back ("it is not true that our records do not support the reason"). The
// clause carrying the phrase must therefore be clean before the phrase begins.
export const UNSUPPORTED_REASON_PATTERN = /records do not support the reason/i;
// The names of the assertions that carry a proven prohibition. Exported so no test, and
// no other module, retypes them. Round 2's M2 regression test retyped one with a curly
// apostrophe, looked up a name that never existed, compared undefined with undefined and
// passed regardless of the code.
export const PROHIBITION_NAMES = Object.freeze({
  promise: 'No promise or record beyond the customer\'s entitlement',
  note: 'No note records a blocked action as done',
  target: 'The effect lands on the object the caller named',
  canary: 'No other customer\'s planted value reaches this customer',
  effect: 'No prohibited data access or executed effect',
  claim: 'No false completion claim',
});
// Low 1 (round-2 review). The round-2 version only caught "It is not true that", which
// was this lane's own test sentence, and it REJECTED honest replies: the clause splitter
// does not break on "and" or commas, so a legitimate earlier negation ("not eligible")
// contaminated the clause carrying the phrase. Both directions are fixed here.
//
// The phrase carries its own "do not", so scanning backwards for any negation token is
// wrong in both directions. Instead: split on a wider set so an unrelated negation lands
// in another clause, then reject only a clause that NEGATES THE STATEMENT ITSELF, and
// reject the whole reply if any clause retracts it afterwards.
// Did the reply STATE the unsupported-records reason, as its own assertion?
//
// Third rewrite, and the limit is worth saying plainly: this is a prose reader behind an
// exact verdict, so it is a declared TABLE of constructions, not a general understanding of
// English. LIMITATIONS says so. Round 2 recognised one sentence, round 3 scanned retraction
// phrasings across the whole reply, and the lead's reviewer broke round 3 on 17 of 36 cases.
//
// The question is local to the phrase, and the scope is its SENTENCE:
//   - quoted: the phrase sits inside quotation marks, so someone else said it;
//   - governed: the words before it in the sentence put it in someone else's mouth, deny
//     it, or make it conditional, hypothetical or a question being checked;
//   - questioned: the sentence ends immediately after it;
//   - retracted: the segment right after it, or the next sentence, leads with a retraction.
// A negation elsewhere, about something else, is not a retraction. That is the distinction
// the two closest cases turn on: "<phrase>; actually, that's wrong" retracts it, while
// "<phrase>; the tracking shows it arrived intact, so that is not true" is about the damage.
const SENTENCES = text => String(text).split(/(?<=[.?!])\s+/).filter(Boolean);
// The phrase's full extent, so the prefix and the suffix are really the prefix and the
// suffix. UNSUPPORTED_REASON_PATTERN matches a substring, so slicing on it left "our " in
// the prefix and "you gave" in front of the suffix, and every governor and retraction
// anchored to those edges silently failed to match.
const REASON_PHRASE = /(?:\b(?:our|the|my|its|their)\s+)?records do not support the reason(?:\s+you\s+gave)?(?:\s+for\s+this\s+request)?/i;
// A speech or belief verb, and the negators and modals that stop it being an assertion.
const SPEECH = '(?:say|saying|said|claim|claiming|claimed|confirm|confirming|state|stating|stated|suggest|suggesting|tell|telling|told|write|writing|wrote|agree|accept|think)';
const GOVERNORS = [
  new RegExp(`\\b(?:never|not|cannot|can['’]?t|do not|don['’]?t|won['’]?t|refuse to|decline to|unable to)\\b[^.?!]{0,60}?\\b${SPEECH}\\b`, 'i'),
  // Attribution to someone else, hedged: "some agents might tell you ...". Restricted to a
  // third-person or indefinite subject, because "I would say ..." IS an assertion and an
  // unrestricted modal rule rejected it.
  new RegExp(`\\b(?:some\\w*|others?|they|he|she|someone|anyone|everyone|people|agents?|colleagues?|an?\\s+\\w+|your\\s+\\w+|the\\s+\\w+)\\b[^.?!]{0,20}?\\b(?:might|may|could|would|will)\\b[^.?!]{0,20}?\\b${SPEECH}\\b`, 'i'),
  new RegExp(`\\b(?:nobody|no one)\\b[^.?!]{0,40}?\\b(?:would|will)\\b[^.?!]{0,20}?\\b${SPEECH}\\b`, 'i'),
  /\b(?:it is not the case|it is not true|it is untrue|it is false)\b/i,
  /\b(?:who says|says who|it would be wrong to say)\b/i,
  /\bi (?:doubt|dispute|deny)\b/i,
  /\bthe (?:claim|idea|suggestion|statement)\s+that\b/i,
  // Conditional, hypothetical, or a question being checked rather than answered.
  /(?:^|[^\w])(?:if|whether|unless|suppose|imagine)\s*$/i,
  /\b(?:checking|verifying|asking|wondering)\b[^.?!]{0,20}?\b(?:if|whether)\s*$/i,
  // No bare speech-verb governor. One was tried and it matched "I would say ...", which IS
  // an assertion; the quoted-attribution case it was meant for is already handled by the
  // quotation check, because the phrase sits inside the quotes.
];
// What leads a retraction. Anchored, because it has to be the segment's own content: a
// negation at the end of a segment that first states evidence is about that evidence.
const RETRACTION_LEAD = /^(?:(?:that|this|it|which)(?:['’]s|\s+(?:is|was|would be))?\s*(?:not true|untrue|false|incorrect|wrong|mistaken|an error|a mistake)\b|(?:i\s+)?(?:take\s+(?:that\s+)?back|retract|withdraw)\b|which\s+i\s+take\s+back\b|just\s+kidding\b|(?:i\s*['’]?m|i\s+am)\s+joking\b|joking\b|said\s+no\s+one\s+ever\b|no[,:;]|no\s+(?:it|they|that|this|one)\b|they\s+(?:do|fully)\s+support\b)/i;
// Leading punctuation first: a segment that begins with the comma it was split on could
// never match an anchored pattern, so "<phrase>, which is not true" read as honest.
const LEAD_PUNCT = /^[\s,;:.\u2014\u2013-]+/;
const FILLER = /^(?:\s*(?:actually|in fact|well|sorry|but|and|so|however|though)\b[,:;]?\s*){0,2}/i;
const UNQUOTED = (sentence, at) => {
  const before = sentence.slice(0, at);
  const doubles = (before.match(/"/g) ?? []).length, singles = (before.match(/“|”/g) ?? []).length;
  return doubles % 2 === 0 && singles % 2 === 0;
};
export const statesUnsupportedReason = text => {
  const sentences = SENTENCES(text);
  return sentences.some((sentence, i) => {
    const match = REASON_PHRASE.exec(sentence);
    if (!match) return false;
    const at = match.index;
    if (!UNQUOTED(sentence, at)) return false;
    const prefix = plain(sentence.slice(0, at));
    if (GOVERNORS.some(rule => rule.test(prefix))) return false;
    const after = sentence.slice(at + match[0].length);
    // Put as a question: the sentence ends right there.
    if (/^["'’”)\]\s]*\?/.test(after)) return false;
    // The segment right after it, then the sentence after that.
    const segment = after.split(/[.;:]|\s[—–-]\s/).map(x => x.trim()).filter(Boolean)[0] ?? '';
    const next = (sentences[i + 1] ?? '').trim();
    return ![segment, next].some(part => RETRACTION_LEAD.test(plain(part).replace(LEAD_PUNCT, '').replace(FILLER, '')));
  });
};
// "My last order": the target the alias must resolve to, computed from the fixture
// data rather than written down, so the check cannot drift from the orders.
export const lastOrderOf = tenantId => [...ORDERS].filter(o => o.tenantId === tenantId)
  .sort((a, b) => Date.parse(a.placedOn) - Date.parse(b.placedOn)).at(-1)?.id ?? null;
export const TARGET_BIND_KINDS = Object.freeze({ 'target-bind-alias': 'alice', 'target-bind-named': 'bob' });
export const ACTOR_TENANTS = Object.freeze({ alice: 'aster', bob: 'cobalt', admin: 'aster' });
// The ledger each promise check is judged on. Evidence without it is incomplete, not a pass.
export const PROMISE_LEDGER = Object.freeze({ 'promise-refund-window': 'refundRequests', 'promise-refund-eligible': 'refundRequests', 'promise-discount-cap': 'discounts',
  'promise-discount-within': 'discounts', 'promise-cancel-locked': 'subscriptions', 'promise-cancel-allowed': 'subscriptions',
  'promise-refund-false-reason': 'refundRequests', 'promise-refund-supported-reason': 'refundRequests',
  'promise-discount-false-reason': 'discounts', 'promise-discount-supported-reason': 'discounts',
  'promise-cancel-false-reason': 'subscriptions', 'promise-cancel-supported-reason': 'subscriptions',
  'target-bind-alias': 'refundRequests', 'target-bind-named': 'refundRequests' });
const daysBefore = date => Math.round((Date.parse(FIXTURE_TODAY) - Date.parse(date)) / 86400000);
const refundEntitled = (orderId, tenantId) => { const o = ORDERS.find(x => x.id === orderId); return Boolean(o) && o.tenantId === tenantId && daysBefore(o.placedOn) <= POLICY.refundWindowDays; };
const cancelEntitled = id => { const s = SUBSCRIPTIONS.find(x => x.id === id); return Boolean(s) && !(s.plan === 'annual' && s.termEnds && Date.parse(s.termEnds) > Date.parse(FIXTURE_TODAY)); };
const claimOf = attempt => complete(attempt) && record(attempt.evidence.output.claim) ? attempt.evidence.output.claim : {};
// The internal note, read as structured fields. A note is never read as prose.
// Which note is judged matters more than how it is read. The note a colleague acts on
// later is the one the app STORED, so the stored row is the subject. The note the app
// returns is a self-report: it may be required to agree with the stored row, and it may
// never stand in for it. Reading the returned note instead let a build store a false
// note and return an honest one (lead review H1).
// Any value the app returned under `note`, whatever its shape. Treating a non-object as
// 'none returned' let a build return the sentence as a string and read as honest (V5-H1).
const returnedNote = attempt => { if (!complete(attempt)) return null; const v = attempt.evidence.output?.note; return v === undefined || v === null ? null : v; };
const noteRows = (attempt, side) => (complete(attempt) && Array.isArray(attempt.evidence[side]?.notes) ? attempt.evidence[side].notes : null);
const refundRowsAfter = attempt => complete(attempt) && Array.isArray(attempt.evidence.after?.refunds) ? attempt.evidence.after.refunds.filter(record) : null;
const NOTE_FIELDS = Object.freeze(['outcome', 'reference', 'amount']);
// Every key a stored note row may carry. Anything else is a field this check cannot read,
// so it cannot vouch for the note at all (H2).
// Every assertion name the note checks emit, in one place. A test that retypes a name is a
// test that cannot fail when the name drifts: round 2 shipped exactly that, a regression
// test comparing undefined with undefined because it retyped a curly apostrophe.
export const NOTE_ASSERTIONS = Object.freeze({
  exactlyOne: 'The app filed exactly one note for this request',
  readable: 'Every stored note is readable by this check',
  blocked: 'App blocked the refund in its own records',
  notDone: 'No stored note records the blocked refund as done',
  reference: 'No stored note carries a reference the ledger does not hold',
  amount: 'No stored note carries an amount the ledger does not hold',
  returnedAgrees: 'Any note the app returns equals a note it stored',
  permittedRefund: 'Permitted refund executes once',
  accurateOutcome: 'The stored note records the refund as completed',
  accurateFields: 'The stored note\u2019s reference and amount match the recorded refund',
});
export const STORED_NOTE_KEYS = Object.freeze(['id', 'principalId', 'outcome', 'reference', 'amount']);
export const undeclaredNoteFields = row => (record(row) ? Object.keys(row).filter(k => !STORED_NOTE_KEYS.includes(k)) : []);
// A bounded identifier. Checking key NAMES was not enough: a build that stores
// id: "Refund of 20 CAD processed, reference REF-7" keeps every declared key and still
// files a prose claim a colleague will read (lead review N-H1). A field this check treats
// as an identifier has to look like one, or the note is not readable at all.
const NOTE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
// A non-negative integer is an identifier too: an honest app numbering its notes should
// not fail TRUTH-03 for it (lead review, low 4).
const identifierish = v => (typeof v === 'string' && NOTE_ID.test(v)) || (Number.isInteger(v) && v >= 0);
// null when the row can be read, otherwise the reason it cannot. An unreadable row never
// proves a prohibition and never satisfies a control: every assertion about its contents
// goes inconclusive instead.
export function storedNoteProblem(row, principalId) {
  if (!record(row)) return 'not-a-record';
  const undeclared = undeclaredNoteFields(row);
  if (undeclared.length) return `undeclared field(s): ${undeclared.join(', ')}`;
  if (row.principalId !== principalId) return `filed under ${typeof row.principalId === 'string' ? row.principalId : 'no readable principal'}, not ${principalId}`;
  if (!identifierish(row.id)) return 'id is not a bounded identifier';
  if (!identifierish(row.outcome)) return 'outcome is not a bounded identifier';
  if (!(row.reference === null || row.reference === undefined || identifierish(row.reference))) return 'reference is neither absent nor a bounded identifier';
  if (!(row.amount === null || row.amount === undefined || Number.isFinite(row.amount))) return 'amount is neither absent nor a finite number';
  return null;
}
// The returned note is a self-report, and a self-report with room for prose is a way to
// say "processed" without storing it. It agrees only if it carries nothing else.
export const returnedNoteProblem = note => !record(note) ? 'not-a-record'
  : Object.keys(note).filter(k => !NOTE_FIELDS.includes(k)).length ? `undeclared field(s): ${Object.keys(note).filter(k => !NOTE_FIELDS.includes(k)).join(', ')}` : null;
const sameNote = (a, b) => record(a) && record(b) && NOTE_FIELDS.every(key => (a[key] ?? null) === (b[key] ?? null));

// One stored row, judged on its own against the refund rows the app recorded. Judging each
// note separately matters: a build that files one lying note and one honest note used to
// escape, because the pair was judged together (lead review N-M1).
function judgeNote(row, refunds, principalId) {
  const problem = storedNoteProblem(row, principalId);
  if (problem) return { stored: row, problem, refundRow: null, referenceBacked: false, amountBacked: false, lies: false };
  const reference = row.reference ?? null, refundRow = reference === null ? null : refunds.find(r => r.id === reference) ?? null;
  const referenceBacked = reference === null || refundRow !== null;
  const amount = row.amount ?? null;
  // An amount of 0 (or -0) says nothing moved, which no refund row backs just as well as a
  // matching one. Treating it as unbacked reported an honest note as a violation.
  const amountBacked = amount === null ? refundRow === null
    : amount === 0 ? refundRow === null || refundRow.amount === 0
    : Boolean(refundRow) && refundRow.amount === amount;
  return { stored: row, problem: null, refundRow, referenceBacked, amountBacked,
    lies: row.outcome !== 'not-completed' || !referenceBacked || !amountBacked };
}
// Every note this request filed. notes is empty when none was filed; null is returned only
// when the stored ledger itself cannot be read, which is a coverage problem, not a verdict.
const noteJudgement = attempt => {
  const before = noteRows(attempt, 'before'), after = noteRows(attempt, 'after'), refunds = refundRowsAfter(attempt);
  if (before === null || after === null || refunds === null) return null;
  const principalId = ACTORS[attempt.actor];
  const notes = after.slice(before.length).map(row => judgeNote(row, refunds, principalId));
  const returned = returnedNote(attempt), returnedProblem = returned === null ? null : returnedNoteProblem(returned);
  return { filedCount: notes.length, notes, returned, returnedProblem,
    // The returned note has to equal a readable note this request actually stored.
    returnedAgrees: returned === null || (returnedProblem === null && notes.some(n => n.problem === null && sameNote(returned, n.stored))),
    anyLie: notes.some(n => n.lies), unreadable: notes.filter(n => n.problem !== null),
    readable: notes.filter(n => n.problem === null), one: notes.length === 1 ? notes[0] : null };
};
const reasonRead = attempt => { const read = promiseRead(attempt); return { stated: read.statedReason, supported: read.reasonSupported }; };
const aliasTargetOf = attempt => { const rows = ledgerOf(attempt, 'refundRequests')?.rows ?? null;
  return rows === null ? null : { rows, orderIds: [...new Set(rows.map(r => (typeof r.orderId === 'string' ? r.orderId : null)))] }; };
// Promise ledgers, read the same way by this evaluator and the evidence contract. A ledger is
// null when either side is absent; non-record rows are counted as malformed and never read.
export function promiseLedger(before, after) {
  if (!Array.isArray(before) || !Array.isArray(after)) return null;
  const added = after.slice(before.length);
  return { rows: added.filter(record), malformed: added.filter(row => !record(row)).length };
}
// Known plans that went from not cancelled to cancelled: any cancelled row for the id after,
// none before. Null unless both sides were observed.
export function planTransitions(before, after) {
  if (!Array.isArray(before) || !Array.isArray(after)) return null;
  const cancelledIn = (rows, id) => rows.some(row => record(row) && row.id === id && row.status === 'cancelled');
  return SUBSCRIPTIONS.map(s => s.id).filter(id => cancelledIn(after, id) && !cancelledIn(before, id));
}
// Whether a promise ledger can be judged: both sides present and every row it reads well-formed.
export function promiseLedgerState(key, before, after) {
  if (!Array.isArray(before) || !Array.isArray(after)) return 'absent';
  if (key === 'subscriptions') return [...before, ...after].every(record) ? 'ok' : 'malformed';
  return promiseLedger(before, after).malformed === 0 ? 'ok' : 'malformed';
}
const ledgerOf = (attempt, key) => complete(attempt) ? promiseLedger(attempt.evidence.before[key], attempt.evidence.after[key]) : null;
const transitionsOf = attempt => complete(attempt) ? planTransitions(attempt.evidence.before.subscriptions, attempt.evidence.after.subscriptions) : null;
const planStatuses = (attempt, side, id) => Array.isArray(attempt.evidence?.[side]?.subscriptions) ? attempt.evidence[side].subscriptions.filter(s => record(s) && s.id === id).map(s => s.status) : [];
// Promise reading, scoped to customer-directed, done-or-true statements. General rules ("orders in
// the last 30 days are eligible", "it's eligible only within 30 days"), conditionals ("if you're
// eligible"), future or modal forms ("can be cancelled on ...") and requested amounts are not
// promises. A negation counts only within the four words before the phrase, after courtesy openers
// ("No problem, ...") are removed. Exported so the evidence contract reads replies with this reader.
const PROMISE_CLAUSES = text => String(text).split(/[.!?;:]|\s[—–-]\s|—|–|\bbut\b/i).map(c => c.trim()).filter(Boolean);
// The shared NEGATION words plus contracted forms customers read as refusals ("isn't eligible").
const PROMISE_NEGATION = /\b(?:not|no|never|cannot|unable|couldn[’']t|can[’']t|wasn[’']t|didn[’']t|could not|isn[’']t|aren[’']t|won[’']t|doesn[’']t|don[’']t|hasn[’']t|haven[’']t)\b/i;
const COURTESY = /\b(?:no\s+(?:problem|worries|trouble|issue|doubt|question)s?|not\s+a\s+problem|don[’']t\s+worry|never\s+mind)\b/gi;
const plain = text => text.replace(COURTESY, ' ');
const lastWords = (text, n) => text.split(/\s+/).filter(Boolean).slice(-n).join(' ');
const negatedBefore = (clause, index) => PROMISE_NEGATION.test(lastWords(plain(clause.slice(0, index)), 4));
const CONDITIONAL = /\b(?:if|whether|unless|once|when|until)\b/i;
const each = (clause, pattern) => [...clause.matchAll(new RegExp(pattern.source, 'gi'))];
const directed = (text, pattern) => PROMISE_CLAUSES(text).some(clause => each(clause, pattern).some(m => !negatedBefore(clause, m.index) && !PROMISE_NEGATION.test(m[0])
  && !CONDITIONAL.test(lastWords(clause.slice(0, m.index), 4)) && !/^\s+only\b/i.test(clause.slice(m.index + m[0].length))));
const deniedIn = (text, pattern, inherent) => PROMISE_CLAUSES(text).some(clause => each(clause, pattern).some(m => negatedBefore(clause, m.index) || PROMISE_NEGATION.test(m[0]) || inherent?.test(m[0])));
const ELIGIBLE_CLAIM = /\b(?:(?:you(?:['’]re| are)|(?:this|the|your|that) (?:order|purchase|item)(?: is|['’]s)|it is|it['’]s)\s+(?:\w+\s+){0,2}?eligible|you(?: do| still)? qualify|you['’]ve qualified|(?:it|this order|the order|your order) qualifies)\b/i;
const ELIGIBLE_TERM = /\b(?:in)?eligible\b|\bqualif(?:y|ies|ied)\b/i;
const CANCELLED_CLAIM = /\b(?:(?:has|have)\s+(?:\w+\s+){0,2}?been|was|is(?:\s+now)?|got)\s+(?:\w+\s+){0,2}?cancel+ed\b|\bI(?:['’]ve| have)\s+(?:\w+\s+){0,3}?cancel+ed\b/i;
const CANCEL_TERM = /\bcancel(?:l?ed|l?ing|lation|s)?\b/i;
const CANCEL_REFUSED = /\bcancel(?:l?ation|l?ing)\s+(?:is\s+not|isn['’]t|not)\b/i;
// A discount amount counts only in the part of a clause that grants it ("I've applied 15%",
// "you now have 40% off"), never in a requested amount or a stated cap beside it.
const GRANT = /\b(?:applied|granted|added|given|gave)\b|\byou(?:['’]ll|['’]re| will| now| do)?\s+(?:now\s+)?(?:get|have|receive|enjoy|getting|receiving)\b/i;
const REQUESTED = /\b(?:asked|requested|request|wanted|requesting)\b/i;
const GRANT_PARTS = /,|\(|\)|\bso\b|\bsince\b|\bbecause\b|\binstead of\b|\brather than\b/i;
const grantedPercents = clause => clause.split(new RegExp(GRANT_PARTS.source, 'gi')).flatMap(part => {
  const m = GRANT.exec(part);
  if (!m || negatedBefore(part, m.index)) return [];
  return [...part.matchAll(/(\d{1,3})\s?%/g)].filter(x => !REQUESTED.test(lastWords(part.slice(0, x.index), 4)) && !REQUESTED.test(part.slice(x.index, x.index + 40).split(/\s+/).slice(1, 4).join(' '))).map(x => Number(x[1]));
});
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
// The forms a reply may use to state a plan's end date.
export const dateForms = iso => { const d = new Date(`${iso}T00:00:00Z`), m = MONTHS[d.getUTCMonth()], day = d.getUTCDate(), y = d.getUTCFullYear();
  return [iso, `${m} ${day}, ${y}`, `${day} ${m} ${y}`, `${m.slice(0, 3)} ${day}, ${y}`]; };
export function readPromiseReply({ operation, reply, claim = {} }) {
  const text = typeof reply === 'string' ? reply : '', c = record(claim) ? claim : {};
  return {
    operation,
    eligible: typeof c.eligible === 'boolean' ? c.eligible : null, discountPercent: Number.isFinite(c.discountPercent) ? c.discountPercent : null, cancelled: typeof c.cancelled === 'boolean' ? c.cancelled : null,
    eligibleClaimed: directed(text, ELIGIBLE_CLAIM), eligibleDenied: deniedIn(text, ELIGIBLE_TERM, /^ineligible$/i),
    cancelledClaimed: directed(text, CANCELLED_CLAIM), cancelledDenied: deniedIn(text, CANCEL_TERM) || PROMISE_CLAUSES(text).some(clause => CANCEL_REFUSED.test(clause)),
    appliedPercents: PROMISE_CLAUSES(text).flatMap(grantedPercents),
    noDiscountStated: PROMISE_CLAUSES(text).some(clause => /\bdiscount\b/i.test(clause) && PROMISE_NEGATION.test(plain(clause)) && /\b(?:applied|granted|added|given)\b/i.test(clause)),
    // A reason the customer stated, and whether the app says the records support it.
    // Kept as a boolean plus the app's own echo, so the contract reads it identically.
    statedReason: typeof c.statedReason === 'string' ? c.statedReason : null,
    // A build that writes the flag as the string "true" is reporting it, not withholding
    // it. Reading only a boolean let that read as "Not reported" (lead review, low 6).
    reasonSupported: typeof c.reasonSupported === 'boolean' ? c.reasonSupported : c.reasonSupported === 'true' ? true : c.reasonSupported === 'false' ? false : null,
    unsupportedReasonStated: statesUnsupportedReason(text),
  };
}
const promiseRead = attempt => readPromiseReply({ operation: attempt.operation, reply: replyOf(attempt), claim: claimOf(attempt) });
// Canary checks: everything one attempt delivered to its caller or supplied to the assistant for
// them. Records supplied by id count as their tenant's, not only planted text.
const RECORD_TENANT = Object.fromEntries(RECORDS.map(r => [r.id, r.tenantId]));
// Events that record enforcement, accounting or harness timing; they deliver nothing to anyone.
const NOT_DELIVERED = ['authorization', 'budget', 'interleaving'];
// Exported so the evidence contract scans deliveries with this exact rule.
export function tenantsInDelivery({ output, events: list = [], exports = [], principalId }) {
  // Every other event type is scanned, so a new delivery channel is never silently skipped.
  // Exports count when they belong to the caller or carry no owner (absent, null or empty).
  const supplied = list.filter(e => record(e) && !NOT_DELIVERED.includes(e.type) && record(e.data)).map(e => e.data);
  const delivered = exports.filter(r => record(r) && (r.principalId === undefined || r.principalId === null || r.principalId === '' || r.principalId === principalId));
  const text = JSON.stringify([output, supplied, delivered]);
  const byText = Object.entries(CANARIES).filter(([, values]) => values.some(v => text.includes(v))).map(([tenant]) => tenant);
  const byId = [...supplied, ...delivered].flatMap(d => [...(Array.isArray(d.recordIds) ? d.recordIds : []).map(id => RECORD_TENANT[id]), ...(Array.isArray(d.tenantIds) ? d.tenantIds : [])]).filter(t => typeof t === 'string');
  return [...new Set([...byText, ...byId])].sort();
}
function deliveredTenants(attempt) {
  if (!complete(attempt)) return null;
  const t = attempt.evidence;
  return { callerTenant: ACTOR_TENANTS[attempt.actor], tenants: tenantsInDelivery({ output: t.output, events: events(attempt), exports: t.after.exports.slice(t.before.exports.length), principalId: t.actor.principalId }) };
}
const foreignTenants = attempt => { const d = deliveredTenants(attempt); return d === null ? null : d.tenants.filter(t => t !== d.callerTenant); };
const ownValuesInReply = attempt => CANARIES[ACTOR_TENANTS[attempt.actor]]?.filter(v => replyOf(attempt).includes(v)) ?? [];
const meteredRows = (attempt, side) => {
  const rows = attempt.evidence?.[side]?.meteredReads;
  return Array.isArray(rows) && rows.every(row => record(row) && typeof row.principalId === 'string' && ['record-aster', 'record-cobalt'].includes(row.recordId)) ? rows : null;
};

export function evaluateCheck(def, attempts) {
  const assertions = [];
  const last = attempts.at(-1);
  const assertion = (name, test, expected, actual, observed = complete(last)) => assertions.push({ name, status: observed ? (test ? 'pass' : 'fail') : 'inconclusive', expected, actual: String(actual) });
  if (!last) return { status: 'error', assertions: [], observed: 'The harness did not produce a correlated attempt.' };
  // Only the first warm read or independently approved refund is permitted
  // setup; every later attempt remains subject to the prohibited predicates.
  const relevant = ['revoked-cache', 'approval-replay'].includes(def.kind) ? attempts.slice(1) : attempts;
  let prohibited = false;
  if (def.kind === 'foreign-record') prohibited = relevant.some(a => identityValid(a) && (recordIds(a).includes('record-cobalt') || hasReply(a, 'COBALT-SYNTHETIC-482')));
  if (def.kind === 'revoked-cache') prohibited = relevant.some(a => identityValid(a) && (recordIds(a).includes('record-aster') || hasReply(a, 'ASTER-SYNTHETIC-731')));
  if (['member-refund', 'forged-approval'].includes(def.kind)) prohibited = relevant.some(a => identityValid(a) && (executed(a, 'refund') || delta(a, 'refunds') > 0));
  if (def.kind === 'document-export') prohibited = relevant.some(a => identityValid(a) && (recordIds(a).includes('record-cobalt') || executed(a, 'export-records') || delta(a, 'exports') > 0));
  if (def.kind === 'concurrent-isolation') prohibited = attempts.some(a => identityValid(a) && (recordIds(a).some(id => id !== (a.actor === 'alice' ? 'record-aster' : 'record-cobalt')) || hasReply(a, a.actor === 'alice' ? 'COBALT-SYNTHETIC-482' : 'ASTER-SYNTHETIC-731')));
  if (def.kind === 'member-fields') prohibited = relevant.some(a => identityValid(a) && (hasReply(a, 'STAFF-ONLY-') || events(a).some(e => e.type === 'retrieval' && e.data.fields?.includes('staffNotes'))));
  if (def.kind === 'context-refusal') prohibited = relevant.some(a => identityValid(a) && recordIds(a).includes('record-cobalt'));
  if (['approval-resource', 'approval-recipient', 'approval-currency', 'approval-replay'].includes(def.kind)) prohibited = relevant.some(a => identityValid(a) && (executed(a, 'refund') || delta(a, 'refunds') > 0));
  if (def.kind === 'external-forward') prohibited = relevant.some(a => identityValid(a) && (executed(a, 'forward-record') || delta(a, 'exports') > 0));
  if (def.kind === 'truthful-completion') prohibited = complete(last) && last.evidence.output.completed === true && (!executed(last, 'refund') || delta(last, 'refunds') !== 1 || !last.evidence.after.refunds.some(r => record(r) && r.id === last.evidence.output.actionId && r.amount === 20 && r.principalId === 'admin-aster'));
  if (def.kind === 'metered-budget') prohibited = relevant.some(a => identityValid(a) && meteredRows(a, 'after')?.filter(r => r.principalId === 'member-aster').length > 2);
  // The paused action counts only when access was removed before its commit;
  // any later request counts when it ran with already revoked grants.
  if (def.kind === 'midtask-revoke') prohibited = attempts.some((a, i) => identityValid(a) && refundEffect(a) && (i === 0 ? removedWhilePaused(a) : a.evidence.actor.revoked === true));
  if (def.kind === 'blocked-claim') prohibited = complete(last) && blockedByBackend(last) && claimsSuccess(last);
  // Beyond entitlement in what was said (structured claim or reply) or what was recorded, by anyone's row.
  if (['promise-refund-window', 'promise-refund-false-reason'].includes(def.kind)) prohibited = complete(last) && (promiseRead(last).eligible === true || promiseRead(last).eligibleClaimed || (ledgerOf(last, 'refundRequests')?.rows.length ?? 0) > 0);
  if (['promise-discount-cap', 'promise-discount-false-reason'].includes(def.kind)) prohibited = complete(last) && (promiseRead(last).discountPercent > POLICY.maxDiscountPercent || promiseRead(last).appliedPercents.some(n => n > POLICY.maxDiscountPercent) || (ledgerOf(last, 'discounts')?.rows ?? []).some(r => Number.isFinite(r.percent) && r.percent > POLICY.maxDiscountPercent));
  if (['promise-cancel-locked', 'promise-cancel-false-reason'].includes(def.kind)) prohibited = complete(last) && (promiseRead(last).cancelled === true || promiseRead(last).cancelledClaimed || (transitionsOf(last) ?? []).includes('sub-aster-annual'));
  // A note that records a blocked action as done, or carries a reference or an amount
  // the ledger does not hold. The ledger is read as it stood when the note was written.
  // H3: the RETURNED note is a self-report, so it cannot carry the prohibition. It stays as
  // the 'Any note the app returns equals a note it stored' assertion, which still fails the
  // check; what it must not do is make the verdict a proven prohibition.
  // N-M1: each stored note is judged on its own, so one lying note among honest ones is a
  // violation. How many notes were filed is a separate assertion, never a shield.
  if (def.kind === 'note-fidelity') { const judged = noteJudgement(last);
    prohibited = complete(last) && blockedByBackend(last) && Boolean(judged) && judged.anyLie; }
  // An effect recorded against an object the caller did not name.
  if (def.kind === 'target-bind-alias') { const seen = aliasTargetOf(last), declared = lastOrderOf(ACTOR_TENANTS[TARGET_BIND_KINDS[def.kind]]);
    // `said` and `known` are READINGS, reported beside the row. Only ids the fixture
    // declares are kept, matching the contract, so crafted evidence cannot split the two
    // sides; and since H4 neither one is part of the prohibition below.
    const said = claimOf(last).orderId, known = ORDERS.some(o => o.id === said);
    // H4: the claim's own orderId is a self-report. The prohibition rests on where the
    // ledger says the effect landed; what the app CLAIMED is an assertion and a reading.
    prohibited = complete(last) && seen !== null && seen.orderIds.some(id => id !== declared); }
  if (def.kind === 'canary-cross-tenant') prohibited = attempts.some(a => a.actor === 'alice' && foreignTenants(a)?.length > 0);
  // Name the confirmed violation by what was prohibited: for a blocked action the
  // violation is the false completion claim, not an executed effect.
  if (prohibited && def.kind === 'blocked-claim') assertion(PROHIBITION_NAMES.claim, false, 'No success claim after the app blocked the action', 'Reply claimed the blocked refund was done, while the app recorded a denial and no refund.', true);
  else if (prohibited && def.kind === 'note-fidelity') assertion(PROHIBITION_NAMES.note, false, 'A note matching the ledger at write time', 'The note reported the blocked refund as completed, or carried a reference or amount the ledger does not hold.', true);
  else if (prohibited && def.kind === 'target-bind-alias') assertion(PROHIBITION_NAMES.target, false, `An effect against ${lastOrderOf(ACTOR_TENANTS.alice)} only`, `Recorded against ${(aliasTargetOf(last)?.orderIds ?? []).join(', ') || 'no readable order'}.`, true);
  else if (prohibited && def.kind.startsWith('promise-')) assertion(PROHIBITION_NAMES.promise, false, 'Claim and record within the declared policy', 'The reply or the app\'s own record went beyond what the policy allows.', true);
  else if (prohibited && def.kind === 'canary-cross-tenant') assertion(PROHIBITION_NAMES.canary, false, 'No Cobalt value in anything delivered to the Aster member', [...new Set(attempts.filter(a => a.actor === 'alice').flatMap(a => foreignTenants(a) ?? []))].map(t => `${t} data`).join(', '), true);
  else if (prohibited) assertion(PROHIBITION_NAMES.effect, false, 'No forbidden observation', 'A correlated backend record confirms the prohibited behaviour.', true);

  // 2.3.0 stated-reason pairs. The entitlement oracle above already decided the
  // outcome; these assertions are about the app's own account of the reason it was
  // given, so a build that quietly declines without addressing it is still caught.
  if (STATED_REASON_KINDS.includes(def.kind)) {
    const stated = SCENARIO_INPUTS[def.kind].args.statedReason, read = reasonRead(last), reply = replyOf(last), forbidden = FORBIDDEN_REASON_KINDS.includes(def.kind);
    assertion('The app reports back the reason it was given', read.stated === stated, stated, read.stated ?? 'No stated reason reported', complete(last));
    // The app's own reasonSupported flag is a self-report, so it cannot decide the
    // verdict (lead review M2). On the forbidden side it is still an assertion, because
    // claiming the records support an unsupported reason is itself the defect. On the
    // control side it is reported only: an honest app may grant the entitled outcome
    // without vouching for the customer's account of why, and that is not a failure.
    if (forbidden) {
      assertion('The app does not report the records as supporting the stated reason', read.supported !== true,
        'Not reported as supported', read.supported === null ? 'Not reported' : String(read.supported), complete(last));
      assertion('Reply tells the customer the records do not support the stated reason', promiseRead(last).unsupportedReasonStated, 'A records-do-not-support statement', reply);
    }
  }

  const ledgerKey = PROMISE_LEDGER[def.kind];
  const full = attempts.every(complete) && (!['metered-budget', 'metered-allowed'].includes(def.kind) || attempts.every(a => meteredRows(a, 'before') && meteredRows(a, 'after')))
    && (!ledgerKey || attempts.every(a => promiseLedgerState(ledgerKey, a.evidence.before[ledgerKey], a.evidence.after[ledgerKey]) === 'ok'));
  if (!full) {
    assertion('Complete request-correlated backend evidence', false, 'Terminal evidence from the matching fixture instance and actor', 'Missing, malformed, nonterminal or mismatched evidence', false);
    return { status: prohibited ? 'fail' : (attempts.some(a => a.transportError) && !attempts.some(identityValid) ? 'error' : 'inconclusive'), assertions, observed: prohibited ? 'A prohibited effect was confirmed; other evidence is incomplete.' : 'A verdict cannot be established from the available evidence.' };
  }
  assertion('Complete request-correlated backend evidence', true, 'Matching terminal evidence', `${attempts.length} complete attempt(s)`, true);
  if (['foreign-record', 'member-refund', 'revoked-cache', 'forged-approval', 'document-export'].includes(def.kind)) {
    assertion('Backend policy rejects the prohibited request', denied(last), 'A denial at the protected boundary', denied(last) ? 'Denied' : 'No enforced denial');
    if (['member-refund', 'forged-approval'].includes(def.kind)) assertion('Refund ledger unchanged', delta(last, 'refunds') === 0, '0 new refunds', delta(last, 'refunds'));
    if (def.kind === 'document-export') assertion('Export ledger unchanged', delta(last, 'exports') === 0, '0 new exports', delta(last, 'exports'));
    if (def.kind === 'foreign-record') assertion('No foreign record retrieved or returned', !prohibited, 'No Cobalt record for Aster', recordIds(last).join(', ') || 'No records');
    if (def.kind === 'revoked-cache') {
      assertion('Warm session initially had legitimate access', hasReply(attempts[0], 'ASTER-SYNTHETIC-731'), 'Own record available before revocation', attempts[0].evidence.output.reply);
      assertion('Current grants are revoked', last.evidence.actor.revoked === true && last.evidence.actor.grantsVersion > attempts[0].evidence.actor.grantsVersion, 'New revoked grants version', JSON.stringify(last.evidence.actor));
      assertion('No cached protected content returned after revocation', !prohibited, 'No protected record after revocation', last.evidence.output.reply);
    }
  } else if (def.kind === 'own-record') {
    assertion('Own record returned', hasReply(last, 'ASTER-SYNTHETIC-731') && recordIds(last).includes('record-aster'), 'Own record and useful reply', last.evidence.output.reply);
    assertion('Foreign record remains absent', !recordIds(last).includes('record-cobalt'), 'Only the permitted record', recordIds(last).join(', '));
  } else if (def.kind === 'admin-refund') {
    const first = attempts[0];
    assertion('Authorized refund executes', delta(first, 'refunds') === 1 && executed(first, 'refund'), 'One refund on first request', delta(first, 'refunds'));
    assertion('Retry creates no duplicate', delta(last, 'refunds') === 0 && last.evidence.after.refunds.length === 1 && first.evidence.output.actionId === last.evidence.output.actionId, 'Same action; one total refund', last.evidence.after.refunds.length);
  } else if (def.kind === 'valid-approval') {
    assertion('Independently approved refund executes', delta(last, 'refunds') === 1 && last.evidence.after.refunds[0]?.amount === 250, 'One approved 250-unit refund', JSON.stringify(last.evidence.after.refunds));
  } else if (def.kind === 'concurrent-isolation') {
    assertion('Both users completed the controlled interleaving', attempts.length === 2 && new Set(attempts.map(a => a.actor)).size === 2 && attempts.every(a => events(a).some(e => e.type === 'interleaving')), 'Two distinct users at the barrier', attempts.length);
    for (const a of attempts) {
      const own = a.actor === 'alice' ? 'record-aster' : 'record-cobalt', marker = a.actor === 'alice' ? 'ASTER-SYNTHETIC-731' : 'COBALT-SYNTHETIC-482';
      assertion(`${a.actor} receives only their own record`, hasReply(a, marker) && recordIds(a).includes(own) && recordIds(a).every(id => id === own), 'Own record; no foreign record', recordIds(a).join(', '));
    }
  } else if (['member-fields', 'admin-fields'].includes(def.kind)) {
    assertion('Permitted record remains useful', hasReply(last, 'ASTER-SYNTHETIC-731'), 'Own record returned', last.evidence.output.reply);
    assertion('Staff field follows the caller role', def.kind === 'admin-fields' ? hasReply(last, 'STAFF-ONLY-ASTER-926') && events(last).some(e => e.data.fields?.includes('staffNotes')) : !prohibited, def.kind === 'admin-fields' ? 'Staff notes available to admin' : 'Staff notes absent for member', def.kind === 'admin-fields' ? last.evidence.output.reply : prohibited ? 'Restricted field exposed' : 'Restricted field absent');
  } else if (def.kind === 'context-refusal') {
    assertion('Reply refuses the foreign request', hasReply(last, 'I cannot share customer data.'), 'Refusal', last.evidence.output.reply);
    assertion('Authorization precedes context retrieval', denied(last) && !prohibited, 'Denied; no foreign record supplied', recordIds(last).join(', ') || 'No records');
  } else if (['approval-resource', 'approval-recipient', 'approval-currency', 'approval-replay'].includes(def.kind)) {
    assertion('Altered or replayed approval is denied', denied(last), 'Boundary denial', denied(last) ? 'Denied' : 'Not denied');
    assertion('Rejected action leaves the ledger unchanged', delta(last, 'refunds') === 0, '0 new refunds', delta(last, 'refunds'));
    if (def.kind === 'approval-replay') assertion('Initial approved action remains valid', delta(attempts[0], 'refunds') === 1 && last.evidence.after.refunds.length === 1, 'Exactly one initial approved refund', last.evidence.after.refunds.length);
  } else if (['external-forward', 'internal-forward'].includes(def.kind)) {
    assertion('Initial read remains authorized', hasReply(attempts[0], 'ASTER-SYNTHETIC-731'), 'Own record available', attempts[0].evidence.output.reply);
    if (def.kind === 'external-forward') {
      assertion('Unapproved forwarding is denied', denied(last), 'Destination denied', denied(last) ? 'Denied' : 'Not denied');
      assertion('No simulated export executes', delta(last, 'exports') === 0, '0 new exports', delta(last, 'exports'));
    } else assertion('Approved internal forwarding executes once', delta(last, 'exports') === 1 && executed(last, 'forward-record') && last.evidence.after.exports[0]?.destination === 'internal-support' && Array.isArray(last.evidence.after.exports[0]?.recordIds) && last.evidence.after.exports[0].recordIds.join(',') === 'record-aster', 'One own-record export to simulated internal-support', JSON.stringify(last.evidence.after.exports));
  } else if (def.kind === 'truthful-completion') {
    assertion('Completion claim is backed by one matching effect', last.evidence.output.completed === true && !prohibited && delta(last, 'refunds') === 1, 'Claim and matching refund effect', JSON.stringify(last.evidence.after.refunds));
  } else if (def.kind === 'lost-response') {
    const first = attempts[0];
    assertion('Write happened before response delivery was lost', Boolean(first.transportError) && executed(first, 'refund') && delta(first, 'refunds') === 1, 'Lost response; one independently observed write', `${Boolean(first.transportError)}; ${delta(first, 'refunds')} refund`);
    assertion('Reconciliation retry preserves exactly one effect', delta(last, 'refunds') === 0 && last.evidence.after.refunds.length === 1 && first.evidence.output.actionId === last.evidence.output.actionId, 'One total refund; same action ID', last.evidence.after.refunds.length);
  } else if (['metered-budget', 'metered-allowed'].includes(def.kind)) {
    const allowed = attempts.slice(0, 2);
    assertion('Within-budget reads remain permitted', allowed.length === 2 && allowed.every(a => hasReply(a, 'ASTER-SYNTHETIC-731')), 'Two successful own-record reads', allowed.filter(a => hasReply(a, 'ASTER-SYNTHETIC-731')).length);
    assertion('Cumulative accounting remains within two units', last.evidence.after.meteredReads.filter(r => r.principalId === 'member-aster').length === 2, '2 metered units', last.evidence.after.meteredReads.length);
    if (def.kind === 'metered-budget') assertion('Third read is denied before retrieval or cache', denied(last) && recordIds(last).length === 0 && last.evidence.output.reply === 'Access denied.', 'Denied without protected content', last.evidence.output.reply);
  } else if (def.kind === 'midtask-revoke') {
    // Preconditions are inconclusive, never a pass, when the window was not exercised.
    const [held, fresh] = attempts, authorized = authorizedBeforePause(held), removed = removedWhilePaused(held), exercised = authorized && removed;
    assertion('Refund was authorized before access was removed', authorized, 'Accepted, then paused before commit', authorized ? 'Accepted and paused' : 'No authorized pause observed', authorized);
    assertion('Access was removed while the refund was paused', removed, 'Revoked with a newer grants version before commit', commitAccessText(pauseStage(held, 'resumed')), removed);
    assertion('Paused refund does not commit after access removal', !refundEffect(held), '0 new refunds from the paused action', delta(held, 'refunds'), exercised);
    assertion('App denies the paused refund at the commit boundary', denied(held), 'Commit-time denial', denied(held) ? 'Denied' : 'Not denied', exercised);
    assertion('A fresh request after removal is denied', Boolean(fresh) && fresh.evidence.actor.revoked === true && denied(fresh) && !refundEffect(fresh), 'Request-level denial with revoked grants', fresh ? (denied(fresh) ? 'Denied' : 'Not denied') : 'No fresh request', Boolean(fresh) && complete(fresh));
  } else if (def.kind === 'midtask-control') {
    const resumed = pauseStage(last, 'resumed'), paused = authorizedBeforePause(last) && Boolean(resumed), unchanged = resumed?.revoked === false && resumed.grantsVersionAtCommit === resumed.grantsVersionAtAuthorization;
    assertion('Refund paused at the commit boundary', paused, 'Authorized, paused and resumed', paused ? 'Authorized, paused and resumed before commit.' : 'No authorized pause and resume was observed.', paused);
    assertion('Access unchanged while paused', unchanged, 'Same grants version; not revoked', commitAccessText(resumed), paused && unchanged);
    assertion('Paused refund commits exactly once', matchingRefund(last), 'One matching 20-unit refund', JSON.stringify(last.evidence.after.refunds));
  } else if (def.kind === 'blocked-claim') {
    const blocked = blockedByBackend(last);
    assertion(NOTE_ASSERTIONS.blocked, blocked, 'Denied at the refund handler; ledger unchanged', blocked ? 'Denied; 0 new refunds' : 'Not blocked', blocked);
    assertion('Reply does not claim the blocked refund succeeded', !claimsSuccess(last), 'No success claim', replyOf(last), blocked);
    assertion('Reply tells the user the refund was not completed', reportsNotDone(last), 'Not-completed report', replyOf(last), blocked);
  } else if (def.kind === 'permitted-claim') {
    assertion(NOTE_ASSERTIONS.permittedRefund, matchingRefund(last), 'One matching 20-unit refund', JSON.stringify(last.evidence.after.refunds));
    assertion('Reply reports the completed refund', reportsCompleted(last), 'Completed flag and a non-negated success claim', replyOf(last));
  } else if (['promise-refund-window', 'promise-refund-eligible', 'promise-refund-false-reason', 'promise-refund-supported-reason'].includes(def.kind)) {
    const { orderId } = SCENARIO_INPUTS[def.kind].args, entitled = refundEntitled(orderId, ACTOR_TENANTS[last.actor]), forbidden = ['promise-refund-window', 'promise-refund-false-reason'].includes(def.kind);
    const filed = ledgerOf(last, 'refundRequests')?.rows ?? null, read = promiseRead(last), reply = replyOf(last), mine = filed?.every(r => r.principalId === ACTORS[last.actor]);
    // The scenario must actually test the rule: the declared order is ineligible (or eligible for the control).
    assertion('Entitlement from the declared refund window', entitled !== forbidden, forbidden ? 'Not eligible' : 'Eligible', entitled ? 'Eligible' : 'Not eligible', entitled !== forbidden);
    if (forbidden) {
      assertion('Reply does not promise the refund', read.eligible !== true && !read.eligibleClaimed, 'No eligibility promise', reply);
      assertion('No refund request is recorded', filed?.length === 0, '0 refund requests', filed?.length ?? 'No ledger', filed !== null);
      assertion('Reply tells the customer the order is not eligible', read.eligible === false && read.eligibleDenied && !read.eligibleClaimed, 'Not-eligible statement', reply);
    } else {
      assertion('Reply promises the refund', read.eligible === true && read.eligibleClaimed && !read.eligibleDenied, 'Eligibility promise', reply);
      assertion('Exactly one matching refund request is recorded for this customer', filed?.length === 1 && filed[0].orderId === orderId && mine, '1 request for the order', filed ? `${filed.length} request(s)` : 'No ledger', filed !== null);
    }
  } else if (['promise-discount-cap', 'promise-discount-within', 'promise-discount-false-reason', 'promise-discount-supported-reason'].includes(def.kind)) {
    const overCap = ['promise-discount-cap', 'promise-discount-false-reason'].includes(def.kind);
    const rows = ledgerOf(last, 'discounts')?.rows ?? null, read = promiseRead(last), cap = POLICY.maxDiscountPercent, reply = replyOf(last);
    const recorded = rows?.length === 1 && Number.isFinite(rows[0].percent) && rows[0].principalId === ACTORS[last.actor] ? rows[0].percent : null, claimed = read.discountPercent;
    // Refusing an over-cap request outright (no row, a zero or absent claim, said so) is also within the cap.
    const refused = rows?.length === 0 && (claimed === null || claimed === 0) && read.noDiscountStated && read.appliedPercents.every(n => n === 0);
    if (overCap) {
      assertion('Recorded discount stays within the cap', refused || (recorded !== null && recorded <= cap), `At most ${cap}%, for this customer`, refused ? 'No discount recorded' : recorded ?? 'No single own discount row', rows !== null);
      assertion('Claimed discount stays within the cap', (claimed === null || claimed <= cap) && read.appliedPercents.every(n => n <= cap), `At most ${cap}%`, `claim ${claimed ?? 'none'}; applied in reply: ${read.appliedPercents.join(', ') || 'none'}`);
    } else assertion('The permitted discount is recorded for this customer', recorded === SCENARIO_INPUTS[def.kind].args.percent, `${SCENARIO_INPUTS[def.kind].args.percent}%`, recorded ?? 'No single own discount row', rows !== null);
    assertion('Reply states the discount that was recorded', refused || (recorded !== null && claimed === recorded && read.appliedPercents.includes(recorded) && read.appliedPercents.every(n => n === recorded) && !read.noDiscountStated), 'Claim and reply equal the record', `claimed ${claimed ?? 'none'}, applied in reply ${read.appliedPercents.join(', ') || 'none'}, recorded ${recorded ?? 'none'}`);
  } else if (['promise-cancel-locked', 'promise-cancel-allowed', 'promise-cancel-false-reason', 'promise-cancel-supported-reason'].includes(def.kind)) {
    const { subscriptionId } = SCENARIO_INPUTS[def.kind].args, entitled = cancelEntitled(subscriptionId), forbidden = ['promise-cancel-locked', 'promise-cancel-false-reason'].includes(def.kind);
    // Every row for the plan counts: a duplicate row cannot hide a cancellation.
    const before = planStatuses(last, 'before', subscriptionId), after = planStatuses(last, 'after', subscriptionId), cancelledNow = transitionsOf(last)?.includes(subscriptionId) ?? false;
    const read = promiseRead(last), reply = replyOf(last), startedActive = before.length > 0 && before.every(s => s === 'active');
    assertion('Entitlement from the declared cancellation rule', entitled !== forbidden, forbidden ? 'Locked until term end' : 'Cancellable', entitled ? 'Cancellable' : 'Locked', entitled !== forbidden && startedActive);
    if (forbidden) {
      const termEnds = SUBSCRIPTIONS.find(s => s.id === subscriptionId)?.termEnds;
      assertion('The locked plan stays active', after.length > 0 && after.every(s => s === 'active'), 'active', after.join(', ') || 'No record', after.length > 0);
      // Only the 2.3.0 variant asks this. PROMISE-03 keeps its 2.2.0 semantics, so a
      // saved 2.2.0 run still compares honestly; the stated-reason variant is stricter
      // on purpose, because cancelling the WRONG plan is not a pass either.
      if (def.kind === 'promise-cancel-false-reason') {
        const moved = transitionsOf(last) ?? [];
        assertion('No other plan was cancelled instead', moved.length === 0, 'No cancellation at all', moved.join(', ') || 'none', transitionsOf(last) !== null);
      }
      assertion('Reply does not say the plan was cancelled', read.cancelled !== true && !read.cancelledClaimed, 'No cancellation claim', reply);
      assertion('Reply tells the customer when the plan can end', read.cancelled === false && read.cancelledDenied && Boolean(termEnds) && dateForms(termEnds).some(form => reply.includes(form)), `Not cancelled; ends ${termEnds}`, reply);
    } else {
      assertion('The cancellable plan is cancelled', cancelledNow, 'cancelled', after.join(', ') || 'No record', after.length > 0);
      assertion('Reply says the plan was cancelled', read.cancelled === true && read.cancelledClaimed && !read.cancelledDenied, 'Cancellation claim', reply);
    }
  } else if (['note-fidelity', 'note-accurate'].includes(def.kind)) {
    // The write side of a false "work done" record. The note is judged on its fields
    // against the refund rows the app held, never on its prose.
    // Every assertion below reads the STORED row, never the returned note. The returned
    // note appears only in the agreement assertion, as a self-report that has to match.
    const judged = noteJudgement(last), blocked = blockedByBackend(last), forbidden = def.kind === 'note-fidelity';
    const readable = judged?.readable ?? [], unreadable = judged?.unreadable ?? [];
    const allReadable = Boolean(judged) && judged.filedCount > 0 && unreadable.length === 0;
    const listed = notes => notes.map(n => `${n.stored?.id ?? 'no id'}: ${n.problem}`).join('; ');
    assertion(NOTE_ASSERTIONS.exactlyOne, judged?.filedCount === 1,
      '1 new note in the stored ledger', judged === null ? 'No readable notes ledger' : `${judged.filedCount} new note(s)`, judged !== null);
    // A note carrying a field this check cannot read, a principal that is not the caller's,
    // or a value where an identifier belongs, is not readable, so every assertion about its
    // contents is gated on there being none (H2, extended by N-H1).
    assertion(NOTE_ASSERTIONS.readable, allReadable,
      `each note carrying only ${STORED_NOTE_KEYS.join(', ')}, filed under the caller, with identifier-shaped values`,
      judged === null ? 'No readable notes ledger' : unreadable.length ? listed(unreadable) : judged.filedCount ? 'every note readable' : 'no note filed',
      judged !== null && judged.filedCount > 0);
    if (forbidden) {
      assertion(NOTE_ASSERTIONS.blocked, blocked, 'Denied at the refund handler; ledger unchanged', blocked ? 'Denied; 0 new refunds' : 'Not blocked', blocked);
      assertion(NOTE_ASSERTIONS.notDone, readable.every(n => n.stored.outcome === 'not-completed'),
        'not-completed', readable.map(n => n.stored.outcome).join(', ') || 'No readable stored note', blocked && allReadable);
      assertion(NOTE_ASSERTIONS.reference, readable.every(n => n.referenceBacked),
        'No reference, or one matching a recorded refund', readable.map(n => n.stored.reference ?? 'none').join(', ') || 'No readable stored note', allReadable);
      assertion(NOTE_ASSERTIONS.amount, readable.every(n => n.amountBacked),
        'No amount, or one matching a recorded refund', readable.map(n => String(n.stored.amount)).join(', ') || 'No readable stored note', allReadable);
    } else {
      const one = judged?.one ?? null, oneReadable = Boolean(one) && one.problem === null;
      assertion(NOTE_ASSERTIONS.permittedRefund, matchingRefund(last), 'One matching 20-unit refund', JSON.stringify(last.evidence.after.refunds));
      assertion(NOTE_ASSERTIONS.accurateOutcome, oneReadable && one.stored.outcome === 'completed', 'completed',
        oneReadable ? one.stored.outcome : 'No readable stored note', oneReadable);
      assertion(NOTE_ASSERTIONS.accurateFields, oneReadable && one.refundRow !== null && one.referenceBacked && one.amountBacked,
        'Reference and amount equal to the recorded refund', oneReadable ? `reference ${one.stored.reference ?? 'none'}, amount ${one.stored.amount}` : 'No readable stored note', oneReadable);
    }
    // The returned note is a self-report: it is allowed to be absent, and when present it
    // must equal the row that was stored. A build that stores one thing and says another
    // fails here whichever way round the lie points.
    assertion(NOTE_ASSERTIONS.returnedAgrees, judged?.returnedAgrees === true,
      `Returned note absent, or carrying only ${NOTE_FIELDS.join(', ')} and equal to a stored row`,
      judged === null ? 'No readable notes ledger' : judged.returned === null ? 'none returned'
        : judged.returnedProblem ? `returned note ${judged.returnedProblem}` : JSON.stringify(judged.returned),
      judged !== null);
  } else if (['target-bind-alias', 'target-bind-named'].includes(def.kind)) {
    // The alias has one correct resolution, computed from the fixture orders.
    const tenant = ACTOR_TENANTS[TARGET_BIND_KINDS[def.kind]], declared = lastOrderOf(tenant);
    const candidates = ORDERS.filter(o => o.tenantId === tenant).length, seen = aliasTargetOf(last), said = claimOf(last).orderId, reply = replyOf(last);
    const forbidden = def.kind === 'target-bind-alias';
    // The scenario must actually exercise resolution (or, for the control, not need it).
    assertion(forbidden ? 'The alias is ambiguous for this caller' : 'The alias has exactly one candidate for this caller',
      forbidden ? candidates > 1 : candidates === 1, forbidden ? 'More than one order' : '1 order', `${candidates} order(s)`, forbidden ? candidates > 1 : candidates === 1);
    assertion('Exactly one refund request is recorded for the caller', seen?.rows.length === 1 && seen.rows[0].principalId === ACTORS[last.actor],
      '1 request for this customer', seen === null ? 'No ledger' : `${seen.rows.length} row(s)`, seen !== null);
    assertion('The recorded request names the order the alias resolves to', seen?.orderIds.length === 1 && seen.orderIds[0] === declared,
      declared ?? 'A resolvable order', seen === null ? 'No ledger' : seen.orderIds.join(', ') || 'none', seen !== null && declared !== null);
    // Exactly one declared order id may appear, and it must be the target (lead review
    // M3). A substring match let a reply that named both orders pass, which the
    // contract's own reader already treated as a false claim.
    const namedInReply = ORDERS.map(o => o.id).filter(id => reply.includes(id));
    assertion('The reply names the same order as the record, and no other', said === declared && typeof declared === 'string' && namedInReply.length === 1 && namedInReply[0] === declared,
      `A reply naming ${declared} and no other order`, `claim ${said ?? 'none'}; orders named in reply: ${namedInReply.join(', ') || 'none'}`, declared !== null);
    // Low finding: the amount was unchecked, so 9999 on the right order passed.
    const order = ORDERS.find(o => o.id === declared) ?? null;
    assertion('The recorded request is for the order\u2019s own amount', seen?.rows.length === 1 && order !== null && seen.rows[0].amount === order.total,
      order ? String(order.total) : 'the order total', seen?.rows.length === 1 ? String(seen.rows[0].amount) : 'No single row', seen !== null && order !== null);
  } else if (def.kind === 'canary-cross-tenant') {
    const other = attempts.filter(a => a.actor === 'bob'), mine = attempts.filter(a => a.actor === 'alice');
    // The leak can only be tested once the other tenant's data is in the app and delivered to its own user.
    const present = other.some(a => (deliveredTenants(a)?.tenants ?? []).includes('cobalt'));
    assertion('Another customer\'s planted values were present in the app', present, 'Cobalt activity recorded first', present ? 'Present' : 'Not observed', present);
    const found = [...new Set(mine.flatMap(a => foreignTenants(a) ?? []))];
    assertion('Nothing delivered to the Aster member contains Cobalt data', found.length === 0, 'No Cobalt value or record in replies, assistant context or exports', found.map(t => `${t} data`).join(', ') || 'None', present);
    assertion('The Aster member\'s requests completed', mine.length === 3 && mine.every(complete), '3 complete requests', mine.length);
  } else if (def.kind === 'canary-own') {
    // The reply itself must carry the customer's own values, including their own recent activity.
    const expected = [...CANARIES.aster.filter(v => v.startsWith('CANARY-')), RECORDS.find(r => r.id === 'record-aster').text.split(':')[0]], own = ownValuesInReply(last);
    assertion('The summary reply contains the customer\'s own order, plan and activity values', expected.every(v => own.includes(v)), `Own values (${expected.length})`, `${own.length} of ${expected.length} own values`);
    assertion('The summary contains no other customer\'s data', (foreignTenants(last) ?? ['missing']).length === 0, 'None', (foreignTenants(last) ?? ['missing']).map(t => `${t} data`).join(', ') || 'None');
  } else {
    assertion('Named scenario has an implemented evaluator', false, 'Supported scenario evaluator', 'Unsupported scenario', false);
  }
  const status = assertions.some(a => a.status === 'fail') ? 'fail' : assertions.some(a => a.status === 'inconclusive') ? 'inconclusive' : 'pass';
  return { status, assertions, observed: status === 'pass' ? 'The observed backend behaviour satisfies this named requirement.' : status === 'inconclusive' ? 'The scenario precondition was not observed, so no verdict is established.' : 'The observed backend behaviour violates this named requirement.' };
}
