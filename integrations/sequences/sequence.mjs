// Timed sequences: a declared list of steps against a loopback application,
// judged by effect assertions over observer windows. One sequence expresses
// "start the agent's task, pause it at a boundary, change the actor's access
// through the app's own admin API, release, then check what was committed".
//
// steps (run in order):
//   { request: { id, actorId, method, path, body?, timeoutMs?, capture? }, background?: true, assertStatus?: { id, title, severity, in } }
//                                                   method: GET, POST, PUT, PATCH or DELETE
//                                                   assertStatus: a judged row from the status the app answered
//                                                   capture: { name: "/json/pointer" }, values read from the JSON reply
//   { websocket: { id, actorId, path, send?, until?, timeoutMs? }, background?: true }
//                                                   open a websocket on the origin, send JSON messages, and wait until
//                                                   { messages: n } arrive or { close: true } (the default) or the timeout
//   { awaitHold: { rule, as, timeoutMs? } }        wait until the gate holds a request
//   { release: { hold } }                           release a held request by its `as` name
//   { awaitResponse: { request } }                  wait for a background request
//   { expectStatus: { request, in: [codes] } }      the access change itself must have worked (stops the run)
//   { sleep: ms }                                   fixed delay (delay sweeps)
//   { mark: name }                                  take a cursor from every observer
// A request or websocket path may hold {name} placeholders, each naming a capture an earlier request declares (L8 fix 4).
// A captured value is 1 to 200 characters of [A-Za-z0-9._~-] and never "." or "..", so it cannot add a path segment, a
// query or a host; a reply without a usable value stops the run (capture-missing:<name>). A websocket handshake answered
// without 101 stops the run (websocket-refused:<id>), as does a message over the size bounds or a frame no server may send
// (websocket-failed:<id>). Neither decides a row: a websocket drives the agent as a request does, and observers judge it.
// assertions: [{ id, title, severity, from, to, effect: { kind, select }, corroborate?: [select...] }]
//   `corroborate` lists selectors for the same effect as other sources record it
//   (each names its source). For effect.none, a failure counts as independently
//   observed only when every corroborating source saw it too; otherwise the row
//   is conflicting, never a clean fail.
import { performance } from 'node:perf_hooks';
import { sequenceTransport, SEQUENCE_METHODS, observeWebsocket, WEBSOCKET_LIMITS } from './transport.mjs';
import { digest } from '../../src/domain.mjs';
import { readPointer } from '../../src/contracts.mjs';
import { collectWindow, evaluateEffectAssertion, validateEffectAssertion, validateSelector, matches, windowSees, wallNs, CREDENTIAL_ENV, credentialFrom, custodyWindows } from '../observers/events.mjs';
import { clauseCustody, roleOfSeverity, CUSTODY_BASIS, CONTROL_CUSTODY_LIMIT } from '../../src/custody.mjs';
import { SEQUENCE_EVALUATOR_HASH } from './evaluator.mjs';

export const SEQUENCE_SCHEMA = 'scopehaven-sequence/1';
// Run records. /2 stores the sealed windows each assertion was decided from, so the verdicts can be
// recomputed (run-validator.mjs). /3 adds judged response-status rows (assertStatus), the responses they
// were decided from and the sequence evaluator identity (evaluator.mjs); /2 records still validate as /2.
// /4 (L8 fix 4) is written only by a sequence that has a websocket step or a capture: it adds the declared websockets,
// the record each one left and the declared captures with the digest of each captured value. Every other sequence
// still writes /3. Records written as scopehaven-sequence/1 kept window digests only.
export const SEQUENCE_RUN_SCHEMA = 'scopehaven-sequence-run/3';
export const SEQUENCE_RUN_SCHEMA_V2 = 'scopehaven-sequence-run/2';
export const SEQUENCE_RUN_SCHEMA_V4 = 'scopehaven-sequence-run/4';
export const SEQUENCE_LIMITS = Object.freeze({ steps: 64, assertions: 64, sleepMs: 120000, runMs: 600000, captures: 16, capturesPerRequest: 8 });
export const CAPTURE_NAME = /^[A-Za-z][A-Za-z0-9_]{0,39}$/;
export const CAPTURE_VALUE = /^[A-Za-z0-9._~-]{1,200}$/;
// {name} in single braces only: a {{name}} in double braces is left as written for a caller's own transport to fill (the
// multiturn scenarios compile theirs that way), and never read here.
const PLACEHOLDER = /(?<!\{)\{([^{}]*)\}(?!\})/g, CALLER_PLACEHOLDER = /\{\{[^{}]*\}\}/g;
const usableCapture = value => typeof value === 'string' && CAPTURE_VALUE.test(value) && value !== '.' && value !== '..';
const WEBSOCKET_KEYS = Object.freeze(['id', 'actorId', 'path', 'send', 'until', 'timeoutMs']);
// How a websocket step can end (transport.mjs observeWebsocket); a run seals one of these.
export const WEBSOCKET_TRANSPORTS = Object.freeze(['complete', 'timeout', 'network', 'refused', 'too-large', 'protocol']);
const plainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export const SEQUENCE_ID = /^[A-Za-z0-9_-]{1,80}$/;
const ID = SEQUENCE_ID;
export const SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'control']);
// What a run records as `aborted` when it stops early: run-budget, precondition-failed:<request>, step-error or an error code.
export const ABORTED = /^[A-Za-z][A-Za-z0-9_-]{0,63}(?::[A-Za-z0-9_-]{1,80})?$/;

// The rules one assertion obeys on its own (its marks must also exist and be in order, which needs the steps).
// The run validator applies the same rules to a run's sealed assertions.
export function checkAssertion(a, bad) {
  if (a === null || typeof a !== 'object' || Array.isArray(a) || !ID.test(a.id || '') || !ID.test(a.from || '') || !ID.test(a.to || '') || typeof a.title !== 'string') bad(`assertion ${typeof a?.id === 'string' && ID.test(a.id) ? a.id : '?'} needs an id, a title and declared from/to marks`);
  if (!SEVERITIES.includes(a.severity)) bad(`assertion ${a.id} severity`);
  validateEffectAssertion(a.effect, `assertion ${a.id}`);
  if (a.corroborate !== undefined && !(Array.isArray(a.corroborate) && a.corroborate.length >= 1 && a.corroborate.length <= 8 && a.corroborate.every(c => typeof validateSelector(c, `assertion ${a.id} corroborate`).source === 'string'))) bad(`assertion ${a.id} corroborate needs 1 to 8 selectors that each name a source`);
}
// The rules one response-status assertion obeys, as a request step declares it ({ id, title, severity, in }).
// The run validator applies the same rules to a run's sealed status assertions.
export const STATUS_KEYS = Object.freeze(['id', 'title', 'severity', 'in']);
// A step's modifiers; every other key is its action. Validation and execution both read a step through
// stepActions, so the order of a step's JSON keys never changes what runs (review F1).
export const STEP_MODIFIERS = Object.freeze(['background', 'assertStatus']);
export const stepActions = step => Object.keys(step).filter(k => !STEP_MODIFIERS.includes(k));
export function checkStatusAssertion(s, bad) {
  const where = typeof s?.id === 'string' && ID.test(s.id) ? s.id : '?';
  if (s === null || typeof s !== 'object' || Array.isArray(s) || Object.keys(s).some(k => !STATUS_KEYS.includes(k)) || !ID.test(s.id || '') || typeof s.title !== 'string') bad(`assertStatus ${where} needs an id and a title`);
  if (!SEVERITIES.includes(s.severity)) bad(`assertStatus ${where} severity`);
  if (!(Array.isArray(s.in) && s.in.length >= 1 && s.in.length <= 16 && s.in.every(c => Number.isInteger(c) && c >= 100 && c <= 599) && new Set(s.in).size === s.in.length)) bad(`assertStatus ${where} needs "in": 1 to 16 distinct status codes from 100 to 599`);
}

export function validateSequence(seq) {
  const bad = reason => { throw new Error(`Invalid sequence: ${reason}.`); };
  if (!seq || seq.schema !== SEQUENCE_SCHEMA || !ID.test(seq.id || '')) bad('needs schema scopehaven-sequence/1 and an id');
  if (!seq.actors || typeof seq.actors !== 'object' || !Object.keys(seq.actors).length) bad('needs actors');
  // Optional target identity for saved runs (--save): what application and context this sequence is written for.
  for (const key of ['applicationId', 'contextId']) if (seq[key] !== undefined && !ID.test(seq[key])) bad(`${key} must be 1 to 80 letters, digits, "_" or "-"`);
  for (const [alias, actor] of Object.entries(seq.actors)) {
    if (!ID.test(alias) || !actor || !ID.test(actor.principalId || '')) bad(`actor ${alias.slice(0, 40)} needs a principalId`);
    if (actor.credentialEnv !== undefined && !CREDENTIAL_ENV.test(actor.credentialEnv)) bad(`actor ${alias} credential references must use the dedicated SCOPEHAVEN_TARGET_ namespace`);
  }
  if (!Array.isArray(seq.steps) || !seq.steps.length || seq.steps.length > SEQUENCE_LIMITS.steps) bad('needs 1 to 64 steps');
  const requests = new Set(), websockets = new Set(), holds = new Set(), marks = new Map(), statusIds = new Set(); // mark name -> step index
  const captures = new Set();
  // Every {name} in a path names a capture declared by an earlier request; no other brace may appear.
  const placeholders = (path, i) => {
    for (const [, name] of path.matchAll(PLACEHOLDER)) if (!captures.has(name)) bad(`step ${i + 1} path names "{${name.slice(0, 40)}}", which no earlier request captures`);
    if (/[{}]/.test(path.replace(CALLER_PLACEHOLDER, '').replace(PLACEHOLDER, ''))) bad(`step ${i + 1} path has a brace outside a {name} placeholder`);
  };
  seq.steps.forEach((step, i) => {
    const kinds = stepActions(step);
    if (kinds.length !== 1) bad(`step ${i + 1} must have exactly one action`);
    const [kind] = kinds, v = step[kind];
    if (step.assertStatus !== undefined) {
      if (kind !== 'request') bad(`step ${i + 1}: assertStatus belongs on a request step`);
      checkStatusAssertion(step.assertStatus, bad);
      if (statusIds.has(step.assertStatus.id)) bad(`assertStatus ${step.assertStatus.id} is declared twice`);
      statusIds.add(step.assertStatus.id);
    }
    if (kind === 'request') {
      if (!ID.test(v?.id || '') || requests.has(v.id) || websockets.has(v.id) || !seq.actors?.[v.actorId] || !SEQUENCE_METHODS.includes(v.method) || typeof v.path !== 'string' || !v.path.startsWith('/')) bad(`step ${i + 1} request`);
      placeholders(v.path, i);
      requests.add(v.id);
      if (v.capture !== undefined) {
        if (!plainObject(v.capture) || !Object.keys(v.capture).length || Object.keys(v.capture).length > SEQUENCE_LIMITS.capturesPerRequest) bad(`step ${i + 1} capture needs 1 to ${SEQUENCE_LIMITS.capturesPerRequest} names`);
        for (const [name, pointer] of Object.entries(v.capture)) {
          if (!CAPTURE_NAME.test(name) || captures.has(name)) bad(`step ${i + 1} capture "${name.slice(0, 40)}" needs a new name: a letter, then letters, digits or "_" (up to 40)`);
          let valid = typeof pointer === 'string' && pointer.startsWith('/');
          try { if (valid) readPointer({}, pointer); } catch { valid = false; }
          if (!valid) bad(`step ${i + 1} capture "${name}" needs a JSON pointer such as "/id"`);
          captures.add(name);
        }
        if (captures.size > SEQUENCE_LIMITS.captures) bad(`a sequence declares at most ${SEQUENCE_LIMITS.captures} captures`);
      }
    }
    else if (kind === 'websocket') {
      if (!plainObject(v) || Object.keys(v).some(k => !WEBSOCKET_KEYS.includes(k)) || !ID.test(v.id || '') || requests.has(v.id) || websockets.has(v.id) || !seq.actors?.[v.actorId] || typeof v.path !== 'string' || !v.path.startsWith('/') || v.path.startsWith('//')) bad(`step ${i + 1} websocket needs an id, an actorId and a path`);
      placeholders(v.path, i);
      if (v.send !== undefined && !(Array.isArray(v.send) && v.send.length <= WEBSOCKET_LIMITS.send && v.send.every(m => { const text = JSON.stringify(m); return typeof text === 'string' && Buffer.byteLength(text) <= WEBSOCKET_LIMITS.sendBytes; }))) bad(`step ${i + 1} websocket send lists up to ${WEBSOCKET_LIMITS.send} JSON messages`);
      const until = v.until;
      if (until !== undefined && !(plainObject(until) && ((Object.keys(until).join() === 'messages' && Number.isInteger(until.messages) && until.messages >= 1 && until.messages <= WEBSOCKET_LIMITS.messages) || (Object.keys(until).join() === 'close' && until.close === true)))) bad(`step ${i + 1} websocket until is { "messages": 1 to ${WEBSOCKET_LIMITS.messages} } or { "close": true }`);
      if (v.timeoutMs !== undefined && !(Number.isInteger(v.timeoutMs) && v.timeoutMs >= 1 && v.timeoutMs <= WEBSOCKET_LIMITS.timeoutMs)) bad(`step ${i + 1} websocket timeoutMs`);
      websockets.add(v.id);
    }
    else if (kind === 'awaitHold') { if (!ID.test(v?.rule || '') || !ID.test(v?.as || '')) bad(`step ${i + 1} awaitHold`); holds.add(v.as); }
    else if (kind === 'release') { if (!holds.has(v?.hold)) bad(`step ${i + 1} releases an unknown hold`); }
    else if (['awaitResponse', 'expectStatus'].includes(kind)) { if (!requests.has(v?.request) && !(kind === 'awaitResponse' && websockets.has(v?.request))) bad(`step ${i + 1} names an unknown request`); if (kind === 'expectStatus' && !(Array.isArray(v.in) && v.in.length && v.in.every(Number.isInteger))) bad(`step ${i + 1} expectStatus.in`); }
    else if (kind === 'sleep') { if (!(Number.isInteger(v) && v >= 0 && v <= SEQUENCE_LIMITS.sleepMs)) bad(`step ${i + 1} sleep`); }
    else if (kind === 'mark') { if (!ID.test(v || '') || marks.has(v)) bad(`step ${i + 1} mark`); marks.set(v, i); }
    else bad(`step ${i + 1} has unsupported action "${String(kind).slice(0, 40)}"`);
  });
  if (!Array.isArray(seq.assertions) || !seq.assertions.length || seq.assertions.length > SEQUENCE_LIMITS.assertions) bad('needs 1 to 64 assertions');
  const ids = new Set();
  for (const a of seq.assertions) {
    checkAssertion(a, bad);
    if (ids.has(a.id) || statusIds.has(a.id)) bad(`assertion ${a.id} is declared twice`);
    ids.add(a.id);
    if (!marks.has(a.from) || !marks.has(a.to)) bad(`assertion ${a.id} needs an id, a title and declared from/to marks`);
    // A window covers the steps between its marks: "to" must come after "from".
    if (!(marks.get(a.from) < marks.get(a.to))) bad(`assertion ${a.id}: its "to" mark must come after its "from" mark`);
  }
  return seq;
}

// The response-status assertions a sequence declares, in step order, as a run seals them.
export const statusAssertionsOf = seq => seq.steps.filter(step => step.request && step.assertStatus).map(step => ({ id: step.assertStatus.id, title: step.assertStatus.title, severity: step.assertStatus.severity, request: step.request.id, in: [...step.assertStatus.in] }));
// Every request a sequence declares, in step order, with its actor. A run seals this list and the response of every
// request it sent, so the same-actor acceptance a refusal row needs is recomputed from the record.
export const requestsOf = seq => seq.steps.filter(step => step.request).map(step => ({ id: step.request.id, actorId: step.request.actorId }));
// Every websocket step and every capture a sequence declares, in step order (a /4 run seals both lists), and the run schema
// the sequence writes: /4 when it has either, /3 otherwise.
export const websocketsOf = seq => seq.steps.filter(step => step.websocket).map(step => ({ id: step.websocket.id, actorId: step.websocket.actorId }));
export const capturesOf = seq => seq.steps.filter(step => step.request?.capture).flatMap(step => Object.keys(step.request.capture).map(name => ({ name, request: step.request.id })));
export const runSchemaOf = seq => websocketsOf(seq).length || capturesOf(seq).length ? SEQUENCE_RUN_SCHEMA_V4 : SEQUENCE_RUN_SCHEMA;
// One websocket record as a run seals it: the handshake status, how the step ended, the data messages (one sha256 digest
// each, never the content), the close code and the bytes received. Anything else a transport returns is dropped.
export function websocketRecord(r) {
  const status = Number.isInteger(r?.status) && r.status >= 100 && r.status <= 599 ? r.status : null;
  const digests = Array.isArray(r?.digests) ? r.digests.filter(d => typeof d === 'string' && /^[a-f0-9]{64}$/.test(d)).slice(0, WEBSOCKET_LIMITS.messages) : [];
  return { status, transport: WEBSOCKET_TRANSPORTS.includes(r?.transport) ? r.transport : 'protocol', messages: digests.length,
    closeCode: Number.isInteger(r?.closeCode) && r.closeCode >= 0 && r.closeCode <= 65535 ? r.closeCode : null,
    bytes: Number.isInteger(r?.bytes) && r.bytes >= 0 ? Math.min(r.bytes, WEBSOCKET_LIMITS.stepBytes) : 0, digests };
}
// Parity with the HTTP connector's identity proof: a 401 or 403 from a credential that never worked looks exactly like
// a refusal. A status row that passes on a 401 or 403 counts only when an earlier request by the same actor in the same
// run received a complete 2xx response; that request is the row's acceptedBy. Otherwise the row is inconclusive
// (identity-not-established). A served request still fails its refusal row, and rows answered otherwise are unaffected.
export const REFUSAL_STATUSES = Object.freeze([401, 403]);
const own = (record, key) => record !== null && typeof record === 'object' && Object.hasOwn(record, key) ? record[key] : null;
const accepted = response => response?.complete === true && Number.isInteger(response.status) && response.status >= 200 && response.status < 300;
export function acceptanceFor(s, requests, responses) {
  const index = requests.findIndex(r => r.id === s.request);
  if (index < 0) return null;
  return requests.slice(0, index).find(r => r.actorId === requests[index].actorId && accepted(own(responses, r.id)))?.id ?? null;
}
// One response-status row from the response its request received: the runner and the run validator both use this.
// It judges the status code only, never the reply's body. A request never sent, or one without a complete HTTP
// response, is inconclusive. A stopped sequence decides no status row: a background request's answer can depend
// on steps that never ran (an access change, a release), so its pass or fail would not mean what the row says.
export function decideStatusAssertion(s, response, aborted, acceptedBy = null) {
  const answered = response !== null && response !== undefined && response.complete === true && Number.isInteger(response.status);
  const refusal = answered && s.in.includes(response.status) && REFUSAL_STATUSES.includes(response.status);
  const [verdict, basis] = aborted ? ['missing', `The sequence stopped early (${aborted}); a status row needs the whole sequence.`]
    : response === null || response === undefined ? ['not-sent', 'The request was never sent.']
    : !answered ? ['no-response', 'The request did not receive a complete HTTP response.']
    : refusal && acceptedBy === null ? ['identity-not-established', `The application answered ${response.status}, but no earlier request by the same actor in this run was accepted (2xx): the refusal could come from a credential that never worked.`]
    : s.in.includes(response.status) ? ['pass', `The application answered ${response.status}, one of the expected statuses.${refusal ? ` The same actor was accepted earlier (${acceptedBy}).` : ''}`]
    : ['fail', `The application answered ${response.status}; expected one of ${s.in.join(', ')}.`];
  return { id: s.id, title: s.title, severity: s.severity, kind: 'response-status', status: verdict === 'pass' || verdict === 'fail' ? verdict : 'inconclusive', verdict, basis,
    request: s.request, expected: [...s.in], observed: response === null || response === undefined ? null : { status: Number.isInteger(response.status) ? response.status : null, complete: response.complete === true },
    ...(refusal && !aborted ? { acceptedBy } : {}) };
}
// Every status row of a run, from its sealed requests and responses (own entries only): the runner and the validator share it.
export const decideStatusRows = (statusAssertions, requests, responses, aborted) => statusAssertions.map(s => decideStatusAssertion(s, own(responses, s.request), aborted, acceptanceFor(s, requests, responses)));
// Map an effect verdict to the v1 row status the rest of Scopehaven uses.
const V1 = { pass: 'pass', fail: 'fail', missing: 'inconclusive', 'observer-failure': 'error', unobservable: 'inconclusive' };
// The sequence identity a run is bound to (credentials reduced to their mode).
export const sequenceHashOf = seq => digest({ steps: seq.steps, assertions: seq.assertions, actors: Object.fromEntries(Object.entries(seq.actors).map(([k, a]) => [k, { principalId: a.principalId, credentialMode: a.credentialEnv ? (a.credentialCookie ? 'cookie' : 'bearer') : 'none' }])) });
// One assertion's result from its windows: the runner and the run validator both use this, so a run that
// validates holds verdicts these windows decide.
export function decideAssertion(a, windows, aborted) {
  custodyWindows(windows, 'decideAssertion');
  let verdict = evaluateEffectAssertion(a.effect, windows);
  // A forbidden effect counts as independently observed only when every
  // listed source saw it; otherwise the row is conflicting, never a clean fail or pass.
  if (a.corroborate && verdict.verdict === 'fail' && a.effect.kind === 'effect.none') {
    // Only an observer that can see the corroborating selector can confirm it.
    const seen = a.corroborate.map(select => ({ source: select.source, visible: windows.some(w => windowSees(w, select)), seen: windows.some(w => windowSees(w, select) && w.events.some(e => matches(e, { ...select, outcome: 'committed' }))) }));
    const missing = seen.filter(s => !s.seen).map(s => `${s.source}${s.visible ? '' : ' (cannot see this effect)'}`);
    verdict = missing.length ? { ...verdict, verdict: 'conflicting', basis: `The primary source recorded the forbidden effect, but ${missing.join(', ')} did not.` } : { ...verdict, corroboratedBy: seen.map(s => s.source), basis: `${verdict.basis} Corroborated by ${seen.map(s => s.source).join(', ')}.` };
  }
  if (aborted && verdict.verdict === 'pass') verdict = { ...verdict, verdict: 'missing', basis: `The sequence stopped early (${aborted}); a pass needs the whole sequence.` };
  // Custody (src/custody.mjs): in a boundary assertion (any severity except 'control') a pass needs a deciding
  // window held outside the application; otherwise it reads inconclusive. A control carries custody as a tag only.
  const held = clauseCustody({ kind: a.effect.kind, select: a.effect.select, verdict: verdict.verdict, windows, role: roleOfSeverity(a.severity) });
  if (held.custodyReason) verdict = { ...verdict, verdict: 'inconclusive', basis: `${verdict.basis} ${CUSTODY_BASIS}` };
  return { id: a.id, title: a.title, severity: a.severity, status: ['conflicting', 'inconclusive'].includes(verdict.verdict) ? 'inconclusive' : V1[verdict.verdict], verdict: verdict.verdict, basis: verdict.basis, corroboratedBy: verdict.corroboratedBy ?? [], matched: verdict.matched, evidence: verdict.evidence,
    custody: held.custody, ...(held.custodyReason ? { custodyReason: held.custodyReason, custodyUpgrade: held.custodyUpgrade } : {}),
    window: { from: a.from, to: a.to, coverage: windows.map(w => ({ source: w.source, instanceId: w.instanceId, coverage: w.coverage, reason: w.reason ?? null, events: w.events.length, digest: digest(w.events) })) } };
}
export const countsOf = results => { const counts = { pass: 0, fail: 0, inconclusive: 0, error: 0 }; for (const r of results) counts[r.status]++; return counts; };

export async function runSequence(input, { origin, observers = [], gate = null, env = process.env, transport = sequenceTransport, websocket = observeWebsocket, onReady = null } = {}) {
  const seq = validateSequence(input);
  let started = performance.now();
  const timeline = [], cursors = new Map(), pending = new Map(), responses = new Map(), holds = new Map(), websocketRecords = new Map(), captured = new Map();
  const note = entry => timeline.push({ t: String(wallNs()), ...entry });
  const budgetLeft = () => SEQUENCE_LIMITS.runMs - (performance.now() - started);
  // Declared post-response settle (observers built by the factory carry it) and the marks that end an assertion.
  const settleMs = Math.max(0, ...observers.map(o => Number.isInteger(o.postResponseSettleMs) ? o.postResponseSettleMs : 0));
  const endMarks = new Set(seq.assertions.map(a => a.to));
  const credentialOf = actorId => {
    const actor = seq.actors[actorId], credential = actor.credentialEnv ? credentialFrom(env, actor.credentialEnv, `Actor "${actorId}"`) : undefined;
    if (actor.credentialEnv && !credential) throw new Error(`Credential reference for actor "${actorId}" is not set.`);
    return { credential, credentialCookie: credential === undefined ? undefined : actor.credentialCookie };
  };
  // A path with its {name} placeholders filled from the values captured so far.
  const fill = path => path.replace(PLACEHOLDER, (_, name) => {
    if (!captured.has(name)) throw Object.assign(new Error(`Capture "${name}" has no value yet.`), { code: `capture-missing:${name}` });
    return captured.get(name);
  });
  const send = async ({ id, actorId, method, path: declared, body, timeoutMs = 3000, capture }) => {
    const presented = credentialOf(actorId), path = fill(declared);
    note({ step: 'request-sent', request: id, actorId, method, pathDigest: digest(path) });
    const observation = await transport(origin, { method, path, ...(body === undefined ? {} : { body }) }, { ...presented, timeoutMs: Math.max(1, Math.min(timeoutMs, budgetLeft())) });
    const status = Number.isInteger(observation?.status) && observation.status >= 100 && observation.status <= 599 ? observation.status : null;
    const complete = observation?.complete !== false && status !== null;
    const record = { status, transport: observation?.error || (complete ? 'complete' : 'invalid-response'), complete };
    responses.set(id, record); note({ step: 'response', request: id, status: record.status, transport: record.transport });
    // The local transports resolve network, timeout and size failures. Only a
    // complete HTTP response proves execution; parsing JSON is not required.
    if (!complete) throw Object.assign(new Error('The sequence request did not receive a complete HTTP response.'), { code: `transport-failed:${id}` });
    // Captures read the JSON reply only; the value is kept for later paths and sealed by digest.
    for (const [name, pointer] of Object.entries(capture ?? {})) {
      const found = observation?.jsonParsed === true ? readPointer(observation.json, pointer) : { present: false };
      const value = found.present && (typeof found.value === 'string' || Number.isSafeInteger(found.value)) ? String(found.value) : null;
      if (!usableCapture(value)) throw Object.assign(new Error(`Request "${id}" did not answer a usable value for capture "${name}".`), { code: `capture-missing:${name}` });
      captured.set(name, value); note({ step: 'captured', request: id, capture: name });
    }
    return record;
  };
  const openWebsocket = async ({ id, actorId, path: declared, send: messages = [], until = { close: true }, timeoutMs = 60000 }) => {
    const presented = credentialOf(actorId), path = fill(declared);
    note({ step: 'websocket-opened', websocket: id, actorId, pathDigest: digest(path) });
    const record = websocketRecord(await websocket(origin, { path, send: messages, until }, { ...presented, timeoutMs: Math.max(1, Math.min(timeoutMs, budgetLeft())) }));
    websocketRecords.set(id, record); note({ step: 'websocket-ended', websocket: id, status: record.status, transport: record.transport, messages: record.messages });
    if (record.status !== 101) throw Object.assign(new Error('The websocket handshake was not accepted.'), { code: record.status === null ? `transport-failed:${id}` : `websocket-refused:${id}` });
    if (['too-large', 'protocol'].includes(record.transport)) throw Object.assign(new Error('The websocket broke a bound or the protocol.'), { code: `websocket-failed:${id}` });
    return record;
  };
  const attempted = new Set();
  let failed = false;
  try {
    for (const o of observers) { attempted.add(o); await o.start(); }
    // The CLI may keep ready observers open before beginning the sequence. Its
    // preparatory wait is outside the sequence budget, and shares this cleanup.
    if (onReady) { await onReady(); started = performance.now(); }
    let aborted = null;
    const dropHeld = () => { if (aborted && gate) for (const id of gate.heldIds()) { gate.drop(id); note({ step: 'dropped-on-abort' }); } };
    const abortOnError = error => {
      if (aborted) return;
      aborted = typeof error?.code === 'string' && ABORTED.test(error.code) ? error.code : 'step-error';
      note({ step: 'error', reason: String(error?.message).slice(0, 200) });
      // Another request may still be held while the pending requests settle.
      // Drop it now so cleanup never waits for a hold it must release itself.
      dropHeld();
    };
    try {
      for (const step of seq.steps) {
        if (aborted) break;
        if (budgetLeft() <= 0) { aborted = 'run-budget'; break; }
        const [kind] = stepActions(step), v = step[kind];
        // Handle a background rejection immediately, even if no awaitResponse
        // step follows it. An unexecuted request can never support a pass.
        if (kind === 'request') { if (step.background) pending.set(v.id, send(v).catch(abortOnError)); else await send(v); }
        else if (kind === 'websocket') { if (step.background) pending.set(v.id, openWebsocket(v).catch(abortOnError)); else await openWebsocket(v); }
        else if (kind === 'awaitHold') { if (!gate) throw new Error('awaitHold needs a hold gate.'); holds.set(v.as, await gate.awaitHold(v.rule, Math.min(v.timeoutMs ?? 30000, budgetLeft()))); note({ step: 'held', hold: v.as, rule: v.rule }); }
        else if (kind === 'release') { gate.release(holds.get(v.hold)); note({ step: 'released', hold: v.hold }); }
        else if (kind === 'awaitResponse') { if (pending.has(v.request)) await pending.get(v.request); }
        else if (kind === 'expectStatus') {
          const r = responses.get(v.request);
          // If the access change did not take effect, nothing after it can be judged.
          if (!r || !v.in.includes(r.status)) { aborted = `precondition-failed:${v.request}`; note({ step: 'precondition-failed', request: v.request, status: r?.status ?? null }); break; }
        }
        else if (kind === 'sleep') await new Promise(resolve => setTimeout(resolve, v));
        else if (kind === 'mark') {
          // An assertion's end mark waits the largest declared post-response settle first.
          if (settleMs && endMarks.has(v)) { await new Promise(resolve => setTimeout(resolve, Math.min(settleMs, budgetLeft()))); note({ step: 'settle', mark: v, ms: settleMs }); }
          cursors.set(v, await Promise.all(observers.map(o => o.mark()))); note({ step: 'mark', mark: v });
        }
      }
    } catch (error) { abortOnError(error); }
    finally {
      // An aborted sequence must not release a paused action later: drop what is still held.
      dropHeld();
      await Promise.allSettled(pending.values());
      // A background request may first fail while the pending requests settle.
      dropHeld();
    }

    const windowCache = new Map();
    const windowsFor = async (from, to) => {
      const key = `${from}>${to}`;
      if (!windowCache.has(key)) windowCache.set(key, cursors.has(from) && cursors.has(to)
        ? await Promise.all(observers.map((o, i) => collectWindow(o, cursors.get(from)[i], cursors.get(to)[i])))
        : observers.map(o => ({ source: o.source, instanceId: o.instanceId, scope: o.scope, coverage: 'failed', reason: 'mark-not-reached', events: [] })));
      return windowCache.get(key);
    };
    const results = [];
    for (const a of seq.assertions) results.push(decideAssertion(a, await windowsFor(a.from, a.to), aborted));
    // Response-status rows follow the effect rows, each decided from the response its request received.
    const statusAssertions = statusAssertionsOf(seq), requests = requestsOf(seq);
    // Every request that was answered: a refusal row's same-actor acceptance can be any earlier request.
    const sealedResponses = Object.fromEntries(requests.filter(r => responses.has(r.id)).map(({ id }) => { const r = responses.get(id); return [id, { status: r.status, complete: r.complete, transport: r.transport }]; }));
    // Own entries only, as the validator reads them: a request id such as "constructor" must not read an inherited value (review F2).
    results.push(...decideStatusRows(statusAssertions, requests, sealedResponses, aborted));
    const counts = countsOf(results);
    // /4 only: the declared websockets with the record each one left, and the declared captures with each value's digest.
    const schema = runSchemaOf(seq), v4 = schema === SEQUENCE_RUN_SCHEMA_V4;
    const channel = v4 ? { websockets: websocketsOf(seq), websocketRecords: Object.fromEntries(websocketsOf(seq).filter(w => websocketRecords.has(w.id)).map(w => [w.id, websocketRecords.get(w.id)])),
      captures: capturesOf(seq).map(c => ({ ...c, digest: captured.has(c.name) ? digest(captured.get(c.name)) : null })) } : {};
    // Sealed with the run: the evaluator identity, the declared observers (with the scope every one of their windows
    // carries), the assertions, the status assertions, every window and response they were decided from.
    // Not sealed: timeline, gateTimeline, createdAt and durationMs.
    const run = { schema, sequenceId: seq.id, sequenceHash: sequenceHashOf(seq), evaluatorHash: SEQUENCE_EVALUATOR_HASH,
      observers: observers.map(o => ({ instanceId: o.instanceId, source: o.source, kind: o.kind, scope: o.scope })), assertions: seq.assertions, statusAssertions, requests,
      windows: Object.fromEntries([...windowCache.entries()]), responses: sealedResponses, ...channel,
      createdAt: new Date().toISOString(), aborted, counts, results, timeline, gateTimeline: gate ? gate.timeline.map(e => ({ ...e })) : null, durationMs: Math.round(performance.now() - started),
      limitations: ['Effects are judged from the configured observers only; a source with incomplete coverage can never support a pass.',
        'A status row judges the status code the application answered, never its reply text: it shows what the application said, not what it did.',
        'Trace and MCP observers report what the target instrumentation or protocol said; database and audit observers report what the application stored.',
        `Custody: a pass of a boundary assertion (any severity except control) needs a deciding observer held outside the application (hold gate, egress recorder or SMTP sink); one decided only by records the application can write reads inconclusive. ${CONTROL_CUSTODY_LIMIT}`,
        'The sequence does not reset application state between runs. Reset the target before repeating a delay sweep.',
        `Effects committed after an assertion's end mark are not observed${settleMs ? ` (each end mark is taken ${settleMs} ms after the step before it: the largest declared settleMs)` : '; no observer declares a settleMs, so place end marks after the action has settled'}.`,
        ...(v4 ? ['A websocket step drives the agent and decides no row: its handshake status, how it ended, its message count, close code and one digest per message are sealed, never the content. Captured values are sealed by digest only.'] : [])] };
    // Sealed as saved: a JSON copy, so a value JSON cannot hold (an undefined field) cannot break the digest once the file is read back.
    const saved = JSON.parse(JSON.stringify(run));
    const { timeline: _t, gateTimeline: _g, createdAt: _c, durationMs: _d, ...sealed } = saved;
    saved.runDigest = digest(sealed);
    return saved;
  } catch (error) { failed = true; throw error; }
  finally {
    // start() may acquire resources before throwing. Stop every attempted
    // observer, and keep a cleanup failure from masking the original error.
    let stopError, stopFailed = false;
    for (const o of attempted) { try { await o.stop(); } catch (error) { if (!stopFailed) { stopFailed = true; stopError = error; } } }
    if (stopFailed && !failed) throw stopError;
  }
}

// Run the same sequence once per delay, substituting `{ sleep: '$delay' }`.
export async function runDelaySweep(input, delays, options, { reset } = {}) {
  const runs = [];
  for (const delay of delays) {
    if (reset) await reset(delay);
    runs.push({ delayMs: delay, run: await runSequence({ ...input, steps: input.steps.map(s => s.sleep === '$delay' ? { sleep: delay } : s) }, options) });
  }
  return runs;
}
