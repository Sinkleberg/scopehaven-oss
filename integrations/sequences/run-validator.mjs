// Recomputes a saved sequence run (scopehaven-sequence-run/3, or /2) from the windows
// it sealed, the way validateHttpRunEvidence does for HTTP runs. A stored
// verdict is never trusted: every assertion is decided again from its windows
// by the runner's own decideAssertion, and the run must match exactly.
// A /3 run also seals its response-status assertions, its declared requests (with actors),
// the responses they received and the sequence evaluator identity; every status row, with
// its same-actor acceptance, is decided again by the runner's own decideStatusRows.
// A /2 record carries none of those and validates as /2.
// A /4 run (a sequence with a websocket step or a capture, L8 fix 4) is a /3 run plus the declared websockets, the record
// each one left and the declared captures with each captured value's digest; none of them decides a row, so they are
// checked for form and, with expectedSequence, bound to the sequence's own lists. A /3 record carries none of them.
// That includes custody (src/custody.mjs): a boundary assertion's pass decided
// only by records the application can write is recomputed as inconclusive, with
// the same custody, custodyReason and custodyUpgrade, so a saved degraded row validates.
//   - schema scopehaven-sequence/1 (window digests only): 'not-recomputable', never trusted
//   - the run digest, over every field except timeline, gateTimeline, createdAt and durationMs (unsealed)
//   - the declared observers: each kind is one a sequence can record, with the source that kind produces,
//     an instance id of that kind's form, and a scope that kind declares (operations, attribution, evidence),
//     carried by every one of its windows
//   - every window is a valid effect window the runner could have stored: one per observer for each
//     assertion's marks, its source, scope and events bound to that observer, exact entries only of the
//     method its kind produces, and coverage and reason as collectWindow sets them
//   - every event as its kind records it: an operation in its observer's scope and, where the kind always
//     names its events from the scope, a declared name
//   - with expectedObservers (built from the observers' configuration, never started) the declared
//     observers are exactly those: kind, instance id, source and scope, names included
//   - the assertions obey the sequence rules; with expectedSequence the run is bound to that sequence
//     (id, hash and assertions)
// Like the HTTP validator, it checks consistency, not authenticity: the digest is
// not keyed, so a consistent forgery of the whole record is out of its scope.
// Scope names come from observer configuration the run does not seal. For the audit
// kinds (SQLite audit table, HTTP audit endpoint) and the hold gate, adding a name to
// the observer and every window, with no other change, turns an unobservable absence
// into a pass: a consistent edit, so out of scope here. For snapshots a names edit
// alone reads missing; an exact entry must also be forged. A sink's evidence comes
// from configuration too (authoritative on a witnessed route, presence-only without
// one), so editing presence-only to authoritative is a consistent edit of the same kind.
// expectedObservers closes both: names and evidence are then checked against the
// configuration the caller supplies.
import { digest } from '../../src/domain.mjs';
import { OBSERVER_OUTPUT } from '../../src/http-effects.mjs';
import { validateWindow } from '../observers/events.mjs';
import { SEQUENCE_SCHEMA, SEQUENCE_RUN_SCHEMA, SEQUENCE_RUN_SCHEMA_V2, SEQUENCE_RUN_SCHEMA_V4, SEQUENCE_ID, SEQUENCE_LIMITS, ABORTED, CAPTURE_NAME, WEBSOCKET_TRANSPORTS, validateSequence, checkAssertion, checkStatusAssertion, statusAssertionsOf, requestsOf, websocketsOf, capturesOf, runSchemaOf, websocketRecord, sequenceHashOf, decideAssertion, decideStatusRows, countsOf } from './sequence.mjs';

export class SequenceRunError extends Error { constructor(code, detail) { super(code); this.name = 'SequenceRunError'; this.code = code; if (detail !== undefined) this.detail = detail; } }
const need = (ok, code, detail) => { if (!ok) throw new SequenceRunError(code, detail); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
// 16 declared observers (the CLI's limit) and the hold gate.
export const SEQUENCE_RUN_LIMITS = Object.freeze({ observers: 17 });
// The observer kinds a sequence can record and the source each produces: the factory's types (their
// instance ids are "<type>-<id>"), the in-process MCP proxy and the hold gate (whose ids are their own).
const KINDS = new Map([
  ...Object.entries(OBSERVER_OUTPUT).map(([type, o]) => [o.kind, { source: o.source, type }]),
  ['mcp-http-proxy', { source: 'mcp-jsonrpc', type: null }],
  ['hold-gate', { source: 'hold-proxy', type: null }],
]);
const typeOfInstance = id => Object.keys(OBSERVER_OUTPUT).filter(type => id.startsWith(`${type}-`)).sort((a, b) => b.length - a.length)[0] ?? null;
const INSTANCE = /^[A-Za-z0-9_-]{1,80}$/;
// Each kind's scope as its observer declares it in code: the operations it can see (fixed, or for an audit log the
// operations of its declared action map, which always include those listed here), its actor attribution and its
// evidence. Names come from the observer's configuration, which a run does not seal.
const KIND_SCOPES = new Map([
  ...['otlp-http-json-receiver', 'mcp-stdio-recorder', 'mcp-http-proxy'].map(kind => [kind, { operations: ['tool-call'], actorAttribution: 'principal', evidence: 'presence-only' }]),
  ['hold-gate', { operations: ['tool-call'], actorAttribution: 'none', evidence: 'authoritative' }],
  ...['sqlite-snapshot-diff', 'postgres-snapshot-diff', 'mysql-snapshot-diff'].map(kind => [kind, { operations: ['insert', 'update', 'delete'], actorAttribution: 'none', evidence: 'authoritative' }]),
  ...['sqlite-audit-table', 'http-audit-endpoint'].map(kind => [kind, { includes: ['update'], actorAttribution: 'principal', evidence: 'authoritative' }]),
  ['audit-log-file', { includes: [], actorAttribution: 'principal', evidence: 'authoritative' }],
  // A sink is authoritative only on a declared route a witness proves, and presence-only without one.
  ...['http-egress-recorder', 'smtp-sink-recorder'].map(kind => [kind, { operations: ['send'], actorAttribution: 'none', evidence: ['authoritative', 'presence-only'] }]),
]);
const scopeFits = (kind, scope) => {
  const fixed = KIND_SCOPES.get(kind);
  return fixed !== undefined && plain(scope) && Array.isArray(scope.operations) && scope.actorAttribution === fixed.actorAttribution && [fixed.evidence].flat().includes(scope.evidence)
    && (fixed.operations ? digest(scope.operations) === digest(fixed.operations) : fixed.includes.every(op => scope.operations.includes(op)));
};
// The exact-entry method each snapshot kind produces; no other kind produces exact entries or net-only windows.
const EXACT_METHOD = Object.freeze({ 'postgres-snapshot-diff': 'xmin', 'sqlite-snapshot-diff': 'change-column', 'mysql-snapshot-diff': 'change-column' });
// The kinds whose every event is named from the scope: a snapshot's tables, an audit file's rules, the gate's rules.
// An audit log names events by their action, and only a mapped or denied action is in its scope, so there an event
// with a mapped operation (anything but update) or a denied outcome must carry a declared name. The others (traces,
// MCP, sinks) record names their scope does not list.
const NAMED_EVENTS = new Set(['sqlite-snapshot-diff', 'postgres-snapshot-diff', 'mysql-snapshot-diff', 'audit-log-file', 'hold-gate']);
const ACTION_EVENTS = new Set(['sqlite-audit-table', 'http-audit-endpoint']);
const eventFits = (kind, scope, e) => scope.operations.includes(e.operation)
  && (!(NAMED_EVENTS.has(kind) || (ACTION_EVENTS.has(kind) && (e.operation !== 'update' || e.outcome === 'denied'))) || (Array.isArray(scope.names) && scope.names.includes(e.name)));
// The fields collectWindow writes; a window with any other was not stored by the runner.
const WINDOW_KEYS = new Set(['source', 'instanceId', 'scope', 'coverage', 'reason', 'events', 'exact']);
// The fields a /3 run adds; a /2 record has none of them. The fields a /4 run adds; a /2 or /3 record has none of them.
const V3_FIELDS = Object.freeze(['evaluatorHash', 'statusAssertions', 'requests', 'responses']);
const V4_FIELDS = Object.freeze(['websockets', 'websocketRecords', 'captures']);
const HEX64 = /^[a-f0-9]{64}$/;
// A sealed websocket record is exactly what websocketRecord keeps, and only a handshake answered 101 carries messages.
const websocketRecordFits = r => plain(r) && digest(websocketRecord(r)) === digest(r) && WEBSOCKET_TRANSPORTS.includes(r.transport)
  && (r.status === 101 ? r.transport !== 'refused' : r.messages === 0 && r.closeCode === null && r.bytes === 0 && (r.status === null ? ['network', 'timeout'].includes(r.transport) : r.transport === 'refused'));
// A sealed response, as the runner records it: a status (or null), whether the HTTP response was complete, and the transport outcome.
const TRANSPORT = /^[a-z][a-z0-9-]{0,39}$/;
const responseFits = r => plain(r) && Object.keys(r).length === 3 && typeof r.complete === 'boolean' && typeof r.transport === 'string' && TRANSPORT.test(r.transport)
  && (r.status === null || (Number.isInteger(r.status) && r.status >= 100 && r.status <= 599)) && (!r.complete || r.status !== null);

export function validateSequenceRun(run, { expectedSequence, expectedObservers } = {}) {
  need(plain(run), 'invalid-sequence-run');
  need(run.schema !== SEQUENCE_SCHEMA, 'not-recomputable', 'scopehaven-sequence/1 records keep window digests only: their verdicts cannot be re-checked');
  need([SEQUENCE_RUN_SCHEMA, SEQUENCE_RUN_SCHEMA_V2, SEQUENCE_RUN_SCHEMA_V4].includes(run.schema), 'invalid-sequence-run', 'schema');
  const v4 = run.schema === SEQUENCE_RUN_SCHEMA_V4, v3 = v4 || run.schema === SEQUENCE_RUN_SCHEMA;
  const { timeline: _t, gateTimeline: _g, createdAt: _c, durationMs: _d, runDigest, ...sealed } = run;
  need(typeof runDigest === 'string' && digest(sealed) === runDigest, 'invalid-sequence-run', 'run-digest');
  need(SEQUENCE_ID.test(run.sequenceId ?? '') && /^[a-f0-9]{64}$/.test(run.sequenceHash ?? ''), 'invalid-sequence-run', 'identity');
  // /3 seals the evaluator that decided it; /2 predates status rows and the evaluator identity.
  need(v3 ? /^[a-f0-9]{64}$/.test(run.evaluatorHash ?? '') : !V3_FIELDS.some(key => Object.hasOwn(run, key)), 'invalid-sequence-run', v3 ? 'identity' : 'schema');
  need(v4 || !V4_FIELDS.some(key => Object.hasOwn(run, key)), 'invalid-sequence-run', 'schema');
  need(run.aborted === null || (typeof run.aborted === 'string' && ABORTED.test(run.aborted)), 'invalid-sequence-run', 'aborted');
  // Status assertions (/3): the same rules as a request step's assertStatus, one per request, ids unique across all rows.
  const statusAssertions = v3 ? run.statusAssertions : [];
  need(Array.isArray(statusAssertions) && statusAssertions.length <= SEQUENCE_LIMITS.steps, 'invalid-sequence-run', 'status-assertions');
  for (const s of statusAssertions) {
    need(plain(s) && Object.keys(s).length === 5 && SEQUENCE_ID.test(s.request ?? ''), 'invalid-sequence-run', 'status-assertions');
    const { request: _r, ...declared } = s;
    try { checkStatusAssertion(declared, () => { throw new Error('status'); }); } catch { throw new SequenceRunError('invalid-sequence-run', 'status-assertions'); }
  }
  need(new Set(statusAssertions.map(s => s.request)).size === statusAssertions.length, 'invalid-sequence-run', 'status-assertions');
  // Requests (/3): every declared request in step order with its actor, ids unique; each status assertion names one.
  const requests = v3 ? run.requests : [];
  need(Array.isArray(requests) && requests.length <= SEQUENCE_LIMITS.steps && requests.every(r => plain(r) && Object.keys(r).length === 2 && SEQUENCE_ID.test(r.id ?? '') && SEQUENCE_ID.test(r.actorId ?? ''))
    && new Set(requests.map(r => r.id)).size === requests.length && statusAssertions.every(s => requests.some(r => r.id === s.request)), 'invalid-sequence-run', 'requests');
  // Responses (/3): only for declared requests, each as the runner records it. A request never sent has none.
  if (v3) need(plain(run.responses) && Object.entries(run.responses).every(([request, r]) => requests.some(x => x.id === request) && responseFits(r)), 'invalid-sequence-run', 'responses');
  // Websockets and captures (/4): declared in step order, ids unique beside the requests' ids, records only for declared
  // websockets, captures only from declared requests, each captured value by digest (null when the run never reached it).
  // A /4 run has at least one of them: a sequence with neither writes /3.
  if (v4) {
    need(Array.isArray(run.websockets) && run.websockets.length <= SEQUENCE_LIMITS.steps && run.websockets.every(w => plain(w) && Object.keys(w).length === 2 && SEQUENCE_ID.test(w.id ?? '') && SEQUENCE_ID.test(w.actorId ?? ''))
      && new Set([...requests, ...run.websockets].map(x => x.id)).size === requests.length + run.websockets.length, 'invalid-sequence-run', 'websockets');
    need(plain(run.websocketRecords) && Object.entries(run.websocketRecords).every(([id, r]) => run.websockets.some(w => w.id === id) && websocketRecordFits(r)), 'invalid-sequence-run', 'websocket-records');
    need(Array.isArray(run.captures) && run.captures.length <= SEQUENCE_LIMITS.captures && run.captures.every(c => plain(c) && Object.keys(c).length === 3 && CAPTURE_NAME.test(c.name ?? '') && requests.some(r => r.id === c.request) && (c.digest === null || HEX64.test(c.digest ?? '')))
      && new Set(run.captures.map(c => c.name)).size === run.captures.length, 'invalid-sequence-run', 'captures');
    need(run.websockets.length + run.captures.length > 0, 'invalid-sequence-run', 'schema');
  }
  if (expectedSequence !== undefined) {
    const seq = validateSequence(expectedSequence);
    need(seq.id === run.sequenceId && sequenceHashOf(seq) === run.sequenceHash && digest(seq.assertions) === digest(run.assertions) && digest(statusAssertionsOf(seq)) === digest(statusAssertions) && (!v3 || digest(requestsOf(seq)) === digest(requests)), 'unexpected-sequence');
    // A /3 or /4 run is the schema its sequence writes, and a /4 run seals that sequence's websockets and captures.
    const declaredCaptures = v4 ? run.captures.map(({ name, request }) => ({ name, request })) : [];
    need(!v3 || runSchemaOf(seq) === run.schema, 'unexpected-sequence');
    need(!v4 || (digest(websocketsOf(seq)) === digest(run.websockets) && digest(capturesOf(seq)) === digest(declaredCaptures)), 'unexpected-sequence');
  }
  // Declared observers, in order: a kind a sequence can record, its source, an instance id of its form, and a scope
  // (checked through the windows: every observer has one per assertion, each valid and carrying this scope).
  need(Array.isArray(run.observers) && run.observers.length <= SEQUENCE_RUN_LIMITS.observers, 'invalid-sequence-run', 'observers');
  for (const o of run.observers) {
    need(plain(o) && Object.keys(o).length === 4 && typeof o.instanceId === 'string' && INSTANCE.test(o.instanceId) && KINDS.get(o.kind)?.source === o.source, 'invalid-sequence-run', 'observers');
    need(typeOfInstance(o.instanceId) === KINDS.get(o.kind).type, 'invalid-sequence-run', 'observers');
    need(scopeFits(o.kind, o.scope), 'invalid-sequence-run', 'observer-scope');
  }
  need(new Set(run.observers.map(o => o.instanceId)).size === run.observers.length, 'invalid-sequence-run', 'observers');
  // Bound to the observers' configuration: the same observers, in order, each with the scope its configuration gives.
  if (expectedObservers !== undefined) {
    const shape = ({ instanceId, source, kind, scope }) => digest({ instanceId, source, kind, scope });
    need(Array.isArray(expectedObservers) && expectedObservers.length === run.observers.length && expectedObservers.every((o, i) => shape(o) === shape(run.observers[i])), 'unexpected-observers');
  }
  // Assertions, under the same rules as a sequence's.
  need(Array.isArray(run.assertions) && run.assertions.length >= 1 && run.assertions.length <= 64 && Array.isArray(run.results) && run.results.length === run.assertions.length + statusAssertions.length, 'invalid-sequence-run', 'assertions');
  for (const a of run.assertions) {
    try { checkAssertion(a, () => { throw new Error('assertion'); }); } catch { throw new SequenceRunError('invalid-sequence-run', 'assertions'); }
    need(a.from !== a.to, 'invalid-sequence-run', 'assertions');
  }
  need(new Set([...run.assertions, ...statusAssertions].map(a => a.id)).size === run.assertions.length + statusAssertions.length, 'invalid-sequence-run', 'assertions');
  // Windows: one per observer for each assertion's marks, valid, and as the runner stores them.
  const keys = new Set(run.assertions.map(a => `${a.from}>${a.to}`));
  need(plain(run.windows) && Object.keys(run.windows).length === keys.size && [...keys].every(k => Object.hasOwn(run.windows, k)), 'invalid-sequence-run', 'windows');
  for (const key of keys) {
    const windows = run.windows[key];
    need(Array.isArray(windows) && windows.length === run.observers.length, 'invalid-sequence-run', 'windows');
    windows.forEach((w, i) => {
      try { validateWindow(w, `window ${key} ${i + 1}`); } catch (error) { throw new SequenceRunError('invalid-sequence-run', typeof error?.code === 'string' ? `effect-window-${error.code}` : 'effect-window'); }
      need(Object.keys(w).every(k => WINDOW_KEYS.has(k)), 'invalid-sequence-run', 'window-fields');
      const o = run.observers[i], snapshot = EXACT_METHOD[o.kind];
      // Bound to its observer: instance, source, scope, and every event's recorded observer.
      need(w.instanceId === o.instanceId && w.source === o.source && digest(w.scope) === digest(o.scope)
        && w.events.every(e => e.observer.kind === o.kind && e.observer.instanceId === o.instanceId), 'invalid-sequence-run', 'window-observer');
      need(w.events.every(e => eventFits(o.kind, o.scope, e)), 'invalid-sequence-run', 'window-events');
      need(w.exact === undefined || (snapshot !== undefined && w.exact.every(e => (e.method === 'xmin' ? 'xmin' : 'change-column') === snapshot)), 'invalid-sequence-run', 'window-observer');
      // Coverage as collectWindow sets it: complete has no reason and nothing in flight, failed has a reason,
      // and only a snapshot's net change is net-only (with that reason) or carries exact entries.
      need(w.coverage !== 'complete' || (w.reason === null && !w.events.some(e => e.outcome === 'started' || e.outcome === 'unknown')), 'invalid-sequence-run', 'window-coverage');
      need(w.coverage !== 'failed' || typeof w.reason === 'string', 'invalid-sequence-run', 'window-coverage');
      need(w.coverage === 'net-only' ? snapshot !== undefined && w.reason === 'net-change-between-snapshots' : w.exact === undefined, 'invalid-sequence-run', 'window-coverage');
    });
  }
  // A run saved before custody decided sequence verdicts has no custody field on any result: refused as such, not as
  // an edited verdict. Removing it from some results still reads sequence-verdict through the recompute below.
  // Status rows never carry custody, so only the effect rows count here.
  need(run.results.slice(0, run.assertions.length).some(r => r !== null && typeof r === 'object' && Object.hasOwn(r, 'custody')), 'sequence-pre-custody');
  // Every verdict, recomputed: effect rows from the sealed windows, then status rows from the sealed responses.
  const results = [...run.assertions.map(a => decideAssertion(a, run.windows[`${a.from}>${a.to}`], run.aborted)),
    ...decideStatusRows(statusAssertions, requests, v3 ? run.responses : {}, run.aborted)];
  const rowIds = [...run.assertions, ...statusAssertions].map(a => a.id);
  results.forEach((r, i) => need(digest(r) === digest(run.results[i]), 'sequence-verdict', rowIds[i]));
  need(digest(countsOf(results)) === digest(run.counts), 'invalid-sequence-run', 'counts');
  return { results };
}
