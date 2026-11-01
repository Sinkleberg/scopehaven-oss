// Turn-runner contract (scopehaven-turn-runner/1): how ScopeHaven drives an
// agent that lives inside a framework process (LangGraph, Mastra) instead of
// behind a loopback HTTP endpoint. Pure: no I/O.
//
// The adapter is a small program ScopeHaven ships per framework. It loads the
// operator's agent unmodified (apart from declared substitutions such as the
// model), and speaks newline-delimited JSON:
//   harness -> adapter, on the adapter's stdin:
//     { type: 'hello', protocol, fault, objectPaths }
//     { type: 'sync', id }                   a barrier before each turn: echo it back
//     { type: 'turn', id, text, steps }      one user turn; steps script the stub model
//     { type: 'snapshot', id, paths }        read operator-named object paths (between turns only);
//                                            paths: [{ path, source: 'object-path' | 'app-report', select? }];
//                                            select { shape, key, keys }: answer { entries, remainder }
//                                            with only those keys (state.mjs). The Python shim answers
//                                            null for a null value, also on a path through null; an
//                                            adapter that cannot (Mastra's) fails the snapshot instead
//     { type: 'close' }
//   adapter -> harness, on file descriptor 3 (stdout and stderr stay the app's own logs):
//     { type: 'ready', framework, tools, template, substitutions }
//     { type: 'sync', id }                   the echo; fd 3 is one ordered stream, so everything
//                                            written before it was written before the turn
//     { type: 'tool', record }               one ledger record, as the tool boundary sees it
//     { type: 'turn-end', id, reply, messages, stub, failure? }
//                                            stub: { consumed, exhausted } of the script;
//                                            failure: an exception that escaped the framework
//     { type: 'state', id, values }          the answer to one snapshot request
//     { type: 'error', message }
// A turn ends only with its turn-end message. Silence past the turn deadline,
// an exit or an error leaves the turn unended, and the run inconclusive.
//
// The tool ledger is presence-only: a record shows that a tool function ran
// with these arguments and returned, raised, or was cancelled (a CancelledError
// or KeyboardInterrupt, which the shim records and lets through). Its silence proves nothing (a
// tool reached outside the wrapped boundary leaves no record), so it never
// supports an absence and never decides what persisted.
import { DUPLICATE_SEEN } from './fault.mjs';

export const TURN_RUNNER_PROTOCOL = 'scopehaven-turn-runner/1';
export const LEDGER_EVIDENCE = 'presence-only';
export const CONTRACT_LIMITS = Object.freeze({ line: 1 << 20, text: 4000, reply: 20000, messages: 64, tools: 256, toolName: 128, ledger: 2000, turns: 32, steps: 32, paths: 16, json: 64 * 1024 });
export const LEDGER_STATUSES = Object.freeze(['returned', 'exception', 'cancelled', 'fault-injected']);
export const STEP_KINDS = Object.freeze(['tool', 'text']);

export class ContractError extends Error { constructor(code) { super(`Turn-runner contract: ${code}.`); this.name = 'ContractError'; this.code = code; } }
const fail = code => { throw new ContractError(code); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
// One line of text: no control characters at all.
export const bounded = (value, maximum) => typeof value === 'string' && value.length >= 1 && value.length <= maximum && !/[\u0000-\u001f\u007f]/.test(value);
const text = (value, maximum) => typeof value === 'string' && value.length <= maximum;
const jsonSize = value => { try { return JSON.stringify(value)?.length ?? 0; } catch { return Infinity; } };
const onlyKeys = (value, keys) => Reflect.ownKeys(value).every(key => keys.includes(key));
const counter = value => Number.isSafeInteger(value) && value >= 1;

// One stub-model step: call a tool with these arguments, or answer with text.
// "{{last.<field>}}" in a text step is replaced by that field of the most recent
// returned tool result, so a scripted reply can quote a real refund id.
export function validateSteps(steps, where = 'steps') {
  if (!Array.isArray(steps) || steps.length > CONTRACT_LIMITS.steps) fail(where);
  for (const step of steps) {
    if (!plain(step) || !STEP_KINDS.includes(step.kind)) fail(`${where}-kind`);
    if (step.kind === 'tool' && !(onlyKeys(step, ['kind', 'tool', 'args']) && bounded(step.tool, CONTRACT_LIMITS.toolName) && plain(step.args) && jsonSize(step.args) <= CONTRACT_LIMITS.json)) fail(`${where}-tool`);
    if (step.kind === 'text' && !(onlyKeys(step, ['kind', 'text']) && typeof step.text === 'string' && step.text.length >= 1 && step.text.length <= CONTRACT_LIMITS.text)) fail(`${where}-text`);
  }
  return steps;
}

// A ledger record as the adapter's tool wrapper writes it. A fault-injected record
// is the fault hook raising before the tool body ran; exception, cancelled and
// fault-injected records carry the exception text and no result. A reset or a
// duplicate (fault.mjs) is the tool body's own record, marked `fault` by the hook:
// a reset only on a body that returned (its result is the one the agent never got),
// a duplicate with `seen`, the delivery whose result the agent was given.
export function validateLedgerRecord(record) {
  if (!plain(record) || !onlyKeys(record, ['seq', 'tool', 'args', 'status', 'result', 'exception', 'fault', 'seen'])) fail('ledger-record');
  if (!counter(record.seq) || !bounded(record.tool, CONTRACT_LIMITS.toolName) || !LEDGER_STATUSES.includes(record.status)) fail('ledger-record');
  if (jsonSize(record.args) > CONTRACT_LIMITS.json || jsonSize(record.result) > CONTRACT_LIMITS.json) fail('ledger-size');
  if (record.status === 'returned' ? Object.hasOwn(record, 'exception') : !(Object.hasOwn(record, 'exception') && text(record.exception, CONTRACT_LIMITS.text)) || Object.hasOwn(record, 'result')) fail('ledger-outcome');
  if (Object.hasOwn(record, 'fault') || Object.hasOwn(record, 'seen')) {
    const reset = record.fault === 'reset-after-commit' && record.status === 'returned' && !Object.hasOwn(record, 'seen');
    const duplicate = record.fault === 'duplicate-delivery' && record.status !== 'fault-injected' && DUPLICATE_SEEN.includes(record.seen);
    if (!reset && !duplicate) fail('ledger-fault');
  }
  return record;
}

// Parse one adapter line. Unknown types, extra fields and oversized lines are
// refused: the harness never guesses what an adapter meant.
export function parseAdapterMessage(line) {
  if (typeof line !== 'string' || line.length > CONTRACT_LIMITS.line) fail('line');
  let message;
  try { message = JSON.parse(line); } catch { fail('json'); }
  if (!plain(message)) fail('message');
  switch (message.type) {
    case 'ready':
      if (!onlyKeys(message, ['type', 'framework', 'tools', 'template', 'substitutions'])) fail('ready');
      if (!bounded(message.framework, 64) || !Array.isArray(message.tools) || message.tools.length > CONTRACT_LIMITS.tools || !message.tools.every(t => bounded(t, CONTRACT_LIMITS.toolName))) fail('ready');
      if (jsonSize(message.template) > CONTRACT_LIMITS.json || jsonSize(message.substitutions) > CONTRACT_LIMITS.json) fail('ready-size');
      return message;
    case 'tool':
      if (!onlyKeys(message, ['type', 'record'])) fail('tool');
      validateLedgerRecord(message.record);
      return message;
    case 'turn-end':
      if (!onlyKeys(message, ['type', 'id', 'reply', 'messages', 'stub', 'failure']) || !counter(message.id) || !text(message.reply, CONTRACT_LIMITS.reply)) fail('turn-end');
      if (!Array.isArray(message.messages) || message.messages.length > CONTRACT_LIMITS.messages || !message.messages.every(m => text(m, CONTRACT_LIMITS.reply))) fail('turn-end-messages');
      if (!(plain(message.stub) && onlyKeys(message.stub, ['consumed', 'exhausted']) && Number.isSafeInteger(message.stub.consumed) && message.stub.consumed >= 0 && typeof message.stub.exhausted === 'boolean')) fail('turn-end-stub');
      if (Object.hasOwn(message, 'failure') && !bounded(message.failure, 400)) fail('turn-end-failure');
      return message;
    case 'state':
      if (!onlyKeys(message, ['type', 'id', 'values']) || !bounded(message.id, 64) || !plain(message.values) || Object.keys(message.values).length > CONTRACT_LIMITS.paths || jsonSize(message.values) > CONTRACT_LIMITS.line) fail('state');
      return message;
    case 'sync':
      if (!onlyKeys(message, ['type', 'id']) || !bounded(message.id, 64)) fail('sync');
      return message;
    case 'error':
      if (!onlyKeys(message, ['type', 'message']) || !text(message.message, CONTRACT_LIMITS.text)) fail('error');
      return message;
    default:
      return fail('type');
  }
}

// The ledger kept for a run: records in the order the adapter sent them, each
// tagged with the turn it arrived in, and marked `outside` when it arrived outside
// a turn (turn-runner.mjs). Sequence numbers must run 1, 2, 3...;
// a gap or repeat means a record was lost or replayed, and the ledger is unusable.
export function ledgerOf(entries) {
  if (entries.length > CONTRACT_LIMITS.ledger) fail('ledger-limit');
  const records = entries.map(({ turn, outside, record }) => ({ turn, ...(outside ? { outside: true } : {}), ...validateLedgerRecord(record) }));
  const ordered = records.every((r, i) => r.seq === i + 1);
  return { evidence: LEDGER_EVIDENCE, ordered, records };
}
