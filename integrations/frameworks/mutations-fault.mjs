#!/usr/bin/env node
// Mutation sweep for the fault defaults (step 17b: reset after commit and duplicate delivery, beside
// the timeout) in fault.mjs, the ledger contract, the JavaScript tool boundary the TypeScript adapters
// use (adapters/tool-ledger.mjs) and the Python shim, and for the delivery schedules (N6: late
// delivery, out-of-order, retried after commit, checkpoint-restore replay) and FW-ONCE in fault.mjs
// (faults.test.mjs and shim.test.mjs): one mutation per property; each must make those tests fail. A
// survivor is a test gap.
//   node integrations/frameworks/mutations-fault.mjs [--out FILE] [--only ID,ID...]
// As mutations-state.mjs: a temporary copy of the modules the tests load, never the checkout; the
// tests run once unmutated (they must pass, with Python present), then once per mutation, one at a
// time. A mutation is one or more exact edits, each matching once.
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const TESTS = ['integrations/frameworks/faults.test.mjs', 'integrations/frameworks/shim.test.mjs'];
const m = (id, property, file, ...edits) => ({ id, property, file: `integrations/frameworks/${file}`, edits });
export const MUTATIONS = [
  // The plan.
  m('FV1', 'a duplicate plan carries no message', 'fault.mjs', ["NO_MESSAGE.includes(plan.kind) ? Object.hasOwn(plan, 'message') :", "NO_MESSAGE.includes(plan.kind) ? false :"]),
  m('FV2', 'seen is only for a duplicate, and is first or second', 'fault.mjs', ["  if (Object.hasOwn(plan, 'seen') && !(plan.kind === 'duplicate-delivery' && DUPLICATE_SEEN.includes(plan.seen))) throw new FaultError('seen');\n", '']),
  // Did it fire?
  m('FK1', 'a hook record of another kind is not this fault', 'fault.mjs', ['if (kindOf(hit) !== plan.kind) return', 'if (false) return']),
  m('FK2', 'a timeout record carries no mark and still reads as a timeout', 'fault.mjs', ["const kindOf = r => r.fault ?? (r.status === 'fault-injected' ? 'timeout' : null);", 'const kindOf = r => r.fault ?? null;']),
  m('FU1', 'a reset or duplicate whose first call raised reads as not returned, not as a tool that ran without the fault', 'fault.mjs', ["!BEFORE_BODY.includes(plan.kind) && first.status !== 'returned' ? 'first-call-did-not-return' :", "false ? 'first-call-did-not-return' :"]),
  m('FR1', 'a reset (as a timeout) is the tool\'s first record (F4, re-applied)', 'fault.mjs', ['if (first !== hit) return', 'if (false) return']),
  m('FR2', 'a reset mark on a body that did not return is never fired, even in an edited stored ledger', 'fault.mjs', ["    if (plan.kind === 'reset-after-commit' && hit.status !== 'returned') return { planned: true, fired: false, reason: 'reset-on-a-body-that-did-not-return' };\n", '']),
  m('FB2', 'with seen first the basis says the agent got the first delivery\'s result, whatever the duplicate did', 'fault.mjs', ["hit.seen === 'second' && hit.status !== 'returned' ? 'exception' : 'result'", "hit.status !== 'returned' ? 'exception' : 'result'"]),
  m('FD1', 'the duplicate is the record right after the first delivery', 'fault.mjs', ['ledger.records[ledger.records.indexOf(first) + 1] !== hit || ', '']),
  m('FD2', 'the first delivery of a duplicate returned', 'fault.mjs', [" || first.status !== 'returned') return", ') return']),
  m('FD3', 'the duplicate is the same call: same turn, same arguments', 'fault.mjs', ['  if (!sameCall(first, hit)) return', '  if (false) return']),
  m('FD5', 'a cancelled duplicate gave the agent nothing, so it never counts as fired', 'fault.mjs', ["  if (hit.status === 'cancelled') return { planned: true, fired: false, reason: 'duplicate-cancelled' };\n", '']),
  m('FD4', 'the agent was given the delivery the plan names', 'fault.mjs', ["  if (hit.seen !== (plan.seen ?? 'first')) return", '  if (false) return']),
  m('FB1', 'a fired reset says the reply was lost and that what persisted is read from AFTER', 'fault.mjs', ['fired after the tool body returned: the agent got a connection reset instead of the result', 'fired before the tool body']),
  // Delivery schedules (N6): the plan.
  m('NV1', 'a retry or a replay hands the agent a real result, so its plan carries no message', 'fault.mjs', ["const NO_MESSAGE = Object.freeze(['duplicate-delivery', 'retried-after-commit', 'checkpoint-restore-replay']);", "const NO_MESSAGE = Object.freeze(['duplicate-delivery']);"]),
  m('NV2', 'attempts is only for a retry', 'fault.mjs', ["!(plan.kind === 'retried-after-commit' && Number.isSafeInteger(plan.attempts)", '!(Number.isSafeInteger(plan.attempts)']),
  m('NV3', 'attempts is at least 2', 'fault.mjs', ['plan.attempts >= 2 &&', 'plan.attempts >= 1 &&']),
  m('NV4', 'attempts is at most 5', 'fault.mjs', ['plan.attempts <= FAULT_LIMITS.attempts', 'plan.attempts <= 9']),
  m('NV5', 'a replay always has a body and no other kind has one', 'fault.mjs', ["if ((plan.kind === 'checkpoint-restore-replay') !== Object.hasOwn(plan, 'body')) throw new FaultError('body');\n", '']),
  m('NV6', 'a body has at least one field', 'fault.mjs', ['if (!fields.length || fields.length >', 'if (fields.length >']),
  m('NV7', 'a body has at most 16 fields', 'fault.mjs', ['fields.length > FAULT_LIMITS.bodyFields || ', '']),
  m('NV8', 'a body field has a name', 'fault.mjs', ['!fields.every(f => bounded(f, FAULT_LIMITS.tool)) || ', '']),
  m('NV9', 'a body is JSON data', 'fault.mjs', ['!data(plan.body) || ', '']),
  m('NV10', 'a body is at most 4096 characters of JSON', 'fault.mjs', [' || JSON.stringify(plan.body).length > FAULT_LIMITS.body', '']),
  m('NV11', 'a body is at most 8 levels deep', 'fault.mjs', ['const data = (value, depth = 0) => depth <= 8 &&', 'const data = (value, depth = 0) => depth <= 99 &&']),
  // The mark on a record.
  m('NM1', 'a record without a mark passes the rule', 'fault.mjs', ["if (!Object.hasOwn(record, 'fault') && !Object.hasOwn(record, 'seen')) return true;", "if (!Object.hasOwn(record, 'fault') && !Object.hasOwn(record, 'seen')) return false;"]),
  m('NM2', 'the rule agrees with the contract on a reset mark', 'fault.mjs', ["return record.status === 'returned' && !Object.hasOwn(record, 'seen');", 'return true;']),
  m('NM3', 'the rule agrees with the contract on a duplicate mark', 'fault.mjs', ["return record.status !== 'fault-injected' && DUPLICATE_SEEN.includes(record.seen);", 'return true;']),
  m('NM4', 'a mark of no known kind is refused', 'fault.mjs', ["if (!SCHEDULE_KINDS.includes(record.fault) || Object.hasOwn(record, 'seen')) return false;", "if (Object.hasOwn(record, 'seen')) return false;"]),
  m('NM5', 'no schedule mark carries seen', 'fault.mjs', ["if (!SCHEDULE_KINDS.includes(record.fault) || Object.hasOwn(record, 'seen')) return false;", 'if (!SCHEDULE_KINDS.includes(record.fault)) return false;']),
  m('NM6', 'a retry or replay mark is never on a fault-injected record', 'fault.mjs', ["return HELD.includes(record.fault) || record.status !== 'fault-injected';", 'return true;']),
  m('NM7', 'a held call\'s mark may be on its fault-injected record', 'fault.mjs', ["return HELD.includes(record.fault) || record.status !== 'fault-injected';", "return record.status !== 'fault-injected';"]),
  // Did a schedule fire?
  m('NS1', 'a schedule is judged by its own rule', 'fault.mjs', ['  if (SCHEDULE_KINDS.includes(plan.kind)) return scheduleFired(plan, ledger);\n', '']),
  m('NS22', 'a stored schedule mark the rule refuses never fired', 'fault.mjs', ["  if (marked.some(r => !faultMarkValid(r))) return no('mark-not-valid');\n", '']),
  m('NS23', 'a hook record outside a turn never fired', 'fault.mjs', ["  if (marked.some(r => r.outside)) return no('fault-outside-a-turn');\n", '']),
  m('NS2', 'a held kind\'s call that ran without it reads tool-ran-without-fault, as a timeout\'s', 'fault.mjs', ["const BEFORE_BODY = Object.freeze(['timeout', ...HELD]);", "const BEFORE_BODY = Object.freeze(['timeout']);"]),
  m('NS3', 'every record the hook marked is for the planned tool', 'fault.mjs', ["  if (marked.some(r => r.tool !== plan.tool)) return no('fault-on-another-tool');\n", '']),
  m('NS4', 'every record the hook marked is of the planned kind', 'fault.mjs', ["  if (marked.some(r => kindOf(r) !== plan.kind)) return no('fault-kind-mismatch');\n", '']),
  m('NS5', 'the first marked record is the tool\'s first record', 'fault.mjs', ["  if (records.find(r => r.tool === plan.tool) !== lead) return no('fault-not-on-first-call');\n", '']),
  m('NS6', 'a held call\'s first record is its timeout, before the body ran', 'fault.mjs', ["    if (lead.status !== 'fault-injected') return no('held-call-ran-first');\n", '']),
  m('NS7', 'a held call that never landed did not fire', 'fault.mjs', ["marked.length === 1 ? 'held-call-never-delivered'", "false ? 'held-call-never-delivered'"]),
  m('NS8', 'a held call lands once', 'fault.mjs', ['if (marked.length !== 2 ||', 'if (marked.length < 2 ||']),
  m('NS24', 'a held call lands as a body\'s own record, not a second timeout', 'fault.mjs', [" || marked[1].status === 'fault-injected')", ')']),
  m('NS25', 'a held call lands in its own turn', 'fault.mjs', ["    if (late.turn !== lead.turn) return no('deliveries-in-another-turn');\n", '']),
  m('NS9', 'the late body is the held call, with its arguments', 'fault.mjs', ["    if (args(late) !== args(lead)) return no('late-call-not-the-held-call');\n", '']),
  m('NS10', 'a late delivery lands right after the next record, or right after the held one', 'fault.mjs', ["      if (late !== next && records[at(next) + 1] !== late) return no('late-call-not-where-planned');\n", '']),
  m('NS11', 'out-of-order: a later call of the tool overtook the held one', 'fault.mjs', ["    if (overtaking === late) return no('held-call-not-overtaken');\n", '']),
  m('NS12', 'out-of-order: the overtaking call has other arguments', 'fault.mjs', ["    if (args(overtaking) === args(lead)) return no('overtaken-by-the-same-call');\n", '']),
  m('NS13', 'out-of-order: the held call lands right after the overtaking one', 'fault.mjs', ["    if (records[at(overtaking) + 1] !== late) return no('late-call-not-where-planned');\n", '']),
  m('NS14', 'a retry or replay follows a first delivery that returned', 'fault.mjs', ["  if (lead.status !== 'returned') return no('first-delivery-did-not-return');\n", '']),
  m('NS15', 'a retry or replay makes as many deliveries as planned', 'fault.mjs', ["  if (marked.length !== planned) return no(marked.length < planned ? 'fewer-deliveries-than-planned' : 'fault-fired-more-than-once');\n", '']),
  m('NS16', 'a retry is two deliveries unless attempts says otherwise', 'fault.mjs', ['plan.attempts ?? 2 : 2', 'plan.attempts ?? 3 : 2']),
  m('NS17', 'every delivery of a retry or replay is written together', 'fault.mjs', ["  if (marked.some((r, i) => records[at(lead) + i] !== r)) return no('deliveries-not-together');\n", '']),
  m('NS18', 'every delivery of a retry or replay is in one turn', 'fault.mjs', ["  if (marked.some(r => r.turn !== lead.turn)) return no('deliveries-in-another-turn');\n", '']),
  m('NS26', 'a retry or replay with a cancelled delivery gave the agent nothing', 'fault.mjs', ["  if (marked.some(r => r.status === 'cancelled')) return no('delivery-cancelled');\n", '']),
  m('NS19', 'a retry repeats the same arguments', 'fault.mjs', ["    if (marked.some(r => args(r) !== args(lead))) return no('retry-not-the-same-call');\n", '']),
  m('NS20', 'a replay carries the plan\'s body fields in place of the first call\'s', 'fault.mjs', ["  if (!plain(lead.args) || args(last) !== canonical({ ...lead.args, ...plan.body })) return no('replay-body-not-as-planned');\n", '']),
  m('NS27', 'a replay needs first-call arguments it can put fields into', 'fault.mjs', ['  if (!plain(lead.args) || args(last)', '  if (args(last)']),
  m('NS21', 'a replay\'s body differs from the first call\'s', 'fault.mjs', ["  if (args(last) === args(lead)) return no('replay-body-not-different');\n", '']),
  m('NB1', 'a late basis names the record the call landed after', 'fault.mjs', ["late === next ? 'once the agent had moved on'", "true ? 'once the agent had moved on'"]),
  m('NB2', 'a retry basis says the agent was given the last delivery', 'fault.mjs', ["the agent was given the last delivery's ${given(last)}", "the agent was given the last delivery's ${given(lead)}"]),
  m('NB3', 'a replay basis names the fields the restored agent sent differently', 'fault.mjs', ["(${Object.keys(plan.body).join(', ')} replaced;", '(fields replaced;']),
  // The boundary (scheduleLedger).
  m('NL1', 'a held call gives the agent a timeout', 'fault.mjs', ["        throw named('TimeoutError', plan.message);\n", '        return undefined;\n']),
  m('NL2', 'a held call\'s record is fault-injected and marked', 'fault.mjs', ["exception: `TimeoutError: ${plan.message}`, fault: kind });", 'exception: `TimeoutError: ${plan.message}` });']),
  m('NL3', 'a held body does not run before it is released', 'fault.mjs', ['        held = { name, args, body };\n', '        held = { name, args, body }; await body(args);\n']),
  m('NL4', 'a late delivery is released by the next record of any tool', 'fault.mjs', ["if (held && (plan.kind === 'late-delivery' || name === plan.tool)) await land();", 'if (held && name === plan.tool) await land();']),
  m('NL5', 'out-of-order is released only by the next record of its tool', 'fault.mjs', ["plan.kind === 'late-delivery' || name === plan.tool", 'true']),
  m('NL6', 'release() lands a call still held', 'fault.mjs', ['    async release() { if (held) await land(); },', '    async release() {},']),
  m('NL7', 'the late body\'s record is marked', 'fault.mjs', ['write(recordOf(h.name, h.args, await outcome(h.body, h.args), true));', 'write(recordOf(h.name, h.args, await outcome(h.body, h.args), false));']),
  m('NL8', 'the late body runs with the held call\'s arguments', 'fault.mjs', ['await outcome(h.body, h.args), true', 'await outcome(h.body, {}), true']),
  m('NL9', 'a plan applies to the first call to its tool only', 'fault.mjs', ['      if (kind) used = true;\n', '']),
  m('NL10', 'a retry runs the body again', 'fault.mjs', ['rest.push([args, await outcome(body, args)])', 'rest.push([args, first])']),
  m('NL11', 'a retry makes the planned number of deliveries', 'fault.mjs', ['i < (plan.attempts ?? 2)', 'i < 2']),
  m('NL12', 'the agent is given the last delivery\'s outcome', 'fault.mjs', ['      return deliver(rest.at(-1)[1]);\n', '      return deliver(first);\n']),
  m('NL13', 'a replay runs with the plan\'s fields in place', 'fault.mjs', ['plain(args) ? { ...args, ...plan.body } : null', 'plain(args) ? { ...args } : null']),
  m('NL14', 'a replay\'s record carries the replay\'s arguments', 'fault.mjs', ['rest.map(([a, o]) => recordOf(name, a, o, true))', 'rest.map(([, o]) => recordOf(name, args, o, true))']),
  m('NL15', 'arguments that are not an object get no replay', 'fault.mjs', ["kind === 'checkpoint-restore-replay' && plain(args) ?", "kind === 'checkpoint-restore-replay' ?"]),
  m('NL16', 'a first call that raises spends the plan unmarked', 'fault.mjs', ["if (!kind || first.status === 'exception' || (kind", 'if (!kind || (kind']),
  m('NL17', 'every delivery of a retry or replay is marked', 'fault.mjs', ['[recordOf(name, args, first, true), ...rest', '[recordOf(name, args, first, false), ...rest']),
  m('NL18', 'a kind that is not a schedule applies nothing', 'fault.mjs', ['!skipFault && plan && SCHEDULE_KINDS.includes(plan.kind) && !used', '!skipFault && plan && !used']),
  m('NL19', 'skipFault never applies the plan', 'fault.mjs', ['const kind = !skipFault && plan &&', 'const kind = plan &&']),
  m('NL20', 'a value that cannot be captured is a marker, never a lost record', 'fault.mjs', ["const safelyCapped = value => { try { return capped(value); } catch (error) { return { unrecordable: error?.name ?? 'Error' }; } };", 'const safelyCapped = capped;']),
  // FW-ONCE.
  m('NO1', 'an unfired fault decides nothing', 'fault.mjs', ['  if (!fault.fired) return row(', '  if (false) return row(']),
  m('NO2', 'a missing snapshot decides nothing', 'fault.mjs', ['  if (!before?.ok || !after?.ok) return row(', '  if (!before?.ok) return row(']),
  m('NO22', 'a collection missing from a snapshot is never read as empty', 'fault.mjs', ['rowsBefore = before.state?.[name], rowsAfter = after.state?.[name];', 'rowsBefore = before.state?.[name] ?? [], rowsAfter = after.state?.[name] ?? [];']),
  m('NO23', 'rows whose keys cannot tell them apart are never counted', 'fault.mjs', ['    if ([rowsBefore, rowsAfter].some(rows => { const keys = rows.map(keyText); return keys.includes(null) || new Set(keys).size !== keys.length; })) {', '    if (false) {']),
  m('NO27', 'a key is 1 to 160 characters of text, as in the state diff', 'fault.mjs', ['return t !== null && bounded(t, 160) ? t : null;', 'return t;']),
  m('NO28', 'more new rows under one key with the expected content than allowed is effect-repeated', 'fault.mjs', ['      if ([...tally(rowsAfter)].some(([k, n]) => k !== null && n - (had.get(k) ?? 0) > allowed)) repeatedUnderOneKey.push(name);\n', '']),
  m('NO29', 'only rows new under the key count', 'fault.mjs', ['n - (had.get(k) ?? 0) > allowed', 'n > allowed']),
  m('NO30', 'only rows with the expected content count under one key', 'fault.mjs', ['const tally = rows => rows.filter(r => inserts.some(e => e.after === undefined || fits(r, e.after))).reduce(', 'const tally = rows => rows.reduce(']),
  m('NO31', 'overlapping expected inserts are counted together under one key', 'fault.mjs', ['allowed = inserts.reduce((n, e) => n + (e.count ?? 1), 0);', 'allowed = 1;']),
  m('NO32', 'a fail stands beside a collection that cannot be counted', 'fault.mjs', ["const failed = repeatedUnderOneKey.length ? 'effect-repeated' :", "const failed = unread.length ? null : repeatedUnderOneKey.length ? 'effect-repeated' :"]),
  m('NO3', 'no declared effect, no verdict', 'fault.mjs', ["  if (!collections.length) return row(", '  if (false) return row(']),
  m('NO4', 'a row an expectation counted is not counted again', 'fault.mjs', ['        for (const [k] of found) open.delete(k);\n', '']),
  m('NO5', 'the rows a where selects are that expectation\'s, not left over', 'fault.mjs', ['      for (const k of keys) open.delete(k);\n', '']),
  m('NO6', 'an insert counts only rows with the declared content', 'fault.mjs', ['(e.after === undefined || fits(r, e.after))', 'true']),
  m('NO7', 'the count defaults to 1 and is honoured', 'fault.mjs', ['const need = e.count ?? 1,', 'const need = 1,']),
  m('NO8', 'more than the count is effect-repeated', 'fault.mjs', ["found.length === need ? 'once' : found.length > need ? 'effect-repeated' : 'effect-missing'", "found.length === need ? 'once' : 'effect-missing'"]),
  m('NO9', 'a where-less update without declared content is net-only', 'fault.mjs', ["e.op === 'update' && e.after === undefined ? 'net-only' :", '']),
  m('NO10', 'a selected row changed to other content, or gone, is effect-differs', 'fault.mjs', ["changed.some(pair => !holds(pair)) ? 'effect-differs'", "false ? 'effect-differs'"]),
  m('NO24', 'a selected row left without the content is effect-missing', 'fault.mjs', ["        : !pairs.every(holds) ? 'effect-missing'\n", '']),
  m('NO25', 'rows that already held the content with nothing changed are not counted once', 'fault.mjs', ["changed.length ? 'once' : 'already-held'", "'once'"]),
  m('NO26', 'already-held reads inconclusive, never a pass', 'fault.mjs', ["  if (verdicts.includes('already-held')) return out(", '  if (false) return out(']),
  m('NO12', 'an expected update without content is net-only', 'fault.mjs', ["        : e.after === undefined ? 'net-only'\n", '']),
  m('NO13', 'an expected delete holds only when the rows are gone', 'fault.mjs', ["(pairs.every(([, b]) => b === undefined) ? 'once' : 'effect-missing')", "'once'"]),
  m('NO14', 'every change left over in an effect collection counts', 'fault.mjs', ["    for (const [k, [op]] of open) other.push(", '    for (const [k, [op]] of []) other.push(']),
  m('NO15', 'a leftover of an expected op is effect-repeated', 'fault.mjs', ["k !== REMAINDER_KEY && ops.has(op) ? 'effect-repeated' : 'effect-extra'", "'effect-extra'"]),
  m('NO16', 'a remainder change is never the expected effect again', 'fault.mjs', ["k !== REMAINDER_KEY && ops.has(op) ? 'effect-repeated'", "ops.has(op) ? 'effect-repeated'"]),
  m('NO17', 'an unresolved expectation leaves the row inconclusive, before any fail', 'fault.mjs', ["  if (verdicts.includes('unresolved')) return out(", '  if (false) return out(']),
  m('NO18', 'net-only reads inconclusive, never a pass', 'fault.mjs', ["  if (verdicts.includes('net-only')) return out(", '  if (false) return out(']),
  m('NO19', 'an app-supplied snapshot never passes', 'fault.mjs', ["  if (snapshotCustody === 'app-report') return out(", '  if (false) return out(']),
  m('NO20', 'a snapshot the app took is app-supplied', 'fault.mjs', ["[before, after].some(s => s.takenBy !== 'scopehaven')", 'false']),
  m('NO21', 'an in-process pass says so', 'fault.mjs', ["snapshotCustody === 'in-process' ? `In-process snapshot", "false ? `In-process snapshot"]),
  // The ledger record.
  m('CF1', 'a reset marks only a body that returned', 'contract.mjs', ["record.fault === 'reset-after-commit' && record.status === 'returned' && ", "record.fault === 'reset-after-commit' && "]),
  m('CF2', 'a reset record carries no seen', 'contract.mjs', [" && !Object.hasOwn(record, 'seen');", ';']),
  m('CF3', 'a duplicate mark carries the delivery the agent got', 'contract.mjs', [' && DUPLICATE_SEEN.includes(record.seen);', ';']),
  m('CF4', 'a duplicate mark is never on a fault-injected record', 'contract.mjs', [" && record.status !== 'fault-injected'", '']),
  m('CF5', 'no seen without a duplicate mark', 'contract.mjs', ["if (Object.hasOwn(record, 'fault') || Object.hasOwn(record, 'seen')) {", "if (Object.hasOwn(record, 'fault')) {"]),
  // The judge.
  m('JF1', 'FW-FAULT reports the basis of the fault that fired', 'judge.mjs', ['fault.fired ? fault.basis :', "fault.fired ? 'Fault fired.' :"]),
  m('J9', 'an unfired fault makes the run inconclusive (re-applied)', 'judge.mjs', ["  if (fault.planned && !fault.fired) return verdict(scenario, record, rows, { verdict: 'inconclusive', reasons: [`fault-not-fired:${fault.reason}`] });\n", '']),
  // The JavaScript tool boundary (the fake adapter and the Mastra adapter).
  m('TL1', 'JS: a reset marks the body\'s record', 'adapters/tool-ledger.mjs', ["write(recordOf(base, first, { fault: 'reset-after-commit' }));", 'write(recordOf(base, first));']),
  m('TL2', 'JS: under a reset the agent gets a connection reset, not the result', 'adapters/tool-ledger.mjs', ["throw named('ConnectionResetError', fault.message, 'ECONNRESET');", 'return deliver(first);']),
  m('TL3', 'JS: a first call that raises spends the fault without a mark', 'adapters/tool-ledger.mjs', ["if (first.status === 'exception' || !APPLIED_AFTER_BODY.includes(planned))", 'if (!APPLIED_AFTER_BODY.includes(planned))']),
  m('TL4', 'JS: the duplicate runs the body again', 'adapters/tool-ledger.mjs', ['again = await outcome(run);', 'again = first;']),
  m('TL5', 'JS: the first delivery\'s record comes first, the duplicate\'s next', 'adapters/tool-ledger.mjs', ["const pair = [recordOf(base, first), recordOf(base, again, { fault: 'duplicate-delivery', seen })];", "const pair = [recordOf(base, again, { fault: 'duplicate-delivery', seen }), recordOf(base, first)];"]),
  m('TL6', 'JS: the agent gets the delivery seen names', 'adapters/tool-ledger.mjs', ["return deliver(seen === 'second' ? again : first);", 'return deliver(first);']),
  m('TL7', 'JS: the duplicate\'s record says which delivery the agent got', 'adapters/tool-ledger.mjs', ["{ fault: 'duplicate-delivery', seen }", "{ fault: 'duplicate-delivery', seen: 'first' }"]),
  m('TL8', 'JS: the fault applies to the first call to its tool only', 'adapters/tool-ledger.mjs', ['      if (planned) used = true;\n', '']),
  m('TL9', 'JS: the reset error carries ECONNRESET, as a socket reset does', 'adapters/tool-ledger.mjs', ["'ECONNRESET'", 'undefined']),
  m('TL10', 'JS: a value past the cap is its digest and length', 'adapters/tool-ledger.mjs', ['json.length <= JSON_CAP ?', 'true ?']),
  m('TL11', 'JS: a value that cannot be captured is a marker, never a lost record', 'adapters/tool-ledger.mjs', ["const safelyCapped = value => { try { return capped(value); } catch (error) { return { unrecordable: error?.name ?? 'Error' }; } };", 'const safelyCapped = capped;']),
  m('TL12', 'JS: a kind the boundary does not know applies nothing', 'adapters/tool-ledger.mjs', ['!APPLIED_AFTER_BODY.includes(planned)', '!planned']),
  m('TL14', 'JS: skipFault (the fake adapter\'s no-fault) never applies the plan', 'adapters/tool-ledger.mjs', ['const planned = !skipFault && fault', 'const planned = fault']),
  // The Python shim.
  m('SH1', 'shim: a reset marks the body\'s record', 'adapters/shim.py', ['rec.update(status="returned", result=safely_capped(result), fault=kind)', 'rec.update(status="returned", result=safely_capped(result))']),
  m('SH2', 'shim: under a reset the agent gets a connection reset, not the result', 'adapters/shim.py', ['        raise ConnectionResetError(self.fault["message"])', '        return result']),
  m('SH3', 'shim: the lost result is never the last one a reply can quote', 'adapters/shim.py', ['        self._record(rec)\n        raise ConnectionResetError', '        self.last_result = result\n        self._record(rec)\n        raise ConnectionResetError']),
  m('SH4', 'shim: a reset or duplicate applies to the first call to its tool only', 'adapters/shim.py', ['            self.fault_used = True\n            if f["kind"] != "timeout":\n                return f["kind"]', '            if f["kind"] != "timeout":\n                return f["kind"]\n            self.fault_used = True']),
  m('SH5', 'shim: the duplicate runs the body again', 'adapters/shim.py', ['                second, caught = fn(*args, **kwargs), None', '                second, caught = result, None']),
  m('SH6', 'shim: the duplicate runs the body again (async)', 'adapters/shim.py', ['second, caught = await fn(*args, **kwargs), None', 'second, caught = result, None']),
  m('SH7', 'shim: both deliveries\' records are written together, so nothing lands between them', 'adapters/shim.py',
    ['            ledger._redeliver()\n            try:\n                second, caught = fn(*args, **kwargs), None', '            ledger._record({**rec, "status": "returned", "result": result})\n            ledger._redeliver()\n            try:\n                second, caught = fn(*args, **kwargs), None'],
    ['            self._write(rec)\n            self._write(dup)', '            self._write(dup)']),
  m('SH8', 'shim: with seen second the agent gets the duplicate\'s result', 'adapters/shim.py', ['        return shown', '        return result']),
  m('SH9', 'shim: the duplicate\'s record says which delivery the agent got', 'adapters/shim.py', ['"seen": seen}', '"seen": "first"}']),
  m('SH10', 'shim: with seen second the duplicate\'s exception reaches the agent', 'adapters/shim.py', ['delivered = error is None or (isinstance(error, Exception) and seen == "first")', 'delivered = error is None or isinstance(error, Exception)']),
  m('SH11', 'shim: the duplicate counts as running until its record is written', 'adapters/shim.py', ['        with self.lock:\n            self.running += 1\n\n    def _delivered_twice', '        pass\n\n    def _delivered_twice']),
  m('SH13', 'shim: only a result the agent was given is the last one a reply can quote', 'adapters/shim.py', ['            if delivered:\n                self.last_result = shown', '            self.last_result = shown']),
  m('SH14', 'shim: a cancelled or interrupted duplicate is recorded as cancelled', 'adapters/shim.py', ['dup.update(status="exception" if isinstance(error, Exception) else "cancelled",', 'dup.update(status="exception",']),
  m('SH15', 'shim: an async first call that raises is recorded and raised, never followed by a reset or a duplicate', 'adapters/shim.py', ['                except Exception as error:\n                    ledger._raised(rec, error)\n                    raise\n                except BaseException as error:\n                    # Cancelled or interrupted (CancelledError, KeyboardInterrupt): recorded, then let through.\n                    ledger._raised(rec, error, "cancelled")\n                    raise\n                if kind', '                except Exception as error:\n                    result = None\n                except BaseException as error:\n                    # Cancelled or interrupted (CancelledError, KeyboardInterrupt): recorded, then let through.\n                    ledger._raised(rec, error, "cancelled")\n                    raise\n                if kind']),
  m('SH12', 'shim: a first call that raises is recorded and raised, never followed by a reset or a duplicate', 'adapters/shim.py', ['            except Exception as error:\n                ledger._raised(rec, error)\n                raise\n            except BaseException as error:\n                ledger._raised(rec, error, "cancelled")\n                raise\n            if kind', '            except Exception as error:\n                result = None\n            except BaseException as error:\n                ledger._raised(rec, error, "cancelled")\n                raise\n            if kind']),
];

function runTests(root) {
  const out = spawnSync(process.execPath, ['--test', '--test-concurrency=1', ...TESTS], { cwd: root, encoding: 'utf8', timeout: 300000 });
  const lines = (out.stdout ?? '').split('\n');
  const failed = [...new Set(lines.filter(l => /^✖ /.test(l)).map(l => l.slice(2).replace(/ \([\d.]+ms\)$/, '')))];
  return { code: out.status, failed, skipped: Number(lines.find(l => /^ℹ skipped /.test(l))?.split(' ').pop() ?? 0) };
}

async function main() {
  const arg = flag => (process.argv.includes(flag) ? process.argv[process.argv.indexOf(flag) + 1] : null);
  const outFile = arg('--out'), only = arg('--only')?.split(',') ?? null;
  const tmp = mkdtempSync(join(tmpdir(), 'scopehaven-fault-mutations-'));
  try {
    for (const dir of ['src', 'integrations/collateral', 'integrations/observers', 'integrations/evid-subject', 'integrations/frameworks']) cpSync(join(ROOT, dir), join(tmp, dir), { recursive: true });
    const base = runTests(tmp);
    if (base.code !== 0) throw new Error(`Unmutated tests fail: ${base.failed.join('; ')}`);
    // A skipped Python test would let a shim mutation survive unseen.
    if (base.skipped) throw new Error(`Unmutated run skipped ${base.skipped} tests (no Python 3 at a fixed path).`);
    const results = [];
    for (const mu of MUTATIONS.filter(x => !only || only.includes(x.id))) {
      const path = join(tmp, mu.file), original = readFileSync(path, 'utf8');
      const counts = mu.edits.map(([find]) => original.split(find).length - 1);
      if (counts.some(c => c !== 1)) { results.push({ id: mu.id, property: mu.property, status: 'not-applied', reason: `finds matched ${counts.join(', ')} times` }); continue; }
      writeFileSync(path, mu.edits.reduce((text, [find, replace]) => text.replace(find, () => replace), original));
      try {
        const r = runTests(tmp);
        results.push({ id: mu.id, property: mu.property, file: mu.file, status: r.code === 0 ? 'SURVIVED' : 'killed', killedBy: r.failed.slice(0, 3) });
      } finally { writeFileSync(path, original); }
      process.stderr.write(`${mu.id} ${results.at(-1).status}\n`);
    }
    const summary = { schema: 'scopehaven-framework-mutations/1', at: new Date().toISOString(), node: process.version, test: TESTS.join(' '), total: results.length, killed: results.filter(r => r.status === 'killed').length, results };
    if (outFile) writeFileSync(outFile, `${JSON.stringify(summary, null, 1)}\n`);
    process.stdout.write(`${JSON.stringify({ total: summary.total, killed: summary.killed, survivors: results.filter(r => r.status !== 'killed').map(r => `${r.id} ${r.status}`) })}\n`);
    if (summary.killed !== summary.total) process.exitCode = 1;
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
