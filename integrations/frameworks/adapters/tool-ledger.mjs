// The tool boundary for JavaScript and TypeScript adapters (scopehaven-turn-runner/1), as
// shim.py's Ledger is for Python ones: one presence-only ledger record per tool body run, and the
// planned fault (fault.mjs) applied to the first call to its tool:
//   timeout             raised before the body; one 'fault-injected' record
//   reset-after-commit  the body runs; if it returns, its record is marked and the agent gets a
//                       connection reset instead of the result
//   duplicate-delivery  the body runs; if it returns, it runs again with the same arguments, and
//                       both records are written together (nothing can land between them); the
//                       agent gets the first delivery's result, or the duplicate's with seen 'second'
// A first call that raises spends the fault without firing it; a kind this boundary does not know
// applies nothing. The sequence number is taken when a record is written, so overlapping calls still
// arrive 1, 2, 3, and a value that cannot be captured is recorded as { unrecordable }, never lost.
//
// usage: const ledger = toolLedger(send, fault); const result = await ledger.call(name, args, () => body(args));
import { createHash } from 'node:crypto';

const JSON_CAP = 60000;
const named = (name, message, code) => Object.assign(new Error(message), { name }, code ? { code } : {});
const text = error => String(error?.message ?? error).slice(0, 4000);
// A value as the record carries it: its JSON, or its digest and length when it is past the cap.
export const capped = value => {
  const json = JSON.stringify(value ?? null);
  return json.length <= JSON_CAP ? JSON.parse(json) : { truncated: true, sha256: createHash('sha256').update(json).digest('hex'), chars: json.length };
};
const safelyCapped = value => { try { return capped(value); } catch (error) { return { unrecordable: error?.name ?? 'Error' }; } };
const APPLIED_AFTER_BODY = ['reset-after-commit', 'duplicate-delivery'];

export function toolLedger(send, fault, { firstSeq = 1, skipFault = false } = {}) {
  let seq = firstSeq - 1, used = false;
  const take = () => ++seq;
  const write = record => send({ type: 'tool', record: { seq: take(), ...record } });
  const outcome = async run => { try { return { status: 'returned', result: await run() }; } catch (error) { return { status: 'exception', error }; } };
  const recordOf = (base, o, mark = {}) => ({ ...base, status: o.status, ...(o.status === 'returned' ? { result: safelyCapped(o.result) } : { exception: text(o.error) }), ...mark });
  const deliver = o => { if (o.status === 'exception') throw o.error; return o.result; };
  return {
    take,
    async call(name, args, run) {
      const base = { tool: name, args: safelyCapped(args) };
      const planned = !skipFault && fault && !used && name === fault.tool ? fault.kind : null;
      if (planned) used = true;
      if (planned === 'timeout') {
        write({ ...base, status: 'fault-injected', exception: `TimeoutError: ${fault.message}` });
        throw named('TimeoutError', fault.message);
      }
      const first = await outcome(run);
      if (first.status === 'exception' || !APPLIED_AFTER_BODY.includes(planned)) { write(recordOf(base, first)); return deliver(first); }
      if (planned === 'reset-after-commit') {
        write(recordOf(base, first, { fault: 'reset-after-commit' }));
        throw named('ConnectionResetError', fault.message, 'ECONNRESET');
      }
      const seen = fault.seen ?? 'first', again = await outcome(run);
      const pair = [recordOf(base, first), recordOf(base, again, { fault: 'duplicate-delivery', seen })];
      for (const record of pair) write(record);
      return deliver(seen === 'second' ? again : first);
    },
  };
}
