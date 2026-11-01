// Test-only turn-runner adapter (scopehaven-turn-runner/1) over a tiny app: a
// SQLite `segments` table (ticket, flight, fare) and in-memory `refunds` and
// `balances`, in the shapes of the LangGraph and Mastra templates. The stub
// steps drive it exactly as the real adapters' stub models do.
//   --variant buggy|fixed   rebook moves every segment of the ticket (buggy, the
//                           LangGraph tutorial's defect) or only the first one
//   --variant idempotent-refund  a repeated refund of the same user and amount returns
//                           the first one instead of refunding again (the billing fix shape)
//   --variant refuse-refund every refund raises and nothing is refunded (a fix that refuses everything)
//   --misbehave a,b,...     adapter faults the turn runner must not accept:
//     error-on-hello, hang-turn, exit-on-turn, wrong-turn-id, gap-ledger, bad-line,
//     stray-state, forge-snapshot, phantom-refund, lie-report, no-fault, late-tool,
//     late-tool-same-write (the turn-end and a later tool record in one write),
//     early-tool (a tool record before any turn), early-turn-end (a turn-end before
//     the turn, then silence), error-after-end, crash-turn, omit-stub, exit-nonzero,
//     late-retry and late-collateral (a write at shutdown, no tool record),
//     late-object-write (an in-memory refund shortly after the turn, no record),
//     startup-write (a write shortly after ready), partial-tail (a last line with
//     no newline), many-tools (more ledger records than the contract allows),
//     spawn-worker (a worker process left running), map-state (balances as a Map),
//     flood-state (more unread messages than the queue holds), tool-on-sync (a tool
//     record written on the sync barrier, before its echo)
import { DatabaseSync } from 'node:sqlite';
import { writeFileSync, writeSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { plainData } from '../adapters/plain-data.mjs';
import { toolLedger } from '../adapters/tool-ledger.mjs';
import { createInterface } from 'node:readline';

const argv = process.argv.slice(2);
const opt = name => { const i = argv.indexOf(`--${name}`); return i === -1 ? null : argv[i + 1]; };
const variant = opt('variant') ?? 'buggy';
const misbehave = new Set((opt('misbehave') ?? '').split(',').filter(Boolean));
const send = message => writeSync(3, `${JSON.stringify(message)}\n`);

let busy = null, db = null, ledger = null, last = null;
const refunds = [], balances = { YJ: 0, Ada: 0 };
const tools = {
  rebook({ ticket, flight }) {
    if (variant === 'fixed') db.prepare('UPDATE segments SET flight = ? WHERE rowid = (SELECT min(rowid) FROM segments WHERE ticket = ?)').run(flight, ticket);
    else db.prepare('UPDATE segments SET flight = ? WHERE ticket = ?').run(flight, ticket);
    return 'Ticket updated.';
  },
  upgrade({ ticket }) { db.prepare("UPDATE segments SET fare = 'business' WHERE ticket = ?").run(ticket); return 'Upgraded.'; },
  // Moves an existing row of another ticket into this one (it was outside a T1 watch before).
  reassign({ from, to, flight }) { db.prepare('UPDATE segments SET ticket = ?, flight = ? WHERE ticket = ?').run(to, flight, from); return 'Reassigned.'; },
  refund({ user, amount }) {
    if (variant === 'refuse-refund') throw new Error('Refunds are disabled.');
    const earlier = variant === 'idempotent-refund' ? refunds.find(r => r.user === user && r.amount === amount) : null;
    if (earlier) return { ...earlier, newBalance: balances[user] };
    const refundId = `r${refunds.length + 1}`;
    if (!misbehave.has('phantom-refund')) { refunds.push({ refundId, user, amount }); balances[user] = (balances[user] ?? 0) + amount; }
    return { refundId, user, amount, newBalance: balances[user] + (misbehave.has('phantom-refund') ? amount : 0) };
  },
  lookup({ user }) { return { user, balance: balances[user] }; },
};
// The tool boundary (adapters/tool-ledger.mjs, as the TypeScript adapters use it): a ledger record
// per call; the planned fault applied to the first call.
async function call(name, input) {
  last = await ledger.call(name, input, () => tools[name](input));
  return last;
}
const render = text => text.replace(/\{\{last\.([A-Za-z_]\w*)\}\}/g, (all, field) => (last && typeof last === 'object' && field in last ? String(last[field]) : all));
const values = (paths, report) => Object.fromEntries(paths.map(({ path }) => {
  if (path === 'refunds') return [path, plainData(report && misbehave.has('lie-report') ? [...refunds, { refundId: 'r99', user: 'YJ', amount: 40 }] : refunds)];
  return [path, plainData(misbehave.has('map-state') ? new Map(Object.entries(balances)) : balances)];
}));

for await (const line of createInterface({ input: process.stdin })) {
  const message = JSON.parse(line);
  if (message.type === 'hello') {
    if (misbehave.has('error-on-hello')) { send({ type: 'error', message: 'load failed' }); continue; }
    ledger = toolLedger(send, message.fault, { firstSeq: misbehave.has('gap-ledger') ? 2 : 1, skipFault: misbehave.has('no-fault') });
    db = new DatabaseSync('app.db');
    db.exec("CREATE TABLE IF NOT EXISTS segments (ticket TEXT, flight INTEGER, fare TEXT); DELETE FROM segments; INSERT INTO segments VALUES ('T1', 100, 'economy'), ('T2', 300, 'economy'), ('T1', 200, 'economy');");
    send({ type: 'ready', framework: 'fake', tools: Object.keys(tools), template: { variant }, substitutions: [] });
    if (misbehave.has('early-tool')) await call('lookup', { user: 'YJ' });
    // A busy app: it keeps writing from startup until the first turn arrives.
    if (misbehave.has('startup-write')) { let n = 0; busy = setInterval(() => db.prepare("UPDATE segments SET fare = ? WHERE ticket = 'T2'").run(`startup-${++n}`), 15); }
    if (misbehave.has('spawn-worker')) writeFileSync('worker.pid', String(spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], { stdio: 'ignore' }).pid));
    if (misbehave.has('early-turn-end')) send({ type: 'turn-end', id: 1, reply: '', messages: [], stub: { consumed: 2, exhausted: false } });
  } else if (message.type === 'turn') {
    clearInterval(busy);
    if (misbehave.has('exit-on-turn')) process.exit(3);
    if (misbehave.has('early-turn-end')) continue;
    if (misbehave.has('bad-line')) writeSync(3, 'not json\n');
    if (misbehave.has('stray-state')) send({ type: 'state', id: 'stray', values: { refunds: [] } });
    const texts = [];
    let consumed = 0;
    if (misbehave.has('many-tools')) for (let i = 0; i < 2100; i++) await call('lookup', { user: 'YJ' });
    for (const step of message.steps) {
      consumed++;
      if (step.kind === 'tool') { try { await call(step.tool, step.args); } catch { /* the model sees the error and goes on */ } continue; }
      texts.push(render(step.text));
      break;
    }
    if (misbehave.has('hang-turn')) continue;
    const end = { type: 'turn-end', id: message.id + (misbehave.has('wrong-turn-id') ? 1 : 0), reply: texts.at(-1) ?? '', messages: texts, stub: { consumed, exhausted: !texts.length } };
    if (misbehave.has('omit-stub')) delete end.stub;
    if (misbehave.has('crash-turn')) end.failure = 'GraphRecursionError: recursion limit reached';
    if (misbehave.has('late-tool-same-write')) {
      const late = { type: 'tool', record: { seq: ledger.take(), tool: 'lookup', args: { user: 'YJ' }, status: 'returned', result: tools.lookup({ user: 'YJ' }) } };
      writeSync(3, `${JSON.stringify(end)}\n${JSON.stringify(late)}\n`);
      continue;
    }
    send(end);
    if (misbehave.has('late-tool')) await call('lookup', { user: 'YJ' });
    if (misbehave.has('error-after-end')) send({ type: 'error', message: 'background task failed' });
    // Keeps refunding in the background after the turn-end, with no tool record, until close.
    if (misbehave.has('late-object-write')) { let n = 0; busy = setInterval(() => { refunds.push({ refundId: `r-late-${++n}`, user: 'YJ', amount: 40 }); balances.YJ += 40; }, 15); }
    if (misbehave.has('flood-state')) for (let i = 0; i < 2100; i++) send({ type: 'state', id: `flood-${i}`, values: {} });
  } else if (message.type === 'sync') {
    if (misbehave.has('tool-on-sync')) await call('lookup', { user: 'YJ' });
    send({ type: 'sync', id: message.id });
  } else if (message.type === 'snapshot') {
    const report = message.paths.some(p => p.source === 'app-report');
    if (misbehave.has('forge-snapshot')) send({ type: 'state', id: 'forged', values: { refunds: [{ refundId: 'r1', user: 'YJ', amount: 40 }], balances: { YJ: 40, Ada: 0 } } });
    send({ type: 'state', id: message.id, values: values(message.paths, report) });
  } else if (message.type === 'close') {
    clearInterval(busy);
    // Shutdown work no tool records (the review's probes P1b, P2b and P3).
    if (misbehave.has('late-retry')) db.prepare('UPDATE segments SET flight = 150 WHERE rowid = (SELECT min(rowid) FROM segments WHERE ticket = ?)').run('T1');
    if (misbehave.has('late-collateral')) db.prepare("UPDATE segments SET fare = 'business' WHERE ticket = 'T2'").run();
    if (misbehave.has('partial-tail')) writeSync(3, JSON.stringify({ type: 'tool', record: { seq: ledger.take(), tool: 'rebook', args: { ticket: 'T2', flight: 999 }, status: 'returned', result: 'Ticket updated.' } }));
    db?.close();
    process.exit(misbehave.has('exit-nonzero') ? 1 : 0);
  }
}
