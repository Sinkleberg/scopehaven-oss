// Turn runner: drive one framework scenario through its adapter and keep the
// record the verdict is computed from (judge.mjs). No network listener: the
// adapter is a child process spoken to over its stdin and file descriptor 3
// (contract.mjs).
//
// Isolation of the child: a minimal environment (no API keys or provider
// variables are passed through), HOME set to a private folder in the run's
// working directory, and every HTTP(S) proxy variable pointed at a dead
// loopback port, so a library that tries to reach a provider fails fast
// instead of leaving the machine. This is best effort inside the process;
// templates that ignore proxy variables are not stopped by it, so adapters
// replace the model with a scripted stub and run on synthetic seed data only.
// The adapter leads its own process group, so any worker the template starts is
// found and killed at the end (a survivor makes the run unusable).
//
// Order of a run: hello, wait for ready, BEFORE snapshot and its quiet check
// (read again a settle interval later: it must not have moved), each turn (a
// sync barrier, then the turn; ledger records stream in while it runs; it ends
// only with its turn-end), AFTER snapshot, the object paths read again a settle
// interval later, close, and once the adapter's whole process group is gone the
// SQLite files read again. Any state that moved after its snapshot, a write the
// app made outside a wrapped tool (a background thread, an unawaited promise, a
// flush at shutdown), makes the run unusable. ScopeHaven takes every snapshot
// itself: SQLite files are read by this process from a private copy
// (sqlite-state.mjs) and recorded as custody 'out-of-process'; object paths are
// read by the adapter inside the app's process on this process's request, and
// recorded as custody 'in-process'.
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { digest } from '../../src/domain.mjs';
import { TURN_RUNNER_PROTOCOL, parseAdapterMessage, ledgerOf, CONTRACT_LIMITS } from './contract.mjs';
import { projectObjects, objectRequest } from './state.mjs';
import { snapshotSqlite } from './sqlite-state.mjs';
import { validateScenario } from './scenario.mjs';
import { FRAMEWORK_RUN_SCHEMA } from './judge.mjs';

export const DEAD_PROXY = 'http://127.0.0.1:9';
// queue: unread adapter messages held at once; ledgerBytes: all tool lines of a run together.
export const RUN_DEFAULTS = Object.freeze({ readyMs: 300000, turnMs: 120000, snapshotMs: 30000, closeMs: 10000, settleMs: 300, tail: 4000, queue: CONTRACT_LIMITS.ledger + 64, ledgerBytes: 8 << 20 });
export const SNAPSHOT_CUSTODY = Object.freeze(['out-of-process', 'in-process', 'app-report']);

export function isolatedEnv(workdir, extra = {}) {
  const home = join(workdir, '.home');
  mkdirSync(home, { recursive: true, mode: 0o700 });
  const proxy = Object.fromEntries(['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'].map(k => [k, DEAD_PROXY]));
  return { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home, LANG: 'en_US.UTF-8', TMPDIR: home, ...proxy, NO_PROXY: '', no_proxy: '', NODE_USE_ENV_PROXY: '1', PYTHONDONTWRITEBYTECODE: '1', PYTHONNOUSERSITE: '1', ...extra };
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// One adapter process and its message stream.
function connect(command, args, { cwd, env }) {
  const child = spawn(command, args, { cwd, env, stdio: ['pipe', 'pipe', 'pipe', 'pipe'], detached: true });
  // arrival: the order each adapter message arrived in (1, 2, 3...), kept beside the message.
  // closed: the process exited and every byte of its output streams has been read.
  const state = { messages: [], waiters: [], exited: null, closed: false, protocolErrors: [], stdout: '', stderr: '', buffer: '', count: 0, arrival: new WeakMap(), tools: 0, toolBytes: 0 };
  const tail = (key, chunk) => { state[key] = (state[key] + chunk).slice(-RUN_DEFAULTS.tail); };
  child.stdout.setEncoding('utf8').on('data', chunk => tail('stdout', chunk));
  child.stderr.setEncoding('utf8').on('data', chunk => tail('stderr', chunk));
  const settle = () => { for (const w of [...state.waiters]) w.check(); };
  child.stdio[3].setEncoding('utf8').on('data', chunk => {
    state.buffer += chunk;
    let at;
    while ((at = state.buffer.indexOf('\n')) !== -1) {
      const line = state.buffer.slice(0, at);
      state.buffer = state.buffer.slice(at + 1);
      if (!line.trim()) continue;
      let message;
      try { message = parseAdapterMessage(line); } catch (error) { state.protocolErrors.push(error.code ?? 'parse'); continue; }
      // Bounded: the ledger (records and bytes) and the unread queue. Past a bound the rest is dropped and the run is unusable.
      if (message.type === 'tool' && (++state.tools > CONTRACT_LIMITS.ledger || (state.toolBytes += line.length) > RUN_DEFAULTS.ledgerBytes)) { state.protocolErrors.push('ledger-limit'); continue; }
      if (state.messages.length >= RUN_DEFAULTS.queue) { state.protocolErrors.push('queue-limit'); continue; }
      state.arrival.set(message, ++state.count);
      state.messages.push(message);
    }
    if (state.buffer.length > CONTRACT_LIMITS.line) { state.protocolErrors.push('line'); state.buffer = ''; }
    settle();
  });
  child.stdio[3].on('error', () => {});
  child.stdin.on('error', () => {});
  child.on('exit', (code, signal) => { state.exited = { code, signal }; });
  child.on('close', () => { state.closed = true; settle(); });
  child.on('error', error => { state.exited = { code: null, signal: null, error: error.code ?? 'spawn' }; state.closed = true; settle(); });
  const send = message => { if (!state.exited && child.stdin.writable) child.stdin.write(`${JSON.stringify(message)}\n`); };
  // Wait for the first unconsumed message matching `want`; resolves { message } or { failure }.
  const wait = (want, ms) => new Promise(resolve => {
    const waiter = {
      check() {
        // Arrival order decides: an error that arrived before the wanted message fails the wait.
        const i = state.messages.findIndex(m => want(m) || m.type === 'error');
        if (i !== -1) { const m = state.messages.splice(i, 1)[0]; return done(want(m) ? { message: m } : { failure: 'adapter-error', detail: m.message }); }
        if (state.closed) return done({ failure: 'adapter-exited' });
        return null;
      },
    };
    const timer = setTimeout(() => done({ failure: 'deadline' }), ms);
    function done(result) { clearTimeout(timer); state.waiters = state.waiters.filter(w => w !== waiter); resolve(result); }
    state.waiters.push(waiter);
    waiter.check();
  });
  // The adapter's process group (it leads one): signal 0 asks whether any member is still alive.
  const group = signal => { try { process.kill(-child.pid, signal); return true; } catch { return false; } };
  // Ask the adapter to stop, then wait until its streams are closed, so every message it sent is
  // parsed; past the deadline kill its group, and stop waiting shortly after. Then any process
  // still in the group (a worker the template started) is recorded and killed.
  const close = async ms => {
    send({ type: 'close' });
    child.stdin.end();
    if (!state.closed) {
      await new Promise(resolve => {
        const kill = setTimeout(() => { group('SIGKILL'); setTimeout(resolve, 2000); }, ms);
        child.once('close', () => { clearTimeout(kill); resolve(); });
      });
    }
    state.survivors = child.pid !== undefined && group(0);
    if (state.survivors) { group('SIGKILL'); await sleep(100); }
  };
  return { child, state, send, wait, close };
}

// The object paths, read by the adapter inside the app's process on this process's request.
async function readObjects(objects, io, ms, label) {
  const id = `${label}-${randomUUID()}`;
  io.send({ type: 'snapshot', id, paths: objects.map(objectRequest) });
  const got = await io.wait(m => m.type === 'state' && m.id === id, ms);
  if (got.failure) return { ok: false, reason: `object:${got.failure}` };
  try { return { ok: true, state: projectObjects(got.message.values, objects) }; }
  catch (error) { return { ok: false, reason: `object:${error.code ?? 'projection'}` }; }
}

// The weakest custody among the sources read: out-of-process < in-process < app-report.
const custodyOf = sources => (sources.includes('app-report') ? 'app-report' : sources.includes('object-path') ? 'in-process' : 'out-of-process');

// Both kinds of snapshot for one point ('before' or 'after').
async function snapshot(point, spec, workdir, io, ms) {
  const sqlite = spec.projections.filter(p => p.source === 'sqlite-file'), objects = spec.projections.filter(p => p.source !== 'sqlite-file');
  const at = new Date().toISOString();
  const state = {}, sources = [];
  if (sqlite.length) {
    const taken = await snapshotSqlite(join(workdir, spec.sqliteFile), sqlite);
    if (!taken.ok) return { ok: false, at, takenBy: 'scopehaven', point, reason: `sqlite:${taken.reason}` };
    Object.assign(state, taken.state); sources.push('sqlite-file');
  }
  if (objects.length) {
    const read = await readObjects(objects, io, ms, point);
    if (!read.ok) return { ok: false, at, point, takenBy: 'scopehaven', reason: read.reason };
    Object.assign(state, read.state);
    sources.push(...new Set(objects.map(p => p.source)));
  }
  // An app-reported projection makes the whole point app-supplied: it can fail a check, never pass it.
  return { ok: true, at, point, takenBy: sources.includes('app-report') ? 'app' : 'scopehaven', custody: custodyOf(sources), sources, state };
}

// Did these collections stay the same between two reads? true, false, or null when a read failed.
const sameState = (a, b, names) => (a?.ok && b?.ok ? digest(names.map(n => a.state[n] ?? null)) === digest(names.map(n => b.state[n] ?? null)) : null);

// Run one scenario with one stub script. `adapter` is { command, args, env }.
// `label` names an adapter variant in the run id (for example the allowed twin).
export async function runScenario(scenarioInput, { stubId, adapter, workdir, adapterInfo = null, label = null }) {
  const scenario = validateScenario(scenarioInput);
  if (!Object.hasOwn(scenario.stubs, stubId)) throw new Error(`Unknown stub script ${stubId}.`);
  if (label !== null && !/^[a-z0-9][a-z0-9-]{0,39}$/.test(label)) throw new Error('A run label is 1 to 40 lowercase letters, digits or hyphens.');
  const limits = { ...RUN_DEFAULTS, ...(scenario.limits ?? {}) };
  const projections = scenario.state.projections;
  const sqliteNames = projections.filter(p => p.source === 'sqlite-file').map(p => p.collection), objectNames = projections.filter(p => p.source !== 'sqlite-file').map(p => p.collection);
  const record = {
    schema: FRAMEWORK_RUN_SCHEMA, runId: `${scenario.id}.${stubId}${label ? `.${label}` : ''}.${Date.now()}`, label, scenarioId: scenario.id, scenarioDigest: digest(scenario),
    stub: { id: stubId, digest: digest(scenario.stubs[stubId]) }, template: scenario.template, adapter: adapterInfo,
    startedAt: new Date().toISOString(), endedAt: null, ready: null, fault: scenario.fault, turns: [], ledger: null,
    snapshots: { before: null, after: null }, quiet: { settleMs: limits.settleMs, before: null, afterObjects: null, afterExit: null },
    errors: [], process: null, unsolicitedStates: 0,
  };
  const io = connect(adapter.command, adapter.args, { cwd: workdir, env: isolatedEnv(workdir, adapter.env) });
  const ledger = [];
  let turn = 0, from = Infinity, to = -Infinity;
  // Tool records keep arrival order, tagged with their turn. One that arrived outside a turn (before
  // the turn was sent, or after its turn-end) means the app acted while ScopeHaven was not waiting
  // on it, possibly while it took a snapshot: it is marked, and the run is not usable (judge.mjs).
  const drainTools = () => {
    for (let j = 0; j < io.state.messages.length;) {
      const m = io.state.messages[j];
      if (m.type !== 'tool') { j++; continue; }
      const n = io.state.arrival.get(m);
      ledger.push({ turn, ...(n > from && n < to ? {} : { outside: true }), record: io.state.messages.splice(j, 1)[0].record });
    }
  };
  try {
    io.send({ type: 'hello', protocol: TURN_RUNNER_PROTOCOL, fault: scenario.fault, objectPaths: projections.filter(p => p.source !== 'sqlite-file').map(objectRequest) });
    const ready = await io.wait(m => m.type === 'ready', limits.readyMs);
    if (ready.failure) { record.errors.push(`ready:${ready.failure}${ready.detail ? `:${ready.detail}` : ''}`.slice(0, 400)); return record; }
    record.ready = ready.message;
    record.snapshots.before = await snapshot('before', scenario.state, workdir, io, limits.snapshotMs);
    if (!record.snapshots.before.ok) return record;
    // Quiet at BEFORE: startup work still landing would be charged to the first turn.
    await sleep(limits.settleMs);
    const settled = await snapshot('before-settle', scenario.state, workdir, io, limits.snapshotMs);
    record.quiet.before = { same: sameState(record.snapshots.before, settled, [...sqliteNames, ...objectNames]) };
    for (const [i, text] of scenario.turns.entries()) {
      turn = i + 1;
      // The barrier: once its echo is read, every message the adapter wrote before the turn has been read.
      const barrier = `sync-${turn}-${randomUUID()}`;
      io.send({ type: 'sync', id: barrier });
      const synced = await io.wait(m => m.type === 'sync' && m.id === barrier, limits.snapshotMs);
      if (synced.failure) { record.errors.push(`sync-${turn}:${synced.failure}${synced.detail ? `:${synced.detail}` : ''}`.slice(0, 400)); return record; }
      drainTools();
      const started = Date.now();
      [from, to] = [io.state.arrival.get(synced.message), Infinity];
      io.send({ type: 'turn', id: turn, text, steps: scenario.stubs[stubId][i] });
      // Only a turn-end that arrived after the turn was sent ends it.
      const end = await io.wait(m => m.type === 'turn-end' && m.id === turn && io.state.arrival.get(m) > from, limits.turnMs);
      if (end.message) to = io.state.arrival.get(end.message);
      drainTools();
      if (end.failure) {
        record.turns.push({ id: turn, user: text, reply: '', messages: [], ended: false, endReason: end.failure, ms: Date.now() - started });
        record.errors.push(`turn-${turn}:${end.failure}${end.detail ? `:${end.detail}` : ''}`.slice(0, 400));
        return record;
      }
      const m = end.message;
      record.turns.push({ id: turn, user: text, reply: m.reply, messages: m.messages, ended: true, ms: Date.now() - started, stub: m.stub, ...(m.failure ? { failure: m.failure } : {}) });
    }
    record.snapshots.after = await snapshot('after', scenario.state, workdir, io, limits.snapshotMs);
    // Quiet at AFTER, in process: the object paths read again a settle interval later, before close.
    if (record.snapshots.after.ok && objectNames.length) {
      await sleep(limits.settleMs);
      const again = await readObjects(projections.filter(p => p.source !== 'sqlite-file'), io, limits.snapshotMs, 'after-settle');
      record.quiet.afterObjects = { same: sameState(record.snapshots.after, again, objectNames) };
    }
    return record;
  } finally {
    await io.close(limits.closeMs);
    // Quiet at AFTER, out of process: with the adapter's whole group gone, the SQLite files read again.
    if (record.snapshots.after?.ok && sqliteNames.length) {
      const exited = await snapshotSqlite(join(workdir, scenario.state.sqliteFile), projections.filter(p => p.source === 'sqlite-file'));
      record.quiet.afterExit = { same: sameState(record.snapshots.after, exited, sqliteNames) };
    }
    // Anything still queued arrived after the last turn-end (or before any turn): outside a turn.
    [from, to] = [Infinity, Infinity];
    drainTools();
    try { record.ledger = ledgerOf(ledger); } catch { record.ledger = { evidence: 'presence-only', ordered: false, records: [], invalid: true }; }
    record.unsolicitedStates = io.state.messages.filter(m => m.type === 'state').length;
    // Nothing the adapter sent goes unread: an error, a turn-end or a ready nobody waited for, or an
    // exit other than a clean 0 after close, makes the run unusable.
    for (const m of io.state.messages) if (m.type !== 'state') record.errors.push(`unconsumed-${m.type}${m.type === 'error' ? `:${m.message}` : ''}`.slice(0, 400));
    if (io.state.buffer.trim()) io.state.protocolErrors.push('partial-line');
    if (io.state.protocolErrors.length) record.errors.push(...[...new Set(io.state.protocolErrors)].map(code => `protocol:${code}`));
    if (io.state.survivors) record.errors.push('adapter-left-processes');
    const exit = io.state.exited;
    if (!exit) record.errors.push('adapter-did-not-exit');
    else if (exit.code !== 0 || exit.signal) record.errors.push(`exit:${exit.signal ?? exit.code ?? exit.error}`);
    // The app's own output (its last RUN_DEFAULTS.tail characters) is kept as a digest; the text
    // itself only when the run is unusable, to debug it.
    const output = text => ({ tailChars: text.length, tailSha256: createHash('sha256').update(text).digest('hex'), ...(record.errors.length || io.state.exited?.code ? { tail: text } : {}) });
    record.process = { exit: io.state.exited, stdout: output(io.state.stdout), stderr: output(io.state.stderr) };
    record.endedAt = new Date().toISOString();
  }
}
