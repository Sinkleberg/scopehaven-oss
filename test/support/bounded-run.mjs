// Runs `node --test` with this script's arguments under a wall-clock bound, so a test file that never exits fails the run loudly
// instead of holding it open (a full suite once held the heavy-job lock for 12.5 h). ./scopehaven test, npm test and the CI retry
// (.github/scripts/run-suite.sh) all run through it. Plain `node --test` waits for every test a file registers, however late.
//
// The bound is SCOPEHAVEN_TEST_BOUND_SECONDS (default 2700, 45 minutes; the slowest full suite observed took about 9). Its timer is
// armed before anything else, and nothing on its path waits for another process: at the bound the runner's process group, and every
// process remembered as descended from it (below), is sent SIGTERM at once and SIGKILL 5 s later, the test files still running are named,
// and the exit status is 124. Otherwise the runner's own status is returned. An error inside the runner itself never leaves the run
// going unbounded: the run is killed, and the status is 124 if the bound had passed, else 1.
//
// Descendants are remembered from the process table, read every 250 ms with kernel fields only (pid, parent, start time; reading a
// process's arguments pages in its memory, which stalls on a machine under memory pressure). That is how a detached process (its own
// process group, which a group kill does not reach) is found. Two limits follow. A process that starts and loses its parent between
// two reads (within about 250 ms) is never on the record. And once no table has been read for 10 s, only the group is stopped:
// every read is asynchronous and killed at 2 s, a read that fails (ps cannot be spawned, fails or runs out of time) leaves the last
// good one in force, but a remembered process is signalled only from a table read in the last 10 s, so a stale pid (one an
// unrelated process may have been given since) is not signalled. A test file is named from its process's arguments, read once when
// that process first appears; at the bound, files named from an older table say how old it is.
//
// After the run, anything on the record still running is stopped and named in a notice. The run's status is unchanged (the processes
// are gone, so they hold nothing): the notice goes to stderr, or is appended to the file named by SCOPEHAVEN_TEST_NOTICES when that
// is set (run-suite.sh sets it, keeping the notice out of the TAP log it parses and raising it as a warning). SIGINT, SIGTERM and
// SIGHUP are passed on to the run.
import { spawn } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { constants } from 'node:os';

const DEFAULT_BOUND_SECONDS = 2700, READ_MS = 250, GRACE_MS = 5000, TIMED_OUT = 124, PS_LIMIT_MS = 2000, RECENT_MS = 10000;
const raw = process.env.SCOPEHAVEN_TEST_BOUND_SECONDS;
const bound = raw === undefined || raw === '' ? DEFAULT_BOUND_SECONDS : Number(raw);
// setTimeout holds at most 2147483647 ms; a longer bound would fire at once.
if (!Number.isFinite(bound) || bound <= 0 || bound * 1000 > 2147483647) {
  process.stderr.write(`bounded-run: SCOPEHAVEN_TEST_BOUND_SECONDS must be a positive number of seconds, at most 2147483; got ${JSON.stringify(raw)}.\n`);
  process.exit(2);
}
const runner = spawn(process.execPath, ['--test', ...process.argv.slice(2)], { stdio: 'inherit', detached: true });
let timedOut = false, interrupted = null;
const timer = setTimeout(() => onBound(), bound * 1000);

const say = text => process.stderr.write(`\nbounded-run: ${text}\n`);
const notice = text => {
  const file = process.env.SCOPEHAVEN_TEST_NOTICES;
  if (file) { try { appendFileSync(file, `bounded-run: ${text}\n`); return; } catch {} }
  say(text);
};
const FILE_ARGS = process.argv.slice(2).filter(arg => arg.endsWith('.test.mjs'));

// ps, asynchronous and killed with SIGKILL at its limit: its output lines, or null when it failed or ran out of time. A spawn that
// fails at once (EMFILE, ENFILE, EAGAIN, ENOMEM) either throws or returns a child with no stdout and an 'error' to come; both are a
// failed read, never an exception, so the reads and the bound go on.
const readers = new Set();
const ps = args => new Promise(resolve => {
  let out = '', done = false, child = null, limit = null;
  const finish = lines => { if (!done) { done = true; clearTimeout(limit); readers.delete(child); resolve(lines); } };
  try { child = spawn('ps', args, { stdio: ['ignore', 'pipe', 'ignore'] }); } catch { finish(null); return; }
  child.on('error', () => finish(null));
  if (!child.stdout) { finish(null); return; }
  limit = setTimeout(() => { child.kill('SIGKILL'); finish(null); }, PS_LIMIT_MS);
  readers.add(child);
  child.stdout.on('data', bytes => { out += bytes; });
  child.on('close', code => finish(code === 0 ? out.split('\n') : null));
});
// pid, parent and start time of every process (a pid counts as the same process only with the same start time), or null.
const table = async () => {
  const lines = await ps(['-A', '-o', 'pid=,ppid=,lstart=']);
  return lines && lines.map(line => /^\s*(\d+)\s+(\d+)\s+(\S.*\S)\s*$/.exec(line)).filter(Boolean)
    .map(m => ({ pid: Number(m[1]), ppid: Number(m[2]), start: m[3] }));
};
const commands = async pids => new Map(((pids.length ? await ps(['-o', 'pid=,command=', '-p', pids.join(',')]) : []) ?? [])
  .map(line => /^\s*(\d+)\s(.*)$/.exec(line)).filter(Boolean).map(m => [Number(m[1]), m[2]]));
// A file is named by the argument it was given as (a path may hold spaces, which a process's command line does not quote).
const fileIn = command => {
  const given = FILE_ARGS.filter(file => command.endsWith(file)).sort((a, b) => b.length - a.length);
  return given.length ? given[0] : command.match(/\S+\.test\.mjs/)?.[0] ?? null;
};

let last = [], lastAt = -Infinity;   // the last table that could be read, and when that read began
// The last table if it was read in the last 10 s, else none: signals go to remembered processes only from a recent table.
const recent = () => performance.now() - lastAt <= RECENT_MS ? last : [];
const seen = new Map();     // pid -> start time of every process seen descended from the runner
const fileOf = new Map();   // pid of each of the runner's children -> its test file (null while being read)
const remember = rows => {
  const children = new Map();
  for (const row of rows) children.set(row.ppid, [...(children.get(row.ppid) ?? []), row]);
  const queue = [runner.pid], fresh = [];
  while (queue.length) for (const row of children.get(queue.shift()) ?? []) {
    seen.set(row.pid, row.start);
    queue.push(row.pid);
    if (row.ppid === runner.pid && !fileOf.has(row.pid)) { fileOf.set(row.pid, null); fresh.push(row.pid); }
  }
  // A pid the read did not return (ps failed, or the process ended) is dropped, so a later read can try it again.
  if (fresh.length) commands(fresh).then(named => {
    for (const pid of fresh) { if (named.has(pid)) fileOf.set(pid, fileIn(named.get(pid))); else fileOf.delete(pid); }
  }).catch(() => { for (const pid of fresh) fileOf.delete(pid); });
};
const aliveIn = rows => { const now = new Map(rows.map(row => [row.pid, row.start])); return [...seen.keys()].filter(pid => now.get(pid) === seen.get(pid)); };
// The group, then each pid; returns the pids the signal reached.
const signal = (pids, name) => {
  try { process.kill(-runner.pid, name); } catch {}
  return pids.filter(pid => { try { process.kill(pid, name); return true; } catch { return false; } });
};
let reading = false;
const read = async () => {
  if (reading) return;
  reading = true;
  try {
    const at = performance.now(), rows = await table();
    if (rows) { last = rows; lastAt = at; remember(rows); }
  } catch {} finally { reading = false; }
};
const poll = setInterval(read, READ_MS);
read();

// SIGTERM now and SIGKILL after the grace period, each to the group and to the descendants alive in a recent table: no step waits
// for ps (the reads go on meanwhile, so the SIGKILL uses the newest table there is).
const stop = name => {
  signal(aliveIn(recent()), name);
  setTimeout(() => signal(aliveIn(recent()), 'SIGKILL'), GRACE_MS).unref();
};
function onBound() {
  timedOut = true;
  stop('SIGTERM');
  const running = last.filter(row => row.ppid === runner.pid).map(row => fileOf.get(row.pid) ?? null);
  const files = [...new Set(running.filter(Boolean))], unnamed = running.filter(file => !file).length;
  const which = files.length ? `${files.join(' ')}${unnamed ? ` and ${unnamed} not yet named` : ''}`
    : unnamed ? `${unnamed} not yet named` : last.length ? 'none found' : 'unknown (the process table could not be read)';
  const age = performance.now() - lastAt, asOf = last.length && age > RECENT_MS ? ` (as of a process table read ${Math.round(age / 1000)} s ago)` : '';
  say(`the run is still going after ${bound} s, so it is treated as a hang and killed (exit status ${TIMED_OUT}). Test files still running: ${which}${asOf}.`);
}
for (const name of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(name, () => { interrupted ??= name; stop(name); });
// A last resort: an error the runner did not expect must not leave the run (its own session) going with no bound.
for (const event of ['uncaughtException', 'unhandledRejection']) process.on(event, error => {
  say(`internal error, so the run is killed (exit status ${timedOut ? TIMED_OUT : 1}): ${error?.stack ?? error}`);
  signal(aliveIn(recent()), 'SIGKILL');
  process.exit(timedOut ? TIMED_OUT : 1);
});

const listed = async pids => {
  const named = await commands(pids);
  return pids.map(pid => { const command = named.get(pid) ?? '?'; return `${pid} ${command.length > 160 ? `${command.slice(0, 160)}...` : command}`; }).join('; ');
};
runner.on('exit', async (code, signalName) => {
  clearTimeout(timer);
  clearInterval(poll);
  const left = aliveIn((await table()) ?? recent()), report = left.length && !timedOut && !interrupted ? await listed(left) : '';
  const reached = signal(left, 'SIGKILL');
  if (report) notice(`stopped ${left.length} process(es) the run left running: ${report}.`);
  // The kill takes a moment to land; whatever is still there after it is named, so nothing outlives the run unseen.
  await new Promise(resolve => setTimeout(resolve, 300));
  const after = await table();
  const survivors = after ? aliveIn(after) : [];
  if (survivors.length) notice(`could not stop ${survivors.length} process(es): ${await listed(survivors)}.`);
  else if (!after && reached.length) notice(`sent SIGKILL to ${reached.length} process(es) the run left running, but could not read the process table to check them.`);
  for (const reader of readers) reader.kill('SIGKILL');
  process.exit(timedOut ? TIMED_OUT : interrupted ? 128 + constants.signals[interrupted] : code ?? 128 + (constants.signals[signalName] ?? 0));
});
