// Runs every available built-in target's assessment and the test suite with outbound network denied
// except loopback, and logs every connection attempt.
//   node integrations/data-handling/zero-egress.mjs --out /abs/new/dir [--skip-suite]
// macOS: sandbox-exec with a profile that denies network-outbound except to localhost; kernel denials
// (any process, Python included) are collected with `log stream`. The deny rule carries a tag unique to
// the run, and only denials with that tag count: other sandboxes on the machine report their own. Linux: unshare with a new user and
// network namespace whose only interface is loopback (not run here).
// Node processes also load net-log.mjs (NODE_OPTIONS=--import), which logs every connect, DNS lookup
// and UDP send, loopback included. A test that starts Node with a cleared environment is still
// sandboxed, but only the kernel log sees it.
// A denied connection to the system resolver socket is a name lookup whose name the kernel log does not show;
// it is reported separately and does not count as a non-loopback connection.
// Writes ZERO-EGRESS.json in --out. Exit 0 when no non-loopback connection was attempted, 1 otherwise, 2 on setup errors.
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, createWriteStream } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const NET_LOG = pathToFileURL(fileURLToPath(new URL('./net-log.mjs', import.meta.url))).href;
export const profile = tag => `(version 1)\n(allow default)\n(deny network-outbound (with message "${tag}"))\n(allow network-outbound (remote ip "localhost:*"))\n`;
export const SUITE = ['test/*.test.mjs', 'integrations/*/*.test.mjs', 'design/dashboard/adapter.test.mjs'];
export const isLoopback = host => typeof host === 'string' && (host === 'localhost' || host === '::1' || /^127\./.test(host) || /^::ffff:127\./.test(host));
// A logged attempt that left the machine's loopback: a TCP or UDP peer, or a DNS name other than localhost.
export const nonLoopback = entry => ['connect', 'udp', 'dns'].includes(entry.kind) && !isLoopback(entry.host);
const RESOLVER = /\/var\/run\/mDNSResponder/;

function usage(message) { console.error(message); process.exit(2); }

async function main(argv) {
  const opt = name => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  const out = opt('--out');
  if (!out || !isAbsolute(out)) usage('Usage: zero-egress.mjs --out /absolute/new/directory [--skip-suite]');
  if (existsSync(out) && readdirSync(out).length) usage('--out must be a new or empty directory.');
  mkdirSync(join(out, 'evidence'), { recursive: true, mode: 0o700 });
  const nodeLog = join(out, 'node-connections.jsonl'), kernelLog = join(out, 'kernel-sandbox.log');
  writeFileSync(nodeLog, '', { mode: 0o600 });
  const node = process.execPath;
  const env = { HOME: process.env.HOME, PATH: '/usr/bin:/bin', SCOPEHAVEN_NODE: node, SCOPEHAVEN_EGRESS_LOG: nodeLog, NODE_OPTIONS: `--import=${NET_LOG}` };

  let wrap, platform, collector = null, sbpl = null;
  const tag = `scopehaven-zero-egress-${randomBytes(6).toString('hex')}`;
  if (process.platform === 'darwin') {
    if (!existsSync('/usr/bin/sandbox-exec')) usage('sandbox-exec is not available.');
    const file = join(out, 'deny-network.sb'); sbpl = profile(tag); writeFileSync(file, sbpl, { mode: 0o600 });
    wrap = argv0 => ['/usr/bin/sandbox-exec', ['-f', file, ...argv0]];
    platform = 'darwin sandbox-exec';
    collector = spawn('/usr/bin/log', ['stream', '--style', 'ndjson', '--predicate', 'sender == "Sandbox" AND eventMessage CONTAINS "network-outbound"'], { stdio: ['ignore', 'pipe', 'ignore'] });
    const chunks = []; collector.stdout.on('data', chunk => chunks.push(chunk)); collector.chunks = chunks;
    await new Promise(resolve => setTimeout(resolve, 1500));
  } else if (process.platform === 'linux') {
    if (spawnSync('unshare', ['--version']).status !== 0) usage('unshare is not available.');
    wrap = argv0 => ['unshare', ['--user', '--map-root-user', '--net', 'sh', '-c', 'ip link set lo up 2>/dev/null || true; exec "$0" "$@"', ...argv0]];
    platform = 'linux unshare --net (loopback only)';
  } else usage(`Unsupported platform ${process.platform}.`);

  // Each command's full output goes to logs/<n>.txt in --out; the summary keeps its exit code and log name.
  mkdirSync(join(out, 'logs'), { mode: 0o700 });
  let n = 0;
  const run = (label, argv0) => new Promise(resolve => {
    const [cmd, args] = wrap(argv0), log = `logs/${String(++n).padStart(2, '0')}.txt`;
    const sink = createWriteStream(join(out, log), { mode: 0o600 });
    const child = spawn(cmd, args, { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.pipe(sink, { end: false }); child.stderr.pipe(sink, { end: false });
    child.on('close', code => { sink.end(); console.log(`${label}: exit ${code}`); resolve({ label, exit: code, log }); });
  });

  const commands = [];
  const list = spawnSync(join(ROOT, 'scopehaven'), ['assess', '--list'], { cwd: ROOT, env: { HOME: process.env.HOME, PATH: '/usr/bin:/bin', SCOPEHAVEN_NODE: node }, encoding: 'utf8' });
  let targets = [];
  try { targets = JSON.parse(list.stdout).targets.filter(t => t.available).map(t => t.id); } catch { usage('Could not read ./scopehaven assess --list.'); }
  for (const id of targets) commands.push(await run(`assess ${id}`, [join(ROOT, 'scopehaven'), 'assess', '--target', id, '--out', join(out, 'evidence')]));
  if (!argv.includes('--skip-suite')) commands.push(await run('test suite', [node, '--test', '--test-concurrency=1', '--test-timeout=180000', ...SUITE]));

  let kernel = [], resolver = [], other = 0;
  if (collector) {
    await new Promise(resolve => setTimeout(resolve, 1500)); collector.kill();
    const messages = Buffer.concat(collector.chunks).toString('utf8').split('\n').map(line => { try { return JSON.parse(line).eventMessage ?? ''; } catch { return ''; } });
    const denials = messages.filter(message => /deny\(\d+\) network/.test(message));
    // Only this run's tagged denials are kept; other processes' denials are counted, not written.
    const ours = denials.filter(message => message.includes(tag)).map(message => message.split('\n')[0]);
    other = denials.length - ours.length;
    writeFileSync(kernelLog, ours.map(line => `${line}\n`).join(''), { mode: 0o600 });
    resolver = ours.filter(line => RESOLVER.test(line)); kernel = ours.filter(line => !RESOLVER.test(line));
  }
  const entries = readFileSync(nodeLog, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line));
  const outside = entries.filter(nonLoopback);
  const summary = { schema: 'scopehaven-zero-egress/1', platform, profile: sbpl, tag: sbpl ? tag : null, targets, commands,
    nodeLog: { entries: entries.length, byKind: Object.fromEntries(['connect', 'unix', 'dns', 'udp'].map(kind => [kind, entries.filter(e => e.kind === kind).length])), nonLoopback: outside.length, nonLoopbackSample: outside.slice(0, 50) },
    kernelDenials: { count: kernel.length, sample: kernel.slice(0, 50) },
    resolverSocketDenials: { count: resolver.length, sample: resolver.slice(0, 20), note: 'Name lookups denied at the system resolver socket; the kernel log does not show the name.' },
    otherSandboxDenials: { count: other, note: 'Network denials without this run\'s tag, from other sandboxes on the machine. Not counted.' },
    verdict: outside.length === 0 && kernel.length === 0 ? 'no-non-loopback-connections' : 'non-loopback-connections-seen',
    limits: ['Node processes started with a cleared environment are sandboxed but logged only through kernel denials.', 'Allowed loopback connections from non-Node processes are not logged.', 'A run covers the commands listed here on this machine and build, not every code path.'] };
  writeFileSync(join(out, 'ZERO-EGRESS.json'), `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600 });
  console.log(`${summary.verdict}: ${entries.length} logged attempts (${outside.length} non-loopback), ${kernel.length} kernel network denials, ${resolver.length} resolver-socket denials. Wrote ${join(out, 'ZERO-EGRESS.json')}`);
  return outside.length || kernel.length ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
