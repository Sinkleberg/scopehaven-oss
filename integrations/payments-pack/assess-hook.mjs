// The payments pack inside `assess` and the regression gate (the Stripe connector): one command checks an app's HTTP
// profile and its money movements, under the one authorization record, and the gate compares both halves.
//
//   ./scopehaven assess --config targets.json --target ID --authorization record.json --payments-pack pack.json [--out DIR]
//   ./scopehaven gate ... --payments-pack pack.json [--payments-baseline DIR/payments/<run>.json]
//
// The two src/ and gate lines that call this module are the to land (integrations/connectors/README.md, "For
// the maintainer"); everything else is here, so the hook is a call and an exit-status rule, nothing more.
//
// assessPayments: the pack must be the target's own (the same id, applicationId and origin), so the record that authorized
// the HTTP run covers it as written; the pack's own authorization rules (pack.mjs authorizePack, refused before the double
// starts) apply unchanged. Its run is written beside the HTTP evidence (DIR/payments/<run-id>.json and .html) and summarized
// with the pack's exit rule: 1 when a row fails or is not decided.
// gatePayments: the candidate run's rows decide the exit (as `payments run`), and with a baseline the comparison labels them
// (comparePaymentsRuns: verified repair only when both runs used the same pack, neither was edited and every control holds).
// A comparison never turns a passing run red. combineExit: the worse of two exits, an error (2) above a failing run (1).
import { basename, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, realpath } from 'node:fs/promises';
import { runPaymentsPack, comparePaymentsRuns, validatePackConfig, authorizePack } from './pack.mjs';
import { writeRun, summarize, readPaymentsJson } from './output.mjs';
import { readAuthorizationFile } from '../roe/file.mjs';

export const PAYMENTS_ASSESS_SCHEMA = 'scopehaven-payments-in-assess/1';
export class PaymentsHookError extends Error {
  constructor(code, message) { super(message); this.name = 'PaymentsHookError'; this.code = code; }
}
const runExit = run => (run.counts.fail || run.counts.inconclusive ? 1 : 0);
export const combineExit = (...codes) => (codes.includes(2) ? 2 : codes.some(code => code === 1) ? 1 : 0);
const stripComparison = ({ comparison: _, ...run }) => run;

// The pack belongs to the assessed target: the same id, application and origin.
export function samePackTarget(pack, target) {
  if (!target) return 'the payments pack runs beside a target from --config';
  for (const key of ['id', 'applicationId', 'origin']) if (pack?.[key] !== target[key]) return `the pack's ${key} must be the target's (${key === 'origin' ? 'the same app' : `"${String(target[key]).slice(0, 80)}"`}), so the record that authorized the run covers it`;
  return null;
}

// Reads and checks the pack before the HTTP run sends anything: its shape, that it is the target's own, and that the record
// file the HTTP run is authorized under covers it now (pack.mjs authorizePack: its id, application, origin, every customer's
// principal, the window). A pack that would be refused never follows a saved run. Returns { pack, run(options) }; the run
// checks the record again, as runPaymentsPack always does.
export async function preparePayments({ packPath, target, authorizationFile, now = new Date() }) {
  const pack = await readPaymentsJson(resolve(packPath), 'The payments pack (--payments-pack)');
  validatePackConfig(pack);
  const problem = samePackTarget(pack, target);
  if (problem) throw new PaymentsHookError('payments-pack-target', problem);
  const record = authorizationFile ? await readAuthorizationFile(resolve(authorizationFile)) : null;
  authorizePack(pack, record, now);
  return { pack, run: options => runPrepared(pack, record, options) };
}

export async function assessPayments({ packPath, target, authorizationFile, now = new Date(), ...options }) {
  return (await preparePayments({ packPath, target, authorizationFile, now })).run({ now, ...options });
}

// directory: the HTTP run's evidence folder; the payments run goes in its "payments" folder, or in paymentsDirectory when the
// caller names one (the gate keeps its own folder to the gate's entries, so its payments runs go beside it).
async function runPrepared(pack, record, { directory, paymentsDirectory = join(directory, 'payments'), env = process.env, now = new Date(), build = null, createDouble }) {
  const run = await runPaymentsPack(pack, { record, env, now, build, ...(createDouble ? { createDouble } : {}) });
  const files = await writeRun(paymentsDirectory, run, null);
  return { schema: PAYMENTS_ASSESS_SCHEMA, summary: summarize(run, files, null), exitCode: runExit(run), run };
}

export async function gatePayments({ packPath, target, authorizationFile, paymentsDirectory, baselinePath, env = process.env, now = new Date(), build = null, createDouble, prepared }) {
  const ready = prepared ?? await preparePayments({ packPath, target, authorizationFile, now });
  const assessed = await ready.run({ paymentsDirectory, env, now, build, createDouble });
  if (!baselinePath) return { ...assessed, comparison: null };
  const baseline = await readPaymentsJson(resolve(baselinePath), 'The payments baseline (--payments-baseline)');
  const comparison = comparePaymentsRuns(stripComparison(baseline), assessed.run);
  return { ...assessed, comparison: { verdict: comparison.verdict, reason: comparison.reason, compatible: comparison.compatible, rows: comparison.rows } };
}

// The report-only window (integrations/regression-gate/report-only.mjs applyReportOnly) relaxes only an assessment-failed
// exit, and only while it applies; the combined exit is relaxed by the same rule.
export const reportOnlyExit = (reportOnly, exitCode) => (reportOnly?.state === 'applied' && exitCode === 1 ? 0 : exitCode);

// The gate's payments folder, held to the gate's own folder rules (gate.mjs prepareOutput): an existing parent, resolved (no
// recursive creation, no symlinked parent), outside the project's data folder, created 0700 if missing, then a real directory
// of this user with mode 0700 holding only payments runs and gate-<id>.json files. Checked before the gate sends anything.
export async function preparePaymentsDirectory(path) {
  const requested = resolve(path);
  let parent;
  try { parent = await realpath(resolve(requested, '..')); } catch { throw new PaymentsHookError('invalid-options', 'the gate folder\'s parent must exist'); }
  const directory = join(parent, basename(requested));
  const project = await realpath(fileURLToPath(new URL('../../', import.meta.url))), fromData = relative(join(project, 'data'), directory);
  if (directory === project || !(fromData === '..' || fromData.startsWith(`..${sep}`) || isAbsolute(fromData))) throw new PaymentsHookError('invalid-options', 'the gate folder\'s payments half would land in the project\'s data folder; give --out outside it');
  try { await mkdir(directory, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o7777) !== 0o700) throw new PaymentsHookError('invalid-options', `${basename(directory)} must be a private (0700) folder of this user, not a link`);
  // Like the gate's folder, it carries a marker written when it was empty, and holds only payments runs (pay-<time>-<hex>) and
  // the gate's payments halves (gate-<run id>).
  const entries = await readdir(directory);
  if (!entries.includes(PAYMENTS_MARKER)) {
    if (entries.length) throw new PaymentsHookError('invalid-options', `${basename(directory)} is not empty and is not a ScopeHaven payments folder; give --out a new folder`);
    const handle = await open(join(directory, PAYMENTS_MARKER), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await handle.writeFile(PAYMENTS_MARKER_TEXT); } finally { await handle.close(); }
  }
  const handle = await open(join(directory, PAYMENTS_MARKER), constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const marker = await handle.stat();
    if (!marker.isFile() || marker.uid !== process.getuid() || (marker.mode & 0o7777) !== 0o600 || await handle.readFile('utf8') !== PAYMENTS_MARKER_TEXT) throw new PaymentsHookError('invalid-options', `${basename(directory)}'s marker is not ScopeHaven's`);
  } finally { await handle.close(); }
  const stray = entries.find(name => name !== PAYMENTS_MARKER && !/^(pay-\d{14}-[0-9a-f]{8}\.(json|html)|gate-[A-Za-z0-9-]{1,80}\.json)$/.test(name));
  if (stray) throw new PaymentsHookError('invalid-options', `${basename(directory)} holds an entry that is not a payments run ("${stray.slice(0, 40)}")`);
  return directory;
}
const PAYMENTS_MARKER = '.scopehaven-gate-payments', PAYMENTS_MARKER_TEXT = 'scopehaven-gate-payments/1\n';

// Writes the gate's payments half beside its folder (<out>-payments/gate-<run id>.json, 0600, never replaced), since the
// gate's own summary file is written before the pack runs. The folder was checked by preparePaymentsDirectory.
async function writeGatePayments(directory, runId, payments) {
  if (typeof runId !== 'string' || !/^[A-Za-z0-9-]{1,80}$/.test(runId)) return null;
  const path = join(directory, `gate-${runId}.json`);
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(`${JSON.stringify(payments, null, 2)}\n`); } finally { await handle.close(); }
  return path;
}

// The gate with the pack: the pack is read and checked first (shape, target, record), then the gate runs as it always does,
// then the pack's run and comparison join the summary under "payments", with the worse exit (and the report-only exit by the
// window's own rule). A gate that ended in a configuration or runtime error runs no pack. A saved refund result (--saved-refund)
// reads a stored run and sends nothing, so the pack is refused with it.
// now: a fixed time for tests; otherwise the clock is read when each half starts, so the payments half is authorized at the time
// it runs, after the gate (a window that ends while the gate runs refuses the pack).
export async function runGateWithPayments(argv, { runGate, parseArgs, env = process.env, now, clock = () => now ?? new Date(), createDouble, loadProfiles } = {}) {
  const rest = [], hook = {};
  for (let i = 0; i < argv.length; i++) {
    if (['--payments-pack', '--payments-baseline'].includes(argv[i])) {
      if (typeof argv[i + 1] !== 'string' || argv[i + 1].startsWith('--') || Object.hasOwn(hook, argv[i])) throw new PaymentsHookError('invalid-options', `${argv[i]} needs one value`);
      hook[argv[i]] = argv[++i]; continue;
    }
    rest.push(argv[i]);
  }
  if (hook['--payments-baseline'] && !hook['--payments-pack']) throw new PaymentsHookError('invalid-options', '--payments-baseline needs --payments-pack');
  const options = parseArgs(rest);
  if (!hook['--payments-pack']) return runGate(options, { env });
  if (options.savedRefund !== undefined || typeof options.outputDirectory !== 'string') throw new PaymentsHookError('invalid-options', '--payments-pack runs beside a gate run with --out; a saved refund result (--saved-refund) sends nothing');
  // The gate's folder holds only the gate's own entries (gate.mjs), so the payments runs go in "<out>-payments" beside it: from
  // the resolved folder (a trailing "/" would put it inside), under the gate's own folder rules (preparePaymentsDirectory).
  const paymentsDirectory = await preparePaymentsDirectory(`${resolve(options.outputDirectory)}-payments`);
  const load = loadProfiles ?? (await import('../../src/registry.mjs')).loadProfiles;
  const target = (await load(options.configFile)).find(p => p.id === options.targetId);
  const prepared = await preparePayments({ packPath: hook['--payments-pack'], target, authorizationFile: options.authorizationFile, now: clock() });
  const summary = await runGate(options, { env });
  if (summary.exitCode === 2) return summary;
  // The gate has sent its requests by now, so a payments half that throws keeps the gate's summary and reports itself.
  let shown, record = null;
  try {
    const { run: _, ...rest } = await gatePayments({ prepared, paymentsDirectory, baselinePath: hook['--payments-baseline'], env, now: clock(), createDouble });
    shown = rest;
    record = await writeGatePayments(paymentsDirectory, summary.current?.runId, { gateRun: summary.current?.runId ?? null, ...shown });
  } catch (error) {
    shown = { exitCode: 2, error: String(error?.code ?? error?.name ?? 'error').slice(0, 80) };
  }
  const exitCode = combineExit(summary.exitCode, shown.exitCode);
  const outcome = exitCode === 0 ? 'clean' : exitCode === 1 ? 'assessment-failed' : 'config-or-runtime-error';
  const reasons = [...(summary.reasons ?? []), ...(shown.error ? ['payments-error'] : shown.exitCode ? ['payments-not-clean'] : [])];
  const noFile = !record && !shown.error ? { summaryFileWhy: 'the gate run has no plain id (letters, digits and dashes), so no payments file was written beside it' } : {};
  return { ...summary, outcome, reasons, payments: { ...shown, ...(record ? { summaryFile: record } : noFile) }, exitCode,
    ...(summary.reportOnly ? { reportOnly: { ...summary.reportOnly, exitCode: reportOnlyExit(summary.reportOnly, exitCode) } } : {}) };
}
