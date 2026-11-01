// Run a boundary sweep from an app spec (integrations/sweep/README.md):
//   node integrations/sweep/cli.mjs --spec /abs/spec.json --out /abs/dir [--concurrency N]
// The spec's "world" command starts one fresh copy of the application per run (launcher.mjs). The sweep runs the
// baseline turn, plans one hold, condition, release execution per observed upstream call, runs each, and writes
// report.json beside every saved run.
// Exit codes: 0 NO_FLAG, 1 FLAG, 3 ABSTAIN, 2 configuration error or a sweep that could not finish.
import { join, resolve } from 'node:path';
import { readJsonArg } from '../cli.mjs';
import { validateSweepSpec } from './spec.mjs';
import { commandWorld } from './launcher.mjs';
import { runSweep } from './runner.mjs';

export const SWEEP_EXIT = Object.freeze({ NO_FLAG: 0, FLAG: 1, ABSTAIN: 3 });
export const MAX_CONCURRENCY = 8;

export async function main(argv = process.argv.slice(2), { log = s => process.stdout.write(`${s}\n`) } = {}) {
  const opt = name => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  let spec, concurrency;
  try {
    if (!opt('--spec') || !opt('--out')) throw new Error('Usage: cli.mjs --spec /abs/spec.json --out /abs/dir [--concurrency N]');
    spec = validateSweepSpec(readJsonArg(opt('--spec'), '--spec'));
    if (!spec.world) throw new Error('The CLI needs "world" in the spec: the command that starts one fresh copy of the application.');
    concurrency = Number(opt('--concurrency') ?? 1);
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > MAX_CONCURRENCY) throw new Error(`--concurrency must be 1 to ${MAX_CONCURRENCY}.`);
  } catch (error) { log(`Configuration error: ${error.message}`); return 2; }
  const outDir = resolve(opt('--out'));
  let report;
  // A sweep that could not finish decides nothing: exit 2, never a verdict's code.
  try { report = await runSweep({ spec, startWorld: commandWorld(spec.world), outDir, concurrency, log }); }
  catch (error) { log(`Sweep error: ${error.message}`); return 2; }
  const counts = { PASS: 0, FAIL: 0, INCONCLUSIVE: 0 };
  for (const o of report.outcomes) counts[o.result]++;
  log(`Sweep ${spec.id}: ${report.verdict}; ${report.plan.executions.length} boundaries from ${report.baseline.calls.length} observed calls; ${counts.PASS} pass, ${counts.FAIL} fail, ${counts.INCONCLUSIVE} inconclusive`);
  log(`Saved ${join(outDir, 'report.json')}`);
  return SWEEP_EXIT[report.verdict];
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) process.exitCode = await main();
