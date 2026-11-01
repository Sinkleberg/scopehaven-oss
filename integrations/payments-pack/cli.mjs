// ./scopehaven payments run --config PACK.json --authorization RECORD.json --out DIR [--baseline RUN.json] [--build LABEL]
// ./scopehaven payments demo --out DIR
// ./scopehaven payments export --run RUN.json --format json|html|sarif --out ABSOLUTE_NEW_FILE [--baseline RUN.json] [--unsigned | --signing-key-dir ABSOLUTE_DIR]
//
// run: checks one app against a payments pack, judged from the payments double's ledger. The app must already be
// running on the pack's origin with its Stripe client pointed at http://127.0.0.1:<provider.port><routePrefix>
// and test tokens in the environment variables the pack names. It refuses (exit 2) before the double starts or
// any request is sent unless the authorization record covers the pack, and with exit 2 and nothing written when the
// record's window ends during the run (authorization-window-ended). Writes <run-id>.json and <run-id>.html
// into DIR (created if missing); with --baseline, the report and the summary carry the before/after comparison.
// Exit 0 when every row passes, 1 otherwise, 2 on refusal. The comparison labels rows; it never turns a passing run red, so the
// same command can stay in CI as a gate after the repair.
//
// demo: runs the owned refund agent demo end to end (vulnerable, then repaired against it) into DIR.
//
// export: exports one saved run (RUN.json from `payments run`) as json (the run record), html (its report) or sarif, signed by
// default exactly as `scopehaven export` signs: a DSSE envelope OUT.dsse.json beside the file with the local Ed25519 key
// (~/.config/scopehaven/signing, or --signing-key-dir ABSOLUTE_DIR), unless --unsigned. --out is an absolute new file in a
// directory of mode 0700 that is yours. With --baseline RUN.json, json is the before/after comparison and html the report with it,
// both recomputed from the two runs (a comparison stored in RUN.json is never exported). Exit 0 when written, 2 on refusal.
import { resolve } from 'node:path';
import { readAuthorizationFile } from '../roe/file.mjs';
import { runPaymentsPack, comparePaymentsRuns } from './pack.mjs';
// A pack or a saved run is read by readPaymentsJson: a regular file, never through a symlink or a FIFO, at most 4 MiB.
import { writeRun, summarize, readPaymentsJson as readJsonFile, exportPaymentsRun, PAYMENTS_RUN_REFUSED } from './output.mjs';
import { SIGNING_KEY_UNSAFE, SIGNING_FAILED } from '../../src/export-cli.mjs';
import { assertRuntime } from '../../src/runtime.mjs';

const USAGE = 'Usage: ./scopehaven payments run --config PACK.json --authorization RECORD.json --out DIR [--baseline RUN.json] [--build LABEL] | demo --out DIR'
  + ' | export --run RUN.json --format json|html|sarif --out ABSOLUTE_NEW_FILE [--baseline RUN.json, json or html] [--unsigned | --signing-key-dir ABSOLUTE_DIR]';
const FLAGS = { run: ['--config', '--authorization', '--out', '--baseline', '--build'], demo: ['--out'], export: ['--run', '--format', '--out', '--baseline', '--signing-key-dir'] };
// Flags that take no value: export's --unsigned only.
const SWITCHES = { export: ['--unsigned'] };

async function main(argv) {
  assertRuntime();
  const [command, ...rest] = argv;
  if (!Object.hasOwn(FLAGS, command)) throw Object.assign(new Error(USAGE), { exit: 2 });
  const options = {};
  for (let i = 0; i < rest.length; i++) {
    if (SWITCHES[command]?.includes(rest[i]) && !Object.hasOwn(options, rest[i])) { options[rest[i]] = true; continue; }
    if (!FLAGS[command].includes(rest[i]) || rest[i + 1] === undefined || rest[i + 1].startsWith('--') || Object.hasOwn(options, rest[i])) throw Object.assign(new Error(`Unsupported, repeated or incomplete option. ${USAGE}`), { exit: 2 });
    options[rest[i]] = rest[++i];
  }
  if (!options['--out']) throw Object.assign(new Error(`--out is required. ${USAGE}`), { exit: 2 });
  if (command === 'export') return exportCommand(options);
  if (command === 'demo') {
    const { runDemo } = await import('./demo/demo.mjs');
    const result = await runDemo(resolve(options['--out']));
    console.log(JSON.stringify(result, null, 2));
    return result.comparison.verdict === 'verified repair' ? 0 : 1;
  }
  if (!options['--config']) throw Object.assign(new Error(`--config is required. ${USAGE}`), { exit: 2 });
  const config = await readJsonFile(resolve(options['--config']), 'The pack (--config)');
  const record = options['--authorization'] ? await readAuthorizationFile(resolve(options['--authorization'])) : null;
  const baseline = options['--baseline'] ? await readJsonFile(resolve(options['--baseline']), 'The baseline run (--baseline)') : null;
  const run = await runPaymentsPack(config, { record, env: process.env, now: new Date(), build: options['--build'] ?? null });
  const comparison = baseline ? comparePaymentsRuns(stripComparison(baseline), run) : null;
  const files = await writeRun(resolve(options['--out']), run, comparison);
  console.log(JSON.stringify(summarize(run, files, comparison), null, 2));
  return run.counts.fail || run.counts.inconclusive ? 1 : 0;
}
// A saved run may carry the comparison it was written with; the run itself is everything else.
const stripComparison = ({ comparison: _, ...run }) => run;

async function exportCommand(options) {
  if (!options['--run'] || !options['--format'] || (options['--unsigned'] && options['--signing-key-dir'])) throw Object.assign(new Error(`export needs --run, --format and --out, and takes --unsigned or --signing-key-dir, not both. ${USAGE}`), { exit: 2 });
  const run = await readJsonFile(resolve(options['--run']), 'The payments run (--run)');
  const baseline = options['--baseline'] ? await readJsonFile(resolve(options['--baseline']), 'The baseline run (--baseline)') : undefined;
  let result;
  try {
    result = await exportPaymentsRun({ run, baseline, format: options['--format'], outputFile: options['--out'], signingKeyDir: options['--signing-key-dir'], sign: !options['--unsigned'] });
  } catch (error) {
    // A key or signing problem is named by its code, as `scopehaven export` names it; no message carries key material.
    if ([SIGNING_KEY_UNSAFE, SIGNING_FAILED].includes(error?.code)) throw Object.assign(new Error(`export failed (${error.message}). The export file was not left behind. The signing key lives in ~/.config/scopehaven/signing (or --signing-key-dir ABSOLUTE_DIR); fix its mode or owner yourself, or pass --unsigned.`), { exit: 2 });
    if (error?.code === PAYMENTS_RUN_REFUSED) throw Object.assign(new Error(`export refused (${error.message}). Nothing was written.`), { exit: 2 });
    const hint = /^Invalid export options\.$|^Export directory must be private|EEXIST/.test(String(error?.message)) ? ' --out is an absolute new file whose directory has mode 0700 and is yours; --format is json, html or sarif (json or html with --baseline).' : '';
    throw Object.assign(new Error(`export failed (${error?.message ?? error}). No export file was left behind.${hint}`), { exit: 2 });
  }
  console.log(JSON.stringify(result, null, 2));
  return 0;
}

main(process.argv.slice(2)).then(code => { process.exitCode = code; }, error => {
  const code = error?.name === 'AuthorizationError' ? `authorization refused (${error.code}): ` : '';
  console.error(`Scopehaven payments could not run: ${code}${error?.message ?? error}`);
  if (!error?.exit && !code) console.error(USAGE);
  process.exitCode = 2;
});
