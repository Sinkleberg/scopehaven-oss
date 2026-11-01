// Coverage report from the command line:
//   node integrations/coverage-report/cli.mjs --inventory inventory.json --contract contract.json --targets targets.json
//        [--target ID] [--suite exported-suite.json] [--run stored-run.json] [--runs runs.json] [--json]
// --suite reconciles against an exported suite (GET /api/suite/export.json) of this exact profile version; without it the
//   profile's checks are the suite.
// --run prints what one stored HTTP run of this target found, from its own grading, beside the not-judgeable count; the
//   run must pass the shared HTTP run validator.
// --runs lists stored runs (full records, or the summaries GET /api/history serves) to report where they stop comparing.
// Exit codes: 0 every suite check is drafted once or declared not applicable and every profile check is in the suite;
// 1 a check is outside the inventory, missing from the profile, missing from the suite or listed twice; 2 a configuration error.
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { validateTargetFile, contractDigest } from '../../src/contracts.mjs';
import { coverageReport, coverageLines, runComparability, runFindings } from './coverage.mjs';

const readJson = (path, name) => { try { return JSON.parse(readFileSync(path, 'utf8')); } catch { throw new Error(`${name} is not a readable JSON file.`); } };

export function main(argv = process.argv.slice(2), { log = s => process.stdout.write(`${s}\n`) } = {}) {
  const opt = name => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  let report, run = null, comparability = null;
  try {
    if (!opt('--inventory') || !opt('--contract') || !opt('--targets')) throw new Error('Usage: cli.mjs --inventory inventory.json --contract contract.json --targets targets.json [--target ID] [--suite suite.json] [--run run.json] [--runs runs.json] [--json]');
    const targets = readJson(opt('--targets'), '--targets');
    validateTargetFile(targets);
    const target = opt('--target') ? targets.targets.find(t => t.id === opt('--target')) : targets.targets.length === 1 ? targets.targets[0] : null;
    if (!target) throw new Error(opt('--target') ? `No target ${opt('--target')} in --targets.` : 'Name the target with --target: the file has several.');
    const suite = opt('--suite') ? readJson(opt('--suite'), '--suite') : null;
    if (suite && (!Array.isArray(suite.checks) || suite.targetId !== target.id)) throw new Error('--suite must be the exported suite of this target.');
    if (suite && suite.hash !== contractDigest(target)) throw new Error('--suite was exported from another version of this profile (its hash is not this profile\'s digest); export it again.');
    const suiteIds = suite ? suite.checks.map(c => c.id) : null;
    report = coverageReport({ inventory: readJson(opt('--inventory'), '--inventory'), contract: readJson(opt('--contract'), '--contract'), target, suiteCheckIds: suiteIds });
    if (opt('--run')) run = runFindings(readJson(opt('--run'), '--run'), target, suiteIds ?? undefined);
    if (opt('--runs')) { const runs = readJson(opt('--runs'), '--runs'); comparability = runComparability(Array.isArray(runs) ? runs : runs?.runs, { target }); }
  } catch (error) { log(`Configuration error: ${error.message}`); return 2; }
  if (argv.includes('--json')) log(JSON.stringify({ ...report, ...(run ? { run } : {}), ...(comparability ? { comparability } : {}) }, null, 2));
  else for (const line of coverageLines(report, { run, comparability })) log(line);
  return report.reconciliation.equal ? 0 : 1;
}

// Run directly: Node loads the main module from its real path, so compare real paths (a symlinked or spaced path still runs it).
const invokedDirectly = () => { try { return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url); } catch { return false; } };
if (process.argv[1] && invokedDirectly()) process.exitCode = main();
