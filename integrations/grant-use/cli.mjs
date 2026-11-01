// Grant versus use from the command line:
//   node integrations/grant-use/cli.mjs --targets targets.json [--target ID] --runs runs.json
//        [--inventory inventory.json --contract contract.json] [--json]
//   node integrations/grant-use/cli.mjs --sequence seq.json --observers observers.json [--gate gate.json] --runs runs.json [--json]
// --runs is a JSON file holding one stored run or a list of them: HTTP runs of the target (each must pass the shared HTTP run
//   validator and carry this profile's digest), or sealed sequence runs (each bound to the sequence and its observer and gate
//   configuration by the sequence run validator).
// --inventory and --contract (the coverage report's inputs) add the operations the stated contract permits each actor.
// Prints the Markdown rendering, or with --json the report itself.
// Exit codes: 0 the report was produced (an inconclusive excess is a result, not an error); 2 a configuration error or a run
// the validators refuse. Anything else is a fault of this tool and is thrown, never reported as a configuration error.
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { validateTargetFile } from '../../src/contracts.mjs';
import { grantUseReport, sequenceGrantUseReport, GrantUseError } from './grant-use.mjs';
import { renderGrantUseMarkdown } from './render.mjs';

const readJson = (path, name) => { try { return JSON.parse(readFileSync(path, 'utf8')); } catch { throw new Error(`${name} is not a readable JSON file.`); } };
const USAGE = 'Usage: cli.mjs --targets targets.json [--target ID] --runs runs.json [--inventory inventory.json --contract contract.json] [--json]\n   or: cli.mjs --sequence seq.json --observers observers.json [--gate gate.json] --runs runs.json [--json]';

export function main(argv = process.argv.slice(2), { log = s => process.stdout.write(`${s}\n`) } = {}) {
  const opt = name => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  // Reading the files and the target manifest: every failure here is the caller's configuration.
  let build;
  try {
    if (!opt('--runs') || Boolean(opt('--targets')) === Boolean(opt('--sequence'))) throw new Error(USAGE);
    const loaded = readJson(opt('--runs'), '--runs'), runs = Array.isArray(loaded) ? loaded : [loaded];
    if (opt('--targets')) {
      if (opt('--observers') || opt('--gate')) throw new Error('--observers and --gate belong to a sequence; a profile declares its observers.');
      const targets = validateTargetFile(readJson(opt('--targets'), '--targets'));
      const target = opt('--target') ? targets.find(t => t.id === opt('--target')) : targets.length === 1 ? targets[0] : null;
      if (!target) throw new Error(opt('--target') ? `No target ${opt('--target')} in --targets.` : 'Name the target with --target: the file has several.');
      if (Boolean(opt('--inventory')) !== Boolean(opt('--contract'))) throw new Error('Give --inventory and --contract together, or neither.');
      const coverage = opt('--inventory') ? { inventory: readJson(opt('--inventory'), '--inventory'), contract: readJson(opt('--contract'), '--contract') } : {};
      build = () => grantUseReport({ target, runs, ...coverage });
    } else {
      if (!opt('--observers')) throw new Error('A sequence report needs --observers (the observers.json its runs used).');
      if (opt('--inventory') || opt('--contract') || opt('--target')) throw new Error('--inventory, --contract and --target belong to a profile report.');
      const sequence = readJson(opt('--sequence'), '--sequence'), configs = readJson(opt('--observers'), '--observers'), gateConfig = opt('--gate') ? readJson(opt('--gate'), '--gate') : null;
      build = () => sequenceGrantUseReport({ sequence, runs, configs, gateConfig });
    }
  } catch (error) { log(`Configuration error: ${error.message}`); return 2; }
  // Building the report: a refusal (an invalid input or a run the validators refuse) is a GrantUseError; anything else is thrown.
  let report;
  try { report = build(); } catch (error) { if (error instanceof GrantUseError) { log(`Configuration error: ${error.message}`); return 2; } throw error; }
  log(argv.includes('--json') ? JSON.stringify(report, null, 2) : renderGrantUseMarkdown(report));
  return 0;
}

// Run directly: Node loads the main module from its real path, so compare real paths (a symlinked or spaced path still runs it).
const invokedDirectly = () => { try { return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url); } catch { return false; } };
if (process.argv[1] && invokedDirectly()) process.exitCode = main();
