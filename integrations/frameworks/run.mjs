#!/usr/bin/env node
// Framework scenario CLI.
//   node integrations/frameworks/run.mjs run --scenario FILE --stub ID --runtime BIN --template DIR --data DIR --out DIR [--label NAME] [--adapter-arg ARG]... [--env K=V]...
//     Checks the template checkout is at the scenario's pinned commit and every
//     seed file matches its sha256, runs the scenario in a fresh working
//     directory, and writes <runId>.record.json and <runId>.verdict.json.
//   node integrations/frameworks/run.mjs judge --scenario FILE --record FILE [--custody tag|gate]
//     Recomputes the verdict from a stored record alone.
// --runtime is what the adapter needs: the template's Python for a 'python' adapter,
// the tsx package folder for a 'tsx' adapter. Nothing is installed here.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, constants, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { validateScenario } from './scenario.mjs';
import { runScenario } from './turn-runner.mjs';
import { judgeRecord } from './judge.mjs';

export const FRAMEWORKS_DIR = fileURLToPath(new URL('.', import.meta.url));
const sha256File = path => createHash('sha256').update(readFileSync(path)).digest('hex');

function parse(argv) {
  const [command, ...rest] = argv, opts = { adapterArgs: [], env: {} };
  for (let i = 0; i < rest.length; i += 2) {
    const [flag, value] = [rest[i], rest[i + 1]];
    if (value === undefined) throw new Error(`Missing value for ${flag}.`);
    if (flag === '--adapter-arg') opts.adapterArgs.push(value);
    else if (flag === '--env') { const at = value.indexOf('='); if (at < 1) throw new Error('--env needs K=V.'); opts.env[value.slice(0, at)] = value.slice(at + 1); }
    else opts[flag.replace(/^--/, '').replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = value;
  }
  return { command, opts };
}

// The template checkout must be at the pinned commit, with no local edits to the template's files.
export function checkTemplate(dir, scenario) {
  const head = execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  if (head !== scenario.template.commit) throw new Error(`Template checkout is at ${head}, not the pinned ${scenario.template.commit}.`);
  // Tracked changes, then any untracked file, in the template's folder. Neither reads ignore
  // rules, which a blob-less sparse checkout may not have locally.
  const dirty = [['status', '--porcelain', '--untracked-files=no'], ['ls-files', '--others']]
    .map(args => execFileSync('git', ['-C', dir, ...args, '--', scenario.template.path], { encoding: 'utf8' }).trim()).filter(Boolean).join('\n');
  if (dirty) throw new Error(`Template files differ from the pinned commit: ${dirty.split('\n')[0]}`);
  return { commit: head, clean: true };
}

// A fresh working directory with each seed file copied in after its sha256 matches.
export function prepareWorkdir(scenario, dataDir) {
  const workdir = mkdtempSync(join(tmpdir(), `scopehaven-${scenario.id}-`));
  const seeds = [];
  for (const seed of scenario.workdir.seed) {
    const from = resolve(dataDir, seed.from), got = sha256File(from);
    if (got !== seed.sha256) { rmSync(workdir, { recursive: true, force: true }); throw new Error(`Seed ${seed.from} sha256 ${got} is not the pinned ${seed.sha256}.`); }
    copyFileSync(from, join(workdir, seed.to), constants.COPYFILE_FICLONE);
    seeds.push({ to: seed.to, sha256: got });
  }
  return { workdir, seeds };
}

// python: --runtime is the template environment's interpreter. tsx: --runtime is the tsx package
// folder; the adapter runs under ScopeHaven's own Node with tsx's loader imported, because the tsx
// command starts a second Node process that would not inherit the contract's file descriptor 3.
export function adapterCommand(scenario, { runtime, template, adapterArgs = [] }) {
  const entry = join(FRAMEWORKS_DIR, scenario.adapter.entry), rest = [entry, '--template', template, ...(scenario.adapter.args ?? []), ...adapterArgs];
  const info = { entry: scenario.adapter.entry, sha256: sha256File(entry), runtime: scenario.adapter.runtime, args: [...(scenario.adapter.args ?? []), ...adapterArgs] };
  if (scenario.adapter.runtime === 'python') return { command: runtime, args: ['-I', '-B', ...rest], env: {}, info };
  const pkg = JSON.parse(readFileSync(join(runtime, 'package.json'), 'utf8'));
  if (pkg.name !== 'tsx' || typeof pkg.exports?.['.'] !== 'string') throw new Error('For a tsx adapter, --runtime is the tsx package folder.');
  return { command: process.execPath, args: ['--import', pathToFileURL(join(runtime, pkg.exports['.'])).href, ...rest], env: {}, info: { ...info, tsx: pkg.version, node: process.version } };
}

async function main() {
  const { command, opts } = parse(process.argv.slice(2));
  const scenario = validateScenario(JSON.parse(readFileSync(opts.scenario, 'utf8')));
  if (command === 'judge') {
    const verdict = judgeRecord(JSON.parse(readFileSync(opts.record, 'utf8')), scenario, { custody: opts.custody ?? 'tag' });
    process.stdout.write(`${JSON.stringify(verdict, null, 1)}\n`);
    return;
  }
  if (command !== 'run') throw new Error('Usage: run.mjs run|judge ...');
  for (const need of ['stub', 'runtime', 'template', 'data', 'out']) if (!opts[need]) throw new Error(`Missing --${need}.`);
  if (!isAbsolute(opts.runtime)) throw new Error('--runtime must be an absolute path.');
  const checkout = checkTemplate(opts.template, scenario);
  const { workdir, seeds } = prepareWorkdir(scenario, opts.data);
  try {
    const adapter = adapterCommand(scenario, { runtime: opts.runtime, template: resolve(opts.template), adapterArgs: opts.adapterArgs });
    const record = await runScenario(scenario, { stubId: opts.stub, adapter: { command: adapter.command, args: adapter.args, env: { ...adapter.env, ...opts.env } }, workdir, label: opts.label ?? null, adapterInfo: { ...adapter.info, checkout, seeds, runtimeName: basename(opts.runtime) } });
    const verdict = judgeRecord(record, scenario, { custody: opts.custody ?? 'tag' });
    mkdirSync(opts.out, { recursive: true });
    writeFileSync(join(opts.out, `${record.runId}.record.json`), `${JSON.stringify(record, null, 1)}\n`);
    writeFileSync(join(opts.out, `${record.runId}.verdict.json`), `${JSON.stringify(verdict, null, 1)}\n`);
    process.stdout.write(`${JSON.stringify({ runId: record.runId, overall: verdict.overall, rows: verdict.rows.map(r => `${r.check}: ${r.status}`) })}\n`);
  } finally { rmSync(workdir, { recursive: true, force: true }); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
