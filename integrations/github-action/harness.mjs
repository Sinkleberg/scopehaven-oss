// A local runner for action.yml's own steps, for the CI proof (ci-proof.mjs) and the CI-mode tests. It parses action.yml with a
// minimal YAML subset parser and executes its `run:` steps in bash, in order, with the environment wiring GitHub uses (inputs and
// step outputs through `env:`, GITHUB_OUTPUT, GITHUB_STEP_SUMMARY, GITHUB_ACTION_PATH, RUNNER_TEMP). `uses:` steps (setup-node,
// upload-artifact, upload-sarif) are skipped: nothing is uploaded, downloaded or sent. The same approach as action.test.mjs.
import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const here = dirname(fileURLToPath(import.meta.url));
export const run = (file, args, options = {}) => new Promise(done => {
  execFile(file, args, { encoding: 'utf8', timeout: 300000, maxBuffer: 32 * 1024 * 1024, ...options }, (error, stdout, stderr) =>
    done({ code: error ? (typeof error.code === 'number' ? error.code : -1) : 0, stdout, stderr }));
});

function scalar(text) {
  const value = text.trim();
  if (value.startsWith("'") && value.endsWith("'")) return value.slice(1, -1).replace(/''/g, "'");
  if (value.startsWith('"') && value.endsWith('"')) return JSON.parse(value);
  return value;
}
export function parseYamlSubset(source) {
  const lines = source.split('\n').map(raw => ({ raw, indent: raw.search(/\S/), text: raw.trim() }))
    .filter(line => line.indent >= 0 && !line.text.startsWith('#'));
  let i = 0;
  function block(indent) {
    if (i < lines.length && lines[i].indent === indent && lines[i].text.startsWith('- ')) {
      const list = [];
      while (i < lines.length && lines[i].indent === indent && lines[i].text.startsWith('- ')) {
        const line = lines[i];
        lines[i] = { raw: line.raw, indent: indent + 2, text: line.text.slice(2) };
        list.push(map(indent + 2));
      }
      return list;
    }
    return map(indent);
  }
  function map(indent) {
    const out = {};
    while (i < lines.length && lines[i].indent === indent && !lines[i].text.startsWith('- ')) {
      const { text } = lines[i];
      const match = /^([A-Za-z0-9_-]+):(?: (.*))?$/.exec(text);
      if (!match) throw new Error(`Unsupported YAML line: ${text}`);
      const [, key, rest = ''] = match;
      if (Object.hasOwn(out, key)) throw new Error(`Duplicate key ${key}`);
      i += 1;
      if (rest === '|') {
        const body = [];
        while (i < lines.length && lines[i].indent > indent) { body.push(lines[i].raw); i += 1; }
        const strip = Math.min(...body.filter(line => line.trim()).map(line => line.search(/\S/)));
        out[key] = body.map(line => line.slice(strip)).join('\n') + '\n';
      } else if (rest === '') out[key] = i < lines.length && lines[i].indent > indent ? block(lines[i].indent) : '';
      else out[key] = scalar(rest);
    }
    return out;
  }
  const result = block(0);
  if (i !== lines.length) throw new Error(`Unparsed YAML from line: ${lines[i].text}`);
  return result;
}

export async function loadAction() {
  const text = await readFile(join(here, 'action.yml'), 'utf8');
  return { text, action: parseYamlSubset(text) };
}
const parseOutputs = text => Object.fromEntries(text.split('\n').filter(Boolean).map(line => { const at = line.indexOf('='); return [line.slice(0, at), line.slice(at + 1)]; }));

/** Runs action.yml's run steps in order. Returns { outputs, steps, logs, failed, exitCode, summary }: exitCode is the first failing
 * step's exit code (what fails the job), or 0. */
export async function runAction(inputs, { workspace, runnerTemp, env }) {
  const { action } = await loadAction();
  const values = Object.fromEntries(Object.entries(action.inputs).map(([key, spec]) => [key, spec.default ?? '']));
  for (const key of Object.keys(inputs)) if (!Object.hasOwn(action.inputs, key)) throw new Error(`action.yml has no input ${key}`);
  Object.assign(values, inputs);
  const steps = {}, logs = [];
  const evaluate = text => String(text).replace(/\$\{\{\s*([^}]+?)\s*\}\}/g, (_, expression) => {
    let match;
    if ((match = /^inputs\.([A-Za-z0-9_-]+)$/.exec(expression))) return values[match[1]] ?? '';
    if ((match = /^steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)$/.exec(expression))) return steps[match[1]]?.outputs?.[match[2]] ?? '';
    if ((match = /^steps\.([A-Za-z0-9_-]+)\.outcome$/.exec(expression))) return steps[match[1]]?.outcome ?? '';
    throw new Error(`Unsupported expression in a run step: ${expression}`);
  });
  const stamp = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const summaryFile = join(runnerTemp, `step-summary-${stamp}.md`);
  await writeFile(summaryFile, '');
  let failed = false, exitCode = 0, index = 0;
  for (const step of action.runs.steps) {
    index += 1;
    if (step.uses) { if (step.id) steps[step.id] = { outcome: 'skipped', outputs: {} }; continue; }
    if (step.if && step.if !== 'always()') throw new Error(`The harness supports only always() on run steps: ${step.name}`);
    if (failed && step.if !== 'always()') { if (step.id) steps[step.id] = { outcome: 'skipped', outputs: {} }; continue; }
    const outputFile = join(runnerTemp, `output-${index}-${stamp}`), script = join(runnerTemp, `step-${index}-${stamp}.sh`);
    await writeFile(outputFile, ''); await writeFile(script, step.run);
    const stepEnv = Object.fromEntries(Object.entries(step.env || {}).map(([key, value]) => [key, evaluate(value)]));
    const cwd = resolve(workspace, step['working-directory'] ? evaluate(step['working-directory']) : '.');
    const result = await run('bash', ['--noprofile', '--norc', '-eo', 'pipefail', script], { cwd,
      env: { ...env, ...stepEnv, GITHUB_OUTPUT: outputFile, GITHUB_STEP_SUMMARY: summaryFile, GITHUB_ACTION_PATH: here, GITHUB_WORKSPACE: workspace, RUNNER_TEMP: runnerTemp } });
    const outcome = result.code === 0 ? 'success' : 'failure';
    if (outcome === 'failure' && !failed) { failed = true; exitCode = result.code; }
    logs.push({ name: step.name, ...result });
    if (step.id) steps[step.id] = { outcome, outputs: parseOutputs(await readFile(outputFile, 'utf8')) };
    else steps[`#${index}`] = { outcome, outputs: {} };
  }
  const outputs = Object.fromEntries(Object.entries(action.outputs).map(([key, spec]) => [key, evaluate(spec.value)]));
  return { outputs, steps, logs, failed, exitCode, summary: await readFile(summaryFile, 'utf8') };
}
