// Model stand-in CLI. Serves OpenAI-shaped chat completions and Responses endpoints on loopback from a scripted plan.
//   node integrations/model-standin/cli.mjs serve --plan FILE [--port N] [--log FILE]
//   node integrations/model-standin/cli.mjs example-plan --out NEW_FILE
//   node integrations/model-standin/cli.mjs check --plan FILE
// serve prints the origin and the environment lines that point an application at it, then runs until SIGINT or SIGTERM.
// --log appends one JSON line per request (what the app sent: endpoint, step, tools offered, roles, digests; never message text
// or a credential). Exit codes: 0 done; 2 usage, file or validation error.
import { appendFileSync } from 'node:fs';
import { lstat, readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { EXAMPLE_PLAN, startStandIn, validatePlan } from './server.mjs';

const USAGE = 'Usage: cli.mjs serve --plan FILE [--port N] [--log FILE] | example-plan --out NEW | check --plan FILE';

function parse(argv) {
  const flags = {}, positional = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) { const value = argv[i + 1]; if (value === undefined || value.startsWith('--')) throw new Error(`${argv[i]} needs a value.`); flags[argv[i].slice(2)] = value; i++; }
    else positional.push(argv[i]);
  }
  return { flags, positional };
}
async function readJson(path) {
  if (!path) throw new Error('--plan is required.');
  const st = await lstat(path);
  if (!st.isFile() || st.isSymbolicLink()) throw new Error(`${path} must be a regular file.`);
  if (st.size > 4 * 1024 * 1024) throw new Error(`${path} is too large.`);
  try { return JSON.parse(await readFile(path, 'utf8')); } catch { throw new Error(`${path} is not valid JSON.`); }
}
export const envLines = origin => [
  `OPENAI_BASE_URL=${origin}/v1`,
  `OPENAI_API_BASE=${origin}/v1`,
  'OPENAI_API_KEY=standin-no-key',
];

// wait: a promise that resolves when the server should stop (tests pass one; the CLI waits for a signal).
export async function main(argv, { out = console.log, wait = null, onStart = null } = {}) {
  if (argv.includes('--help') || argv[0] === 'help' || !argv.length) { out(USAGE); return 0; }
  const [command, ...rest] = argv;
  const { flags } = parse(rest);
  if (command === 'example-plan') {
    if (!flags.out) throw new Error('--out NEW_FILE is required.');
    await writeFile(flags.out, `${JSON.stringify(EXAMPLE_PLAN, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    out(JSON.stringify({ wrote: flags.out, model: EXAMPLE_PLAN.model, steps: EXAMPLE_PLAN.steps.length }));
    return 0;
  }
  if (command === 'check') { const plan = validatePlan(await readJson(flags.plan)); out(JSON.stringify({ model: plan.model, steps: plan.steps.length, default: plan.default ? 'set' : 'built-in' })); return 0; }
  if (command === 'serve') {
    const plan = validatePlan(await readJson(flags.plan));
    const port = flags.port === undefined ? 0 : Number(flags.port);
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('--port is 0 to 65535.');
    const log = flags.log ? entry => appendFileSync(flags.log, `${JSON.stringify(entry)}\n`, { mode: 0o600 }) : null;
    const server = await startStandIn({ plan, port, log });
    out(`model stand-in listening on ${server.origin} (model ${plan.model}); loopback only, no provider is called`);
    for (const line of envLines(server.origin)) out(line);
    out(`requests so far: GET ${server.origin}/_standin/requests`);
    if (onStart) onStart(server);
    await (wait ?? new Promise(resolve => { for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, resolve); }));
    await server.stop();
    out(`stopped after ${server.requests().length} request(s)`);
    return 0;
  }
  throw new Error(USAGE);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main(process.argv.slice(2)).then(code => { process.exitCode = code; }, error => { console.error(error.message); process.exitCode = 2; });
}
