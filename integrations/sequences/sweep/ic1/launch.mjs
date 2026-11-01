// World launcher (integrations/sweep/launcher.mjs protocol) for the IC1 DeskLane app, for practice and regression
// runs of the boundary sweep on IC1's revealed cases. It starts the IC1 backend (model, tools, deliveries, identity),
// reports it as the upstream, starts DeskLane pointed at the hold gate the sweep returns, and reports DeskLane's
// origin with this world's staff and admin tokens. The IC1 files are read from --app (a checkout or archive of the
// differentiation lane's lane-ic1/app); this file never writes there.
//   node launch.mjs --app DIR --seed-file seed.json --script APP-SCRIPT.json --actor STAFF_ID --timing-seed HEX --exec N
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

const arg = name => { const i = process.argv.indexOf(name); if (i < 0 || !process.argv[i + 1]) throw new Error(`missing ${name}`); return process.argv[i + 1]; };
const token = () => randomBytes(24).toString('base64url');
const children = [];
const stopAll = () => { for (const c of children) if (c.exitCode === null) c.kill('SIGTERM'); setTimeout(() => process.exit(0), 300).unref(); };

// One child that prints a JSON "ready" line with `key` set; resolves that line.
function start(script, args, env, key) {
  const child = spawn(process.execPath, [script, ...args], { env: { PATH: '/usr/bin:/bin', ...env }, stdio: ['ignore', 'pipe', 'ignore'] });
  children.push(child);
  return new Promise((resolve, reject) => {
    const lines = createInterface({ input: child.stdout });
    lines.on('line', line => { try { const m = JSON.parse(line); if (m[key] === 'ready') resolve(m); } catch {} });
    child.once('exit', code => reject(new Error(`${key} exited (${code}) before it was ready`)));
  });
}

try {
  const app = arg('--app'), seedFile = arg('--seed-file'), script = arg('--script'), actor = arg('--actor'), seedHex = arg('--timing-seed'), exec = arg('--exec');
  const staff = Object.keys(JSON.parse(readFileSync(seedFile, 'utf8')).staff ?? {});
  if (!staff.includes(actor)) throw new Error('unknown actor');
  const operator = token(), admin = token(), tokens = Object.fromEntries(staff.sort().map(id => [id, token()]));
  process.on('SIGTERM', stopAll);
  const backend = await start(join(app, 'backend.mjs'), ['--script', script, '--exec', exec], { BACKEND_OPERATOR_TOKEN: operator, BACKEND_SEED: seedHex }, 'backend');
  process.stdout.write(`${JSON.stringify({ upstream: `http://127.0.0.1:${backend.port}` })}\n`);
  const input = createInterface({ input: process.stdin });
  input.on('close', stopAll);
  for await (const line of input) {
    let gate = null;
    try { gate = JSON.parse(line).gate; } catch {}
    if (!gate) continue;
    const desk = await start(join(app, 'desklane.mjs'), ['--script', script, '--seed', seedFile, '--backend', gate, '--identity', `http://127.0.0.1:${backend.identityPort}`, '--port', '0'],
      { DESK_TOKENS: JSON.stringify(tokens), DESK_ADMIN_TOKEN: admin, DESK_OPERATOR_TOKEN: operator }, 'desklane');
    process.stdout.write(`${JSON.stringify({ origin: desk.origin, credentials: { SCOPEHAVEN_TARGET_SWEEP_USER: tokens[actor], SCOPEHAVEN_TARGET_SWEEP_ADMIN: admin } })}\n`);
  }
} catch (error) { process.stderr.write(`ic1 launch: ${error.message}\n`); stopAll(); process.exitCode = 2; }
