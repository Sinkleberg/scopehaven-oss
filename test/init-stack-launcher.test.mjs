import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// The launcher runs integrations/init/cli.mjs as the entry module, whose top-level `await main()` is pending while
// main hands --stack off to runStack. runStack must receive main through io instead of importing the entry module
// again: that import waits for the entry's evaluation, which waits for main, and Node exits 13 with "Detected
// unsettled top-level await" before any request is sent. No fixture: --help goes through the same hand-off.
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const run = args => new Promise(resolve => execFile(process.execPath, ['integrations/init/cli.mjs', ...args], { cwd: ROOT, timeout: 60_000 },
  (error, stdout, stderr) => resolve({ code: error ? (error.code ?? 1) : 0, stdout, stderr })));

test('the launcher form of init --stack reaches the connector path instead of dying on an unsettled top-level await', async () => {
  const r = await run(['--stack', 'supabase', '--help']);
  assert.doesNotMatch(r.stderr, /unsettled top-level await/, r.stderr);
  assert.notEqual(r.code, 13, r.stderr);
  assert.equal(r.code, 0, `${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout, /--stack/);
});
