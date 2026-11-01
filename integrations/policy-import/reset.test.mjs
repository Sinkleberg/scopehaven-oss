import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RESET_SCHEMA, ensureSeed, runCommand, runReset, seedHash, validateReset } from './reset.mjs';
import { main } from './cli.mjs';

const scratch = async t => { const dir = await mkdtemp(join(tmpdir(), 'scopehaven reset ')); t.after(() => rm(dir, { recursive: true, force: true })); return dir; };
// A seed script: writes a fixed database file (and, with a second argument, a different one).
const seedScript = `import { writeFileSync } from 'node:fs';
writeFileSync(process.argv[2], JSON.stringify({ orders: ['A-1', 'B-1'], variant: process.argv[3] ?? 'seed' }));
if (process.env.LEAK_CHECK) process.stderr.write('env leaked: ' + Object.keys(process.env).filter(k => k.startsWith('SCOPEHAVEN_')).join(',') + '\\n');
`;
const declFor = (dir, extra = {}) => ({ schema: RESET_SCHEMA, targetId: 'support', reset: { command: [process.execPath, join(dir, 'seed.mjs'), join(dir, 'db.json')], cwd: dir, timeoutMs: 10000 }, seed: { files: [join(dir, 'db.json')], expected: null }, ...extra });

test('ensureSeed runs the reset, records the seed hash the first time, and refuses a run whose seed differs after a failed restore', async t => {
  const dir = await scratch(t);
  await writeFile(join(dir, 'seed.mjs'), seedScript);
  const first = await ensureSeed(declFor(dir), { now: new Date('2026-10-26T00:00:00Z') });
  assert.equal(first.recorded, true);
  assert.equal(first.seed.matches, null);
  assert.equal(first.reset.ok, true);
  assert.equal((await runReset(declFor(dir))).ok, true);
  assert.match(first.seed.hash, /^[a-f0-9]{64}$/);
  assert.equal(first.declaration.seed.expected, first.seed.hash);
  assert.deepEqual(JSON.parse(await readFile(join(dir, 'db.json'), 'utf8')), { orders: ['A-1', 'B-1'], variant: 'seed' });
  // A run dirtied the target; the reset restores the seed and the hash matches.
  await writeFile(join(dir, 'db.json'), '{"orders":["A-1"]}');
  const second = await ensureSeed(first.declaration);
  assert.equal(second.recorded, false);
  assert.equal(second.seed.matches, true);
  assert.equal(second.seed.parts[0].kind, 'file');
  // A reset that restores a different state is refused, naming the source.
  const drifted = { ...first.declaration, reset: { ...first.declaration.reset, command: [...first.declaration.reset.command, 'other'] } };
  await assert.rejects(ensureSeed(drifted), /seed state differs from the recorded seed[\s\S]*db\.json/);
  // Without the reset the dirty state is caught too.
  await writeFile(join(dir, 'db.json'), '{"orders":["A-1"]}');
  await assert.rejects(ensureSeed(first.declaration, { skipReset: true }), /seed state differs/);
  // A failing or missing reset command is refused before any hash.
  await assert.rejects(ensureSeed({ ...first.declaration, reset: { ...first.declaration.reset, command: [process.execPath, '-e', 'process.exit(3)'] } }), /exited 3/);
  await assert.rejects(ensureSeed({ ...first.declaration, reset: { ...first.declaration.reset, command: ['/nonexistent/reset'] } }), /could not start/);
  await assert.rejects(ensureSeed({ ...first.declaration, reset: { ...first.declaration.reset, command: [process.execPath, '-e', 'setTimeout(()=>{}, 5000)'], timeoutMs: 1000 } }), /timed out/);
});

test('the reset command runs without a shell and without the caller\'s secrets; seed sources can be a command\'s stdout and loopback reads', async t => {
  const dir = await scratch(t);
  await writeFile(join(dir, 'seed.mjs'), seedScript);
  const r = await runCommand([process.execPath, join(dir, 'seed.mjs'), join(dir, 'db.json')], { cwd: dir, env: { LEAK_CHECK: '1' }, baseEnv: { PATH: process.env.PATH, SCOPEHAVEN_TARGET_SECRET: 'never-passed' } });
  assert.equal(r.exitCode, 0);
  assert.equal(r.stderrTail.trim(), 'env leaked:');
  const shellish = await runCommand(['echo $HOME; touch', join(dir, 'pwned')], { cwd: dir });
  assert.notEqual(shellish.spawnError ?? shellish.exitCode, 0);
  await assert.rejects(rm(join(dir, 'pwned')), /ENOENT/);
  // Command stdout as a seed source.
  const withCommand = declFor(dir, { seed: { command: [process.execPath, '-e', 'process.stdout.write(require("fs").readFileSync(process.argv[1]))', join(dir, 'db.json')], expected: null } });
  const h1 = await seedHash(await ensureSeed(withCommand).then(r => r.declaration));
  assert.equal(h1.parts[0].kind, 'command');
  await assert.rejects(seedHash(declFor(dir, { seed: { command: [process.execPath, '-e', 'process.exit(2)'], expected: null } })), /seed command exited 2/);
  // Loopback reads as a seed source, with a credential read from the environment and never stored.
  const seen = [];
  const server = createServer((req, res) => { seen.push(req.headers.authorization ?? null); res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ path: req.url })); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const origin = `http://127.0.0.1:${server.address().port}`;
  const env = { ...process.env, SCOPEHAVEN_TARGET_RS_A: 'tok-123' };
  const httpDecl = declFor(dir, { seed: { http: { origin, paths: ['/api/orders/A-1', '/api/orders/B-1'], credentialEnv: 'SCOPEHAVEN_TARGET_RS_A' }, expected: null } });
  const receipt = await ensureSeed(httpDecl, { env });
  assert.deepEqual(receipt.seed.parts.map(p => [p.kind, p.ref, p.status]), [['http', '/api/orders/A-1', 200], ['http', '/api/orders/B-1', 200]]);
  assert.deepEqual(seen, ['Bearer tok-123', 'Bearer tok-123']);
  assert.equal(JSON.stringify(receipt).includes('tok-123'), false);
  await assert.rejects(ensureSeed(httpDecl, { env: { ...process.env, SCOPEHAVEN_TARGET_RS_A: '' } }), /not set/);
  assert.throws(() => validateReset(declFor(dir, { seed: { http: { origin: 'http://10.0.0.5:80', paths: ['/x'] }, expected: null } })), /loopback/);
  assert.throws(() => validateReset(declFor(dir, { seed: { http: { origin: 'https://127.0.0.1:443', paths: ['/x'] }, expected: null } })), /plain http loopback/);
});

test('validation refuses shell strings, relative paths, secret-looking env values, bad timeouts and a missing seed source', async t => {
  const dir = await scratch(t);
  const ok = declFor(dir);
  assert.equal(validateReset(ok), ok);
  assert.throws(() => validateReset({ ...ok, reset: { ...ok.reset, command: 'node seed.mjs' } }), /argv list/);
  assert.throws(() => validateReset({ ...ok, reset: { ...ok.reset, cwd: 'relative' } }), /absolute/);
  assert.throws(() => validateReset({ ...ok, reset: { ...ok.reset, env: { DB_PASSWORD: 'x' } } }), /looks like a secret/);
  assert.throws(() => validateReset({ ...ok, reset: { ...ok.reset, timeoutMs: 5 } }), /timeoutMs/);
  assert.throws(() => validateReset({ ...ok, seed: { expected: null } }), /at least one source/);
  assert.throws(() => validateReset({ ...ok, seed: { files: ['db.json'], expected: null } }), /absolute paths/);
  assert.throws(() => validateReset({ ...ok, seed: { files: [join(dir, 'db.json')], expected: 'short' } }), /expected/);
  assert.throws(() => validateReset({ ...ok, schema: 'x' }), /schema/);
});

test('CLI: reset records a new declaration file the first time, exits 0 on a matching seed and 1 on a different one', async t => {
  const dir = await scratch(t), out = [];
  await writeFile(join(dir, 'seed.mjs'), seedScript);
  await writeFile(join(dir, 'reset.json'), JSON.stringify(declFor(dir)));
  assert.equal(await main(['reset', join(dir, 'reset.json'), '--record', join(dir, 'reset.recorded.json')], { out: s => out.push(s) }), 0);
  const recorded = JSON.parse(await readFile(join(dir, 'reset.recorded.json'), 'utf8'));
  assert.match(recorded.seed.expected, /^[a-f0-9]{64}$/);
  assert.equal(await main(['reset', join(dir, 'reset.recorded.json')], { out: s => out.push(s) }), 0);
  assert.match(out.at(-1), /"matches":true/);
  await assert.rejects(main(['reset', join(dir, 'reset.json')], { out: () => {} }), /--record/);
  await writeFile(join(dir, 'seed.mjs'), seedScript.replace("'seed'", "'changed'"));
  assert.equal(await main(['reset', join(dir, 'reset.recorded.json')], { out: s => out.push(s), err: () => {} }), 1);
  assert.equal(await main(['seed-hash', join(dir, 'reset.recorded.json')], { out: s => out.push(s) }), 0);
  assert.match(out.at(-1), /"hash":"[a-f0-9]{64}"/);
  // --skip-reset takes no value (m2): it hashes the seed as it stands, so the changed seed is refused without running the reset.
  assert.equal(await main(['reset', join(dir, 'reset.recorded.json'), '--skip-reset'], { out: s => out.push(s), err: () => {} }), 1);
  assert.match(out.at(-1), /"matches":false/);
});

test('a reset that times out has its whole process group killed, its children included (m7)', async t => {
  const dir = await scratch(t);
  const script = `const { spawn } = require('node:child_process'); const fs = require('node:fs');
const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
fs.writeFileSync(process.argv[1], String(child.pid)); setInterval(() => {}, 1000);`;
  const r = await runCommand([process.execPath, '-e', script, join(dir, 'child.pid')], { cwd: dir, timeoutMs: 1500 });
  assert.equal(r.timedOut, true);
  const pid = Number(await readFile(join(dir, 'child.pid'), 'utf8'));
  await new Promise(resolve => setTimeout(resolve, 200));
  assert.throws(() => process.kill(pid, 0), /ESRCH/, 'the reset command\'s child is gone');
});
