import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MANIFEST_NAME, artifactName, excluded, filesAt, main } from '../packaging/build-release.mjs';
import { NODE_ENGINES } from '../src/runtime.mjs';

// The npm package: what package.json declares for a public release, that its file list is the release's shipped set, and
// that the bin from a fresh offline install runs doctor and the demo assessment. Local only: npm pack and npm install
// --offline with a private HOME and cache, from git objects at HEAD. Nothing is published and no registry is contacted.
const PROJECT = fileURLToPath(new URL('../', import.meta.url));
const pkg = JSON.parse(await readFile(join(PROJECT, 'package.json'), 'utf8'));
const head = spawnSync('git', ['-C', PROJECT, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim();
const name = artifactName(pkg.version, head);
const bin = dirname(process.execPath), npm = join(bin, 'npm'), npx = join(bin, 'npx');
const noNpm = !(existsSync(npm) && existsSync(npx)) && 'no npm and npx beside this Node';

async function folder(t, label = 'scopehaven npm ') {
  const dir = await realpath(await mkdtemp(join(tmpdir(), label)));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}
const isolated = home => ({ PATH: `${bin}:/usr/bin:/bin`, HOME: home, npm_config_cache: join(home, '.npm-cache'), npm_config_update_notifier: 'false', npm_config_audit: 'false', npm_config_fund: 'false' });
const run = (command, args, cwd, home) => spawnSync(command, args, { cwd, env: isolated(home), encoding: 'utf8', timeout: 180000 });
const tarList = file => spawnSync('tar', ['-tzf', file], { encoding: 'utf8', maxBuffer: 1 << 26 }).stdout.split('\n').filter(line => line && !line.endsWith('/'));

test('package.json carries what a public release needs and runs nothing on install', () => {
  assert.deepEqual(pkg.bin, { scopehaven: 'scopehaven' }, 'the launcher itself, so the version range and actions keep one source');
  assert.deepEqual(pkg.publishConfig, { access: 'public' });
  assert.equal(pkg.license, 'Apache-2.0');
  assert.equal(pkg.repository.url, 'https://github.com/YusefSyed/scopehaven-oss.git');
  assert.equal(pkg.homepage, 'https://github.com/YusefSyed/scopehaven-oss#readme');
  assert.equal(pkg.bugs.url, 'https://github.com/YusefSyed/scopehaven-oss/issues');
  assert.ok(pkg.description && pkg.keywords.length, 'description and keywords');
  assert.equal(pkg.engines.node, NODE_ENGINES);
  assert.deepEqual(pkg.os, ['!win32'], 'the launcher is POSIX sh and the store needs Unix modes, so npm refuses early on Windows');
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare', 'preprepare', 'postprepare', 'prepack', 'postpack']) assert.equal(pkg.scripts[hook], undefined, hook);
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies']) assert.equal(pkg[field], undefined, field);
});

test('prepublishOnly refuses a publish from a folder without the release manifest, and passes in a release copy', async t => {
  const dir = await folder(t);
  const refused = spawnSync('/bin/sh', ['-c', pkg.scripts.prepublishOnly], { cwd: dir, encoding: 'utf8' });
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /Publish the \.tgz from packaging\/build-release\.mjs --npm, not this folder: see packaging\/RELEASE\.md/);
  await writeFile(join(dir, MANIFEST_NAME), '{}');
  assert.equal(spawnSync('/bin/sh', ['-c', pkg.scripts.prepublishOnly], { cwd: dir }).status, 0);
});

test('npm pack of a clean checkout lists the release\'s shipped files, minus the ones only the build generates', { skip: noNpm }, async t => {
  const place = await folder(t), checkout = join(place, 'checkout');
  const all = filesAt(head);
  for (const file of all) { await mkdir(dirname(join(checkout, file.path)), { recursive: true }); await writeFile(join(checkout, file.path), file.content); }
  const packed = run(npm, ['pack', '--dry-run', '--json'], checkout, place);
  assert.equal(packed.status, 0, packed.stderr);
  const [info] = JSON.parse(packed.stdout);
  assert.deepEqual(info.files.map(f => f.path).sort(), all.map(f => f.path).filter(path => !excluded(path)).sort());
});

test('the built package has the tarball\'s files and no others; its bin runs doctor and the demo assessment from a fresh offline install', { skip: noNpm }, async t => {
  const out = await folder(t), place = await folder(t, 'scopehaven npm install ');
  const lines = [];
  assert.equal(main(['--out', out, '--npm'], line => lines.push(line)), 0, lines.join('\n'));
  assert.match(lines.join('\n'), pkg.private ? /^npm .*private: true, so npm refuses to publish it/m : /^npm .*publishable: see packaging\/RELEASE\.md/m);
  const inTarball = tarList(join(out, `${name}.tar.gz`)).map(path => path.slice(name.length + 1)).sort();
  assert.deepEqual(tarList(join(out, `${name}.tgz`)).map(path => path.slice('package/'.length)).sort(), inTarball);
  for (const left of ['.github/workflows/test.yml', '.editorconfig', 'docs/demo/false-success-refund.gif', 'test/npm-bin.test.mjs']) assert.ok(!inTarball.includes(left), left);
  assert.ok(inTarball.includes('scopehaven') && inTarball.includes(MANIFEST_NAME) && inTarball.includes('packaging/RELEASE.md'));

  const installed = run(npm, ['install', '--no-save', '--offline', join(out, `${name}.tgz`)], place, place);
  assert.equal(installed.status, 0, installed.stderr);
  const root = join(place, 'node_modules', 'scopehaven');
  assert.notEqual((await stat(join(place, 'node_modules', '.bin', 'scopehaven'))).mode & 0o100, 0, 'the bin is executable');

  // The launcher takes Node from PATH here: no SCOPEHAVEN_NODE, and the package has no .runtime.
  const doctor = run(npx, ['--offline', 'scopehaven', 'doctor', '--port', '65002'], place, place);
  assert.equal(doctor.status, 0, doctor.stdout + doctor.stderr);
  assert.match(doctor.stdout, /^\[ok\] +Node v\S+ from PATH /m);
  assert.match(doctor.stdout, /^\[ok\] +Release .*: all \d+ files match RELEASE-MANIFEST\.json$/m);
  assert.ok(doctor.stdout.includes(`Result: ready. Next: npx scopehaven assess --target demo-vulnerable --out ./scopehaven-evidence, then ${root}/docs/QUICKSTART.md for your own app.`), doctor.stdout);
  assert.equal(run(join(place, 'node_modules', '.bin', 'scopehaven'), ['doctor', '--port', '65002'], place, place).status, 0, 'and without npx');

  // A relative --out means the folder the user is in, not the installed package.
  const assess = run(npx, ['--offline', 'scopehaven', 'assess', '--target', 'demo-vulnerable', '--out', 'evidence'], place, place);
  assert.equal(assess.status, 1, assess.stderr);
  const report = JSON.parse(assess.stdout);
  assert.deepEqual([report.counts.fail, report.counts.fail + report.counts.pass], [26, 44]);
  assert.ok(existsSync(join(place, 'evidence', 'runs', `${report.id}.json`)), 'the run is in the caller\'s folder');
  assert.equal(existsSync(join(root, 'evidence')), false, 'nothing landed in the package');
});
