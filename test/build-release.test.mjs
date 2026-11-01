import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { chmod, mkdtemp, readFile, readdir, rm, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { main, excluded, applyReleaseEdits, artifactName, homePathFiles, climbingFiles, ownerFiles, signedConflict, CLIMB_EXCEPTIONS, MANIFEST_NAME, MANIFEST_SCHEMA, RELEASE_EDITS, SIGNATURE_NAMESPACE } from '../packaging/build-release.mjs';
import { ADVISORIES, SBOM_NAME, VEX_NAMES, reviewedLists, unreviewedLists, uvLockPackages } from '../packaging/third-party.mjs';

// Builds the release from this checkout's HEAD into private temp folders (one with a space in its name), extracts it
// with the system tar and runs the extracted launcher's doctor. Local only: git objects, tar, ssh-keygen; no network.
const PROJECT = fileURLToPath(new URL('../', import.meta.url));
const version = JSON.parse(await readFile(join(PROJECT, 'package.json'), 'utf8')).version;
const head = spawnSync('git', ['-C', PROJECT, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim();
const name = artifactName(version, head);
const sha256 = data => createHash('sha256').update(data).digest('hex');
const hasSshKeygen = spawnSync('ssh-keygen', ['-?'], { encoding: 'utf8' }).error === undefined;

async function folder(t, label = 'scopehaven release ') {
  const dir = await mkdtemp(join(tmpdir(), label));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}
function build(args) { const lines = []; const code = main(args, line => lines.push(line)); return { code, text: lines.join('\n') }; }
function launch(root, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(join(root, 'scopehaven'), args, { cwd: root, env: { PATH: '/usr/bin:/bin', SCOPEHAVEN_NODE: process.execPath }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 120000);
    child.stdout.on('data', bytes => { stdout += bytes; });
    child.stderr.on('data', bytes => { stderr += bytes; });
    child.on('error', reject);
    child.on('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}

test('exclusion rule: tests and coordination notes are left out, shared test helpers stay', () => {
  for (const path of ['test/install-launcher.test.mjs', 'integrations/init/init.test.mjs', 'test/fixtures/x.json', 'WORKFLOWS.json', 'AGENTS.md', '.gitignore', 'integrations/x/.gitignore']) assert.ok(excluded(path), path);
  for (const path of ['.github/workflows/test.yml', '.github/CODEOWNERS', '.editorconfig', '.gitattributes', 'docs/demo/false-success-refund.gif']) assert.ok(excluded(path), path);
  for (const path of ['test/support/authorization.mjs', 'src/server.mjs', 'integrations/init/AGENTS.md', 'integrations/init/test/fixtures/two-tenant-app.mjs', 'scopehaven', 'docs/INSTALL.md', 'docs/demo/README.md', 'packaging/RELEASE.md']) assert.ok(!excluded(path), path);
  for (const path of ['integrations/frameworks/setup/langgraph-cs.requirements.txt', 'integrations/frameworks/acceptance/mastra-billing/packages-mastra-billing.json', 'packaging/osv-snapshot.mjs']) assert.ok(excluded(path), path);
  for (const path of ['integrations/frameworks/judge.mjs', 'integrations/frameworks/scenarios/mastra-billing.s2-timeout.json', 'packaging/third-party.mjs', ADVISORIES, '.gitleaks.toml']) assert.ok(!excluded(path), path);
});

test('left-out records: nothing that names a home folder ships, and nothing shipped reads what is left out', () => {
  for (const path of ['coordination/receipts/x.json', 'integrations/regression-gate/history/x.txt', 'PILOT_READINESS.json']) assert.ok(excluded(path), path);
  for (const path of ['integrations/regression-gate/gate.mjs', 'docs/DEPENDENCIES.md']) assert.ok(!excluded(path), path);
  const home = ['Users', 'home'].map(root => `/${root}/someone/project`);
  for (const path of home) assert.deepEqual(homePathFiles([{ path: 'a.mjs', content: Buffer.from(`const x = '${path}';`) }]), ['a.mjs']);
  assert.deepEqual(homePathFiles([{ path: 'b.bin', content: Buffer.from(`\0${home[0]}`) }, { path: 'c.md', content: Buffer.from(`see /${'home'}/`) }, { path: 'd.json', content: Buffer.from(`"/${'Users'}/"`) }]), ['b.bin', 'c.md', 'd.json'], 'binaries and bare prefixes count');
  assert.deepEqual(homePathFiles([{ path: 'e.mjs', content: Buffer.from('install under the home folder; /usr/local/bin; Users/ and home/ without a leading slash') }]), []);
  for (const path of ['DESIGN_DIRECTION.txt', 'CHECK_COVERAGE.json']) assert.ok(excluded(path), path);
});

test('climbing and owner refusals: no shipped file reaches outside the folder or names the GitHub owner', () => {
  const up = n => '../'.repeat(n);
  const file = (path, text) => ({ path, content: Buffer.from(text) });
  const climbs = [file('src/a.mjs', `new URL('${up(2)}outputs/x/run.mjs', import.meta.url)`), file('src/b.mjs', `join(HERE, '..', '..', 'outputs')`),
    file('src/c.mjs', `HERE + '/${up(2)}outputs'`), file('README.md', `see \`${up(1)}outputs/\``), file('d.bin', `\0${up(1)}x`),
    file('integrations/x/y.mjs', `import z from '${up(3)}outputs/z.mjs';`)];
  assert.deepEqual(climbingFiles(climbs), climbs.map(f => f.path));
  const inside = [file('integrations/x/y.mjs', `import z from '${up(2)}src/z.mjs'; const p = './a'; // a ".." segment is refused`),
    file('src/a.mjs', `new URL('${up(1)}public/x.html', import.meta.url); path.split('/').includes('..')`)];
  assert.deepEqual(climbingFiles(inside), []);
  const [exception] = CLIMB_EXCEPTIONS;
  assert.deepEqual(climbingFiles([file(exception.path, `[${exception.text}]`)]), [], 'a reviewed exception is excused');
  assert.deepEqual(climbingFiles([file(exception.path, `[${exception.text}, '${up(2)}outputs']`)]), [exception.path], 'only its exact text');
  assert.deepEqual(climbingFiles([file('src/other.mjs', exception.text)]), ['src/other.mjs'], 'and only in its own file');
  const owner = ['Yusef', 'Syed'];
  assert.deepEqual(ownerFiles([file('a.yml', `# ${owner.join('')}/scopehaven`), file('b.md', owner.join('').toLowerCase()), file('c.md', `Licensor: ${owner.join(' ')}`)]), ['a.yml', 'b.md']);
});

test('release edits: a sealed home-path constant becomes a folder inside the install; a stale table fails the build', () => {
  const home = `/${'Users'}/someone/project`;
  const content = Buffer.from(`const A = 1;\nexport const ROOT = '${home}';\nconst PY = '${home}/python';\nconst B = ROOT;\n`);
  const edits = [{ path: 'x.mjs', constant: 'ROOT', folder: 'one' }, { path: 'x.mjs', constant: 'PY', folder: 'two' }];
  const done = applyReleaseEdits([{ path: 'x.mjs', content }, { path: 'y.mjs', content: Buffer.from('y') }], edits);
  assert.equal(done.files[0].content.toString(), "const A = 1;\nexport const ROOT = import.meta.dirname + '/not-in-release/one';\nconst PY = import.meta.dirname + '/not-in-release/two';\nconst B = ROOT;\n");
  assert.equal(done.files[1].content.toString(), 'y');
  assert.deepEqual(done.edits, [{ path: 'x.mjs', constants: ['ROOT', 'PY'], paths: [], gitSha256: sha256(content), sha256: sha256(done.files[0].content) }]);
  assert.deepEqual(homePathFiles(done.files), []);
  assert.throws(() => applyReleaseEdits([{ path: 'x.mjs', content: Buffer.from("const ROOT = 'relative';\n") }], edits), /no single home-path ROOT/);
  assert.throws(() => applyReleaseEdits([], edits), /x\.mjs is not in this commit/);
  assert.deepEqual(RELEASE_EDITS.map(e => e.path).filter(path => excluded(path)), [], 'every edited source still ships');
});

test('release edits: a relative path out of the folder becomes a folder inside the install; a stale count fails the build', () => {
  const from = `${'../'.repeat(3)}outputs/proto`;
  const content = Buffer.from(`import { run } from '${from}/run.mjs';\nconst ROOT = resolve(HERE, "${from}");\n// ${from} in a comment stays\nconst X = '${from}x';\n`);
  const edits = [{ path: 'a/b/x.mjs', from, into: 'a/not-in-release/proto', count: 2 }];
  const done = applyReleaseEdits([{ path: 'a/b/x.mjs', content }], edits);
  assert.equal(done.files[0].content.toString(), `import { run } from '../not-in-release/proto/run.mjs';\nconst ROOT = resolve(HERE, "../not-in-release/proto");\n// ${from} in a comment stays\nconst X = '${from}x';\n`);
  assert.deepEqual(done.edits, [{ path: 'a/b/x.mjs', constants: [], paths: [from], gitSha256: sha256(content), sha256: sha256(done.files[0].content) }]);
  assert.equal(applyReleaseEdits([{ path: 'a/x.mjs', content: Buffer.from(`'${'../'.repeat(2)}outputs/proto'`) }], [{ path: 'a/x.mjs', from: `${'../'.repeat(2)}outputs/proto`, into: 'a/n/p', count: 1 }]).files[0].content.toString(), "'./n/p'");
  assert.throws(() => applyReleaseEdits([{ path: 'a/b/x.mjs', content }], [{ ...edits[0], count: 1 }]), /quotes .*outputs\/proto 2 times, not 1; update RELEASE_EDITS/);
});

test('artifact names and signed versions: two commits never share a name, and a signed version stays with its commit', () => {
  const [a, b] = ['5cc395a82ad85e7eea57980b11654a503af445bf', '02f447a2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'];
  assert.equal(artifactName('0.7.0', a), 'scopehaven-0.7.0-5cc395a8');
  assert.notEqual(artifactName('0.7.0', a), artifactName('0.7.0', b));
  const ledger = { releases: [{ version: '0.7.0', commit: a }] };
  assert.equal(signedConflict(ledger, '0.7.0', a), null, 'rebuilding the signed commit is allowed');
  assert.deepEqual(signedConflict(ledger, '0.7.0', b), ledger.releases[0]);
  assert.equal(signedConflict(ledger, '0.7.1', b), null);
});

test('third-party package lists: only declared lists ship, and a declared list must match the reviewed OSV snapshot', () => {
  assert.deepEqual(uvLockPackages('version = 1\n[[package]]\nname = "app"\nsource = { virtual = "." }\n\n[[package]]\nname = "pillow"\nversion = "12.3.0"\nsource = { registry = "x" }\n[package.optional-dependencies]\nversion = "no"\n'),
    [{ name: 'pillow', version: '12.3.0' }]);
  const lock = 'vendored/uv.lock', declared = [{ path: lock, ecosystem: 'PyPI', parse: 'uv.lock', covers: ['vendored/pyproject.toml'], why: 'test list' }];
  assert.deepEqual(unreviewedLists(['package.json', lock, 'vendored/pyproject.toml', 'src/server.mjs'], declared), []);
  assert.deepEqual(unreviewedLists(['package.json', lock, 'src/server.mjs']), [lock], 'no list is declared today, so a shipped list is refused');
  assert.deepEqual(unreviewedLists(['integrations/x/requirements.txt', 'a/package-lock.json', 'a/package.json', 'b/packages-mastra.json', 'c/mastra.package.json']),
    ['integrations/x/requirements.txt', 'a/package-lock.json', 'a/package.json', 'b/packages-mastra.json', 'c/mastra.package.json']);
  assert.throws(() => reviewedLists([{ path: 'x/requirements.txt', content: Buffer.from('a==1\n') }]), /ships without review: x\/requirements\.txt/);
  const snapshot = (sha, packages) => ({ path: ADVISORIES, content: Buffer.from(JSON.stringify({ schema: 'scopehaven-third-party-advisories/1', queriedAt: 'T', endpoint: 'E', lists: [{ path: lock, ecosystem: 'PyPI', sha256: sha, packages }] })) });
  const content = Buffer.from('[[package]]\nname = "pillow"\nversion = "12.3.0"\n');
  const pillow = [{ name: 'pillow', version: '12.3.0', advisories: [{ name: 'CVE-1', aliases: ['GHSA-1'] }] }];
  assert.throws(() => reviewedLists([{ path: lock, content }], declared), /third-party-advisories\.json is missing/);
  assert.throws(() => reviewedLists([{ path: lock, content }, snapshot('0'.repeat(64), pillow)], declared), /does not match .*uv\.lock/);
  assert.throws(() => reviewedLists([{ path: lock, content }, snapshot(sha256(content), [])], declared), /does not match .*uv\.lock/);
  const { lists } = reviewedLists([{ path: lock, content }, snapshot(sha256(content), pillow)], declared);
  assert.deepEqual(lists[0].packages, [{ name: 'pillow', version: '12.3.0', purl: 'pkg:pypi/pillow@12.3.0', advisories: pillow[0].advisories }]);
});

test('release tarball: deterministic, checksummed, manifest-complete; the extracted copy passes doctor and refuses tampering', async t => {
  const out1 = await folder(t), out2 = await folder(t);
  let r = build(['--out', out1]);
  assert.equal(r.code, 0, r.text);
  assert.match(r.text, /unsigned no --sign-key/);
  r = build(['--out', out2]);
  assert.equal(r.code, 0, r.text);
  const tar1 = await readFile(join(out1, `${name}.tar.gz`)), tar2 = await readFile(join(out2, `${name}.tar.gz`));
  assert.equal(sha256(tar1), sha256(tar2), 'two builds of one commit are byte-identical');
  assert.equal(await readFile(join(out1, 'SHA256SUMS'), 'utf8'), `${sha256(tar1)}  ${name}.tar.gz\n`);
  const release = JSON.parse(await readFile(join(out1, 'release.json'), 'utf8'));
  assert.equal(release.commit, spawnSync('git', ['-C', PROJECT, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim());
  assert.equal(release.signature, null);

  const place = await folder(t, 'scopehaven install ');
  const untar = spawnSync('tar', ['-xzf', join(out1, `${name}.tar.gz`), '-C', place], { encoding: 'utf8' });
  assert.equal(untar.status, 0, untar.stderr);
  assert.deepEqual(await readdir(place), [name], 'one top-level folder');
  const root = join(place, name);
  const manifest = JSON.parse(await readFile(join(root, MANIFEST_NAME), 'utf8'));
  assert.equal(manifest.schema, MANIFEST_SCHEMA);
  assert.equal(manifest.files.length, release.manifest.files);
  assert.ok(manifest.files.length > 500 && manifest.excluded.files > 100, `${manifest.files.length} shipped, ${manifest.excluded.files} left out`);
  assert.ok(!manifest.files.some(f => excluded(f.path)), 'no excluded file shipped');
  assert.equal(manifest.files.find(f => f.path === 'scopehaven').mode, '755');
  for (const file of manifest.files.filter((_, i) => i % 97 === 0)) assert.equal(sha256(await readFile(join(root, file.path))), file.sha256, file.path);
  // The SBOM ships and is listed in the manifest. No package list ships, so neither does a VEX.
  assert.ok(manifest.files.some(f => f.path === SBOM_NAME), SBOM_NAME);
  for (const generated of [VEX_NAMES.cyclonedx, VEX_NAMES.openvex]) assert.ok(!manifest.files.some(f => f.path === generated), generated);
  assert.ok(manifest.files.some(f => f.path === '.gitleaks.toml'), 'the gitleaks allowlist ships');
  // No home folder ships, the seals stay behind, and each edit of a sealed source is listed beside the hash git holds.
  assert.ok(!existsSync(join(root, 'coordination')), 'no coordination folder');
  const every = await Promise.all(manifest.files.map(async f => ({ path: f.path, content: await readFile(join(root, f.path)) })));
  assert.deepEqual(homePathFiles(every), [], 'no shipped file names a home folder');
  assert.deepEqual(climbingFiles(every), [], 'no shipped file climbs out of the folder');
  // The open edition names its GitHub owner in README links on purpose; ownerFiles() is kept for private builds.
  for (const e of CLIMB_EXCEPTIONS) assert.ok(every.find(f => f.path === e.path).content.toString().includes(e.text), `exception still needed: ${e.path}`);
  assert.deepEqual(manifest.releaseEdits.files.flatMap(f => f.constants).sort(), RELEASE_EDITS.filter(e => e.constant).map(e => e.constant).sort());
  assert.deepEqual(manifest.releaseEdits.files.flatMap(f => f.paths).sort(), RELEASE_EDITS.filter(e => e.from).map(e => e.from).sort());
  for (const edit of manifest.releaseEdits.files) {
    assert.equal(sha256(await readFile(join(root, edit.path))), edit.sha256, edit.path);
    assert.notEqual(edit.gitSha256, edit.sha256, edit.path);
    assert.deepEqual(homePathFiles([{ path: edit.path, content: await readFile(join(root, edit.path)) }]), []);
  }
  const sbom = JSON.parse(await readFile(join(root, SBOM_NAME), 'utf8'));
  assert.equal(sbom.metadata.component.properties.find(p => p.name === 'scopehaven:commit').value, release.commit);
  assert.deepEqual(release.thirdParty.lists, []);
  assert.deepEqual(unreviewedLists(manifest.files.map(f => f.path)), [], 'no undeclared package list ships');

  let doctor = await launch(root, ['doctor', '--port', '65000']);
  assert.match(doctor.stdout, new RegExp(`^\\[ok\\] +Release ${version.replaceAll('.', '\\.')} \\(commit [0-9a-f]{12}\\): all ${manifest.files.length} files match ${MANIFEST_NAME}$`, 'm'), doctor.stdout);
  assert.match(doctor.stdout, /^\[ok\] +Workbench modules load/m, doctor.stdout);
  assert.equal(doctor.code, 0, doctor.stdout);
  assert.match(doctor.stdout, /Result: ready\. Next: \.\/scopehaven assess --target demo-vulnerable, then docs\/QUICKSTART\.md/);
  const tests = await launch(root, ['test']);
  assert.equal(tests.code, 2);
  assert.match(tests.stderr, /This is a release copy: the test suite is not shipped in it/);

  await writeFile(join(root, 'src', 'runtime.mjs'), '// changed\n', { flag: 'a' });
  await unlink(join(root, 'docs', 'QUICKSTART.md'));
  doctor = await launch(root, ['doctor', '--port', '65000']);
  assert.equal(doctor.code, 1, doctor.stdout);
  assert.match(doctor.stdout, new RegExp(`^\\[fail\\] Release .*: 2 of ${manifest.files.length} files differ from ${MANIFEST_NAME}, first `, 'm'), doctor.stdout);
  assert.match(doctor.stdout, /docs\/QUICKSTART\.md \(missing\)/);
  assert.match(doctor.stdout, /src\/runtime\.mjs \(changed\)/);
});

test('a run made from a release copy names that release, in its core and in both builds a pack prints; with no manifest and no git it reads unknown', async t => {
  const out = await folder(t);
  assert.equal(build(['--out', out]).code, 0);
  const release = JSON.parse(await readFile(join(out, 'release.json'), 'utf8'));
  const place = await folder(t, 'scopehaven install ');
  assert.equal(spawnSync('tar', ['-xzf', join(out, `${name}.tar.gz`), '-C', place], { encoding: 'utf8' }).status, 0);
  const root = join(place, name), work = await folder(t, 'scopehaven release run ');
  const saved = async (data, id) => JSON.parse(await readFile(join(data, 'runs', `${id}.json`), 'utf8')).core;
  const assess = async data => { const run = await launch(root, ['assess', '--target', 'demo-repaired', '--out', data]); assert.equal(run.code, 0, run.stderr); return JSON.parse(run.stdout).id; };

  const data = join(work, 'store'), id = await assess(data), core = await saved(data, id);
  const named = { source: 'release-manifest', version, commit: head, manifestSha256: release.manifest.sha256 };
  assert.deepEqual(core.producer, { release: named });
  assert.equal(release.manifest.sha256, sha256(await readFile(join(root, MANIFEST_NAME))));

  const packed = await launch(root, ['evidence-pack', '--run', id, '--data', data, '--out', join(work, 'pack'), '--signing-key-dir', join(work, 'keys')]);
  assert.equal(packed.code, 0, packed.stderr);
  if (spawnSync('python3', ['--version']).status === 0) {
    const verified = spawnSync('python3', ['-I', 'verify_envelope.py', '--key', 'scopehaven-signing-key.pub.pem', '--envelope', 'evidence-pack.dsse.json', '--dir', '.'], { cwd: join(work, 'pack'), encoding: 'utf8' });
    assert.equal(verified.status, 0, verified.stdout);
    const { builds } = JSON.parse(verified.stdout);
    assert.deepEqual(builds.packing, named);
    assert.deepEqual(builds.running.find(b => b.subject === 'run.json').release, named);
  }
  assert.match(await readFile(join(work, 'pack', 'VERIFY.md'), 'utf8'), new RegExp(`Build that ran it: ScopeHaven ${version}, commit ${head} \\(release-manifest`));

  // The same copy with its manifest gone: it has no git either, so the run still runs, and reads unknown.
  await unlink(join(root, MANIFEST_NAME));
  const bare = join(work, 'bare'), bareId = await assess(bare);
  assert.deepEqual((await saved(bare, bareId)).producer, { release: { source: 'unknown', version, commit: 'unknown', manifestSha256: null } });
});

test('signing: an OpenSSH signature over SHA256SUMS verifies; a key in the repository or readable by others is refused', { skip: !hasSshKeygen && 'ssh-keygen is not on this machine' }, async t => {
  const keys = await folder(t, 'scopehaven release key '), out = await folder(t);
  const key = join(keys, 'release_ed25519');
  const made = spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'scopehaven-release-test', '-f', key], { encoding: 'utf8' });
  assert.equal(made.status, 0, made.stderr);
  const ledger = join(keys, 'signed-releases.json');
  await writeFile(ledger, JSON.stringify({ releases: [{ version, commit: '0'.repeat(40) }] }));
  assert.throws(() => build(['--out', out, '--sign-key', key, '--signed-ledger', ledger]), /already signed for commit 0{40}; bump/, 'a signed version is not signed again for another commit');
  await writeFile(ledger, JSON.stringify({ releases: [{ version, commit: head }] }));
  await writeFile(join(out, 'scopehaven-0.0.0-deadbeef.tar.gz'), 'an earlier build');
  const r = build(['--out', out, '--sign-key', key, '--signed-ledger', ledger]);
  assert.equal(r.code, 0, r.text);
  const publicKey = (await readFile(`${key}.pub`, 'utf8')).trim().split(/\s+/).slice(0, 2).join(' ');
  const signers = join(keys, 'allowed_signers');
  await writeFile(signers, `scopehaven-release-test namespaces="${SIGNATURE_NAMESPACE}" ${publicKey}\n`);
  const sums = await readFile(join(out, 'SHA256SUMS'));
  const verify = input => spawnSync('ssh-keygen', ['-Y', 'verify', '-f', signers, '-I', 'scopehaven-release-test', '-n', SIGNATURE_NAMESPACE, '-s', join(out, 'SHA256SUMS.sig')], { input, encoding: 'utf8' });
  assert.equal(verify(sums).status, 0, verify(sums).stderr);
  assert.notEqual(verify(Buffer.concat([sums, Buffer.from('0  extra\n')])).status, 0, 'an edited SHA256SUMS does not verify');
  const release = JSON.parse(await readFile(join(out, 'release.json'), 'utf8'));
  assert.equal(release.signature.publicKey, publicKey);
  assert.deepEqual((await readdir(out)).filter(file => file.endsWith('.tar.gz')), [`${name}.tar.gz`], 'artifacts of earlier builds do not sit beside this SHA256SUMS');
  assert.match(r.text, /^record +add \{"version"/m);
  const listing = JSON.stringify(release) + r.text;
  assert.ok(!listing.includes((await readFile(key, 'utf8')).split('\n')[1]), 'no private key material in the outputs');

  assert.throws(() => build(['--out', out, '--sign-key', join(PROJECT, 'package.json')]), /inside the repository/);
  await chmod(key, 0o644);
  assert.throws(() => build(['--out', out, '--sign-key', key, '--signed-ledger', ledger]), /readable by other users/);
});

const npm = join(dirname(process.execPath), 'npm');
test('npm package: the same files as the tarball, installs offline into a fresh folder, and its doctor passes the manifest check', { skip: !existsSync(npm) && 'no npm beside this Node' }, async t => {
  const out = await folder(t);
  const r = build(['--out', out, '--npm']);
  assert.equal(r.code, 0, r.text);
  const release = JSON.parse(await readFile(join(out, 'release.json'), 'utf8'));
  assert.deepEqual(release.artifacts.map(a => a.file), [`${name}.tar.gz`, `${name}.tgz`]);
  assert.equal((await readFile(join(out, 'SHA256SUMS'), 'utf8')).trim().split('\n').length, 2);
  const place = await folder(t, 'scopehaven npm install ');
  const env = { PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, HOME: place, npm_config_cache: join(place, '.npm-cache') };
  const installed = spawnSync(npm, ['install', '--no-save', '--offline', '--no-audit', '--no-fund', join(out, `${name}.tgz`)], { cwd: place, env, encoding: 'utf8' });
  assert.equal(installed.status, 0, installed.stderr);
  const root = join(place, 'node_modules', 'scopehaven');
  const doctor = await launch(root, ['doctor', '--port', '65001']);
  assert.match(doctor.stdout, /^\[ok\] +Release .*: all \d+ files match RELEASE-MANIFEST\.json$/m, doctor.stdout);
  assert.equal(doctor.code, 0, doctor.stdout);
});
