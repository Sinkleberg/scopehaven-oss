#!/usr/bin/env node
// Builds the installable release of the scopehaven folder from one git commit, never from the working tree:
//   scopehaven-<version>-<commit>.tar.gz   the folder's tracked files at that commit, minus tests, plus RELEASE-MANIFEST.json
//                                 and the generated SBOM.cdx.json, with VEX files when a package list ships (packaging/third-party.mjs)
//   scopehaven-<version>-<commit>.tgz      the same files as an npm package (--npm; npm pack with the selected Node's npm)
//   SHA256SUMS                    one line per artifact, `shasum -a 256 -c` format
//   SHA256SUMS.sig                an OpenSSH signature over SHA256SUMS (--sign-key; namespace scopehaven-release)
//   release.json                  what was built, from which commit, and what was left out
// The tarball is deterministic for a commit: entries sorted, mtime = the commit time, uid/gid 0, modes from git.
// It reads git objects and writes only under --out. It never reads, copies or prints a private key: the key path is
// handed to ssh-keygen, and a key inside the repository is refused. Signing also reads packaging/signed-releases.json.
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, posix, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { SBOM_NAME, VEX_NAMES, reviewedLists, sbom, vexCycloneDX, vexOpen } from './third-party.mjs';

export const MANIFEST_NAME = 'RELEASE-MANIFEST.json';
export const MANIFEST_SCHEMA = 'scopehaven-release-manifest/1';
export const SIGNATURE_NAMESPACE = 'scopehaven-release';
// Left out of the release: test files (the suite reads fixtures outside this folder), the repository's own
// coordination notes for the chats that build it, and the framework targets' setup scripts, package lists and acceptance
// records (framework targets are unavailable in a release copy, and their package lists would read to a buyer's
// composition scan as 247 packages ScopeHaven never installs). Shared test helpers under test/support/ stay: a demo CLI
// imports one.
export const EXCLUDE = Object.freeze([
  { pattern: '**/*.test.mjs', why: 'test files; the suite needs the full repository' },
  { pattern: 'test/* (except test/support/)', why: 'test fixtures and data' },
  { pattern: 'AGENTS.md, CLAUDE.md, WORKFLOWS.json, CONTINUATION.txt (top level)', why: 'repository coordination notes' },
  { pattern: '**/.gitignore', why: 'git settings; npm pack drops them, so the npm package and the tarball ship the same files' },
  { pattern: '.github/, .editorconfig, .gitattributes', why: 'repository settings: workflows, issue drafts and editor rules act on the repository, not on an install' },
  { pattern: 'docs/demo/false-success-refund.gif', why: "the README's recording; GitHub and npm show it from the repository, so an install does not carry it" },
  { pattern: 'integrations/frameworks/setup/, integrations/frameworks/acceptance/', why: 'framework-target setup scripts, their package lists and acceptance records; only the tests read them, and framework targets are unavailable in a release copy' },
  { pattern: 'packaging/osv-snapshot.mjs', why: 'maintainer tool that queries api.osv.dev; the release carries its reviewed output' },
  { pattern: 'coordination/', why: 'build records of the chats that build the repository' },
  { pattern: 'integrations/regression-gate/history/, PILOT_READINESS.json, design/dashboard/CONTINUATION.md, design/raisedhand-intro/IMPLEMENTATION.md, DESIGN_DIRECTION.txt, CHECK_COVERAGE.json', why: 'records of how this repository was built, which name folders on the machine that produced them or beside the scopehaven folder; only tests and the local dashboard preview read them' },
]);
const TOP_LEVEL_NOTES = new Set(['AGENTS.md', 'CLAUDE.md', 'WORKFLOWS.json', 'CONTINUATION.txt']);
const LEFT_OUT_FOLDERS = ['.github/', 'integrations/frameworks/setup/', 'integrations/frameworks/acceptance/', 'coordination/', 'integrations/regression-gate/history/'];
const LEFT_OUT_FILES = new Set(['.editorconfig', '.gitattributes', 'docs/demo/false-success-refund.gif', 'packaging/osv-snapshot.mjs', 'PILOT_READINESS.json',
  'design/dashboard/CONTINUATION.md', 'design/raisedhand-intro/IMPLEMENTATION.md',
  'DESIGN_DIRECTION.txt', 'CHECK_COVERAGE.json']);
export const excluded = path => path.endsWith('.test.mjs') || (path.startsWith('test/') && !path.startsWith('test/support/')) || TOP_LEVEL_NOTES.has(path)
  || path === '.gitignore' || path.endsWith('/.gitignore') || LEFT_OUT_FOLDERS.some(folder => path.startsWith(folder))
  || LEFT_OUT_FILES.has(path);

// Sources that bind a target to folders on the machine that produced it. Git keeps a sealed source as it is and only the
// release copy changes: each constant is rewritten to a folder inside the install that never exists, and the target then
// reads unavailable without looking outside the install. The manifest lists each edit beside the hash git holds. A constant
// that no longer holds a home path fails the build, so this table cannot go stale.
// `levels` runs of ../ before a path, built here so this file never holds one itself (it ships, and climbingFiles checks it).
const up = (levels, path) => '../'.repeat(levels) + path;
// The open edition's sources hold no home paths or climbs out of the folder, so no release edit is needed. The mechanism
// stays for a future edit.
export const RELEASE_EDITS = Object.freeze([]);
export function applyReleaseEdits(files, edits = RELEASE_EDITS) {
  const changed = new Map();
  for (const { path, constant, folder, from, into, count } of edits) {
    const file = changed.get(path) ?? files.find(f => f.path === path);
    if (!file) throw new Error(`release edit: ${path} is not in this commit`);
    const text = file.content.toString();
    const done = { constants: file.constants ?? [], paths: file.paths ?? [] };
    let content;
    if (constant) {
      const line = new RegExp(`^((?:export )?const ${constant} = )'\\/(?:Users|home)\\/[^'\\n]*';$`, 'gm');
      if (text.match(line)?.length !== 1) throw new Error(`release edit: ${path} has no single home-path ${constant}; update RELEASE_EDITS`);
      content = text.replace(line, `$1import.meta.dirname + '/not-in-release/${folder}';`);
      done.constants = [...done.constants, constant];
    } else {
      const quoted = new RegExp(`(?<=['"\`])${from.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?=[/'"\`])`, 'g');
      const found = text.match(quoted)?.length ?? 0;
      if (found !== count) throw new Error(`release edit: ${path} quotes ${from} ${found} times, not ${count}; update RELEASE_EDITS`);
      const to = posix.relative(posix.dirname(path), into);
      content = text.replace(quoted, to.startsWith('..') ? to : `./${to}`);
      done.paths = [...done.paths, from];
    }
    changed.set(path, { ...file, ...done, content: Buffer.from(content), gitSha256: file.gitSha256 ?? sha256(file.content) });
  }
  return { files: files.map(f => changed.get(f.path) ?? f), edits: [...changed.values()].map(f => ({ path: f.path, constants: f.constants, paths: f.paths, gitSha256: f.gitSha256, sha256: sha256(f.content) })) };
}

// Nothing that ships may name a home folder: it would show a reviewer the developer's folder layout, and in code it would
// read outside the install on the developer's machine. Every shipped file is checked byte for byte, binaries too, and no
// file is excused: a legitimate case would need its own reviewed exception here.
const HOME_PATH = /\/(?:Users|home)\//;
export const homePathFiles = files => files.filter(f => HOME_PATH.test(f.content.toString('latin1'))).map(f => f.path);
// Nor may it climb out of the folder by a relative path: from an install that reads whatever sits beside it, and on the
// developer's machine that is the private edition's record folder. Each run of ../ is resolved from the file's own folder, and two
// quoted '..' segments in a row count too. A reviewed exception names the exact text and why it stays inside.
export const CLIMB_EXCEPTIONS = Object.freeze([
  { path: 'src/collector-identity.mjs', text: `'${up(2, 'src/pg-readback.mjs')}'`, why: 'collector file names are relative to integrations/<collector>/, so this one is src/pg-readback.mjs inside the folder' },
]);
export function climbingFiles(files, exceptions = CLIMB_EXCEPTIONS) {
  return files.filter(f => {
    const text = exceptions.filter(e => e.path === f.path).reduce((t, e) => t.split(e.text).join(''), f.content.toString('latin1'));
    return /(['"])\.\.\1\s*,\s*\1\.\.\1/.test(text)
      || [...text.matchAll(/(?<![\w.-])(?:\.\.\/)+/g)].some(m => posix.join(posix.dirname(f.path), m[0]).startsWith('..'));
  }).map(f => f.path);
}
// And it may not name the private repository's GitHub owner: a buyer has no use for it, and it tells a reviewer where the
// source lives. The licence's licensor, "Yusef Syed" with a space, is the legal party and stays.
const OWNER = /yusef[s]yed/i; // the class keeps this line from matching itself
export const ownerFiles = files => files.filter(f => OWNER.test(f.content.toString('latin1'))).map(f => f.path);

// Every artifact names its commit, so builds of two commits never share a name. A hyphen, not semver's `+`: GitHub renames
// release assets with a `+`, and SHA256SUMS would then no longer match the file a buyer downloaded.
export const artifactName = (version, commit) => `scopehaven-${version}-${commit.slice(0, 8)}`;
// A version that was signed belongs to that commit. Unsigned builds stay allowed: their names already differ.
export const SIGNED_LEDGER = join('packaging', 'signed-releases.json');
export function signedConflict(ledger, version, commit) { return ledger.releases.find(r => r.version === version && r.commit !== commit) ?? null; }

const HERE = dirname(fileURLToPath(import.meta.url));
const FOLDER = resolve(HERE, '..');
const sha256 = data => createHash('sha256').update(data).digest('hex');
const git = (args, options = {}) => execFileSync('git', ['-C', FOLDER, ...args], { maxBuffer: 1 << 30, ...options });

// The scopehaven folder's files at a commit: path (relative to the folder), git mode and content.
export function filesAt(commit) {
  const prefix = git(['rev-parse', '--show-prefix'], { encoding: 'utf8' }).trim();
  const listing = git(['ls-tree', '-r', '-z', '--full-name', commit, '--', '.'], { encoding: 'utf8' }).split('\0').filter(Boolean);
  const entries = listing.map(line => {
    const [meta, full] = line.split('\t');
    const [mode, type, object] = meta.split(' ');
    if (type !== 'blob') throw new Error(`unsupported tree entry ${type} at ${full}`);
    if (mode === '120000') throw new Error(`symbolic link at ${full}: the release format carries files only`);
    if (!full.startsWith(prefix)) throw new Error(`git ls-tree listed ${full} outside ${prefix}`);
    return { path: full.slice(prefix.length), mode, object };
  });
  const out = git(['cat-file', '--batch'], { input: entries.map(e => e.object).join('\n') + '\n' });
  let at = 0;
  for (const entry of entries) {
    const end = out.indexOf(10, at);
    const [object, , size] = out.subarray(at, end).toString().split(' ');
    if (object !== entry.object) throw new Error(`git cat-file answered ${object} for ${entry.object}`);
    entry.content = out.subarray(end + 1, end + 1 + Number(size));
    at = end + 1 + Number(size) + 1;
  }
  return entries;
}

// ustar, with the long-name prefix field; a path that cannot be split fails rather than being truncated.
function tarHeader(name, size, mode, mtime, type = '0') {
  const header = Buffer.alloc(512);
  let prefix = '', base = name;
  if (Buffer.byteLength(name) > 100) {
    const cut = name.lastIndexOf('/', 155);
    if (cut <= 0 || Buffer.byteLength(name.slice(cut + 1)) > 100) throw new Error(`path too long for ustar: ${name}`);
    prefix = name.slice(0, cut); base = name.slice(cut + 1);
  }
  const put = (text, offset, length) => header.write(text, offset, length, 'utf8');
  const octal = (value, length) => value.toString(8).padStart(length - 1, '0') + '\0';
  put(base, 0, 100); put(octal(mode, 8), 100, 8); put(octal(0, 8), 108, 8); put(octal(0, 8), 116, 8);
  put(octal(size, 12), 124, 12); put(octal(mtime, 12), 136, 12); put('        ', 148, 8); put(type, 156, 1);
  put('ustar\0', 257, 6); put('00', 263, 2); put(prefix, 345, 155);
  let sum = 0; for (const byte of header) sum += byte;
  put(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8);
  return header;
}
export function tarball(root, files, mtime) {
  const parts = [], dirs = new Set();
  const addDir = dir => {
    if (!dir || dirs.has(dir)) return;
    addDir(dir.includes('/') ? dir.slice(0, dir.lastIndexOf('/')) : '');
    dirs.add(dir); parts.push(tarHeader(`${root}/${dir}/`, 0, 0o755, mtime, '5'));
  };
  parts.push(tarHeader(`${root}/`, 0, 0o755, mtime, '5'));
  for (const file of [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))) {
    addDir(file.path.includes('/') ? file.path.slice(0, file.path.lastIndexOf('/')) : '');
    parts.push(tarHeader(`${root}/${file.path}`, file.content.length, file.mode === '100755' ? 0o755 : 0o644, mtime));
    parts.push(file.content, Buffer.alloc((512 - (file.content.length % 512)) % 512));
  }
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts), { level: 9 });
}

export function manifest({ version, commit, commitTime, files, left, edits = [] }) {
  return {
    schema: MANIFEST_SCHEMA, name: 'scopehaven', version, commit, commitTime: new Date(commitTime * 1000).toISOString(),
    scope: 'The scopehaven folder at this commit, minus the excluded patterns. ./scopehaven doctor checks every file below.',
    excluded: { patterns: EXCLUDE, files: left },
    releaseEdits: { why: 'These files differ from git on the listed constants and relative paths only: each now names a folder inside the install that never exists, in place of a folder on the machine that built the target or in the repository beside the scopehaven folder.', files: edits },
    files: files.map(f => ({ path: f.path, mode: f.mode === '100755' ? '755' : '644', size: f.content.length, sha256: sha256(f.content) })),
  };
}

function parseArgs(argv) {
  const o = { commit: 'HEAD', out: join(FOLDER, 'artifacts', 'release'), npm: false, signKey: null, ledger: join(FOLDER, SIGNED_LEDGER), node: process.execPath };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i], value = () => { if (i + 1 >= argv.length) throw new Error(`${flag} needs a value`); return argv[++i]; };
    if (flag === '--commit') o.commit = value();
    else if (flag === '--out') o.out = resolve(value());
    else if (flag === '--npm') o.npm = true;
    else if (flag === '--sign-key') o.signKey = resolve(value());
    else if (flag === '--signed-ledger') o.ledger = resolve(value());
    else if (flag === '--help' || flag === '-h') o.help = true;
    else throw new Error(`unknown option ${flag}`);
  }
  return o;
}
const USAGE = 'Usage: node packaging/build-release.mjs [--commit REV] [--out DIR] [--npm] [--sign-key /path/outside/the/repo/key] [--signed-ledger FILE]';

export function main(argv = process.argv.slice(2), say = line => console.log(line)) {
  const o = parseArgs(argv);
  if (o.help) { say(USAGE); return 0; }
  const repoRoot = git(['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
  if (o.signKey) {
    const rel = relative(repoRoot, o.signKey);
    if (!rel.startsWith('..') && !isAbsolute(rel)) throw new Error('--sign-key is inside the repository; keep the private key outside it');
    if (!existsSync(o.signKey)) throw new Error('--sign-key does not exist');
    if ((statSync(o.signKey).mode & 0o077) !== 0) throw new Error('--sign-key is readable by other users; chmod 600 it');
  }
  const commit = git(['rev-parse', '--verify', `${o.commit}^{commit}`], { encoding: 'utf8' }).trim();
  const commitTime = Number(git(['show', '-s', '--format=%ct', commit], { encoding: 'utf8' }).trim());
  const all = filesAt(commit);
  const pkgJson = JSON.parse(all.find(f => f.path === 'package.json').content.toString());
  const { version } = pkgJson;
  if (o.signKey) {
    const earlier = signedConflict(JSON.parse(readFileSync(o.ledger, 'utf8')), version, commit);
    if (earlier) throw new Error(`version ${version} was already signed for commit ${earlier.commit}; bump package.json's version before signing ${commit}`);
  }
  const kept = all.filter(f => !excluded(f.path));
  const left = all.length - kept.length;
  const { files, edits } = applyReleaseEdits(kept);
  const name = artifactName(version, commit);
  // The SBOM and VEX are generated from the same commit and listed in the manifest like any shipped file.
  const { snapshot, lists } = reviewedLists(files);
  const json = (path, value) => ({ path, mode: '100644', content: Buffer.from(JSON.stringify(value, null, 2) + '\n') });
  const generated = [json(SBOM_NAME, sbom({ version, commit, commitTime, files }))];
  if (lists.length) generated.push(json(VEX_NAMES.cyclonedx, vexCycloneDX({ version, commit, commitTime, snapshot, lists })),
    json(VEX_NAMES.openvex, vexOpen({ version, commit, commitTime, snapshot, lists })));
  const content = [...files, ...generated];
  const homes = homePathFiles(content);
  if (homes.length) throw new Error(`${homes.length} shipped files name a home folder, first ${homes.slice(0, 5).join(', ')}; leave them out or fix them`);
  const climbs = climbingFiles(content);
  if (climbs.length) throw new Error(`${climbs.length} shipped files climb out of the folder by a relative path, first ${climbs.slice(0, 5).join(', ')}; release-edit them or leave them out`);
  // ownerFiles() stays available for a private build; the open edition's README names its own GitHub owner on purpose.
  const record = manifest({ version, commit, commitTime, files: content, left, edits });
  const shipped = [...content, { path: MANIFEST_NAME, mode: '100644', content: Buffer.from(JSON.stringify(record, null, 2) + '\n') }];
  const thirdParty = { advisoriesQueriedAt: snapshot?.queriedAt ?? null, lists: lists.map(l => ({ path: l.path, packages: l.packages.length,
    withAdvisories: l.packages.filter(p => p.advisories.length).length, advisories: l.packages.reduce((n, p) => n + p.advisories.length, 0), vex: 'not_affected' })) };

  mkdirSync(o.out, { recursive: true, mode: 0o700 });
  // Artifacts of other commits go too: SHA256SUMS describes this build only.
  const stale = readdirSync(o.out).filter(file => /^scopehaven-.*\.(?:tar\.gz|tgz)$/.test(file));
  for (const file of [...stale, 'SHA256SUMS', 'SHA256SUMS.sig', 'release.json']) rmSync(join(o.out, file), { force: true });
  const artifacts = [];
  const tar = tarball(name, shipped, commitTime);
  writeFileSync(join(o.out, `${name}.tar.gz`), tar);
  artifacts.push({ file: `${name}.tar.gz`, bytes: tar.length, sha256: sha256(tar), install: `tar -xzf ${name}.tar.gz && cd ${name} && ./scopehaven doctor` });
  say(`tarball  ${name}.tar.gz  ${files.length} files + ${generated.length} generated + manifest, ${left} left out, ${(tar.length / 1048576).toFixed(1)} MiB`);
  for (const l of thirdParty.lists) say(`vex      ${l.path}: ${l.packages} packages, ${l.advisories} advisories (OSV ${thirdParty.advisoriesQueriedAt}), all not_affected`);

  if (o.npm) {
    // npm pack over an extracted copy of the shipped files; package.json "files" must then keep exactly those.
    const npm = join(dirname(o.node), 'npm');
    if (!existsSync(npm)) throw new Error(`--npm needs npm beside the selected Node (${npm})`);
    const stage = mkdtempSync(join(tmpdir(), 'scopehaven-release-'));
    try {
      const pkg = join(stage, 'package');
      for (const file of shipped) {
        mkdirSync(dirname(join(pkg, file.path)), { recursive: true });
        writeFileSync(join(pkg, file.path), file.content); chmodSync(join(pkg, file.path), file.mode === '100755' ? 0o755 : 0o644);
      }
      const packed = spawnSync(npm, ['pack', '--json', '--pack-destination', stage], { cwd: pkg, encoding: 'utf8', env: { ...process.env, PATH: `${dirname(o.node)}:${process.env.PATH}`, npm_config_update_notifier: 'false', npm_config_fund: 'false', npm_config_audit: 'false' } });
      if (packed.status !== 0) throw new Error(`npm pack failed: ${packed.stderr.trim().split('\n').slice(-3).join(' ')}`);
      const [info] = JSON.parse(packed.stdout);
      const inPack = new Set(info.files.map(f => f.path));
      const missing = shipped.filter(f => !inPack.has(f.path)).map(f => f.path);
      if (missing.length) throw new Error(`npm pack left out ${missing.length} shipped files, first ${missing[0]}; check package.json "files"`);
      const tgz = readFileSync(join(stage, info.filename));
      writeFileSync(join(o.out, `${name}.tgz`), tgz);
      artifacts.push({ file: `${name}.tgz`, bytes: tgz.length, sha256: sha256(tgz), install: `npm install --no-save ./${name}.tgz && npx scopehaven doctor`, npmVersion: spawnSync(npm, ['--version'], { encoding: 'utf8' }).stdout.trim() });
      say(`npm      ${name}.tgz  ${info.entryCount} entries (${pkgJson.private ? 'private: true, so npm refuses to publish it' : 'publishable: see packaging/RELEASE.md'})`);
    } finally { rmSync(stage, { recursive: true, force: true }); }
  }

  const sums = artifacts.map(a => `${a.sha256}  ${a.file}`).join('\n') + '\n';
  writeFileSync(join(o.out, 'SHA256SUMS'), sums);
  let signature = null;
  if (o.signKey) {
    const signed = spawnSync('ssh-keygen', ['-Y', 'sign', '-f', o.signKey, '-n', SIGNATURE_NAMESPACE, join(o.out, 'SHA256SUMS')], { encoding: 'utf8' });
    if (signed.status !== 0) throw new Error(`ssh-keygen -Y sign failed: ${signed.stderr.trim()}`);
    const publicKey = existsSync(`${o.signKey}.pub`) ? readFileSync(`${o.signKey}.pub`, 'utf8').trim().split(/\s+/).slice(0, 2).join(' ') : null;
    const fingerprint = publicKey ? spawnSync('ssh-keygen', ['-l', '-f', `${o.signKey}.pub`], { encoding: 'utf8' }).stdout.trim().split(/\s+/)[1] : null;
    signature = { file: 'SHA256SUMS.sig', namespace: SIGNATURE_NAMESPACE, tool: 'ssh-keygen -Y sign (OpenSSH)', publicKey, fingerprint };
    say(`signed   SHA256SUMS.sig  ${fingerprint ?? '(no .pub beside the key)'}`);
    say(`record   add {"version": "${version}", "commit": "${commit}"} to ${SIGNED_LEDGER} if it is not there, and commit it`);
  } else say('unsigned no --sign-key: SHA256SUMS is written but not signed');
  writeFileSync(join(o.out, 'release.json'), JSON.stringify({ schema: 'scopehaven-release/1', name: 'scopehaven', version, commit,
    commitTime: record.commitTime, artifacts, signature, excluded: record.excluded, releaseEdits: edits, thirdParty, manifest: { name: MANIFEST_NAME, files: record.files.length, sha256: sha256(shipped.at(-1).content) } }, null, 2) + '\n');
  say(`commit   ${commit}`);
  say(`out      ${o.out}`);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = main(); } catch (error) { console.error(`build-release: ${error.message}`); console.error(USAGE); process.exitCode = 2; }
}
