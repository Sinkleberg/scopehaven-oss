// Check pack CLI.
//   ./scopehaven pack list                         the shipped packs: name, version, behaviour, parameters
//   ./scopehaven pack show NAME                    one shipped pack's manifest and check templates
//   ./scopehaven pack lock --config PROFILE [--update]   write scopehaven.lock beside the profile
//   ./scopehaven pack verify --config PROFILE      check the profile's packs against its lock, as a load does
//   ./scopehaven pack status --config PROFILE      each pinned pack against the shipped version, and the shipped packs not used
//   ./scopehaven pack pull --config PROFILE --out DIR   a copy of the profile in DIR taking each newer same-major version, locked
//   ./scopehaven pack seal DIR                     for a pack's author: write the sha256 of its files into its manifest
// lock reads every pack the profile references, runs each pack's own known-negative self-test cases, expands the profile
// through the gate a load keeps, and only then writes the lock (a new file; --update replaces an existing one). verify
// and status write nothing; pull writes only into DIR (pull.mjs). Exit codes: 0 done; 2 usage, file or validation error, or a refusal.
// Nothing here contacts a target: the self-test is pure.
import { readdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { readPack, readRegular, validateManifest, validateTemplates, validateCases, sha256Hex, PACK_FILES } from './pack.mjs';
import { expandPacks, lockProfile, readProfileFile, runCases, usesPacks, SHIPPED_PACKS } from './expand.mjs';
import { packStatus, pullProfile } from './pull.mjs';
import { admitDraftedLines } from '../watch-first/lines.mjs';
import { assertRuntime } from '../../src/runtime.mjs';

const USAGE = 'Usage: pack list | show NAME | lock --config PROFILE [--update] | verify --config PROFILE | status --config PROFILE | pull --config PROFILE --out DIR | seal DIR';

function parse(argv) {
  const flags = {}, positional = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--update') { flags.update = true; continue; }
    if (argv[i].startsWith('--')) { const value = argv[i + 1]; if (value === undefined || value.startsWith('--')) throw new Error(`${argv[i]} needs a value.`); if (Object.hasOwn(flags, argv[i].slice(2))) throw new Error(`${argv[i]} is given twice.`); flags[argv[i].slice(2)] = value; i++; }
    else positional.push(argv[i]);
  }
  return { flags, positional };
}
const only = (flags, allowed) => { const extra = Object.keys(flags).find(f => !allowed.includes(f)); if (extra) throw new Error(`Unsupported option --${extra}.`); };

export async function main(argv, { log = console.log } = {}) {
  const [command, ...rest] = argv;
  const { flags, positional } = parse(rest);
  if (command === 'list') {
    only(flags, []);
    const names = (await readdir(SHIPPED_PACKS, { withFileTypes: true })).filter(d => d.isDirectory()).map(d => d.name).sort();
    const packs = [];
    for (const name of names) {
      const pack = await readPack(join(SHIPPED_PACKS, name));
      packs.push({ name, version: pack.manifest.version, behaviour: pack.manifest.behaviour, parameters: Object.fromEntries(Object.entries(pack.manifest.parameters).map(([k, p]) => [k, `${p.type}${p.optional ? ', optional' : Object.hasOwn(p, 'default') ? `, default ${JSON.stringify(p.default)}` : ''}`])), selfTest: runCases(pack).map(r => `${r.id}: ${r.ok ? 'as expected' : 'DIFFERS'}`) });
    }
    log(JSON.stringify({ packs }, null, 2));
    return 0;
  }
  if (command === 'show') {
    only(flags, []);
    if (positional.length !== 1 || !/^[a-z][a-z0-9-]{1,47}$/.test(positional[0])) throw new Error(USAGE);
    const pack = await readPack(join(SHIPPED_PACKS, positional[0]));
    log(JSON.stringify({ manifest: pack.manifest, checks: pack.checks, digests: pack.digests }, null, 2));
    return 0;
  }
  if (command === 'lock') {
    only(flags, ['config', 'update']);
    if (!flags.config || positional.length) throw new Error(USAGE);
    const { path, lock, kept } = await lockProfile(resolve(flags.config), { replace: flags.update === true });
    // kept: the entries an --update carried over for the other profiles in this directory (no entry is ever pruned).
    log(JSON.stringify({ lock: path, lockId: lock.lockId, packs: lock.packs.map(p => `${p.name}@${p.version}${p.from ? ` from ${p.from}` : ''}: self-test ${p.selfTest.passed}/${p.selfTest.cases}`), ...(kept.length ? { keptForOtherProfiles: kept } : {}) }, null, 2));
    return 0;
  }
  if (command === 'verify') {
    only(flags, ['config']);
    if (!flags.config || positional.length) throw new Error(USAGE);
    const file = resolve(flags.config);
    const input = admitDraftedLines(await readProfileFile(file));
    if (!usesPacks(input)) throw new Error(`${file} references no packs: nothing to verify.`);
    const expanded = await expandPacks(input, { profileFile: file });
    log(JSON.stringify({ verified: true, targets: expanded.targets.map(t => ({ id: t.id, checks: t.checks.length })) }, null, 2));
    return 0;
  }
  if (command === 'status') {
    only(flags, ['config']);
    if (!flags.config || positional.length) throw new Error(USAGE);
    log(JSON.stringify(await packStatus(resolve(flags.config)), null, 2));
    return 0;
  }
  if (command === 'pull') {
    only(flags, ['config', 'out']);
    if (!flags.config || !flags.out || positional.length) throw new Error(USAGE);
    log(JSON.stringify(await pullProfile(resolve(flags.config), resolve(flags.out)), null, 2));
    return 0;
  }
  if (command === 'seal') {
    only(flags, []);
    if (positional.length !== 1) throw new Error(USAGE);
    // Everything is checked in memory first (manifest, templates, cases, and the pack's own cases run); the manifest is written
    // only when all of it holds, so a failed seal leaves the pack as it was.
    const dir = resolve(positional[0]), path = join(dir, 'manifest.json');
    const parse = (bytes, name) => { try { return JSON.parse(bytes.toString('utf8')); } catch { throw new Error(`${join(dir, name)} is not valid JSON.`); } };
    const manifest = parse(await readRegular(path), 'manifest.json'), files = {}, docs = {};
    for (const name of PACK_FILES) { const bytes = await readRegular(join(dir, name)); files[name] = sha256Hex(bytes); docs[name] = parse(bytes, name); }
    manifest.files = files;
    validateManifest(manifest);
    const pack = { manifest, checks: validateTemplates(docs['checks.json'], manifest), cases: validateCases(docs['cases.json'], manifest) };
    const failed = runCases(pack).filter(r => !r.ok);
    if (failed.length) { log(JSON.stringify({ sealed: false, selfTest: failed.map(f => `${f.id}: read ${JSON.stringify(f.outcomes)}, expected ${JSON.stringify(f.expected)}`) }, null, 2)); return 2; }
    await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`);
    log(JSON.stringify({ sealed: path, files, selfTest: 'every case as expected' }, null, 2));
    return 0;
  }
  throw new Error(USAGE);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { assertRuntime(); process.exitCode = await main(process.argv.slice(2)); }
  catch (error) { console.error(`pack: ${error.message}`); process.exitCode = 2; }
}
