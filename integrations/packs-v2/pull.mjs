// Pack updates in CI: how a profile's pinned packs stand against the packs this checkout ships, and a pulled copy of the
// profile that takes each newer compatible version, locked through the same gate a person's `pack lock` keeps.
//   packStatus(profileFile)          every reference's pinned and shipped version and its state, and the shipped packs the
//                                    profile does not use (a new intake pack needs its parameters once, so it is listed, not added)
//   pullProfile(profileFile, outDir) a copy of the profile in outDir (a new directory), each "pull" reference moved to the
//                                    shipped version, with that copy's own scopehaven.lock
// One version of each pack ships at a time (packs/<name>/), so a pin older than the shipped version no longer loads
// (pack-version-mismatch). A reference reads:
//   current  the pin is the shipped version
//   pull     the shipped version is newer in the same major: pullProfile takes it
//   major    the shipped version is a newer major, whose parameters may differ: never pulled
//   older    the shipped version is older than the pin: this checkout predates the profile
//   local    an operator's own pack ("from"): never pulled, and a profile with one is not pulled when another pin would be
//   missing  no shipped pack has the name
// The committed profile and lock are never written. The pull runs the lock step itself (each pack's own cases, then the
// load gate), so a pulled version that would not load for this profile is refused, not run. Nothing here contacts a target.
import { lstat, mkdir, readdir, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { readPack, PackError } from './pack.mjs';
import { lockProfile, readProfileFile, usesPacks, packDir, SHIPPED_PACKS } from './expand.mjs';
import { admitDraftedLines } from '../watch-first/lines.mjs';

export const STATUS_SCHEMA = 'scopehaven-pack-status/1';
export const PULL_SCHEMA = 'scopehaven-pack-pull/1';
export const STATES = Object.freeze(['current', 'pull', 'major', 'older', 'local', 'missing']);
const refuse = (code, detail) => { throw new PackError(code, detail); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const VERSION = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const numbers = version => VERSION.exec(version).slice(1).map(Number);

/** -1, 0 or 1. Both are MAJOR.MINOR.PATCH: packDir and the manifest check refuse anything else before this is called. */
export function compareVersions(a, b) {
  const [x, y] = [numbers(a), numbers(b)];
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}
export function stateOf(pinned, shipped) {
  if (shipped === null) return 'missing';
  const order = compareVersions(pinned, shipped);
  if (order === 0) return 'current';
  if (order > 0) return 'older';
  return numbers(pinned)[0] === numbers(shipped)[0] ? 'pull' : 'major';
}

async function readInput(profileFile) {
  // As a load reads it: a drafted line no one approved is refused here too, and approved lines lose their markers.
  const input = admitDraftedLines(await readProfileFile(profileFile));
  if (!usesPacks(input)) refuse('pack-reference-invalid', `${profileFile} references no packs`);
  return input;
}
const referencesOf = input => input.targets.flatMap(target => plain(target) && Array.isArray(target.packs) ? target.packs.map(ref => ({ target, ref })) : []);
async function shippedVersion(name, shipped) {
  try { return (await readPack(join(shipped, name))).manifest.version; }
  catch (error) { if (error.code === 'pack-file-missing') return null; throw error; }
}

/** shipped: the shipped packs' directory (a test points it at a copy). */
export async function packStatus(profileFile, { shipped = SHIPPED_PACKS } = {}) {
  const input = await readInput(profileFile), packs = [], used = new Set();
  for (const { target, ref } of referencesOf(input)) {
    packDir(plain(ref) ? ref : {}, profileFile, shipped); // the name and version are checked before either is used
    const entry = { target: target.id, as: ref.as, name: ref.name, pinned: ref.version };
    if (ref.from !== undefined) { packs.push({ ...entry, shipped: null, state: 'local' }); continue; }
    used.add(ref.name);
    const version = await shippedVersion(ref.name, shipped);
    packs.push({ ...entry, shipped: version, state: stateOf(ref.version, version) });
  }
  const unused = [];
  const names = (await readdir(shipped, { withFileTypes: true })).filter(d => d.isDirectory() && !used.has(d.name)).map(d => d.name).sort();
  for (const name of names) unused.push({ name, version: (await readPack(join(shipped, name))).manifest.version });
  return { schema: STATUS_SCHEMA, packs, unused };
}

/** Writes the pulled copy and its lock into outDir, which must not exist yet. With nothing to pull, writes nothing. */
export async function pullProfile(profileFile, outDir, { shipped = SHIPPED_PACKS } = {}) {
  const status = await packStatus(profileFile, { shipped });
  const held = status.packs.find(p => ['major', 'older', 'missing'].includes(p.state));
  if (held) refuse(`pack-pull-${held.state}`, held.state === 'missing' ? `no shipped pack is named ${held.name}`
    : `${held.name} is pinned at ${held.pinned} and ${held.shipped} ships; ${held.state === 'major' ? 'a new major version is taken by hand (its parameters may differ): edit the version, then pack lock --update' : 'this checkout is older than the profile'}`);
  const pulled = status.packs.filter(p => p.state === 'pull');
  if (!pulled.length) return { schema: PULL_SCHEMA, file: null, lockId: null, pulled: [] };
  // Only a copy would need the operator's own directory, so a local pack stops a pull only when something would be pulled.
  const local = status.packs.find(p => p.state === 'local');
  if (local) refuse('pack-pull-local', `${local.name} is read from the operator's own directory ("from"); a profile with one is not pulled, since its copy could not reach that directory`);
  let out = null;
  try { out = await lstat(outDir); } catch (error) { if (error.code !== 'ENOENT') throw error; await mkdir(outDir, { mode: 0o700 }); }
  if (out?.isSymbolicLink()) refuse('pack-pull-out-symlink', `${outDir} is a symbolic link; the copy goes in a new, empty directory`);
  if ((await readdir(outDir)).length) refuse('pack-pull-out-not-empty', `${outDir} must be a new, empty directory`);
  const input = await readInput(profileFile);
  for (const { target, ref } of referencesOf(input)) {
    const p = pulled.find(x => x.target === target.id && x.as === ref.as);
    if (p) ref.version = p.shipped;
  }
  const file = join(outDir, basename(profileFile));
  await writeFile(file, `${JSON.stringify(input, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  const { lock } = await lockProfile(file, { shipped });
  return { schema: PULL_SCHEMA, file, lockId: lock.lockId, pulled: pulled.map(({ target, as, name, pinned, shipped: to }) => ({ target, as, name, from: pinned, to })) };
}
