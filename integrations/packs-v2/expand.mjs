// Check packs in a profile: a target's "packs" references, the lockfile beside the profile, and the expansion every
// profile load runs (src/registry.mjs loadProfiles, so check-config, assess, gate and the dashboard all keep it).
//   "packs": [{ "name": "tenant-isolation", "version": "1.0.0", "as": "TI", "params": { ... }, "from": "packs" }]
// "from" (optional) is a directory, relative to the profile file, holding the operator's own packs (<from>/<name>/);
// without it the pack is one shipped in integrations/packs-v2/packs/. A check entry { "pack": "TI" } in the target's
// checks marks where that instance's checks go; without one they go after the target's own checks.
// scopehaven.lock (scopehaven-pack-lock/1), written by `scopehaven pack lock` in the profile's directory, pins each
// referenced pack: its name, version, where it came from, the sha256 of its manifest and of each file. A profile load
// refuses a pack missing from the lock, or whose manifest or files no longer have the locked digests.
// After expansion, the known-negative self-test (src/known-negative.mjs, LQ-5) runs over the target as loaded, and a
// pack check with any predicate not shown able to fail (cannot-fail, always-fails, unprovable or error; proven and
// pass-unreachable can fail) is refused, naming the predicate, its outcome and reason: a pack cannot load a check that
// cannot fail. The test runs with the profile's own observers, so a pack whose effect clauses this profile cannot
// observe is refused rather than run blind.
import { rename, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical, sha256 } from '../policy-import/matrix.mjs';
import { validateTargetFile } from '../../src/contracts.mjs';
import { knownNegativeTarget } from '../../src/known-negative.mjs';
import { postChangeChecks } from '../../src/http-lifecycle.mjs';
import { readPack, readRegular, instantiate, PackError } from './pack.mjs';
// A watch-first profile (integrations/watch-first/lines.mjs): its drafted lines are admitted first, as loadProfiles does.
import { admitDraftedLines } from '../watch-first/lines.mjs';

export const LOCK_SCHEMA = 'scopehaven-pack-lock/1';
export const LOCK_FILE = 'scopehaven.lock';
export const SHIPPED_PACKS = fileURLToPath(new URL('./packs/', import.meta.url));
// A pack check loads only when the self-test shows every one of its predicates able to fail.
export const CAN_FAIL = Object.freeze(['proven', 'pass-unreachable']);
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const refuse = (code, detail) => { throw new PackError(code, detail); };

export const usesPacks = input => plain(input) && Array.isArray(input.targets) && input.targets.some(t => plain(t) && Object.hasOwn(t, 'packs'));

/** Where a reference's pack lives. shipped: the shipped packs' directory (a test points it at a copy; a load never does). */
export function packDir(ref, profileFile, shipped = SHIPPED_PACKS) {
  // The name and version are checked before either is used in a path.
  if (!/^[a-z][a-z0-9-]{1,47}$/.test(ref.name) || !/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ref.version)) refuse('pack-reference-invalid', 'a reference names a pack (2-48 lower-case letters, digits or "-") and a version (MAJOR.MINOR.PATCH)');
  if (ref.from === undefined) return join(shipped, ref.name);
  if (typeof ref.from !== 'string' || !ref.from.length || isAbsolute(ref.from) || ref.from.includes('\0')) refuse('pack-reference-invalid', `${ref.name}: "from" is a directory relative to the profile file`);
  return join(resolve(dirname(profileFile), ref.from), ref.name);
}
const lockKey = ref => `${ref.name}@${ref.version}${ref.from === undefined ? '' : ` from ${ref.from}`}`;

function references(input) {
  const refs = [];
  for (const target of input.targets) {
    if (!plain(target) || !Object.hasOwn(target, 'packs')) continue;
    if (!Array.isArray(target.packs) || !target.packs.length || target.packs.length > 16) refuse('pack-reference-invalid', `target ${JSON.stringify(target.id)}: "packs" is a list of 1 to 16 references`);
    const as = new Set();
    for (const ref of target.packs) {
      if (!plain(ref) || Object.keys(ref).some(k => !['name', 'version', 'as', 'params', 'from'].includes(k)) || typeof ref.name !== 'string' || typeof ref.version !== 'string') refuse('pack-reference-invalid', `target ${JSON.stringify(target.id)}: a reference is { name, version, as, params?, from? }`);
      if (as.has(ref.as)) refuse('pack-reference-invalid', `target ${JSON.stringify(target.id)}: two references use "as" ${JSON.stringify(ref.as)}`);
      as.add(ref.as); refs.push({ target, ref });
    }
  }
  return refs;
}

// lockId is a checksum: it catches an accidental edit or drift, not a deliberate re-seal. Like the packs, the lock is not signed.
async function readLock(profileFile) {
  const path = join(dirname(profileFile), LOCK_FILE);
  let bytes;
  try { bytes = await readRegular(path, { limit: 262144, missing: 'pack-lock-missing', invalid: 'pack-lock-invalid' }); }
  catch (error) { if (error.code === 'pack-lock-missing') refuse('pack-lock-missing', `the profile references packs and ${path} does not exist; run "scopehaven pack lock --config ${profileFile}"`); throw error; }
  let lock;
  try { lock = JSON.parse(bytes.toString('utf8')); } catch { refuse('pack-lock-invalid', `${path} is not valid JSON`); }
  const { lockId, ...body } = lock ?? {};
  if (lock?.schema !== LOCK_SCHEMA || !Array.isArray(lock.packs) || lockId !== sha256(canonical(body))) refuse('pack-lock-invalid', `${path} is not a ${LOCK_SCHEMA} lock, or was edited without recomputing its lockId`);
  return lock;
}
/** A profile file, read as a load reads it: a regular file of at most 2 MiB, never through a link. */
export async function readProfileFile(profileFile) {
  const bytes = await readRegular(profileFile, { limit: 2097152, missing: 'pack-reference-invalid', invalid: 'pack-reference-invalid' });
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { refuse('pack-reference-invalid', `${profileFile} is not valid JSON`); }
}

/** Each referenced pack read and checked against its own manifest: [{ target, ref, pack, entry }]. */
async function resolved(input, profileFile, shipped = SHIPPED_PACKS) {
  return Promise.all(references(input).map(async ({ target, ref }) => {
    const pack = await readPack(packDir(ref, profileFile, shipped));
    if (pack.manifest.name !== ref.name || pack.manifest.version !== ref.version) refuse('pack-version-mismatch', `${lockKey(ref)} is referenced, but that directory holds ${pack.manifest.name}@${pack.manifest.version}`);
    const entry = { name: ref.name, version: ref.version, from: ref.from ?? null, manifest: pack.digests.manifest, files: pack.digests.files };
    return { target, ref, pack, entry };
  }));
}

/** The document with every target's packs expanded into ordinary checks, as the validator reads a hand-written profile. */
export async function expandPacks(input, { profileFile }) {
  if (!usesPacks(input)) return input;
  if (typeof profileFile !== 'string') refuse('pack-lock-missing', 'a profile with packs is read from a file, beside its scopehaven.lock');
  const items = await resolved(input, profileFile), lock = await readLock(profileFile);
  for (const { ref, entry } of items) {
    const locked = lock.packs.find(p => p.name === entry.name && p.version === entry.version && (p.from ?? null) === entry.from);
    if (!locked) refuse('pack-not-locked', `${lockKey(ref)} is not in ${LOCK_FILE}; run "scopehaven pack lock"`);
    if (locked.manifest !== entry.manifest || canonical(locked.files) !== canonical(entry.files)) refuse('pack-digest-mismatch', `${lockKey(ref)} no longer has the digests ${LOCK_FILE} pins (manifest or files changed since it was locked)`);
  }
  return expandResolved(input, items);
}

// Instantiation, placement and the self-test gate, from packs already read and checked.
function expandResolved(input, items) {
  const copy = structuredClone(input), packChecks = new Map();
  for (const [t, target] of copy.targets.entries()) {
    if (!plain(target) || !Object.hasOwn(target, 'packs')) continue;
    const mine = items.filter(i => i.target === input.targets[t]);
    const instances = new Map(mine.map(({ ref, pack }) => [ref.as, instantiate(pack, ref, target)]));
    const placed = new Set(), checks = [];
    for (const check of Array.isArray(target.checks) ? target.checks : []) {
      if (plain(check) && Object.keys(check).length === 1 && Object.hasOwn(check, 'pack')) {
        if (!instances.has(check.pack) || placed.has(check.pack)) refuse('pack-reference-invalid', `target ${JSON.stringify(target.id)}: a { "pack": ${JSON.stringify(check.pack)} } entry names no reference, or names one twice`);
        placed.add(check.pack); checks.push(...instances.get(check.pack).checks);
      } else checks.push(check);
    }
    for (const [as, instance] of instances) if (!placed.has(as)) checks.push(...instance.checks);
    target.checks = checks;
    // A pack's account change makes every later check of that actor a post-change check (src/http-lifecycle.mjs): it must
    // reach only the pack's own checks, never one of the profile's.
    for (const [as, instance] of instances) {
      const own = new Set(instance.checks.map(c => c.id));
      for (const entry of instance.lifecycle) {
        const foreign = postChangeChecks(checks, entry).map(c => c.id).filter(id => !own.has(id));
        if (foreign.length) refuse('pack-reference-invalid', `target ${JSON.stringify(target.id)}: pack instance ${as}'s account change (${entry.changeCheckId}) would make ${foreign.join(', ')} post-change checks of ${entry.actorId}; place { "pack": ${JSON.stringify(as)} } after every other check of that actor`);
      }
    }
    target.requiredControlIds = [...new Set([...(Array.isArray(target.requiredControlIds) ? target.requiredControlIds : []), ...[...instances.values()].flatMap(i => i.requiredControlIds)])];
    const lifecycle = [...instances.values()].flatMap(i => i.lifecycle);
    if (lifecycle.length) target.lifecycle = [...(Array.isArray(target.lifecycle) ? target.lifecycle : []), ...lifecycle];
    delete target.packs;
    packChecks.set(target.id, new Map([...instances].flatMap(([as, i]) => i.checks.map(c => [c.id, `${mine.find(m => m.ref.as === as).ref.name} as ${as}`]))));
  }
  const targets = validateTargetFile(copy);
  for (const target of targets) {
    const fromPacks = packChecks.get(target.id);
    if (!fromPacks?.size) continue;
    const report = knownNegativeTarget(target);
    // A check declared not applicable is never sent, so it can never fail (templates cannot declare one; this holds anyway).
    const inapplicable = target.checks.filter(c => fromPacks.has(c.id) && c.applicability?.applies === false).map(c => c.id);
    if (inapplicable.length) refuse('pack-check-cannot-fail', `${inapplicable.join(', ')} declared not applicable: a pack check is always applicable`);
    const bad = report.checks.filter(c => fromPacks.has(c.id) && (!Array.isArray(c.predicates) || !c.predicates.length || c.predicates.some(p => !CAN_FAIL.includes(p.outcome))));
    if (bad.length) refuse('pack-check-cannot-fail', bad.map(c => `${c.id} (${fromPacks.get(c.id)}) reads ${c.outcome} in the known-negative self-test: ${(c.predicates ?? []).filter(p => !CAN_FAIL.includes(p.outcome)).map(p => `${p.kind} ${p.outcome}${p.reason ? ` (${p.reason})` : ''}`).join(', ')}`).join('; ') + ': a pack cannot load a check that is not shown able to fail');
  }
  return copy;
}

/** A pack's own self-test cases: each case's parameters instantiated in the case target, and the known-negative outcome of
 * every check compared with the one the case expects. Returns [{ id, ok, outcomes, expected }]. */
export function runCases(pack) {
  return pack.cases.cases.map(c => {
    const target = structuredClone(pack.cases.target);
    const { checks, requiredControlIds, lifecycle } = instantiate(pack, { name: pack.manifest.name, version: pack.manifest.version, as: c.as, params: c.params }, target);
    target.checks = [...(target.checks ?? []), ...checks];
    if (lifecycle.length) target.lifecycle = [...(target.lifecycle ?? []), ...lifecycle];
    target.requiredControlIds = [...new Set([...(target.requiredControlIds ?? []), ...requiredControlIds])];
    const [validated] = validateTargetFile({ schemaVersion: 1, targets: [target] });
    const outcomes = Object.fromEntries(knownNegativeTarget(validated).checks.filter(k => checks.some(x => x.id === k.id)).map(k => [k.id, k.outcome]));
    return { id: c.id, ok: canonical(outcomes) === canonical(c.expect), outcomes, expected: c.expect };
  });
}

/** Writes scopehaven.lock beside the profile: every referenced pack read, its own cases passed, and the profile expanded
 * through the same gate a load keeps, so no lock is written for a profile that would not load. replace: overwrite an
 * existing lock (through a new file and a rename); otherwise an existing lock is never overwritten. */
export async function lockProfile(profileFile, { replace = false, shipped = SHIPPED_PACKS } = {}) {
  let input = await readProfileFile(profileFile);
  // As a load reads it: a drafted line no one approved is refused here too, and approved lines lose their markers.
  input = admitDraftedLines(input);
  if (!usesPacks(input)) refuse('pack-reference-invalid', `${profileFile} references no packs`);
  const items = await resolved(input, profileFile, shipped), seen = new Map();
  for (const { pack, entry } of items) {
    const key = canonical([entry.name, entry.version, entry.from]);
    if (seen.has(key)) continue;
    const failed = runCases(pack).filter(r => !r.ok);
    if (failed.length) refuse('pack-cases-failed', `${entry.name}@${entry.version}: self-test case(s) ${failed.map(f => `${f.id} read ${canonical(f.outcomes)}, expected ${canonical(f.expected)}`).join('; ')}`);
    seen.set(key, { ...entry, selfTest: { cases: pack.cases.cases.length, passed: pack.cases.cases.length } });
  }
  expandResolved(input, items);
  // One lock serves every profile in its directory: --update keeps the entries other profiles there pinned (a valid lock's
  // entries for packs this profile does not reference), so relocking one profile never unlocks another.
  // An existing lock that is not valid is refused rather than silently replaced (its other profiles' pins would vanish).
  const kept = [];
  if (replace) {
    let old = null;
    try { old = await readLock(profileFile); } catch (error) { if (error.code !== 'pack-lock-missing') refuse('pack-lock-invalid', `the existing ${LOCK_FILE} cannot be read (${error.message}); remove it to lock from scratch`); }
    for (const p of old?.packs ?? []) { const key = canonical([p.name, p.version, p.from ?? null]); if (!seen.has(key)) { seen.set(key, p); kept.push(`${p.name}@${p.version}${p.from ? ` from ${p.from}` : ''}`); } }
  }
  const body = { schema: LOCK_SCHEMA, packs: [...seen.values()].sort((a, b) => canonical([a.name, a.version, a.from]).localeCompare(canonical([b.name, b.version, b.from]))) };
  const lock = { ...body, lockId: sha256(canonical(body)) }, path = join(dirname(profileFile), LOCK_FILE);
  const text = `${JSON.stringify(lock, null, 2)}\n`;
  if (!replace) await writeFile(path, text, { flag: 'wx', mode: 0o600 });
  else { const next = `${path}.${process.pid}.new`; await writeFile(next, text, { flag: 'wx', mode: 0o600 }); await rename(next, path); }
  return { path, lock, kept };
}
