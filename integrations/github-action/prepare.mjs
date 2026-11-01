#!/usr/bin/env node
// Small helpers for the Scopehaven composite action. Zero dependencies; local
// files only. Each subcommand prints a single identifier and nothing from the
// profile or run besides it. Errors are generic so no file content is echoed.
//   target-id --profile FILE [--target ID]  -> the target id to assess
//   run-id --from FILE                      -> run id from assess stdout or a gate summary
//   seed-baseline --run FILE --gate-dir DIR -> baseline id, after seeding a new gate store
import { constants, lstatSync, readFileSync } from 'node:fs';
import { lstat, mkdir, open } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { digest } from '../../src/domain.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TARGET = /^[A-Za-z0-9_-]{1,80}$/;
// Must equal the marker in ../regression-gate/gate.mjs (asserted by action.test.mjs).
export const GATE_MARKER = '.scopehaven-regression-gate';
export const GATE_MARKER_TEXT = 'scopehaven-regression-gate/1\n';
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const fail = message => { throw new Error(message); };

function readBoundedJson(path, maxBytes) {
  let stat;
  try { stat = lstatSync(path); } catch { fail('file is unavailable'); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxBytes) fail('file must be a regular, bounded file and not a symlink');
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { fail('file is not valid JSON'); }
}

export function targetId({ profile, target }) {
  if (target) { if (!TARGET.test(target)) fail('target must be a target identifier'); return target; }
  const input = readBoundedJson(resolve(profile), 262144);
  const ids = object(input) && Array.isArray(input.targets) ? input.targets.map(row => row?.id) : [];
  if (ids.length !== 1 || !TARGET.test(ids[0] ?? '')) fail('set the target input: the profile must define exactly one target to infer it');
  return ids[0];
}

export function runId({ from }) {
  const input = readBoundedJson(resolve(from), 1024 * 1024);
  const id = object(input?.current) ? input.current.runId : input?.id;
  return typeof id === 'string' && UUID.test(id) ? id : '';
}

/** Reconstruct the immutable store record from a store file or an exported run, and verify its digest. */
export function baselineRecord(input) {
  let core, sha256;
  if (object(input) && object(input.core)) ({ core, sha256 } = input);
  else if (object(input) && object(input.integrity)) { const { integrity, notes, ...rest } = input; core = rest; sha256 = integrity.sha256; }
  else fail('baseline-run must be a saved run (a run.json export or a store runs/<id>.json file)');
  if (core.schemaVersion !== 1 || !UUID.test(core.id ?? '') || !Array.isArray(core.results)) fail('baseline-run is not a saved native run');
  if (typeof sha256 !== 'string' || digest(core) !== sha256) fail('baseline-run failed its evidence integrity check');
  return { core, sha256 };
}

async function writePrivate(path, content) {
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(content); await handle.sync(); } finally { await handle.close(); }
}

/** Create a new dedicated gate directory holding only the verified baseline. */
export async function seedBaseline({ run, gateDir }) {
  const record = baselineRecord(readBoundedJson(resolve(run), 2 * 1024 * 1024));
  const directory = resolve(gateDir);
  let exists = true;
  try { await lstat(directory); } catch (error) { if (error.code === 'ENOENT') exists = false; else throw error; }
  if (exists) fail('gate directory must not exist yet');
  await mkdir(directory, { mode: 0o700 });
  await writePrivate(join(directory, GATE_MARKER), GATE_MARKER_TEXT);
  for (const name of ['runs', 'notes']) await mkdir(join(directory, name), { mode: 0o700 });
  await writePrivate(join(directory, 'runs', `${record.core.id}.json`), JSON.stringify(record, null, 2));
  return record.core.id;
}

export async function main(args) {
  const [command, ...rest] = args, options = {};
  const names = { '--profile': 'profile', '--target': 'target', '--from': 'from', '--run': 'run', '--gate-dir': 'gateDir' };
  for (let i = 0; i < rest.length; i += 2) {
    const key = names[rest[i]];
    if (!key || Object.hasOwn(options, key) || i + 1 >= rest.length) fail('invalid options');
    options[key] = rest[i + 1];
  }
  if (command === 'target-id' && options.profile) return targetId(options);
  if (command === 'run-id' && options.from) return runId(options);
  if (command === 'seed-baseline' && options.run && options.gateDir) return seedBaseline(options);
  fail('usage: prepare.mjs target-id --profile FILE [--target ID] | run-id --from FILE | seed-baseline --run FILE --gate-dir DIR');
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const previous = process.umask(0o077);
  try { process.stdout.write(`${await main(process.argv.slice(2))}\n`); }
  catch (error) { console.error(`Scopehaven action: ${error.message}`); process.exitCode = 2; }
  finally { process.umask(previous); }
}
