// Watch-first CLI: draft a profile from what a local target did, for a person to approve.
//   ./scopehaven watch-first watch WATCH --authorization RECORD --out NEW_RECORD
//   ./scopehaven watch-first draft WATCH --record RECORD --out-profile NEW_PROFILE --out-report NEW_REPORT
//   ./scopehaven watch-first lines PROFILE
//   ./scopehaven watch-first approve PROFILE --approved-by "NAME" [--line ID,ID...] [--strip] --out NEW_PROFILE
// watch sends the watch file's turns to its loopback target once, with its observers on, under an authorization record
// that covers the target (as assess does), and writes the watch record. draft writes the drafted profile (every proposed
// line "approved": false) and its draft report. lines lists a profile's drafted lines; approve marks them approved by a
// label the caller supplies (it authenticates no one; editing "approved" and "approvedBy" by hand is the same act). With
// --strip, once every line is approved, it writes the plain profile, markers removed: the file tools that read a profile
// directly (coverage-report, grant-use, policy-import confirm and explain) can read, which refuse marker keys.
// Any command that loads a profile (check-config, assess, gate) refuses one with an unapproved drafted line.
// Outputs are new files (never overwritten), mode 0600. Exit codes: 0 done; 2 usage, file or validation error.
// No model is called anywhere here.
import { lstat, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runWatch, validateWatch, watchProfileTarget } from './watch.mjs';
import { draftFromWatch } from './draft.mjs';
import { admitDraftedLines, approveLines, draftedLines } from './lines.mjs';
import { buildObservers } from '../observers/factory.mjs';
import { authorizeConfigured } from '../../src/authorization-file.mjs';
import { guardObserverFactory, windowRefusal } from '../../src/authorization.mjs';
import { assertRuntime } from '../../src/runtime.mjs';

const MAX_BYTES = 8 * 1024 * 1024;
const USAGE = 'Usage: watch-first watch WATCH --authorization RECORD --out NEW | draft WATCH --record RECORD --out-profile NEW --out-report NEW | lines PROFILE | approve PROFILE --approved-by NAME [--line ID,ID] [--strip] --out NEW';

function parse(argv) {
  const flags = {}, positional = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--strip') { if (flags.strip) throw new Error('--strip is given twice.'); flags.strip = true; continue; }
    if (argv[i].startsWith('--')) {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) throw new Error(`${argv[i]} needs a value.`);
      if (Object.hasOwn(flags, argv[i].slice(2))) throw new Error(`${argv[i]} is given twice.`);
      flags[argv[i].slice(2)] = value; i++;
    } else positional.push(argv[i]);
  }
  return { flags, positional };
}
async function readJson(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${path} must be a regular file, not a link or directory.`);
  if (stat.size > MAX_BYTES) throw new Error(`${path} is larger than ${MAX_BYTES} bytes.`);
  try { return JSON.parse(await readFile(path, 'utf8')); } catch { throw new Error(`${path} is not valid JSON.`); }
}
async function writeNew(path, value) {
  if (!path) throw new Error('An output path is required.');
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
}
const only = (flags, allowed) => { const extra = Object.keys(flags).find(f => !allowed.includes(f)); if (extra) throw new Error(`Unsupported option --${extra}.`); };

// observerFactory and transport: the observers' builder and the HTTP transport (tests inject them); the window guard is always applied.
export async function main(argv, { env = process.env, log = console.log, observerFactory = buildObservers, transport } = {}) {
  const [command, ...rest] = argv;
  const { flags, positional } = parse(rest);
  if (command === 'watch') {
    only(flags, ['authorization', 'out']);
    if (positional.length !== 1 || !flags.out) throw new Error(USAGE);
    const watch = validateWatch(await readJson(positional[0]));
    // The rule assess keeps for a configured target: an authorization record that covers it now, checked again before every
    // request and when every observer call starts (guardObserverFactory); once the window ends nothing more is sent or started,
    // and no record is written.
    const granted = await authorizeConfigured(watchProfileTarget(watch), flags.authorization && resolve(flags.authorization));
    let record;
    try { record = await runWatch(watch, { env, beforeRequest: granted.window.check, factory: guardObserverFactory(observerFactory, granted.window.check), ...(transport ? { transport } : {}) }); granted.window.check(); }
    catch (error) { throw windowRefusal(granted.window, error); }
    await writeNew(flags.out, record);
    log(JSON.stringify({ recordId: record.recordId, turns: record.turns.map(t => ({ id: t.id, status: t.response.status, events: t.windows.reduce((n, w) => n + w.events.length, 0), windows: t.windows.map(w => `${w.observer}:${w.coverage}`) })) }, null, 2));
    return 0;
  }
  if (command === 'draft') {
    only(flags, ['record', 'out-profile', 'out-report']);
    if (positional.length !== 1 || !flags.record || !flags['out-profile'] || !flags['out-report']) throw new Error(USAGE);
    const { profile, report } = draftFromWatch(await readJson(positional[0]), await readJson(flags.record));
    await writeNew(flags['out-profile'], profile);
    await writeNew(flags['out-report'], report);
    log(JSON.stringify({ draftId: report.draftId, drafted: draftedLines(profile).map(l => l.at), notDrafted: report.notDrafted.map(n => `${n.turn}: ${n.reason.split(':')[0]}`), warnings: report.warnings }, null, 2));
    return 0;
  }
  if (command === 'lines') {
    only(flags, []);
    if (positional.length !== 1) throw new Error(USAGE);
    const lines = draftedLines(await readJson(positional[0]));
    log(JSON.stringify({ drafted: lines.length, unapproved: lines.filter(l => !l.approved).length, lines }, null, 2));
    return 0;
  }
  if (command === 'approve') {
    only(flags, ['approved-by', 'line', 'out', 'strip']);
    if (positional.length !== 1 || !flags.out || !flags['approved-by']) throw new Error(USAGE);
    const ids = flags.line ? flags.line.split(',').map(s => s.trim()).filter(Boolean) : 'all';
    const { profile, approved } = approveLines(await readJson(positional[0]), { approvedBy: flags['approved-by'], ids });
    // --strip refuses (through the gate itself) while any drafted line is still unapproved.
    await writeNew(flags.out, flags.strip ? admitDraftedLines(profile) : profile);
    log(JSON.stringify({ approved, approvedBy: flags['approved-by'], note: 'approvedBy is a label the caller supplies; it authenticates no one.' }, null, 2));
    return 0;
  }
  throw new Error(USAGE);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { assertRuntime(); process.exitCode = await main(process.argv.slice(2)); }
  catch (error) { console.error(`watch-first: ${error?.name === 'AuthorizationError' ? `authorization refused (${error.code}): ` : ''}${error.message}`); process.exitCode = 2; }
}
