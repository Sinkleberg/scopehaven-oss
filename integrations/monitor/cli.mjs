// Run the monitor over a saved trace:
//   node integrations/monitor/cli.mjs <trace.jsonl> [--json] [--rules id,id] [--interleavable op,op]
//
// The trace is JSON Lines: one observation per line, in the shape validateObservation accepts
// (see ./README.md). Blank lines are skipped. A line that is not an object, or is not valid
// JSON, is COUNTED as a source problem and named by its line number; it never stops the run and
// its content is never echoed, because a trace can hold an application's own ids and bodies.
//
// Every line is attributed TOGETHER, which is the saved-run reading: a row two windows share is
// charged to neither. That is deliberately not the live reading, where only one batch is
// compared at a time; a file is a saved set, so comparing all of it is the honest choice and the
// report's limitations say what attribution can and cannot do.
//
// A line also has to carry a ledger reading: `ledgerReadable` false, or `ledgerReadable` true with
// a `committed` list, which is what observationFromAttempt always writes. A line with neither read
// as a request that committed nothing and counted toward exit 0. And `droppedEffects` is a count
// only attributeEffects sets, always above zero, so a line carrying one that is negative or not a
// whole number lowered the CLI's own count of invalid lines and could cancel real gaps. Both kinds
// of line are counted in source.invalid, named by line number and skipped, like a malformed one.
//
// Exit codes, in order of precedence: 2, 1, 3, 4, 0.
//   0  no alerts, at least one observation, and all four of the report's unjudged counters at
//      zero: coverageGaps, unjudgedAuthority, unreadableClaims and ruleErrors. It speaks only
//      for the rules that ran (--rules narrows them) and for the trace's own fields, which this
//      CLI does not check against anything; it is still not a clean bill of health.
//   1  at least one alert
//   3  no alerts, but this run did not judge everything, for any of four reasons:
//        coverageGaps above zero       it could not read everything it observed, including
//                                      every malformed or skipped line;
//        unreadableClaims above zero   a claim it could not read at all;
//        ruleErrors above zero         a rule threw;
//        observed === 0                it judged nothing at all.
//      The last matters because a trace that was never written, or was truncated to nothing,
//      otherwise prints and exits exactly like a clean run, so a CI step pointed at a missing
//      file would read green.
//   4  no alerts and none of the reasons for 3, but unjudgedAuthority above zero: a commit whose
//      commit-time authority was never observed, so no access change after the request started
//      could be judged. The report keeps it out of coverageGaps because a saved run records
//      commit-time authority only for requests the application paused, so on honest traffic
//      most commits carry none. It has its own code so that a CI step can accept honest saved
//      traffic without accepting an empty trace: with one code for both, a step that had to
//      accept it for the first would also accept the second.
//      Until the exit code counted them, unjudgedAuthority, unreadableClaims and ruleErrors were
//      all outside it, and a run with any of them exited 0. The monitor's own limitation is that
//      no alert is not a clean bill of health; an exit code that did not distinguish these cases
//      would be that same overclaim in another place.
//   2  usage or input error (a missing path, an unreadable or oversized file, an unknown rule)
//
// It reads one local file and writes to stdout. No network, no credentials, no environment
// reads, and nothing is written back to the trace.
import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createMonitor, RULE_IDS } from './monitor.mjs';
import { attributeEffects, droppedEffectsOf } from './trace.mjs';

export const MAX_TRACE_BYTES = 64 * 1024 * 1024;
const USAGE = 'Usage: node integrations/monitor/cli.mjs <trace.jsonl> [--json] [--rules id,id] [--interleavable op,op]';

class UsageError extends Error {}

// A comma list, with the empty string meaning "none given" rather than one empty entry.
const list = value => String(value).split(',').map(part => part.trim()).filter(Boolean);

export function parseArguments(argv) {
  const options = { path: null, json: false, rules: null, interleavableOperations: null };
  for (let i = 0; i < argv.length; i++) {
    const argument = argv[i];
    if (argument === '--json') { options.json = true; continue; }
    if (argument === '--rules' || argument === '--interleavable') {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) throw new UsageError(`${argument} needs a comma-separated value.`);
      if (argument === '--rules') options.rules = list(value); else options.interleavableOperations = list(value);
      i += 1; continue;
    }
    if (argument.startsWith('--')) throw new UsageError(`Unknown option ${argument}.`);
    if (options.path !== null) throw new UsageError('Give one trace file.');
    options.path = argument;
  }
  if (options.path === null) throw new UsageError('Give a trace file.');
  if (options.rules !== null) {
    const unknown = options.rules.filter(id => !RULE_IDS.includes(id));
    if (unknown.length) throw new UsageError(`Unknown rule${unknown.length === 1 ? '' : 's'}: ${unknown.join(', ')}. Known: ${RULE_IDS.join(', ')}.`);
    if (!options.rules.length) throw new UsageError('--rules needs at least one rule.');
  }
  return options;
}

// Read the trace. A parse failure names the LINE, never the content: a trace can carry the
// application's own identifiers and bodies, and an error message is not the place for them.
export function readTrace(path) {
  const full = resolve(path);
  let stats;
  try { stats = statSync(full); } catch { throw new UsageError(`Cannot read ${path}.`); }
  if (!stats.isFile()) throw new UsageError(`${path} is not a regular file.`);
  if (stats.size > MAX_TRACE_BYTES) throw new UsageError(`${path} is larger than ${MAX_TRACE_BYTES} bytes.`);
  let text;
  try { text = readFileSync(full, 'utf8'); } catch { throw new UsageError(`Cannot read ${path}.`); }
  const observations = [], malformed = [], withoutLedger = [], badCounts = [];
  text.split('\n').forEach((line, index) => {
    if (line.trim() === '') return;
    let parsed;
    try { parsed = JSON.parse(line); } catch { malformed.push(index + 1); return; }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) { malformed.push(index + 1); return; }
    if (badCount(parsed)) { badCounts.push(index + 1); return; }
    if (!carriesLedgerReading(parsed)) { withoutLedger.push(index + 1); return; }
    observations.push(parsed);
  });
  return { observations, malformed, withoutLedger, badCounts };
}

// What a line must say about its ledger: that it could not be read, or that it was read and
// what committed. Silence on either is not a reading of "nothing committed".
export const carriesLedgerReading = line => line.ledgerReadable === false
  || (line.ledgerReadable === true && Array.isArray(line.committed));
// A droppedEffects the line carries itself. attributeEffects only ever sets a whole number above
// zero, so anything else did not come from a rebuild, and a negative one would be subtracted.
export const badCount = line => Object.hasOwn(line, 'droppedEffects')
  && !(Number.isInteger(line.droppedEffects) && line.droppedEffects >= 0);

export function runTrace({ observations, malformed, withoutLedger = [], badCounts = [] }, { rules, interleavableOperations }) {
  const monitor = createMonitor({ ...(rules ? { rules } : {}), ...(interleavableOperations ? { interleavableOperations } : {}) });
  // Attribution can throw on a trace this cannot read at all. That is the whole file's problem,
  // not one line's, so it is counted and nothing is observed from it rather than charging the
  // rows to nobody, which is what the live path learned to do.
  let attributed = observations, attributionFailed = false;
  try { attributed = attributeEffects(observations); } catch { attributionFailed = true; }
  let invalid = malformed.length + withoutLedger.length + badCounts.length + (attributionFailed ? observations.length : 0);
  if (!attributionFailed) {
    for (const observation of attributed) {
      try { monitor.observe(observation); } catch { invalid += 1; }
    }
    // What the rebuild filtered out of an effects list is counted the same way the live path
    // counts it, so a malformed effect is not free just because its observation collided. Only a
    // count above zero is added: a line's own negative one used to cancel real gaps.
    invalid += attributed.reduce((n, obs) => n + droppedEffectsOf(obs), 0);
  }
  monitor.noteSource({ readErrors: 0, invalid, batches: 1, ticks: 1 });
  return { report: monitor.report(), malformed, withoutLedger, badCounts, attributionFailed };
}

export function summarize({ report, malformed, withoutLedger = [], badCounts = [], attributionFailed }) {
  const lines = [];
  lines.push(`Observed ${report.observed} observation${report.observed === 1 ? '' : 's'}; ${report.alerts} alert${report.alerts === 1 ? '' : 's'}.`);
  // Said before the alert list and the gap count, because it changes what both of them mean:
  // zero of everything is the shape of a clean run AND the shape of an empty file.
  if (report.observed === 0) lines.push('  Nothing was observed; this is not a clean run.');
  for (const alert of report.alertList) lines.push(`  [${alert.severity}] ${alert.rule}: ${alert.reason}`);
  lines.push(`Coverage gaps: ${report.coverageGaps}.`);
  if (report.coverageGaps > 0) lines.push('  A run with gaps has not judged everything it observed, whatever its alert count says.');
  lines.push(`Verdicts resting on an absence: ${report.answeredByAbsence}; readable empty ledgers with no claim: ${report.absencesWithNoClaim}.`);
  if (report.unjudgedAuthority > 0) lines.push(`Commits whose commit-time authority was never observed, so no access change after the request started could be judged: ${report.unjudgedAuthority}.`);
  if (report.unreadableClaims > 0) lines.push(`Claims that could not be read at all: ${report.unreadableClaims}.`);
  if (report.ruleErrors > 0) lines.push(`Rules that threw: ${report.ruleErrors}.`);
  if (report.unjudgedAuthority > 0 || report.unreadableClaims > 0 || report.ruleErrors > 0)
    lines.push('  Each of those is something this run did not judge, so it is not a clean run either, whatever its alert count says.');
  if (attributionFailed) lines.push('Attribution failed for this trace, so nothing in it was observed.');
  if (malformed.length) lines.push(`Malformed line${malformed.length === 1 ? '' : 's'} counted and skipped: ${malformed.join(', ')}.`);
  if (withoutLedger.length) lines.push(`Line${withoutLedger.length === 1 ? '' : 's'} with no ledger reading (no ledgerReadable flag, or a readable ledger with no committed list) counted and skipped: ${withoutLedger.join(', ')}.`);
  if (badCounts.length) lines.push(`Line${badCounts.length === 1 ? '' : 's'} carrying a droppedEffects that is negative or not a whole number counted and skipped: ${badCounts.join(', ')}.`);
  if (report.alerts === 0) lines.push('No alert is not a clean bill of health, only the absence of the declared patterns.');
  return lines.join('\n');
}

// An alert outranks everything. After that, judging nothing counts the same as leaving something
// unjudged, and so does a claim that could not be read or a rule that threw: 3. A commit with no
// commit-time authority view, when it is the only thing left, is 4, which is what honest saved
// traffic gives, so that 3 never has to be accepted for it. None of them is a clean run, and only
// a run that observed something and left none of these counters above zero can exit 0.
export const exitCodeFor = report => (report.alerts > 0 ? 1
  : report.observed === 0 || report.coverageGaps > 0 || report.unreadableClaims > 0 || report.ruleErrors > 0 ? 3
    : report.unjudgedAuthority > 0 ? 4 : 0);

export function main(argv, { log = console.log, error = console.error } = {}) {
  let options;
  try { options = parseArguments(argv); } catch (problem) {
    error(problem instanceof UsageError ? `${problem.message}\n${USAGE}` : String(problem?.message ?? problem));
    return 2;
  }
  let trace;
  try { trace = readTrace(options.path); } catch (problem) {
    error(problem instanceof UsageError ? `${problem.message}\n${USAGE}` : String(problem?.message ?? problem));
    return 2;
  }
  const outcome = runTrace(trace, options);
  log(options.json ? JSON.stringify(outcome.report, null, 2) : summarize(outcome));
  return exitCodeFor(outcome.report);
}

// pathToFileURL, not `file://${argv[1]}`: this project's own checkout is "Scope Haven", and a
// path with a space percent-encodes in a URL but not in argv, so the string compare would never
// match and the CLI would exit silently having done nothing. That is the one defect this
// repository's tests are run from a spaced path to catch.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = main(process.argv.slice(2));
