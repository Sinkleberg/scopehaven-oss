#!/usr/bin/env node
// Report-only mode for the regression gate (`gate --report-only`, and the GitHub Action's report-only input).
// A rollout aid: for a bounded window (through a last UTC date, for a number of runs, or both, whichever ends
// first) the gate records its real verdict, writes the report and SARIF marked REPORT-ONLY and exits 0 on an
// assessment-failed verdict. After the window the normal exit codes apply. An error (exit 2) is never relaxed.
// The verdict, reasons and counts are never changed; the mode is a gate decision, not run evidence, so the
// stored run is untouched and a later `scopehaven export` of it carries no mark.
// Each command prints one stdout line: its result, or the refusal code with exit 2.
//   window --until DATE                    -> applied or ended, for that date today
//   stamp --until DATE --file F [--gate G] -> marks F (.html or .sarif) in place; exit 3, unchanged, when the
//                                             gate summary G did not apply report-only
import { constants } from 'node:fs';
import { open, readdir, rename, unlink } from 'node:fs/promises';
import { dirname, extname, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { escape, renderReport } from '../../src/report.mjs';
import { serializeSarif } from '../../src/sarif.mjs';

export const MAX_WINDOW_DAYS = 90;
export const MAX_WINDOW_RUNS = 100;
const DAY_MS = 86400000;
const FILE_LIMIT = 8 * 1024 * 1024;
const SUMMARY_LIMIT = 1024 * 1024;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export class ReportOnlyError extends Error { constructor(code) { super(code); this.name = 'ReportOnlyError'; this.code = code; } }

const utcDay = now => now.toISOString().slice(0, 10);
/** A real calendar date written YYYY-MM-DD (2026-02-30 is not one). */
export const validDate = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)
  && !Number.isNaN(Date.parse(`${value}T00:00:00Z`)) && new Date(`${value}T00:00:00Z`).toISOString().slice(0, 10) === value;

/** The declared window, checked against the run date. A date already passed is accepted: that window has ended.
 * A date more than MAX_WINDOW_DAYS ahead is refused, so report-only cannot stand in for a permanent mode. */
export function checkWindow({ until = null, runs = null } = {}, now = new Date()) {
  if (until === null && runs === null) throw new ReportOnlyError('report-only-window-required');
  if ((until !== null && !validDate(until)) || (runs !== null && !(Number.isSafeInteger(runs) && runs >= 1 && runs <= MAX_WINDOW_RUNS))) throw new ReportOnlyError('report-only-window-invalid');
  if (until !== null && Date.parse(`${until}T00:00:00Z`) - Date.parse(`${utcDay(now)}T00:00:00Z`) > MAX_WINDOW_DAYS * DAY_MS) throw new ReportOnlyError('report-only-window-too-long');
  return { until, runs };
}

/** applied while today (UTC) is on or before `until` and this run (the used runs plus one) is within `runs`. */
export function windowState({ until = null, runs = null }, { used = 0, now = new Date() } = {}) {
  const run = used + 1, datePassed = until !== null && utcDay(now) > until, runsUsed = runs !== null && run > runs;
  return { state: datePassed || runsUsed ? 'ended' : 'applied', ...(datePassed ? { endedBy: 'date-passed' } : runsUsed ? { endedBy: 'runs-used' } : {}), until, runs, ...(runs !== null ? { run } : {}) };
}

const periodText = period => [period.until !== null ? `through ${period.until} UTC` : null, period.runs !== null ? `run ${period.run} of ${period.runs}` : null].filter(Boolean).join(', ');
export const reportOnlyNote = period => period.state === 'applied'
  ? `Report-only run (${periodText(period)}): the gate exits 0 on a failed assessment, so a zero exit is not a pass. The verdict, reasons and statuses recorded here are the real results; an error still exits 2.`
  : `Report-only window ended (${period.endedBy}): the normal exit codes apply.`;

/** The gate summary with its window beside the verdict. Only an assessment-failed verdict (exit 1) is relaxed, and only
 * in the process exit (reportOnly.exitCode): outcome, exitCode and reasons stay the verdict's. */
export function applyReportOnly(summary, period) {
  const { schemaVersion, ...rest } = summary;
  const exitCode = period.state === 'applied' && summary.exitCode === 1 ? 0 : summary.exitCode;
  return { schemaVersion, reportOnly: { mode: 'report-only', ...period, exitCode, note: reportOnlyNote(period) }, ...rest };
}

/** Report-only runs already recorded in a gate's summaries directory: each saved summary whose window was not ended.
 * A summary that cannot be read or parsed counts as used, so accidental damage shortens a window. The count is only as
 * good as the directory: deleting a summary, or editing one to drop its window, gives a run back (README). */
export async function runsUsed(summaries) {
  let used = 0;
  for (const name of (await readdir(summaries)).filter(name => name.endsWith('.json'))) {
    let parsed = null, handle;
    try {
      handle = await open(join(summaries, name), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const stat = await handle.stat();
      if (stat.isFile() && stat.size <= SUMMARY_LIMIT) parsed = JSON.parse(await handle.readFile('utf8'));
    } catch {} finally { await handle?.close().catch(() => {}); }
    if (!object(parsed) || (Object.hasOwn(parsed, 'reportOnly') && parsed.reportOnly?.state !== 'ended')) used += 1;
  }
  return used;
}

// Every page: the title, a banner on the cover, a line in each check and in the limits, and (where the print engine
// supports page margin boxes) a header on each printed page. The anchors are the report's own tags; data in it is escaped.
const MARK_CSS = '.report-only{border:3px solid #9a3412;background:#fff7ed;color:#7c2d12;padding:10px 14px;margin:12px 0;font-weight:600}.report-only-tag{color:#9a3412;font-weight:600;font-size:.9em}@page{@top-center{content:"Scopehaven REPORT-ONLY run: not a pass"}}';
const MARK_TAG = '<p class="report-only-tag">REPORT-ONLY run: not a pass.</p>';
const once = (text, token) => text.indexOf(token) !== -1 && text.indexOf(token) === text.lastIndexOf(token);
export function stampHtml(html, period) {
  if (period?.state !== 'applied') throw new ReportOnlyError('report-only-not-applied');
  if (typeof html !== 'string' || !once(html, '<title>') || !once(html, '</style>')) throw new ReportOnlyError('report-only-stamp-failed');
  if (html.includes('<section class="cover">') && (!html.includes('<article>') || !once(html, '<section class="limits">'))) throw new ReportOnlyError('report-only-stamp-failed');
  const banner = `<div class="report-only" role="note">REPORT-ONLY RUN. ${escape(reportOnlyNote(period))}</div>`;
  return html.replace('<title>', () => '<title>REPORT-ONLY · ').replace('</style>', () => `${MARK_CSS}</style>${banner}`)
    .replaceAll('<article>', () => `<article>${MARK_TAG}`).replace('<section class="limits">', () => `<section class="limits">${MARK_TAG}`);
}

// Each result's message (the text a code scanning alert shows) starts with the mark; the run's properties and its
// invocation carry the window. Levels, kinds and fingerprints are as recorded, so a merge rule that reads levels still does.
export const RESULT_MARK = '[REPORT-ONLY run: not a pass] ';
export function stampSarif(text, period) {
  if (period?.state !== 'applied') throw new ReportOnlyError('report-only-not-applied');
  let sarif;
  try { sarif = JSON.parse(text); } catch { throw new ReportOnlyError('report-only-stamp-failed'); }
  if (!object(sarif) || !Array.isArray(sarif.runs) || !sarif.runs.length || !sarif.runs.every(run => object(run) && Array.isArray(run.results) && Array.isArray(run.invocations) && object(run.invocations[0])))
    throw new ReportOnlyError('report-only-stamp-failed');
  const note = reportOnlyNote(period);
  for (const run of sarif.runs) {
    run.properties = { ...(object(run.properties) ? run.properties : {}), reportOnly: { mode: 'report-only', ...period, note } };
    const invocation = run.invocations[0];
    invocation.toolExecutionNotifications = [{ level: 'note', message: { text: `REPORT-ONLY RUN. ${note}` } }, ...(Array.isArray(invocation.toolExecutionNotifications) ? invocation.toolExecutionNotifications : [])];
    for (const result of run.results) result.message = { ...(object(result?.message) ? result.message : {}), text: `${RESULT_MARK}${typeof result?.message?.text === 'string' ? result.message.text : ''}` };
  }
  return `${JSON.stringify(sarif, null, 2)}\n`;
}

/** The gate's own report-only files for a saved run, rendered as `scopehaven export` renders them, then marked. */
export const markedReport = (run, period) => stampHtml(renderReport(run), period);
export const markedSarif = (run, period) => stampSarif(serializeSarif(run), period);

async function readBounded(path, limit) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > limit) throw new Error('not a bounded regular file');
    return await handle.readFile('utf8');
  } catch { throw new ReportOnlyError('report-only-stamp-failed'); } finally { await handle?.close().catch(() => {}); }
}
/** Mark an exported report (.html) or SARIF file (.sarif) in place: a new private file renamed over it. */
export async function stampFile(path, period) {
  const kind = { '.html': stampHtml, '.sarif': stampSarif }[extname(path)];
  if (!kind) throw new ReportOnlyError('report-only-stamp-failed');
  const stamped = kind(await readBounded(path, FILE_LIMIT), period);
  const temporary = join(dirname(path), `.${randomUUID()}.report-only.tmp`);
  try {
    const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await handle.writeFile(stamped); await handle.sync(); } finally { await handle.close(); }
    await rename(temporary, path);
  } finally { await unlink(temporary).catch(() => {}); }
}

export async function main(args, now = new Date()) {
  const [command, ...rest] = args, options = {}, names = { '--until': 'until', '--file': 'file', '--gate': 'gate' };
  for (let i = 0; i < rest.length; i += 2) {
    const key = names[rest[i]];
    if (!key || Object.hasOwn(options, key) || i + 1 >= rest.length) throw new ReportOnlyError('invalid-options');
    options[key] = rest[i + 1];
  }
  if (command === 'window' && options.until !== undefined && !options.file && !options.gate) return windowState(checkWindow({ until: options.until }, now), { now }).state;
  if (command === 'stamp' && options.until !== undefined && options.file) {
    // The Action decides once, in its prepare step, that the window is open; this marks what that decision covers.
    if (!validDate(options.until)) throw new ReportOnlyError('report-only-window-invalid');
    if (options.gate !== undefined) {
      let gate = null;
      try { gate = JSON.parse(await readBounded(resolve(options.gate), SUMMARY_LIMIT)); } catch {}
      if (gate?.reportOnly?.state !== 'applied') return 'not-applied';
    }
    await stampFile(resolve(options.file), { state: 'applied', until: options.until, runs: null });
    return 'marked';
  }
  throw new ReportOnlyError('invalid-options');
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const result = await main(process.argv.slice(2));
    process.stdout.write(`${result}\n`);
    if (result === 'not-applied') process.exitCode = 3;
  } catch (error) { process.stdout.write(`${error instanceof ReportOnlyError ? error.code : 'report-only-error'}\n`); process.exitCode = 2; }
}
