// Onboarding clocks: stage stamps every init run appends to init-stamps.jsonl in its --out folder, and the two clocks a
// receipt computes from them.
//
//   first decided row   the first starter run whose first row was a FAIL, or an INCONCLUSIVE row with its fired check.
//                       It is "a first result", not a finding.
//   first held FAIL     the first run with a FAIL row that a reviewer later confirmed holds (`init review`). The clock
//                       stops at that run, not at the review; the review time is recorded beside it. A FAIL the reviewer
//                       says does not hold is a false FAIL, and a FAIL nobody reviewed keeps the receipt open.
//
// Both clocks start at the onboarding start stamp (`init start`, written before the operator opens the docs) or, when
// there is none, at the first init run's start, and the receipt says which. Stamps are wall-clock ISO times from this
// machine, unkeyed: a timing receipt, not evidence. A stamp holds stage names, times, exit and stop codes, run ids,
// check ids, verdicts, counts and the product head; never a credential, path, host or value. The onboarding start and review lines
// also hold the operator's free-text label and roles, which only the operator can keep free of names.
import { closeSync, constants, fstatSync, openSync, realpathSync, writeSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { InitError } from './envfile.mjs';

export const STAMP_SCHEMA = 'scopehaven-init-stamp/0';
export const RECEIPT_SCHEMA = 'scopehaven-onboarding-receipt/0';
export const STAMPS_FILE = 'init-stamps.jsonl';
export const RECEIPT_FILE = 'onboarding-receipt.json';
// Stage names init writes, in order. A run stops at any of them; "end" is always the last, with the exit status.
export const STAGES = Object.freeze(['start', 'identities-read', 'authorization-drafted', 'authorization-sealed', 'probe-start', 'whoami-found', 'records-probed',
  'profile-written', 'config-checked', 'run-saved', 'first-decided-row', 'end']);
// Stamps the onboarding commands write.
export const MARKS = Object.freeze(['onboarding-start', 'review']);
const RUN_ID = /^[A-Za-z0-9-]{1,80}$/;
const CHECK_ID = /^[A-Za-z0-9_.:-]{1,120}$/;
export const LABEL = /^[A-Za-z0-9_-]{1,40}$/;
const ROLE = /^[A-Za-z0-9 ,.()/_-]{1,80}$/;
const MAX_STAMPS_BYTES = 1 << 20;

// The product head this checkout runs at, or null outside a git checkout (a git archive tree, an install without git).
export function productHead(root) {
  try {
    const r = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
    return r.status === 0 && /^[0-9a-f]{40}$/.test(r.stdout.trim()) ? r.stdout.trim() : null;
  } catch { return null; }
}

// Appends lines to the stamps file: created 0600, never through a symlink, never truncated.
export async function appendStamps(dir, lines) {
  if (!lines.length) return;
  let handle;
  try { handle = await open(join(dir, STAMPS_FILE), constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND | constants.O_NOFOLLOW, 0o600); }
  catch (error) { throw new InitError('stamps', error?.code === 'ELOOP' ? `${STAMPS_FILE} is a symlink` : `${STAMPS_FILE} could not be opened for appending`); }
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || (typeof process.getuid === 'function' && stat.uid !== process.getuid()) || (stat.mode & 0o077) !== 0) throw new InitError('stamps', `${STAMPS_FILE} is not a private regular file the current user owns`);
    await handle.writeFile(lines.map(line => `${JSON.stringify(line)}\n`).join(''));
  } finally { await handle.close(); }
}

// The same append, synchronous: init writes each stage as it happens, so a run killed mid-way keeps what it reached.
function appendStampsSync(dir, lines) {
  let fd;
  try { fd = openSync(join(dir, STAMPS_FILE), constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND | constants.O_NOFOLLOW, 0o600); }
  catch (error) { throw new InitError('stamps', error?.code === 'ELOOP' ? `${STAMPS_FILE} is a symlink` : `${STAMPS_FILE} could not be opened for appending`); }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || (typeof process.getuid === 'function' && stat.uid !== process.getuid()) || (stat.mode & 0o077) !== 0) throw new InitError('stamps', `${STAMPS_FILE} is not a private regular file the current user owns`);
    writeSync(fd, lines.map(line => `${JSON.stringify(line)}\n`).join(''));
  } finally { closeSync(fd); }
}

// One init run's clock. Stamps are kept in memory until init knows its --out folder, then appended as each stage
// happens; a failed append stops further appends and is reported once at the end, never changing the exit status.
export function initClock(now, { head } = {}) {
  const run = randomBytes(6).toString('hex');
  const t0 = now();
  const stamps = [];
  let out = null, stop = null, firstRow = null, saved = null, written = 0, failure = null;
  const write = () => {
    if (!out || failure || written === stamps.length) return;
    try { appendStampsSync(out, stamps.slice(written)); written = stamps.length; } catch (error) { failure = error; }
  };
  const stamp = (stage, extra = {}) => {
    const at = now();
    const line = { schema: STAMP_SCHEMA, run, stage, at: at.toISOString(), ms: at - t0, ...extra };
    stamps.push(line);
    write();
    return line;
  };
  stamp('start', head === undefined ? {} : { head });
  return {
    run, stamp,
    // The folder the stamps go to, once init knows it.
    setOut(dir) { if (!out) { out = dir; write(); } },
    // The InitError code a stop carried (a fixed word; the message is never stamped).
    stopped(code) { stop = typeof code === 'string' && /^[A-Za-z0-9_-]{1,40}$/.test(code) ? code : 'error'; },
    runSaved(runId, summary) {
      saved = stamp('run-saved', { runId, fail: summary.counts.FAIL, inconclusive: summary.counts.INCONCLUSIVE, notExercised: summary.counts['not exercised'], failChecks: summary.failIds ?? [] });
      if (summary.first) firstRow = stamp('first-decided-row', { runId, verdict: summary.first.verdict, check: summary.first.id });
    },
    // This run's timing for init-report.json.
    snapshot() {
      return { schema: 'scopehaven-init-timing/0', run, startedAt: t0.toISOString(), stages: stamps.map(({ stage, at, ms }) => ({ stage, at, ms })),
        firstDecidedRow: firstRow ? { at: firstRow.at, ms: firstRow.ms, verdict: firstRow.verdict, check: firstRow.check, runId: firstRow.runId } : null,
        firstHeldFail: saved?.fail ? 'pending review: ./scopehaven init review' : null };
    },
    async flush(code, { say } = {}) {
      if (!out) return;
      stamp('end', { exit: code, ...(stop ? { stop } : {}) });
      if (failure) say?.(`Note: timing stamps not written (${failure?.message ?? 'error'}); the run itself is unaffected.`);
    },
  };
}

// Reads every stamp line. A damaged line stops the receipt: a clock read from a partial file would be wrong.
export async function readStamps(dir) {
  let text;
  try {
    const handle = await open(join(dir, STAMPS_FILE), constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.size > MAX_STAMPS_BYTES) throw new InitError('stamps', `${STAMPS_FILE} is not a regular file of at most 1 MiB`);
      text = await handle.readFile('utf8');
    } finally { await handle.close(); }
  } catch (error) {
    if (error instanceof InitError) throw error;
    if (error?.code === 'ENOENT') return [];
    throw new InitError('stamps', `${STAMPS_FILE} could not be read`);
  }
  const out = [];
  text.split('\n').forEach((line, i) => {
    if (!line.trim()) return;
    let s;
    try { s = JSON.parse(line); } catch { throw new InitError('stamps', `${STAMPS_FILE} line ${i + 1} is not JSON`); }
    if (s?.schema !== STAMP_SCHEMA || ![...STAGES, ...MARKS].includes(s.stage) || typeof s.at !== 'string' || Number.isNaN(Date.parse(s.at)) || typeof s.run !== 'string' || !(FIELDS[s.stage] ?? (() => true))(s)) throw new InitError('stamps', `${STAMPS_FILE} line ${i + 1} is not a stamp`);
    out.push(s);
  });
  return out;
}

// The fields each stage needs, so a damaged line stops the receipt instead of dropping out of a count.
const str = v => typeof v === 'string' && v.length > 0;
const count = v => Number.isSafeInteger(v) && v >= 0;
const FIELDS = {
  'onboarding-start': s => str(s.label) && typeof s.owned === 'boolean' && str(s.operatorRole) && (s.head === null || str(s.head)),
  review: s => str(s.runId) && str(s.check) && typeof s.holds === 'boolean' && str(s.reviewerRole),
  'run-saved': s => str(s.runId) && count(s.fail) && count(s.inconclusive) && count(s.notExercised) && Array.isArray(s.failChecks) && s.failChecks.every(str) && s.failChecks.length === s.fail,
  'first-decided-row': s => str(s.runId) && ['FAIL', 'INCONCLUSIVE'].includes(s.verdict) && str(s.check),
  end: s => [0, 1, 2, 3].includes(s.exit),
};

const minutes = (from, to) => Math.round(((Date.parse(to) - Date.parse(from)) / 60000) * 100) / 100;

// The receipt for one onboarding folder: both clocks, every init run's outcome, and the reviews.
export function computeReceipt(stamps) {
  if (!stamps.length) throw new InitError('stamps', `no stamps yet: run init with --out pointing at this folder first`);
  const starts = stamps.filter(s => s.stage === 'onboarding-start');
  if (starts.length > 1) throw new InitError('stamps', 'more than one onboarding start in this folder; one folder is one onboarding');
  const onboarding = starts[0] ?? null;
  const runs = [...new Set(stamps.filter(s => STAGES.includes(s.stage)).map(s => s.run))].map(run => {
    const own = stamps.filter(s => s.run === run && STAGES.includes(s.stage));
    const start = own.find(s => s.stage === 'start'), end = own.find(s => s.stage === 'end'), saved = own.find(s => s.stage === 'run-saved');
    const first = own.find(s => s.stage === 'first-decided-row');
    return { run, startedAt: start?.at ?? own[0].at, endedAt: end?.at ?? null, exit: end?.exit ?? null, stop: end?.stop ?? null, reached: own.filter(s => s.stage !== 'end').at(-1)?.stage ?? null, head: start?.head ?? null,
      starterRun: saved ? { runId: saved.runId, fail: saved.fail, inconclusive: saved.inconclusive, notExercised: saved.notExercised, failChecks: saved.failChecks ?? [], savedAt: saved.at } : null,
      firstDecidedRow: first ? { at: first.at, verdict: first.verdict, check: first.check } : null };
  }).sort((x, y) => Date.parse(x.startedAt) - Date.parse(y.startedAt));
  // An onboarding with a start but no stamped run keeps its row: it never reached a result.
  const t0 = onboarding?.at ?? runs[0]?.startedAt;
  if (!t0) throw new InitError('stamps', 'no onboarding start and no init run in this folder');
  if (runs.some(r => Date.parse(r.startedAt) < Date.parse(t0))) throw new InitError('stamps', 'an init run started before the onboarding start; start a new folder');
  // Reviews: the latest answer per (run, check) counts.
  const reviews = new Map();
  for (const s of stamps.filter(s => s.stage === 'review')) reviews.set(`${s.runId} ${s.check}`, s);
  const fails = runs.flatMap(r => (r.starterRun?.failChecks ?? []).map(check => ({ run: r, check, review: reviews.get(`${r.starterRun.runId} ${check}`) ?? null })));
  const held = fails.filter(f => f.review?.holds === true).sort((x, y) => Date.parse(x.run.starterRun.savedAt) - Date.parse(y.run.starterRun.savedAt))[0] ?? null;
  const firstRow = runs.find(r => r.firstDecidedRow);
  const heads = [...new Set(runs.map(r => r.head).filter(Boolean))];
  return {
    schema: RECEIPT_SCHEMA,
    // The start stamp's random id names the onboarding, so a folder given twice or copied is not counted twice.
    // Without a start stamp, the first run's id names it, so a copied folder is still counted once.
    onboardingId: onboarding?.run ?? runs[0]?.run ?? null, label: onboarding?.label ?? null, owned: onboarding?.owned ?? null, operatorRole: onboarding?.operatorRole ?? null,
    productHead: heads.length === 1 ? heads[0] : heads.length ? heads : null,
    clockStart: { from: onboarding ? 'onboarding-start' : 'first-init-run', at: t0 },
    clocks: {
      firstDecidedRow: firstRow ? { minutes: minutes(t0, firstRow.firstDecidedRow.at), at: firstRow.firstDecidedRow.at, verdict: firstRow.firstDecidedRow.verdict, check: firstRow.firstDecidedRow.check, runId: firstRow.starterRun?.runId ?? null } : null,
      firstHeldFail: held ? { minutes: minutes(t0, held.run.starterRun.savedAt), at: held.run.starterRun.savedAt, check: held.check, runId: held.run.starterRun.runId, reviewedAt: held.review.at, reviewerRole: held.review.reviewerRole } : null,
    },
    initRuns: runs.map(r => ({ startedAt: r.startedAt, exit: r.exit, stop: r.stop, reached: r.reached, ended: r.endedAt !== null, starterRun: r.starterRun && { runId: r.starterRun.runId, fail: r.starterRun.fail, inconclusive: r.starterRun.inconclusive } })),
    fails: { total: fails.length, held: fails.filter(f => f.review?.holds === true).length, falseFails: fails.filter(f => f.review?.holds === false).map(f => ({ runId: f.run.starterRun.runId, check: f.check })),
      unreviewed: fails.filter(f => !f.review).map(f => ({ runId: f.run.starterRun.runId, check: f.check })) },
    note: 'Wall-clock stamps from this machine, unkeyed: a timing receipt, not evidence. "First decided row" is a first result, not a finding.',
  };
}

const median = values => { const v = [...values].sort((a, b) => a - b); return v.length ? (v.length % 2 ? v[(v.length - 1) / 2] : (v[v.length / 2 - 1] + v[v.length / 2]) / 2) : null; };

// The timing table over several onboardings, and the onboarding done condition: at least five, median under 60 minutes, worst
// under 90, zero false FAILs and none unreviewed, at least two on apps ScopeHaven does not own.
export function timingTable(receipts) {
  const ids = receipts.map(r => r.onboardingId).filter(Boolean);
  if (new Set(ids).size !== ids.length) throw new InitError('stamps', 'the same onboarding appears twice (a folder given twice, or a copy of one); each onboarding counts once');
  const rows = receipts.map(r => ({ label: r.label, owned: r.owned, operatorRole: r.operatorRole, productHead: Array.isArray(r.productHead) ? r.productHead.map(h => h.slice(0, 8)).join('+') : r.productHead?.slice(0, 8) ?? null,
    clockFrom: r.clockStart.from, firstDecidedRow: r.clocks.firstDecidedRow?.minutes ?? null, verdict: r.clocks.firstDecidedRow ? `${r.clocks.firstDecidedRow.verdict} ${r.clocks.firstDecidedRow.check}` : null,
    firstHeldFail: r.clocks.firstHeldFail?.minutes ?? null, initRuns: r.initRuns.length, falseFails: r.fails.falseFails.length, unreviewed: r.fails.unreviewed.length }));
  const reached = rows.map(r => r.firstDecidedRow);
  const all = reached.every(m => m !== null);
  const summary = { onboardings: rows.length, notOwned: rows.filter(r => r.owned === false).length, medianMinutes: all ? median(reached) : null, worstMinutes: all && reached.length ? Math.max(...reached) : null,
    falseFails: rows.reduce((n, r) => n + r.falseFails, 0), unreviewed: rows.reduce((n, r) => n + r.unreviewed, 0), allReached: all,
    fromOnboardingStart: rows.filter(r => r.clockFrom === 'onboarding-start').length };
  const done = { atLeastFive: summary.onboardings >= 5, medianUnder60: summary.medianMinutes !== null && summary.medianMinutes < 60, worstUnder90: summary.worstMinutes !== null && summary.worstMinutes < 90,
    zeroFalseFails: summary.falseFails === 0 && summary.unreviewed === 0, twoNotOwned: summary.notOwned >= 2,
    // A clock that started at the first init run leaves out reading the docs and earlier stops, so it understates.
    allFromOnboardingStart: summary.onboardings > 0 && summary.fromOnboardingStart === summary.onboardings };
  return { rows, summary, done: { ...done, met: Object.values(done).every(Boolean) }, limits: TABLE_LIMITS };
}

// Printed under every table and kept in its JSON: what the timings cannot show.
export const TABLE_LIMITS = Object.freeze([
  'stamps are this machine\'s wall clock and carry no key: a timing table, not evidence',
  'what each operator had in context before the start stamp is only what the operator role says; init cannot check it',
]);

export function tableMarkdown(table) {
  const { rows: onboardings, summary, done } = table;
  const cell = v => (v === null || v === undefined ? 'n/a' : String(v));
  const lines = ['| Onboarding | Owned | Operator role | Product head | Clock from | First decided row (min) | Row | First held FAIL (min) | init runs | False FAILs | Unreviewed FAILs |', '|---|---|---|---|---|---|---|---|---|---|---|'];
  for (const r of onboardings) lines.push(`| ${cell(r.label)} | ${r.owned === null ? 'n/a' : r.owned ? 'yes' : 'no'} | ${cell(r.operatorRole)} | ${cell(r.productHead)} | ${r.clockFrom} | ${r.firstDecidedRow === null ? 'not reached' : r.firstDecidedRow} | ${cell(r.verdict)} | ${cell(r.firstHeldFail)} | ${r.initRuns} | ${r.falseFails} | ${r.unreviewed} |`);
  lines.push('', `Onboardings ${summary.onboardings} (${summary.notOwned} on apps ScopeHaven does not own; ${summary.fromOnboardingStart} clocked from an onboarding start); median ${cell(summary.medianMinutes)} min, worst ${cell(summary.worstMinutes)} min to the first decided row; false FAILs ${summary.falseFails}, unreviewed ${summary.unreviewed}.`);
  lines.push(`Done condition: ${Object.entries(done).filter(([k]) => k !== 'met').map(([k, v]) => `${k} ${v ? 'yes' : 'no'}`).join(', ')}; met: ${done.met ? 'yes' : 'no'}.`);
  lines.push(`Limits: ${TABLE_LIMITS.join('; ')}.`);
  return lines.join('\n');
}

// A folder's real path, so the same folder given twice is refused.
export const realDir = dir => { try { return realpathSync(dir); } catch { return dir; } };

export { RUN_ID, CHECK_ID, ROLE };
