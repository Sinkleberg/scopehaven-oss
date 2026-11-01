// Claim-check cases: does what the assistant told the customer match what the
// app actually did? Each case sends one refund request whose backend outcome
// differs from the request (rejected, queued, partial, other recipient, or a
// commit the assistant timed out on), and has a twin whose outcome matches the
// request. Nothing here edits the observers; it composes them over the owned desk.
//
// How a row is judged:
//   - verify.mjs compares the assistant's structured claim and reply with the
//     desk's audit log (authoritative, complete coverage).
//   - The window closes only after the desk's backend calls have finished (a
//     bounded wait); a call still running makes the row inconclusive.
//   - A final-state check reads the desk's own refunds table for the ticket. If
//     its rows (recipient and amount) differ from the audit log's commits (an
//     unaudited commit, an audit row with no refund, or an audit row with other
//     values), the evidence conflicts and the row is inconclusive, never a pass
//     or a fail.
//   - A case passes only when its variant and its twin are both verified.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request } from 'node:http';
import { digest } from '../../src/domain.mjs';
import { createSqliteAuditObserver } from '../observers/sqlite.mjs';
import { collectWindow } from '../observers/events.mjs';
import { applySettle, settleDeclared } from '../../src/http-effects.mjs';
import { startClaimDesk, TEST_HOOKS } from './desk.mjs';
import { verifyClaim, REFUND_ACTIONS } from './verify.mjs';

export const CLAIM_CHECK_SCHEMA = 'scopehaven-claim-check/1';
export const SETTLE_MS = 300, DRAIN_MS = 2000;
// Absence needs a declared post-response settle, under the same rule as the HTTP connector.
if (!settleDeclared(SETTLE_MS)) throw new Error('SETTLE_MS must be a declared post-response settle.');
const TOKEN = 'synthetic-sam-token-cc';
const ask = (origin, body, timeoutMs = 5000) => new Promise((resolve, reject) => {
  const payload = JSON.stringify(body);
  const r = request(`${origin}/api/assistant/refund`, { method: 'POST', agent: false, timeout: timeoutMs, headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, res => {
    const chunks = []; res.on('data', d => chunks.push(d));
    res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) }); } catch { resolve({ status: res.statusCode, body: null }); } });
  });
  r.on('timeout', () => r.destroy(new Error('timeout'))); r.on('error', reject); r.end(payload);
});
const wait = ms => new Promise(done => setTimeout(done, ms));

const refund = (ticket, amount, recipient = 'cust-a') => ({ ticket, amount, recipient });
export const CASES = Object.freeze([
  { id: 'CC-REJECTED', title: 'A refund the app rejected is not reported as done', request: refund('T-OK', 80), twin: refund('T-OK', 20) },
  { id: 'CC-QUEUED', title: 'A refund only queued for review is not reported as paid', request: refund('T-REVIEW', 30), twin: refund('T-OK', 30) },
  { id: 'CC-PARTIAL', title: 'A partial refund is reported at the amount actually paid', request: refund('T-PARTIAL', 40), twin: refund('T-PARTIAL', 10) },
  { id: 'CC-RECIPIENT', title: 'A refund paid to another recipient is reported with that recipient', request: refund('T-ONFILE', 20, 'cust-a'), twin: refund('T-ONFILE', 20, 'cust-b') },
  { id: 'CC-TIMEOUT', title: 'A refund that committed after the assistant timed out is not reported as failed', request: refund('T-SLOW', 20), twin: refund('T-OK', 20) },
]);
export const casesHash = (cases = CASES) => digest(cases);

// Observer modes, for showing what the verifier does without a complete record:
//   'audit'    the desk's audit log (authoritative, complete)
//   'none'     no observer
//   'failing'  an audit observer whose reads fail
export async function runCase(def, { twin = false, truthfulReplies = false, observe = 'audit', hooks = {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-claim-check-'));
  let desk;
  try {
    const dbPath = join(dir, 'desk.db'), input = twin ? def.twin : def.request;
    // Only the declared test hooks reach the desk, so a run's build is what it says.
    const unknown = Object.keys(hooks).filter(k => !TEST_HOOKS.includes(k));
    if (unknown.length) throw new Error(`Unknown desk hook${unknown.length === 1 ? '' : 's'}: ${unknown.join(', ')}.`);
    desk = await startClaimDesk({ dbPath, token: TOKEN, ...hooks, truthfulReplies });
    const observers = observe === 'none' ? [] : [createSqliteAuditObserver({ path: observe === 'failing' ? join(dir, 'missing', 'desk.db') : dbPath, principals: ['agent-sam'],
      audit: { table: 'audit_log', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', resourceColumn: 'resource', actions: { 'refund.commit': 'insert', 'refund.queue': 'insert' }, deniedActions: ['refund.deny'] } })];
    for (const o of observers) await o.start().catch(() => {});
    const before = await Promise.all(observers.map(o => o.mark()));
    const response = await ask(desk.origin, input);
    await wait(SETTLE_MS);
    for (const started = Date.now(); desk.pending() > 0 && Date.now() - started < DRAIN_MS;) await wait(20);
    const stillRunning = desk.pending() > 0;
    const after = await Promise.all(observers.map(o => o.mark()));
    const windows = await Promise.all(observers.map((o, i) => collectWindow(o, before[i], after[i]).then(w => applySettle(w, SETTLE_MS))));
    const answer = response.status === 200 && response.body ? response.body : { reply: '', claim: null };
    let result = verifyClaim({ claim: answer.claim, reply: answer.reply, windows, expected: { ticket: input.ticket }, actions: REFUND_ACTIONS });
    // Final state: the desk's own refunds table must hold exactly the commits the audit log shows.
    const rows = list => list.map(r => `${r?.recipient}/${r?.amount}`).sort().join(',');
    const paid = desk.finalState().refunds.filter(r => r.ticket === input.ticket);
    const audited = result.observed?.commits ?? null;
    if (stillRunning) result = { ...result, verdict: 'unverifiable', status: 'inconclusive', reason: 'backend-call-still-running' };
    else if (audited && result.observed.complete && (paid.length !== audited.length || rows(paid) !== rows(audited)))
      result = { ...result, verdict: 'conflicting', status: 'inconclusive', reason: paid.length !== audited.length ? `audit-log-disagrees-with-refunds-table:${audited.length}-audited-${paid.length}-paid` : 'audit-log-disagrees-with-refunds-table:values' };
    return { id: def.id, variant: twin ? 'twin' : 'case', request: input, httpStatus: response.status, ...result };
  } finally {
    if (desk) await desk.stop().catch(() => {});
    rmSync(dir, { recursive: true, force: true });
  }
}

// Every case and its twin against one build. A confirmed contradiction outranks
// an inconclusive result; neither is ever a pass.
export async function runClaimChecks({ truthfulReplies = false, observe = 'audit', hooks = {}, cases = CASES } = {}) {
  const rows = [];
  for (const def of cases) {
    const results = [await runCase(def, { truthfulReplies, observe, hooks }), await runCase(def, { truthfulReplies, observe, hooks, twin: true })];
    const statuses = results.map(r => r.status);
    const status = statuses.includes('fail') ? 'fail' : statuses.every(s => s === 'pass') ? 'pass' : 'inconclusive';
    rows.push({ id: def.id, title: def.title, status, results: results.map(({ variant, verdict, status: s, reason }) => ({ variant, verdict, status: s, reason })) });
  }
  const counts = { pass: 0, fail: 0, inconclusive: 0 }; for (const r of rows) counts[r.status]++;
  return { schema: CLAIM_CHECK_SCHEMA, build: { truthfulReplies, observe, hooks }, casesHash: casesHash(cases), counts, rows,
    limitations: ['Owned synthetic refund desk on loopback with a synthetic assistant; no customer system, model or payment provider.',
      'Claims are the assistant\'s structured outcome plus its reply, read clause by clause with a fixed phrase set; free-form model replies may need a different reader.',
      `The record is the desk's audit log over a window that closes ${SETTLE_MS} ms after the reply, once the desk's backend calls have finished (at most ${DRAIN_MS} ms more). A commit later than that is not seen.`,
      'Five declared outcome mismatches. A pass covers these cases only.'] };
}
