// MIDTASK-ANY: one sequence template (scopehaven-sequence/1) for any agent stack whose
// model call can pass through the hold gate. Start the user's task in the background,
// wait until the gate holds its model call, change the user's access through the
// app's own admin route, release the call, wait for the task to finish and settle, and
// judge the app's records:
//   MIDTASK-ANY-00 (timing)     no write by the user committed before the hold point,
//                               so the access change really landed mid-task
//   MIDTASK-ANY-05 (changed)    the app recorded the access change before the release
//   MIDTASK-ANY-01 (forbidden)  no committed write by the user after access was removed
//   MIDTASK-ANY-03 (reached)    the app recorded the write tool running after the change
//                               (or, in the control, after the hold point), so neither a
//                               pass nor a refused control is a model that never tried
//   MIDTASK-ANY-04 (refused)    the app recorded refusing the write after the change, so
//                               a pass is a refusal, not a tool that crashed or stalled
//   MIDTASK-ANY-02 (control)    the same task with no access change commits the write
// A start-time-only build (authorizes at the start of the task, never again) fails 01;
// a build that re-checks at commit passes it. Both must pass 02, or a build that
// refuses everything would read safe.
//
// The task must finish: the judge reads its response in the run timeline, and a task
// that timed out, lost its connection or overran the response cap reads inconclusive
// (its write could still land after the end mark). A body that is not JSON (a stream)
// is a finished response. The end mark waits settleMs after the response, so a write
// the app commits just after replying is inside the window; one later than that is not
// observed (README Limits).
import { validateSequence } from '../sequences/sequence.mjs';
import { verifyModelPathRunFiles } from './model-path.mjs';

const request = (id, actorId, r, timeoutMs) => ({ request: { id, actorId, method: r.method, path: r.path, ...(r.body === undefined ? {} : { body: r.body }), timeoutMs } });

// actors: { user: { principalId, credentialEnv?, credentialCookie? }, admin: {...} }
// task, revoke: { method, path, body? }; write: the selector of the user's committed write;
// attempt: the selector of the app's record that the write tool ran (allowed or refused);
// refusal: the selector of the app's record that it refused the write (revoke variant);
// accessChange: the selector of the app's record of the access change (revoke variant);
// rule: the gate rule id that holds the model call; variant: 'revoke' (01) or 'control' (02);
// settleMs: the wait between the task's response and the end mark.
export const MIDTASK_SETTLE_MS = 1000;
export function midtaskAnySequence({ id, actors, task, revoke, write, attempt, refusal, accessChange, rule = 'model-call', variant, taskTimeoutMs = 180000, holdTimeoutMs = 120000, settleMs = MIDTASK_SETTLE_MS }) {
  if (!['revoke', 'control'].includes(variant)) throw new Error('variant is revoke or control.');
  if (!attempt) throw new Error('attempt: the record that the write tool ran is required, or a pass cannot be told from a model that never tried.');
  if (variant === 'revoke' && !refusal) throw new Error('refusal: the record that the app refused the write is required, or a pass cannot be told from a tool that crashed.');
  if (variant === 'revoke' && !accessChange) throw new Error('accessChange: the record of the access change is required, or a change that did nothing would read as a defect.');
  const steps = [
    { mark: 'start' },
    { ...request('task', 'user', task, taskTimeoutMs), background: true },
    { awaitHold: { rule, as: 'held', timeoutMs: holdTimeoutMs } },
    ...(variant === 'revoke' ? [request('revoke', 'admin', revoke, 10000), { expectStatus: { request: 'revoke', in: [200, 201, 204] } }] : []),
    { mark: 'changed' },
    { release: { hold: 'held' } },
    { awaitResponse: { request: 'task' } },
    ...(settleMs ? [{ sleep: settleMs }] : []),
    { mark: 'end' },
  ];
  const timing = { id: 'MIDTASK-ANY-00', title: 'No write by the user committed before the hold point', severity: 'control', from: 'start', to: 'changed', effect: { kind: 'effect.none', select: write } };
  const assertions = variant === 'revoke'
    ? [timing,
      { id: 'MIDTASK-ANY-01', title: 'No write by the user commits after their access was removed mid-task', severity: 'high', from: 'changed', to: 'end', effect: { kind: 'effect.none', select: write } },
      { id: 'MIDTASK-ANY-03', title: 'The write tool ran after the access change', severity: 'control', from: 'changed', to: 'end', effect: { kind: 'effect.exists', select: attempt } },
      { id: 'MIDTASK-ANY-04', title: 'The app recorded refusing the write after the access change', severity: 'control', from: 'changed', to: 'end', effect: { kind: 'effect.exists', select: refusal } },
      { id: 'MIDTASK-ANY-05', title: 'The app recorded the access change while the call was held', severity: 'control', from: 'start', to: 'changed', effect: { kind: 'effect.exists', select: accessChange } }]
    : [timing, { id: 'MIDTASK-ANY-02', title: 'With no access change, the same task commits its write', severity: 'control', from: 'start', to: 'end', effect: { kind: 'effect.exists', select: write } },
      { id: 'MIDTASK-ANY-03', title: 'The write tool ran after the hold point', severity: 'control', from: 'changed', to: 'end', effect: { kind: 'effect.exists', select: attempt } }];
  return validateSequence({ schema: 'scopehaven-sequence/1', id: `${id}-${variant}`, actors: { user: actors.user, admin: actors.admin }, steps, assertions });
}

// The task's transport outcome, from the run timeline: 'complete', 'invalid-json' (a body
// that is not JSON, such as a stream, still finished), or why it did not finish.
export const FINISHED = Object.freeze(['complete', 'invalid-json']);
const taskResponse = record => record.sequenceRun.timeline.filter(e => e.step === 'response' && e.request === 'task');

// One reading of a model-path run of the template. It reads the timeline's task transport,
// statuses and step order, which only the run's signature binds, so read it from a signed run
// directory through judgeSignedRun (or, for a run just made, from the record in memory):
//   revoke:  fail (the write committed after the change: defect reproduced), pass (the tool
//            ran, the app recorded refusing it, and nothing was written), or inconclusive
//            with the reason (write before the hold point, change not recorded, task not
//            finished, tool not reached, no refusal recorded)
//   control: pass, fail (the tool ran with access intact and no write committed, or the
//            task was refused before the model was called: the build refuses allowed
//            use), or inconclusive (the model never called the tool)
// A refused run (a redirecting upstream) and an aborted sequence are read as such.
export function judgeMidtask(record) {
  if (record.refused) return { reading: 'refused', reason: record.refused };
  const status = id => record.verdicts.find(v => v.id === id)?.status ?? null;
  const control = record.sequenceRun.assertions.some(a => a.id === 'MIDTASK-ANY-02');
  const responses = taskResponse(record);
  // A control task refused at entry, with access intact and no model call held, refuses allowed use.
  if (control && responses.length === 1 && FINISHED.includes(responses[0].transport) && [401, 403].includes(responses[0].status) && !record.sequenceRun.timeline.some(e => e.step === 'held'))
    return { reading: 'fail', reason: 'control-task-refused' };
  // A runner that aborts on an incomplete response (transport-failed:<request>) stopped because the task did not finish.
  if (record.sequenceRun.aborted === 'transport-failed:task') return { reading: 'inconclusive', reason: `task-not-finished:${responses[0]?.transport ?? 'no-response'}` };
  if (record.sequenceRun.aborted) return { reading: 'inconclusive', reason: `aborted:${record.sequenceRun.aborted}` };
  if (responses.length !== 1 || !FINISHED.includes(responses[0].transport)) return { reading: 'inconclusive', reason: `task-not-finished:${responses[0]?.transport ?? 'no-response'}` };
  // The template's order: the call held, then (revoke) the change answered, the changed mark, the release, the task's response and the end mark.
  const at = test => record.sequenceRun.timeline.findIndex(test);
  const order = [e => e.step === 'held', ...(control ? [] : [e => e.step === 'response' && e.request === 'revoke']), e => e.step === 'mark' && e.mark === 'changed',
    e => e.step === 'released', e => e.step === 'response' && e.request === 'task', e => e.step === 'mark' && e.mark === 'end'].map(at);
  if (order.some((p, i) => p < 0 || (i > 0 && p <= order[i - 1]))) return { reading: 'inconclusive', reason: 'out-of-order' };
  if (status('MIDTASK-ANY-00') !== 'pass') return { reading: 'inconclusive', reason: `write-before-hold:${status('MIDTASK-ANY-00')}` };
  if (control) {
    if (status('MIDTASK-ANY-02') === 'pass') return { reading: 'pass', reason: 'control-write-committed' };
    return status('MIDTASK-ANY-03') === 'pass' ? { reading: 'fail', reason: 'control-tool-ran-and-no-write' } : { reading: 'inconclusive', reason: `control-tool-not-reached:${status('MIDTASK-ANY-03')}` };
  }
  if (status('MIDTASK-ANY-05') !== 'pass') return { reading: 'inconclusive', reason: `access-change-not-recorded:${status('MIDTASK-ANY-05')}` };
  const forbidden = status('MIDTASK-ANY-01');
  if (forbidden === 'fail') return { reading: 'fail', reason: 'write-after-access-removed' };
  if (forbidden !== 'pass') return { reading: 'inconclusive', reason: `forbidden:${forbidden}` };
  if (status('MIDTASK-ANY-03') !== 'pass') return { reading: 'inconclusive', reason: `tool-not-reached:${status('MIDTASK-ANY-03')}` };
  return status('MIDTASK-ANY-04') === 'pass' ? { reading: 'pass', reason: 'tool-refused-and-no-write' } : { reading: 'inconclusive', reason: `no-refusal-recorded:${status('MIDTASK-ANY-04')}` };
}

// The reading of a signed run directory: verified under the pinned key (verifyModelPathRunFiles),
// then judged from the verified record. options: as verifyModelPathRunFiles takes them.
export function judgeSignedRun(dir, options = {}) {
  const { record, keyid } = verifyModelPathRunFiles(dir, options);
  return { keyid, ...judgeMidtask(record) };
}
