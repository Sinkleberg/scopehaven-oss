# Access-change cases

These cases ask one question: if work was legitimately started, can it still produce an effect after the authority behind it changed?

Each case is a declared timed sequence. It runs on the existing sequence runner (`integrations/sequences`) and is judged by the existing audit-table observer (`integrations/observers`); this folder does not change either. Every case has a permitted twin with no access change, which must still commit an exact number of refunds. Several cases also carry a same-run control: another user, or a fresh approval, that must still commit. A repair that blocks everything fails its controls and never passes.

## Cases

| Case | What changes | Forbidden result | Guard that prevents it |
|---|---|---|---|
| AC-LATE-REVOKE | The user is suspended while the refund is paused inside the payment step, before commit | A refund commits. (A fresh request after the suspension must also get 401.) | `commitRecheck` |
| AC-INFLIGHT-REGRANT | The user is suspended and then regranted while the refund is paused | The refund commits under its old authorization | `commitRecheck` |
| AC-REGRANT | The user is suspended and regranted, and then uses an approval issued before the suspension | The old approval commits. (A fresh approval must still commit.) | `grantsVersionBinding` |
| AC-TARGET | A refund names a different recipient, a larger or smaller amount, or another ticket than its approval, directly or through the queue | A refund commits. (Another user spending or queueing the approval must get 403.) | `approvalBinding` |
| AC-QUEUED | The user is suspended after queueing a refund and before the worker drains it | The queued refund commits. (Another user's queued refund must still commit.) | `commitRecheck` |
| AC-QUEUED-REGRANT | The user is suspended and regranted between queueing and draining | The queued refund commits | `commitRecheck` |
| AC-RETRY | The worker commits, then fails before acknowledging, and the job is retried | A second refund commits. (In the twin, a job that failed before commit must commit on retry, and two distinct jobs on one ticket must both commit.) | `idempotentRetry` or `commitRecheck` (layered) |
| AC-RETRY-UNMARKED | The worker writes the refund, then fails before the approval is marked used, and the job is retried | A second refund commits. The commit-time recheck passes the retry because the approval still reads unused, so only the job's idempotency key stops it. (Another user's job in the same drain must still commit; in the twin, a job that failed before commit must commit on retry.) | `idempotentRetry` |
| AC-CONCURRENT | Two users are paused in the payment step, and only one is suspended | The suspended user's refund commits. (The other user must still commit in the same run.) | `commitRecheck` |

## How results are judged

- **Sequence assertions read the app's audit table.** The observer declares it an authoritative source with complete coverage, but it is the application's own record, so under custody a forbidden-absence row that rests on it holds its pass at inconclusive. Its fails stand, and a twin's permitted commit still passes. A forbidden refund is selected by action (`refund.commit`) and ticket under any principal, so a commit by another identity still counts. Controls use other tickets, so every count is unambiguous.
- **The final state is two rows, read from the desk's own tables.** After a bounded settle (300 ms), the harness reads the refunds and jobs tables. Both rows are tagged custody `subject-writable`, because those tables are the application's own, and they answer different questions:
  - `<case>-FINAL-STATE` (boundary, critical): the refunds table holds no refund the declared outcome did not allow. More refunds than declared on any ticket is a fail, even when the audit table missed the commit. Its pass is held at inconclusive, because nothing outside the application witnesses it.
  - `<case>-FINAL-STATE-WORK` (control): the declared refunds all happened and the jobs settled. Fewer refunds than declared is a fail. A job not in a terminal state (done or denied) means the work did not finish, which is inconclusive. It keeps its pass, with custody stated as a limit.
  - So a forbidden run reports a held boundary row beside a passing control row, and the two do not conflict.
- **Revocation closure is a third row.** Every run whose sequence suspends a user also carries `<case>-REVOKE-CLOSE` (critical). It fails when an open job of the suspended user still carries the authority the suspension retired, meaning the job's grants version is below the user's current one. A parked job of that kind fails this row, and so the case, while the `-FINAL-STATE-WORK` row still reads the same job as unsettled (inconclusive). A desk that logged no suspension, or whose two records of it disagree, reads inconclusive, and a pass is held under custody like the boundary row's.
- **Conflicting evidence.** If the audit table reports a forbidden commit on a ticket where the refunds table holds nothing, that row reads inconclusive (`conflicting`) rather than fail.
- **Request-level refusals are results of their own.** These are a fresh request from a suspended user, and another user spending or queueing an approval. They are read from the run's response timeline, so an app that fails one is reported as a fail, not as an aborted run. A confirmed fail outranks an observer error in the row roll-up.
- **Preconditions are checked.** Every access change, approval and drain is followed by a status check. A run that did not reach them aborts, and an aborted run never passes.
- **Each run is isolated.** Every run gets a fresh database, payment stub, hold gate and app.

The final-state check works because the desk is owned. For a customer app, add an equivalent observer on its own effect tables.

## Run

```js
import { runAccessChangeCases } from './cases.mjs';
const baseline = await runAccessChangeCases({ recheckAtCommit: false }); // 9 fail; every twin and control passes
const repaired = await runAccessChangeCases({ recheckAtCommit: true });  // 9 inconclusive: nothing fails, and custody holds each pass that rests on the desk's own tables
const oneGuardOff = await runAccessChangeCases({ recheckAtCommit: true, repairs: { approvalBinding: false } }); // only AC-TARGET fails
```

Tests: `node --test integrations/access-change/access-change.test.mjs` (about 45 s). The tests cover the following:
- Removing each guard fails exactly the cases that guard protects.
- An over-blocking build never passes.
- An unaudited commit is still caught. An audit row without a refund fails every control, and on a forbidden commit it reads inconclusive (`conflicting`) rather than pass.
- Unsettled jobs never pass.
- A failed request-level refusal is a fail.
- An access change that did not take effect never passes.
- A failed setup leaves no listener behind.
- The case definitions are pinned by hash.

## Scope and limits

- **Synthetic only.** The owned synthetic access desk runs on loopback with synthetic users. It uses no customer system, model or payment provider.
- **Bounded settle.** A commit later than the 300 ms settle is not seen.
- **Nine declared cases.** A repaired-build result covers these nine cases only, not every interleaving.
- **The contract for "revoked" varies.** Some apps intentionally let an already-authorized transaction finish. Agree the contract with the customer before applying these cases to their app.
- **Running against a real app.** For a customer app, write the same sequences against its admin API, with observers on its own audit and effect tables. The runner, gate and audit observer are the same.
