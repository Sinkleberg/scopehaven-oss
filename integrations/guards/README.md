# Runtime guards

The suite's checks tell a team that two things can go wrong. These guards are what an application installs so they stop going wrong:

| Check | What it finds | Guard |
|---|---|---|
| MIDTASK-01 | Work authorized before access was removed still commits afterwards | `createAccessGuard` re-checks at every commit |
| TRUTH-01 | The app blocked an action, but the reply says it succeeded | `createClaimGuard` compares the reply with the record |

A request-level permission check runs once, when the request starts. An agent turn can keep committing effects for seconds after that, so removing access mid-turn may not stop it, and a reply composed from the request can report work that never happened.

## The library (`guards.mjs`)

Pure and framework-neutral: no I/O, no credentials, no network. The application supplies small functions that read its own state. Every decision goes to `onDecision` so the app can audit it. The guards do not replace the app's authorization; they re-run the app's own check at the moment that matters.

### Access guard

```js
const guard = createAccessGuard({ currentAccess, onDecision });
const turn = await guard.beginTurn(principalId);          // at the start of the work
await guard.beforeCommit(turn, { action, resource });     // immediately before each effect
```

`currentAccess(principalId)` returns the app's live view: `{ active, grantsVersion, allows?(action, resource) }`. It must read the store on every call; a guard that caches is the defect it is meant to prevent.

`grantsVersion` must be comparable by value: a string, a finite number or a bigint. `null`, `NaN` and objects are reported as `access-unreadable` rather than used, because `null` would make the version check never fire and an object or `NaN` would deny every commit. `allows`, when present, must be callable; an authz answer that arrived as data would otherwise skip the permission check silently, so it is reported as unreadable too. A permission check that throws is unreadable, not allowed.

`beforeCommit` accepts only the turn object `beginTurn` returned, not a copy of it. A copy could be handed back with a refreshed `grantsVersion`, which would defeat the one check that notices authority moving.

`beforeCommit` throws `GuardDenied` when:

| Reason | Meaning |
|---|---|
| `principal-inactive` | The principal is no longer active. |
| `grants-changed` | The grants version moved since the turn began, so this is a different authority, even if the principal is active again. |
| `permission-revoked` | The app now refuses this action on this resource. |
| `access-unreadable` | Access could not be read, came back malformed, or carried a grants version that cannot be compared. Unreadable is a denial, never a pass. |

`guardCommits({ guard, turn, effects, resourceOf })` wraps an effect map so every call passes `beforeCommit` first. The check runs before the effect, so a denial means that call committed nothing.

### Claim guard

```js
const claims = createClaimGuard({ onDecision });
const { verdict, reply } = claims.review({ claim, reply, record, identifiers });
```

`record` is what the app's own store shows for this work: `{ committed: true | false | null }`, where `null` means the app could not determine the outcome. The reply is read clause by clause with the shared reader in `integrations/claim-check/verify.mjs`, which handles negation and masks ids the reply quotes.

| Verdict | When | Reply |
|---|---|---|
| `supported` | The reply, the claim and the record agree | Unchanged |
| `unsupported` | An outcome is asserted that the record contradicts | Replaced |
| `unverifiable` | The record could not be read, so success cannot be asserted | Replaced |
| `no-claim` | The reply asserts no outcome the reader recognises | Unchanged |

Three kinds of assertion are compared with the record, not just success:

- **Success**, which needs a record that shows the effect.
- **Failure**, because telling the user an action failed when it committed invites a second payment.
- **Still pending** (`queued`, `awaiting approval`), for the same reason. Pending alongside a success claim is ordinary wording ("processed; the receipt is queued for approval") and is left alone.

**The replacement has to be true as well.** When the record shows part of the work landed (`{ committed: false, effects: 1, expected: 3 }`), the guard says so rather than claiming nothing changed, and when the effect did commit it asks the user to check rather than asserting either outcome. `CLAIM_MESSAGES` carries the three sentences (`unsupported`, `partial`, `unverifiable`) and an app can replace any of them.

## The demonstration (`guarded-app.mjs`)

An owned synthetic app on loopback runs one task of three effects for a signed-in agent, with a control hold that pauses it between authorization and its first commit. The same app runs with `guards: false` and `guards: true`; nothing else differs.

| Run | Effects committed | What the agent was told |
|---|---|---|
| Guards off, agent suspended mid-task | 3 of 3 | "All 3 steps completed successfully" |
| Guards on, agent suspended mid-task | 0 | Told it was not completed |
| Guards on, no access change | 3 of 3 | "All 3 steps completed successfully" (unchanged) |
| Guards on, a different agent suspended | 3 of 3 | Unchanged |
| Guards on, suspended then reactivated while paused | 0 (`grants-changed`) | Told it was not completed |
| Guards on, the app's own commits fail part-way | 1 of 3 | Told it was not completed in full, and that part was applied |
| Guards on, outcome unreadable | 3 of 3 | Told the outcome could not be confirmed |

```js
import { startGuardedApp } from './guarded-app.mjs';
const baseline = await startGuardedApp({ dbPath, tokens, guards: false }); // both defects reproduce
const guarded = await startGuardedApp({ dbPath, tokens, guards: true });   // neither does
```

Tests: `node --test integrations/guards/guards.test.mjs` (21 tests, under a second). They cover the four denial reasons, how a grants version is compared and which kinds are accepted, an `allows` that is data or throws, that only an issued turn is accepted, that access is read fresh at every commit, that a denied effect never runs and keeps its receiver, each claim verdict including the failure and pending cases, that every replacement sentence is true for the record that produced it, negation and id masking in the reply reader, the durable audit trail, the app-level before and after, the allowed-path controls, and the app's own request-level rules.

## Scope and limits

- **Synthetic only.** The demonstration app is an owned synthetic app on loopback with synthetic users. There is no model, provider or customer system.
- **The app's own state.** The guards are only as good as the functions the app supplies. `currentAccess` must read the live store, and `record` must reflect what was actually committed.
- **One authority model.** "Changed" here means inactive, a moved grants version, or a refused action. An app whose authority changes in other ways needs those folded into `currentAccess`.
- **Replacing a reply is a last line.** It stops a false claim reaching the user; it does not undo an effect that already committed. The access guard is what prevents the effect.
- **The reply reader is domain-shaped.** It is the shared reader from `integrations/claim-check`, whose phrases are refund-and-ticket wording. An app whose replies read differently should pass a structured `claim`, which is compared whatever the prose says.
- **Not a scanner.** These guards protect an app at runtime. Finding the defect in the first place is what the suite's MIDTASK and TRUTH checks, and `integrations/kill-switch`, are for.
