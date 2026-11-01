# Watch-first setup: draft the declarations from what the target did

Writing a profile by hand is most of the setup work. Watch-first drafts it instead: run the target once with its observers on and no declarations, then turn what the observers recorded into proposed checks. A person approves every proposed line before any command will load the profile.

No model is used anywhere in this module. Every drafted line is computed from recorded events, and each one is only a proposal. It says what the application did, not what it should do.

## The three steps

```sh
./scopehaven watch-first watch watch.json --authorization authorization.json --out record.json
./scopehaven watch-first draft watch.json --record record.json --out-profile drafted.targets.json --out-report draft-report.json
./scopehaven watch-first approve drafted.targets.json --approved-by "Your Name" --out approved.targets.json
./scopehaven check-config --config approved.targets.json
./scopehaven assess --config approved.targets.json --target my-app --authorization authorization.json
```

`lines PROFILE` lists the drafted lines and which of them are approved. `approve --strip` writes the plain profile once every line is approved (below). Outputs are new files (never overwritten), mode 0600.

### 1. The watch file (`scopehaven-watch/1`) and the watch run

A watch file is a profile target without checks, plus the turns to send:
- `target`: the application, its actors and the observers you can give. The product's own validator checks it, as it will check the drafted profile. It must be a local application on loopback.
- `turns`: up to 64 `{ id, actorId, method, path, body? }`. Each is sent once.
- `checks: { first, last }` and `requiredControlIds` (optional): hand-written checks, such as identity controls. They are not sent in the watch. They go into the draft unchanged, before and after the drafted lines. A `last` check must not commit a write: after the drafted lines, its effect would hold every drafted effect.only clause undecided (the draft warns). Put writing controls in `first`.

`watch` needs an authorization record that covers the target, as `assess` does.
- **The window.** It is checked before every request and when every observer call starts (the observers are built through `guardObserverFactory`). Once it ends, nothing more is sent or started and no record is written (`authorization-window-ended`).
- **Each turn.** The command starts the observers. For each turn it marks every observer, sends the turn through the connector's own loopback transport and waits the largest declared settle.
- **Witnesses.** In the connector's order, an observer with a witness is marked for it (`{ headSplit: true }`), sent its witness, then given its end mark. The other observers are marked, and one window is collected per observer.
- **Failures.** As in a run, an observer whose start or mark fails reads a failed window and the watch goes on.
- **Windows.** Windows are collected whole, not scoped to a destination as a check's are, because the draft reads each window's coverage as a whole.

The watch record (`scopehaven-watch-record/1`) holds each turn's status and its sealed windows. Events are kept by identifier and digest, as a run keeps them. The record judges nothing. Its `recordId` and `watchId` tie it to its watch file. They are checksums: they catch an edit made without recomputing them, not a deliberate re-seal.

### 2. The draft

The draft follows policy-import's draft (`../policy-import/draft.mjs`). Lines are proposals only, each with one provenance entry. Turns that are not drafted are listed with the reason, and warnings are listed too. A `draftId` covers the canonical body. Policy-import marks a whole draft `"confirmed": false`. Here, every drafted line carries `"drafted": "observed"` and `"approved": false`, so the profile itself refuses to load until each line is approved.

For each write turn (one whose judged windows hold a committed insert, update, delete, send or access change), two lines, in this order:
- **`WF-<turn>-USE`**, the allowed-use twin. It is a required control that repeats the turn, with an `effect.count` per expected effect. An application that refuses everything cannot pass the pair.
- **`WF-<turn>-ONLY`**, an `effect.only` check. It sends the turn again and expects the effects the watch saw, each with its observed count, and nothing else.

The twin goes first. Its effects settle before the ONLY window opens. If the same effect were made after the ONLY check, the settlement rule would read it as possibly the ONLY check's own late effect, and the check would stay undecided.

**One target per write turn.** For the same reason, when the watch has more than one write turn, each is drafted in a target of its own: `<target id>-<turn id>`, with the hand-written checks around it. In one run, a later turn's write fits an earlier effect.only clause and holds it undecided, so you assess each target. A profile holds at most 20 targets, so a watch with more write turns than that is refused: split the watch file. A split id is cut to the validator's 80 characters (and a name to 160), and ids that would collide are refused.

**Which sources decide.** The clause's `sources` are the authoritative sources whose windows were complete on every write turn. A net-only snapshot, presence-only telemetry or a failed observer is left out, and a warning names it. A write only that source records is not judged.

**Custody.** A source whose record the application can write, such as its own audit table, can fail "nothing else happened" but never pass it (`src/custody.mjs`). The draft says so when a judged source is one of these. To get a pass, narrow `sources` to independent ones, such as an egress recorder on the request path. That pass then ignores writes only the application's own record shows.

**Selectors.** A resource is pinned only when the turn's path names it. That means its type and id appear as consecutive path segments (`orders/B-1` in `/api/orders/B-1/refunds`), or its last segment alone appears in the path when that segment is not a bare number (`B-1` in an egress resource `POST /v1/refunds/B-1`). A resource the application generated is left open, even when its id happens to equal a number in the path (`refunds/1` beside `/api/orders/1/refunds`). An actor is pinned when the observer named one.

**Undeclared principals.** An observer names a principal it does not declare by a keyed digest (`unlisted:...`), which cannot be read back. The draft infers the principal only when both of these hold:
- the turn's own actor is missing from that observer's principals;
- the observer shows exactly one undeclared principal in the turn.

It then pins the turn actor's `principalId` and drafts the observer with it added, recorded as an inference. A digest names the same principal across a run, so one that appears in write turns sent as different actors is no one's: no turn that shows it is drafted.

**Not proposed:**
- a write the application answered with a non-2xx status (`write-with-refusal-status`);
- a write attributed to anyone other than the turn's actor (`write-by-another-principal`), read over every committed write of the turn from every source, judged or not;
- a turn with no committed write (`no-write-observed`), or none any authoritative observer could report (`no-complete-window`);
- a turn whose response was incomplete (`response-incomplete`);
- a turn whose writes only non-deciding sources saw (`no-deciding-source`).

Each of these is listed with its reason, and the first two also raise a warning.

**Observers are kept as declared.** They are never narrowed to what was seen: a snapshot cut down to the tables one run wrote would be blind to a collateral write anywhere else. The draft report's `inventory` lists what was seen instead:
- destinations, with the declared paths they hit (raw paths are never stored, so an undeclared path reads `METHOD *`);
- tables written and audit actions;
- identities used.

Columns are not recorded by any observer (events carry a digest of the row, never its fields), so none are drafted.

Before writing anything, the draft runs the product's own validator on the profile as approval would make it. It also reports the known-negative self-test of the drafted checks (`src/known-negative.mjs`). An `effect.only` clause is not planted by that mode, so a drafted ONLY check reads `partial`: its status can be shown to fail, and its clause is shown on the real builds instead (below).

### 3. Approval, and the gate every load keeps

`src/registry.mjs` `loadProfiles` reads every profile through `lines.mjs` before the validator. That covers `check-config`, `assess`, `gate` and the dashboard. A profile with any drafted line whose `approved` is not `true` is refused, with the lines named:

```
Scopehaven could not run: The profile has 2 drafted line(s) no one has approved (proposals drafted from a watch run): target "example-watch" check "WF-T2-USE"; target "example-watch" check "WF-T2-ONLY". Review each one, then set "approved": true and "approvedBy", or delete it.
```

The markers are read exactly:
- An approved line needs `approvedBy` (1 to 120 characters).
- `approvedBy` on an unapproved line is refused.
- `drafted` must be `observed`.
- Markers may stand only on a check, an observer or an actor. A marker on the document or on a target is refused.
- A check's request body is the application's data, so `"approved"` inside a body is not a marker.

An approved line's markers are removed before validation, so an approved profile has the same profile hash as the same lines written by hand. The provenance stays in the drafted file and the draft report, never in a run.

**Tools that read a profile file directly** call the validator on the file itself, without the loader's gate, and refuse marker keys: `coverage-report`, `grant-use`, and policy-import `confirm` and `explain`. For those, write the plain profile with `approve --strip`. It refuses, through the same gate, while any drafted line is unapproved. `approvedBy` is a label the caller supplies. Like policy-import's `confirmedBy`, it authenticates no one, and editing `approved` and `approvedBy` by hand is the same act as running `approve`.

## What the tests show (`watch-first.test.mjs`, on the owned example app)

The tests use `examples/observed-support-app.mjs`: loopback, synthetic data and a fixed-text assistant. The watch runs on the `secure` build with an audit table, a table snapshot and an egress recorder. The approved draft is then run on these builds:

| Build | `WF-T2-USE` | `WF-T2-ONLY` |
| --- | --- | --- |
| secure | pass | inconclusive (the audit table's custody) |
| refund-plus-discount | pass | fail: `insert discount.create orders/B-1` |
| refund-plus-cancel | pass | fail: `update subscription.cancel subscriptions/globex-monthly` |
| refuse-b (refuses everything) | fail | not pass |

Narrowed by a person to the egress recorder, `WF-T2-ONLY` passes on `secure` and fails on `pay-wrong-order`.

A watch on the `leaky` build does not propose the cross-company refund the application answered with 404 and still committed. A watch on `leaky-owner-audit` does not propose the refund audited under the order owner's name.

## What it does not establish

- A drafted line is what one watch run did, so a defect present during the watch is drafted as expected behaviour. That is why a person approves every line, and why the two refusal-shaped cases above are never proposed.
- The twin repeats the turn. When an action consumes its object, point the twin at another object before approving it (the draft warns on every write twin).
- A watch sees only what its declared observers can see. A source left out of the clause, or never declared, judges nothing.
