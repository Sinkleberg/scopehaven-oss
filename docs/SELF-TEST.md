# Known-negative self-test (`--self-test`)

A check that cannot fail is broken: it reads pass on a vulnerable build as well as on a repaired one. `--self-test` plants violations in every check of an HTTP contract profile before the run, and refuses a clean result when any check is shown unable to fail or always failing. A check it cannot plant is reported, not proven, so a clean result with the flag is not a proof that every check can fail (see What a report says). It plants violations through the same pure evaluators a run uses (`src/known-negative.mjs`; the CLI and gate wiring is `src/self-test.mjs`) and contacts nothing: no target, observer, authorization record or credential is read for it.

This is a different check from the confined launch's self-test (`--confine`, [ONBOARDING.md](ONBOARDING.md)), which tests the sandbox profile.

## Commands

| Command | What it does with the result |
|---|---|
| `./scopehaven check-config --config targets.json --self-test` (or the targets file named by `SCOPEHAVEN_TARGETS_FILE`) | Adds a `selfTest` report to each HTTP contract target in the listing. Exit 1 when any target has a broken check, 0 otherwise. No run is made, so nothing needs authorizing. |
| `./scopehaven assess --config targets.json --target <id> --authorization record.json --self-test` | Runs the self-test, then the assessment as usual. The printed summary carries `selfTest`, and the exit is 1 when a check is broken, even if every check passed. |
| `./scopehaven gate --target <id> --config /abs/targets.json --out /abs/gate-dir --authorization /abs/record.json --self-test` | Runs the self-test before the record is checked or the output directory is touched, then gates the run as usual. A broken check adds the reason `check-cannot-fail` or `check-always-fails` (exit 1). The summary, printed and saved under `gate-summaries/`, carries the report as `selfTest`. |
| GitHub Action input `self-test: 'true'` | Passes `--self-test` to assess or the gate. With `fail-on: fail` a broken check fails the job (`assessment-not-clean`, or `gate-check-cannot-fail` / `gate-check-always-fails`). The report is in `gate-summary.json` or, without a baseline, in `assess.json` in the evidence artifact. |

The self-test never changes a verdict. A broken check's own row reads exactly what the run observed, and the self-test only keeps the result off clean. The refusal lives in the command's output, its exit code and the saved gate summary, not in the saved run: an HTML, SARIF or comparison export, and the dashboard's gate view, recompute from the run and do not carry it. Only HTTP contract targets from `--config` are planted. With any other target (the built-in fixtures or the owned refund contract) the flag is refused with `self-test-unsupported-target` (exit 2) before anything runs, so it never reads as tested when nothing was. The gate also refuses it beside `--saved-refund` (`invalid-options`), since a saved result is read, not run. The gate refuses a target that is unavailable or missing credentials for that first (`target-unavailable`, `target-credentials-unavailable`), as without the flag, and assess refuses it as without the flag (exit 2) before printing any report. `check-config --self-test` still plants and lists such a target (`available: false`, with its `selfTest` report), since it contacts nothing. If the self-test itself cannot run (an exception, not a finding), the gate reports `self-test-error` and assess exits 2; nothing is authorized, written or sent. `check-config --self-test` with no HTTP contract target is refused the same way.

## What a report says

The report (`scopehaven-known-negative/1`) names check ids, predicate positions and kinds, outcomes and reason codes. It never includes an expected value, a planted value, a declared name or a canary. For each predicate, a fixed twin (one synthetic observation that satisfies it) and a defective twin (the same observation with that predicate violated) go through the evaluator:

| Predicate outcome | Meaning | Effect on the result |
|---|---|---|
| `proven` | The fixed twin passes, and the defective twin fails on this predicate's own row for the planted reason. | none |
| `cannot-fail` | The violation reached the evaluator and did not read fail. Examples: `json.exists` at the root, `json.noForeignValues` with no other tenant's identifier, `effect.exists` on presence-only evidence, or an absence that attribution charges to background or late activity. | refused: `check-cannot-fail` |
| `always-fails` | The fixed twin fails too (contradictory predicates), so the check's fails mean nothing. | refused: `check-always-fails` |
| `pass-unreachable` | It can fail, but its fixed twin never passes (custody, pairing, a name not given exactly, no declared settle, net-only coverage), so a repair could never be confirmed. The reason is named. | reported |
| `unprovable` | Nothing the run could record was planted, or this mode does not plant that kind. The reason is named. | reported |
| `error` | An evaluator threw on the plant. | reported |

A check is `broken` when any predicate cannot fail or always fails, `proven` when every predicate is proven, and `partial`, `unprovable` or `error` otherwise. Only `broken` refuses a clean result. `unprovable`, `partial` and `error` say what the self-test could not show, not that the check is wrong, so a profile with many of them should be read with that in mind. A clean result with `--self-test` does not mean every check was shown able to fail. Read `selfTest.counts`.

To fix a broken check, read its predicates in the report: the `index` is the position in the check's `assertions` or `effects`. Remove a vacuous predicate, or replace it with one that is decided (for example, an exact name instead of a prefix, or an authoritative observer for an `effect.exists`). Remove one of two contradictory predicates.

## Not covered

- Claim rules, `effect.only`, `countBy`, body-field and upstream selectors, and exact coverage (Postgres row versions, a snapshot change column) are listed `unprovable`, never counted as proven.
- Lifecycle steps, captures, preconditions, sequences and conversation specs are not planted. Their checks are judged only on the response and effect predicates above.
- Custody that depends on an observer declaration (a provider feed's key source) is judged on the source alone.
- Judged late effects and the other settlement findings, later outcomes and app-log admissions are not modelled. Each can only stop a pass that this mode shows as reachable, never a fail.
- Seeded canary values: the module can plant one (`knownNegativeCanary`), but no profile field declares a canary yet, so this flag plants none.
- The self-test models what each declared observer can record, from its declaration. It does not show that the real observer, application or database records it, which is what a run's evidence is for.
