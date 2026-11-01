# Scopehaven GitHub Action

A composite action that runs a Scopehaven HTTP assessment against an application the workflow has started on loopback, optionally gates it against a saved baseline run, optionally diffs two policy matrices, exports JSON, HTML and SARIF (signed, with `sign: true`), optionally appends the signed run to an operator-kept evidence ledger and gates against the ledger's previous run, and writes a job summary. It uses the existing launcher (`scopehaven/scopehaven`) and needs no `npm install`: Scopehaven has zero runtime dependencies.

It runs on GitHub in this repository's own workflow, `.github/workflows/scopehaven-action.yml`, against the owned synthetic lab. "Verification" lists what the local tests and that workflow cover, and what is still not verified.

## Usage (from this repository)

From a workflow in this repository, use the in-repo path after checkout:

```yaml
permissions:
  contents: read
steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
    with:
      persist-credentials: false
  # Start your app in the background on 127.0.0.1 here.
  - uses: ./integrations/github-action
    env:
      SCOPEHAVEN_TARGET_APP_MEMBER_TOKEN: ${{ secrets.SCOPEHAVEN_TARGET_APP_MEMBER_TOKEN }}
    with:
      profile: path/to/targets.json
      authorization: path/to/authorization.json
      wait-url: http://127.0.0.1:3000/health
```

### From another repository: the root action

The repository root holds a second `action.yml`, a composite wrapper that declares the same inputs and outputs as this folder's and forwards every one of them here, so a workflow in another repository can write `uses: YusefSyed/scopehaven-oss@<ref>` and GitHub Marketplace can list the action. Its one step is `uses: $/integrations/github-action`: GitHub's self-repository reference, which resolves to this repository at the running commit rather than to whatever the caller checked out. `$/` is not available on GitHub Enterprise Server; there, use this folder directly, `uses: YusefSyed/scopehaven-oss/integrations/github-action@<ref>`, with the same inputs. `test/root-action.test.mjs` checks that the two files agree, and [docs/guides/ci-in-five-minutes.md](../../docs/guides/ci-in-five-minutes.md) is the copy-paste workflow.

A configured target runs only under an authorization record that covers it now ([RULES-OF-ENGAGEMENT.md](../../docs/RULES-OF-ENGAGEMENT.md)). The prepare step checks the record (`node integrations/roe/cli.mjs check`, the check assess and the gate make) before the wait or any request: without `authorization`, or with a record that is expired, edited, repeats a field name, is for another target or misses an endpoint or test account the run uses, the action stops there with exit 2 and `authorization refused (CODE)`, contacts nothing and saves no run. The prepare step also refuses a `wait-url` whose origin is not one of the record's origins (`authorization-origin`), so the wait never contacts an endpoint the record does not cover. The wait stops when the record's window ends (`authorization-window-ended`); assess and the gate send no further request and start no further observer call once it ends (one already running can finish its reads), and refuse to save or stamp a run whose window ended before it was saved. The record's checksum is unkeyed (not a signature), so keep the file where the application under test cannot write it.

[`example-workflow.yml`](example-workflow.yml) is a complete, inert example. It starts the owned synthetic lab (`./scopehaven lab`) as the app under test and includes a commented SARIF variant. Copy it to `.github/workflows/` only after review.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `profile` | required | HTTP target profile JSON, relative to `working-directory`. Origins must be literal `http://127.0.0.1:PORT`, or an `operator-remote` https origin that the `authorization` record names (enforced by Scopehaven). |
| `authorization` | `''` | Authorization record (`scopehaven-authorization/1`), relative to `working-directory`: a regular file, not a symlink. Needed for every configured target; the prepare step checks it before the wait, and without a covering record the action exits 2 before any request. The saved run, `report.html`, SARIF and the gate summary carry its id and checksum. |
| `target` | `''` | Target id in the profile. Optional when the profile has exactly one target. |
| `baseline-run` | `''` | A saved run to gate against: `run.json` from an earlier evidence artifact, or a store `runs/<id>.json` file. Its integrity digest is verified before use. |
| `fail-on` | `fail` | `fail` (follow assess and the gate), `inconclusive` (alias) or `never` (see below). |
| `report-only` | `false` | `true`: a report-only rollout through `report-only-until` (see "Report-only"). Until that date the job does not fail on what the checks find, and every report says REPORT-ONLY. Setup errors, errored checks, `require-model-identity` and `fail-on-policy-diff` still fail it. Exactly `true` or `false`. |
| `report-only-until` | `''` | The last day of the report-only window, `YYYY-MM-DD` in UTC, at most 90 days after the run date. Required with `report-only: true`, refused without it. A date already passed is accepted: the job follows `fail-on`. |
| `require-model-identity` | `false` | `true` requires `baseline-run` and a comparable model identity on both HTTP runs, observed by a model tap Scopehaven held in its own process (see "Model identity"). It fails closed even with `fail-on: never`. Exactly `true` or `false`. It trusts the stored baseline file (a checksum, not a signature) and sees only calls sent to the tap port, so keep `baseline-run` out of the application's reach and enforce routing outside the application. |
| `self-test` | `false` | `true` runs the known-negative self-test before assess or the gate ([docs/SELF-TEST.md](../../docs/SELF-TEST.md)). A check that cannot fail or always fails keeps the run from reading clean, so with `fail-on: fail` the job fails; verdicts are unchanged. The report is in `gate-summary.json` (`selfTest`) or, without a baseline, `assess.json` in the evidence artifact. Exactly `true` or `false`. |
| `single-identity` | `false` | `true` assesses a tenant-scoped profile with fewer than two credentialed identities in distinct declared tenants anyway (`assess --single-identity`, [docs/ONBOARDING.md](../../docs/ONBOARDING.md) "Two identities by default"); its cross-tenant checks then run from one side only. Without it, `assess` refuses such a profile (exit 2) before anything is sent. The gate does not refuse and takes no waiver: with `baseline-run`, `true` stops the action. |
| `trials` | `''` | With `baseline-run` only: the gate runs the target this many times (2 to 100) and reads pass^k per check over the trials (see "Repeated trials"). Empty: one run. |
| `pass-k` | `''` | With `trials` only: the k of pass^k, 1 to the number of trials. Empty: the gate's default, 1. |
| `pass-k-floor` | `''` | With `trials` only: the pass^k floor, `1` or a reduced fraction such as `9/10`. A check that passed some trials and is below it reads `FAIL-flaky`. Empty: the gate's default, 1. |
| `pack-updates` | `report` | For a profile with check packs: `report` lists each pin against the shipped version and the shipped packs not used; `pull` (assess mode only; refused with `pack-lock` or `baseline-from-ledger`) assesses a locked copy that takes each newer same-major version of the packs the profile already uses; `off`. See "Check packs". |
| `upload-sarif` | `false` | Upload SARIF to GitHub code scanning. See the cost caveat. |
| `sarif-category` | `scopehaven` | Code scanning category. |
| `policy-baseline-matrix` | `''` | The previous policy matrix (`scopehaven-policy-matrix/2`, written by `scopehaven policy import`). A `/1` matrix is read, but its gaps have no identities, so every gap of the current matrix is gated: re-import it. Set it together with `policy-matrix`. |
| `policy-matrix` | `''` | The current matrix of the same application and layer. |
| `fail-on-policy-diff` | `false` | `true` fails the job on a gated policy cell or a new gap, or when the diff is unavailable or not comparable. `false`: report only. Independent of `fail-on`. |
| `working-directory` | `.` | Base for relative `profile`, `authorization`, `baseline-run` and policy matrix paths. |
| `wait-url` | `''` | Loopback URL to wait for before assessing. Its origin must be one of the authorization record's origins (`authorization-origin` otherwise, before any request). The wait stops when the record's window ends. |
| `wait-timeout-seconds` | `60` | 1 to 900. |
| `artifact-name` | `scopehaven-evidence` | Evidence artifact name; must be unique per workflow run. |
| `sign` | `false` | `true` signs the exports with the existing export signing (see "CI mode"). Needs `signing-key-dir`; refused with `report-only: true`. Exactly `true` or `false`. |
| `signing-key-dir` | `''` | With `sign: true`: absolute path to a 0700 folder holding `scopehaven-signing-key.pem` (0600) and `scopehaven-signing-key.pub.pem` (`integrations/attest/cli.mjs keygen`). The action never creates a key. |
| `ledger-dir` | `''` | Absolute path to an operator-kept, initialized evidence ledger (`integrations/ledger/cli.mjs init`). Needs `sign: true`, `ledger-key-dir` and `ledger-run-files`. Each run's signed `run.json` envelope is appended and the ledger verified; a failure fails the job (exit 2). |
| `ledger-key-dir` | `''` | With `ledger-dir`: absolute path to a 0700 folder with the ledger key pair (same file names). It may be the signing key folder. |
| `ledger-run-files` | `''` | With `ledger-dir`: absolute path to an operator-kept 0700 folder where the action keeps each appended `run.json` as `RUN_ID.json`. |
| `baseline-from-ledger` | `false` | `true` gates against the latest run of this target and application in the verified ledger instead of `baseline-run`; with none yet, the run is assessed without a gate. Needs `ledger-dir`; refused with `baseline-run`, `trials`, `require-model-identity` and `single-identity`. |
| `pack-lock` | `''` | The packs-v2 `scopehaven.lock` beside the profile, relative to `working-directory`. Verified before any request; the pinned packs are recorded in the summary and `pack-lock.json`. |

## Outputs

| Output | Meaning |
| --- | --- |
| `run-id` | Saved run id, or empty. |
| `status-counts` | JSON, for example `{"pass":5,"fail":2,"inconclusive":0,"error":0,"not_applicable":0}`. |
| `gate-verdict` | `clean`, `assessment-failed` or `config-or-runtime-error` from the gate; `not-requested` without a baseline; `unavailable` if the gate produced no summary. |
| `sarif-path` | Absolute path of the SARIF file on the runner, or empty. |
| `policy-diff` | `clean`, `gated`, `not-comparable` or `unavailable`; `not-requested` without matrices. |
| `report-only` | `off`, `applied`, `ended`, `not-applied` (requested and the date not passed, but the gate did not apply it or a report could not be marked) or `invalid`. With `applied`, a green job is not a pass on its own. |

## What it runs

All paths are absolute; `$ROOT` is the `scopehaven` folder containing this action, and `$WORK` is a fresh 0700 directory under `$RUNNER_TEMP`.

- Without `baseline-run`:
  `$ROOT/scopehaven assess --config PROFILE --target ID --out $WORK/evidence [--authorization RECORD]`
  (exit 0 clean, 1 failed/inconclusive/error checks, 2 setup error).
- With `baseline-run`: the action copies the verified baseline into a new dedicated gate directory, then runs
  `$ROOT/scopehaven gate --target ID --config PROFILE --out $WORK/gate --baseline BASELINE_ID [--require-model-identity] [--report-only --report-only-until DATE] [--authorization RECORD] [--self-test] [--trials N [--pass-k K] [--pass-k-floor F]]`.
  The gate performs the assessment itself, so the target is assessed once, not twice (or once per trial with `trials`).
- Exports: `$ROOT/scopehaven export --run RUN_ID --format json|html|sarif --out $WORK/export/FILE --data STORE --unsigned`, plus `--baseline BASELINE_ID --format html` for `comparison.html` when gating. With report-only applied, `report.html`, `comparison.html` and `scopehaven.sarif` are then marked in place by `../regression-gate/report-only.mjs stamp`. By default every export line passes `--unsigned`, so the artifact holds no `.dsse.json` envelope. With `sign: true` each line passes `--signing-key-dir SIGNING_KEY_DIR` instead, and each export gets its `NAME.dsse.json` envelope beside it (see "CI mode"). `sign` is refused with `report-only: true`, because that marking changes the files after export and would break their signatures.
- With `policy-baseline-matrix` and `policy-matrix`:
  `$ROOT/scopehaven policy diff BEFORE AFTER --out $WORK/export/policy-diff.json`
  (exit 0 nothing gated, 1 a gated cell or a new gap, 2 not comparable or unreadable). It reads the two local files only.
- `wait-for.mjs`, `summary.mjs` and `prepare.mjs` in this folder handle readiness, the summary and outputs, and target/baseline preparation.

The artifact contains `run.json`, `report.html`, `scopehaven.sarif`, `summary.md`, `gate-summary.json` and `comparison.html` when gating, `trials.html` and `trials.sarif` with `trials`, and `policy-diff.json` when diffing matrices. With CI mode it also holds the `.dsse.json` envelopes, `scopehaven-signing-key.pub.pem`, `ci-evidence.json`, and with a ledger `ledger-key.pub.pem`, `ledger-append.json`, `ledger-verify.json` and `ledger-baseline.json`, and `pack-lock.json` with `pack-lock`. For a profile with packs it holds `pack-status.json` unless `pack-updates` is `off`, and `pack-pull.json` with `pull`. A later job can pass that `run.json` as `baseline-run`.

## Repeated trials

`trials: N` (with `baseline-run`) passes `--trials N`, and `pass-k` and `pass-k-floor` when set, to the gate ([../regression-gate/README.md](../regression-gate/README.md), "Repeated trials and pass^k"). The gate runs the HTTP target N times, one after another under one lock and the authorization window, and reads each check over the trials: `PASS` only when every trial passed (on an operator-forwarded or remote target, each pass also paired with a passing same-route control, or the check reads `NOT-PASSED`); `FAIL-flaky` when some trials passed and pass^k is below the floor (the gate adds `checks-flaky`); otherwise `FAIL` or `NOT-PASSED`. Every trial's own gate reasons count, so trials never relax the verdict, and `fail-on` follows the gate as usual.

- The job summary gets a "Repeated trials" section: N, k, the floor, the count of each reading, each trial's run id, exit code and reasons, and the checks that did not read `PASS`. The status counts, checks and comparison above it are the first trial's.
- The artifact gets the gate's `trials.html` and `trials.sarif` (every check's reading; marked REPORT-ONLY by the gate while that window applies). `scopehaven.sarif`, which the code scanning upload sends, stays the first trial's.
- If the gate did not stop on a setup error and its summary has no trials block for exactly N, the job fails with `gate-trials-unavailable`, whatever `fail-on` and `report-only` say.
- Trials are fresh runs, only as independent as the application and its state between runs; correlated trials overstate pass^k.

## Policy matrix diff

The summary prints a **Policy matrix diff** section after the Release permission diff. The Release permission diff compares observed check results between two runs. The policy matrix diff compares what one layer of the application *declares* (Postgres RLS, OpenAPI security, Open WebUI grants), cell by cell (role, resource, action), between two matrices from `scopehaven policy import`:

- Gated cells are listed with their before and after decisions (at most 100 rows; the rest are in `policy-diff.json`):
  - `widened`: the decision moved toward access;
  - `added-open`: a new cell that is not declared closed;
  - `became-unknown`: the declaration could no longer be read, or a cell already unknown gained a reason other than a gap (marked "new reason"), such as an owner that now bypasses RLS;
  - `became-undeclared`: the declaration is gone. Between two `unknown` cells (behind a gap), this is read from what each would have decided, so RLS turned off after a standing gap still shows.
- Every other change (narrowed, conditions changed, added closed, removed) is counted, and listed in full in `policy-diff.json`.
- Gaps (statements or rows the importer could not read) are compared by identity, and gated gaps are listed with their scope, source file and the first 16 characters of their id (their reasons stay in `policy-diff.json`):
  - `gap-added`: a gap the previous matrix does not have. It gates even when no cell changed: with one standing gap every cell is already `unknown`, and a release that hides a change behind a new gap changes no cell. A gap statement that was edited, or moved within the earlier migration history, counts as new (see the policy-import README);
  - `gap-unidentified`: the previous or current matrix has gaps without identities (an older `scopehaven-policy-matrix/1`), so every gap of the current matrix is gated, and the summary says so. Re-import that matrix from its sources;
  - `gap-removed` is counted, not gated.
- Matrices of different applications or layers, or a matrix whose id does not verify, are **not comparable**, and no cells are shown.
- The summary recomputes the diff from the two matrices. It accepts the diff step's file only when it is exactly that diff and the step's exit code matches (1 for a gated cell or gap). Otherwise the diff is **unavailable**.

The diff only reports by default. With `fail-on-policy-diff: true` the job fails on a gated cell or gap, and also when the diff is not comparable or unavailable. A failing assessment keeps its own reason. Setting `fail-on-policy-diff: true` without both matrices is an input error. A matrix is a reading of declared policy, not observed behaviour: a clean diff does not show the application enforces it.

## Check packs

One version of each check pack ships with this action (`integrations/packs-v2/packs/`), so a profile pinned behind it no longer loads (`pack-version-mismatch`).

**What a pull covers.** A pull takes new versions of the packs a profile already uses. It never adds a new pack: each pack needs the application's parameters once (`scopehaven pack show NAME`), which only the operator can give. New shipped packs are listed in the job summary ("Shipped packs this profile does not use") for the operator to add by hand.

- `pack-updates: report` (default): the prepare step reads every pin against the shipped version (`scopehaven pack status`) and the job summary lists each as current, behind in the same major, behind by a major version, newer than this action ships, the operator's own, or no longer shipped, with the shipped packs the profile does not use. `pack-status.json` goes into the evidence artifact. Nothing else changes.
- `pack-updates: pull` (assess mode only): each pin behind in the same major is taken. The prepare step writes a copy of the profile into its private work directory and locks it (`scopehaven pack pull`: each pack's own cases, then the load gate, as `pack lock` does), the authorization record is checked against that copy, and the assessment uses it. The committed profile and `scopehaven.lock` are never written; `pack-pull.json` records each pinned and pulled version. A newer major (its parameters may differ), a pin newer than this action ships or a pack that no longer ships stops the job before any request (exit 2, `pack-updates pull refused (pack-pull-<state>)`), as does an operator's own pack (`from`) when another pin would be pulled (`pack-pull-local`). With every shipped pin current, a profile with its own packs is assessed as committed. With `baseline-run` it is refused: a pulled pack changes the checks the baseline was taken with. With `pack-lock` or `baseline-from-ledger` it is refused too, in the prepare step's input checks before any file is read or request sent (exit 2): a pull takes newer pack versions than the pinned lock and the ledger baseline were taken with.
- A pulled run is not the committed configuration. To keep it, set the version in the profile and run `scopehaven pack lock --update`.

## fail-on

The assessment and gate steps never fail the job directly. The last step applies `fail-on`:

- `fail` (default): CI follows Scopehaven. The job fails whenever `scopehaven assess` or the regression gate would exit non-zero. It also fails on the same conditions recomputed from the saved run: a failed, errored or inconclusive check, required controls that are missing or not passing, or a test user whose login is not proven. Response-only profiles keep backend-required rows inconclusive, so they stay red until backend observers report.
- `inconclusive`: an alias of `fail`, kept for existing workflows.
- `never`: report only.

Setup errors fail regardless of `fail-on`: invalid inputs, a missing or tampered baseline, assessment exit 2, or no saved run. A green job without evidence would hide a broken pipeline.

## Report-only

A rollout aid for turning Scopehaven on in an existing pipeline: findings are recorded and shown for a bounded time before they start failing builds. Unlike `fail-on: never`, it ends by itself, and every report says so.

```yaml
      - uses: ./integrations/github-action
        with:
          profile: scopehaven/targets.json
          authorization: scopehaven/authorization.json
          report-only: 'true'
          report-only-until: '2026-12-15'   # the last green day (UTC); fail-on applies from 2026-12-16
```

- **Decided once.** The prepare step reads today's UTC date: on or before `report-only-until` the window is `applied`, after it `ended`. Without `baseline-run` that decision holds for the whole job, so a job that starts on the last day and ends after midnight UTC is still relaxed. With `baseline-run` the gate checks the date again when it runs, and the job is relaxed only if both say `applied`. A date more than 90 days ahead is refused (`report-only-window-too-long`), so report-only cannot stand in for a permanent mode. `report-only-until` without `report-only: true`, or a malformed date, is an input error.
- **What it relaxes.** While applied, the job passes where `fail-on` would fail it on findings: failed, inconclusive or not-applicable checks, required controls not passing, a test user whose login is not proven, assess exit 1, or a gate verdict of `assessment-failed` (exit 1). The decision reads `pass` (`report-only`), the summary and the `would-fail` step output name the reason it would have failed, and a warning annotation on the run page says it is not a pass.
- **What it never relaxes.** Setup errors (as under `fail-on`), an errored check (counted from the saved run), a gate exit 2 or an assess exit other than 0 or 1 (whatever else the run shows), `require-model-identity: 'true'` and `fail-on-policy-diff: 'true'`. These fail the job as without report-only.
- **Every page says so.** The job summary opens with a REPORT-ONLY banner and its decision line names the state. `report.html` gets a REPORT-ONLY title, a banner on the cover, a line in each check and in the limits, and a header on each printed page where the browser supports page margin boxes; `comparison.html` gets the title, the banner and the print header. In `scopehaven.sarif` every result message starts with `[REPORT-ONLY run: not a pass]`, and the run's properties and invocation carry the window. Levels, kinds and fingerprints stay as recorded, so a code scanning merge rule that reads levels still blocks, and alerts keep their identity when the window ends. `run.json` is the recorded run, unchanged, so it still works as a later `baseline-run`.
- **Fail closed.** The job is relaxed only when the export step marked every report and SARIF file. A file that could not be exported or marked ends the relaxation for that job (`report-only` output `not-applied`) and a warning names it. With `baseline-run`, the gate also runs with `--report-only --report-only-until DATE`, its summary (`gate-summary.json`) records the window beside the real verdict, and the job is relaxed only if the gate applied it too.
- **Dates, not run counts.** The gate CLI also takes `--report-only-runs N`, counted in its output directory. The action does not offer it: each job starts with a fresh evidence directory, so a count would never advance.

## Scope

The summary states the evidence scope. HTTP profiles produce **response-level evidence**: Scopehaven checks HTTP response contracts and does not independently verify backend access or action effects unless backend observers are configured (not part of this action). A passed run is observed checks, not a safety certification. A fail-to-pass transition is labelled a restored response contract, not a verified backend fix.

When the compared runs are incompatible, or the candidate's required allowed-use controls did not all pass, the summary's restoration label reads "Unverified changes" and no repair is credited. A compatible pair that restored nothing, introduced a new failure or left a row unverified or not applicable reads "No verified repair".

For HTTP comparisons the summary also states the model attribution: who verdict changes are credited to, or that the model was not recorded for one or both runs, so a verdict change may come from the model. Repairs not credited to the application are marked "(not credited to the application)". The gate reasons `model-identity-malformed` and `model-identity-not-recorded` fail the job like any non-clean gate. They are listed as soft reasons, so when the gate also gives a hard reason, the job names the hard one. With `require-model-identity: 'true'` the summary recomputes the policy from the saved runs and names its own reason, and `model-identity-not-recorded` and `model-identity-unverified` can occur (see "Model identity").

## Model identity

`require-model-identity: 'true'` passes `--require-model-identity` to the gate and needs `baseline-run`; without one the prepare step refuses it (`require-model-identity needs baseline-run`), as the gate itself refuses the switch without `--baseline` (`invalid-options`). The default `'false'` keeps the earlier behaviour. Under the policy, both HTTP runs need a readable, comparable model identity, and it fails closed even with `fail-on: never`:
- a missing identity fails with `model-identity-not-recorded`, an unreadable one with `model-identity-malformed`;
- an identity that is partial, mixed, requested-only or not observed, or whose custody is not `tap-memory`, fails with `model-identity-unverified`;
- a different or silently changed model is comparable, not a failure: the attribution rules then decide, and a repair under a model change is not credited (`repair-not-attributable`). The policy requires comparable identity, not identical models or a weights digest.

The summary prints the policy and, when it is not met, why (for example `candidate` `subject-writable-custody`), and credits no repair. The gate summary carries the same causes in `comparison.modelIdentityPolicy`. When the policy is not met, the gate summary credits no repair: `modelAttribution.repairCreditedToApp` reads `false` with `policy: 'not-met'`, and a repair label that could stand reads `Not attributable to the application: the model identity policy was not met`.

**What the policy cannot see.** It reads a stored run's identity and custody as the run's file records them. The run digest is a checksum, not a signature: a baseline edited to the candidate's model and resealed, or a `tap-file` baseline relabelled `tap-memory` and resealed, passes the policy. Keep `baseline-run` where the application and its authors cannot write it; signing or anchoring the identity when it is captured is future work. The tap also sees only calls sent to its port: an application that sends one call through the tap and its real calls straight to the model server meets the policy. The policy holds only where routing enforced outside the application leaves the tap port its only way to the model server.

**Recording the identity: the owned tap.** Point the application's model base URL at `http://127.0.0.1:PORT`, and give the action's step the model server and that port:

```yaml
  - uses: ./integrations/github-action
    env:
      SCOPEHAVEN_MODEL_TAP_UPSTREAM: http://127.0.0.1:11434
      SCOPEHAVEN_MODEL_TAP_PORT: '4319'
      # SCOPEHAVEN_MODEL_TAP_OLLAMA_TAGS: 'false'  # for a loopback model server that is not Ollama
    with:
      profile: path/to/targets.json
      baseline-run: path/to/baseline/run.json
      require-model-identity: 'true'
```

`scopehaven assess` and `scopehaven gate` then start the existing model tap in their own process before the first assessment request, listening on 127.0.0.1 at that port and forwarding only to that literal loopback upstream. They mark it at the start and after the identity probes, refuse a window with calls in flight or a broken in-memory chain, and stop it before saving the run, also when the run fails. The application needs no tap control: it only sends its model calls to the port. The run records the identity with custody `tap-memory`: its frames never leave Scopehaven's process. Keep the tap port exclusive to the application during the run; calls on it are attributed to the run. Both baseline and candidate need it, so take the baseline run with the same settings. A port already in use, or a setting that is not a literal loopback origin and a port from 1 to 65535, reads partial (`tap-owned-unavailable-at-start`, `tap-owned-config-invalid`), never absent. Two configured sources (the owned tap and a log file) read partial (`tap-capture-ambiguous-sources`). An empty value counts as unset. Hosted vendors are not supported by the owned tap; run the tap CLI for them (below), as a reading only.

**Other routes.**
- Library: `runHttpAssessment(profile, { modelTap: tap })` takes a started tap the caller holds in the same process (custody `tap-memory`). The caller routes the application through it and stops it.
- Log file: `SCOPEHAVEN_MODEL_TAP_LOG=/absolute/tap.jsonl` (or `modelTapLog`) reads a log another process wrote, such as the tap CLI. The reader opens only a regular, non-symlink file up to 64 MiB and needs a final close frame with nothing in flight; an open log reads partial (`tap-log-not-closed-at-end`), and neither the CLI, the gate nor the action can close a tap another process runs, so an operator-run tap always reads partial here. Its custody is `tap-file`: any process running as the log's user, the application under test included in a usual CI job, can rewrite the closed log in place and re-chain it, which the reader cannot see. The strict policy therefore reads every `tap-file` identity unverified (`subject-writable-custody`). Without the policy it still shows which model the file reports, and a model it shows changed still blocks a repair, but a model it shows held constant credits no repair: those verdict changes read `model-unverified`, and the gate fails a counted repair with `repair-not-attributable`. No head anchor is accepted yet: a head digest captured outside the application would be needed, and none is wired in.

**Limits.** Every model reading, a weights digest included, is what the model upstream reported to the tap. An upstream the application controls can report any model name, fingerprint or digest, so keep the model server outside the application's control; vendor strings and fingerprints remain vendor readings. The owned tap's frames are held in Scopehaven's memory; a process with debugger rights over Scopehaven's process is outside that boundary. Not verified: the step-level `env:` reaching the composite steps on GitHub-hosted runners, and a real Ollama or vendor upstream (the tests use fixed loopback stubs).

Capture changes `HTTP_EVALUATOR_HASH`, because the connector, the capture module and the tap helpers it uses are hashed. Runs saved before it compare as incompatible: take a fresh baseline with the same release as the candidate, and never edit the hash of a saved run.

## SARIF and cost

`upload-sarif` defaults to `false`. Code scanning uploads to **private repositories require paid GitHub Code Security** (formerly Advanced Security). Without it the upload fails; the step uses `continue-on-error: true` and the summary records the outcome. When enabled, the job also needs `security-events: write` and `actions: read`. Scopehaven SARIF has logical locations only (application, target, check), so code scanning may not show results on source lines. The SARIF file is always in the evidence artifact.

## Security notes

- **Loopback waits.** `wait-for.mjs` accepts only `http://127.0.0.1:PORT` or `http://localhost:PORT` (dialled as 127.0.0.1), uses a fresh non-proxy agent and does not follow redirects. Scopehaven profiles accept literal 127.0.0.1 origins, and an `operator-remote` https origin only under an authorization record naming it (DNS pinned for the run, certificate verified, no redirect followed).
- **Secrets via environment only.** Pass each credential the profile references (`SCOPEHAVEN_TARGET_*`) through `env:` from repository secrets. The action has no credential inputs (`signing-key-dir` and `ledger-key-dir` take folder paths, never key material), never uses `set -x`, and no step echoes credentials. `summary.mjs` prints only ids, titles, statuses, severities, counts and hashes, plus the role, resource, action and decision of each gated policy cell and the scope, source file name and id of each gated gap, and redacts any `SCOPEHAVEN_TARGET_*` value (4 characters or longer) that appears in a title.
- **No telemetry.** No step sends data anywhere except the optional `actions/upload-artifact` and `github/codeql-action/upload-sarif` uploads to GitHub itself.
- **No expression injection.** Inputs reach shell steps only through `env:`; no `${{ }}` appears inside `run:` blocks.
- **Artifacts are readable by anyone with repository read access.** They hold metadata, not raw responses or credentials, but titles and profile ids come from your private profile. `policy-diff.json` also holds the declared conditions (policy predicates, verbatim) of every changed cell. Keep the profile itself private.
- **Pinning.** Third-party actions are pinned to full commit SHAs, read from the upstream `v4` tags on 2026-10-05 with `git ls-remote` (setup-node 49933ea5, upload-artifact ea165f8d, codeql-action upload-sarif 2892aa5e). Review the upstream diff before you bump a pin. The action's `setup-node` step also puts Node 24 on PATH for the caller's later steps.

## CI mode: signed exports, the evidence ledger and pinned packs

Every CI input defaults off, so a workflow that sets none of them runs exactly as before. `ci.mjs` in this folder does the work; it uses the existing code read-only: the export signing (`src/export-cli.mjs`, `integrations/attest`), the ledger's own CLI (`integrations/ledger/cli.mjs append` and `verify`) and verifier, and the packs-v2 load check.

```yaml
      # Keys and the ledger are the operator's. Write the keys from secrets into private folders; never echo them.
      - name: Keys and ledger
        env:
          EVIDENCE_KEY: ${{ secrets.SCOPEHAVEN_EVIDENCE_KEY }}      # scopehaven-signing-key.pem from attest keygen
          EVIDENCE_PUB: ${{ vars.SCOPEHAVEN_EVIDENCE_PUB }}
          LEDGER_KEY: ${{ secrets.SCOPEHAVEN_LEDGER_KEY }}
          LEDGER_PUB: ${{ vars.SCOPEHAVEN_LEDGER_PUB }}
        run: |
          umask 077
          mkdir -p "$RUNNER_TEMP/keys/evidence" "$RUNNER_TEMP/keys/ledger"
          printf '%s\n' "$EVIDENCE_KEY" > "$RUNNER_TEMP/keys/evidence/scopehaven-signing-key.pem"
          printf '%s\n' "$EVIDENCE_PUB" > "$RUNNER_TEMP/keys/evidence/scopehaven-signing-key.pub.pem"
          printf '%s\n' "$LEDGER_KEY" > "$RUNNER_TEMP/keys/ledger/scopehaven-signing-key.pem"
          printf '%s\n' "$LEDGER_PUB" > "$RUNNER_TEMP/keys/ledger/scopehaven-signing-key.pub.pem"
      - uses: ./integrations/github-action
        with:
          profile: scopehaven/targets.json
          authorization: scopehaven/authorization.json
          sign: 'true'
          signing-key-dir: ${{ runner.temp }}/keys/evidence
          ledger-dir: /operator/scopehaven-ledger            # kept on the runner between releases (a self-hosted runner)
          ledger-key-dir: ${{ runner.temp }}/keys/ledger
          ledger-run-files: /operator/scopehaven-ledger-runs
          baseline-from-ledger: 'true'
          pack-lock: scopehaven/scopehaven.lock
```

- **Signed exports (`sign`).** `run.json`, `report.html`, `scopehaven.sarif` and, when gating, `comparison.html` are signed by the export itself (`--signing-key-dir`), each into `NAME.dsse.json` beside it (DSSE, in-toto Statement v1, Ed25519). A later step verifies every envelope with `integrations/attest/cli.mjs verify` against the public key, which goes into the artifact; one that does not verify fails the job with exit 2 and `signed-export-unverified:FILE`, whatever `fail-on` says. The key folder must already hold both key files: the action never creates a key, because a fresh key would sign evidence no reader has confirmed. No key material is printed or put in the artifact. `trials.html` and `trials.sarif` are copies of the gate's files and are not signed, nor are `summary.md` and the CI records written after export. A signature shows the key holder produced these bytes, not that the results are correct.
- **The ledger (`ledger-dir`).** After the exports are signed and verified, the action keeps `run.json` in `ledger-run-files` as `RUN_ID.json` (a new file; never overwritten), appends `run.json.dsse.json` with `integrations/ledger/cli.mjs append`, then runs `cli.mjs verify --run-files`. It requires the append to succeed, the ledger to verify, every entry to be covered by a checkpoint, and the ledger to have grown by exactly one entry. Otherwise the job fails with exit 2 and a named reason: `ledger-append-refused`, `ledger-verify-failed`, `ledger-not-extended-by-one`, `run-file-not-kept`, `ledger-unreadable` or `no-saved-run`. A refused append removes the run file it kept. A run that fails its checks is still appended: the ledger records every release, and the job then fails on `fail-on` (exit 1). The ledger must already exist (`cli.mjs init`): the action never starts a new one, so a lost ledger cannot be silently replaced by an empty history. Checkpoints are signed by the operator's ledger key only (`witness: none`); see [../ledger/README.md](../ledger/README.md). Someone who can write the ledger folder can cut it back: with `baseline-from-ledger`, an emptied ledger reads `ledger-empty` and the run is not gated against a baseline (its own fails still fail the job). Keep the latest checkpoint outside the folder and compare (ledger README, walkthrough step 2).
- **Baseline from the ledger (`baseline-from-ledger`).** In the prepare step, before any request, the ledger is verified with the kept run files. The baseline is the latest run in it with this target id and application id. Its run file is found by the digest the evidence key signed for it in that entry's envelope, checked against the run id and integrity digest the entry records, and copied into the private work folder; the gate then verifies it as it verifies `baseline-run`. A ledger that does not verify, or has entries no checkpoint covers, stops the action with exit 2 (`ledger baseline refused (ledger-unverified)` and similar). With no run of that target yet (a new ledger), the run is assessed without a gate and the summary says so. The baseline is the latest run, not the latest passing run: a release after a failed one is compared with the failed run, and its fixes read as restored contracts. A failing check still fails the job on its own, so a regression that persists stays red. Whether the latest run is comparable (suite, policy, evaluator and the rest) is the gate's call: an incompatible one fails the job (`incompatible-baseline`).
- **Pinned packs (`pack-lock`).** It must be the `scopehaven.lock` beside the profile, the one a profile load reads (`pack-lock-not-beside-profile` otherwise). The prepare step runs the packs-v2 load check (`expandPacks`, as `scopehaven pack verify` does) before the authorization check and again before writing `pack-lock.json`. That check covers every referenced pack's files against its manifest, the lock's own checksum, and the lock's digests for each reference. A lock that fails, a profile with no packs (`pack-lock-unused`), or a lock that changes while it is read stops the action with exit 2 before any request. The summary lists each pinned pack's name, version, source and manifest digest. These are checksums, not signatures. `pack-updates: pull` cannot be combined with `pack-lock` (see "Check packs").

### Proof over 10 releases (local, laptop only)

`ci-proof.mjs` builds a scratch git repository under `$TMPDIR`, outside the checkout, holding an owned app: this repository's synthetic HTTP lab (`examples/http-lab.mjs`) at the build named in a `BUILD` file. The app's profile is the lab profile without its backend-required row, plus an operator pack locked with `scopehaven pack lock`. The script tags v1 to v10. v6 uses the lab's existing `baseline` build, the foreign-record regression this repository's own action workflow already uses; no new defect was written. For each tag it checks the release out, starts the app, and runs `action.yml`'s own run steps in order through `harness.mjs`, with `sign`, the ledger, `baseline-from-ledger`, `pack-lock` and `fail-on: fail`. It then verifies the ledger with `integrations/ledger/cli.mjs verify` and `python3 -I integrations/ledger/verify_ledger.py log`. Keys, ledger and run files stay in the scratch folder, which is removed afterwards unless `--keep` is given. The result is recorded outside this repository.

```sh
/absolute/path/to/node24 integrations/github-action/ci-proof.mjs [--keep]
```

What it shows: each release appended one signed run; v6 failed its job (exit 1) against v5's run taken from the ledger, with its signed run still appended; after 10 releases both verifiers verified the ledger, with every run file checked against its recorded verdicts. What it does not show: a workflow run on GitHub. That leaves unexercised GitHub's expression evaluation, `setup-node`, the artifact upload, secrets reaching the step, and the ledger and keys persisting on a real runner. It also does not show key custody: the keys sat in a folder the same user owned, and on a usual runner the application under test can read them. Nor does it say anything about applications other than the owned synthetic lab.

**Pending:** the same proof as a workflow on GitHub, on the hosted runner or the laptop runner. GitHub Actions minutes after November 1 are Yusef's decision, so it has not run there.

## Verification

`action.test.mjs` (node:test) runs locally against the owned synthetic lab on 127.0.0.1. It parses `action.yml` with a minimal YAML-subset parser and executes its `run:` steps in bash, in order, with the same environment wiring GitHub uses; `uses:` steps are skipped. It covers the full assess path, the baseline gate path, a tampered baseline, invalid inputs, markdown escaping, credential redaction, wait-for loopback/timeout behaviour, the policy matrix diff (gated cells, a new gap where every cell was already unknown failing the opted-in job and a moved one passing, an older baseline's gaps gated, opt-in failure, not comparable, a diff file or exit code that does not match its matrices, and policy input validation), the model identity policy: the owned tap through the real launcher passing an unchanged model and failing a swap with no application cooperation, and a tap log file failing as `subject-writable-custody`, and report-only: the assess and gate paths relaxed and marked while the window applies, the same evidence failing once the date has passed, input validation (a missing, malformed or too distant date, a date without the switch), and the summary never relaxing a setup error, an errored check, an unmarked report, a gate that did not apply the window or the strict model identity policy. `../regression-gate/report-only.test.mjs` covers the gate side. `ci-mode.test.mjs` covers CI mode through the same steps (`harness.mjs`). Off: a default run writes no envelope and no CI record. Refusals: each CI input invalid, incomplete or combined with an input it excludes, all stopped in the prepare step before any request. Pack lock: recorded, and an edited pack refused. Signing: three verified envelopes, both attest verifiers, no private key bytes anywhere, and an unsafe key failing with exit 2. Ledger: two releases, the second on the regressed build failing against the first from the ledger while still appended, both ledger verifiers, then an injected entry refusing the ledger baseline and the append, exit 2.

```sh
/absolute/path/to/node24 --test integrations/github-action/action.test.mjs
```

On GitHub, checked on 2026-10-16 against run 38969977581 (a pull request run on a GitHub-hosted `ubuntu-latest` runner): every step of the synthetic-lab workflow passed, including `actions/setup-node`, GitHub's own expression evaluation of the inputs that workflow passes, the release gate self-test, and both evidence artifact uploads (`scopehaven-evidence-previous-release` and `scopehaven-evidence-this-release`).

Not verified: the code scanning upload. That step runs with `continue-on-error`, so a failed upload never fails the job and its result is not checked here; it needs code scanning enabled on the repository (free on public repositories, paid GitHub Code Security on private ones). On GitHub, the action has run only against the owned synthetic lab.
