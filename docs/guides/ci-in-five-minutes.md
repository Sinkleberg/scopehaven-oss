# CI in five minutes

One job in a GitHub Actions workflow: it starts your app on the runner's loopback, runs ScopeHaven's checks against it
under your authorization record, gates the result against a run you saved earlier, uploads the evidence as an artifact
and, if you want, uploads SARIF to code scanning. No model takes part in a verdict, and nothing leaves the runner except
those two uploads to GitHub itself.

The action is `YusefSyed/scopehaven-oss`. Pin `@<ref>` to a release tag or a commit SHA rather than a branch.

## What you need in your repository

1. **A profile**, for example `scopehaven/targets.json`: who the test identities are and which routes each may and may
   not use. `./scopehaven init` drafts one from a running app ([QUICKSTART.md](../QUICKSTART.md)). Its `origin` must be
   the literal loopback origin your job starts the app on, such as `http://127.0.0.1:3000`. Credentials are named in it
   as `SCOPEHAVEN_TARGET_*` environment variables and never stored.
2. **An authorization record**, for example `scopehaven/authorization.json`: your sealed statement of what this run may
   touch: the target, its origin and every test identity, with a validity window
   ([RULES-OF-ENGAGEMENT.md](../RULES-OF-ENGAGEMENT.md)). Write the draft, then seal it:

   ```sh
   node integrations/roe/cli.mjs seal draft.json scopehaven/authorization.json
   ```

   The action checks the record before the wait and before any request; without a record that covers the target now
   it exits 2 and contacts nothing. Renew it before `validUntil`, or the job stops with
   `authorization refused (authorization-window)`.
3. **One repository secret per credential** the profile names, under the same `SCOPEHAVEN_TARGET_*` name.

A baseline run comes from the first green run (below). Leave `baseline-run` out until you have one.

## The workflow

Copy this to `.github/workflows/scopehaven.yml`. Three things to change: the step that starts your app (and its port),
the `env:` lines (one secret per `SCOPEHAVEN_TARGET_*` name in your profile) and the paths under `with:`.

```yaml
name: ScopeHaven

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  # For the SARIF upload to code scanning. Drop these two lines and set upload-sarif to 'false' to skip it.
  security-events: write
  actions: read

jobs:
  scopehaven:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          persist-credentials: false

      # CHANGE 1: start your app in the background on 127.0.0.1, with synthetic test data, and remember its pid.
      # The action waits for wait-url before it sends anything, so the app may still be starting here.
      - name: Start the app under test
        run: |
          npm ci
          nohup npm start > "$RUNNER_TEMP/app.log" 2>&1 &
          echo $! > "$RUNNER_TEMP/app.pid"

      - name: ScopeHaven
        id: scopehaven
        uses: YusefSyed/scopehaven-oss@main # pin this to a release tag or a commit SHA
        # CHANGE 2: one line per credential the profile names, each from a repository secret of the same name.
        env:
          SCOPEHAVEN_TARGET_APP_A: ${{ secrets.SCOPEHAVEN_TARGET_APP_A }}
          SCOPEHAVEN_TARGET_APP_B: ${{ secrets.SCOPEHAVEN_TARGET_APP_B }}
        # CHANGE 3: the profile, the record, the readiness URL and, after the first run, the baseline.
        with:
          profile: scopehaven/targets.json
          authorization: scopehaven/authorization.json
          wait-url: http://127.0.0.1:3000/health
          wait-timeout-seconds: '90'
          baseline-run: scopehaven/baseline-run.json
          upload-sarif: 'true'
          sarif-category: scopehaven

      - name: Stop the app under test
        if: always()
        run: |
          if [ -f "$RUNNER_TEMP/app.pid" ]; then kill "$(cat "$RUNNER_TEMP/app.pid")" 2>/dev/null || true; fi
```

Two details about the app step. The `wait-url` origin must be one of the record's origins, and the profile's `origin`
must be the same literal `http://127.0.0.1:PORT`; a `localhost` URL is dialled as 127.0.0.1. The action's own step puts
Node.js 24.22.2 on `PATH` for the steps after it; if your app needs another Node, set yours up before the app step.

## Save the baseline

The first run has nothing to compare with, so run it once without `baseline-run` (comment the line out). When it is
green, download the `scopehaven-evidence` artifact from the run page, take `run.json` out of it, commit it as
`scopehaven/baseline-run.json` and put the `baseline-run` line back. From then on the regression gate compares every
run with that one: same application, suite, policy, profile and evaluator, or the summary says "not comparable" and
lists why. Refresh the file the same way whenever you accept a change in the checks or the app.

The baseline's integrity digest is verified before it is used. It is a checksum, not a signature: a file edited and
resealed passes, so keep it where the application under test cannot write it (a reviewed file in the repository is
fine).

## What the job summary shows

Each run writes one summary, built from the saved run and the gate's own files, never from the step log:

- **Scope**: what the result covers (HTTP response contracts, or effects from declared observers). A tag or a count is
  never a security score, and the line says so.
- **Run**: id, target, application, build label, evidence origin, number of checks, and the evidence, profile, suite
  and policy hashes.
- **Status counts**: `pass`, `fail`, `inconclusive`, `error`, `not_applicable`.
- **Regression gate**: the verdict (`clean`, `assessment-failed` or `config-or-runtime-error`) with its exit code and
  reasons, the baseline it compared with, and a table of transitions such as `regression` and `preserved`.
- **Release permission diff**: check by check against the baseline: `DENY → ALLOW flips` (a check that held before
  and fails now), `New failures (previously undecided)`, `Broken allowed-use controls`, `Newly inconclusive` and
  `Restored`.
- **Checks needing attention**: every failed, errored or inconclusive row with its severity.
- **Action decision**: `fail-on fail: pass` or `fail`, with the reason code that decided it.
- **SARIF**: where the file is, and whether the upload was requested.

The step also sets outputs for later steps: `run-id`, `status-counts` (JSON), `gate-verdict`, `sarif-path`,
`policy-diff` and `report-only`.

## When the job is red

- `authorization refused (CODE)` in the prepare step, exit 2: the record is missing, expired (`authorization-window`),
  does not name the profile's or the `wait-url`'s origin (`authorization-origin`), or misses a test identity
  (`authorization-identity`). Fix the draft and seal it again; nothing was sent.
- The wait timed out: the app did not come up on that port in `wait-timeout-seconds`, or `wait-url` is wrong. Read
  `$RUNNER_TEMP/app.log` by uploading it, or print it in a step with `if: failure()`.
- Gate verdict `assessment-failed`: read "Release permission diff" and "Checks needing attention" first. An
  inconclusive row is not a pass, and `fail-on: fail` (the default) fails the job on it. `fail-on: never` reports
  without failing, which is the way to look at a first run on a new profile.
- The SARIF upload failed: code scanning on a private repository needs paid GitHub Code Security. The upload runs with
  `continue-on-error`, so the job is not red for that alone; set `upload-sarif: 'false'` to skip it. The SARIF file is
  always in the evidence artifact.

## GitHub Enterprise Server

The root action's one step is `uses: $/integrations/github-action`, GitHub's self-repository reference, which resolves
to this repository at the running commit. `$/` is not available on GitHub Enterprise Server. There, use the inner action
directly: `uses: YusefSyed/scopehaven-oss/integrations/github-action@<ref>`. It takes the same inputs and sets the same outputs.

## Further reading

- [integrations/github-action/README.md](../../integrations/github-action/README.md): every input, repeated trials and
  pass^k, the policy matrix diff, report-only rollouts, signed exports and the evidence ledger.
- [.github/workflows/scopehaven-action.yml](../../.github/workflows/scopehaven-action.yml): this repository's own
  workflow. It runs the action twice against the owned synthetic lab, once as the "previous release" and once with a
  planted regression gated against it, and then asserts that the gate caught exactly that regression.
- [docs/ONBOARDING.md](../ONBOARDING.md) for declaring observers on your app's own records, so the checks decide from
  effects rather than from responses.
