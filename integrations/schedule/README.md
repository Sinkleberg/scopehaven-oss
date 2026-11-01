# Scheduled re-runs with a drift summary

A scheduled job re-runs the regression gate on a built-in synthetic target and says what moved since the last successful run. **New files only:**
- `drift.mjs`: reads one gate summary and returns the drift. It has a small CLI.
- `run-local.sh`: one re-run, for launchd, cron or the workflow.
- `com.scopehaven.drift.plist.template`: a launchd job for the local runner.
- `.github/workflows/scopehaven-drift.yml` (repository root): the same run on a GitHub schedule.
- `drift.test.mjs`.

## What the summary says

| Status | When | Exit |
| --- | --- | --- |
| no change | every row kept its transition label (`preserved`, `still-failing`) | 0 |
| improved | some rows are labelled fixed or restored by the comparison itself | 0 |
| no baseline | the first run: nothing to compare with yet | 0 |
| regression | some rows regressed (this wins over an improvement in the same run) | 1 |
| needs review | some rows changed in a way the comparison could not verify (unverified, blocked by controls, not applicable) | 1 |
| not comparable / not run | the runs differ in application, suite or context, the gate did not run, or the summary is unreadable | 2 |

An unchanged run reads "no change", never "fixed". The summary names the current run, the baseline, the gate's outcome and the checks per transition, and states the scope: the built-in synthetic target, no customer system, model or external service.

## The local runner

```sh
integrations/schedule/run-local.sh demo-repaired
```

- **Data directory:** `SCOPEHAVEN_DRIFT_DIR`, or `~/Library/Application Support/Scopehaven/drift`. The runner creates it with mode 0700 and umask 077.
- **Baseline:** the last successful run is kept there as `last-run.json`.
- **Each run:** it seeds that run into a fresh gate store, gates the target against it, and writes `latest-drift.md` (plus a per-run folder).
- **Updating the baseline:** only a run that exits 0 replaces it. A regression, or a run that could not be compared, never becomes the next baseline.
- **Planting a regression:** the target `demo-vulnerable` against a stored `demo-repaired` run.

**launchd:** replace `__SCOPEHAVEN_ROOT__` and `__DATA_DIR__` in the template (create the data directory with `mkdir -m 700` first). Save it as `~/Library/LaunchAgents/com.scopehaven.drift.plist` and load it with `launchctl bootstrap gui/$(id -u) <path>`. It runs weekly (Monday 06:17) with umask 077 and writes only to the data directory.

## The workflow

`scopehaven-drift.yml` runs twice a week (Monday and Thursday 06:17 UTC, inside the cache's 7-day eviction window) and on `workflow_dispatch`.
- **Choosing the target:** the dispatch's `target` input; `demo-vulnerable` plants a regression.
- **The baseline:** restored from the Actions cache, and saved back only when the run exits 0.
- **Output:** the drift summary goes to the job summary.
- **Constraints:** permissions are `contents: read`, every action is pinned to a commit, and inputs reach the script only through `env`. No secret is read, and no mail, chat or webhook is sent.

Merging it enables the scheduled run on GitHub-hosted Linux, a few minutes a week.

## Limits

- It runs the built-in synthetic target only. A configured target would also need its authorization record (`integrations/roe`), credentials and a reachable app, and none of that belongs in a scheduled public-runner job.
- The cache holds one baseline per branch scope. GitHub evicts an entry unused for 7 days, which is why the job runs twice a week. If an entry is evicted anyway, the next run reads "no baseline" and starts again.
- Drift is between two runs. It says what moved, not why.
