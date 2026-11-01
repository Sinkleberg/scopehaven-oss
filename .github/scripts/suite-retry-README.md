# Suite retry wrapper

Run `bash ../.github/scripts/run-suite.sh false 1/4` from `scopehaven/` in CI.
The first argument is `true` for the laptop runner or `false` for hosted runners;
the optional shard is decimal `INDEX/TOTAL`, with `1 <= INDEX <= TOTAL <= 99`.
The existing file selection and sharding remain in the launcher and Node.

The wrapper mirrors the launcher's runtime **selection**, selects once, probes it, and
exports its absolute path as `SCOPEHAVEN_NODE`. The launcher's engine-range check
remains authoritative. Initial execution, parsing and retry use this same path.
An invalid explicit runtime does not fall back. A runnable unsupported pinned
runtime does not fall back either. Keep the small selection block synchronized
with `scopehaven/scopehaven` when the launcher changes; the focused tests exercise
the actual committed launcher using intercepted test invocations.

Both attempts force `--test-reporter=tap`. The parser supports Node 24.21.0's
observed TAP v13 output, including nested tests/suites, ordinary failures, abort
failures, TODO failures, skipped tests, spaces in paths and escaped console text.
It requires matching subtest starts/results, closed diagnostic blocks, nested and
root plans, the final ordered eight-counter summary, coherent counts, and a
consistent process status. It rejects zero tests, missing/truncated/malformed or
contradictory evidence, spec output and unsupported formats. Future Node reporter
changes may keep CI red until their format is reviewed and covered by captures.
Coverage-enabled output and generic third-party TAP/YAML are outside this parser's
supported format. The normal wrapper does not enable coverage.

A normal exit-1 failure with every failed location identified can retry once,
using only its 1..8 distinct files. Files must exist inside the suite directory;
resolved symlinks outside it and newline-containing paths are rejected. Nested
failures in the same file deduplicate. TODO/skip results retain Node's semantics.
Cancelled tests and abnormal process exits stay red. A failed or incomplete retry
stays red; a complete successful retry emits the existing explicit flake warning
with the files and both loads. There is no third attempt. Retry concurrency and
the laptop's 60 x 20-second load wait remain unchanged.

Both runs go through `test/support/bounded-run.mjs` (the first
through the launcher's test action, the retry directly), which runs `node --test`
under a wall-clock bound (`SCOPEHAVEN_TEST_BOUND_SECONDS`, default 2700). A run
still going at its bound is killed as a hang, and the status is 124: the runner's
process group is sent SIGTERM at the bound and SIGKILL 5 s later without waiting
for anything, and so is every process the runner has seen descended from it, and
the test files still running are named. Descendants are seen in the process table,
read every 250 ms (each read killed at 2 s, and a `ps` that cannot be spawned
counted as a failed read): a detached process that starts and loses its parent
between two reads is never seen, and a seen process is signalled only from a table
read in the last 10 s, so once no table has been read for that long only the group
is stopped. An error inside the runner itself kills the run (status 124 past the
bound, else 1) rather than leaving it unbounded. A first run with status 124 is
never retried, and a retry with status 124 stays red, so a killed run can never
turn into a flake warning and a pass. Plain `node --test` waits for every test a
file registers, so a test registered late still runs.

After a run that ends by itself, any seen process still running is stopped and
named. That does not change the run's status (the processes are gone, so they hold
nothing): the runner appends the notice to the file `SCOPEHAVEN_TEST_NOTICES`
names, which this wrapper sets, and the wrapper prints each notice as a
`::warning` annotation, so it stays out of the TAP log the parser reads. Through
the launcher alone the notice goes to stderr, with the same status.

The wrapper preserves nonzero test-process statuses, including signal-derived
statuses. If log capture fails while the test process exits zero, it preserves
the capture status. If a zero-exit process has invalid completion evidence, the
wrapper exits 1. Logs remain visible through `tee`; temporary log files are removed
on exit. Parser CLI exit codes are 0 (complete success), 10 (identified retry
candidate, newline-separated absolute paths), and 1 (everything else).

## Local verification

From the repository root, using a supported Node executable:

```sh
node --test .github/scripts/parse-suite-log.test.mjs .github/scripts/run-suite.test.mjs
bash -n .github/scripts/run-suite.sh
```

These are isolated synthetic checks. The wrapper tests copy the launcher into a
temporary fake project, intercept every `--test` invocation, record executable
identity and arguments, and reject unknown commands. No fixture/product source
is executed by that harness. Load and sleep are stubbed. The test host's Bash 3.2
is exercised directly. The parser tests read saved benign Node captures; their
generation sources live under `suite-retry-fixtures/`. `captures.json` records
generation arguments and statuses; only the absolute capture root was replaced
with `@ROOT@` to make the snapshots portable. These captures are format evidence,
not evidence that the product suite passes.

Optional baseline regression reproduction uses an untouched copy of
`run-suite.sh` from before the retry change (a private build; not in this repository's history):

```sh
SUITE_RETRY_BASELINE=/absolute/path/to/baseline/run-suite.sh \
  node --test .github/scripts/run-suite.test.mjs
```

Those four extra cases assert the original TAP retry omission, missing-summary
false green, runtime divergence on a spec retry, and invalid shard admission.
They are skipped unless the baseline path is explicitly supplied.

`.github/workflows/test.yml` runs this wrapper for every shard, and shard 1 also
runs these focused checks (with the inventory guard's) before the suite. A
passing focused check is synthetic format and wrapper evidence; it does not show
that the product suite passed.
