# Give every CLI the same `--json` shape

Three of the twenty-four `cli.mjs` entry points take `--json`: `integrations/coverage-report/cli.mjs`, `integrations/grant-use/cli.mjs` and `integrations/monitor/cli.mjs`. `src/cli.mjs` and `integrations/regression-gate/cli.mjs` always print JSON. The rest print prose, write files, or both, and none says on stdout which document it printed. A script that wraps ScopeHaven has to special-case every command, and a wrapper author holding an output cannot tell from the output alone which document it is.

Audit first, then change the smallest thing. Write a table, as a new document `docs/CLI-OUTPUT.md` (new), listing each entry point, whether it takes `--json`, what it prints by default, what `--json` prints, the document's `schema` value where the output already carries one (the `scopehaven-.../N` strings the reports use), and its exit codes. Then make the three existing `--json` flags consistent: exactly one JSON document on stdout, nothing else on stdout, every human message on stderr, and a top-level `schema` string. Do not add `--json` to every command in this issue; list in the table which commands should get it next, so each can be its own small change. Exit codes stay as the README documents them.

## Pointers

- `src/cli.mjs`, `src/export-cli.mjs`, `integrations/regression-gate/cli.mjs`, `integrations/sequences/cli.mjs`: the commands that print JSON today without a flag, or write it to files.
- `integrations/coverage-report/cli.mjs`, `integrations/grant-use/cli.mjs`, `integrations/monitor/cli.mjs`: the three `--json` flags to align.
- `integrations/coverage-report/examples/` and `integrations/grant-use/fixtures/`: checked-in inputs for the first two; `integrations/monitor/cli.test.mjs` shows how a trace file is written for the third.
- `README.md`: the "Commands" section and the exit-code paragraph the table must agree with.

## Acceptance

The table is accurate for every `cli.mjs` entry point, and for each of the three `--json` commands stdout parses as exactly one JSON document with a `schema` string.

## Test

`test/cli-json.test.mjs` (new): runs the three `--json` commands on their fixtures through `node`, asserts stdout parses as one JSON document with a `schema` string and that stderr carries any prose.

## Labels

`good first issue`, `cli`

## Effort

3 to 4 hours.
