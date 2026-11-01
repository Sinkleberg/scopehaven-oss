# Walk through one Mastra billing scenario end to end, without the setup scripts

The frameworks README's "Run it" section and `docs/FRAMEWORK-MODE.md` both point at `setup/mastra-billing.sh` and `setup/langgraph-cs.sh`, and `integrations/frameworks/setup/` (not in this repository) is left out of the release on purpose. The six frozen Mastra scenarios in `integrations/frameworks/scenarios/` and their acceptance records under `integrations/frameworks/acceptance/mastra-billing/` are checked in, but there is no written path from a clean machine to a verdict, so the one framework a TypeScript developer can try has no instructions.

Write the walkthrough for `mastra-billing.reset-after-commit` (the default scenario for `--framework mastra`) as a new section of `docs/FRAMEWORK-MODE.md`, replacing the `setup/` references: check out `mastra-ai/mastra` at the commit the scenario's `template` block pins, install that example's own dependencies inside the checkout (nothing is added to ScopeHaven; `tsx` is the template-side runtime the adapter loads through `--runtime`), then run `./scopehaven assess --framework mastra --template ... --runtime ... --stub blind-retry --out ...` and the same with `--stub checks-then-reports`, and show the rows each produces (`FW-EXEC`, `FW-FAULT`, `COLLATERAL-01`, `COLLATERAL-GOAL`, `FW-CONTENT`, `FW-SAID-DID`) beside the checked-in verdict files for those two stubs. Say what a verdict on the scripted stub shows and does not: the model is ScopeHaven's scripted stand-in, so the result is about the template's tools and state under the planned fault, not about any model, and the acceptance records hold no application-side fix, only other personas. Replace the frameworks README's "Run it" block with one command set that names no `setup/` script.

## Pointers

- `docs/FRAMEWORK-MODE.md`: "Run it", the options table and the paragraph that names the setup scripts.
- `integrations/frameworks/README.md`: the "Run it" section.
- `integrations/frameworks/scenarios/mastra-billing.reset-after-commit.json`: the `template` block (repository, path, commit, licence), the stubs (`checks-then-reports`, `claims-done`, `reports-failed`, `blind-retry`, `do-nothing`) and the planned fault.
- `integrations/frameworks/adapters/mastra_billing.mts`: what the adapter needs from the checkout.
- `integrations/frameworks/acceptance/mastra-billing/`: one `record.json` and `verdict.json` per stub to compare against.
- `integrations/frameworks/run.mjs`, `integrations/frameworks/assess.mjs`: the runner and the CLI wiring.

## Acceptance

A reader with Node 24 and git reaches a saved run for two stubs following the document alone, and neither document names a file that is not in this repository.

## Test

Extend `integrations/frameworks/frameworks.test.mjs` with one case that re-judges the two acceptance records the walkthrough cites and asserts their `overall` verdicts match what the document says (the file already re-judges every acceptance record; this pins the documented wording to them).

## Labels

`good first issue`, `documentation`

## Effort

3 to 5 hours, most of it the template's own install.
