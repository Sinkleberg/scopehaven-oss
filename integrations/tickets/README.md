# Offline ticket export

Turns a saved run, or a comparison, into tickets a team can import by hand:
- **Jira CSV:** columns Summary, Description, Labels, Priority, Dedupe Key and Scopehaven Status.
- **GitHub-issue markdown:** one issue draft per ticket.

Nothing is sent anywhere: there is no Jira or GitHub API, and the export makes no network call. The same run, or the same pair of runs, always gives identical bytes.

## Tickets

| Status | When |
|---|---|
| Open | a check that fails in the run |
| Resolved candidate | a check whose comparison transition is a repair (`fixed`, `contract-restored`, `local-control-restored`), only when every one of core's conditions for crediting a repair holds (below). It carries core's restoration label, copied, never upgraded. |
| Unverified change | the same transition when any condition does not hold. The description says which; no resolution is claimed. |

**Conditions for Resolved candidate.**
- The comparison is core's own for this pair: it is checked against a fresh `compareRuns(baseline, candidate)` by the regression gate's `validateComparison`, so a forged, edited or mismatched comparison is refused.
- The runs are compatible and every required allowed-use control passes.
- The candidate has no new failures.
- No model identity was present but unreadable.
- Where core records model attribution, it credits the repair to the application, both for the pair and for this row.

**Dedupe key.** The key is the SHA-256 of the JSON array `[check id, application id, policy hash, profile hash, target context, target label]`. The profile hash is core's identity of the target profile; `compareRuns` requires it to match, so every pair that can resolve shares it. The same check on the same target, under the same policy, keeps its key across runs, builds and re-exports, so an importer can match the issue it opened earlier and close it. Two targets never share a key: another origin under the same application, a local and a forwarded target, or two forwarded targets with the same label. A legacy synthetic run without a stored profile hash gets the one core's comparison fills in. The target id is not in the key: in the owned demo it names the build (`demo-vulnerable`, `demo-repaired`), and the profile hash already separates targets.

**Description.** The fixed lines come first and are never cut:
- the status, with the reason when no repair is claimed;
- the run's scope statement;
- the line "These are observed checks, not a safety certification.";
- the evidence hashes: the run's integrity hash, and the check's evidence digest when one was saved;
- the identity: application, target, profile, suite, policy and evaluator;
- for a comparison: the baseline, core's evidence scope, its model-attribution note and caveats;
- every limitation the run states.

The check's own text follows, cut to the 8000-character field. Bidirectional controls are removed from every line. Human notes are excluded, as in every other export.

## Safety of the files

- **CSV.** Every cell is quoted (RFC 4180), so a semicolon locale cannot split one. A cell that a spreadsheet would read as a formula (`=`, `+`, `-` or `@`, after any leading space, or a leading tab or carriage return) gets a leading apostrophe. Labels are single lowercase words.
- **Markdown.** Every free-text field sits inside a fenced code block, longer than any backtick run it holds, so nothing in it renders, links, mentions, references or closes the fence. Outside the fence there are only fixed words and the ticket's number, the status, the priority, the labels and the dedupe key. The check id stays inside the fence, so an id like `GH-12` never links to an issue.
- **Text.** Bidirectional control characters are removed, and cuts never split a character.

## Use

```
node integrations/tickets/cli.mjs --run UUID --format jira-csv|github-md --out ABSOLUTE_NEW_FILE [--data ABSOLUTE_STORE] [--baseline UUID]
```

- With `--baseline`, the candidate run is compared with the baseline exactly as the local API compares them.
- The output parent must exist with mode 0700 and belong to you. An existing file is never overwritten.
- The formats are not yet wired into `src/export-cli.mjs` or the dashboard.

Tests: `node --test integrations/tickets/tickets.test.mjs`.
