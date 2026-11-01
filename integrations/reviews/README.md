# Reviewer sign-off

A person's agreement with a finding, or dispute of it, recorded beside the verdict and never inside it.

**The record.** A review (`scopehaven-review/1`) is `{ reviewer, at, runId, findingId, decision: agree | dispute, reason }`. A dispute needs a reason. The finding must be a check of that saved run. A reviewer name or reason with a line break, a control character or a format character (bidirectional overrides and isolates, zero-width spaces, the BOM) is refused, so it cannot forge, reorder or hide lines in a text summary.

**Where it lives.**
- Reviews are kept in a review store beside the run store's notes, under `<data>/reviews/<runId>/`. Like human notes, they sit outside the run core and its integrity hash.
- Nothing in the runner, the comparison or the gate reads them.

**Signing and verification.**
- Each review is signed with `integrations/attest` when it is recorded. The store keeps the signed bytes and the DSSE envelope as `<n>.review.json` and `<n>.dsse.json`. The number is one past the highest in use, and publishing the envelope exclusively claims it: two reviews recorded at once never share one, a gap or a planted file never blocks recording, and files are never rewritten.
- Reading the store verifies every review against the reviewer key it is given.
- A review that does not verify (edited bytes, another key, a missing envelope, a review moved from another run) is reported as unverified and never counted. The reviewer key must be a public key: the attest verifier refuses a private one.
- A verified review of this run whose check the run does not have is reported as `outsideRun`, never counted.
- The latest verified review of a finding decides its state.

**What reviews change: nothing that is computed.**
- **Verdicts, comparison labels and gate exit codes** are byte-identical with and without reviews (tested).
- **The counts name their run.** `reviewSummary` carries `runId`, and the counts are attached only where that run is:
  - **SARIF:** `annotateExport` adds them at `runs[0].properties.reviews` only when `runs[0].properties.runId` is the reviewed run; a log that does not name its run is refused.
  - **Comparisons:** a comparison document holding the run gets `reviews` with `role: baseline` or `candidate`; one without it is refused, as is any other document.
  - **Gate summaries:** `annotateGateSummary` refuses a summary whose `current.runId` is another run (or absent), so a clean candidate never shows a baseline's disputes.
  Every computed field is copied as it is, and the caller's document is not changed.
- **Gate summaries.** `annotateGateSummary` adds the same counts. Each failed check a reviewer disputes gets a line `<check>: reviewer disputes (<reviewer>, <time>): <reason>`. The exit code, outcome, reasons and comparison stay as computed.

```
node integrations/reviews/cli.mjs record --data ABSOLUTE_STORE --run UUID --finding CHECK_ID --decision agree|dispute [--reason TEXT] --reviewer NAME --key PRIVATE_PEM
node integrations/reviews/cli.mjs summary --data ABSOLUTE_STORE --run UUID --pub PUBLIC_PEM
```

**Limits.**
- The store is append-only by convention only: anyone who can write the data directory can delete a later review, and the finding then reverts to the earlier one.
- The reviewer name is free text. It is not bound to the signing key; the store verifies every review against the one reviewer key it is given.
- The CLI reports a generic message for a missing run, and a summary of a run with no reviews succeeds whatever `--pub` names.

**Not done here.** Wiring the counts into the dashboard, `src/export-cli.mjs` and the regression-gate CLI output is a separate shared-file step not done here. The functions above are what those call.

Tests: `node --test integrations/reviews/reviews.test.mjs`.
