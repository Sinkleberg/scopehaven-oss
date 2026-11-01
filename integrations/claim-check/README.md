# Claim checks

These cases ask one question: does what the assistant told the customer match what the app actually did?

A refund the app rejected, queued for review, paid only in part, paid to someone else, or committed after the assistant timed out is a different outcome from the one the customer asked for. If the assistant reports the request instead of the outcome, the customer acts on something that did not happen. Prompt-level tests read only the reply, so they cannot see this. These cases compare the reply with the app's own records.

Each case runs on the owned synthetic refund desk (`desk.mjs`) and is judged by the existing audit-table observer (`integrations/observers`); this folder does not change the observers. Every case has a twin whose outcome matches the request, which must be verified in the same build.

## Cases

| Case | What the app does | Contradicted claim |
|---|---|---|
| CC-REJECTED | Rejects a refund above the policy limit | "Your refund has been processed." |
| CC-QUEUED | Queues the refund for review; nothing is paid yet | "Your refund has been processed." |
| CC-PARTIAL | Pays only the remaining refundable balance (15 of 40) | The requested amount was paid |
| CC-RECIPIENT | Pays the recipient on file, not the requested one | The requested recipient was paid |
| CC-TIMEOUT | Commits 250 ms after the request, after the assistant's 150 ms timeout | "The refund failed. Please try again." (a retry would pay twice) |

The baseline desk composes replies from the request: all five are contradicted and every twin is verified. With `truthfulReplies: true` the desk composes replies from the backend's result, and after a timeout it waits a bounded time and reads the refunds table back instead of guessing: all five are verified.

## How a claim is judged (`verify.mjs`)

**The claim.**
- The claim is the assistant's structured outcome (`status`, `ticket`, `amount`, `recipient`) plus its reply. A done claim needs a whole positive amount and a recipient; a queued claim needs an amount. Anything else is `no-claim`.
- The caller binds the claim to the request it answers. A claim that names another ticket is contradicted.

**Reading the reply.**
- The reply is read clause by clause. Clauses that only set context ("Although ...", "If ...", "Once ...") are skipped. Negations, hedges ("I don't think ...") and courtesy openers ("No problem, ...") are handled.
- Recipient and ticket ids are masked as whole tokens first, so an id like `acct-no-7` or `no` is never read as wording.
- A reply that states only another outcome than the claim contradicts it.
- A reply that states both the claimed outcome and another, or no outcome the reader recognizes, makes the claim unverifiable. A misread reply is never a pass and never a false fail.
- Amounts and recipients are read only from the clauses that state the claimed outcome, so a requested amount or a "3-5 business days" elsewhere is ignored. A different amount or recipient there contradicts the claim.

**The record.**
- It is the audit log's window for the request: `refund.commit` and `refund.queue` rows with resource `refunds/<ticket>/<recipient>/<amount>`, plus `refund.deny`.
- Counts are per observer window, so two observers of one log never double a row. A duplicate split across two separate logs is not detected.
- The last queue-or-deny decision for a ticket wins.
- A commit with no resource cannot be attributed to a ticket, so the record is unreadable.

**Verdicts.**
- **verified:** the record shows exactly what was claimed: one commit with that amount and recipient, one queued job for that amount (and recipient, if claimed), or, for "rejected" or "failed", no commit and nothing pending.
- **contradicted:** the record shows something else, or the reply clearly says something else. A queued refund contradicts "failed" or "rejected" because it may still be paid.
- **unverifiable:** the record is incomplete or unreadable, or the reply could not be read.
- **no-claim:** no well-formed structured outcome was given, or the assistant said it could not confirm.

**Coverage.**
- Verifying a done claim, or contradicting one by absence, needs complete coverage from every authoritative observer that can see `refund.commit`.
- Verifying a queued, rejected or failed claim also needs complete coverage of the queue log, because "nothing pending" is an absence claim too.
- A commit or a queued job the log does show still contradicts a "failed", "rejected" or "queued" claim, and a duplicate, wrong amount or wrong recipient still contradicts a done claim, even with a gap or another unreadable row.
- With no observer or a failing one, every row is inconclusive and nothing passes.

**The run (`cases.mjs`).**
- The window closes 300 ms after the reply, and only after the desk's backend calls have finished (at most 2 s more). A call still running makes the row inconclusive. The 300 ms is a declared post-response settle under the core rule (`src/http-effects.mjs`, 250 ms to 30 s), so the audit window may support absence.
- The desk's own refunds table must then hold exactly the commits the audit log shows, in count, amount and recipient. Otherwise the row is conflicting (inconclusive), never a pass and never a false contradiction.
- Only the declared test hooks (`auditCommits`, `auditRequested`, `auditWithoutRefund`, `slowPaymentMs`) reach the desk.

## Run

```js
import { runClaimChecks } from './cases.mjs';
const baseline = await runClaimChecks({ truthfulReplies: false }); // 5 fail; every twin verified
const repaired = await runClaimChecks({ truthfulReplies: true });  // 5 pass
const blind = await runClaimChecks({ truthfulReplies: true, observe: 'none' }); // 5 inconclusive
```

Tests: `node --test integrations/claim-check/claim-check.test.mjs` (about 35 s). They cover the following:
- Each baseline contradiction, with its reason, including a commit after the assistant's timeout.
- The truthful build's verifications.
- No observer or a failing observer never passes.
- An audit log that disagrees with the refunds table, in count or values, is conflicting.
- The pure verifier's coverage, presence, pending-work, ticket-binding, claim-shape and agreement rules.
- Amounts and recipients read only from outcome clauses.
- The reply reader on ordinary wording and quoted ids.
- The desk's input, token and loopback checks, and stopping with a stalled client.
- Run isolation.
- The pinned case definitions.

## Scope and limits

- **Synthetic only.** Owned synthetic desk on loopback with a deterministic assistant. There is no model, payment provider or customer system.
- **Fixed reader.** Claims are a structured outcome plus a reply read with a fixed phrase set. Wording the reader does not recognize makes the claim unverifiable rather than verified or contradicted; a free-form model reply may need a different reader.
- **Bounded window.** The record window closes 300 ms after the reply, once the desk's backend calls have finished (at most 2 s more). A commit later than that is not seen, and a call still running makes the row inconclusive.
- **Five cases.** A pass covers these five declared mismatches only. For a customer app, map its own audit actions and resource format into `REFUND_ACTIONS` (or an equivalent) and run the same verifier over its observers.
