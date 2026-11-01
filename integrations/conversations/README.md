# Conversation steps for support assistants

Multi-turn chats against a support assistant on loopback, judged on two things: what the assistant says, and what the customer-visible surfaces show afterwards. This is the support-bot connector work for "any business with a support bot".

```bash
node integrations/conversations/cli.mjs --spec <private spec.json> --out <private reports dir> --authorization <record.json>
```

Exit codes: 0 when every conversation passed, 1 on any fail, error or inconclusive, and 2 when the run could not start. The report is written with mode 0600.

The spec's origin is an application you configured, so a run needs an authorization record ([docs/RULES-OF-ENGAGEMENT.md](../../docs/RULES-OF-ENGAGEMENT.md)) naming the spec's `id` and `applicationId`, its origin and every credentialed actor's principal, valid now. Without one, nothing is sent and the run stops with `authorization refused (<code>)`. A spec without an `applicationId` cannot be authorized. The report, the printed summary and the saved run carry the record's id and checksum.

## What a spec declares (`scopehaven-conversation/1`)

- **`origin`:** a literal `http://127.0.0.1:PORT`. Nothing else is accepted.
- **`actors`:**
  - Credentials come from `SCOPEHAVEN_TARGET_*` variables, as a Bearer token or a named cookie.
  - A judged actor declares `identity: { path, pointer, value }`. Its login counts as proven only when that who-am-I route returns the value with its credential, and does not return it with no credential or with a random one. An unproven actor's trials are inconclusive, never passes.
- **`conversations`:** each has one or more `turns`.
  - **`mode`:**
    - `json`: read the reply at `replyPointer`.
    - `sse`: join the `deltaEvent` texts until `doneEvent`.
    - `ndjson`: join the delta lines until the done line.
    - `async`: poll the URL at `pollPointer` until `statusPointer` equals `completeValue`, at most `maxPolls` times.
  - **`capture`:** `{ name: pointer }` saves a value, such as a conversation ID, from the response, the done event or the completed poll. Later bodies use it as `"{{name}}"`. If a capture is missing, the turn is an error and later turns are not sent.
  - **`expect`:** `status.in`, `reply.notContains` / `reply.contains` (with `value`, or `valueEnv` for a canary), and `reply.matches` / `reply.notMatches`.
    - **`reply.notContains` is the canary check.** It fails on any match anywhere the target sent text: the reply, the whole response body (every key and value), every stream event including other event types and the done payload, the raw stream, and every async body (initial, intermediate and final). It matches the value verbatim and also in folded form: HTML entities decoded, NFKC-normalised, format and default-ignorable characters removed, and case-folded. For a **marker-shaped** value it also matches the boundary-anchored skeleton (see "Canary matching channels" below), and the failing expectation records which `channel` found it.
    - `reply.contains` and the patterns check the reassembled reply only.
    - A pattern is at most 200 characters, with flags `""` or `"i"`. Patterns that can backtrack catastrophically are refused: a quantified group that contains a quantifier or an alternation, and backreferences.
  - **`after`:** state checks on GET routes, using the connector's predicates (`status.*`, `json.*`). This is how claim versus state is checked.
  - **`trials` and `policy`:**
    - `trials` is 1 to 50.
    - The default policy, `confirmed`, fails the conversation on one failing trial. Use it for canaries.
    - `{ rate: { maxFailureRate } }` reports the failure rate and fails above the limit. Use it for promise checks. A conversation with a canary check cannot use a rate policy.
- **`observers` and `victimUnchanged`:** a declared field on another customer's account is snapshotted before and after each trial.
  - A change is a confirmed fail.
  - A surface that is unreadable, signed out, or missing the declared pointer is `unavailable`, which is inconclusive.
  - No change is a pass only for an `authoritative` surface.
  - A `presence-only` surface reports "not observed", and the conversation is labelled "not reproduced on observed surfaces".
- **`reset`:** an optional POST, sent by an operator actor before every trial.

A trial is a pass only if something was actually judged: a reply expectation, a state check, or an authoritative surface. A trial with no predicates, or with only presence-only evidence, is inconclusive.

Each turn fails on its own, without stopping the run: an unusable target-supplied poll path, a body over 8 KiB built from captures, or a request the client refuses is a per-turn error. Streams accept comment lines, `data: [DONE]` and deltas without text.

## Evidence

The report holds statuses, byte counts, the names of captured values, expectation outcomes, failure rates and identity reasons. It never holds reply text, captured values, credentials or expectation values. The spec digest covers the contract shape with literal values hashed.

**Not observed:** data the assistant fetched but did not say, tool-call arguments, and effects outside the declared surfaces. A pass means "not reproduced on observed surfaces", not "enforced".

## Profiles

- `profiles/generic-json-chat.json`: a starting point for a JSON chat endpoint with two customers. It covers an own-data lookup then an action on the next turn, a cross-customer canary over 5 trials, and an over-cap promise checked by rate.
- `profiles/storefront.json`: the owned storefront practice app, which is kept outside this repository. It runs the conversations the tests run, with canaries by `valueEnv`.

## Limits

- Loopback only. A business's vendor-hosted bot needs the target-mode decision (in-network or allowlisted remote HTTPS), which belongs to Yusef.
- One HTTP client per turn, with no browser. Each response is at most 64 KiB for JSON and 256 KiB for streams. A run is capped at 10 minutes.
- Standalone report. Conversation runs do not yet feed `compareRuns` or the regression gate.

## Saved runs, comparison and the gate

```bash
node integrations/conversations/cli.mjs --spec <spec> --out <reports> --authorization <record.json> --save <data dir> --gate [--baseline <saved run id>]
```

A spec that declares `applicationId`, `build` and `contextId` can save its run as a native run. The run's evidence origin is `local-conversation`, with one row per conversation; required controls are the `control` conversations. A spec without those fields is report-only, and the CLI says so.

- **Validation:** the comparison and the gate both run `validateConversationRun` (`validation.mjs`). It recomputes every turn, trial, victim and row verdict, plus the failure rate and policy, from the saved evidence, and refuses any stored label that disagrees. Reply-expectation and state-check predicate outcomes are stored outcomes, consistency-checked but not re-derived, because no reply text is kept.
- **Comparability:**
  - Two runs compare only when their spec digests match: any spec edit makes them incompatible.
  - They must also agree on actors, trials, policies, turns and observed surfaces.
- **"Conversation checks restored":** a row counts as restored only when all of these hold:
  - it went from fail to a judged pass;
  - every required control passed with a proven login;
  - the candidate ran at least as many trials as the baseline.

  An error or inconclusive baseline never counts as restored. Rows of an actor whose login the baseline did not prove are unverified.
- **Gate:** the exported suite (`exportConversationSuite`) binds the run's shape and evaluator identity, and a same-spec baseline is held to it too. A rate-policy row over its limit adds the reason `conversation-rate-above-limit`.
- **Evaluator identity:** `CONVERSATION_EVALUATOR_HASH` digests exactly `CONVERSATION_EVALUATOR_FILES` (`conversation.mjs`, `validation.mjs`), every module that computes or recomputes a verdict.
- **History:** run history omits `conversationEvidence`; the full saved run keeps it.

## Canary matching channels

A `reply.notContains` value is looked for on three channels, and the verdict
reports which one found it in `channel`:

| channel | what it is |
| --- | --- |
| `verbatim` | the value appears as written |
| `folded` | it appears after HTML entities are decoded twice, NFKC normalisation, format and default-ignorable characters are stripped, and case is folded |
| `skeleton` | it appears once both sides are reduced to their alphanumerics, with confusable letters mapped to Latin |

**The skeleton channel is deliberately narrow.** It applies only to
`reply.notContains`, only to **marker-shaped** values (no whitespace, at least
one letter and one digit, at least 8 alphanumerics), and a hit must start and end
on an alphanumeric-run boundary of the reply. An earlier version applied it to
every value of 8 or more alphanumerics and flagged honest replies: "refund
issued" matched "There is no refund. Issued orders...", and across 60,000
generated honest replies nine word-like values produced 8,487 hits.

So **a canary must carry random characters**, and not merely be marker-shaped.
`ORDER-1290` *is* marker-shaped, so it does use the skeleton, and its skeleton
appears inside "Your order: $12.90" at a run boundary: that value reads as
present in a reply that never mentioned it. The shape rule keeps the skeleton off
ordinary prose; only randomness keeps it off values that look like real
identifiers. A value with whitespace, or with no digit, is matched verbatim and
folded only.

`reply.contains` never uses the skeleton, because a loose match there would let a
control row pass ("up to 5%" on "50%").
