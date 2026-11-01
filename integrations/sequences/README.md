# Timed sequences

A sequence runs a declared list of steps against an application on loopback, then judges effect assertions over what its observers recorded between two marks. One sequence can say: start the agent's task, pause it at a boundary, change the user's access through the app's own admin API, release it, then check what the app recorded. Each run is saved, and `--validate` re-checks a saved run later from the observer windows it sealed.

Everything runs on your machine against a literal `http://127.0.0.1` origin, with test users whose credentials come from `SCOPEHAVEN_TARGET_` variables.

## Run a sequence

From the `scopehaven` folder, with absolute paths (the launcher works from the project folder):

```sh
./scopehaven sequence --sequence /abs/seq.json --origin http://127.0.0.1:PORT --observers /abs/observers.json --authorization /abs/record.json [--gate /abs/gate.json] [--out /abs/runs] [--hold-open-ms N]
    [--save /abs/data --build LABEL [--regression-gate [--baseline RUN_ID]]]
```

`--authorization` names the authorization record ([docs/RULES-OF-ENGAGEMENT.md](../../docs/RULES-OF-ENGAGEMENT.md)) that covers this run: the sequence's `id` and `applicationId`, `--origin`, each observer's endpoint, the hold gate's upstream, and every credentialed actor's principal, valid now. A sequence without an `applicationId` cannot be authorized. Without a covering record the command exits 2 (`Authorization refused (<code>)`) after checking the rest of the configuration and before anything starts or is sent. The stamp (the record's id and checksum) is printed and carried by the saved run (`--save`); the sealed `--out` record does not carry it.

`--gate` is the hold gate's configuration. The regression gate is `--regression-gate` (see [Judge a run with the regression gate](#judge-a-run-with-the-regression-gate)).

**`seq.json`** has schema `scopehaven-sequence/1`, an `id`, `actors`, `steps` and `assertions`.
- `actors` maps aliases to a `principalId` and an optional `credentialEnv` with the `SCOPEHAVEN_TARGET_` prefix (add `credentialCookie` for a cookie login, as in an HTTP profile). An app that checks a CSRF token on every signed-in route (a header that must equal a cookie) takes `"csrf": { "env": "SCOPEHAVEN_TARGET_...", "header": "X-CSRF-Token", "cookie": "csrf_token" }` on the actor: each of its requests then carries that header and that cookie with the env value, beside its credential. The CLI reads it, the value is never written to a run, and the sequence and evaluator identities do not change.
- Limits: 64 steps, 64 assertions, a `sleep` of at most 120000 ms, and 600000 ms for the whole run.
- Optional `applicationId` and `contextId` name the target the sequence is written for. `--save` needs them.

Steps run in order, and each step has exactly one action:

| Step | What it does |
| --- | --- |
| `{ "request": { "id", "actorId", "method", "path", "body"?, "timeoutMs"? }, "background"?: true, "assertStatus"?: { "id", "title", "severity", "in": [codes] } }` | Sends one request as that actor: GET, POST, PUT, PATCH or DELETE. With `background`, the next step starts without waiting for the reply. With `assertStatus`, the status it answered becomes a judged row (see [Judged response status](#judged-response-status-assertstatus)). |
| `{ "awaitHold": { "rule", "as", "timeoutMs"? } }` | Waits until the hold gate holds a request matching that rule, and names the held request. |
| `{ "release": { "hold" } }` | Releases a held request by its `as` name. |
| `{ "awaitResponse": { "request" } }` | Waits for a background request to finish. |
| `{ "expectStatus": { "request", "in": [codes] } }` | The named request must have answered with one of these statuses, for example the access change itself. If it did not, the sequence stops (`precondition-failed:<request>`), because nothing after a failed access change can be judged. It is a precondition, not a row: use `assertStatus` for a status you want judged. |
| `{ "sleep": ms }` | A fixed delay, for delay sweeps. |
| `{ "mark": "name" }` | Takes a cursor from every observer. A mark that ends an assertion first waits the largest `settleMs` (250 to 30000) declared by an observer other than `otel`. |

Each assertion is `{ "id", "title", "severity", "from", "to", "effect": { "kind", "select" }, "corroborate"?: [selectors] }`.
- `from` and `to` name marks, and `to` must come after `from`.
- `severity` is `critical`, `high`, `medium`, `low` or `control`.
- `effect` takes the same `effect.none`, `effect.exists` and `effect.count` kinds and selectors as an HTTP profile (see [Observe what the app recorded](../../docs/ONBOARDING.md#observe-what-the-app-recorded-the-default)). Unlike in a profile, an observer that declares no `settleMs` can still show absence in a sequence, so place each end mark after the app has finished its writes.
- `corroborate` lists 1 to 8 selectors for the same effect as other sources record it, each naming its `source`. When an `effect.none` fails and a listed source did not record the effect too, the row reads inconclusive (conflicting), never a clean fail.

**`observers.json`** lists 1 to 16 observers, in the same shape as an HTTP profile's: `otel`, `sqlite-audit`, `sqlite-snapshot`, `http-audit`, `mcp-log`, `pg-snapshot`, `mysql-snapshot`, `egress-recorder` or `smtp-sink` (see [the observers guide](../observers/README.md)). A sequence sends no witness request, so `audit-file` is refused, and so is an egress recorder or SMTP sink with a `witness`, because their windows would always be partial. Without a witness a sink is presence-only: a recorded send can fail an assertion, and silence proves nothing.

**`files.json`** (optional, `--files`, report only) lists directories the app writes, as `{ "roots": [{ "alias": "exports", "path": "/abs/dir" }], "exclude": ["cache/**"], "maxFiles": 20000, "maxFileBytes": 67108864 }`. The CLI lists those files (by sha256, never their content; symlinks are never followed and FIFOs never opened) before the run and after it, and writes what was added, changed or removed to `<run file>.files.json` (mode 0600) beside the run, with one printed line. It is not part of the run and not a verdict: no window, no row, no digest, and a files channel still reads not observed. A file written and removed during the run is not listed.

**`gate.json`** (optional) declares the hold gate: a loopback proxy you put in front of the app's model server or a tool service, so a step can pause a request there and release it later. It is also an observer: every request it forwards is a `tool-call` effect named by its rule (or `ungated`), committed when upstream answered 2xx, and denied when its rule declares the status answered as a refusal ([below](#declared-refusals-at-the-hold-gate-rulesrejected)). Any other answer leaves the call's outcome unknown and its window partial. The app cannot write that record (a declared refusal rests on the upstream's answer; see below), so a boundary absence the gate decides can pass under custody.

```json
{ "upstream": "http://127.0.0.1:8001", "port": 8002, "rules": [{ "id": "model", "method": "POST", "pathPrefix": "/v1/chat" }] }
```

Here the model server listens on 8001 and the gate on 8002: point the app's model base URL at 8002. A rule's `holds` limits how many matching requests it holds (default 1); later matches pass through. A rule with `holds: 0` holds nothing and only names the calls it records. The gate binds 127.0.0.1 only, its upstream must be literal loopback HTTP, and `gate.json` cannot set `instanceId`. An app in a Docker Desktop container reaches the gate at `http://host.docker.internal:GATE` (the gate's `containerUrl`); the gate admits that Host as the egress recorder does, and still refuses a repeated Host, any other name or port, an Origin other than `http://127.0.0.1:GATE` and a cross-site fetch, so no relay is needed.

`--hold-open-ms N` starts the observers, then waits N ms (at most 600000) before the first step, so the app can connect to them first.

Credentials are read only from `SCOPEHAVEN_TARGET_` variables: those the sequence's actors name, and an observer's `credentialEnv` (`http-audit`, `pg-snapshot`, `mysql-snapshot`). Neither is written to the run. Input files must be regular files of at most 64 MiB; a parse error names the argument, never the content.

**Output.** One line of counts, one line per row (a status row also shows the status answered) and the saved file. On the owned mini helpdesk fixture (`fixtures/mini-helpdesk.mjs`: loopback, synthetic data and a scripted model), with a sequence that suspends the agent's user while its task is held at the model call, the build that checks permission only when the task starts printed:

```
Sequence MIDTASK-DOCS: 0 pass, 1 fail, 0 inconclusive, 0 error
  FAIL         MIDTASK-NOTE  No note after suspension
Saved /abs/runs/MIDTASK-DOCS-3d2dcc0f592a.json
```

The build that checks again when the action commits printed `1 pass` and exited 0. The run file is `<sequence id>-<first 12 characters of the run digest>.json`, mode 0600, in `--out` (created with mode 0700). Pass `--out` with a private directory: the default, `.scopehaven-sequences`, is created inside the `scopehaven` folder (git ignores it). Its schema is `scopehaven-sequence-run/3`. Runs saved earlier as `scopehaven-sequence-run/2` still validate as /2.

**Exit codes:**
- `0`: every assertion passed.
- `1`: an assertion failed. An effect row's failure decides the code even when the sequence stopped early (a stopped sequence decides no status row).
- `3`: nothing failed, but an assertion was inconclusive or hit an observer error, or the sequence stopped early. A stopped sequence never passes, because a pass needs the whole sequence; the counts line says why it stopped, for example `(stopped: hold-timeout)`, and any request still held is dropped, never released.
- `2`: a configuration error.

## Judged response status (`assertStatus`)

`expectStatus` stops the run when a precondition fails. To judge a status instead, put `assertStatus` on the request step:

```json
{ "request": { "id": "amy-refund", "actorId": "amy", "method": "POST", "path": "/api/refunds", "body": { "ticket": "T-1", "amount": 20 } }, "background": true,
  "assertStatus": { "id": "AMY-HELD-REFUSED", "title": "Amy's held refund is refused once she is suspended", "severity": "high", "in": [401, 403] } }
```

- `id` is unique across all of the sequence's rows, `severity` is one of the assertion severities, and `in` lists 1 to 16 distinct status codes from 100 to 599. One `assertStatus` per request.
- The row follows the effect rows in `results`, with `kind: "response-status"`:
  - **pass**: the request received a complete HTTP response whose status is in `in`.
  - **fail**: it received one whose status is not.
  - **inconclusive**: the request was not sent or not answered, or the sequence stopped early, or a refusal has no same-actor acceptance (`identity-not-established`, below).
- A stopped sequence decides no status row, a failure included: a background request's answer can depend on steps that never ran, such as the access change or the release.
- Only the status code is judged. The reply's text is never read or kept, so a reply that claims success cannot make a row pass, and one that says "refused" cannot either.
- A status row shows what the application answered, not what it did. A 403 can come with a refund that still committed, so judge the effect with an effect assertion over an observer the application cannot write (a hold gate, egress recorder or SMTP sink).
- **Same-actor acceptance.** A 401 or 403 from a credential that never worked looks exactly like a refusal. So, as the HTTP connector's identity proof does for its rows, a status row that would pass on a 401 or 403 counts only when an earlier request by the same actor in the same run received a complete 2xx answer. That request is the row's `acceptedBy`; it can be an asserted control, like `AMY-LOGIN` below, or any earlier request. Without one the row reads inconclusive (`identity-not-established`): the gate fails with `inconclusive-evidence` and a comparison gives it no restoration credit. Another actor's 2xx, a later 2xx and an earlier refusal do not count. A refusal row whose request was served (any other answer) still fails, and a row whose answer is not 401 or 403 is unaffected. Even with the pairing, a refusal row says what the application answered, not that an authorization change took effect in its records.
- A step's keys can come in any order: `background` and `assertStatus` are modifiers, and the remaining key is the action, both when the sequence is validated and when it runs.

A run records `statusAssertions` (as declared, with the request each names), `requests` (every declared request in step order, with its actor alias), `responses` (for each request that was answered: its status, whether the response was complete, and the transport outcome) and `evaluatorHash`. All are sealed in the run digest, and `--validate` decides every status row again, same-actor acceptance included, from `requests` and `responses`.

**Evaluator identity.** `evaluator.mjs` lists the modules that decide or recompute a sequence verdict (`sequence.mjs`, `run-validator.mjs`, and the effect and custody rules in `src/effect-events.mjs`, `src/custody.mjs` and `src/effect-lineage.mjs`). `SEQUENCE_EVALUATOR_HASH` digests exactly those sources and every /3 run seals it. The regression gate compares only runs of one evaluator, so a change to how sequence runs are judged makes old baselines incompatible instead of silently comparable.

## In-flight lifecycle: a refund held while its agent is suspended

`fixtures/inflight-refund.json` runs against the owned refund desk (`fixtures/refund-desk.mjs`: loopback, synthetic users, no model). Each refund asks an approval service and then commits through a refund tool, both behind one hold gate:

```json
{ "upstream": "http://127.0.0.1:TOOLS", "port": GATE, "rules": [{ "id": "approve", "method": "POST", "pathPrefix": "/v1/approve" }, { "id": "refund", "method": "POST", "pathPrefix": "/tool/refund", "holds": 0 }] }
```

The sequence:
1. checks that Amy's credential is accepted (`AMY-LOGIN`, a control);
2. starts Amy's refund in the background, which the gate holds at the approval;
3. suspends Amy through the desk's admin API (a precondition);
4. releases the held approval and waits for Amy's answer;
5. has Ben request a refund, the allowed-use twin;
6. sends a fresh refund from Amy.

`INFLIGHT-REFUND` is `effect.none` over the gate's `refund` tool calls between the suspension and Amy's answer. `BEN-REFUND` is the control: exactly one `refund` tool call in Ben's window. The gate records no acting principal, so these selectors name none. They are sound because only one actor acts in each window.

On the three builds, with a sqlite-audit observer on the desk's own audit table as well:

| Row | `unchecked-at-commit` (defect) | `recheck-at-commit` (repair) | `halt-all` (over-blocking) |
| --- | --- | --- | --- |
| `INFLIGHT-REFUND` (critical) | fail, custody `independent` | pass, custody `independent` | pass |
| `BEN-REFUND` (control) | pass | pass | fail |
| `AMY-LOGIN` (control) | pass (200) | pass (200) | pass (200) |
| `AMY-HELD-REFUSED` (high) | fail (200) | pass (403) | pass (403) |
| `BEN-REFUND-ACCEPTED` (control) | pass (200) | pass (200) | fail (403) |
| `AMY-FRESH-REFUSED` (high) | pass (401) | pass (401) | pass (401) |
| Exit | 1 | 0 | 1 |

The defect's fresh request is refused, so the fix looks done, while the refund already in flight still commits through the tool. That failure is decided by the hold gate's record, which the desk cannot write. Without a hold gate (no `--gate`, the desk calling its tools directly), the sequence stops at its first hold (`step-error`) and every row reads inconclusive. `INFLIGHT-REFUND` reads `unobservable`: no configured observer sees the tool calls.

## Declared refusals at the hold gate (`rules[].rejected`)

By default the gate trusts only a 2xx: any other answer (a 4xx, a 5xx, a reset, no answer by the window end) leaves the call's outcome unknown, because the upstream may have acted before failing, and an unknown call keeps its window partial. So when the tool service correctly refuses a held call, for example with 403 once the agent is suspended, an `effect.none` over that call reads inconclusive, and a build that authorizes at commit cannot pass under a tool-call hold.

A reply of any status, a 2xx included, that the upstream cuts off after its status line is unknown too: a reset, or a close before the declared length or the last chunk. The gate notes it as an upstream error after the response, so anything reading the timeline sees an incomplete round trip, and it cuts its own reply to the client off too, rather than ending it as if whole. A reply with no length ends, in HTTP, when its connection closes cleanly, so one cut off by a clean close reads whole; only a reset shows it was cut.

A rule may opt in and declare the statuses its upstream answers only when it did not apply the call:

```json
{ "id": "refund", "method": "POST", "pathPrefix": "/tool/refund", "rejected": [403] }
```

- A call under that rule answered a listed status reads `denied` once that reply has arrived in full within the window, with no upstream error. It is not a committed effect and it leaves the window complete, so the `effect.none` can pass. A reply without a length ends when its connection closes cleanly; one reset mid-body stays unknown.
- The declaration covers every call the rule names: any method, held or passed through, on any path the rule's prefix matches (decoded and case-folded, as the rule matches paths), not only the calls the rule holds.
- Everything else keeps the default reading: a 2xx that is not cut off is committed, and an unlisted 4xx, every 5xx, a reset, an upstream error, a listed status whose reply was cut off or had not ended by the window's end mark, and a call with no answer yet are unknown. Another rule's calls, and ungated ones, are unaffected.
- `rejected` lists up to 16 distinct 4xx statuses, the ones an egress destination's `forward.rejected` allows: never a 2xx, 3xx or 5xx, nor 408, 425, 429 or 499, which may be answered while the upstream still applies the call. A declaring rule's id must be its own (no other rule uses it), and it cannot be `ungated`, the name of calls no rule matches. Anything else is refused when the gate is built, before anything binds (`Configuration error`, exit 2). An empty list is the same as none.
- The gate's observer scope carries the declarations (`scope.rejected`, by rule id), so a run seals them, a run with a declaration never compares with one without it, and `--validate` with `--observers` and `--gate` binds them. Without a declaration the gate, its scope and every window it records are exactly as before.

**What the declaration asserts.** The gate sees the status the upstream answered, never what the upstream did, and unlike `forward.rejected` there is no proof behind it: declaring a status is your statement that this upstream never answers it after applying the call. An upstream that applies a call and still answers a listed status reads denied, and the row passes. Declare only statuses the tool service answers before it changes anything. Do not declare `rejected` for an upstream inside the application's trust domain (the same codebase or deployment, or one that shares its credentials or data). There the application chooses the status, and the row still reads custody `independent`, because custody follows the gate's record, not who chose the answer.

## Websocket steps and captured paths

Some agents run over a websocket: the client posts a chat turn, the reply names an invocation, and the client opens a websocket at a path built from it. A sequence can drive that with `capture` on a request and a `websocket` step:

```json
{ "request": { "id": "chat", "actorId": "sam", "method": "POST", "path": "/api/chat", "body": { "text": "approve order 7" }, "capture": { "invocation": "/websocketUUID" } } },
{ "websocket": { "id": "agent-ws", "actorId": "sam", "path": "/api/agent-invocation/{invocation}", "send": [{ "type": "start" }], "until": { "messages": 20 }, "timeoutMs": 60000 }, "background": true },
{ "awaitResponse": { "request": "agent-ws" } }
```

- **Captures.** `capture` maps a name to a JSON pointer into the request's JSON reply (1 to 8 per request, 16 per sequence, names unique). A later request or websocket path uses the value as `{name}`. A value must be a string or an integer of 1 to 200 characters from `A-Z a-z 0-9 . _ ~ -`, and never `.` or `..`, so it cannot add a path segment, a query or a host. A reply without a usable value stops the run (`capture-missing:<name>`). Only JSON replies are read; a streamed (SSE) reply is not.
- **The websocket.** It opens `ws://127.0.0.1:<origin port><path>` with the actor's credential (Bearer header or cookie) and the actor's CSRF pair when it declares one. It sends each `send` message (up to 16 JSON values) once the handshake is done, and ends at whichever comes first: `until` (`{ "messages": n }`, 1 to 1000 data messages, or `{ "close": true }`, the default, when the server closes), or `timeoutMs` (default 60000).
- **Bounds.** The transport rules of a request apply (a literal loopback origin, a same-origin path, no proxy, no redirect, no retry). It offers no extension, so no compression. Each message is at most 1 MiB and a step at most 8 MiB.
- **What stops the run.** A handshake answered without 101 (`websocket-refused:<id>`), no answer at all (`transport-failed:<id>`), or a message over a bound or a frame no server may send (`websocket-failed:<id>`). A timeout, or a connection that ends after the handshake, is recorded and the run goes on: observers judge what the agent did.
- **No row.** A websocket drives the agent as a request does; it decides no row, and the sequence has no `assertStatus` for it. Judge the agent's effects with effect assertions as before.

A sequence with a websocket step or a capture writes `scopehaven-sequence-run/4`: a /3 run plus `websockets` (each declared step and its actor), `websocketRecords` (for each step that ran: the handshake status, how it ended, the message count, the close code, the bytes received and one sha256 digest per message, never the content) and `captures` (each declared capture and the digest of its value, or null when the run never reached it). All three are sealed in the run digest. `--validate` checks their form, and with `--sequence` binds them to the sequence. Every other sequence still writes /3. The regression gate reads /4 runs as it reads /3.

## Judge a run with the regression gate

`--save DATA_DIR --build LABEL` also stores the run in a core run store, as a native saved run with the evidence origin `local-sequence`. `--regression-gate` then judges it with the regression gate (`integrations/regression-gate/gate.mjs`), and `--baseline RUN_ID` compares it with a run saved earlier in the same store. This follows the conversations CLI (`--save`, `--gate`, `--baseline`), with a name that cannot be confused with the hold gate's `--gate`.

- `--save` needs `--build`: 1 to 200 printable characters naming the build under test. It is the operator's declaration, not a build hash.
- `--save` needs the sequence's target identity: top-level `"applicationId"` and `"contextId"` (1 to 80 letters, digits, `_` or `-`). It also needs at least one row of severity `control`: without one, an absence could come from a target that does nothing.
- `--regression-gate` and `--baseline` need `--save`, and `--baseline` needs `--regression-gate`. The baseline is read and validated before any request is sent.
- The stored run's id is the run digest in UUID form, so one run is stored once. Its first 12 characters match the run file's name.
- With `--regression-gate`, the exit code is the gate's: 0 clean, 1 assessment failed, 2 evidence refused or configuration error. Without it, the exit code is the run's own.

```sh
./scopehaven sequence --sequence /abs/inflight-refund.json --origin http://127.0.0.1:DESK --observers /abs/observers.json --gate /abs/gate.json --out /abs/runs --authorization /abs/record.json --save /abs/data --build unchecked-at-commit
./scopehaven sequence --sequence /abs/inflight-refund.json --origin http://127.0.0.1:DESK --observers /abs/observers.json --gate /abs/gate.json --out /abs/runs --authorization /abs/record.json --save /abs/data --build recheck-at-commit --regression-gate --baseline RUN_ID
```

On the owned desk, the repair against the defect printed:

```
Regression gate: clean (exit 0)
  Against 1900d3ac-da05-6b0d-d692-33bf6438efa3: compatible; Observed effects and response status restored; contract-restored 1, local-control-restored 1, preserved 4
Gate summary: {"schemaVersion":1,"outcome":"clean","exitCode":0,"reasons":[], ...}
```

The other builds, against the same baseline:
- `halt-all`: `assessment-failed (exit 1): checks-failed, required-controls-not-passed, comparison-incomplete`. Its two restored rows read `blocked-by-controls`, never restored.
- No hold gate: `assessment-failed (exit 1): inconclusive-evidence, required-controls-not-passed, incompatible-baseline, comparison-incomplete`. Another observer configuration is another identity.

How the gate judges a sequence run:
- **Recomputed.** The native run is rebuilt from the sealed sequence run it carries, after every verdict is recomputed (`run-validator.mjs`). A row, count, control list or identity field that disagrees is refused (`invalid-sequence-evidence`, with the part as detail, for example `native-run` or `sequence-run:sequence-verdict:INFLIGHT-REFUND`).
- **Bound.** The candidate is bound to the sequence this process ran: scenario hash, assertions, status assertions, target, the evaluator this process runs, and the observers the run was given. Otherwise: `unexpected-suite-evidence`.
- **Compared.** A pair is comparable only with the same evaluator hash, scenario hash (the sequence's steps, assertions and actors), sealed assertion and status-assertion definitions, target (sequence id, `applicationId`, `contextId`) and declared observers. Otherwise it reads `incompatible-baseline`. The definitions are compared directly because a run cannot recompute its own scenario hash: the steps are not stored. The build label may differ.
- **Labelled.** A restored effect row reads `local-control-restored`, and a restored status row `contract-restored`. The pair's label says which: `Observed effects restored`, `Response status restored`, or both.
- **Never a fix from an inconclusive row.** A row inconclusive on either side reads `unverified`, never restored, and the gate fails with `comparison-incomplete`. A pair whose controls did not all pass reads `Unverified changes`.
- **Never from a /2 run.** Only `scopehaven-sequence-run/3` runs can be saved: a /2 run carries no evaluator identity.
- **Never in the core comparison.** The core comparison (`compareRuns`, the dashboard's compare) does not know this origin and reads such a pair as unsupported, never as a repair.

## Re-check a saved run (`--validate`)

```sh
./scopehaven sequence --validate /abs/runs/RUN.json [--sequence /abs/seq.json] [--observers /abs/observers.json [--gate /abs/gate.json]]
```

`--validate` reads the saved file only. It sends no request and starts no observer. It never trusts a stored verdict: it decides every assertion again from the observer windows the run sealed, with the same decision function the runner uses, and every result must match exactly. It also checks:
- the run digest, over every field except `timeline`, `gateTimeline`, `createdAt` and `durationMs`;
- each declared observer: a kind a sequence can record, the source that kind produces, an instance id of that kind's form, and the scope that kind declares in code;
- each window: one per observer for each assertion's marks, bound to its observer, with coverage as the runner sets it;
- every window event fits its observer: an operation in the observer's scope and, for kinds that always name their events from the scope (snapshots, the audit-log file and the hold gate), a declared name; an audit-table or audit-endpoint event needs a declared name too, unless it is an update that was not denied;
- the assertions, under the same rules as a sequence's, and the counts. The order of each assertion's marks is checked only with `--sequence`, because the run does not store the steps;
- in a /3 run: the evaluator hash's form, the status assertions (the rules of `assertStatus`, one per request, ids unique across all rows), the requests (ids unique, each status assertion's request among them) and the responses (only for declared requests, in the runner's shape). Every status row, with its same-actor acceptance, is decided again from them. A /2 run carries none of these fields.

With `--sequence`, the run must also come from that sequence: the same id, sequence hash, assertions, status assertions and requests. With `--observers` (and `--gate`, when the run used the hold gate), the run must also have been recorded by that observer configuration: the observers are built from it but never started (nothing binds, connects or reads a credential), and the run's declared observers must equal them in order, kind, instance id, source and scope, names included. `--gate` without `--observers` is refused.

When everything matches, it prints one line and exits with the run's own code (0, 1 or 3):

```
Recomputed 1 assertion of MIDTASK-DOCS from the sealed windows: every verdict matches, bound to the given sequence and the given observer configuration.
```

Otherwise it prints `Run evidence refused: <code>`, with the detail in parentheses when there is one, and exits 2. A file it cannot read or parse, or an invalid `--sequence`, `--observers` or `--gate` file, prints `Configuration error: ...` and also exits 2. The refusal codes:

| Code | Meaning |
| --- | --- |
| `not-recomputable` | A `scopehaven-sequence/1` record. It kept window digests only, so its verdicts cannot be re-checked. |
| `invalid-sequence-run` | The record is not one the runner could have written. The detail names the part, for example `run-digest`, `identity`, `schema`, `observers`, `observer-scope`, `windows`, `window-events`, `window-coverage`, `status-assertions`, `requests`, `responses` or `counts`. |
| `unexpected-sequence` | With `--sequence`: the run came from a different sequence. |
| `unexpected-observers` | With `--observers`: the run was not recorded by that observer configuration (a different observer, order or scope, names included). |
| `sequence-verdict` | A stored result differs from the one its windows (or, for a status row, its response) decide. The detail names the row. |
| `sequence-pre-custody` | No stored result carries a custody field: the run was saved before custody decided sequence verdicts. Re-run it. |

On the failing run above:
- the run itself validated and exited 1;
- with one stored verdict edited to pass, it read `invalid-sequence-run (run-digest)`;
- with the same edit and the digest recomputed, it read `sequence-verdict (MIDTASK-NOTE)`;
- checked against a sequence with another id, it read `unexpected-sequence`;
- checked with `--observers` against a configuration whose audit observer declares one more action name, it read `unexpected-observers`.

`fixtures/sequence-run-v1.json` reads `not-recomputable`.

## Limits

- **Consistency, not authenticity.** The digest is not keyed. A record rewritten consistently as a whole, windows, verdicts and digest together, validates. Keep run files private, as you keep the evidence directory.
- **Pass `--observers` to bind the configuration.** The names an observer was configured to see, and a sink's evidence level, come from its configuration. Without `--observers`, nothing outside the run says what they were. For the SQLite audit table, HTTP audit endpoint and hold gate kinds, a consistent change to those names alone can then turn an unobservable absence into a pass, and a sink's evidence level can be changed from presence-only to authoritative. With `--observers` (and `--gate`), the run's declared observers must equal the ones that configuration builds, scope included, so such a change is refused (`unexpected-observers`). Keep the observer configuration with the run.
- `timeline`, `gateTimeline`, `createdAt` and `durationMs` are outside the digest.
- A status row is the application's own answer. It never shows that an effect did or did not happen.
- A hold gate rule's declared refusals (`rules[].rejected`) are the upstream's word: a listed status reads denied whatever the upstream did, and the row still reads custody `independent`. A run seals each gate event's outcome, not the status behind it (the gate timeline is outside the digest), so `--validate` recomputes verdicts from the sealed outcomes and binds the declaration through the scope, but does not derive a denied outcome from a status again.
- Effects committed after an assertion's end mark are not observed in that window. Set each observer's `settleMs` above the slowest write the app completes after replying.
- A sequence does not reset application state between runs. Reset the target before repeating a run or a delay sweep.
- A websocket record keeps one digest per message, never the content: `--validate` can show how many messages arrived and that a later run saw the same ones, not what they said.
- Validation re-checks what a saved run recorded. It does not show what the application does on a new run.
