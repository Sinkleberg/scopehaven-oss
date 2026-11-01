# Rules of engagement and the authorization record

Before ScopeHaven sends a request to an application you configured, someone should have agreed to it in writing. This folder makes that agreement a record ScopeHaven checks. The template is `docs/RULES-OF-ENGAGEMENT.md`. The record (`scopehaven-authorization/1`) is a JSON file with an integrity checksum that says:
- who signed;
- which target, origins and test accounts it covers;
- until when.

**Files:**
- `src/authorization.mjs`: the record, its checksum and the check (this folder's `authorization.mjs` re-exports it);
- `src/authorization-file.mjs`: `readAuthorizationFile`, which reads the record from a regular file (never through a symlink or a FIFO, at most 256 KiB), and `authorizeConfigured`, the one step every entry point runs (this folder's `file.mjs` re-exports both);
- `run.mjs`: `runAuthorized`, a check-run-stamp wrapper for callers;
- `cli.mjs`: `seal` (adds the checksum to a draft and writes a new file) and `check` (the check a run makes, without running);
- `roe.test.mjs`, and `test/authorization.test.mjs` for the wiring;
- `fixtures/authorization.example.json` (synthetic);
- `docs/RULES-OF-ENGAGEMENT.md`.

No pinned identity hash moves: none of these files is in an evaluator or collector identity. The refund evaluator identity, computed at run time and pinned nowhere, does move: it hashes `integrations/regression-gate/gate.mjs` and `src/registry.mjs`, which this change edits.

## What is checked, and when

`checkAuthorization(record, profile, { now })` runs before the first request. It refuses, without echoing any value, when any of these fails:

| Rule | Code |
| --- | --- |
| The record is well formed | `authorization-invalid` |
| Its checksum matches: `sha256` is the digest of every other field, so an edit made without recomputing it shows. It is unkeyed, so it is not a signature | `authorization-checksum` |
| It names the profile's `id` and `applicationId` | `authorization-target` |
| Its `origins` include every endpoint the run contacts: the profile's origin (a literal `http://127.0.0.1:PORT`; for a forwarded staging target, the forwarder's port) and each observer's (an http-audit origin, `tcp://127.0.0.1:PORT` for a database snapshot, a provider feed's endpoint, and an egress recorder's forwarding upstreams and request feed). An observer type the check does not know is refused | `authorization-origin` |
| For a remote target (`operator-remote`), its exact https origin is in `origins` (it is the target's origin, so the row above covers it). The record's `addresses` reach the run's transport: a non-public address the host resolves to is refused unless listed there (`src/remote-target.mjs`, `remote-address-refused`) | `authorization-origin` |
| Its `identities` include the principal of every actor that holds a credential (a signed-out actor needs none) | `authorization-identity` |
| The current time is inside `[validFrom, validUntil)` | `authorization-window` |
| `signedAt` is not after the current time | `authorization-invalid` |
| For a target declared `operator-forwarded`, the record names the forwarder's destination (`forwarded.destination`, an http or https origin); a record that names one covers only a forwarded target. The destination is the operator's statement and never reaches the run | `authorization-forwarded` |

Two more refusals come from the entry points rather than the check itself:

| Rule | Code |
| --- | --- |
| The record file repeats no field name in any object (`readAuthorizationFile`): JSON keeps only the last of the repeats, so a file could show one value while the check enforced, and the checksum covered, another | `authorization-duplicate-key` |
| The window is still open immediately before each request the run sends, before each call it makes to an observer except `stop` (`windowGuard`, `guardObserver`, used through `authorizeConfigured`), and once more immediately before the run is saved or stamped: once it ends, no further request is sent and no further observer call starts (one already running, or `stop`, can still read; Limits below), and the run is refused, never saved or stamped | `authorization-window-ended` |

`runAuthorized(profile, { record, env, now })` checks first, then runs with the window checked again before every request and every observer call (on a clock that starts at `now`; once it ends no further request is sent and no further observer call starts, and it throws `authorization-window-ended`), checks it once more when the run returns, then adds `authorization: { schema, id, sha256 }` to the run. A missing record is refused (`authorization-missing`), and so is a profile that is not plain data, a function, symbol or proxy in it (`authorization-profile`): `runAuthorized` copies the profile once and gives the check and the run that copy, so each reads the same values. The tests show that a refused run sends no request at all.

**The record never changes a verdict.** It is checked before the run and only its stamp is copied onto the result. The tests compare the same run with and without a record: statuses, assertions, counts and every identity hash are identical, and only `authorization` differs.

**Built-in fixture targets** need no record: the synthetic demos (`BUILT_IN_KINDS`) and exact registered owned refund target IDs. A refund-looking prefix or unknown owned-refund label does not grant this exemption. Every other registry entry, including an unknown kind or none at all, needs one: `needsAuthorization` fails closed. The built-in targets run unchanged: same verdicts, same SUITE and POLICY hashes.

## Where it is enforced

Every entry point that sends requests to a target the operator configured calls `authorizeConfigured` with the validated profile the run uses, before any connection:
- `assess` (`src/cli.mjs`): `--authorization <file>`. A configured target without a covering record exits 2 before anything starts, `--confine` included; the refusal prints its code. With one, the saved run carries the stamp and the printed summary shows it.
- the regression gate (`integrations/regression-gate/gate.mjs`): `--authorization <absolute file>`, refused before the output directory is touched; the refusal code is the gate's reason (`authorization-missing`, `authorization-window`, ...), exit 2. The summary's `current` and the saved run carry the stamp. The gate's validator accepts a stamp only of the exact shape `{ schema, id, sha256 }`.
- the GitHub Action: an `authorization` input, checked like `profile` (a single-line path to a regular file, not a symlink), then checked in the prepare step with `cli.mjs check`, before the wait or any request (a refusal stops the action with exit 2 and its code), and passed to assess and the gate. The prepare step passes `wait-url` to the check (`--wait-url`), which refuses it (`authorization-origin`) unless its origin is one of the record's origins. The wait (`wait-for.mjs --until`) stops when the window ends. The owned lab writes its own record (`examples/http-lab.mjs` `makeLabAuthorization`, `data/http-lab.authorization.json`), and the workflows pass it.
- the web dashboard's run path (`src/server.mjs`, `POST /api/runs`): `SCOPEHAVEN_AUTHORIZATION_FILE`, read again at each run; a refusal is a 403 with the refusal code, and nothing is sent.
- the sequence command (`integrations/sequences/cli.mjs`): `--authorization <file>`. The record names the sequence's `id` and `applicationId`, `--origin`, each observer's endpoint and the hold gate's upstream. The saved run (`--save`) carries the stamp; the sealed `--out` record does not (it is sealed before the stamp exists), so the stamp is printed.
- the conversation command (`integrations/conversations/cli.mjs`): `--authorization <file>`, naming the spec's `id`, `applicationId` and origin. The report, the printed summary and the saved run carry the stamp.

For assess, the gate and the dashboard, the owned model tap's upstream (`SCOPEHAVEN_MODEL_TAP_UPSTREAM`), which the run forwards the application's model calls to, must be in the record's `origins` too.

The HTML report's provenance block, the comparison export's run identities and SARIF `runs[0].properties.authorization` carry the stamp when the run has one; the dashboard labels the new gate reason codes.

Runs of built-in fixture targets keep exactly their shape. **This is a breaking change for anyone running a configured target:** each entry point refuses it until a record is supplied.

## Limits

- The record's `sha256` is an unkeyed integrity checksum, not a signature: it shows an edit made without recomputing it, and anyone who can edit the record can recompute it. The record is the operator's statement. Who signed it is what the record says. A cryptographic signature (`integrations/attest` keys) is a later step.
- The check binds the record to the configured target, its origin and its accounts, and for a forwarded target to the destination the operator names. It cannot tell whether the forwarder behind a loopback origin goes there (operator trust, as in `integrations/forwarded/README.md`).
- Library callers that run a configured target directly (`runHttpAssessment`, `runSequence`, `runConversations`) are not checked: the check is at the entry points an operator runs. `runAuthorized` is the checked library path. The exception is a remote target: `runHttpAssessment` (and `registry.run`, which calls it) refuses one, before any lookup, unless its `remote` option carries the grant `authorizedRemote` makes from a record naming the target's origin and a `beforeRequest` window check is passed (`authorization-missing`). Only the grant's addresses are dialled.
- The stamp is copied onto the run after validation; the stored run's checksum then covers it like the rest of the run (an unkeyed checksum too), and the gate and sequence validators check only its shape. Nothing binds it to the run's target: it says which record the run was started under, not that the run could only have been made under it.
- The window is checked before every request ScopeHaven sends (to a remote target too, before its host is resolved again, once more after that DNS check, immediately before the connection, and again when the TLS handshake is done, immediately before the request is written; a connection started before the end can finish its handshake after it, within that check's request timeout, but its request is not written) and when each call it makes to a declared observer starts, and once more before the run is saved or stamped. The check is made when each observer call starts. A call already running when the window ends (a provider feed's run-end drain or later-outcome wait, a request feed's run-end read) finishes its reads, up to its own cap, and stopping a provider feed lets its queued read finish. The final check then refuses the run. An observer's own activity between its start and stop (a provider feed's poll timer, an egress recorder, hold gate or the owned model tap relaying the application's calls, and a recorder's read-back reads) is not checked request by request: it stops with the run, and the final check refuses a run that ended at or after `validUntil`. Library callers that run a profile themselves (`runHttpAssessment` without `beforeRequest`, `runSequence`, `runConversations`) are not guarded. Two seams skip the per-request check and still stamp, and only tests use them: `runAuthorized` with a custom `run` that ignores `beforeRequest` and the guarded observer factory (its final check still applies), and `startServer({ assess })` with an `assess` that ignores its second argument.
- `cli.mjs check` counts the owned model tap's upstream from the environment, as assess, the gate and the dashboard do; it does not know a sequence's hold-gate upstream, which the sequence command checks.
- The check reads the profile it is given; each entry point passes the same validated profile the run uses.
