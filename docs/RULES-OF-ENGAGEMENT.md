# Rules of engagement (template)

Fill this in and have it signed before ScopeHaven runs against any application you configure: a staging environment reached through a forwarder, or a local copy of your own app. The built-in synthetic fixtures need none. The signed terms then go into an authorization record (`scopehaven-authorization/1`, below). ScopeHaven checks the record before it sends a single request and stamps it on every run it authorizes: it won't run a configured target without a matching authorization record.

**Where the check runs.** Every entry point that sends requests to an application you configured:

| Entry point | How the record is given |
| --- | --- |
| `./scopehaven assess --config ... --target ID` | `--authorization record.json` |
| `./scopehaven gate --config ... --target ID --out DIR` | `--authorization /absolute/record.json` |
| The GitHub Action | the `authorization` input |
| The web dashboard (`./scopehaven start`) | `SCOPEHAVEN_AUTHORIZATION_FILE=record.json`, read again at each run |
| `./scopehaven sequence --sequence ... --origin ...` | `--authorization record.json` |
| `node integrations/conversations/cli.mjs --spec ...` | `--authorization record.json` |

Without a record, or with one that does not cover the run now, each of them stops before any connection: the CLIs exit 2 with the refusal code (for example `authorization refused (authorization-window)`), the gate reports the code as its reason, and the dashboard answers 403 with it. The GitHub Action makes the check in its prepare step, before its wait for the application. The window is checked again before every request a run sends and when each call it makes to a declared observer starts, and once more immediately before the run is saved or stamped: if it has ended, no further request is sent, no further observer call starts, and the run is refused the same way with `authorization-window-ended`, with nothing saved or stamped. An observer call already running when the window ends, or stopping an observer, can still read after the end (section 5, Limits); the run is still refused, and nothing from it is saved or stamped. `node integrations/roe/cli.mjs check RECORD --config TARGETS --target ID` makes the same check as assess and the gate without running anything (a sequence's hold-gate upstream is checked by the sequence command itself).

This template is a starting point, not legal advice. Use your organization's own approval process where it has one.

## 1. Scope

- **Application:** name, version or build, and the environment (for example "staging, synthetic data only").
- **In scope:** the checks or check families to run, by their ids.
- **Out of scope:** anything not listed above, including production, other tenants, third-party services the app calls, and denial-of-service or load testing.

## 2. Target origins

ScopeHaven connects to literal loopback endpoints and, for a remote target over HTTPS, to the one origin the record names. List every one a run contacts:
- for a remote target (`"targetContext": "operator-remote"`), its exact origin (`https://staging.acme.example`, or `https://staging.acme.example:8443`), and in `addresses` any non-public IP address its host resolves to (a VPN or internal address); a non-public address the record does not name is refused;
- the loopback origin of the target (`http://127.0.0.1:PORT`), or of the forwarder for a remote staging app;
- each observer endpoint: an audit API (`http://127.0.0.1:PORT`) or a database read for snapshots (`tcp://127.0.0.1:PORT`);
- for a sequence with a hold gate, the gate's upstream; for a run with ScopeHaven's own model tap, its upstream (`SCOPEHAVEN_MODEL_TAP_UPSTREAM`);
- where the forwarder sends traffic: the staging origin (for example `https://staging.acme.example`). It goes into the record's `forwarded.destination`, never into the run label or the run.

## 3. Test identities

For each actor, give the dedicated test account's principal id (`principalId` in the profile) and its role. Never use a real person's login. The record must name every test account the run signs in as: each actor with a credential. A credential an observer reads evidence with (a database reader's user, an audit API token) is not an actor and is not listed here; the record binds the observer's endpoint instead (section 2). Agree on those accounts in writing too.

## 4. Allowed data classes

- **May be read or created during testing:** for example "synthetic customer records, synthetic payments in test mode".
- **Must not be touched:** for example "real personal data, real payment methods, production secrets".

POST, PUT, PATCH and DELETE checks can change data. List the actions that may be exercised and how the environment is reset afterwards.

## 5. Time window

The start and end, in UTC, at most 366 days apart. The record's `validFrom` and `validUntil` must match. A run outside the window is refused before any request is sent. The window is checked:

- when a run starts;
- immediately before every request ScopeHaven sends (checks, identity probes, witnesses, sequence request steps, conversation turns and the Action's readiness probes);
- when each call the run makes to a declared observer starts, except stopping it, so no observer call starts after the end (one already running can finish its reads; see Limits below);
- once more immediately before the run is saved, written or stamped.

If it has ended at any of these points, no further request is sent and no further observer call starts, the run ends with `authorization-window-ended` (exit 2, or a 403 on the dashboard), and nothing is saved, written or stamped. That includes a run whose window ends after its last request was sent, while a response is still arriving, and a run whose observer call or `stop` read after the end. Leave room in the window for the whole run.

## 6. Stop conditions

When testing stops at once, and who is told. For example:
- unexpected real data appears;
- the app reaches a third-party service in live mode;
- error rates suggest an outage;
- the owner asks.

## 7. Contacts

The owner's technical contact and an escalation contact, each with how to reach them during the window.

## 8. Evidence retention

- **Where run evidence is kept:** a private directory, owner-only permissions.
- **For how long, and who may see it.**
- **What is shared outside the team, if anything.**

ScopeHaven keeps response metadata and predicate outcomes, not raw response bodies or resolved credentials.

## 9. Signatory

The name, role and organization of the person authorizing the test, and the date signed.

## The authorization record

The signed terms become one JSON record. The example is `integrations/roe/fixtures/authorization.example.json` (synthetic).

| Field | Content |
| --- | --- |
| `id` | your reference for this authorization |
| `target` | the profile's `id` and `applicationId` (for a sequence or a conversation spec, its `id` and `applicationId`; one without an `applicationId` cannot be authorized) |
| `origins` | the endpoints from section 2: loopback ones, and a remote target's https origin |
| `addresses` | a remote target only, optional: the non-public IP addresses its host may resolve to |
| `identities` | the principal ids from section 3 |
| `validFrom`, `validUntil` | the window from section 5, in UTC |
| `signer`, `signedAt` | from section 9 |
| `rulesOfEngagement` | this document's title, and optionally its SHA-256 |
| `forwarded` | for a target declared `operator-forwarded`, and required for one: `{ "destination": "https://staging.acme.example" }`, the origin its forwarder sends to (http or https, a host, an optional port, nothing else). A record with it covers only a forwarded target |
| `sha256` | an integrity checksum: the SHA-256 of the record without this field |

Write the record without `sha256`, then seal it: `node integrations/roe/cli.mjs seal draft.json record.json` adds the checksum and writes a new file (it never overwrites one). In code, `checksumAuthorization` (`src/authorization.mjs`) does the same. The checksum shows an edit made without recomputing it. **It is not a signature:** it uses no key, so anyone who can edit the record can recompute it. Keep the signed rules-of-engagement document itself where your organization keeps signed approvals, and treat the record as the operator's statement of what it covers.

ScopeHaven refuses to start, before any connection, when the record is:
- missing;
- edited without recomputing its checksum;
- outside its window;
- for another target, or it disagrees with the target on whether a forwarder is in front of it (`authorization-forwarded`);
- missing an endpoint the run contacts (the target's origin or an observer's);
- missing one of the run's test accounts;
- not a regular file (a symlink or a FIFO is refused), or larger than 256 KiB;
- repeating a field name in any object (`authorization-duplicate-key`): JSON keeps only the last of the repeats, so the file could show one value while the check enforced another;
- dated (`signedAt`) after the current time.

The record never changes a verdict. It is checked before the run, and only its stamp (`{ schema, id, sha256 }`) is copied onto the saved run, the HTML report's provenance, the SARIF properties, the comparison export and the gate summary. The stored run's checksum covers the stamp like the rest of the run, and that checksum is unkeyed too; the validators check only the stamp's shape, and nothing binds it to the run's target. It says which record the run was started under, not that the run could only have been made under it.

**Limits.** The window is checked before every request ScopeHaven sends. The check is made when each observer call starts. A call already running when the window ends (a provider feed's run-end drain or later-outcome wait, a request feed's run-end read) finishes its reads, up to its own cap, and stopping a provider feed lets its queued read finish. The final check then refuses the run. What runs on its own between an observer's start and stop is not checked request by request: a provider feed's poll timer, and an egress recorder, a sequence's hold gate (including a `release` step, which forwards a held request) or the owned model tap relaying the application's own calls (with an egress recorder's read-back reads). A sequence's hold gate is also an observer of the run, but its observer calls are not checked; they read only the gate's own record in memory. These stop when the run stops, and a run that ends at or after `validUntil` is refused at the final check, so no run that contacted anything after the end is saved or stamped. A sequence's own run file (`--out`) is sealed before the stamp exists, so the stamp is printed and carried by the saved run (`--save`), not by that file. The record cannot show where a forwarder behind a loopback origin sends traffic: that is the operator's statement.
