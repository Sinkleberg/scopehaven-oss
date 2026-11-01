# Retest history (scopehaven-retest-history/1)

For each finding on a customer's applications, what happened to it across the runs an operator kept in an evidence ledger (`integrations/ledger`): when it was found, whether a fix was claimed, whether a later run verified the fix, and whether it came back. The history is built only from a ledger that verifies with every run's signed file, so it reads the same runs the ledger and their signatures vouch for. It ships signed, and anyone with the same ledger, run files and declarations can rebuild it byte for byte.

**What it shows:** for each finding, the runs that moved it and core's own reading of each move (`compareRuns` in `src/runner.mjs`).

**What it does not show:** that a check covers the behaviour it names, that a fix holds outside the runs in the ledger, or anything about runs the ledger does not hold. It is not externally witnessed (`"witness": "none"`), like the ledger it reads.

| File | Role |
|---|---|
| `history.mjs` | Pure: validates the operator's declarations and builds the history from a verified ledger result and the run files. |
| `cli.mjs` | `build`, `export` (signed, into a new private folder) and `verify` (signature, then a byte-for-byte rebuild). |
| `retest-ledger.test.mjs` | Real runs of the owned HTTP lab in its baseline and repaired builds, exported, signed and appended as an operator would. |

## Finding identity

A finding is the SARIF fingerprint `scopehavenCheck/v1` that `src/sarif.mjs` puts on every result: the SHA-256 of the stable JSON of `{ applicationId, suiteId, checkId }`. It stays the same across runs, builds, re-exports and SARIF uploads, and two applications never share one. A test checks it equals the fingerprint `renderSarif` writes.

## States

| State | When |
|---|---|
| `found` | A run failed the check. |
| `fix-claimed` | The operator declared a fix in a build (`fixClaims`). It is placed at the first run of that build, or at the end when the ledger has no run of it yet. A declaration, labelled `source: "declared"`. A claim is consumed by the first run of its build whatever the state (on a FIXED_VERIFIED finding, with no event); a claim on a build already run before the finding was found is ignored; and a claim never replaces a computed FIXED_VERIFIED or regressed state. A regression answers an open claim, so a later failing run is not read as still failing in the claimed build. |
| `FIXED_VERIFIED` | A later run passed the check, compared by core's `compareRuns` with the last run that failed it: the pair is compatible (same suite, policy, fixture, evaluator, application, profile and evidence origin), every required allowed-use control passed with a proven identity, no row that passed before failed, the row's transition is one of core's repair transitions (`fixed`, `contract-restored`, `local-control-restored`), core credits the change to the application (where the runs carry model identity: a model change, a confounded change or an unreadable identity is never credited, by the same rule as `integrations/tickets` `resolutionBlocker`), and every declared twin passed. A fail that rests only on the app's own log, a declared absent field or a provider's later outcome is never credited, because core reads those rows as unverified. |
| `NO_VERIFIED_REPAIR` | After a fix claim, or when a run moved the check off fail, the run did not verify a repair. The event says why: still failing, not comparable (core's reasons), controls not passing, a new failure, a row core reads as unverified (with its status and any custody reason), or a declared twin that did not pass. |
| `regressed` | The check failed again after `FIXED_VERIFIED`, whatever the pair: a fail is never weaker evidence than a pass. Each finding counts its regressions (`regressions`), and `counts.regressedEver` counts findings that regressed at least once, so a regression stays visible after a later state replaces it. |

A `FIXED_VERIFIED` finding stays verified only while later runs of its application and suite pass the check: a later run that reads it as anything but pass, or that does not carry the check, moves it to `NO_VERIFIED_REPAIR` (open), and a later verified pass closes it again.

**Order.** Runs of one application and suite must appear in the ledger in the order they were made (each run's signed `createdAt`); a ledger that goes back in time for one application and suite is refused, so a backfill or an envelope listing runs out of order can never let an older pass close a finding a newer run failed. A repair is credited only from a run made strictly after the run that failed.

A finding is open unless it is `FIXED_VERIFIED`. Each event carries the run, its ledger entry, its time and build, and for a comparison the baseline run, core's row transition and core's run-level `retestVerdict`.

**Row level, not run level.** `FIXED_VERIFIED` here is about one finding. It does not require every other row of the run to be decided, which core's run-level `retestVerdict` does (an owned app with custody-held rows never reads `FIXED_VERIFIED` at run level). Every event keeps the run-level verdict beside it, so a reader sees both.

## Declarations

The operator's file, `scopehaven-retest-declarations/1`:

```json
{ "schema": "scopehaven-retest-declarations/1", "customer": "Owned lab", "findings": [
  { "applicationId": "owned-http-lab", "suiteId": "...", "checkId": "FOREIGN-STATUS", "class": "B2", "twins": ["OWN-RECORD"],
    "fixClaims": [{ "build": "lab-repaired" }], "openReason": "held by the owner" } ] }
```

- `class` is a class code (`A4`, `B2`, ...), carried to the assessor pack.
- `twins` are the finding's allowed-use checks; each must pass for `FIXED_VERIFIED`, on top of the run's required controls.
- `openReason` is shown only while the finding is open.

Declarations never change a computed state. Unknown fields, duplicate findings and text outside a plain character set (letters, digits, spaces and `. , : ; ( ) ' / _ + # @ & -`, at most 200, no link) are refused, so nothing an operator writes carries markup, a link or a claim-shaped field into the signed history. A declaration for a check that never failed adds no finding and is counted in `declaredFindingsNotSeen`.

## Use

Every path is absolute. Verify the ledger with run files first if you want its own report; `build` does it anyway.

```sh
node integrations/retest-ledger/cli.mjs build  --ledger /ABS/ledger --key /ABS/ledger.pub.pem --run-files /ABS/runs --declarations /ABS/declarations.json [--require-reasons]
node integrations/retest-ledger/cli.mjs export --ledger ... --run-files ... --declarations ... --out /ABS/NEW_DIR [--signing-key-dir /ABS/keys]
node integrations/retest-ledger/cli.mjs verify --ledger ... --run-files ... --declarations ... --history /ABS/NEW_DIR
```

- `--require-reasons` refuses a history in which any open finding has no declared reason.
- `export` writes `retest-history.json`, `retest-history.json.dsse.json` (attest's DSSE envelope, the same key as `./scopehaven export`) and the signer's public key into a new 0700 folder, built beside `--out`. Only after the envelope verifies is `--out` claimed (created exclusively, so an existing one is refused, also one made meanwhile) and the built folder renamed over the empty claim in one step; a claim someone filled in between fails and is left as it is.
- Exit codes: 0 done (`verify`: reproduced), 1 refused, rejected or not reproduced, 2 usage or file error.

**Refused:** a ledger that does not verify; runs of one application and suite out of creation order, or without a readable `createdAt`; an unsigned tail; a ledger run with no run file whose core digest matches the signed entry; a run file whose verdicts differ from the ledger's; two files with one run core; malformed declarations.

## Auditor walkthrough

1. Get the signer's key id over a separate channel.
2. Check the signature with the standard-library Python verifier: `python3 -I integrations/attest/verify_envelope.py --key KEY.pub.pem --envelope retest-history.json.dsse.json --dir HISTORY_DIR`. Exit 0, `"verdict": "verified"`, and the `keyid` you were given.
3. Check the ledger the history names (`ledger.log`, `ledger.size`, `ledger.root`): `python3 -I integrations/ledger/verify_ledger.py log --key ledger.pub.pem --ledger LEDGER --run-files RUNS`. Its last checkpoint must have that size and root, and every run must be checked against its run file.
4. Rebuild: `node integrations/retest-ledger/cli.mjs verify ... --history HISTORY_DIR` prints `reproduced` when the signed file is exactly what the ledger, the run files and the declarations give. The rebuild needs Node, because it uses core's `compareRuns`; there is no Python recomputation of the history.

## Limits

- The history reads run exports only. A payments-pack run in the ledger is verified with its file but not read (`paymentsRunsSkipped`).
- Fix claims match a build string exactly.
- Twins are checked for a passing status; their identity proof is core's, through the required controls.
- One customer per declarations file; a ledger per customer is the expected layout.

Tests: `node --test integrations/retest-ledger/retest-ledger.test.mjs` (unsandboxed: it starts the lab on loopback and spawns `python3`).
