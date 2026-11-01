# Re-derived verdicts (scopehaven-verdict-check/1)

Re-derives the PASS/FAIL verdicts in an exported evidence pack from the observations the pack kept. Someone else can then check those verdicts on their own machine without running Scopehaven's code. `verify_verdicts.py` uses only the Python 3.8+ standard library and shares no code with Scopehaven: the rules it applies are written out in the file.

**What a pass shows:** each verdict listed as re-derived follows from the recorded observations under the pinned rules. The counts and failure rates tally, and no stored verdict label disagrees: no row, assertion, trial, custody, corroboration or count. Explanatory text, such as a row's basis or summary, is not compared.

**What it does not show:** that the observations are true or that the application is safe. If someone consistently fabricates the observations (the attempts, windows or trial records), the verdicts will follow from them. A signature says who produced the files. This checker says the verdicts follow from what the files recorded.

| File | Role |
|---|---|
| `verify_verdicts.py` | The checker. It runs `verify_envelope.py` first as its own process, then re-derives the verdicts, lists the rest and runs its self-checks |
| `SCOPE.md` | Which verdicts each run type lets you re-derive and why the rest can't be, with file:line references |
| `verdict-check.test.mjs` | Real exports of every run type, signed and unsigned, checked against the in-repo evaluators, along with mutated copies of them |
| `http-rederive.test.mjs` | HTTP contract runs shaped like the ADV-OOB-2 arm (a retail app, a ledger and a mail sink with one failure), in each predicate record mode, packed and signed by `evidence-pack` and checked from the pack, with the forgeries the checker and ScopeHaven both refuse |
| `demo.mjs` | Builds a check-it-yourself pack from the synthetic fixture: a signed pack and a forgery signed by the same key |
| `parity_driver.py` | Test helper that exposes the checker's internals to the tests. Auditors don't need it |

## What gets re-derived

| Run type | Re-derived from the export | Listed, not re-derived |
|---|---|---|
| Synthetic fixture (`synthetic-local-http`, suite 2.3.0) | Every row status and assertion status, from the kept attempts | Rows the harness lowered after an error, which isn't kept. Runs of other suite versions |
| Conversation (`local-conversation`) | Every turn, after-check, victim and trial outcome. Each conversation's status under its policy, the failure rates and the counts | Reply-expectation outcomes, after-check assertion statuses and victim states, because no reply text, response body or state snapshot is kept. Login proofs |
| Sequence (`scopehaven-sequence-run/3` and `/2`, and the saved `local-sequence` form) | Every effect row from its sealed windows, including corroboration, early stops and the custody hold. Every status row from its sealed responses, and the counts | Observer scope names and evidence kinds, which are configuration and not sealed. `scopehaven-sequence/1` records |
| HTTP contract (`local-http-response`, loopback-response-contract/1 to /3) | Each row whose assertions fix its status: the status assertion from the observed status, `json.equals` and `json.exists` from their predicate records, `json.notContains` from a value-mode record, `json.noForeignValues` from its recorded counts, then the roll-up and the row's decision. A row one assertion fails is re-derived whatever its other assertions read | Rows resting on an effect, claim or read-back clause (`effect-clauses-not-carried`), on an outcome-only JSON predicate (`predicate-not-carried`), or on a digest-mode `json.notContains` over a present string (`predicate-value-not-carried`). Rows whose identity reason rests on probe-bracket or lifecycle rules (`identity-rules-not-carried`): a carried identity assertion there is read as recorded (a stored input). Declared `not_applicable` rows |
| Other origins | No verdicts. Only the integrity hash, the run shape, the counts and the required controls are checked | Every row |

Other files (SARIF, HTML, comparisons) are listed as not checked.

## What gets checked

In order:

- **Signature first.** With `--key` and `--envelope`, `verify_envelope.py` runs as a separate process. It must report `verified`, which includes passing its own negative controls. Each file is then read once, and its SHA-256 must equal the digest that verifier accepted. With `--unsigned`, the output says no signature was checked.
- **Numbers as JavaScript reads them.** Every number is read as `JSON.parse` reads it, as a double. So `9007199254740993` is `9007199254740992` here too, and no comparison is stricter than Scopehaven's.
- **Integrity.** Each run export's integrity hash is recomputed. As in attest, the hash has no key, so this catches only careless edits. A synthetic row's evidence digest and its trace are recomputed too: the trace is a second copy of its attempts, so it must say what they say.
- **Pinned rules.** A run's declared rules must be ones this checker carries. For synthetic runs that means the suite, policy and fixture hashes: the policy and fixture data are carried in full and hashed here. For other runs it means the schema versions. If the rules don't match, every row is listed as `rules-not-pinned`.
- **Re-derivation.** Each verdict in the table above is recomputed. For an HTTP contract row, each assertion the row keeps enough for is recomputed and must equal its stored status (`verdict-mismatch`). The row is re-derived when those assertions fix its status, whatever the rest read. Its stored status must always be one its assertions allow. A failed JSON predicate is reported with the field it compared, the expected value and the actual one, as far as its record keeps them. A predicate record of the wrong shape for its mode is refused (`evidence-malformed`), as are two rows that record one request (`row-duplicated`). A saved sequence run's rows are rebuilt from its sealed run, and a sequence row's matched evidence and window coverage are recomputed from its windows. The pack is refused if a stored row status, assertion status, trial outcome, failure rate, custody tag or count disagrees, with a reason such as `verdict-mismatch`, `counts-mismatch` or `coverage-mismatch`. A stored `fail` must always re-derive, because the harness never lowers one. A conversation run the runner cannot write is refused as `src/conversation-native.mjs` refuses it, under the same code: no conversation (`no-conversation-recorded`), a conversation with no trial (`no-trial-recorded`) or more than 50 (`trials-out-of-range`), or a rate policy outside 0 to under 1 (`max-failure-rate-out-of-range`).
- **Whole sequence rows.** As `validateSequenceRun` compares them, a sealed sequence row must hold exactly the fields the rules write (`sequence-verdict`), and a run saved before custody decided sequence verdicts is refused (`sequence-pre-custody`). A saved `local-sequence` run must be exactly the one its sealed run gives, with effect controls that prove their use and a printable build label, as `validateSequenceNativeRun` requires (`invalid-sequence-evidence`).
- **Run shape.** Each file read as a run export must have the shape the regression gate's `validateRun` requires, whatever its origin: identifier ids; 64 hex digits in every run hash, `evaluatorHash` and `targetConfigHash` included; 1 to 1,000 rows counted by `checksTotal`; rows whose assertions agree with their status; counts of known statuses; and at least one required control, because without one a target that does nothing passes. Otherwise the run is refused as the gate refuses it (`invalid-run-evidence`). A run missing `suiteHash` or not at `schemaVersion` 1 is reported as not checked (exit 4), not refused, though the gate refuses it. That is because a file is read as a run export only if it has `schemaVersion` 1, a string `id`, a string `suiteHash` and a SHA-256 `integrity` block.
- **Listing.** Everything not re-derived is listed by id with its reason, and so is any file in a `--dir` folder that the signature does not cover; such files are named, never read. So is every signed file that is not a run export (an HTML report, SARIF, a comparison): it can state verdicts of its own, and the checker does not compare those with the run. A pack with any listed entry reads `rederived-in-part`, never `rederived`, even when every verdict was re-derived; the `detail` sentence says which it was, and `summary` gives the counts. To get exit 0 for a run, check the run export alone against its own envelope (`--envelope run.json.dsse.json run.json`).
- **Negative controls.** After a run passes, four tampered copies go through the same code:
  - one verdict flipped without resealing
  - one verdict forged with its own labels, digests, counts and integrity hash resealed
  - one required control's row dropped
  - one row added

  Each copy must be rejected. If any is accepted, the verdict is `self-check-failed`.

## Use

The operator exports and signs the runs as described in `integrations/attest/README.md`. Send the files, the envelope and the public key, plus `verify_envelope.py` and `verify_verdicts.py` in one folder. The checker looks for `verify_envelope.py` in its own folder, or you can pass `--attest-verifier PATH`. The recipient needs Python 3.8 or later:

```sh
python3 verify_verdicts.py --key scopehaven-signing-key.pub.pem --envelope evidence.dsse.json --dir ./received --text
python3 verify_verdicts.py --unsigned run.json --text
```

Use copies of both checkers you trust, for example from the repository, or read them first. The output prints the SHA-256 of the `verify_envelope.py` it ran.

Each run's report names the evaluator build the run records (`evaluatorHash`), shown as recorded: the verdicts are re-derived under this checker's pinned rules whichever build it names.

Output is JSON. Add `--text` for a readable report. Exit codes:

- 0: every verdict re-derived, and nothing else given to it left unchecked
- 1: rejected (the output names the reason)
- 2: usage or file error
- 3: self-check failed (do not rely on this checker)
- 4: consistent, but the checker did not vouch for everything it was given: verdicts left out, stored inputs, or files not checked (read `summary`)

### Try it

`demo.mjs` builds a check-it-yourself pack from the owned synthetic fixture and prints the commands that check it:

```sh
node integrations/verdict-check/demo.mjs /ABSOLUTE/NEW/DIR
```

The pack has two parts, signed with one fresh key:

- `signed/` holds both demo builds. All 88 verdicts re-derive (exit 0).
- `forged/` holds the planted-defect build with one failing critical row relabelled pass. Its assertions, counts and keyless integrity hash are recomputed, and the key holder signed it. `verify_envelope.py` verifies the signature. `verify_verdicts.py` refuses the file with `verdict-mismatch`, because the row's kept attempts still grade fail.

The private key exists only in memory: only the public key is written.

## Limits

- The rules are this checker's own reading of Scopehaven's rules: `src/evaluator-synthetic.mjs`, `src/conversation-native.mjs`, and `integrations/sequences/run-validator.mjs` with `src/effect-events.mjs` and `src/custody.mjs`. The tests show the two readings agree on real exports and on mutated copies. That agreement is tested, not proven, so the readings could differ on input the tests don't reach.
- The reply-truth and promise checks read replies through declared tables of patterns. They are ported pattern for pattern, with JavaScript's whitespace, word-boundary, truthiness and comparison rules written out.
- Sequence and conversation runs are checked without their definitions (the sequence file, the conversation spec or an exported suite). So if a forger removes an assertion together with its row, or a conversation together with its shape entry, only the definition can catch it. Synthetic coverage is pinned by the suite.
- Sequence event fields that no verdict reads are not validated: captured body fields, idempotency and upstream records, and the format of `observedAt`.
- Explanatory text is not compared: a row's basis, summary or assertion texts may be edited without changing a verdict. Scopehaven does compare five explanatory fields: a sealed sequence row's `basis` and `custodyUpgrade`, and a saved sequence run's scope label, limitations and trace labels. Scopehaven refuses a run with any of the five edited, and this checker reads it as consistent. In each case the checker's verdicts still match Scopehaven's: it reports the run consistent where Scopehaven refuses it, and it never passes a verdict Scopehaven fails.
- With `--dir`, files whose names start with a dot are not listed.
- The synthetic rules are pinned to suite 2.3.0 (`support-fixture/5`) only.
- HTTP contract runs are re-derived for their response rules only. Effect, claim and read-back clauses, settlement, pairing, attribution, captures and the probe-bracket and lifecycle parts of the actor-identity rules are not carried. Those rows are listed, and an identity assertion they decide is read as recorded, so `validateHttpRunEvidence` may refuse a run this checker reads as consistent. A `json.equals` digest shows that two values are equal, not what they are. A forger who rewrites the observed digest to the expected one, and everything above it, produces a consistent record. Only the signature ties that record to a signer.
- Refund runs are not re-derived. Only the run shape the gate requires is checked for them, so their own validator may refuse a run this checker lists.
- A run whose rules this checker does not pin (another adapter or schema version, or a `scopehaven-sequence/1` record) is listed, where Scopehaven's validators may refuse it. Either way it is never read as re-derived.
- Consistency between files is not checked, so a SARIF or HTML report of a run may say something its JSON export does not.
- JSON that repeats a key in one object is refused (`evidence-ambiguous`). So is JSON nested deeper than 200 levels (`evidence-unparseable`); Scopehaven's exports are far shallower. Numbers are read as `JSON.parse` reads them, so an integer of 5,000 digits reads as Infinity.
- A file `JSON.parse` cannot read, such as an HTML report or a `.json` export holding a `NaN` literal, is listed as not checked. Scopehaven cannot read it either.
- One refusal goes further than Scopehaven's: counts without a `not_applicable` key are refused (`counts-mismatch`), where the gate reads the missing key as 0.

`verdict-check.test.mjs` builds these exports:

- both demo builds of the synthetic fixture
- five storefront conversation runs: clean, three drilled defects and one unproven login
- sequence runs from the real runner with five scripted observer kinds: clean, violations, a conflicting corroboration, coverage gaps and an early stop, plus a saved run and a `/1` record

It checks the checker against `evaluateCheck`, `validateConversationRun`, `validateSequenceRun`, `validateSequenceNativeRun` and the gate's `validateRun`, both on those exports and on several thousand seeded mutations of them, and on forged packs that only one reading of a number, a run shape or a whole row would let through. It also signs packs with attest, including a forgery the key holder resealed, which the signature accepts and the checker refuses. The rest of the file covers each tamper reason, the listing rules, a checker that trusts every stored label, the standard-library-only rule, the pinned constants against `src/`, and the commands `demo.mjs` prints.
