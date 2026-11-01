# Sample evidence pack (signed and countersigned)

`pack/` is an unmodified evidence pack of ScopeHaven's owned synthetic fixture: the repaired build (`demo-repaired`) compared with its failing baseline (`demo-vulnerable`). It was made on 2026-10-30 with ScopeHaven 0.7.0 (a private build; not in this repository's history), so it includes the verdict checker (`verify_verdicts.py`) that every pack now carries. It is evidence about that synthetic fixture only, not about any other application.

| Signature | Key id | Made by |
| --- | --- | --- |
| Operator (`evidence-pack.dsse.json` and each `NAME.dsse.json`) | `6e8a609bc0c2b1a1ff0a85608120eaf73a9d1a4d6711355bcb22ed851f9d846b` | A throwaway key made for this sample. Its private half was deleted. |
| ScopeHaven countersignature (`evidence-pack.countersign.dsse.json`) | `fa62f453b740196129814c40e80cfab1e63b455306b44bf01ac309e47133e169` | The interim ScopeHaven key in the published key set ([docs/SIGNING-KEYS.md](../../docs/SIGNING-KEYS.md)) |
| RFC 3161 timestamp (`evidence-pack.countersign.tsr`) | freetsa.org, `genTime` 2026-10-30T22:19:23Z | freetsa.org, over the SHA-256 of the countersignature |

Verify it from this folder with your own checkout at CHECKOUT, and the key set from https://scopehaven.dev/.well-known/scopehaven-keys.json (or `CHECKOUT/integrations/attest/scopehaven-keys.json`):

    cd pack
    python3 -I CHECKOUT/integrations/attest/verify_envelope.py \
      --key scopehaven-signing-key.pub.pem --envelope evidence-pack.dsse.json --dir . \
      --scopehaven-keys CHECKOUT/integrations/attest/scopehaven-keys.json \
      --countersignature evidence-pack.countersign.dsse.json --timestamp evidence-pack.countersign.tsr

Both verifiers print `"verdict": "verified"` with a `countersignature` block. `integrations/attest/countersign.test.mjs` runs this check on every test run, offline, since the token is in the folder.

The pack's own `VERIFY.md` was printed by that private build, whose checkout kept the app under a `scopehaven/` folder, so its `CHECKOUT/scopehaven/integrations/...` commands need that segment dropped here: in this repository the app is at the root, as the commands in this file are written. The pack is left exactly as signed.

## Re-deriving the verdicts

The checker re-derives the verdicts of `run.json` from the observations the run kept, under rules written out in the checker. From `pack/`:

    python3 -I verify_verdicts.py --key scopehaven-signing-key.pub.pem --envelope run.json.dsse.json run.json --text

This prints `rederived` and exits 0: 44 of 44 verdicts re-derived. The `--dir` command in `pack/VERIFY.md` re-derives the same 44 of 44, with 0 left out. It reads `rederived-in-part` and exits 4 because it also lists every other file in the folder as not checked.

What this shows, and what it does not:

- This is the owned synthetic fixture at suite 2.3.0, a run kind and suite whose rules the checker carries. It does not show the same result on an HTTP contract run, whose JSON predicates depend on how the run recorded them. This pack holds no HTTP run ([integrations/verdict-check/SCOPE.md](../../integrations/verdict-check/SCOPE.md) gives the limits for each run kind).
- A re-derived verdict follows from what the run recorded. It does not show that the recorded observations are true: the fixture writes its own evidence.

## The files

`pack/VERIFY.md` is the file `evidence-pack` wrote. It covers the operator signature only, because the countersignature was added after the pack was made. The two countersignature files sit beside the folder envelope and are not among the files it names.

How it was made: the two runs were made with `runAssessment` (`src/runner.mjs`) and saved to a new temporary store (`src/store.mjs`), then:

    ./scopehaven evidence-pack --data STORE --run REPAIRED_RUN --baseline BASELINE_RUN --out ABS/pack --signing-key-dir ABS/keys
    node integrations/attest/cli.mjs countersign --envelope ABS/pack/evidence-pack.dsse.json \
      --key ABS/interim-countersign-key.pem --licence-id sample
