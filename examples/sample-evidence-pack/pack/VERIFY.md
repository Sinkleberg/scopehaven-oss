# Verifying this evidence pack

This folder holds the exports of one ScopeHaven run, made by ScopeHaven 0.7.0. Each export is signed into a DSSE envelope beside it (scopehaven-attest/1, Ed25519), and evidence-pack.dsse.json signs every other file in this folder at once.

- Run: `427361c7-b66b-4482-af2d-86e95d1c1c93`
- Baseline run: `d64b4056-b66c-457c-a7cd-975549fa54c0`
- Key id the signer wrote here: `6e8a609bc0c2b1a1ff0a85608120eaf73a9d1a4d6711355bcb22ed851f9d846b`

## Before you rely on it

1. Get the signer's key id from the signer over a separate channel, not from this folder. A key id is the SHA-256 of the public key's DER SubjectPublicKeyInfo (not of the .pem file), and both verifiers print it as `keyid`.
2. Run the commands below. Each must exit 0, print `"verdict": "verified"`, and print a `keyid` equal to the id you got from the signer. The id written above is only a convenience: anyone who can make a key can write any id here, put their own public key in scopehaven-signing-key.pub.pem and sign a folder that verifies.

## What a signature does and does not show

A valid signature shows that the key holder produced these exact bytes, not that the results are correct. The holder of this signing key produced these exact files. The signature does not show that the checks, the application or the results inside them are correct.

- It does not show that the application is safe, that every behaviour was checked, or that a fix holds beyond the runs named here. What each run checked, and its limits, is stated inside the files.
- The signed time is the signer's local clock; not a trusted timestamp.
- evidence-pack.dsse.json shows that no file it names was changed or removed; a file added to the folder later is not covered by it.

## Files

| File | What it is |
| --- | --- |
| `run.json` | The run record as the store returns it: the run core, its integrity hash (over the core only) and any notes, which that hash does not cover. Its envelope is `run.json.dsse.json`. |
| `run.html` | The HTML report. Its envelope is `run.html.dsse.json`. |
| `run.sarif` | SARIF 2.1.0, for code-scanning tools. Its envelope is `run.sarif.dsse.json`. |
| `summary.html` | A one-page summary. Its envelope is `summary.html.dsse.json`. |
| `residual.json` | Each row's claim type and what the run did not show. Its envelope is `residual.json.dsse.json`. |
| `comparison.json` | The before-and-after comparison with the baseline run, as the workbench computes it. Its envelope is `comparison.json.dsse.json`. |
| `comparison.html` | The comparison as an HTML report. Its envelope is `comparison.html.dsse.json`. |
| `scopehaven-signing-key.pub.pem` | The signer's public key. Verification needs only this key, never a private key. It came with the evidence: the key id check above is what ties it to the signer. |
| `verify_envelope.py` | A copy of ScopeHaven's verifier (integrations/attest/verify_envelope.py), standard-library Python 3.8 or newer, sha256 `177b16e08f3beda79121f7def4e9816ba22693aad6eb490853e77e252ff0c53f`. It came with the evidence: confirm that sha256 with the signer, or use your own copy (below), never this file's word alone. |
| `verify_verdicts.py` | A copy of ScopeHaven's verdict checker (integrations/verdict-check/verify_verdicts.py), standard-library Python 3.8 or newer, sha256 `27928b3e957883a61ff130b9f78a35185d021870b82fabaf7ac24fd282c41309`. The same caution applies: confirm that sha256 with the signer, or use your own copy. |
| `VERIFY.md` | This file. |
| `evidence-pack.dsse.json` | One envelope over every file above and their envelopes. |

## Commands

From this folder, with the verifier copy here:

    python3 -I verify_envelope.py --key scopehaven-signing-key.pub.pem --envelope evidence-pack.dsse.json --dir .
    python3 -I verify_envelope.py --key scopehaven-signing-key.pub.pem --envelope run.json.dsse.json --dir .
    python3 -I verify_envelope.py --key scopehaven-signing-key.pub.pem --envelope run.html.dsse.json --dir .
    python3 -I verify_envelope.py --key scopehaven-signing-key.pub.pem --envelope run.sarif.dsse.json --dir .
    python3 -I verify_envelope.py --key scopehaven-signing-key.pub.pem --envelope summary.html.dsse.json --dir .
    python3 -I verify_envelope.py --key scopehaven-signing-key.pub.pem --envelope residual.json.dsse.json --dir .
    python3 -I verify_envelope.py --key scopehaven-signing-key.pub.pem --envelope comparison.json.dsse.json --dir .
    python3 -I verify_envelope.py --key scopehaven-signing-key.pub.pem --envelope comparison.html.dsse.json --dir .

With your own ScopeHaven checkout at CHECKOUT, from this folder, for each envelope above. Use these unless you confirmed the copy's sha256 with the signer (`shasum -a 256 verify_envelope.py` prints it): a copy that came with the evidence could have been changed by the sender or on the way.

    python3 -I "CHECKOUT/scopehaven/integrations/attest/verify_envelope.py" --key scopehaven-signing-key.pub.pem --envelope evidence-pack.dsse.json --dir .
    node "CHECKOUT/scopehaven/integrations/attest/cli.mjs" verify --key scopehaven-signing-key.pub.pem --envelope evidence-pack.dsse.json --dir .

Each prints a JSON result and exits 0 when verified, 1 when rejected, 2 on a usage or file error, and 3 when the verifier's own self-check failed (then do not rely on it). `-I` keeps Python from importing anything from this folder.

## Re-deriving the verdicts

A signature shows the files are unchanged since signing; it does not show the verdicts follow from what the run observed. `verify_verdicts.py` checks that: it runs `verify_envelope.py` first and reads only the bytes that signature covers, recomputes each verdict it can from what the run kept under rules written out in the file, refuses the pack when a stored verdict disagrees, and lists every verdict it could not recompute, by id, with its reason. A failed JSON predicate it recomputes is printed with the field compared, the expected value and the actual one, as far as the record keeps them. Standard-library Python 3.8 or newer.

    python3 -I verify_verdicts.py --key scopehaven-signing-key.pub.pem --envelope evidence-pack.dsse.json --dir . --text

With your own ScopeHaven checkout at CHECKOUT, from this folder (the checkout's copy runs the checkout's own `integrations/attest/verify_envelope.py`):

    python3 -I "CHECKOUT/scopehaven/integrations/verdict-check/verify_verdicts.py" --key scopehaven-signing-key.pub.pem --envelope evidence-pack.dsse.json --dir . --text

It exits 0 when every verdict was re-derived, 4 when the files are consistent but some verdicts are listed rather than re-derived (each listed with its reason), 1 when a stored verdict or record disagrees (rejected), 2 on a usage or file error, and 3 when its own negative controls failed (then do not rely on it).

What it re-derives for each run kind, and why the rest cannot be, is in integrations/verdict-check/SCOPE.md of a ScopeHaven checkout.

A re-derived verdict follows from what the run recorded. It does not show the recorded observations are true or that the application is safe; the signature is what ties them to the signer.
