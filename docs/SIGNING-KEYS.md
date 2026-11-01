# Signing keys and the ScopeHaven countersignature

An evidence pack can carry two signatures and a timestamp:

1. **The operator's signature** (`evidence-pack.dsse.json` and one `NAME.dsse.json` per export). It is made with a local Ed25519 key on the machine that ran ScopeHaven (`~/.config/scopehaven/signing`). It shows only that whoever holds that key produced these bytes. A pack signed on the application owner's machine is self-attested.
2. **ScopeHaven's countersignature** (`evidence-pack.countersign.dsse.json`). It is made with a ScopeHaven key whose id is published below, over hashes only: the SHA-256 of the operator's signed statement, the operator's key id and the SHA-256 of the operator's signature. ScopeHaven never receives a file, row or result.
3. **An RFC 3161 timestamp** (`evidence-pack.countersign.tsr`) from a public time-stamping authority, over the SHA-256 of the countersignature. The time comes from neither the operator nor ScopeHaven.

## Published keys

The key set is published at:

- **https://scopehaven.dev/.well-known/scopehaven-keys.json** (served by the scopehaven.dev website)
- `integrations/attest/scopehaven-keys.json` in this repository (byte for byte the same file; a test checks this)

| Key id | Status | In use from | Until |
| --- | --- | --- | --- |
| `fa62f453b740196129814c40e80cfab1e63b455306b44bf01ac309e47133e169` | interim | 2026-10-29 | (open) |

A key id is the SHA-256 of the public key's DER SubjectPublicKeyInfo, as the operator's key ids are. Both verifiers refuse a key set whose key id does not match its key.

| Time-stamping authority | URL | Pinned root certificate (SHA-256 of DER) |
| --- | --- | --- |
| freetsa.org | `https://freetsa.org/tsr` | `a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc` |

Take the key set from scopehaven.dev over HTTPS, or from a ScopeHaven checkout you trust. Never use a copy that came with the evidence. Someone who can replace the evidence can also replace a key set sent with it.

## Verifying

From a pack folder, with the key set saved as `scopehaven-keys.json` beside your own ScopeHaven checkout at CHECKOUT:

    curl -sSfo scopehaven-keys.json https://scopehaven.dev/.well-known/scopehaven-keys.json
    python3 -I CHECKOUT/integrations/attest/verify_envelope.py \
      --key scopehaven-signing-key.pub.pem --envelope evidence-pack.dsse.json --dir . \
      --scopehaven-keys scopehaven-keys.json \
      --countersignature evidence-pack.countersign.dsse.json --timestamp evidence-pack.countersign.tsr

`node CHECKOUT/integrations/attest/cli.mjs verify` takes the same arguments. Both verifiers first verify the operator's envelope as before, then the countersignature, which must:

- be signed by a key in the published set;
- name the SHA-256 of this envelope's statement, its signer's key id and the SHA-256 of its signature;
- carry a timestamp token that the pinned TSA root vouches for (the token's signing certificate must be marked for time stamping only, and must be valid at the stamped time). The token must stamp the SHA-256 of the countersignature;
- have been stamped while its key was in use and before any revocation.

The output's `countersignature` block names the ScopeHaven key id and its status, the operator key id it binds (`firstSignerKeyid`), the licence id, and the TSA's `genTime`. Exit codes are the same as before: 0 verified, 1 rejected (the reason is named), 2 usage or file error, and 3 when the verifier's own negative controls failed. With `--scopehaven-keys`, both countersignature flags are required. A missing countersignature file is rejected as `countersign-missing`.

The operator's key id no longer has to come over a separate channel when the countersignature verifies, because ScopeHaven's signature names it. What that adds is stated under Limits.

## Countersigning

ScopeHaven countersigns with:

    node integrations/attest/cli.mjs countersign --envelope ABSOLUTE/evidence-pack.dsse.json \
      --key ABSOLUTE/scopehaven-countersign-key.pem --licence-id LICENCE_ID

The client computes the request from the envelope and sends only this JSON (`scopehaven-countersign-request/1`): `request`, `licenceId`, `release`, `statementSha256`, `signerKeyid`, `signatureSha256` and a random `nonce`. The countersigning step refuses any other field. It signs an in-toto statement (`https://scopehaven.dev/attestation/countersignature/v1`) over those hashes, then asks the TSA to stamp the SHA-256 of that signature. The TSA learns that digest and nothing else. The command checks the result with the verifier before writing the two files beside the envelope, and it never overwrites a file. The TSA must be one the key set names.

## Rotation and revocation

These rules are also in the key set's `policy` field.

- **Rotation.** A new key is added to the set with its `notBefore` before it signs anything. The old key then gets a `notAfter` and the status `retired`. Countersignatures stamped before `notAfter` stay valid. Key ids are never reused.
- **Revocation.** A compromised key gets the status `revoked` and a `revokedAt` time. Verifiers reject every countersignature stamped at or after `revokedAt`, and keep those stamped before it. Because the stamp comes from the TSA, not the key holder, a stolen key cannot backdate a countersignature past a revocation. The published key set is the only revocation list.
- A TSA is removed from the set, or its pinned root replaced, if its key is compromised. Packs stamped by it then stop verifying.

## Limits

- **The interim key.** The current countersigning key is interim: made on 2026-10-29 for the sample pack, held on one machine outside the repository, protected by file permissions only (no passphrase or hardware key). It will be retired, under the rotation rule above, when a hardware-backed key replaces it.
- **No hosted endpoint and no licence check yet.** Countersigning is a local CLI that ScopeHaven runs with its key. The request format is the one a hosted endpoint will take. Today `licenceId` is a label the countersigner writes by hand, and nothing verifies it.
- **What it shows.** A countersignature shows that ScopeHaven's key signed these hashes, for the named licence, before the TSA's time. It does not show that ScopeHaven ran the checks, or that the checks, the application or the results are correct. A licensee can have the hash of any statement countersigned, including one built by hand.
- **Edits before signing.** The countersignature does not stop the operator's key holder from editing a run before packing it. It fixes when the pack existed, and that the operator's key signed it then.
- **The key set is not itself signed.** Trust rests on HTTPS to scopehaven.dev and on this repository.
- **TSA trust.** freetsa.org is a free service with no service agreement. Its root is pinned here. The verifiers check no CRL or OCSP status for the TSA's certificate, and they accept RSA (2048 bits and up) or ECDSA P-256/P-384 tokens whose signer is named by issuer and serial number.
- **The sample pack.** `examples/sample-evidence-pack/pack/` is a real pack of the owned synthetic fixture (a baseline and a repaired run), signed by a throwaway operator key and countersigned with the interim key and a freetsa.org timestamp. It is evidence about the synthetic fixture only.
