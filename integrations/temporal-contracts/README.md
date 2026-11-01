# Owned refund lifecycle contract

This local synthetic milestone evaluates one registered workflow over real loopback HTTP using the existing connector transport and canonical regression gate. No model, customer service or real payment provider is exercised.

The fixture issues eight immutable refund authorities before execution. The operator records provider sequence bounds and monotonic times around every invoke, release and revoke. Provider effects belong to those windows. Application headers are checked against the window and cannot choose a different instruction. The operator revoke log orders the cutoff, and operator observed successful responses with matching provider effects decide completion time.

Acceptance timing cannot be independently observed. Authority rows are application ledger controls carrying `CONTROL_CUSTODY_LIMIT`, even when they pass. They can detect inconsistent reported order but do not establish that acceptance actually preceded revocation. A clean gate means the independently observed window checks and these limited controls passed. It does not prove acceptance time authority.

Run with the pinned Node24.21.0 through the existing launcher:

```sh
./scopehaven gate --target refund-clean --out /absolute/private/gate-output --refund-trust-out /absolute/operator-owned/trusted-refund-public.pem
```

The output parent and public-key parent must already exist. The key output file is created exclusively outside the result directory. The private signing key stays in the evaluator process, unavailable to the HTTP fixture. The signed JSON is written exclusively at `signed-results/<run-id>.json`, reloaded, externally key-verified, and then consumed by the canonical gate. It also saves a minimized summary and ordinary core run. The ordinary store checksum or raw export does not grant refund trust.

Verify the signed result in a fresh process using the operator-pinned public key and exact expected run ID:

```sh
./scopehaven gate --target refund-clean --saved-refund /absolute/private/gate-output/signed-results/RUN-ID.json --refund-public-key /absolute/operator-owned/trusted-refund-public.pem --refund-key-fingerprint OPERATOR_ENROLLED_SPKI_DER_SHA256 --expected-run RUN-ID
```

The operator enrolls the Ed25519 SPKI DER SHA256 fingerprint when the trusted signer creates the key and keeps that policy outside the result tree. Do not derive the expected fingerprint from an untrusted key delivered with saved results. Keys inside the result tree, including resolved path aliases, are refused.

The registry supplies the current trusted contract/build/evaluator/check set; the artifact does not supply those expectations. Ed25519 authenticates the evaluator's finalized adjudication. Unknown, stale, missing or unfinished evidence blocks. Historical HTTP baselines remain unchanged; this new evaluator family requires a fresh run. Baseline comparison for refund results is explicitly unsupported until both independently authenticated records and comparison semantics are supplied. Raw stored or copied payment bundles remain inconclusive.

Qualification variants are registered as `refund-deny-all`, `refund-no-op`, `refund-never-completing`, `refund-duplicate-effect`, `refund-shared-effect`, `refund-false-success`, `refund-accept-after-revoke` and `refund-changed-binding-dispatch`. They use the same schedule, contract, evaluator and gate; the checker never reads a variant label from observations. A correct qualification result blocks these defective targets. No-op/deny-all cannot satisfy the separate completion controls.

Operator timing gives a monotonic start, closure and observed response bounds. Five seconds is the completion deadline. An app clock cannot shorten it. Provider collection and app closure still bound the declared interval; future effects are outside this claim. Missing operator windows never support a boundary pass. The custody module is called for every row.

The payment window records an observer dispatched witness explicitly. It closes recorder delivery only. The collector separately validates closure from the operator supplied live fixture before and after delivery, including its identity, horizon, pending work and stable records. That validation stays in private collector custody and is bound to the original payment window and expected contract. Without it, every would be pass reads inconclusive, including identity controls. Observed failures remain failures. A copied record or a caller supplied closure flag cannot establish this validation. The fixture capability is trusted synthetic configuration; this does not authenticate an arbitrary application or isolate another process running as the same user.

Application ledger inconsistencies may make unrelated rows inconclusive. Independently observed count mismatches, malformed dispatch bindings and sends in refusal windows remain failures. A fabricated ledger dispatch without a provider effect fails the corresponding effect count. All inconclusive rows block the gate.

Threat boundary: an owned HTTP application has no evaluator filesystem or key interface. This is a declared workflow boundary, not same-user OS isolation. Malicious host processes, stolen evaluator keys and a compromised trusted evaluator are outside this claim. No production readiness, real settlement, external conformance or global cessation claim follows.

The assessment CLI routes registered refund targets through this same gate. Use `--out` for a dedicated gate directory, rather than the ordinary dashboard data directory. Dashboard/API run storage retains the standard record but does not restore signed producer trust; refund release acceptance uses the signed CLI route above. Dashboard integration and authenticated refund-baseline comparison are outside this milestone.
