# Requirements for recurring checks

The implemented gate runs once. Its explicit target/configuration, optional same-store baseline, private immutable evidence, summary and `0/1/2` exits are the foundation for a later recurring job. The CI example is inert; no recurring job or notification transport is enabled.

| Later decision | Required behavior |
| --- | --- |
| Target and effect scope | Choose the owned test target, identities and isolated downstream dependencies. Approve the request mix and cadence, including POST effects. Loopback does not isolate the target's downstream services. Define state reset or synthetic test-data preparation without adding automatic retries. |
| Trigger and owner | Choose release-triggered CI, a local schedule, or both, with a responsible operator. Pin the reviewed runtime and gate/source/configuration identities. Provision credentials separately if needed; never put them in command arguments, output summaries or CI artifacts. |
| Baseline lifecycle | Pin a compatible run ID per target/context, retain it in the same private store as candidates, and establish explicit reviewed promotion. Do not silently replace a failed or incompatible baseline. A clean run with no baseline makes no repair claim. |
| Single writer and recovery | Enforce one writer per output store, including unrelated core-store writers. Decide how the operator detects crashes, confirms liveness and recovers stale locks. A timeout or exit `2` can follow a target effect or saved core run; inspect before a manual rerun. |
| Retention and integrity | Choose durable private storage across CI jobs, evidence retention and capacity handling. The core currently caps stored runs and bytes; preserve pinned baselines before choosing a fresh store. Gate-summary retention also needs a policy. Local SHA-256 detects altered evidence but is not an independent attestation. No automatic eviction, copying or artifact upload is implemented. |
| Results and notifications | Choose an authorized protected destination and transport. Preserve exit distinctions, counts, positive-control status, compatibility, evidence scope and `fixed` versus `contract-restored`. Treat incomplete/error outcomes as actionable. Define notification deduplication and recovery handling before enabling delivery. |
| Operational acceptance | Verify overlapping triggers, target failure, interrupted writes, capacity exhaustion, incompatible baselines and secret-free artifacts/notifications using isolated fixtures before recurring use. The one-shot acceptance alone does not prove unattended operation. |

These decisions belong to the later product phase. They do not block the current one-shot release gate, and this document does not configure a scheduler or authorize external sending.
