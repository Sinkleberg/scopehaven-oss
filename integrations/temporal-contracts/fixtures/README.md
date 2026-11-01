# Owned synthetic refund application

`startRefundFixture({runId,targetId,payments,variant,identityContext})` starts one Node HTTP app on
`127.0.0.1` using a started local payment double. It implements the v1 interface,
including its measured timing and fresh-context refinements.
It does not use real payment providers, models, customer records or databases.

The returned `actors.revoked` and `actors.control` have separate bearer credentials
and tenants. GET `/identity` returns the authenticated identity. The operator's
local `authorize(binding)` hook registers a unique instruction and independent
authority before POST `/refund`; actor HTTP requests cannot mint that authority.
The binding contains instruction/authority IDs, principal, tenant, operation,
charge, positive integer amount, lowercase currency and destination. A returned
instruction and all source snapshots are deeply frozen.

An optional trusted operator `identityContext` supplies `revoked`/`control`
`{principalId,tenantId}` mappings without credentials. The fixture validates and
copies that mapping; operator mutation after startup cannot change actors.
Defaults are `principal-${runId}-${role}` / `tenant-${runId}-${role}`. Credentials
are always generated fresh. Charges are taken from independent instruction
bindings; the application does not hardcode charge names. The operator seeds the
provider and authorities with the independently derived per-run charge.
`refundBuildHash(variant)` independently computes exactly the source/behavior
identity used by the app, without generated credentials, actor context or run ID.

POST `/refund` accepts `instructionId`, optional binding overrides, caller `key`,
`hold` and `loseResponse`. Every clean invocation checks the authenticated identity
and original binding. The app records acceptance and revocation in one monotonically
ordered event stream, with no await between its authorization check and acceptance.
Unchanged accepted work can dispatch/retry after revocation; arrival alone cannot
reserve that authority. New work by a revoked principal refuses. GET
`/instructions/:id` exposes lifecycle status only to its bound principal/tenant.

`hold:'before-acceptance'` queues work without acceptance. `hold:'after-acceptance'`
queues accepted work. Both return 202, and `release(instructionId)` lets the app
make its own authorization/dispatch decision. No scheduler performs that check.
`loseResponse:true` discards the provider's successful response after commit and
keeps the instruction pending. Retry uses an instruction/run-scoped provider key
even if the caller changes or omits its retry key. Two independently authorized
identical instructions use different provider keys.

Each actual send records a unique attempt and the immutable dispatched binding,
then sends the v1 causal headers over loopback. Provider refusal remains an attempt,
and only a successful matching provider response supplies terminal success.
Transport uncertainty remains pending. A returned HTTP 200 with state `failure`
does not claim completion. Application terminal success is evidence to reconcile
with the provider ledger, never proof of an effect on its own.

`snapshot({horizonId,deadlineMs,close:false})` fixes the collector's measured source
start and requested deadline. Deadline must be a positive integer at most 5000ms;
neither horizon ID nor deadline can change on later calls. Every event has
monotonic `atMs` from the same fixture clock. Snapshot `timing` contains unique
`clockId`, fixed `startedAtMs` and measured `closedAtMs` (null until closure).
Events before a collector's opened start prevent complete coverage. Direct first
close uses the whole fixture lifetime beginning at its measured clock origin zero;
the integrated collector always opens before issuing independent authorities.

`snapshot({horizonId,deadlineMs,close:true})` synchronously closes registration
before awaiting bounded current provider operations, then fixes a measured close
and watermark. New authorize/refund/revocation work cannot enter during drain or
after closure. Previously registered delivery/jobs may settle; undrained work
leaves `horizon.closed` and `horizon.sealed` false. A fully drained, registration
closed source exposes both as true. It accounts for scheduled jobs, in-flight operations,
pending lifecycle states and unfinished authenticated HTTP bodies. Pending work
leaves the horizon incomplete. A conflicting invocation cannot erase a queued
legitimate instruction. Subsequent app events remain visible and make coverage
incomplete; closing again cannot erase that fact or change the horizon identity.
No scheduled/never-completing operation can hang snapshot capture. Operator
registration ends at first closure, but previously registered subsequent execution
stays observable. Rereads retain the exact first close time; they never expand the
claim interval. A successful terminal after start plus deadline remains measured
success in complete source evidence; the evaluator must fail completion for its
lateness. This app does not shorten deadlines or fabricate a timely failure.

Qualification variants `deny-all`, `no-op`, `never-completing`, `duplicate-effect`,
`shared-effect`, `false-success`, `accept-after-revoke` and
`changed-binding-dispatch` deliberately break one lifecycle property. Their labels
are confined to the operator's startup configuration. The app exposes an opaque
build hash covering source and behavior; HTTP/snapshot records contain no variant
label. The shared-effect fault targets only `identical-a`/`identical-b`, collapsing
their effects even with different caller keys while the unrelated control still
works. Tests inspect real HTTP behavior, source events and provider effects.

This fixture proves bounded synthetic behavior only. It has no OS isolation and
does not authenticate persisted adjudications. Evidence trust, complete provider
coverage, duplicate observation handling, contract evaluation, durable signatures,
fresh-process verification and the canonical regression gate are outside this
fixture. The earlier payment double does not yet collect the v1 causal headers.
