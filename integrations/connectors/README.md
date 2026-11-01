# Stack connectors (`scopehaven-connector/1`)

One declarative file per stack, read by `scopehaven init --stack NAME`, so a
customer on a supported stack gets that stack's identity rules, refusal forms, observers, policy importer, packs and reset
without an assessor writing them for each company. Internal; owned apps and synthetic data only.

```sh
./scopehaven init --stack supabase --id myapp --base-url http://127.0.0.1:54321 --env ids.env --observer-env observers.env \
  --record-a '/rest/v1/profiles?id=eq.<A id>' --record-b '/rest/v1/profiles?id=eq.<B id>' --app-dir ./my-app \
  --client "..." --contact "Name, Role" --confirm-authorization
```

`node integrations/init/stack.mjs --stack ...` runs the same command directly.

## Files

- `spec.mjs`: the schema, the strict loader (`loadConnector`, which also returns the sha256 of the bytes it validated;
  `readConnector`, `parseConnector`, `validateConnector`) and `matchRecord`.
- `catalog/supabase.json`, `catalog/stripe.json`, `catalog/chat-completions.json`: the shipped connectors. The last declares
  frameworks over a chat-completions base URL; the binder that runs class templates on such an app is not part of the open edition.
- `connectors.test.mjs`: every shipped file loads, and a negative control for each rule (below).
- `stack.test.mjs`: `init --stack` against init's owned two-tenant app in PostgREST mode. It covers:
  - the pure wiring rules;
  - the observer endpoint and the twin's write joining the record before it is sealed;
  - `--actions`, `--no-twin` and the flags an observer needs;
  - the pg_net use check in the spellings and live results it lists (including a pg_cron job table the role sees filtered);
  - no credential value on disk or in the output, with and without the starter run;
  - refusals before any request;
  - a leaky app deciding FAIL;
  - the starter run on the onboarding clock.
- `../init/stack.mjs`: the `--stack` command.
- `../payments-pack/assess-hook.mjs` and its test: the payments pack inside `assess` and the gate.

## The spec

| Field | What it holds |
| --- | --- |
| `schema`, `stack`, `title`, `kind`, `summary` | `kind` is `http`, `payments` or `model`; each kind carries only its own sections |
| `identity` (http) | the credential slot, gateway headers every request also needs (Supabase's `apikey`), who-am-I routes with the pointer that names the user, what a signed-out who-am-I answers |
| `refusals` (http) | `{ status, body, means }`. **A 2xx refusal must name its body form** (`empty-array`, `null`, `empty`): PostgREST answers a row that row-level security hides with `200 []` and a filtered UPDATE with `204`, so a boundary check judges the body or the row, never the status alone |
| `records` (http) | record path templates (`/rest/v1/{table}?{key}=eq.{id}`), so init names the observed table, key and id without asking |
| `observers` | `{ type, role, source, why, defaults, credentialEnvSuffix?, setup?, unloggedTables? }`. `role: "absence"` only for a source whose custody can support a pass (`src/custody.mjs`: pg-wal, the egress recorder, the SMTP sink, a provider feed); the app's own rows are `presence`. `defaults` may set only an observer type's connection fields and its settle, barrier and timeout values (`DEFAULT_KEYS`: host, port, database, platform `none` or `supabase`; the timings within the product's own bounds, `DEFAULT_BOUNDS`). The settle and barrier values do decide when a window counts as complete, so `init --stack` reports them under `assumptions`. A connector never sets what a window may leave out or the platform's own waits (`ignore`, `queues`, `runLease`, drain and poll timings, `actorCapture`). `unloggedTables` entries name the unlogged table (`net.http_request_queue`), its live check (`pg_net`), the strings that mark a use and the folders scanned; the loader pins each to its check's table, every string the check scans for and `supabase/migrations`. `init --stack` reports them and never ignores them |
| `backendRow` (http) | the observer and the clauses init may use for its backend row (below), and the row's title |
| `policyImporter` | the `integrations/policy-import` source kind and where the stack keeps its declarations |
| `rules` | stack identity rules the profile may carry (Supabase: the service roles that bypass row-level security) |
| `packs` | default packs (`integrations/packs-v2/packs/<name>`; `payments-pack` for a payments connector only) |
| `payments` / `model` | the provider double and the client's environment names / the model protocol, the base-URL variable names frameworks read, and class templates |
| `reset`, `limits` | the command that returns a disposable copy to its seed; what the connector does not do |

**What the loader refuses** (each with a negative control in `connectors.test.mjs`):
- **Format:** unknown keys and schemas, unbounded strings, non-plain objects, a non-string record template, a file not named for
  its stack.
- **Headers:** a reserved header (Host, Cookie, Authorization, proxy and `x-forwarded-` names).
- **Observers:** an observer type the connector does not build, a source that is not the observer's, a remote observer host, a
  defaults key outside the type's allowlist or out of bounds.
- **Catalog:** duplicates, an unshipped pack, shell syntax in `reset`.

It never reads an environment value: environment entries are names.

## What `init --stack` adds to init

1. **Before any request**, from the flags. `--id` is always a flag, since it names the folder init writes and `--stack` reads
   after it. With `--observer-env`, `--base-url`, `--env`, `--record-a` and `--record-b` are flags too, since the observer's
   credential name, endpoint and record are fixed before init seals the record:
   - **The connector's credential slot.**
   - **The backend record.** It must resolve to a table: a connector record template, or `--record-table`. Only then does the
     observer's `tcp://127.0.0.1:PORT` join the authorization hosts. An unresolvable record wires and authorizes no observer.
   - **The write twin** (below). It is named in the authorization's permitted actions: init's read-only default, plus "one
     allowed-use write: identity A's PATCH <path> of its own record". So the record init seals covers every request the run
     sends. An operator's own `--actions` together with a twin is refused; `--no-twin` keeps init's read-only actions and sends
     no write.
2. Init itself, with `--no-run` (init's own probes only). `init --stack` then wires the backend row itself, and that includes
   the guarded live pg_net check against the observer database (step 4), even when the operator gives `--no-run`: `--no-run`
   stops only step 7 (check-config, the roe check and the starter assessment).
3. **The backend row.** The connector's absence observer joins the profile (Supabase: `pg-wal` on the record's table, with the
   connector's defaults) and the backend check gets clauses chosen by the pairing rules (`src/http-pairing.mjs`):
   - `record-row-unchanged` (`effect.none` on the record's row) pins a resource, so it needs a twin showing the pin selects:
     on a PostgREST record init adds `A-WRITES-OWN-RECORD`, a `PATCH` of the key to its own value (204; Postgres logs the update,
     and the table's UPDATE triggers run, so a trigger such as an `updated_at` stamp still changes that column; the sealed actions
     say so), sent before every boundary check; on an app route the operator gives `--twin-write`. Init wires a
     twin only if it is exactly the write the sealed actions name.
   - `record-table-unchanged` (`effect.none` on the table) pins nothing: on a check that expects a refusal status it needs no
     twin. On one that expects `200 []` the allowed-use guard would hold it back, so it is used there only without a twin, and
     the row then reads inconclusive (the output says so).
   - Every clause names the table: an absence needs an exact name from the observer's vocabulary.
4. **pg_net's queue stays watched; the checks are the reason.** pg_net's request queue is unlogged, so every pg-wal window reads
   `table-not-in-wal` while it exists. `init --stack` never adds it to the observer's `ignore` (the observer's own ignore-list rule: an entry is listed only once its requests are observed on the wire, by an egress
   recorder under a confined run). An inference from files and catalogs is not that, and the app's own server code or an API
   exposing the `net` schema are seen by neither. So both checks run, and `stack-report.json` (`watched`) and the output say
   what they found as the reason windows read partial: `unused` ("pg_net installed but unused per the migrations and the
   catalog"), `used`, or `unknown`, with what each check read and when (`checkedAt`, on the guard's clock, and null when no live
   check ran or it did not read the catalog; `scanDigest`).
   - **The migrations:** no file under the entry's scan paths (`supabase/migrations`, `supabase/seed.sql`, read to depth 4)
     names pg_net, with case, double quotes and spacing ignored. `supabase/migrations` must itself have been read, and anything
     the scan left unread (a `.sql` file over 4 MiB, anything past the 2000th file, a folder deeper than four, a symbolic link or
     other entry that is neither a file nor a folder, a scan path whose real path leaves `--app-dir` through a linked folder above
     it, an unreadable entry) makes the finding `unknown`. A `.sql` extension is matched in any case.
   - **The live copy**, read under the sealed record with the observer's own role from the catalogs: pg_net installed, its
     queue unlogged, and no function, trigger or dependent object that calls pg_net or Supabase's webhook function. If pg_cron
     is installed, the observer role must be able to read every row of `cron.job` (it has row-level security, so the setup
     grants SELECT and BYPASSRLS; a filtered view reads `unknown`) and no job may call pg_net.
   - **Under the sealed record.** Before the live check connects, the record is checked again against the target, the
     observer's endpoint and the window, and the window again before each query. A record that no longer covers it stops
     the stack with exit 3 before the database is reached.
   - **Not seen by either check** (so `unused` is a reason, never a pass): a call whose function name is quoted on its own
     (`"http_post"(` under a `search_path` of `net`) in a function created outside the scanned files; a call built as a
     string; a function created outside the migrations inside the `net` or `supabase_functions` schema; the app's server code
     calling `net.http_post` over its own connection; an API exposing the `net` schema; and an app's own replacement body for
     `extensions.grant_pg_net_access` (excluded by name).
   - **What would close the window:** observing the queue's requests on the wire (an egress recorder under a confined run),
     which is a separate observer path, not built here.
   - **The platform ignore list** (`platform: supabase`, the observer's checked-in list) is applied because the stack declares
     the platform, not because anything observed it. `stack-report.json` names it and its sha256 (`platformIgnoreList`); it
     never covers an observed table.
   - **One table per check, pinned.** The loader allows the entry only for pg_net's own table, scanning `supabase/migrations`
     for every string the check names.
5. With `--app-dir`: the policy importer's matrix, unconfirmed (`policy-matrix.json`), and the stack's identity rules as a draft
   with placeholders (`stack-rules.draft.json`: the actor capture block and `supabaseRules`; the capture's install needs a
   superuser on the copy, so init does not wire it). The policy section of the report counts what the scan left unread
   (`skipped`), since the matrix may then be partial.
6. `stack-report.json` (`scopehaven-init-stack/1`): the connector's sha256, what was wired and from what, what was not and why,
   the watched tables and why (`watched`), what the wiring takes as given rather than observes (`assumptions`: the connector's
   settle and barrier timings, since a window counts as complete when the app commits within `settleMs` of answering; the
   functions the live pg_net check does not count, when it ran; for a template twin, that its key names one row, since a key
   that is not unique would PATCH every matching row identity A can see; and with `--record-table`, a key column taken as `id`
   and an id taken from the path's last segment), how each prohibition was judged against the stack's refusal forms, gateway
   headers (declared, not sent), packs, reset and limits. A `--twin-write` that is not sent (`--no-twin`, no observer wired,
   one identity) is said in the output and listed under `notWired`.
7. check-config, roe check and the starter assessment, with the identities' and the observer's credentials in the child's
   environment only. The starter run is stamped on the onboarding clock (`integrations/init/clocks.mjs`).

The observer's credential comes from its own 0600 file (`--observer-env`), never from the identities' file or the app's `.env`.

## Deciding runs (owned apps, local copies, 2026-10-26)

`init --stack supabase` at head 8428865e (the copy of 729eda8c before a later rebase onto main; connectors, init and the
payments pack are identical between them), one local Supabase project at a time under the heavy-job lock (taken
2026-10-27T00:00:45Z at a 1-minute load of 15.35, released 00:12:14Z). Each target is a fresh APFS clone (`cp -c -R`) of the
source below, with demo mode on, live SMS and voice off, and synthetic seed users. Everything binds 127.0.0.1, and each project
was stopped by its own workdir afterwards.

| Copy | Source | Ports (API / database / app) | Run id | Rows | Backend row |
|---|---|---|---|---|---|
| AestheticsAI practice | local practice copy | 56321 / 56322 / none | 2c78c05d | 9 pass | pass, `effect.none` on `profiles` pinned to A's row, custody observer-held |
| AestheticsAI real-app copy | local real-app copy | 57321 / 57322 / none | 48531382 | 9 pass | pass, same clause, observer-held |
| App-routes app, practice | local practice copy | 58321 / 58322 / 3310 | 4db249a9 | 7 pass, 1 control inconclusive | pass, `effect.none` on table `message_threads`, observer-held |
| App-routes app, real-app copy | local real-app copy | 59321 / 59322 / 3320 | 848bbf49 | 8 pass | pass, same clause, observer-held |

- **AestheticsAI (PostgREST record paths).** The record matches the connector's template, so init wires the
  `record-row-unchanged` clause and its write twin, `A-WRITES-OWN-RECORD` (A's own `profiles` row, the PATCH the sealed
  authorization names). The twin passes with subject-writable custody, as a positive control should. It shows the row pin
  selects, and it decides nothing on its own.
- **The app-routes app.** The record is an app route, so init takes the table from `--record-table message_threads` and
  wires the table clause, `record-table-unchanged`. It sends no twin and pins no row.
- **The control that read inconclusive.** In the app-routes app's practice run, `A-OWN-RECORD`'s response predicates passed, but the
  connector withheld it because an identity check did not complete (timeout, network error or run budget; likely the dev server compiling under load). The
  backend row was still decided. The same copy read 8 of 8 in its earlier run.
- **pg_net, and what these rows mean now.** On all four copies the live check found pg_net installed with nothing in the copy
  calling it, and no migration names the queue. Under the rule then, `net.http_request_queue` was ignored for the window, so no
  window read partial and the backend row was decided. **That rule is withdrawn** (see above): `init --stack`
  now leaves the queue watched, so on these copies the window reads partial and the backend row reads INCONCLUSIVE, with the
  finding ("pg_net installed but unused per the migrations and the catalog") as the reason. The decided rows above are what
  the observer reads once the queue is accounted for; deciding them under the current rule needs the queue observed on the
  wire.
- **Confirming rerun under the current rule.** 2026-10-27, head fd23153a, unsandboxed, heavy-job.lock taken 09:23:02Z at a
  1-minute load of 20.03 (TIME_WAIT 29). AestheticsAI practice copy,
  ports 56321/56322, stack stopped after. `stack-report.json` reports pg_net as installed but unused per the migrations and the
  catalog, and the queue stays watched. The backend row `B-READS-A-RECORD-BACKEND` is INCONCLUSIVE because the pg-wal window is
  partial (`table-not-in-wal`). This is the expected result until the wire observation lands.
- **The twin's effect, corrected after these runs.** Both AestheticsAI copies stamp `profiles.updated_at` in a `before update`
  trigger, so each twin PATCH also changed that column on identity A's own row in the scratch copy. The sealed actions of these
  two runs said the twin changed no value. The wording init seals now says the table's UPDATE triggers run (a later review
  of this PR); the runs were not repeated for the wording alone.
- **Earlier runs, not counted.**
  - Runs before the first review's fixes sent the twin PATCH while the sealed authorization still read "read-only GET requests;
    no writes". The actions now name the twin before anything is sent.
  - One early run used the default observer port 54322, which another session's Supabase project holds on this Mac. Its
    observer collect failed there. Pass `--observer-port` for a scratch project.
- **Changes to `init --stack` after these runs** (review fixes):
  - the twin's sealed wording (above);
  - pg_cron jobs counted only when the observer sees every row (none of the four copies installs pg_cron, so their result
    is unchanged);
  - `--id` required as a flag (every run here passed it);
  - the live check run under the sealed record (every run here was inside its window);
  - **the queue is never ignored on these checks**: this changes these runs' backend rows to INCONCLUSIVE
    (above);
  - the file half pinned per check, and a scan that left anything unread reading `unknown` (on these copies nothing was: no
    link, no file over 4 MiB, no folder deeper than four, 23 or 24 migrations plus the seed file);
  - the connector file's setup text (the BYPASSRLS grant), so the connector sha256 in `stack-report.json` differs from these
    runs' (setup text only, which decides nothing).
- Run records, authorizations and tokens stay in a local scratch folder outside this repository. This table holds ids and statuses only.

**Limit of the decided row:** it shows that the foreign record's row (or its table) was not written while the read ran,
from the write-ahead log the app cannot edit. Postgres does not log reads, so nothing here shows the row was never loaded.

## Stripe: the payments pack inside `assess` and the gate

`../payments-pack/assess-hook.mjs` runs the target's payments pack after its HTTP checks.
- **Checked first.** Before the HTTP run or the gate sends anything, the pack is read and validated. It must be the target's
  own (same id, applicationId and origin), and the record file the run is authorized under must cover it now (`authorizePack`:
  id, application, origin, every test customer's principal, the window).
- **Where it writes.** Its run goes to `<out>/payments/`, and it adds `payments` to the assess summary. A FAIL or undecided
  payments row makes the exit 1. In the proposed `src/cli.mjs` call site, a payments run that throws after the HTTP run was
  saved still prints the HTTP summary, with `payments: { error }`, and exits 2.
- **Under the gate:**
  - **Comparison.** The run is compared with `--payments-baseline` (`comparePaymentsRuns`: a verified repair only when the pack
    is the same, neither run was edited and every control holds).
  - **Where it writes.** The runs, and a `gate-<run id>.json` with this gate run's payments half, go beside the gate's folder
    (`<out>-payments`), since the gate's folder holds only its own entries. That folder follows the gate's own folder rules,
    checked before the gate sends anything: an existing, resolved parent, outside the project's data folder, a private (0700)
    folder of this user and not a link. Like the gate's folder it carries a marker written while it was empty, and holds only
    payments runs (`pay-<time>-<hex>`) and the gate's payments halves (`gate-<run id>.json`).
  - **Clock.** The payments half is authorized at the time it starts, after the gate, so a window that ends while the gate runs
    refuses the pack (exit 2, the gate's summary kept).
  - **Exits.** The exit is the worse of the two halves, and the outcome and reasons follow it (`payments-not-clean`,
    `payments-error`). A payments half that throws after the gate ran keeps the gate's summary, with `payments: { error }` and
    exit 2. The report-only exit follows the window's own rule: an assessment-failed exit is relaxed only while the window
    applies.
  - **Refusals.** `--payments-pack` with `--saved-refund` (which sends nothing) is refused.

Run on the storefront practice app, scratch copy, with the proposed diffs applied to a `git archive` export of the code after
this PR's first review fixes (f215484f before the later rebases). Changed since, by later reviews: the payments folder's rules
and marker, the clock read again after the gate, a payments half that throws keeping the gate's summary, the gate summary's
`outcome` and `reasons` following the combined exit, and in the proposed diffs, the error and refusal handling. The run was not
repeated for them. The hook's changes are tested in `assess-hook.test.mjs`; the proposed diffs' refusals were checked by hand on
a patched export and have no test here.
- **The copy.** A Stripe-shaped refund client was added to the copy (each refund the assistant issues is also
  `POST /v1/refunds` to the payments double, keyed on the refund reference), plus a `GET /scopehaven/witness` route. Nothing else
  changed; no drill is on.
- **assess.** `assess --payments-pack`: the HTTP half has 7 pass and 1 INCONCLUSIVE (the backend row; the storefront has no
  observer wired). The payments half has 5 pass: two controls moved money, three boundaries held (another customer's order, a
  repeated refund, an order outside the refund window).
- **Refused before any request.** A pack whose second customer the record does not cover: exit 2
  (`authorization-identity`), no HTTP run saved.
- **gate.** The gate twice in a fresh folder: the second run's payments comparison reads "still passing", the combined exit is the
  HTTP half's (1, for the unwired backend row), and each run's payments half is in `<out>-payments/gate-<run id>.json`.
- **Tests.** `assess-hook.test.mjs` covers the owned refund demo: the repaired build passes, the vulnerable build exits 1, a
  verified repair against the vulnerable baseline, refusals before anything is sent (shape, target, record), and the gate
  wrapper with a real pack (checked before the gate runs, the worse exit and its outcome, report-only applied and ended, the
  payments half written beside the gate, a payments half that throws, the payments folder's rules, `--saved-refund` refused).

## What still needs `src/`

| Stack | Connector state | Needs |
| --- | --- | --- |
| Supabase | spec, `init --stack` (with the init hook), observer-wired profile on four owned copies (backend row decided there under the withdrawn ignore rule; INCONCLUSIVE under the current one until pg_net's queue is observed on the wire); policy matrix and identity rules drafted | (0) a way to observe pg_net's queue on the wire, so the backend row can decide: the container-network tap (`pgNetWire`, with a `src/` proposal pending), which `init --stack` then wires with its own pg_net witness role; (1) the `apikey` gateway header (below); (2) column read-back: in the HTTP evaluator (`b1c4a90d`), not yet wired by `init --stack` (it needs a SELECT role for a `pg-snapshot` observer and the table's value columns, since read-back never reads the key); (3) actor capture stays an operator install |
| Stripe | spec, hook module and tests, run inside assess and the gate on a patched export | a diff to `src/cli.mjs` (12 added and 4 removed lines; `--payments-pack` is refused with `--confine`, `--list` and `--check-config`) and a diff to `integrations/regression-gate/cli.mjs` (6 added and 3 removed; a refusal before the gate keeps its code as the reason), neither shipped in the open edition. Neither file is in an evaluator pin, so no re-pin |
| Frameworks over a chat-completions base URL | spec and catalog file | the binder that runs two class templates on a framework app with no per-template adapter (not part of the open edition) |

**The `apikey` gateway header (design, not built).**
- **Shape:** a target-level `gatewayHeaders: [{ header, credentialEnv }]`, sent by every actor (the signed-out actor included)
  on every request. It never replaces the actor's own credential, and the run digests its value as it does `credentialHeaders`.
- **Re-pin:** it touches `src/contracts.mjs` and the HTTP connector's request builder, so it would be an announced re-pin.
- **Not needed here:** none of the four copies needed it, since the local CLI gateway accepts the user's token alone. Hosted
  gateways that require it are out of scope (local copies only).

The name guard reports one judged hit on these files, hash `7d3194f79e`: a public model provider's name inside the
base-URL environment-variable identifiers that frameworks read.

## Limits

- Local copies only, on loopback. A hosted Supabase project, a live Stripe account and a remote model are never touched.
- Two identities at most, and the record paths are given (init's v0 limits).
- The Stripe run used a payment client added to a scratch copy of the storefront. That shows the pack runs inside
  `assess`; it shows nothing about a storefront that ships its own client.
- `init --stack` for a payments or model connector says what to run instead and exits 2: those kinds have no HTTP profile of
  their own to wire.
- The gate's own summary file (`gate-summaries/`) is written before the pack runs, so it does not carry the payments half; the
  half is in `<out>-payments/gate-<run id>.json`.
