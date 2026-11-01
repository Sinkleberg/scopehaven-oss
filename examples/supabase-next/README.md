# Supabase + Next.js example: a ready-to-fill profile

Templates for a Next.js app whose users sign in with Supabase Auth and whose data is Postgres behind row-level security,
run as a local `supabase start` copy. Fill in the placeholders, seal the authorization record, and
`./scopehaven assess` decides rows about what the app's own records show, not what its replies say. The step-by-step
path with a time budget is [docs/guides/supabase-next-10-minutes.md](../../docs/guides/supabase-next-10-minutes.md).

Everything here points at loopback: the Supabase API gateway on `http://127.0.0.1:54321` and its Postgres on
`127.0.0.1:54322`, the ports `supabase start` uses by default. A hosted project is never probed or observed.

## Files

| File | What it is |
| --- | --- |
| `profile.json` | the target: two test users in two tenants, a third user whose session was ended, a signed-out actor, six allowed-use controls and five prohibitions, and a `pg-snapshot` observer on the local Postgres |
| `authorization.json` | the authorization record the connector requires before it sends anything, sealed over placeholder values; re-seal it after you edit it |
| `.env.example` | the `SCOPEHAVEN_TARGET_*` names the profile reads; copy it to a private 0600 file and fill in the values |
| `supabase/migrations/0001_synthetic_tenancy.sql` | the synthetic schema the profile assumes (workspaces, memberships, notes, with row-level security policies), for `./scopehaven policy import rls` and as the shape to map your own tables onto |
| `README.md` | this file |

## What the profile tests

The actors: `a` (an admin of tenant A's workspace), `b` (a member of tenant B's workspace), `revoked` (a member of
tenant B whose session was ended with `POST /auth/v1/logout` after its access token was copied) and `anonymous` (no
session at all).

| Check | Actor | What it asks | Decided by |
| --- | --- | --- | --- |
| `A-WHOAMI`, `B-WHOAMI` | a, b | `GET /auth/v1/user` names the user (identity controls) | the response |
| `A-OWN-NOTE`, `B-OWN-NOTE` | a, b | each user opens its own note (allowed-use controls) | the response |
| `A-OWN-WORKSPACE-UPDATE` | a | the admin renames its own workspace: the observer is shown to see workspace updates | the response and the `workspaces` rows |
| `B-OWN-NOTE-UPDATE` | b | the member edits its own note: the observer is shown to see note updates | the response and the `notes` rows |
| `B-READS-A-NOTE`, `A-READS-B-NOTE` | b, a | a cross-tenant read answers `200` with no rows (PostgREST's refusal under row-level security); any row in the answer fails it | the response body |
| `ANON-READS-A-NOTE` | anonymous | a request with no session is refused | the status |
| `B-MEMBER-ADMIN-WRITE` | b | a member's `PATCH` of its workspace, an admin-only write: PostgREST answers `204` whether or not a row changed, so the `workspaces` rows decide | the rows |
| `REVOKED-WHOAMI` | revoked | the ended session is refused at the auth server | the status |
| `REVOKED-WRITES-OWN-NOTE` | revoked | the ended session's `PATCH` of its own note: the status and the `notes` rows decide | the status and the rows |

**How the rows read with `pg-snapshot`.** The observer reads the app's own tables before and after each check, so it
decides allowed-use controls (a write that happened) and FAILs (a write the check forbids). It is a record the
application can write, so a boundary row whose only evidence is "no row changed" reads INCONCLUSIVE with
`subject-writable-custody`, never pass. That is the designed outcome of `B-MEMBER-ADMIN-WRITE` and
`REVOKED-WRITES-OWN-NOTE` when row-level security holds. To decide those rows as passes, add the connector's `pg-wal`
observer, whose record the application cannot edit: `./scopehaven init --stack supabase --observer-env observers.env`
wires it, and [docs/PG-WAL.md](../../docs/PG-WAL.md) describes it.

**The `revoked` actor** has no identity control, because an ended session has no identity to establish. Its rows read
FAIL when the token still acted, or "prohibition observed, identity not established" when it was refused; they never
read pass. Supabase access tokens are JSON Web Tokens that PostgREST accepts until their `exp`, whatever happened to the
session, while the auth server checks the session itself. So on a stock local stack `REVOKED-WHOAMI` is refused and
`REVOKED-WRITES-OWN-NOTE` reads FAIL until the token expires (`[auth] jwt_expiry` in your `supabase/config.toml`, 3600
seconds by default). That row records what your stack does with an ended session's token; whether your app's agent path
should rely on PostgREST alone is your decision. To test your app's own route instead, point the check at it (see
"Your app instead of the gateway" below).

## What to replace

Search each file for `REPLACE` and put in your own values. Identifiers (user and row ids) are 1 to 80 letters, digits,
`_` or `-`; Supabase's UUIDs fit.

| Placeholder | Where | Replace with |
| --- | --- | --- |
| `REPLACE_USER_A_ID`, `REPLACE_USER_B_ID`, `REPLACE_USER_C_ID` | `profile.json` (`principalId`), `authorization.json` (`identities`) | each test user's `id` from `auth.users` (the `id` in the sign-in response) |
| `a@tenant-a.example`, `b@tenant-b.example` | `profile.json` (`identityValue` and the `A-WHOAMI`, `B-WHOAMI` predicates) | the email each test user signed up with; the two must differ |
| `REPLACE_NOTE_A_ID`, `REPLACE_NOTE_B_ID`, `REPLACE_NOTE_C_ID` | `profile.json` (paths and `/0/id` predicates, `B-OWN-NOTE-UPDATE`'s effect resource) | the `id` of one note each user wrote in its own workspace |
| `REPLACE_WORKSPACE_A_ID`, `REPLACE_WORKSPACE_B_ID` | `profile.json` (paths, `A-OWN-WORKSPACE-UPDATE`'s effect resource) | the `id` of tenant A's and tenant B's workspace |
| `notes`, `workspaces` | `profile.json` (paths, observer `tables`, effect `name`s) | your own table names, if your schema differs from the migration; keep `key` as each table's primary key column |
| `buildLabel` | `profile.json` | which build of your app this copy runs |
| `validFrom`, `validUntil`, `signedAt` | `authorization.json` | your window, in UTC, at most 366 days; `signedAt` before `validUntil` and not in the future |
| `signer`, `rulesOfEngagement.title`, `id` | `authorization.json` | the person who authorizes the test, their role, whose app it is, and the title of your rules-of-engagement note |
| the four values | your copy of `.env.example` | the tokens and the observer role's `user:password` (never into the repository) |

Leave `origin` and the observer's `host`, `port` and `database` as they are for a default `supabase start`. If your
copy uses other ports (`supabase status` shows them), change them in `profile.json` and in `authorization.json`'s
`origins`: the record must list the gateway origin and `tcp://127.0.0.1:<db port>`.

## Steps

1. **Seed the synthetic data** on the local copy: two workspaces, a user A with an `admin` membership of workspace A, users
   B and C with `member` memberships of workspace B, and one note by each user in its workspace. Use your app's own
   sign-up and screens, or the Studio at `http://127.0.0.1:54323`. Synthetic data only, never a copy of production.
2. **Get the three access tokens.** The anon key is in `supabase status`. For each user:

   ```sh
   umask 077
   curl -s -X POST 'http://127.0.0.1:54321/auth/v1/token?grant_type=password' \
     -H "apikey: $ANON_KEY" -H 'Content-Type: application/json' \
     -d '{"email":"a@tenant-a.example","password":"<the test password>"}' > /absolute/private/supabase-next/a.json
   ```

   `access_token` is the credential and `user.id` the principal id. Do the same for B and C, then end C's session:
   `curl -s -X POST http://127.0.0.1:54321/auth/v1/logout -H "apikey: $ANON_KEY" -H "Authorization: Bearer <C's access_token>"`.
   Copy the three tokens into your private copy of `.env.example`, then delete the JSON files.
3. **Create the observer's read-only role**, once, in the SQL editor of the Studio or with `psql` as `postgres`:

   ```sql
   create role scopehaven_read login bypassrls password '<a generated test password>';
   grant usage on schema public to scopehaven_read;
   grant select on public.notes, public.workspaces to scopehaven_read;
   ```

   Put `scopehaven_read:<that password>` into `SCOPEHAVEN_TARGET_SUPABASE_NEXT_DB_READ`. `bypassrls` lets it read every row
   of the two tables it may select from; it can read nothing else and write nothing.
4. **Fill in and seal.** Copy `profile.json` and `authorization.json` to the private folder, replace the placeholders,
   then seal the record into a new file (the sealer recomputes the checksum and never overwrites):

   ```sh
   node integrations/roe/cli.mjs seal /absolute/private/supabase-next/authorization.json /absolute/private/supabase-next/authorization.sealed.json
   ```

5. **Check, then run**, from the `scopehaven` folder, with the env file loaded:

   ```sh
   set -a; . /absolute/private/supabase-next/supabase-next.env; set +a
   ./scopehaven check-config --config /absolute/private/supabase-next/profile.json
   node integrations/roe/cli.mjs check /absolute/private/supabase-next/authorization.sealed.json --config /absolute/private/supabase-next/profile.json --target supabase-next
   ./scopehaven assess --config /absolute/private/supabase-next/profile.json --target supabase-next --authorization /absolute/private/supabase-next/authorization.sealed.json --out /absolute/private/supabase-next/evidence
   ```

   The two write controls change a title and a workspace name on the local copy at every run; `supabase db reset`
   returns the copy to its seed.

## Your app instead of the gateway

To test your Next.js routes rather than PostgREST, set `origin` to the app (for example `http://127.0.0.1:3000`), the
who-am-I path to your route (`/api/me` or similar, with the pointer that names the user), the record paths to your
routes, and the expected refusals to what your routes answer: an app route usually refuses with `401`, `403` or `404`
rather than `200 []`, so replace the `json.exists /0 false` predicates with `status.in`. Add the app's origin to
`authorization.json`. Warm up a development server first (one request per path as a test user), as
[docs/ONBOARDING.md](../../docs/ONBOARDING.md) explains. The `REVOKED-*` checks then ask your route, which can check
the session with the auth server, and `401` is the usual expectation.

## Limits

- Local `supabase start` copies only, on loopback, under a sealed authorization record.
- `pg-snapshot` decides FAILs and allowed-use controls; a boundary pass needs the `pg-wal` observer (above). Postgres does
  not log reads, so no observer here shows that a row was never loaded; the cross-tenant read is judged by its answer.
- The local gateway accepts the user's token alone. A gateway that also requires the project's `apikey` header answers
  `401` on every row; that header is declared in the Supabase connector and not yet sent (`integrations/connectors/README.md`).
- The signed-out request's refusal (`ANON-READS-A-NOTE`) and the auth server's refusal of an ended session
  (`REVOKED-WHOAMI`) are expected as `401` or `403`; if your copy answers otherwise, the row says so and you adjust the
  expectation. The expectations here were checked for shape with the product's own validators, not against a running
  Supabase stack (the test is `test/example-supabase-next.test.mjs`).
- `assess` refuses a target with one credentialed identity; this profile has three.
