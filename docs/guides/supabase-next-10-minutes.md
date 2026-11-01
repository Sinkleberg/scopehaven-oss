# Supabase + Next.js: a first decided row in ten minutes

For an app whose users sign in with Supabase Auth, whose data is Postgres behind row-level security, and whose agent runs in
Next.js server code. This page assumes the app already runs on your machine: `supabase start` is up and `npm run dev` answers,
on a local copy with synthetic data. It takes you to the first row ScopeHaven decides about what the app's records show: a
**FAIL**, or an **INCONCLUSIVE** row that names the check that fired. Every command touches loopback only; a hosted project is
never probed or observed.

Two paths, both under ten minutes for someone whose app already runs:

| Path | Steps | Budget |
| --- | --- | --- |
| **A. The stack command** drafts and runs a starter profile from two signed-in users | 1, 2, 3, then 6 | about 5 minutes |
| **B. The templates** in [`examples/supabase-next/`](../../examples/supabase-next/) add the three prohibitions a Supabase app needs first: a cross-tenant read, a member's admin-only write, an ended session acting | 1, 2, 4, 5, then 6 | about 9 minutes |

**How the minutes were measured.** The ScopeHaven commands below were timed on 2026-11-01 against the product's own synthetic
two-tenant fixture app in its PostgREST mode (no Postgres, no Supabase stack): the stack command 0.9 s through the starter run
(90 requests), the policy import 0.2 s on the example migration, `seal` 0.2 s, `check-config` 0.3 s, `roe check` 0.2 s. The
Supabase-side minutes (signing users in, the SQL role, copying ids) are estimates and remain **unmeasured** against a running
Supabase stack. To measure your own onboarding, start the product's clock before step 1:

```sh
./scopehaven init start --out /absolute/private/supabase-next/init --label supabase-first-try --owned yes --operator-role "engineer on the app team"
```

[`docs/QUICKSTART.md`](../QUICKSTART.md) explains the two clocks and the receipt (`init receipt`).

## 1. Check both stacks (0.5 min)

```sh
supabase status          # API URL http://127.0.0.1:54321, DB port 54322, Studio 54323, and the anon key
./scopehaven doctor      # Node in range, loopback free; installs nothing
```

If your copy uses other ports, carry them through every command below. Open one page of the app once, so a development server
has compiled its routes before anything is timed.

## 2. Two test users, their tokens and their records (2 min, unmeasured)

Sign two test users up in the app, in two different tenants (two workspaces, two organizations): user A and user B. Never a
real person's login. Then take each one's access token from the local auth server and keep it in a private file whose names
start with `SCOPEHAVEN_TARGET_`:

```sh
umask 077; mkdir -p /absolute/private/supabase-next
curl -s -X POST 'http://127.0.0.1:54321/auth/v1/token?grant_type=password' \
  -H "apikey: $ANON_KEY" -H 'Content-Type: application/json' \
  -d '{"email":"a@tenant-a.example","password":"<the test password>"}' > /absolute/private/supabase-next/a.json
# the same for B into b.json; then:
cat > /absolute/private/supabase-next/ids.env <<'ENV'
SCOPEHAVEN_TARGET_SUPABASE_NEXT_A=<the access_token in a.json>
SCOPEHAVEN_TARGET_SUPABASE_NEXT_B=<the access_token in b.json>
ENV
rm /absolute/private/supabase-next/a.json /absolute/private/supabase-next/b.json
```

Note each user's `id` (the `user.id` in the sign-in answer) and one row each owns, as the PostgREST path the agent's data goes
through: `/rest/v1/<table>?id=eq.<row id>`. The file must be mode 0600; `init` refuses one other users can read, and never
prints or writes the values.

## 3. Path A: the stack command (1 min; 0.9 s measured on the fixture)

```sh
node integrations/init/stack.mjs --stack supabase --yes --id supabase-next \
  --base-url http://127.0.0.1:54321 --env /absolute/private/supabase-next/ids.env \
  --record-a '/rest/v1/notes?id=eq.<A row id>' --record-b '/rest/v1/notes?id=eq.<B row id>' \
  --client "My company" --contact "Your Name, Role" --confirm-authorization \
  --out /absolute/private/supabase-next/init
```

This is `./scopehaven init --stack supabase` with the Supabase connector (`integrations/connectors/catalog/supabase.json`),
run from the `scopehaven` folder. `--confirm-authorization` is your statement that you may test this local copy; the record it
seals is checked before every request. In order it: seals the authorization record (`authorization.json`, with
`rules-of-engagement.md`), finds the who-am-I route (`/auth/v1/user`) and checks each record opens for its owner (GET only),
writes the starter profile (`targets.json`: two identity controls, two allowed-use controls, the two cross-tenant reads, a
signed-out read, and the same cross-tenant read again requiring backend evidence), runs `check-config`, the `roe check` and the
starter assessment, and prints the first decided row. Against PostgREST a hidden row answers `200 []`, so each prohibition is
judged by its body: any row in the answer fails it.

On the fixture the starter run ended with 0 FAIL and 1 INCONCLUSIVE, and the first decided row read:

```
First decided row: INCONCLUSIVE  B-READS-A-RECORD-BACKEND  (high)  The foreign record is not read inside the app (needs an observer)
  fired check: Trusted backend observation available: expected Independent backend evidence required; got Backend evidence unavailable
```

That is a first result, not a finding: the backend row needs an observer. **Optional, +2 min (unmeasured):** create the
connector's WAL role on the local copy (the SQL is under `observers[].setup` in the connector file: a `LOGIN REPLICATION` role,
no table grants), put `SCOPEHAVEN_TARGET_SUPABASE_NEXT_DB_WAL=scopehaven_wal:<password>` alone in a 0600 `observers.env`, and
add `--observer-env /absolute/private/supabase-next/observers.env --app-dir /absolute/path/to/your-app`. The backend row is then
wired to the `pg-wal` observer ([`docs/PG-WAL.md`](../PG-WAL.md)) and `--app-dir` adds step 4's matrix beside the profile.
`stack-report.json` says what was wired and why.

## 4. Policy import from your row-level security (1 min; 0.2 s measured on the example migration)

Your migrations already say who may read and write each table. Turn them into a cited matrix, with no database connection:

```sh
./scopehaven policy import rls --app supabase-next --roles anon,authenticated --bypass-roles service_role \
  /absolute/path/to/your-app/supabase/migrations --out /absolute/private/supabase-next/matrix.json
```

The summary line counts cells by decision. On the example migration
`examples/supabase-next/supabase/migrations/0001_synthetic_tenancy.sql` it reads 12 allow, 6 conditional, 18 deny, 0 unknown,
0 gaps: the `conditional` cells are the policies that depend on `auth.uid()` and a membership row, which is what steps 5 and 6
test. An `unknown` cell is a statement the importer could not follow, never a guess; its reasons are in the matrix. Replaying
migrations is best effort; the authoritative input is a catalog dump of the test database (`integrations/policy-import/README.md`).
A matrix is a reading of declarations, not an observation of behaviour.

## 5. Path B: the templates (4 min, unmeasured, plus 0.7 s of measured commands)

The folder `examples/supabase-next/` holds `profile.json`, `authorization.json`, `.env.example`, the migration above and a
`README.md` whose table says exactly what to replace. The profile adds a third user C in tenant B whose session was ended, and
beside each prohibition the allowed-use control that shows the observer sees that kind of write.

1. **User C and the observer role (1 min).** Sign C up as a member of tenant B, take its token as in step 2, then end the
   session: `curl -s -X POST http://127.0.0.1:54321/auth/v1/logout -H "apikey: $ANON_KEY" -H "Authorization: Bearer <C's token>"`.
   In the Studio's SQL editor (`http://127.0.0.1:54323`), as the README shows, create `scopehaven_read`: a `LOGIN BYPASSRLS`
   role with `SELECT` on the two observed tables and nothing else.
2. **Fill in (2.5 min).** Copy the three template files to `/absolute/private/supabase-next/`, add C's token and
   `scopehaven_read:<password>` to your copy of `.env.example` (saved as `supabase-next.env`, mode 0600), and replace every
   `REPLACE` placeholder: the three user ids, the two emails, the three note ids, the two workspace ids, the authorization's
   window and signer. Keep `origin` and the observer's port for a default `supabase start`.
3. **Seal and check (0.5 min; 0.7 s of commands).** The sealer recomputes the checksum and never overwrites a file:

   ```sh
   node integrations/roe/cli.mjs seal /absolute/private/supabase-next/authorization.json /absolute/private/supabase-next/authorization.sealed.json
   set -a; . /absolute/private/supabase-next/supabase-next.env; set +a
   ./scopehaven check-config --config /absolute/private/supabase-next/profile.json
   node integrations/roe/cli.mjs check /absolute/private/supabase-next/authorization.sealed.json --config /absolute/private/supabase-next/profile.json --target supabase-next
   ```

   `check-config` lists the target with `"available": true`; a refused profile names the check, assertion and field, never a
   value. The `roe check` prints the stamp the run will carry.

Then run it:

```sh
./scopehaven assess --config /absolute/private/supabase-next/profile.json --target supabase-next \
  --authorization /absolute/private/supabase-next/authorization.sealed.json --out /absolute/private/supabase-next/evidence
```

The run sends the twelve checks once each, with identity probes around them (about 60 requests), and two of them write: the
admin renames tenant A's workspace and the member edits its own note, on the local copy. `supabase db reset` returns the copy
to its seed before a comparison.

## 6. Read the first FAIL or INCONCLUSIVE row (1 min)

The stack command prints the first decided row itself; after `assess`, the run file under `--out` has every row, and
`./scopehaven export --format html` renders it. Read the row's `fired check` line: it names the assertion that decided, what was
expected and what came back. The rows this guide produces, and what each means:

| Row | Reads | What it says |
| --- | --- | --- |
| `B-READS-A-RECORD-BACKEND` (path A, no observer) | INCONCLUSIVE, `Backend evidence unavailable` | No observer was wired, so nothing independent decided the backend half. Wire the WAL observer (step 3, optional) or add `pg-snapshot` as the templates do. |
| `B-READS-A-NOTE`, `A-READS-B-NOTE`, or path A's `B-READS-A-RECORD` | FAIL on `json.exists /0` | A row of the other tenant came back: row-level security did not hide it from this user. Read the policy on that table against the matrix from step 4. |
| `B-MEMBER-ADMIN-WRITE` | FAIL on `effect.none` | The workspace row changed under the member's `PATCH`: the policy that limits that write to admins did not hold. The `204` alone could not tell. |
| `B-MEMBER-ADMIN-WRITE` | INCONCLUSIVE, `subject-writable-custody` | No row changed, which is what the policy intends, but `pg-snapshot` reads the app's own tables, a record the app can write, so it cannot carry a pass. The `pg-wal` observer can (docs/PG-WAL.md). |
| `REVOKED-WHOAMI` | "prohibition observed, identity not established" | The auth server refused the ended session, as expected. An ended session has no identity control, so its refused rows read this distinct state, never pass. |
| `REVOKED-WRITES-OWN-NOTE` | FAIL on `status.in [401, 403]` (answered `204`) | The ended session's token still edited the row through PostgREST. Supabase access tokens are stateless JSON Web Tokens that PostgREST accepts until `exp` (`[auth] jwt_expiry` in `supabase/config.toml`, 3600 s by default), while the auth server checks the session. The row records that; whether your agent path should rely on PostgREST alone is your decision. To test your app's own route instead, see the README's "Your app instead of the gateway". |
| Any row | `not exercised` | The request did not complete (a timeout or a 5xx). Warm the development server up (step 1) and rerun; a timeout does not undo a write. |

A row that met its contract is not a clean bill of health: this profile tests a handful of actions on two tables. The next
checks to add are the ones your agent's tools actually perform, each with an allowed-use control beside it
([`docs/ONBOARDING.md`](../ONBOARDING.md), "Connecting a local application you own"). Then `./scopehaven gate` before and
after a change, in one gate directory, compares the two runs.

## Limits

- Local `supabase start` copies only, on loopback, under a sealed authorization record. The record's checksum is unkeyed: it
  shows an edit, it is not a signature.
- The local gateway accepts the user's token alone. A gateway that also requires the project's `apikey` header answers `401`
  on every row; the header is declared in the connector and not yet sent (`integrations/connectors/README.md`).
- Postgres does not log reads: no observer here shows that a row was never loaded. The cross-tenant reads are judged by what
  came back; the backend row says the record was not written during the read.
- The minutes for the Supabase-side steps are estimates. Only the ScopeHaven commands were timed, on the synthetic fixture,
  and a `next dev` server on a busy machine can take longer on first requests than the three-second request timeout.
