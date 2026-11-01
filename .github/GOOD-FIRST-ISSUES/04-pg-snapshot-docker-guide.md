# Guide: run the `pg-snapshot` observer and its live tests against a disposable Postgres in Docker

`pg-snapshot` reads an application's own Postgres tables through a built-in wire client, and the tests that need a real server (`integrations/observers/pg.live.test.mjs` and the other `*.live.test.mjs` files beside it) skip unless `SCOPEHAVEN_PG_LIVE` names a disposable database as `user:password@127.0.0.1:port/db`. The only `docker run` line in the documentation is in `docs/PG-WAL.md`, for the logical-decoding observer, and the observers README describes the profile shape but not how to get a server to point it at. A contributor who wants to touch the Postgres code has to read the test headers to work out which roles, version and settings the live tests expect.

Write a short guide, either as a section "Trying it against a local Postgres" in `integrations/observers/README.md` under the `pg-snapshot` heading or as `docs/POSTGRES-LOCAL.md` (new): one `docker run` for `postgres:17-alpine` published on `127.0.0.1` only, with `-c wal_level=logical` so the same server also serves the `pg-wal` tests; the roles the tests need (one that may create tables and roles for `pg.live.test.mjs`, a role with `REPLICATION` for `pg-wal.live.test.mjs`); the exact `SCOPEHAVEN_PG_LIVE` value; the single-file test command; a minimal profile observer block (`host`, `port`, `database`, `credentialEnv`, `tables`) for a `SELECT`-only role; and the clean-up. Say what it does not show: the live tests prove the observer against that server version only, and nothing about any application. Every address stays loopback.

## Pointers

- `integrations/observers/README.md`: the `pg-snapshot` section (what the observer reads at each mark, and its net-only limit).
- `integrations/observers/pg-snapshot.mjs`, `integrations/observers/pg-wire.mjs`: the observer and its client (SCRAM-SHA-256 only, PostgreSQL 13 or later).
- `integrations/observers/pg.live.test.mjs`: its header lists what the live tests cover and the form of `SCOPEHAVEN_PG_LIVE`; `integrations/observers/pg-wal.live.test.mjs` for the replication role.
- `docs/PG-WAL.md`: the existing `docker run` line to align with.
- `docs/ONBOARDING.md`: the `pg-snapshot` observer declaration the profile block must match.

## Acceptance

A contributor on macOS or Linux with Docker goes from nothing to a passing `pg.live.test.mjs` by following the guide alone, and the guide names the Postgres version it was tried on and the limit of what the run shows.

## Test

Extend `integrations/observers/pg.live.test.mjs` so its skip message names the guide (one line), and run it with the guide's `SCOPEHAVEN_PG_LIVE` to show it passes.

## Labels

`good first issue`, `observer`

## Effort

2 to 3 hours, plus a Docker pull.
