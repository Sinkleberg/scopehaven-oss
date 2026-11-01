# pg_net on the wire (`pgNetWire`, collector `pg-net-wire/1`)

Supabase projects ship pg_net, whose request queue (`net.http_request_queue`) is unlogged: the write-ahead log never carries it. While it exists, every pg-wal window reads `table-not-in-wal`, and an absence on that window cannot pass. The queue may be counted as observed only once its requests are observed on the wire. Reading the migrations, the catalog or the queue says what could be sent, never what was. This option observes what was sent. Module: `pg-net-wire.mjs`. Tests: `pg-net-wire.test.mjs`, `pg-net-wire.live.test.mjs`. Mutation sweep: `mutations-pg-net-wire.mjs`.

```json
{ "id": "wal", "type": "pg-wal", "host": "127.0.0.1", "port": 54322, "database": "postgres", "credentialEnv": "SCOPEHAVEN_TARGET_APP_WAL",
  "platform": "supabase", "tables": [{ "table": "message_threads", "key": "id" }],
  "pgNetWire": { "container": "supabase_db_myapp", "credentialEnv": "SCOPEHAVEN_TARGET_APP_PGNET", "image": "python@sha256:<64 hex>", "programRoles": ["supabase_admin"],
    "requestRoles": ["anon", "authenticated", "authenticator", "service_role"] } }
```

`container` is the database container's name (`docker ps`). `credentialEnv` holds `user:password` for a role that may call `net.http_get`. It is never the REPLICATION role's or an actor's credential. `programRoles` (1 to 16 role names) declares the login roles that can run a program inside the database's container, each held by you and none by the application. `requestRoles` (1 to 16 role names) names the roles the application's own requests run as; on a Supabase stack these are the API gateway's login role and the roles its tokens select, which `init --stack` fills in. See Custody below. Without both, a window never covers the queue. `image` (required) names the tap's image by digest only, `name@sha256:<64 hex>`, with Python 3; a tag is refused. It must already be on this machine: `start` checks it with `docker image inspect` and refuses when it is absent, and the tap runs with `docker run --pull never`, so ScopeHaven never downloads an image (load one yourself, for example `docker pull python:3.12-slim`, then `docker image inspect --format '{{index .RepoDigests 0}}' python:3.12-slim` prints the value to use). Other optional settings: `witnessWaitMs` (1000 to 60000, default 10000) and `quietMs` (100 to 10000, default 1500). A profile declares `pgNetWire` on a pg-wal observer: `src/contracts.mjs` validates it, and the connector (`src/http-connector.mjs`, `startObservers`) builds the wire and gives it to the pg-wal observer before it starts (`attachWire`). The observer factory (`factory.mjs`) and the Supabase ignore list are left unchanged, because both are among the files whose digests identify the egress, SMTP, provider-feed and Postgres collectors in saved suites.

## How it observes

- **A tap in the database's own network.** At start, a sidecar container joins the database container's network namespace (`docker run --network container:<db>`). It drops every capability except `NET_RAW`, and runs with a read-only root, no new privileges, 64 MB of memory and 8 processes. It runs a Python standard-library script on one `AF_PACKET` socket bound to no interface, so it receives every frame the namespace sends on `eth0` and `lo`. The namespace has no other interface, so nothing inside it can route around the tap.
- **What it reports**, one line per frame:
  - every connection the namespace opens (a SYN without ACK);
  - each payload segment on such a connection, at most once per 250 ms per connection. This catches a request on a connection that was opened earlier or reused. The segment is classified as an HTTP request (method, target, Host), a TLS hello (server name) or opaque;
  - every UDP datagram, with the question name of a DNS query. Docker's resolver at `127.0.0.11` counts, since a lookup can carry data out;
  - ICMP, ARP and any other IP protocol.
- **What it does not report.** A server's answers to connections it accepted, and replies from Docker's resolver, are skipped. Traffic on `lo` to a loopback address other than the resolver never leaves the container (health checks, pg_cron's own session), so it is counted, not reported.
- **A witness per mark.** After the tap has read everything sent up to the mark, the observer queues `net.http_get('http://<host gateway>:<fresh port>/scopehaven-pg-net-witness')` through pg_net itself. The tap reads the witness from its SYN, by address and port, so nothing needs to listen there. pg_net 0.20.4 takes its queue `ORDER BY id LIMIT n` (read from the worker library's own query), so every request queued before the mark goes out in the witness's batch or an earlier one.
- **A window** holds what the tap reported after the start witness, up to the end of the quiet period after the end witness. Requests in one batch go out concurrently, so a request that reaches the wire just after the end witness is still this window's.

## Custody

The tap's frames are copied by the kernel into the sidecar, which the application cannot write, so what the tap reports is held by the observer. A window's two ends, though, are witnesses that pg_net sends from the application's own database. A window may count the queue as observed only if the application cannot move them.

**Through pg_net alone it cannot.** pg_net sends its queue in id order, so a request queued before the end mark goes out in the witness's batch or an earlier one, and is seen. A request the application deletes from the queue never leaves. A row it locks keeps the worker, and so the witness, waiting, which reads `pg-net-witness-missing`. A copy of the witness URL it queues has a later id than the witness.

**Anything else that can put a frame on the wire from the database's namespace could.** It could connect to the witness's port, close the window early, and send its own request after the quiet period. So every witness statement first reads, in one statement before the witness is queued:

- the login roles that hold, can borrow or can give themselves a way to put a frame on the wire outside pg_net. Each power is read over everything a login role can act as, by any number of steps of two kinds: `SET ROLE` (membership, INHERIT or not, so a NOINHERIT login role counts for what it can switch to), and calling a `SECURITY DEFINER` function, which runs as its owner (no extension owns it, initdb did not create it). A gateway that may call a function owned by a role with no power of its own, which may in turn call one owned by a role with a power, reaches that power. The powers are:
  - a superuser or a member of `pg_execute_server_program`;
  - CREATEROLE on PostgreSQL 15 and earlier (it can grant itself `pg_execute_server_program` between two marks);
  - CREATE in the database while a trusted extension outside `NO_BACKEND_NETWORK` is available or, on PostgreSQL 16 and later, with `pg_create_subscription` (a subscription connects out at once);
  - membership in supautils' privileged role while its extension list names one outside `NO_BACKEND_NETWORK`;
- entries no declaration can name:
  - `(PUBLIC)` when PUBLIC may execute such a lending function (the default on a new function);
  - `(supautils unconfirmed)` when either supautils setting is not defined in the witness's own session (so it is not loaded server-wide) while some role or database carries its own preload or `supautils.*` settings (`pg_db_role_setting`). On an owned Supabase copy (Postgres 17.6) the witness read supautils' settings and the same program roles as a superuser, and could read `pg_db_role_setting`; the unconfirmed case cannot be produced there because supautils is configured server-wide, so it is pinned by the unit test;
  - `(subscription)` while any subscription exists, since its worker connects out on its own.
- the installed extensions;
- functions in an untrusted language (C included) that no extension owns and initdb did not create. initdb's own are told apart only by what no role can do later: an OID below 16384 (FirstNormalObjectId) and the `pg_catalog` namespace. Never by a name, a schema the application could create, or an owner the application could be;
- the number of such lending functions, as a reading.

The observer also reads, through the docker CLI at the tap's start and at the end probe, the other containers whose network is the database container's, and whether the database container itself joined another container's.

A window is `observer-held` only when all of these hold:
- `programRoles` is declared;
- at both marks every such role is declared;
- every extension is in `NO_BACKEND_NETWORK` (no backend or background-worker network code; `pg_net` itself is the path the witnesses bound);
- no such untrusted-language function exists;
- no other container shares the namespace.

Otherwise it is `subject-writable` and covers nothing, though its record still lists what was sent. The record keeps:
- counts: `programRoles: { declared, read, undeclared }`, `backendNetwork: { extensions, untrustedFunctions, definerFunctions }` and `sharedNamespace`. The definer-function count is a reading; who may call one is in `programRoles`;
- the names of extensions outside the list;
- your declaration, word for word (`declaration`), which holds the only role names in the record. It names no role it read.

The CREATEROLE reading applies only before PostgreSQL 16; it is pinned by the unit test and not exercised live (the owned copy runs 17.6). pg-wal counts the queue as observed only through a window that is both complete and observer-held. With a subject-writable wire an absence reads inconclusive (`table-not-in-wal`) as it does without the wire, and a write the WAL shows still decides.

A second connection to a witness's port (a second source port; a retransmitted SYN keeps its port) makes the window partial (`pg-net-witness-repeated`).

**Who may be declared, and what the run refuses.** `programRoles` must name only roles you, the operator, actually control, never one the application can act as or through. The run checks this against `requestRoles` at every mark. It reads everything a request role can act as, by the same closure: `SET ROLE` (membership, NOINHERIT included) and `SECURITY DEFINER` calls, any number of steps. A declared program role among them is refused and named in the record (`declaration.refused`), and the window is subject-writable. So is a window whose request roles are not declared, or name a role that does not exist (`declaration.checked: false`). Copying every role the custody query lists into `programRoles` is therefore refused wherever the application reaches one of them.

**Every verdict carries its declaration.** The record (`declaration: { programRoles, requestRoles, refused, checked }`, the declared names word for word) goes beside the custody verdict, and the pg-wal window carries it into the run and the report. A reader sees whose word a window rests on.

**When a window reads subject-writable,** its record carries a fixed remedy text. Roles the application reaches must hold no superuser, `pg_execute_server_program`, database CREATE, extension or subscription power: move such functions to an owner without those powers.

**What to expect on stock Supabase.** On a Supabase app whose RPC functions are owned by `postgres` and callable by `service_role`, the wire usually reads subject-writable, and the backend row stays inconclusive. The gateway reaches `postgres` through those functions, and `postgres` may create a networked extension. On the owned copy of such an app, the honest declaration (every role read, less the ones the application reaches) read subject-writable in each wire run made so far (2 of 2, before request roles were declared). The pull request records the full rerun. Re-owning the functions, to show the path to observer-held, is a separate follow-up, since it changes what the functions can do.

**The declaration is yours, not something a run shows.** On a local Supabase stack every role's default password is public, and the application may be able to reach the database port. Declare a role only once its password is one the application does not hold, for example after rotating it on your owned copy.

### Ways a window could miss a request, and what each reads

| Way | Reads |
| --- | --- |
| Another egress extension or path from a backend: `dblink`, `postgres_fdw`, `http`, `wrappers`, an untrusted language | Its frames are seen if sent in the window. Its presence alone makes every window subject-writable (the extension list or the untrusted-function count). |
| `pg_cron` (a job row names the host it connects to) | subject-writable while installed. A job it runs in the window is seen. A job scheduled in the window writes `cron.job`, which is WAL-logged and not on the Supabase list, so the absence cannot pass. |
| A background worker or a job that fires after the window, on a change pg-wal decodes | The change itself is in the WAL, so the absence fails or cannot pass. |
| The same, on a channel pg-wal does not decode (a sequence, LISTEN/NOTIFY, a large object) | A documented limit (pg-wal's own, `docs/PG-WAL.md`). |
| A request made and cleaned up between marks | Through pg_net: sent, so seen (partial); or deleted before it was sent, so nothing left. Through another path present at a mark, or one a counted role could add between marks: subject-writable, above. |
| A role given superuser or `pg_execute_server_program`, or an extension added, between marks and taken away before the second | The readings are taken at the marks only, so the roles reading also counts every role that could do this to itself: CREATEROLE on PostgreSQL 15 and earlier, a role that may create a trusted extension outside `NO_BACKEND_NETWORK`, and a member of supautils' privileged role while its list names one outside it. Undeclared, each keeps the window subject-writable. A grant by a declared role, or a path this list does not name, is a documented limit. |
| A declaration that is wrong or stale | A role not declared is read and refused at each mark. A declared role whose password the application holds is a documented limit. |
| A `SECURITY DEFINER` function that lends a program-capable role's power to the application, directly or through other such functions | Every login role that can reach a power through `SET ROLE` and definer calls, any number of steps, is read as a program role, so an undeclared one makes the window subject-writable. A function an extension owns is the platform's, a documented limit. So is a trigger or event-trigger function, whose EXECUTE is checked when the trigger is created rather than when it fires. |
| A tap that drops frames under load | The kernel's drop count (`pg-net-tap-drops`, partial). An overlong line (`pg-net-tap-unreadable`, partial). A tap that dies (`pg-net-tap-down`, failed). |
| A second container in the database's namespace | Its frames are seen. Its presence at the tap's start or at the end probe makes the window subject-writable. One that joins and leaves between those reads is a documented limit. |
| A container on the same Docker network with its own namespace (PostgREST, Kong, Realtime, Storage) | Outside the tap: a request the database makes to it is seen (a frame on `eth0`). What it sends on its own is outside this observation (egress recorders cover HTTP sends). |
| The witness forged by queuing its URL through pg_net | A later id, so it is sent after everything queued before the mark. A second source port at one of the window's witness ports reads `pg-net-witness-repeated` (partial). |
| A request sent to an earlier mark's witness port (learned from the queue) | A window counts only its own marks' witnesses; a frame to an earlier mark's port is a send (`pg-net-sent`, partial). |
| A segment just before a mark hiding one on the same connection just after it (the tap reports at most one segment per connection per 250 ms) | Each mark and the end probe restart that throttle. |
| A background worker a library loads at server start (`shared_preload_libraries`), with no extension row | Changing that setting takes a superuser and a restart, so a declared role. A documented limit. |
| The database container itself in another container's namespace, or on the host's network | Read at the tap's start: subject-writable. |
| A process the operator starts in the namespace (`docker exec`, a host-side tool), or a container sharing the database's PID namespace (`--pid container:<db>`), which could enter its network namespace | The operator's, not the application's: a documented limit. Frames sent in a window are seen. |
| A subscription (logical replication), existing or created between marks | An existing one is an undeclarable `(subscription)` entry. A role that could create one (CREATE in the database with `pg_create_subscription`, PostgreSQL 16+) is a program role. |
| Writing server files (`pg_write_server_files`), `LOAD` from `$libdir/plugins`, `ALTER EXTENSION UPDATE` of an allowlisted extension, supautils' allowed-configs list granting a preload setting, `GRANT SET ON PARAMETER` on a preload or supautils setting, another extension whitelist or a managed service's admin roles, supautils settings under other names | Documented limits. Each needs a superuser to set up or a platform-specific mechanism these readings do not name. |

## What a window says

| Coverage | When | Reason |
| --- | --- | --- |
| complete | both witnesses were seen, the tap dropped nothing, and nothing else was sent | none; `covers` names the queue table when the window is also observer-held (Custody) |
| partial | anything else was sent: a connection, a DNS query, a datagram, an unknown IP protocol | `pg-net-sent` |
| partial | a witness did not arrive within `witnessWaitMs` | `pg-net-witness-missing` |
| partial | the kernel dropped frames before the tap read them | `pg-net-tap-drops` |
| partial | a line the tap wrote could not be read | `pg-net-tap-unreadable` |
| partial | the marks and the end probe were not all answered by the one tap that started before the window (each start draws its own epoch) | `pg-net-tap-gap` |
| partial | the namespace's interface list, read with every answer, differs from the list at the tap's start | `pg-net-interfaces-changed` |
| partial | a witness's port saw connections from two source ports (Custody) | `pg-net-witness-repeated` |
| failed | a mark was taken before the tap started | `pg-net-tap-not-started` |
| failed | a mark could not be taken or its witness could not be queued | `pg-net-mark-failed` |
| failed | the tap was not running at a mark, or stopped since | `pg-net-tap-down` |
| failed | the window's records are no longer held | `pg-net-records-evicted` |

pg-wal treats only a complete, observer-held wire window as covering the queue. Any other wire window leaves the queue counted, so the pg-wal window still reads `table-not-in-wal`. The wire window's sealed record sits in `others.wire` either way. A pg-wal observer without `pgNetWire` returns exactly what it did before.

The record lists the namespace's interfaces (`tap.interfaces`: at the tap's start, at the start mark and at the end probe), so "every interface" can be checked against the namespace. It keeps counts, the interface, the destination port and an address class (`host-gateway`, `resolver`, `loopback`, `private` or `public`). Each address, Host, request target and DNS name is kept only as a digest salted per observer, never as a value the app sent.

## Limits

- It sees the database's network namespace only. A request another service makes on pg_net's behalf is not in it.
- A request pg_net sends after the quiet period lands in the next window, which its start witness bounds.
- A request that never produced a frame (a URL curl refused before connecting) is not seen. Such a request carried nothing out.
- An observed send makes the window partial. It is not attributed to a check: the evidence vocabulary has no pg_net source.
- Checked on Docker Desktop for macOS, with the docker CLI at `/usr/local/bin/docker`, on owned Supabase copies only. The real tap was also run against a throwaway container on this Mac. It saw a SYN from another process in the shared namespace, DNS on both interfaces and ICMP, and counted an in-container connection. The sidecar was removed afterwards.
