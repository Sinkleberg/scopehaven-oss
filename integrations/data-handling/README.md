# Data handling: the sheet and the zero-egress check

| File | What it does |
|---|---|
| `render.mjs` | Renders `docs/DATA-HANDLING.md` from facts it reads out of the source (`--write`), or checks it (`--check`). |
| `data-handling.test.mjs` | Fails when the sheet is stale, when a network call site appears without review, when a shipped file is of a kind the scan does not know, when the store gains a method that could delete evidence, or when a fact can no longer be read. |
| `zero-egress.mjs` | Runs every available built-in target's assessment and the test suite with outbound network denied except loopback, and logs every attempt. |
| `net-log.mjs` | Loaded into Node processes by `zero-egress.mjs`; records each socket connect, DNS lookup and UDP send. Opens no connection itself. |

## Keeping the sheet current

```sh
node integrations/data-handling/render.mjs --write
```

When the source changes a fact the sheet states, the render fails and names it. When a shipped file starts reaching the network (the rules are in `render.mjs`), review what it reaches and add it to `SITES` in `render.mjs`.

## What the scan covers

- **Files.** Everything the release ships: `shippedFiles` reads `RELEASE-MANIFEST.json` in a release copy, and in a checkout lists the folder's files through git and applies `excluded` from `packaging/build-release.mjs`, so there is no second list to keep. Fixtures and vendored source ship, so they are scanned. A checkout's new uncommitted files count too. A folder with neither a manifest nor git fails rather than guessing.
- **Kinds.** JavaScript and TypeScript, HTML, CSS, Python, shell (the launcher by its `#!` line), the Action's YAML, SQL and Rego each have rules. Other kinds are declared as data in `DATA`, and a shipped file of an undeclared kind fails the render.
- **Limits.** It matches text and does not parse. A name built at run time, an aliased or injected `fetch`, or a call made inside a library the file does not name (a model client in a framework) is not found. Finer JavaScript, Python and shell lexers are drafted but not shipped. `docker run` counts only with `--network`, since every shipped call passes `--pull never`. `zero-egress.mjs` is the run-time check.

## The zero-egress check

```sh
node integrations/data-handling/zero-egress.mjs --out /absolute/new/directory [--skip-suite]
```

- **macOS:** each command runs under `sandbox-exec` with a profile that denies `network-outbound` except to localhost. `log stream` collects the kernel's denials from every process, Python included. The deny rule carries a tag unique to the run; denials without it come from other sandboxes on the machine and are counted separately (`otherSandboxDenials`), not as this run's attempts.
- **Linux:** each command runs under `unshare` in a new network namespace whose only interface is loopback. This path has not been run here.
- **Logging:** Node processes also load `net-log.mjs` through `NODE_OPTIONS`, which logs every attempt, loopback included.
- **Output:** `ZERO-EGRESS.json` in `--out`, with the commands, their exit codes and logs, the counts by kind, any non-loopback attempt, and kernel denials. Exit 0 means no non-loopback connection was attempted.

**Limits:**
- A denied connection to the system resolver socket is a name lookup whose name the kernel log does not show. It is reported separately (`resolverSocketDenials`).
- A Node process started with a cleared environment is still sandboxed, but it is logged only through kernel denials.
- Loopback connections from processes other than Node are not logged.
- A run covers the commands it lists, on that machine and build. It does not cover every code path, or the application under test, which can make its own outbound calls.
