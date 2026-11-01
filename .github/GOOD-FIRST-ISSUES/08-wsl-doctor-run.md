# Run `doctor`, the demo assessment and one test file under WSL, and write down what happens

The README says Node 22 or 24 is all you need; `docs/KNOWN-LIMITS.md` and `docs/DEPENDENCIES.md` say Windows is not verified. The launcher is POSIX `sh`, the store checks Unix owner ids and `0700` and `0600` modes (`src/store.mjs`), and the tests bind `127.0.0.1` only. None of that has been tried on Windows Subsystem for Linux, which is where most Windows developers would run it, so a Windows user cannot tell whether to expect a clean run or a wall of permission errors.

On WSL 2 (Ubuntu) with the official Linux Node 24 build selected through `SCOPEHAVEN_NODE`, run `./scopehaven doctor`, `./scopehaven assess --target demo-vulnerable --out <absolute dir>` (expected: exit 1, 26 of 44 checks failing on the synthetic app), `./scopehaven assess --target demo-repaired --out <absolute dir>` (expected: exit 0) and `./scopehaven test test/runner.test.mjs`, once with the repository on the Linux filesystem and once under `/mnt/c`, where the `0700` check will probably refuse the drvfs mount; record the exact message. Write the result into the Windows line of `docs/KNOWN-LIMITS.md` and the runtime section of `docs/DEPENDENCIES.md`: WSL version, distribution, Node version, what passed, what failed with its message, and that native Windows (PowerShell, cmd) stays unverified. If a launcher change is needed to get through `doctor`, keep it POSIX `sh` and add its case to `test/install-launcher.test.mjs`.

## Pointers

- `docs/KNOWN-LIMITS.md`: the "Windows is not verified" line under "Scope of the product".
- `docs/DEPENDENCIES.md`: the "Runtime" section and its last sentence about Windows.
- `scopehaven`: the launcher (`#!/bin/sh`, Node selection order).
- `src/store.mjs`: `process.getuid()` and the mode checks that decide "Storage directories must be real, owner-controlled directories with mode 0700."
- `test/install-launcher.test.mjs`: the launcher's tests, if a change is needed.
- `README.md`: the sentence about what you need.

## Acceptance

Both documents say exactly what was run on WSL 2, with versions and outcomes, and the README's sentence about what you need is still true as written or has been corrected.

## Test

`test/install-launcher.test.mjs`, only if the launcher changes; otherwise nothing to add, the acceptance is the documented run.

## Labels

`good first issue`, `documentation`

## Effort

2 to 3 hours on a Windows machine.
