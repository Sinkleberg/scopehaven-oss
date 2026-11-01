<!-- Keep the PR in draft while you iterate; CI runs the whole suite when you mark it ready. -->

## What changes

<!-- One paragraph: what the change does and why. Link the issue if there is one. -->

## The failing case

<!-- Which test fails without this change, or which new test covers the new behaviour? Name the file. -->

## Limits

<!-- Does this widen or narrow what a result can show? If yes, which line of README.md or docs/KNOWN-LIMITS.md changes? -->

## Checklist

- [ ] `./scopehaven test` passes locally (or the named shard does, with the reason the rest was not run)
- [ ] Tests and fixtures bind `127.0.0.1` only; `docs/DATA-HANDLING.md` regenerated if a network site changed
- [ ] No new dependency
- [ ] Every commit is signed off (`git commit -s`, Developer Certificate of Origin)
- [ ] Wording follows `test/claims-wording.test.mjs`: counts carry their limits, nothing says "fixed" outside the owned fixture
