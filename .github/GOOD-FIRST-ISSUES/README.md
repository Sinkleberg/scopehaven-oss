# Good first issue drafts

One file per issue, opened on GitHub by the maintainer when the repository goes public. Each draft is the issue body:
its first line is the title (`# ...`), then two paragraphs (the problem as a user meets it, the shape of the fix),
then `## Pointers`, `## Acceptance`, `## Test`, `## Labels` and `## Effort`. `issues.json` lists the title, body file
and labels of each; `../labels.json` defines every label with a colour and a description.

Every repository path a draft names in backticks must exist, unless it is followed by `(new)` (a file the issue
adds) or `(not in this repository)` (a dead reference the issue removes). `test/good-first-issues.test.mjs` checks
that, the labels, and that both scripts only print unless `--apply` is given.

```sh
.github/create-labels.sh YusefSyed/scopehaven-oss                  # prints the gh label commands
.github/GOOD-FIRST-ISSUES/create-issues.sh YusefSyed/scopehaven-oss  # prints the gh issue commands
```

Add `--apply` to run them. Create the labels before the issues.
