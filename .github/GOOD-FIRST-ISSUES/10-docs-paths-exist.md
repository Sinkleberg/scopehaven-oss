# Docs: every repository path in the documentation must exist, with a test that keeps it so

Several documents name files that are not in this repository. `docs/FRAMEWORK-MODE.md` and `integrations/frameworks/README.md` point at `setup/langgraph-cs.sh` and `setup/mastra-billing.sh`; `integrations/evid-bounds/README.md` names `src/evidence-bounds.mjs` (not in this repository) where the module is `integrations/evid-bounds/bounds.mjs`; `integrations/init/README.md` names `integrations/session-import/init-hook.mjs` (not in this repository), while the two hooks that exist are `integrations/policy-import/init-hook.mjs` and `integrations/model-standin/init-hook.mjs`. A reader who follows one of these hits a dead end and cannot tell whether the file was renamed, withheld or never written.

Fix each reference (rename it, remove it, or say in plain words that the file is not part of this repository and why), then add a test that walks every `.md` file outside `.github/`, extracts backticked tokens that start with a top-level folder of this repository (`docs/`, `src/`, `test/`, `integrations/`, `examples/`, `public/`, `packaging/`, `design/`) and asserts each exists, resolved from the repository root and, failing that, from the document's own folder (the init README writes `integrations/init/test/fixtures/hooks/` as test/fixtures/hooks/, relative to itself). Two documented exceptions: paths under `data/`, which are written at run time (`data/http-lab.targets.json`, `data/local-access.html` and the like), and a path followed by `(new)` or `(not in this repository)`. The test prints every miss with its file, so the next dangling path is a one-line fix.

## Pointers

- `docs/FRAMEWORK-MODE.md`, `integrations/frameworks/README.md`: the `setup/` scripts.
- `integrations/evid-bounds/README.md`: the module name.
- `integrations/init/README.md` and `integrations/init/hooks.mjs`: the hook modules init actually loads.
- `test/good-first-issues.test.mjs`: applies the same check to these issue drafts; reuse its extractor and markers.

## Acceptance

The new test passes on `main` and fails when a documentation file names a repository path that does not exist.

## Test

`test/docs-paths.test.mjs` (new).

## Labels

`good first issue`, `docs-wording`

## Effort

2 to 3 hours.
