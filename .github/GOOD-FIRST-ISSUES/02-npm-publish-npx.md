# Add the tag-triggered workflow that publishes the built npm package

The package is ready for npm: `package.json` has its `bin`, `files` and metadata, a clean checkout packs the release's file list, and `test/npm-bin.test.mjs` runs `npx scopehaven doctor` from an offline install. What is left is the publish itself, and `packaging/RELEASE.md` describes that as steps a maintainer runs by hand. A tag should be able to do the last of them, so every release reaches npm from the same build, with provenance and no stored token.

Add `.github/workflows/publish.yml` (new), triggered by a `v*` tag. It checks out the tagged commit, builds with `node packaging/build-release.mjs --npm`, and publishes the built `.tgz`, never the working tree, through an npm trusted publisher: `id-token: write` on that one job, `contents: read` everywhere else, actions pinned by digest as in `.github/workflows/test.yml`, and a GitHub-hosted runner. It stops if `package.json` still says `"private": true`, or if the tag is not `v` plus the package version. Flipping `private`, the registry settings and the first publish belong to the maintainer, not to a fork.

## Pointers

- `packaging/RELEASE.md`: step 6 is the part this workflow takes over; update it when the workflow lands.
- `packaging/build-release.mjs`: `--npm`, and the artifact name the workflow has to find.
- `.github/workflows/test.yml`: the workflow style to follow.
- `test/npm-bin.test.mjs`: where the workflow's test goes.

## Acceptance

Pushing a `v*` tag to a repository with a trusted publisher set up publishes the built `.tgz` with provenance, and the same workflow on a commit with `"private": true`, or on a tag that does not match the package version, stops before it reaches `npm publish`.

## Test

Add a case to `test/npm-bin.test.mjs` that reads the workflow and asserts the `v*` trigger, `id-token: write` on the publish job only, every action pinned by digest, and that it publishes the `.tgz` from `artifacts/`. The test reads the file; it never runs the workflow or contacts a registry.

## Labels

`good first issue`, `cli`

## Effort

2 to 4 hours, plus the maintainer's registry steps.
