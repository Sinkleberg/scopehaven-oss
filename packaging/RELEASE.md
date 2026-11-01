# Publishing to npm

The package is built and tested but not published. `package.json` says `"private": true`, so `npm publish` refuses it.
That flag changes in the release commit below and nowhere else, and publishing is the maintainer's step: nothing in
this repository publishes on its own.

Publish the `.tgz` that `packaging/build-release.mjs --npm` builds, never the working folder. The build packs the files
at one commit and adds `RELEASE-MANIFEST.json` and the generated SBOM, and `doctor` checks an install against that
manifest. The `prepublishOnly` script refuses a publish from a folder without the manifest. A published version can
never be reused, even after an unpublish, so a mistake here costs a version number.

## What you need

- Node 24.22.2 (the pinned version) and its npm. A trusted publisher needs npm 11.5.1 or newer.
- An npm account with two-factor authentication.
- The release signing key, kept outside the repository. The public half is in `packaging/allowed_signers`.

## Steps

Run these from the repository root.

1. Check the account and the name. A 404 from `npm view` means the name is still free.

   ```sh
   npm whoami
   npm view scopehaven version
   ```

2. Start from a clean `main` with the whole suite green.

   ```sh
   git status --short
   ./scopehaven test
   ```

3. Change `"private": true` to `"private": false` in `package.json` and commit that alone. It comes before the build:
   the `.tgz` carries this commit's `package.json` and the manifest holds its hash, so a later flip could not reach the
   built package, and npm would refuse it.

   ```sh
   git commit -s -am "release: publish 0.7.0 to npm"
   ```

4. Build and sign from that commit. The build reads git objects, not the working tree.

   ```sh
   node packaging/build-release.mjs --npm --sign-key /path/outside/the/repo/key --out artifacts/release
   TGZ=artifacts/release/scopehaven-0.7.0-$(git rev-parse --short=8 HEAD).tgz
   ```

5. Verify what was built: the checksums, the signature, then an offline install in an empty folder. Use the identity at
   the start of the signing key's line in `packaging/allowed_signers`.

   ```sh
   (cd artifacts/release && shasum -a 256 -c SHA256SUMS)
   ssh-keygen -Y verify -f packaging/allowed_signers -I scopehaven-release-interim-2026-10-29 -n scopehaven-release -s artifacts/release/SHA256SUMS.sig < artifacts/release/SHA256SUMS
   ```

   ```sh
   FULL="$PWD/$TGZ"; cd "$(mktemp -d)"
   npm install --no-save --offline "$FULL"
   npx --offline scopehaven doctor
   npx --offline scopehaven assess --target demo-vulnerable --out ./evidence    # exit 1: 26 of 44 checks fail
   ```

6. Publish the `.tgz`, from the repository root, by one of these two routes.

   **From GitHub Actions, with a trusted publisher.** This needs a publish workflow in `.github/workflows/`, a
   GitHub-hosted runner, `id-token: write` on that job and a public repository whose address matches `repository.url`
   exactly. Set the publisher in the package's settings on npmjs.com; those settings belong to an existing package, so
   a new name may need one local publish first. No token is stored, and npm attaches provenance by itself.

   ```sh
   npm publish "$TGZ" --provenance
   ```

   **From this machine, with two-factor authentication.** `--provenance` works only from a supported cloud CI runner,
   so a local publish carries none.

   ```sh
   npm publish "$TGZ" --otp=YOUR_CODE
   ```

7. Tag the release commit, then record the signed version. The build printed the ledger entry; it goes in
   `packaging/signed-releases.json`, in a commit of its own after the tag.

   ```sh
   git tag -s v0.7.0 -m "ScopeHaven 0.7.0"
   git push origin main v0.7.0
   ```

8. Check the published copy from an empty folder.

   ```sh
   cd "$(mktemp -d)"
   npx scopehaven@0.7.0 doctor
   ```

`private` stays `false` after the first publish. Later releases bump `version` in `package.json` and repeat from step 2,
without step 3.
