# Demo: the false-success refund

See the product without installing it. Everything in this folder was made on the built-in synthetic fixture, our test
support app (`demo-vulnerable` and `demo-repaired`, suite 2.3.0, 44 checks), with local synthetic data on loopback: no
production system, customer data, real user or live model took part. The reply the finding quotes is scripted by the
test app.

| File | What it is | Size |
|---|---|---|
| `false-success-refund.gif` | 24.8 s, 1000x680, eight captioned frames of the local workbench: SupportDesk · baseline (26 of 44 checks fail), the refund finding `TRUTH-01` with the assertions that decided it, SupportDesk · repaired (all 44 pass) and the comparison (26 fixed, 18 preserved). | 488,441 bytes |
| `vulnerable-run.html` | The full HTML report of the baseline run, as `./scopehaven export --format html` writes it: cover, every finding with its claim type, coverage and residual, limits. | 289,156 bytes |
| `repaired-comparison.html` | The HTML comparison of the repaired run against the baseline run: compatibility, allowed-use controls, 26 fixed / 18 preserved, the per-check table. | 16,403 bytes |
| `vulnerable-run.html.dsse.json`, `repaired-comparison.html.dsse.json` | The signature envelope the export wrote beside each report (DSSE, Ed25519). | |
| `demo-signing-key.pub.pem` | The public half of the key that signed them, generated only for these two files. A valid signature shows the files are unchanged since signing, not that the verdicts are right. | |
| `tools/` | The two scripts that recorded and assembled the GIF (below). | |

## Viewing the HTML

GitHub shows an HTML file as source, not as a page. Download `vulnerable-run.html` or `repaired-comparison.html` (open the
file on GitHub, choose Raw, save it) and open it from disk: each is one self-contained file with inline styles and no
scripts, images or network requests. If this repository later publishes a GitHub Pages site, the same two files can be
served from it unchanged.

## Verifying the signatures

```sh
node integrations/attest/cli.mjs verify --key docs/demo/demo-signing-key.pub.pem --envelope docs/demo/vulnerable-run.html.dsse.json docs/demo/vulnerable-run.html
node integrations/attest/cli.mjs verify --key docs/demo/demo-signing-key.pub.pem --envelope docs/demo/repaired-comparison.html.dsse.json docs/demo/repaired-comparison.html
```

## How these files were made

Recorded on 2026-11-01 from a workbench whose `data/` folder was empty. Run ids: baseline
`e8fb00d6-a12e-4c73-9f70-050f40e1ab70`, repaired `a61fb75d-959e-46ef-ab7a-3d5276ee21e6`.

```sh
# 1. A fresh local workbench (a free port is named because 4317 was busy on the recording machine).
SCOPEHAVEN_PORT=4327 ./scopehaven start

# 2. Record the scene: headless Chrome follows data/local-access.html, runs both builds, opens the finding, compares.
node docs/demo/tools/record-frames.mjs --launch /ABSOLUTE/scopehaven/data/local-access.html --out /ABSOLUTE/private/frames

# 3. Assemble the GIF. runs.json beside the frames names the two saved run ids used in step 4.
node docs/demo/tools/make-gif.mjs --frames /ABSOLUTE/private/frames --out /ABSOLUTE/CHECKOUT/docs/demo/false-success-refund.gif

# 4. Export the baseline run and the comparison into a private directory (mode 0700), signed with a key made for the demo.
./scopehaven export --run e8fb00d6-a12e-4c73-9f70-050f40e1ab70 --format html \
  --out /ABSOLUTE/private/exports/vulnerable-run.html --signing-key-dir /ABSOLUTE/private/demo-signing-key
./scopehaven export --run a61fb75d-959e-46ef-ab7a-3d5276ee21e6 --baseline e8fb00d6-a12e-4c73-9f70-050f40e1ab70 --format html \
  --out /ABSOLUTE/private/exports/repaired-comparison.html --signing-key-dir /ABSOLUTE/private/demo-signing-key

# 5. Copy the two reports, their .dsse.json envelopes and the key directory's scopehaven-signing-key.pub.pem
#    (renamed demo-signing-key.pub.pem) into docs/demo/.
```

Before copying, both reports were searched for home-folder paths, temporary-folder paths and the `evidenceDirectory` value:
none appears, so nothing was redacted. `test/demo-assets.test.mjs` checks the first three on every run of the suite, with
the GIF's presence and size and this file's contents.

## Rerunning the recording

`tools/record-frames.mjs` and `tools/make-gif.mjs` are optional tooling for this folder only; neither the product nor its
tests load them. They need Node 24 (the project's runtime) and, for recording only, Google Chrome or Chromium on the
machine (`--chrome /path/to/browser` when it is not in the usual place). Nothing else: no ImageMagick, ffmpeg or Python
package, because the scripts decode the frames and encode the GIF themselves. The recorder drives one headless page over
the DevTools protocol, exactly as a person would use the workbench, and the browser talks only to the loopback server.

Record into a workbench with no saved runs for a clean first frame (stop it, delete its `data/` folder, start it again),
and expect run ids, dates and the eight-character run prefixes in the frames to differ from these. The captions live in
`record-frames.mjs`; keep them to the synthetic fixture's facts (44 checks, 26 fail on the baseline, all 44 pass repaired,
26 fixed and 18 preserved in the comparison). `make-gif.mjs` refuses a result over 25 seconds or 3,000,000 bytes.
