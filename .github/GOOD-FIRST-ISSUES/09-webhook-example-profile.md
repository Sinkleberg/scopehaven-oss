# Add an example profile for a webhook-driven app to `docs/profiles/`

`docs/WEBHOOK-DRIVER.md` explains how a check declares a signed Twilio, Telnyx or Stripe webhook and what the egress recorder makes of the app's own outbound sends, and the worked example lives in `test/webhook-driver.test.mjs` as an owned fixture app with three checks (`SMS-SIGNED`, `SMS-FORGED`, `SMS-UNSIGNED`). But the five example profiles in `docs/profiles/` are all for a browser-style app with a session, and none shows a `webhook` block or an unsigned-delivery prohibition. Someone whose app takes its main writes from provider webhooks has to assemble a profile out of a test file.

Add `docs/profiles/webhook-twilio.example.json` (new): a profile for the SMS fixture in `test/webhook-driver.test.mjs`, with the three checks from the worked example, the `webhook` block (`provider`, `secretEnv`, `url`, and `"signature": "omit"` on the unsigned prohibition), an `egress-recorder` observer on the billing host, and the allowed-use control bracketing each prohibition the way the other examples do. Introduce it in `docs/ONBOARDING.md`'s observer table (the example-profile test requires every example to be introduced there) and in `docs/WEBHOOK-DRIVER.md` as the copy-and-edit starting point. Synthetic keys only, named by `SCOPEHAVEN_TARGET_` variables, never values. The existing example test runs every profile against `examples/observed-support-app.mjs`, which has no webhook route, so split its list: the five record-based examples keep running there, the webhook example is validated there and run in `test/webhook-driver.test.mjs`.

## Pointers

- `docs/WEBHOOK-DRIVER.md`: "Declaring a webhook check" and "The worked example".
- `docs/profiles/egress-recorder.example.json`: the closest existing shape (an egress observer, paired controls).
- `test/webhook-driver.test.mjs`: `smsApp` builds the fixture application, `receiver` the billing sink; the three checks are declared inline today.
- `src/webhook-driver.mjs` and `src/contracts.mjs`: the declaration's rules and its validation at profile load.
- `test/onboarding-profiles.test.mjs`: asserts the exact list of example files and that `docs/ONBOARDING.md` introduces each.
- `docs/ONBOARDING.md`: the observer table that names each example.

## Acceptance

The new profile validates, runs against the fixture app with the documented outcomes on the fixed build and both defective builds, and the example-profile test lists it.

## Test

Extend `test/onboarding-profiles.test.mjs` (the list and the ONBOARDING check) and `test/webhook-driver.test.mjs` (load the checks from the profile instead of declaring them inline, so document and test cannot drift).

## Labels

`good first issue`, `check`

## Effort

3 to 4 hours.
