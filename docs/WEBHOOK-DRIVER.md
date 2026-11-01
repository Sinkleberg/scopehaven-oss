# Signed-webhook driver

`src/webhook-driver.mjs` builds a check's request the way a provider sends a webhook: the body bytes (form-encoded or JSON), the provider's documented headers, and the signature computed over the exact bytes sent. The key is a synthetic test key that the profile names by a `SCOPEHAVEN_TARGET_` variable. Many applications take their main writes from signed provider webhooks: Twilio and Telnyx for inbound SMS and voice, Stripe for payments. Without the driver, a check can only send JSON with no signature, so those write paths are out of reach.

The driver makes no network call. Whoever sends its output sends it to the profile's own origin, and nothing contacts Twilio, Telnyx or Stripe. Use synthetic keys only: a key the provider really issued has no place in a test profile, and the driver cannot tell the two apart.

**Status.** The connector sends a check that declares `webhook` itself: `src/contracts.mjs` validates the declaration when the profile loads, and `src/http-connector.mjs` builds the request with the driver and sends it (`test/webhook-wiring.test.mjs`). Operator code can still call the driver directly through the connector's `transport` option, as the worked example in `test/webhook-driver.test.mjs` does.

## Declaring a webhook check

A webhook check is a `POST` whose `body` is the provider's payload: the parameters for a form, the event for JSON. Beside the body, the check declares:

```json
"webhook": {
  "provider": "twilio",
  "secretEnv": "SCOPEHAVEN_TARGET_TWILIO_AUTH_TOKEN",
  "url": "https://sms-app.example.test/twilio/sms",
  "headers": { "I-Twilio-Idempotency-Token": "idem-0001" }
}
```

| Field | Meaning |
| --- | --- |
| `provider` | `twilio`, `telnyx` or `stripe`. |
| `secretEnv` | The `SCOPEHAVEN_TARGET_` variable holding the synthetic key. Required to sign; refused with `"signature": "omit"`. |
| `signature` | `"sign"` (the default) or `"omit"`: the request goes out without the signature headers, as declared, which tests that the application refuses an unsigned delivery. The driver never sends a request unsigned because a key is missing. |
| `encoding` | Twilio: `"form"` (the default) or `"json"`. Telnyx and Stripe: `"json"`. |
| `url` | Twilio only: the webhook URL as the provider is configured with it, which the signature covers. Write it exactly as a URL parser writes it (percent-encoded, lower-case host, no default port; no user, password or fragment), as its own origin followed by the check's own `path`, because the request goes to that path. The default is the profile origin and path, signed in the parser's form too: a path such as `/twilio/sms?name=O'Brien` is signed and sent as `/twilio/sms?name=O%27Brien`. An application behind a proxy checks the signature against its public URL, so declare that URL here. |
| `timestampOffsetSeconds` | Telnyx and Stripe only: an integer within one day (default 0) added to the signed time, so a check can send a stale or future signature. |
| `headers` | Only headers the provider documents for its webhooks, with literal values: for Twilio, `I-Twilio-Idempotency-Token`. Telnyx and Stripe take none here. The driver sets `Content-Type` and the signature headers itself. Names compare without case; values are 1 to 255 visible ASCII characters or inner spaces. |

A form body maps each parameter name to a string, or to a list of 1 to 32 strings for a repeated parameter. Parameters go out in the object's own key order, which JavaScript gives integer-like names first; Twilio's signature sorts the names, so the order never changes it. The encoded body is at most 8192 bytes, the connector's request limit.

## Keys

| Provider | Variable holds |
| --- | --- |
| twilio | an auth token: 16 to 256 visible ASCII characters |
| stripe | an endpoint secret: 16 to 256 visible ASCII characters (a `whsec_` form is used as given) |
| telnyx | an Ed25519 private key seed: canonical base64 of 32 bytes (the last character's two padding bits zero, so no two spellings name one seed). `telnyxPublicKey(seed)` gives the base64 raw 32-byte public key, the form Telnyx's Go, C# and PHP samples read; a receiver that parses the key as X.509 SubjectPublicKeyInfo, as Telnyx's Java sample does, needs the SPKI form instead. |

`createWebhookDriver({ target, env })` reads every variable it compares once, and every rule and key comes from those values. It refuses the run before any request when a key is missing or not in its provider's form, when one variable is declared for two providers, when two webhook variables hold the same key, by value or by key bytes (a wrong-key check would then be signed validly), or when a webhook key's variable or value is also another credential the profile names: an actor's, or an observer's under any field, a read-back credential or identity included. It also refuses, as the profile validator does at load, a profile whose correlation header, or the `credentialHeader` of a webhook check's actor, has the name of one of that check's provider headers (its signature or further headers, compared without case): sent beside the driver's headers, it would replace the signature or add one to an unsigned request. Refusal messages name variables and fields, never a value. `close()` zeroes the key bytes, and any later build is refused.

## The schemes

Each scheme was checked at the provider's own source on 2026-10-24, and the module header cites them.

- **Twilio** ([webhooks security](https://www.twilio.com/docs/usage/webhooks/webhooks-security)). `X-Twilio-Signature` is the base64 HMAC-SHA1, keyed with the auth token, of the webhook URL followed by each POST parameter in name order, written as name then value with no separator. A repeated name appears once per distinct value, values sorted, as twilio-node's `getExpectedTwilioSignature` does it. A JSON body instead carries `bodySHA256=<hex SHA-256 of the raw body>` on the URL, and no parameters follow it. Twilio signs no timestamp. The tests reproduce twilio-python's published vectors for a form body and a JSON body.
- **Telnyx** ([receiving webhooks](https://developers.telnyx.com/docs/messaging/messages/receiving-webhooks)). `telnyx-signature-ed25519` is the base64 Ed25519 signature of `<timestamp>|<raw JSON body>`, and `telnyx-timestamp` carries the Unix seconds signed. The tests pin the key handling to RFC 8032's first test vector.
- **Stripe** ([verify manually](https://docs.stripe.com/webhooks#verify-manually)). `Stripe-Signature` is `t=<Unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<raw body>">`, keyed with the endpoint secret. Stripe signs each delivery again, retries included, with a new timestamp. Test mode's extra `v0` entry is not sent.

## What a request records

`build(check, { origin })` returns `{ path, headers, payload, record }`. `path` is the path to send; a JSON Twilio webhook's path carries `bodySHA256`. `headers` join the connector's own, the driver's `Content-Type` replacing the connector's. The connector refuses, before writing anything, a request in which one of its own headers has the name, compared without case, of any of the provider's headers (signature and further headers, whether or not the request carries them) or of another header the driver built. `payload` is the exact body, sent as given. `record` is evidence:

| Field | Value |
| --- | --- |
| `schema` | `scopehaven-webhook/1` |
| `provider`, `encoding` | as declared |
| `signature` | `signed` or `omitted` |
| `secretEnv` | the variable's name, or null when omitted |
| `keyDigest` | SHA-256 of `scopehaven-webhook-key/1`, the run's salt, the variable name and the key bytes, or null |
| `headers` | the names the driver set, lower case, sorted |
| `signedAt`, `timestampOffsetSeconds` | the signed Unix time and the declared offset (Telnyx and Stripe; null for Twilio or an omitted signature) |
| `url` | Twilio: `declared` or `origin`, the URL that was signed |
| `payloadDigest` | SHA-256 of `scopehaven-webhook-payload/1`, the salt and the body bytes |

`webhookEvidenceProblem(run, { checks })` is the check a run's evidence validator applies to these records. Each row of a check that declares `webhook` whose request was attempted (`requestAttempted`, which a run-window refusal also sets) must carry exactly the record its declaration gives (provider, encoding, signature, variable, offset, which URL was signed, header names), every signed record must name a key of the run's driver record under the same digest, and no other row may carry one. It returns `webhook-declaration`, `webhook-driver-record`, `webhook-record` or `webhook-record-declaration`, or null. It checks the records' form and their agreement only: only whoever holds the synthetic key can recompute a digest. An exported suite never names a credential variable, so it carries `webhookSuiteViews(profile)` instead: each declaration with its key as a slot (the variable's place among the profile's webhook key variables, in sorted order), which still shows which checks share a key and which use another. The validator reads either form.

`record()` gives the run's key record: `{ schema: "scopehaven-webhook-driver/1", salt, keys: [{ secretEnv, provider, keyDigest }] }`, with the keys sorted by variable (an empty list when every signature is omitted) and a salt of 16 to 64 random bytes. The salt is recorded, so whoever holds a synthetic key can recompute its digest and tell which key a check used. Within one run, one key always has one digest. No key, no signature value, and nothing else derived from a key is ever recorded. A guessable key could still be confirmed against its digest, so use generated test keys.

## What the egress recorder makes of these requests

The driver signs requests going into the application. The egress recorder sees what the application sends out. When the application's outbound sends are themselves provider-style signed events, the recorder's `idempotency.signing` verifies the HMAC-SHA256 schemes (Stripe, Standard Webhooks, Slack). It verifies no Twilio scheme (an untimed MAC) and no Telnyx scheme (Ed25519). The tests show the recorder's rules on driver-built requests, exactly as `docs/KNOWN-LIMITS.md` states them under keyed retries:

- **Stripe**, with `idempotency.signing` declared. A re-signed redelivery (a new timestamp, the same event) verifies under the one declared secret and counts as one application. A changed body, another key, or a signing time outside the run window does not verify. Without signing, a re-sign reads as a changed request, unless `stripe-signature` is declared `volatile`.
- **Telnyx**. An exact redelivery collapses, because Ed25519 is deterministic. A re-sign under a new `telnyx-timestamp` reads as a changed request: neither Telnyx header is on the declarable signature list, and declaring one volatile is refused.
- **Twilio**. An exact redelivery under one `I-Twilio-Idempotency-Token` collapses, because the signature repeats exactly. The same delivery signed under another key stays bound even with `x-twilio-signature` declared volatile.

## The worked example

The worked example is in `test/webhook-driver.test.mjs`. An owned fixture application takes inbound Twilio-style SMS webhooks and checks each signature against its public URL. On a valid one, its write path sends one Stripe-style usage event to `billing.example.test` through the egress recorder, signed with the application's own synthetic billing secret, which the recorder declares under `idempotency.signing`. A connector run sends three driver-built SMS checks:

| Check | Request | Fixed app | App that verifies nothing | App that verifies only a present header |
| --- | --- | --- | --- | --- |
| `SMS-SIGNED` (allowed-use control) | signed with the declared token | pass: 200, one billing event, verified | pass | pass |
| `SMS-FORGED` (prohibition) | signed with another synthetic token | pass: 403, no billing event | fail: 200, a billing event | inconclusive (see below) |
| `SMS-UNSIGNED` (prohibition) | signature omitted | pass: 403, no billing event | fail | fail: 200, a billing event |

On the third application, the unsigned check's billing send lands after the forged check's window and fits that check's selector. Settlement therefore withholds the forged check's absence pass (`effect-outside-window`), while the unsigned check fails and catches the defect. Pinning each prohibition to its own event id would need an allowed-use twin with the same field value (positive-match pairing), which a refused request never has, so the selectors name the billing host only.

## Limits

- Content types are `application/x-www-form-urlencoded` and `application/json`, without the charset parameter some providers add.
- Twilio's GET webhooks, Stripe's rotation signatures (several `v1` entries at once) and its test-mode `v0` entry are not built.
- A signed request shows that the driver held the declared synthetic key. It shows nothing about the provider, and the application under test must hold the matching key (or, for Telnyx, the public key) for the request to be accepted.
- The driver signs with the wall clock by default, which is the clock receivers compare against. `timestampOffsetSeconds` moves only the signed time.
- The connector reads replies as JSON. An application that answers a webhook with TwiML (XML) reads `invalid-json`, which still decides the status assertion; JSON predicates on such a reply read inconclusive.
