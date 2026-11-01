// Reviewed exact source identities. A moved evaluator requires a new baseline.
import test from 'node:test';
import assert from 'node:assert/strict';
import { HTTP_EVALUATOR_HASH, runHttpAssessment } from '../src/http-connector.mjs';
import { EVALUATOR_HASH, compareRuns } from '../src/runner.mjs';
import { CONTRACT_EVALUATOR_HASH } from '../src/contract-synthetic.mjs';
import { CONVERSATION_EVALUATOR_HASH } from '../integrations/conversations/validation.mjs';
import { SUITE, POLICY_HASH, FIXTURE_HASH } from '../src/suite.mjs';
const PINNED = {
  // The fast-loop fixes (W1 declared body-field capture with the three-valued `fields` selector, src/body-fields.mjs;
  // W3 claim rules, src/http-claims.mjs; both join the evaluator file list, twenty-two files) moved the HTTP evaluator
  // from 0808f8f5 (main b003e4f, the 0.7.0-alpha candidate) to 94bc3dad; their review fixes (a field-blind observer holds a
  // fields clause at missing; wider claim negation cues; a wider capture deny-list and identifier redaction) moved it to a82c0032;
  // their review round 2 fixes (a claim segmenter that never splits inside numbers, abbreviations, initials, ellipses, URLs or
  // addresses; wider denial, hedge, condition, modal, contrast, retraction and reversal cues; the claim cap after NFKC; capture
  // only on declared paths; NFKC key folding, more deny-list spellings, any-separator card and nine-digit redaction and the
  // Number.MAX_SAFE_INTEGER bound) moved it to ec1f94b6; their review round 3 fixes (claim cues after a success phrase read to
  // the end of the reply; quoted phrases and letters outside a-z read ambiguous; a case-aware segmenter that keeps list numbers
  // and lowercase continuations in one sentence and counts other scripts' stops and question marks; folded apostrophe lookalikes
  // and format characters; a refusal's later clauses must agree with it) moved it to 5c256b66; their review round 4 redesign
  // (lead decision of 2026-10-10: a text trigger is an allowlist, so a phrase decides a claim only when the whole reply is
  // clean: phrases of one side with closed function words, that side's phrase words and nonzero amounts beside them, and
  // whole courtesy templates, built in or declared) moved it to b1edd55c; their review round 5 fixes (to, be, by, had,
  // they, them, us, me and their never stand beside a phrase; a closed word-order table rules out question order, a
  // sentence cut short and a preposition before a phrase; the action stays with the app; amounts are marked; a negated
  // phrase adds no words and is never restated; a bidi control reads ambiguous) moved it to 19e8952d; the exact-sentence
  // cut (lead decision of 2026-10-10: free text is not parsed; a text trigger decides only when the whole normalised reply
  // is exactly one declared sentence, optionally followed by one declared courtesy template) moved it to df92d63a (main 5e3e7f2).
  // Fast-loop fix W2 (correlated and per-check settlement: src/http-settlement.mjs, the correlation header rules in
  // src/egress-rules.mjs, the target declaration and record validation in src/contracts.mjs, the header and the drain
  // barrier in src/http-connector.mjs; no file joins the list) moved the HTTP evaluator from 0808f8f5 (0.7.0-alpha) to 8576ee81;
  // its review round (P1 credit from an exact effect.count only, never an effect.only upper bound) moved it to f447da31; its second review round (that count gives credit only when the rest of the run leaves it settled) moved it to 35097acc; its third review round (lead direction of 2026-10-10: the token never releases or fails a pass, so P1 and P3 are removed and effect-correlated-late withholds; a re-cased custom header value records no token) moved it to 8bcd8670; its fourth review round (the recorded token moves to correlation.settlementToken, which no selector or pairing pin reads, http-egress events never carry a traceId, and a correlated target refuses a traceId selector an egress recorder could see) moved it to ada45927 (unmerged).
  // Merging main 5e3e7f2 (W1 and W3, df92d63a) into fast-loop fix W2 (ada45927) combined both moves at b8a39508; the
  // merge's integration fixes (a claim rule's traceId selector refused on a correlated target, checks with claim rules
  // counted toward the per-check barrier total and the run budget, judgeOnly with fields in effect-correlated-late)
  // moved it to 978b03ed (main b83051d).
  // The core batch v3 final wording (the pairing header states the closure over an unclassified committed effect of the
  // name, with the selector's source and operation when given) moved the HTTP evaluator from 05157d9a (round 3) to this
  // identity. The core batch v3 round-3 fixes (Decision 3b: an identity probe at a probe point is refused as identityRefused judges it, so a
  // complete 2xx naming another principal or null withholds every row of the actor as bracket-not-passed, like a refusal status;
  // its comments in contracts.mjs and the connector header) had moved it from 4ee0a6f4 (the round-2 fixes). The core batch v3 round-2 fixes (Decision 3a: an identity probe refused with the actor's own credential at any probe point
  // withholds every row of the actor as bracket-not-passed, which outranks surface-refused; the closure wording in the pairing
  // header and the probe-point wording in the connector header) had moved it from 096fa8a0 (the core batch v3
  // review fixes). The review fixes (A-1, a check's two covering points ranked together; B-M1, a twin control
  // that was not sent; the decisions of 2026-10-09: an actor-pin twin carries the absence's source, operation and name, a
  // resource vocabulary is keyed by name and closed over the deciding window, a refused surface probe withholds every row of
  // the actor; A-3, no decision on a not-applicable row; the review Lows) had moved it from 48395264 (core batch v3 as built).
  // Core batch v3 (identity provenance per check, actor-identity/5; positive-match pairing of absence selectors; the core
  // batch v2 review Lows) had moved it from 44b0962c (core batch v2); core batch v2 had moved it from cc13de98 (effect.only),
  // which had moved it from 5994280c (G1-v4 capture).
  // Readiness gap 5 (background attribution: src/http-attribution.mjs joins the evaluator file list; three exports in
  // src/http-settlement.mjs; the attribution step in src/http-connector.mjs, src/http-effects.mjs and src/contracts.mjs)
  // moved the HTTP evaluator from c2c2467d (main 303bf27, readiness gap 4) to 7282547d; its fail-open review fixes (a control's
  // pass that settlement only tagged is still attributed; a traceId pin, like an actor pin, never excludes a background effect)
  // moved it to b8d61e4b. Merging main e49ea20 (readiness gap 3a, f4aa9e46) into readiness gap 5 (b8d61e4b), with the
  // attribution of a keyed (countBy) count in applications, moved it to 45abd901 (twenty-four files);
  // merging main d349c7c (E2a, f1c9a94c) into it moved it to this identity.
  // Readiness edge E1 (opt-in forwarding of an egress destination's sends to a declared loopback upstream, the upstream outcome
  // on the send event, decided only with a valid per-request proof, and the `upstream: "applied"` selector; src/effect-outcome.mjs
  // joins the list, twenty-five files): merge of main 30da053 (7e3b9744) into readiness edge E1 (abeb4bbd), with background attribution setting an earlier selector's upstream requirement aside, -> 5fc2197e.
  // Readiness gap 4 (form-encoded declared body fields) moved it from 978b03ed to c2c2467d (main 303bf27). Readiness gap 3a (keyed
  // retries, src/idempotency.mjs joins the list) moved it to f4aa9e46 (main e49ea20); E2a (re-signed redeliveries, body event ids)
  // moved it to f1c9a94c (main d349c7c). Readiness gap 2 (the declared effect horizon and run budget, src/http-timing.mjs joins
  // the list: twenty-four files) had moved c2c2467d to b8c9984a and, with its fail-open review fixes, to 160e251b on its own
  // branch, and to 37c141e1 merged with e49ea20; and to 69783356 merged with d349c7c.
  // Merged with main 30da053 (readiness gap 5, 7e3b9744; twenty-five files) it moved 7e3b9744 to c4681fb9; the late rules
  // (timing "lateFails": "withhold", late-unattributed in src/http-attribution.mjs) moved it to 20beaa66; their review fix (a later
  // send never excuses a keyed count that applied too many times) moved it to e12d60b5.
  // Merged with main 4e7001d (readiness edge E1, 5fc2197e; twenty-six files, http-timing.mjs last; the late rules set an
  // upstream outcome requirement aside like attribution) it moved 5fc2197e to f5bff205.
  // Merged with main 42605f7 (E2b, 024d300d) it moves 024d300d to this identity.
  // The lifecycle attribution fix (a change whose pass attribution withholds is not attributed: it reads unconfirmed and its
  // sent post-change checks read change-not-attributed, in the connector and the validator) moved it to cd2c1036; its review fixes
  // (only an inconclusive change row, tagged effect or claim rows only, the wording) moved it to this identity.
  // Readiness edge E3 (forward-proof/2, returned-id closures seeded only by a check's own token-carrying selected send, and one
  // use: a gap-5-withheld effect.exists pass released; src/id-closure.mjs joins the list, twenty-seven files): merge of main
  // fc76deb (2327d138) into readiness edge E3 (b43cf65f) -> e2c5c818.
  // Readiness gap 1 (effect.only selector and destination path limits) moved it to f4ff6eee and, with its review hardening, to 7c0265cf.
  // Control claim rules (an allowed-use control's claim rules declare success only, so an honest refusal never passes a control
  // or establishes its actor; no file joins the list) moved 7c0265cf to a4e8a658; its review fixes (a saved run whose control
  // declares a refusal side reads control-refusal-claim) moved it to fef4548d.
  // Control positive effects (an allowed-use control that declares effects must prove one positively; no file joins the list)
  // moved fef4548d to d97b0c72; its review fixes (positiveClause reused, wording) moved it to 51e0eb04; readiness gap 1 part 2
  // moved it to be1b303a. Control settlement (a control's positive pass whose deciding effect carries another check's token is
  // withheld, and the validator reads such a lifecycle change as not attributed; no file joins the list): merge of main 7c1a45c
  // (be1b303a) into control settlement (8d2ef097) -> 8a2a297a.
  // effect.only keyed applications (countBy "idempotency-key" on effect.only: an exact keyed replay counts with its application;
  // no file joins the list): merge of main 208e443 (8a2a297a) into it (43e6b7f0) -> 498850b5; its review fixes (re-judges keep
  // countBy, an out-of-set unproven resend stays offending) move it to this identity.
  // Settlement re-judge part 1 (the opt-in settlement "outsideWindow": "judge" re-judges an effect.only pass on its late
  // candidates, worst case; no file joins the list; an effect.only clause with countBy keeps the rule, and a late countBy
  // release is not included): built on 4214451 as 25832eab; merge of main 8115aa6 (7ecfd8c0) into it (25832eab) moves it to
  // this identity.
  // Coverage v2 Part C (an egress background source may pin a resource; an ambiguous-path send fits every pin; no file joins
  // the list): merge of main 18808cc (a96bf37a) into it (50a29796) -> ce5e2a42.
  // SETTLE-V3 (fix A: non-pass verdicts decided through followed non-fitting late entries; fix B: the judge re-judges countBy
  // effect.only clauses worst case; fix C: effect.only passes read through late sends a decidable allow covers; no file joins
  // the list): built on 606d9aa (ce5e2a42) as 097e2e6f; its fail-open review fix (under countBy an entry on a host that records
  // keys never lifts) moves it to e9922a3c.
  // Fix C follow-up (host-wide fitting of a late entry against an expected selector only on a host that records keys, whose
  // entries never lift; no file joins the list) moves it to ce91a311 (fix C host fit, 2026-10-12).
  // E2a tightening (timestamped signature schemes leave head only when they parse inside the run window, and re-signed sends count
  // once only when their signed items agree; untimed MACs stay bound; a signature header is never a keyed destination's correlation
  // header; no file joins the list): built on 14aa373 (e9922a3c) as 9807e097; rebased on 6ea5446 (ce91a311) -> 0b4995da.
  // effect.only countBy hint (a fail on a clause that could opt in to countBy but does not names its beyond-count sends that countBy
  // would read as exact keyed replays; basis text only; no file joins the list): built on 4108229 (0b4995da) as 6b7119b5.
  // Provider feed (G2: a provider-feed observer type, source provider-feed, lineage provider-record with independent custody, its
  // sealed windows bound to the run record's witnessed and feed; provider-feed-rules.mjs joins the list): built on 14aa373
  // (e9922a3c) as 0b739c10; rebased on 4108229 (0b4995da) as c5bb8591; its fail-open code review fixes (recipients the app chooses
  // read partial, never a fault; the provider feed's witness close reserves its head reads) as 9cbd83f5; merge of main 84c7008
  // (6b7119b5) into the provider feed (9cbd83f5) as 16b5d554; the recipient rules moved to src/mail-address.mjs (it joins the list,
  // shared with the SMTP sink's coming fix) -> 27117278.
  // Mail alias fail-open (src/mail-address.mjs: an address that could be a declared mailbox under common alias rules, a "+" or
  // "-" subaddress or the same local part without dots, is ambiguous; the SMTP sink now names recipients by these rules; no
  // file joins the list): built on 6583921 (27117278) as 5100cd04; its fail-open review fixes (canonical mailboxes only: no
  // "%" or "!" relay route, printable ASCII before lowercasing, no odd host; Proton-style stems; declared aliases of each other
  // are ambiguous; declared addresses must be canonical) -> 2280cd02.
  // Value-leak (an earlier review ported onto 86e8f15: json.noForeignValues reads the target's declared tenant values; a literal
  // whole-token foreign identifier fails, a pass needs every leaf in the allowlisted plain form, anything else reads
  // inconclusive; src/tenant-values.mjs joins the list) -> 3dc2318d. #273's branch identities (662e767c to ae3ef577)
  // never reached main.
  // LATE-FIELDS (a late scoped egress entry that is exactly one completed after-witness request carries its seq and captured record,
  // egress-recorder/4; an effect.only pass reads it covered when that record matches a field-pinned allow; the validator binds the
  // seq and the record to its gap event; no file joins the list): built on 86e8f15 (2280cd02) as ba932b9e; its fail-open review
  // fixes (a comment, docs and tests) -> ba0d7c0b; merged with main 8c1dbab (3dc2318d) -> 976a6025.
  // Provider feed v2, template binding (a feed that declares a template vocabulary reads an entry's signed template as a declared
  // label, captured /template, provider-feed/2; anything else reads unknown; the validator binds the labels to the run record's feed;
  // no file joins the list): built on 85be010 (976a6025) as 642cec4b; its fail-open review fixes (in effect.only a feed send whose
  // template reads unknown under a template-pinned expect is never absorbed by an allow; a template pin must name a declared label;
  // a repeated template key reads undeclared; a recipient domain over 128 characters is unusable) -> 043bd057.
  // Verified signature headers (b': idempotency.signing, a declared scheme and SCOPEHAVEN_TARGET_ secrets the egress recorder reads
  // once to verify each send; a re-sign collapses only under exactly one declared secret, in window, in order and within
  // dedupeSeconds; the run records a usable vector and nothing derived from a secret; egress-recorder/5; no file joins the list):
  // built on 85be010 (976a6025) as 54359d6e (badd9844 a working identity before it, never committed); its fail-open review fixes
  // (dedupeSeconds bounds every collapse on a signing host and is anchored on the earlier of the first send's timestamp and
  // arrival; the proof clash reads whsec_ and base64 forms; the signing clock is read once) -> c3b44482; merged with main cddb4be (043bd057) -> 98f0add4.
  // App logs (PR-1a: the application's own action log, declared under appLogs, read apart from the observers and sealed as
  // data.appLogWindows; it decides nothing, every custody entry point refuses an app-log window; app-log-rules.mjs and
  // app-log-verdicts.mjs join the list): built on 85be010 (976a6025) as 6705cce2; its fail-open review fixes -> 8e9aab75; merged
  // with main f89c464 (98f0add4) -> eccf8c35.
  // Provider feed v2 Part B (a witnessed endpoint feed scopes its late entries, a lone one carrying its event seq and template record,
  // outside a template-pinned clause whose pin its declared label does not meet; the follow rule and a run-end feed drain that reads
  // to a signed head decide whether they count; provider-feed/3; no file joins the list): built on cddb4be (043bd057) as cc320407; its
  // fail-open review fixes (narrowing only on a feed window that sees every pinned field; a drainer whose run-end window failed is
  // recorded neither quiescent nor clear; each drain read is bounded by the time left) -> 583cc84e; merged with main f89c464 (98f0add4)
  // -> 972e733a; merged with main 7a329e4 (eccf8c35) -> 788bf36f.
  // Unknown-field allow (in effect.only a send of any source whose fields could not be read under a fields-pinned expect, its actor
  // unknown too against an actor pin, is undecided, never absorbed by an allow without that pin; feed v2 held it for provider-feed
  // sends only; no file joins the list): built on cddb4be (043bd057) as 4fc930f3; merged with main f89c464 (98f0add4) as a0698a4a;
  // merged with main 7a329e4 (eccf8c35) as 70b96baa; merged with main 76908a5 (788bf36f) -> 635074b8.
  // App-log admissions (PR-1b: with "use": "admission" the application's own log can make a clause fail, never pass; no file joins
  // the list): built on 7a329e4 (eccf8c35) as e01b2d6a; merged with main 76908a5 (788bf36f) -> 547f9afe; merged with main 5c3b3f6
  // (635074b8) -> 46d4b6da.
  // JSON decimal fail-open (a string, JSON or form, reads "no" against a pinned string only where no common reading makes the two one
  // value, so "105.50" against "105.5" is unknown; an `in` member of another type reads unknown unless no reading makes it equal;
  // settlement reads another check's token first on a positive clause; template pins must be labels; no file joins the list): built
  // on 5c3b3f6 (635074b8) as 46145eb1; its fail-open review fixes -> 39ee67ab; merged with main 742e422 (46d4b6da) -> c4276699.
  // App-log admissions PR-1c-1 (word maps, distinctFrom, exact background paths; no file joins the list): built on 742e422
  // (46d4b6da) as 882b3720; its fail-open review fixes -> 476b614d; merged with main 62342fb (c4276699) -> 8f3c2d29.
  // Provider feed v2 Part C (under provider-feed/4 a window's only late feed entry, one signed send whose template is a declared label,
  // lifts effect.only through an allow it matches template included; a provider-feed/3 run keeps its semantics; no file joins the
  // list): built on 5c3b3f6 (635074b8) as cfe135d9; its fail-open review fixes (the lift decided from one flag that also writes the run
  // record's label; one late feed entry per check, not per window) -> cb9cf49e; merged with main 742e422 (46d4b6da)
  // -> cb477520; merged with main 62342fb (c4276699) -> 12186829; merged with
  // main 14815de (8f3c2d29) -> this identity.
  // App-log admissions PR-1c-2 (per-application countBy, allowBackground, background principals, per-window job check, own-token
  // lines; no file joins the list): built on 14815de (8f3c2d29) as 0add640d; its fail-open review fixes -> d85763b6; merged with
  // main 70917a4 (e6416d94) -> 7d3f404b.
  // Form decimals (fail direction only: a clause that reads missing is judged once more with a form decimal that no common reading
  // makes the pinned value read "no", and that judgement is kept only when it fails; no file joins the list): built on 62342fb
  // (c4276699) as 888ca353; its fail-open review fixes -> 27987482; merged with main 14815de (8f3c2d29) as 0424cd09, with main 70917a4
  // (e6416d94) as 9b9a2d97, and with main 9f6098e (7d3f404b) -> 1137a358.
  // Later outcomes PR-1 (a provider feed that declares outcomes reads signed outcome entries, binds them to its in-run sends by the
  // provider's message id and canonical recipient, and seals them in the settlement record after a later wait that changes no drain;
  // provider-feed/5; the records decide no verdict; no file joins the list): built on cc9b681 (1137a358) as 2fddeeee; its fail-open
  // review fixes (the later wait after the final mark and every run-end window; clear only at a later mark read to its signed head)
  // -> cbd32ec3; the later mark's two feed requests kept out of the wait -> 9c332e56.
  // Later outcomes PR-2 (under provider-feed/6 the stage lowers a positive pass whose matched send no longer credits, judged again through
  // custody, settlement and attribution; a control is withheld, never failed; compareRuns credits a repair over a later failure only on a
  // signed success; a lifecycle change the stage withheld is not attributed; later-outcome joins the list): built on 290b509 (9c332e56)
  // as f0d350d5; its fail-open review fixes (the backend row decided again with the stage's findings; the findings applied after app-log
  // admissions, only to a clause that still passes) -> fbff4cd3; comments brought in line with that order -> 95e57520.
  // Absent fields (fail direction only, opt-in per pin: a field pin that declares absent "fails" reads a field absent from a body the
  // egress recorder read in full as "no" when a clause that still reads missing is judged once more, and that judgement is kept only
  // when it fails; effect.none never moves; no file joins the list): built on 39c45ba (95e57520) as 8a3e32f4; its review fixes (the
  // declaration, a JSON field missing beside a URL query or under a non-object root recorded unusable, and the absenceDecided tag that
  // compareRuns never credits as a repair) -> d66ae4d2.
  // Suspend-aware custody time, first slice (F4, DP5 R65-123: a check window a host suspend overlapped carries a sealed record that
  // the gap basis names, and a settle or horizon wait the suspend cut short in awake time is extended; the record decides no verdict;
  // suspend-clock joins the list), built on 39c45ba (95e57520) as c63f9966 (its working identity 72d7f0b4 was never committed); its
  // review fixes (PR340-REVIEW.md: extensions bounded by the run deadline, a proportional floor and a frozen awake clock read as
  // unusable, record bounds anchored on elapsed time, a pass or fail decided on a suspended window's coverage names it) -> 0b71f0b3;
  // merged with main d0fe04a (d66ae4d2) -> a5308153.
  // Suspend-aware awake truncation (F4b, PR340-REVIEW-FINAL.md finding 1: a wait a host suspend left short of its declared awake time
  // reads partial, sealed under a timing plan as the awake time it held and without one as the record's shortMs; inert where no awake
  // clock can be read, and said so; the suspend notes appended last when a row is built; no file joins the list), built on 64daacc
  // and merged with main 89b59d8 (a5308153) -> 0f17f616 (its working identities were never committed).
  // In-doubt resolution IDR-0 (gate A: semantics types on core clauses and claims, upstream "resolved" only on agent-write and exactly-n, read
  // exactly as "applied" with no resolver; effect.only outcomeJudged selectors pinning their object and overlapping no effect.none; without an
  // opt-in every verdict is main's; no file joins the list): built on 39c45ba (95e57520) as 0f09a3ed; a comment naming the gate-A helper
  // corrected -> f4f00bf4; review fixes (destination-declared object routes, egress-recorder/6 target flags, an applied member standing for
  // its key group, refusal claims and canonical hosts in the overlap check, the validator re-checking) -> df860cb6; a template needs a literal
  // segment (PR341-REVIEW-R2 nit 5) -> e31be590.
  // Merged with main 86c8a96 (0f17f616) -> 9040bb98.
  // In-doubt resolution IDR-1 (strict combination with core-owned applicability, R0, keyed outcomeJudged collapse on resolved fates, full
  // group interval on failure or conflict, the sealed operation record, the backend tier withheld while a selected attempt is in doubt,
  // egress-recorder/7 transport records; without an opt-in, or under an earlier recorder label, every verdict is as before; in-doubt joins
  // the list): pushed stacked on IDR-0 as 12860425, 0e25390e and c0ae487a, rebased onto main 4b2e2f7 (9040bb98) -> 1f5ea353; the group
  // interval always intersects the members' own per-attempt decisions (PR342-REVIEW-R2 N1) -> 5b42796f.
  // Suspend-aware lead-in and stop (F4c, PR343-REVIEW.md finding 1, minor 2 and nits 4 to 6: under a timing plan the lead-in is held in
  // awake time and a lead-in still short cuts its check and every later one; without a plan a check whose settle or barrier a sleep left
  // short is the last one sent (host-suspend-run-stopped, derived from the sealed windows); a live awake clock that reads no movement over
  // a pair is a suspend of the whole pair; a sleep inside an extension is owed again; the notes per cause; records always sealable and
  // only where the connector writes them; no file joins the list), built on main 86c8a96 (0f17f616) as bbf012c1; merged with main
  // 61adb01 (5b42796f) -> 3ed66f46.
  // In-doubt resolution IDR-2 (the run-end re-decide stage: a later resolver's records bound onto the attempts they name through an event
  // overlay, every row with an opted-in clause that reads a changed attempt decided again before settlement and resealed with the records,
  // the validator binding the sealed records before it decides; no later resolver exists, so nothing binds and a run carrying a record is
  // refused; no file joins the list): built on main 61adb01 (5b42796f) -> f7908d21; PR348-REVIEW fixes (an effect.only outcomeJudged clause
  // reads every admitted send for its re-decide flag, as its replay hint does; a later resolver applies only to attempts that connected) ->
  // fd2b1364; merged with main 8eaa589 (3ed66f46, after the suspend-aware lead-in and stop #344) -> 33449ad9.
  // Suspend follow-ups (F4d, the an earlier review ultrareview's findings 1 and 2 with its lookup-table refactor, PR344-REVIEW nits 3 and 4 and
  // PR344-REVIEW-FINAL N1: without a plan a settle or barrier the spare budget could not restore goes on into the time kept for later
  // checks, is decided when that restores it, and stops the run either way (reserveMs, derived by the validator); an unreadable reading on
  // an awake clock already seen to move is a suspend of the pair; a timed run a sleep cut is worded apart; the not-sent words from one
  // table; no file joins the list), built on main 4f2d57d (3ed66f46) and merged with main 8eaa589 (3ed66f46, the #344 merge) as af37c38b;
  // merged with main ff3a980 (33449ad9, the #348 merge) -> cff0af99.
  // In-doubt resolution IDR-4 (resolver R1, the request feed: an egress recorder may declare a provider-signed feed of the requests the provider
  // received, joined to its own sends by their exact idempotency key; a later resolver seals its read and both sides derive the result; a
  // confirmed attempt reads applied in the key collapse; a lifecycle change check takes no late record; request-feed-rules joins the list),
  // built on main c8f8bd3 (cff0af99) as eae0b5ab; with its review fixes (PR363-REVIEW: the key collapse's identity and retention function
  // moves to key-identity.mjs, which joins the list, and R1 reads through it; the positive control; one recorder per feed host) and merged
  // with main 13d95693 -> 2896464d.
  // SB-W, the allowed-use guard (FIX-07: an absence that pins nothing, in a boundary check that expects a success status and has no
  // positive clause, passes only beside a required allowed-use control of its actor with a positive effect, else reads
  // allowed-use-not-declared; a sealed pass of one is refused as prohibition-no-allowed-use; no file joins the list; collector records
  // unchanged), built on main b33cd26f and merged with main 582cb23a (both 2896464d) as 8403be45; its PR382-REVIEW fix (a guard counts
  // only when its positive clause passed, so identity option B never releases a prohibition whose guard failed on a gap; the named
  // refusal reads the pairing stage; no file joins the list) -> d47576d9 (main c042d215).
  // In-doubt resolution IDR-3 (resolver R2, read-back: a forwarded destination may declare ScopeHaven's own proven reads of the system of record
  // after a declared settlement bound, joined to the recorder's own sends by their group; a later resolver seals its read and both sides
  // derive the result; a count the reads pin exactly is assigned only within one identity; read-back-rules joins the list), built on main
  // b33cd26f (2896464d) as 8ba1b0a1; with its review fixes (PR373-REVIEW: a refutation or cap only on a POST route whose host declares minted
  // ids; no two applied members the key collapse reads as one, through key-identity.mjs; the forward start sealed and the pre-image checked
  // against it; a control read at start) and merged with main da27674d as 3a851154 (approved at 5bdc0047); merged with main c042d215
  // (d47576d9, SB-W #382) -> 430010c7 (main abceac86).
  // SB-W2, FIX-02 and FIX-06 (SURPASS-BYPASS-01 A-21 and B-12: a provider feed's declared key source, keySource and adapterReads, is
  // carried in its run record and every window, and custody reads it, so an undeclared source or an adapter that reads the application's
  // own store never supports a pass; the sinks hold their port on 127.0.0.1 and [::1]; provider-feed/7, egress-recorder/10 and
  // smtp-sink/2; no file joins the list), built on main abceac86 (430010c7) as dd1b9f7e and merged with main b8699535 (reviewed at
  // 0f69d16d); with its review fixes (PR398-REVIEW: a boundary absence one of whose deciding windows is a feed whose key the application
  // could hold stays inconclusive, whatever else decided it; the sinks' port errors name both loopback addresses) as c625aede (reviewed at
  // 004a0c95); with the delta's D1 fix (a feed whose key the application could hold that sees the select keeps the absence inconclusive
  // even when it is presence-only and decided nothing) as 470b0f49, and the same rule for effect.only (a pass that judges such a feed,
  // presence-only included, reads inconclusive) as 7569cb54 (main 0bdc7e7d).
  // FIX-04 (SURPASS-BYPASS-01 A-32: another name of a declared provider. A destination may declare aliases, folded into its host; an
  // undeclared host that shares a destination's registrable domain is a scoped entry egress-undeclared-sibling-host in a check window and
  // that code window-wide elsewhere, and the validator binds both to the window's own sends; the clause text names the undeclared hosts
  // its egress windows saw; egress-recorder/11; public-suffix joins the list), built on main 0bdc7e7d (7569cb54) as 5c657ca4; with the
  // vendored suffixes in their own MPL-2.0 file (public-suffix-list joins the list) as 85374c7a (main c5515273).
  // The feed drain's quiet confirmation (the run-end drain's confirming head is held to the read it found quiet, so a background read
  // between the quiet check and that head no longer leaves the drain quiescent just after an entry arrived; provider-feed/8; no file
  // joins the list), built on main c5515273 (85374c7a) as 4dcc9345 (main ae769185).
  // The unresolved-send rule (an effect whose outcome no observer decided, started or unknown, from any relevant window, presence-only
  // included, holds an absence, a count it could still change and an effect.only pass at missing, never a pass; a provider feed's export
  // file stamped before its window no longer lets a silent observer pass; no file joins the list), built on main 0bdc7e7d (7569cb54) as
  // ed682136 (afcf711e, reviewed at ed682136); with its PR429-REVIEW fix (a keyed count its applications already decide, below or above
  // the expected number, keeps its fail, as a plain count does) as 44cadf60 on main c5515273 (e1ab95c6, reviewed at 44cadf60); rebased on
  // main ae769185 (4dcc9345) as 64fcd098 (main 197e55aa).
  // The egress drain's quiet recheck (the run-end drain's last look, one turn after it found the recorder settled and quiet, checks quiet
  // again, so a request read, recorded and answered in that turn no longer leaves the drain quiescent just after it arrived;
  // egress-recorder/12; no file joins the list), built on main ce9ead1f (85374c7a) as 7e5ea134 (reviewed at 616f9e18); rebased on main
  // 926d64d7 (64fcd098) as aadc0ca9 (main a3db37c7).
  // The pg-snapshot collector identity (pg-snapshot/1: a pg-snapshot observer's run record names the reader code that read it, the
  // read-back rules in src/pg-readback.mjs included, and the run validator accepts a collector on a pg-snapshot record; no file joins the
  // list), built on main 22608334 (aadc0ca9) as c99a89ae (main a2b37f14).
  // H1 step 3 (an operator-remote target over direct HTTPS under an authorization record naming its origin, DNS pinned; remote-target
  // joins the list), built on main 7c931ae3 (64fcd098) as 5a8f8fc5 (reviewed at 3e049987); rebased on main ed074d67 (c99a89ae) as
  // 831fa88f (6b511f37).
  // H1 step 4 (a static credential header on an actor, credentialHeader, value from credentialEnv only, sent only in that header to the
  // target origin, digest kept in the run; no file joins the list), built on 3e049987 (5a8f8fc5) as cf1cbf1f (reviewed at 6a045df8);
  // rebased on 6b511f37 (831fa88f) as 3f4f9c83 (af8d8c67).
  // Self-change lifecycle (a lifecycle change sent by the changed actor itself: a required non-GET allowed-use control outside its
  // brackets, attributed to the actor's whole pre-change proof, identity rules 6; no file joins the list), built on main f424b18d
  // (aadc0ca9) as 80eac864 (4340f499); rebased on H1 step 4 af8d8c67 (3f4f9c83) as 93ab8acb (e3aabaed).
  // Signed webhooks (a check that declares "webhook" is sent as its provider would send it; src/webhook-driver.mjs joins the list),
  // wired on main after the self-change lifecycle (93ab8acb) as 54e6cb89 (1f6d9f33); its review fixes (no header the connector adds
  // may share a provider header's name, a webhook key is no read-back credential, the driver closed on every exit; no file joins
  // the list) as abbe8511 (577040e1); its round-2 fixes (the connector refuses any provider header name at send time, signed or
  // not; a build refusal names its check) as e760747d (976bc728).
  // Declared channels (N11: a profile's "channels" is validated, digested when declared and recorded on the run; the absence rule is
  // read from the saved run, src/channels.mjs; no file joins the list), on main after the signed-webhook wiring (e760747d) as 450e5445.
  // N13 catalog identity (the connector records each database observer's catalog() record as run.catalog, checked by the shared
  // validator; catalog-identity.mjs joins the list), the merge-line hunks re-pinned on #500 after declared channels (450e5445)
  // as 625b0911; its review fixes (one import from http-effects, an observer's record cannot relabel its instance, a comment
  // pointer; no file joins the list) as 3002c6d9 (main 59f2ffc2).
  // NC2 item 1, two identities by default (a tenant-scoped profile's boundary checks get generated mirrors under the second identity,
  // the "mirrors" declaration and "mirrorOf" key, the single-identity rule for the CLI; src/two-identities.mjs joins the list), built
  // on main 59f2ffc2 (3002c6d9) as 6bdb08a0; its review fixes (identity values swapped, answer probes with json.noForeignValues
  // alone, undeclared identifiers and own-view predicates left unmirrored, declared equal roles and identity controls, mirrors in
  // canonical order and skipped as profile-limit rather than refusing the profile; no file joins the list) as cfe37772; its round-2
  // fixes (only declared counterparts swapped, a mirror only into a route the second identity uses, either identity's names leave a
  // check unmirrored, no effect clauses, a mirror that breaks a rule left out alone; no file joins the list) as e24426a9; its
  // round-3 fixes (a mirror follows the statuses the second identity's own applicable checks expect, refusals only across the
  // boundary with a boundary status, successes only reads of one's own, digit-bearing path parts undeclared, json.exists in a
  // success the first identity's view, the limits' cutoff computed once; no file joins the list) as 503ac4d9; its round-4
  // fixes (a refusal mirrored only on a record the profile shows, a GET success only on the counterpart record's own path, a
  // POST answer probe only on a declared read-only route; no file joins the list) as d95d1b9e; its round-5 fixes (a refusal
  // mirrored only as a GET beside both identities' own allowed twins, no mirror on a record a declared write changes,
  // json.equals in a success the first identity's view, query parts marked in a route's parts; no file joins the list) as
  // b2dd82c4; its round-6 fixes (writes seen in the body and on a redirect, a read-only turn no write, twins on the
  // exact counterparts, path and query parts marked apart; no file joins the list) as 50137c28; its round-7 fixes (a mirror
  // naming a written value anywhere, its body included, is not generated; a value inside a longer path part is named; query
  // names and values marked apart; no file joins the list) as 1b4e4144; its round-8 fixes (extraRequests, the headroom a
  // per-user limit needs; case-folded, exact and numeric names of a written record; no file joins the list) as 79f75dfa; its
  // round-9 fix (mirrors opt-in: a target without a "mirrors" object gets none; no file joins the list) as 1fdf1bd2 (main fbb7c189).
  // NC9 item 1, the Postgres and DNS collector labels (pg-snapshot/2: N12's end barrier, run lease and ignore-list reader with its
  // lists join the pg-snapshot collector's files; pg-wal/1 and dns-stub/1 registered, neither yet a declared observer type; no file
  // joins the list), built on main fbb7c189 as 17b927f6.
  // NC9 item 2, the actor capture's profile key (a pg-snapshot observer's "actorCapture": the installed capture's block and its
  // installation digest, checked for declared principals and an install credential of its own; the factory passes it; NC2's join in
  // pg-snapshot and pg-wal; pg-snapshot/3 and pg-wal/2; no file joins the list), stacked on NC9 item 1 (17b927f6) as d72d2f7e (reviewed
  // at ff1318df); its PR518 review fixes (the net join accounts for the net operation, an actor-pinned selector is never exact on a
  // net-only snapshot window, the factory gives the key only to a caller that reads it, three block rules at load; no file joins the
  // list) as a12153c6.
  // NC9 item 3, the Supabase identity rules in the run (a target's "supabaseRules"; the rules' resolver passed to the actor capture; a
  // pinned clause names service-role writes; rls-zero-row judged per allowed-use control after every other stage, FAIL-only, from a
  // sealed zero-row record the validator recomputes; pg-snapshot/4 and pg-wal/3; no file joins the list), stacked on NC9 item 2
  // (d72d2f7e) as f6b7996f (built and tested at d3af51f1, never pushed); rebased on item 2's review fixes (a12153c6) as 3cd97fe2 (reviewed
  // at 7f3cc65c); its PR520 review fixes (a change check failed by the stage is not attributed, the record bound to the declaration through
  // the exported suite and checked against its window, a write no one is named for suppresses the FAIL, declarations the rule could never
  // apply to refused; no file joins the list) as c23c314f (reviewed at 70539912); its round-2 fix (a zero-row FAIL counts as passed when
  // sent only over a prior pass or a tagged inconclusive; no file joins the list) as 3a7f10c7.
  // NC9 item 4, pg-wal in profiles (a profile observer type with a source of its own, sql-wal: lineage database-log, custody
  // observer-held, so a database-only prohibition can pass on it; its contracts shape, factory build, authorization endpoint, self-test
  // model and limitations line; pg-snapshot's background-writer keys; pg-wal among the collector-carrying types; pg-snapshot/5 and
  // pg-wal/4; no file joins the list), first built on 3cd97fe2 as c93b49d1 (pushed at ac92e375); stacked on NC9 item 3's review fixes
  // (c23c314f) as 2f680930 (never pushed); stacked on NC9 item 3's round-2 fix (3a7f10c7) as 97237b44; its PR521 review fixes (sql-wal
  // custody for an absence only, an actor-pinned boundary pass principal-unverified, pg-wal a store and port channel observer, the
  // factory's pg-wal only for an HTTP assessment, a pg-wal credential never an actor's, a degraded database-write absence names pg-wal
  // as its upgrade; no file joins the list) as d25bdb2b (reviewed at 8e369fdc); its round-2 fix (a pass that needs a matched write on
  // the WAL, an effect.count of one or more or an effect.only's expected effect, is a presence; the effect.only principal rule only
  // where a window in scope names principals; no file joins the list) as b42302c7 (reviewed at 61bd6801); its round-3 fix (the principal
  // rule reaches only actor names an actor capture supplies, CAPTURED_ACTOR_SOURCES; a held window that names principals keeps its pass;
  // no file joins the list) as 5d501549 (reviewed at e5bd2246); its round-4 fix for the stack review (the pg-wal upgrade only where a
  // Postgres observer's window decided the row; the recompute also accepts the text main wrote, so a run recorded before still validates;
  // no file joins the list) as f228ce9b, main's identity at 7134a8e9.
  // NC11 items 1 and 3, the mirror phase (generated mirrors sent after every declared check, the final mark, the observers' stop and the
  // identity-refusal probes, outside the brackets, between probe points of their own that bind mirror rows only, under a budget of their
  // own; a mirror a per-user limit answers, 429 or a declared "rateLimitStatuses" answer, reads inconclusive as produced and the validator
  // recomputes it; mirrorOf on mirror rows and in the exported suite; #512's carried leftovers; no file joins the list), built on main
  // 7134a8e9, rebased on 4da63033 as ac9056fa (reviewed at ed272277); its review R1 fixes (the header's wording; docs and tests only
  // otherwise; no file joins the list) as 15f1d937, main's identity at 0de64259.
  // NC12, the Object.hasOwn coercion sweep (a string check before each coercing lookup of a profile, run or suite value the evaluator
  // decides on: an app-log rule's vocabulary, the audit-file, egress, provider-feed and SMTP witness actorIds, a catalog record's engine,
  // a webhook suite view's, driver key's and record's provider; no file joins the list), built on main 0de64259 and rebased on 96f15d25 -> this identity.
  // Read-back in HTTP checks (ROADMAP v2 item 2, lane O): a pg-snapshot table may declare readBack, a check names its tables in
  // "readBack", each judged by judgeReadBack over the sealed record (data.readBack), fail-only on a boundary; src/http-readback.mjs and
  // src/pg-readback.mjs join the list; built on main 42a10d62 as 16732dae (reviewed at 6fae0b7d); its review fixes (a value-free sealed view
  // that keeps a clear column's declared value and binds it, no digest of the whole declaration, the reader's error codes only, mirrors
  // skip a read-back check; two-identities.mjs changes, no other file joins the list) as 10051cf2 (reviewed at 07bd381d); the
  // review (the profile and suite digests read a read-back declaration through its view; no file joins the list) as b1c4a90d (main efdcaa98).
  // FIX-08 (SURPASS-BYPASS-01 M3 A-xrec: another recorder's destination. Each egress recorder also reads the destinations the run's other
  // recorders declare: a send to one is recorded under it, a send to its sibling adds it a scoped entry, the scope and run record publish
  // them as cross, a window holding such a send can see that destination, and settlement reads such a later window too; egress-recorder/13;
  // no file joins the list), built on main efdcaa98 (b1c4a90d) -> aa3566f8.
  // N6-E1 (predicate records: each json.equals, json.exists and json.notContains keeps its field pointer and a keyed digest of
  // the configured and observed values, or both values in value mode, so verify_verdicts.py can recompute it from an export;
  // the validator recomputes each record's outcome and texts; no verdict changes; contracts.mjs and http-connector.mjs change,
  // no file joins the list), built on main 93d25fd4 (aa3566f8) -> 717bb581. Security review F12: the digests are keyed with 32 random
  // bytes per run that no run or pack keeps (or SCOPEHAVEN_PREDICATE_KEY), not a public salt in the record; contracts.mjs and
  // http-connector.mjs change, no file joins the list -> 81c15901.
  // pg_net on the wire: a pg-wal observer may declare pgNetWire { container, credentialEnv, programRoles?, image (by digest),
  // witnessWaitMs?, quietMs? }, validated in src/contracts.mjs (the witness credential never an actor's or the REPLICATION role's;
  // programRoles 1 to 16 distinct role names; no file joins the list), first built on main 8ecfe737 from b1c4a90d; first proposed without
  // programRoles as 6ef2b2a4 (never on main); as first reviewed at 87d3c7c7 (8e9483f7, never on main); its review fix (the witness
  // credential is never another observer's either; no file joins the list) as 7c862b18 (reviewed at 24fc85a4, never on main); the connector
  // gives a pg-wal observer its wire (startObservers, attachWire) so the observer factory stays unchanged; no file joins the list) as 570b3f58
  // (reviewed at 6539c66c and 5a3518c4, never on main); the declaration conditions (pgNetWire.requestRoles, a pg-wal window's
  // declaration sealed by collectWindow and sealWindows and checked by validateWindow, the report's pg_net custody declaration; no file joins the list) as 7d82f950
  // (reviewed at 9e172d06, never on main); its review fix (a checked declaration names its request roles and what it refused) -> 15b571da (reviewed, never on main); merged with main 30 commits later (FIX-08, aa3566f8; no file joins
  // the list) -> 974e4507 (never on main); merged with main after N6-E1 and F12 (81c15901), its pgNetWire image now required and
  // named by digest only, as the tap requires since security F4 (no file joins the list) -> 015af8ab.
  // L8 fix 6b (exactFor: a quiescent pg-snapshot xmin window decides insert and delete absence; no file joins the list), merged
  // with main cb7e9efa (015af8ab) -> this identity.
  "httpEvaluatorHash": "a5bd87760ff72371c8b6df855604515ba91597488943c07b20e17bd238840f0e",
  "syntheticEvaluatorHash": "126abb46d501270869b7da0b8a57c61ffa93579933955c6ca02923c122d247ef",
  // NC12 PR C, the contract evaluator's coercion fixes (src/contract-synthetic.mjs identityMismatch reads an attempt actor only as a
  // string, which also keeps readTarget from coercing it; src/contract-http.mjs httpVersionOf reads both versions only as strings; no
  // file joins CONTRACT_SOURCES): 08166764 (refused: every contract view is projected from its run when read, src/contract-views.mjs and
  // integrations/evid-bounds/bounds.mjs, and no code reads a saved view's contractEvaluatorHash back) -> 51c7d84e. Four comment lines
  // of src/contract-synthetic.mjs reworded, no code changed and no file joining CONTRACT_SOURCES: 51c7d84e -> this identity.
  "contractEvaluatorHash": "5dd9519fb12ed8697b6580a54d4c7d78c9069199133b8190ef3e0b27414e29b2",
  // src/conversation-native.mjs refuses a conversation with no trial (no-trial-recorded), more than 50 trials
  // (trials-out-of-range), a rate policy outside 0 to under 1 (max-failure-rate-out-of-range) and a run with no
  // conversation (no-conversation-recorded): 69ea63ca -> this identity (9e0f984f with the zero-trial rule alone, unmerged).
  "conversationEvaluatorHash": "7763dcba0d476fb27dd32cc7d8c2f35b1d017111aa767c72e28c873baff72edd",
  "suiteHash": "d8f385a80cf1206f709881eca7502432f05828d64dbb9738cfdf130059a442c2",
  "policyHash": "f450ae2c7fe3045e56281b2d37369467d9803b9a8b715f7b3a0deb91561582fa",
  "fixtureHash": "5df3c877bcd8cb91f1ddafd9ef21a45b38e151ef395a10c439b1819204dbc1dc",
  "adapterVersion": "loopback-response-contract/3",
  "identitySchema": "scopehaven-model-identity/2",
  "tapSchema": "scopehaven-model-tap/2",
  "attributionSchema": "scopehaven-model-attribution/2"
};
test('HTTP capture moves only the explicitly reviewed HTTP evaluator identity', () => {
  assert.equal(HTTP_EVALUATOR_HASH, PINNED.httpEvaluatorHash);
  assert.equal(EVALUATOR_HASH, PINNED.syntheticEvaluatorHash);
  assert.equal(CONTRACT_EVALUATOR_HASH, PINNED.contractEvaluatorHash);
  assert.equal(CONVERSATION_EVALUATOR_HASH, PINNED.conversationEvaluatorHash);
  assert.equal(SUITE.hash, PINNED.suiteHash); assert.equal(POLICY_HASH, PINNED.policyHash); assert.equal(FIXTURE_HASH, PINNED.fixtureHash);
});
// Earlier evaluator identities: main before write methods (3ddd9b2c), before capture (bbf7ba64), before
// effect.only (5994280c), before core batch v2 (cc13de98) and before core batch v3 (44b0962c), core batch v3 as built
// before its review fixes (48395264), core batch v3 with the review fixes before round 2 (096fa8a0), core batch v3 after
// round 2 before round 3 (4ee0a6f4), core batch v3 after round 3 before its final wording (05157d9a), main before the
// fast-loop fixes (0808f8f5), the fast-loop fixes' working identities before their final pin (834ad730, f4225919) and before their
// review fixes (94bc3dad), before their review round 2 fixes (a82c0032), a round 2 working identity (615a30bb), before
// their review round 3 fixes (ec1f94b6), before their allowlist redesign (5c256b66), an allowlist working identity (ca3378f6),
// before their review round 5 fixes (b1edd55c), before their exact-sentence cut (19e8952d), the fast-loop fixes as merged
// before fast-loop fix W2 joined them (df92d63a), fast-loop fix W2 before its review round (8576ee81, unmerged), before its second
// review round (f447da31, unmerged), before its third review round (35097acc, unmerged), before its fourth review round (8bcd8670,
// unmerged), fast-loop fix W2 before main 5e3e7f2 was merged into it (ada45927, unmerged), the merge before its integration
// fixes (b8a39508, unmerged), the unmerged G1 prototypes v2 (80fa9b43) and v3 (17aab62f), main before readiness gap 4
// (978b03ed) and readiness gap 4 before its egress-rules comment (6793b6a2, unmerged) and before its review fixes (f70af2dc, unmerged), main before readiness gap 3a (c2c2467d), gap 3a before its review fixes (098533c7, unmerged), main before E2 (f4aa9e46), and E2 before its review fixes (fec1822f, unmerged),
// readiness gap 5 before its review fixes (7282547d, unmerged), before main e49ea20 was merged into it (b8d61e4b, unmerged) and before main d349c7c was merged into it (45abd901, unmerged),
// readiness edge E1 as first built (c49641cf, unmerged), after its review round 1 (ca7f46f7, unmerged) and after merging main
// d349c7c (abeb4bbd, unmerged), main before E1 (7e3b9744), main before E2b (5fc2197e), and E2b before its review fixes (5ea6afc2, unmerged),
// main before readiness edge E3 (024d300d), readiness edge E3 before merging it (968a9031, unmerged) and before its
// review round 1 fixes (5b0575a5, unmerged),
// main before readiness edge E3 (69043c96), and readiness edge E3 as built (968a9031), after merging 42605f7 (5b0575a5), after review round 1
// (8aa7d5be) and after merging f6d0b44 (e1a81e00), all unmerged,
// main before readiness edge E3 (2327d138), and readiness edge E3 as built (968a9031), after merging 42605f7 (5b0575a5), after review round 1
// (8aa7d5be), after merging f6d0b44 (e1a81e00) and after review round 2 (b43cf65f), all unmerged, main before readiness
// gap 1 (e2c5c818), and gap 1 before its review hardening (f4ff6eee, unmerged), main before control claim rules (7c0265cf), and control claim rules before their review fixes (a4e8a658, unmerged), main before control positive effects (fef4548d), and control positive effects before their review fixes (d97b0c72, unmerged).
// Main before readiness gap 1 part 2 (51e0eb04), and gap 1 part 2 before its review fixes (8c7ed440, unmerged) and before its rebase on 4214451 (a86f8eb4, unmerged).
// Main before control settlement (be1b303a), and control settlement as built (15591ad2), narrowed (4009c698), merged with 4214451
// (d5bdbaaa) and after its review fix (8d2ef097), all unmerged.
// Main before effect.only keyed applications (8a2a297a), and that change as built (71905719) and merged with 7c1a45c (43e6b7f0) and with 208e443 before its review fixes (498850b5), unmerged.
// Main before settlement re-judge part 1 (7ecfd8c0), and settlement re-judge part 1 as built on 4214451 (25832eab), unmerged.
// Main before coverage v2 PR-1 (eeb71f87), and coverage v2 PR-1 as first built (3197f6ed, unmerged) and before its rebase on d6314af (e9673a73, unmerged).
// Main before coverage v2 PR-2 (5cf9b289), and PR-2 before its review fixes (9f2f242f, unmerged); its later working identities were never pinned.
// Main before identity option B (4c43e13d), and option B as first built (0fff55f0, unmerged); its later working identities were never pinned.
// Main before coverage Part C (a96bf37a), and Part C as built (9ffe4a53), merged with 23bbc9e (e9ddf694) and after its review fix
// (50a29796), all unmerged.
// Main before SETTLE-V3 (ce5e2a42), and SETTLE-V3 before its fail-open review fix (097e2e6f, unmerged).
// Main before the fix C follow-up (e9922a3c) (fix C host fit, 2026-10-12).
// Main before the E2a tightening (ce91a311), and the E2a tightening as built on 14aa373 (9807e097, unmerged; its working identities
// 27b3cee3 and ac0a2bac were never committed).
// Main before the effect.only countBy hint (0b4995da), and the merge of that hint (6b7119b5) before the provider feed.
// Main before the provider feed (0b4995da), and the provider feed as built on 14aa373 (0b739c10, unmerged; its working identity
// f9fddf9e was never committed) and rebased on 4108229 before its code review fixes (c5bb8591, unmerged) and after them (9cbd83f5, unmerged), and merged with 84c7008 before
// the shared recipient rules (16b5d554, unmerged).
// Main before the mail alias fail-open (27117278), and the fail-open as built before its review fixes (5100cd04, unmerged).
// Main before value-leak (2280cd02), and the value-leak branch of an earlier review (never merged): as first built (662e767c), after review
// rounds 1 to 5 (e188440a, 41bd7d4e, cec49e1b, 0288b65c, 0621da5f), the allowlist redesign (cb2012cc), its merge with 5e3e7f22
// (b6eead6c), rounds 7 and 8 (9845d4ea, 2614fbfb), its merge with b83051d (a65fe6e9), round 9 (72a1291b) and its adversarial
// passes 1 to 3 (f7e5832b, 62408a7d, ae3ef577).
// Main before LATE-FIELDS (3dc2318d), and LATE-FIELDS as built on 86e8f15 (ba932b9e, unmerged) and after its fail-open review fixes
// (ba0d7c0b, unmerged).
// Main before provider feed v2 template binding (976a6025), and the binding before its fail-open review fixes (642cec4b, unmerged).
// Main before verified signature headers (043bd057, after provider feed v2), and b' as built on 85be010 (c3b44482, unmerged),
// before its fail-open review fixes (54359d6e, unmerged) and a working identity before that (badd9844, never committed).
// Main before app logs (98f0add4), and app logs as built on 85be010 (6705cce2, unmerged) and after its fail-open review fixes
// (8e9aab75, unmerged).
// Main before provider feed v2 Part B (eccf8c35), and Part B as built on cddb4be (cc320407, unmerged), after its fail-open review fixes
// (583cc84e, unmerged) and merged with f89c464 (972e733a, unmerged).
// Main before the unknown-field allow fix (788bf36f, after provider feed v2 Part B), and the fix as built on cddb4be (4fc930f3, unmerged),
// merged with f89c464 (a0698a4a, unmerged) and with 7a329e4 (70b96baa, unmerged).
// Main before app-log admissions (635074b8), and PR-1b as built on 7a329e4 (e01b2d6a, unmerged) and merged with 76908a5 (547f9afe, unmerged).
// Main before the JSON decimal fail-open fix (46d4b6da, after app-log admissions), and the fix as built on 5c3b3f6 (46145eb1, unmerged)
// and after its fail-open review fixes (39ee67ab, unmerged).
// Main before app-log admissions PR-1c-1 (c4276699), and PR-1c-1 as built on 742e422 (882b3720, unmerged) and after its fail-open review
// fixes (476b614d, unmerged).
// Main before provider feed v2 Part C (8f3c2d29, after app-log admissions PR-1c-1), and Part C as built on 5c3b3f6 (cfe135d9, unmerged),
// after its fail-open review fixes (cb9cf49e, unmerged), merged with 742e422 (cb477520, unmerged) and with 62342fb (12186829, unmerged).
// Main before app-log admissions PR-1c-2 (e6416d94), and PR-1c-2 as built on 14815de (0add640d, unmerged) and after its fail-open
// review fixes (d85763b6, unmerged).
// Main before form decimals (7d3f404b, after app-log admissions PR-1c-2), and form decimals as built on 62342fb (888ca353, unmerged), after
// its fail-open review fixes (27987482, unmerged), merged with 14815de (0424cd09, unmerged) and with 70917a4 (9b9a2d97, unmerged).
// Main before later outcomes PR-1 (1137a358, after form decimals), and later outcomes PR-1 as built on cc9b681 (2fddeeee, unmerged) and after its fail-open review fixes (cbd32ec3, unmerged).
// Main before later outcomes PR-2 (9c332e56, after PR-1), and PR-2 as built on 290b509 (f0d350d5, unmerged) and after its fail-open review fixes (fbff4cd3, unmerged).
// Main before absent fields (95e57520, after later outcomes PR-2), and absent fields as built on 39c45ba (8a3e32f4, unmerged).
// Main before suspend-aware custody time (d66ae4d2, after absent fields), and suspend-aware custody time as built on 39c45ba before its
// review fixes (c63f9966, unmerged) and after them (0b71f0b3, unmerged).
// Main before suspend-aware awake truncation (a5308153, after suspend-aware custody time #340).
// In-doubt resolution IDR-0 as built on 39c45ba (0f09a3ed, unmerged), as first pushed for review (f4f00bf4, unmerged), after its first
// review fixes (df860cb6, unmerged) and after its re-review fixes (e31be590, unmerged).
// Main before in-doubt resolution IDR-0 (0f17f616, after suspend-aware awake truncation #343).
// Main before in-doubt resolution IDR-1 (9040bb98, after IDR-0 #341), and IDR-1 as pushed stacked on IDR-0 (12860425, 0e25390e, cb328074,
// c0ae487a and ae7b5a48, unmerged), and IDR-1 rebased onto main before N1 (1f5ea353, unmerged).
// Main before the suspend-aware lead-in and stop (5b42796f, after in-doubt resolution IDR-1 #342), and the lead-in and stop as built on
// 86c8a96 (bbf012c1, unmerged).
// Main before in-doubt resolution IDR-2 (3ed66f46, after the suspend-aware lead-in and stop #344), and IDR-2 as first pushed for review on
// 61adb01 (f7908d21) and with its review fixes (fd2b1364), both unmerged.
// Main before the suspend follow-ups (33449ad9, after in-doubt resolution IDR-2 #348), and the follow-ups as built on 4f2d57d and merged
// with 8eaa589 (af37c38b, unmerged).
// Main before in-doubt resolution IDR-4 (cff0af99, after the suspend follow-ups #353), and IDR-4 as first pushed for review on c8f8bd3
// (eae0b5ab, unmerged; prepended, as PR363-REVIEW asks).
// Main before SB-W, the allowed-use guard (2896464d, after IDR-4 #363; prepended), and SB-W as first pushed for review (8403be45, unmerged).
// Main before in-doubt resolution IDR-3 (2896464d, after IDR-4 #363), and IDR-3 as first pushed for review on b33cd26f (8ba1b0a1,
// unmerged; prepended, as IDR-4's was).
// Main before the merge (d47576d9, after SB-W #382), and IDR-3 as approved at 5bdc0047 (3a851154, unmerged; prepended, keeping
// 8ba1b0a1 after it).
// Main before SB-W2, FIX-02 and FIX-06 (430010c7, after the IDR-3 merge; prepended).
// SB-W2 as reviewed at 0f69d16d (dd1b9f7e, unmerged; prepended, as IDR-3's was).
// SB-W2 as reviewed at 004a0c95 (c625aede, unmerged; prepended).
// SB-W2 with the D1 fix alone (470b0f49, 579b3896, never a reviewed head; prepended).
// Main before FIX-04 (7569cb54, after the SB-W2 merge; prepended).
// FIX-04 as delivered on 004a0c95 in patches 0001 (d4f5fe1e, 6cc591a4) and 0002 (905188f9, 53afbf02), unmerged; prepended.
// FIX-04 commit 1 alone, on 5bbe66b4 or main 0bdc7e7d (5c657ca4, before the MPL-2.0 file split; prepended).
// FIX-04 as merged (85374c7a, main c5515273, before the feed drain's quiet confirmation #430; prepended).
// Main before the unresolved-send rule (4dcc9345, after #430; prepended).
// The unresolved-send rule as reviewed at ed682136 on main 0bdc7e7d (afcf711e, unmerged; prepended).
// The unresolved-send rule rebased on main c5515273 alone (27cd4c16, a7e85652, never a reviewed head; prepended).
// The unresolved-send rule with its PR429-REVIEW fix, as reviewed at 44cadf60 on main c5515273 (e1ab95c6, unmerged; prepended).
// The unresolved-send rule rebased on main ae769185 alone (4d425a87, e0ac6be1, never a reviewed head; prepended).
// Main before the egress drain's quiet recheck (64fcd098, after the unresolved-send rule #429; prepended), and the recheck as reviewed at
// 616f9e18 on main 2cbec065 (7e5ea134, unmerged; prepended).
// Main before the pg-snapshot collector identity (aadc0ca9, after the egress drain's quiet recheck #431; prepended).
// Main before H1 step 3 (c99a89ae, after the pg-snapshot collector identity #435; prepended), and step 3 as reviewed at 3e049987 on
// main 7c931ae3 (5a8f8fc5, unmerged; prepended).
// Main before H1 step 4 (831fa88f, step 3 rebased; prepended), and step 4 as reviewed at 6a045df8 on 3e049987 (cf1cbf1f, unmerged;
// prepended).
// Main before the self-change lifecycle (3f4f9c83, H1 step 4; prepended), and the self-change lifecycle as built on main f424b18d
// (80eac864, 4340f499, unmerged; prepended).
// NC9 item 2 as first reviewed (d72d2f7e at ff1318df; never on main; prepended).
// Read-back in HTTP checks with its first review fixes (10051cf2 at 07bd381d; never on main; prepended).
// Read-back in HTTP checks as first reviewed (16732dae at 6fae0b7d; never on main; prepended).
// Main before pg_net on the wire (b1c4a90d, read-back in HTTP checks; prepended), and pg_net on the wire as first proposed without
// programRoles (6ef2b2a4; never on main; prepended), and as first reviewed at 87d3c7c7 (8e9483f7; never on main; prepended), and its review fix at 24fc85a4 (7c862b18; never on main; prepended), the connector-attached wire as reviewed at 6539c66c (570b3f58; never on main; prepended), and the declaration as reviewed at 9e172d06 (7d82f950; never on main; prepended).
// Main before read-back in HTTP checks (d563a9f7, after NC12's coercion sweep; prepended).
// Main before NC12's coercion sweep (15f1d937, after NC11's mirror phase #525; prepended).
// NC11 items 1 and 3 as first reviewed (ac9056fa at ed272277, #525; never on main; prepended).
// Main before NC11's mirror phase (f228ce9b, after NC9 item 4 #521; prepended).
// NC9 item 4's PR521 round-3 fix as reviewed (5d501549 at e5bd2246; never on main; prepended).
// NC9 item 4's PR521 round-2 fix as reviewed (b42302c7 at 61bd6801; never on main; prepended).
// NC9 item 4's PR521 review fixes as reviewed (d25bdb2b at 8e369fdc; never on main; prepended).
// NC9 item 4 stacked on NC9 item 3's round-2 fix (97237b44; never on main; prepended).
// NC9 item 4 stacked on NC9 item 3's review fixes (2f680930; never pushed or on main; prepended).
// NC9 item 4 as first pushed (c93b49d1 at ac92e375; never on main; prepended).
// NC9 item 3's round-2 fix (3a7f10c7, the identity NC9 item 4 is stacked on; prepended).
// NC9 item 3's PR520 review fixes as reviewed (c23c314f at 70539912; never on main; prepended).
// NC9 item 3 as first reviewed (3cd97fe2 at 7f3cc65c; never on main; prepended).
// NC9 item 3 as first built on d72d2f7e (f6b7996f at d3af51f1; never pushed or on main; prepended).
// NC9 item 2's review fixes (a12153c6, the identity NC9 item 3 is stacked on; prepended).
// NC9 item 1's collector labels (17b927f6, the identity NC9 item 2 is stacked on; prepended).
// Main before NC9 item 1's collector labels (1fdf1bd2, after NC2 item 1's two identities by default #512; prepended).
// NC2 item 1's own working identities as reviewed (79f75dfa at c3875379, 1b4e4144 at 136068d3; never on main; prepended).
// Main before NC2 item 1's two identities by default (3002c6d9, after the N13 catalog identity #500; prepended), and main before
// that catalog identity (450e5445, after declared channels #490; prepended), which its move left off this list.
// Main before the declared-channel wiring (e760747d, the signed-webhook wiring; prepended).
// Main before the signed-webhook wiring (93ab8acb, the self-change lifecycle; prepended), and the wiring as first proposed at 1f6d9f33
// (54e6cb89, unmerged; prepended), and its first review fixes at 577040e1 (abbe8511, unmerged; prepended).
// Earlier conversation evaluator identities (69ea63ca, 9e0f984f) are pinned incompatible in
// integrations/conversations/gate.test.mjs, which builds a real conversation run.
// Main before FIX-08 (b1c4a90d, after the read-back lane's merge; prepended).
test('an earlier evaluator identity cannot earn a compatible comparison', async () => {
  const profile = { id: 'hash-stub', name: 'Hash stub', applicationId: 'hash-stub', origin: 'http://127.0.0.1:4318', buildLabel: 'same', contextId: 'stub', actors: { anon: { principalId: 'anonymous' } }, requiredControlIds: ['allow'], checks: [{ id: 'allow', title: 'Allowed', category: 'Synthetic', severity: 'control', actorId: 'anon', method: 'GET', path: '/allowed', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }] };
  const run = await runHttpAssessment(profile, { env: {}, transport: async () => ({ status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 }) });
  for (const evaluatorHash of ["81c159012aafcc3ad1750d956dbdbdf7148227354d3c98ad97d109b5c130da87", "974e4507082e5d6b2ba36dc4ca19bf2ec3ceee9d3e31710a1e4af92e266c4968", "aa3566f8de446fac8b47910c6605d3b2defad973adde924af3c7c4cacce526e1", "15b571da5c16b4d1c083f557a7020edda1d48b03dd3cc6d42cb14baf84073078", "7d82f950234fade9c6c220a218f040f553592f359ed62d7803406d21124a0b47", "570b3f5883b8bdb7e503c066f6e32a275fc8dd179c0e74727e093c089ea2b3e8", "7c862b1879b32da2f4b83090c50fa1a9cbba100a1626b13964a449a7cc80fadf", "8e9483f7805e8f09d6420148507bb9abd35e53f77381008bf12f19b241cd311d", "b1c4a90d0b49fadc0a11da2cf87d81dbad5893e60cff301aee17cbeabd1ab5d4", "6ef2b2a4deebb04cd33978cdafd424aa991dd88e8d0e20b2b95e94d924a3dc20", "10051cf232560d6dc33eda2a7d9abf7c07ef0ab5f41f2b8b0196e83d764c6ab5", "16732dae569afbf81b4a65269a0c58a769859304c2d2670d22e8c1cd6a7ae42a", "d563a9f71ab83e4e798df807b3fb793b6101525f6113e95ac2a76c56d7e4ecb6", "15f1d937828a478b33e4ac684477e0a2cdd27c49db91e1b7fcb04f8c1a03d612", "ac9056fa922875161acfa05d66ff2868ac9b7e0722df14c3ba06b0b437635fde", "f228ce9b23b2782b491bafb6b3b69fca88024ec5b6bd29c70dcae3335656b679", "5d5015497db969d9a0aedefa0510415d08399926764bd508d1dfab6c8be84108", "b42302c7e50394c10bc689e532dd7a338373645586d06128f9fa12f794149c7b", "d25bdb2b81aa7a5b3164a2a90b60804fdeae4a991df210f54dd4f98adcb38aac", "97237b446fc9ba1405bbf418ecfbca649a72a013399e5c83a4a8c1aead2786aa", "2f680930c4d90cd261be39447ed422a8c41229b81df82cafc8152d2a9c70c5a3", "c93b49d157233b855cbab4660420c4814f38c5ad8d8a8c13c138879a10d81c44", "3a7f10c7bacc6aeec41a347a546958e4894b8acf7e55ecb3b4f4211d2937a884", "c23c314fcae2d8cb5dbabd5a85707b93a0f7471b4ea72d68d8c26b62f429623c", "3cd97fe248aa8d8fe0dfc2f99f55e29bc94f6851b6c9c065c8a782f1c51622cc", "f6b7996f58835b6a0b102636ecafe698a8684ad599f83ec500339264c2cb291b", "a12153c658042774989af3f91e2975e3ea76b31fa5b487f31810a2dbabafe0ef", "d72d2f7e8704a5131d5bcb14dea3bb70bdfeb5f10f7f7660f75fb5ed673ad4dd", "17b927f6bdb1801f3190b79b0e684e3ac49ee942d8ea96836e07a89d103fd6d5", "1fdf1bd2b3691162a9d0744de6f2d260cb422b519af86877ebab306584e61b10", "79f75dfa1bf0e79057ce862192baa6fbcb6b0a6a47c9e887b6d8854c74683b0c", "1b4e4144e6774a4db7f529e632746b0e25d6d010fd9fd958db54e1f7f0a1b43a", "3002c6d9cdc59563353e876722472d2548443a4e23eefdda32235abba26ea246", "450e54456a3be41a8bf52742a598e97706bdcb43b0ec7ad977f39f0cb4101c03", "e760747d04e642aae21ba65647439e63ebe18b9b3be85fb4d3375d5b085ad04b", "abbe8511463c45697d1ff8469b615d224d635a41b7fc76d6a828f8da316dbaec", "54e6cb8933fab43610b900c1e323220055c86dc41d09a1691c0e45ccec94678e", "93ab8acbea61e99349ed36fb00ec8c1c49d3b1aa4212d7472ce0f0a900b13d5f", "3f4f9c83ff57c91b993593b4696d850e97f62a39fe4c017964224d1dd1546ad7", "80eac86445068415b92db535a4bf04192dc32b542fb81edad1b3195e2fb4ebb1", "831fa88f187f270411c46d45745c768b461e11b4cca3b53c8b633d1ec945fdb5", "cf1cbf1fa0626051b903648a6e9dfb8e40b35bcf5ba757ef66ec202f5359aee0", "c99a89ae0250e5b2192c24d4b65c4093b6b9c056c33ab21a890305963bec991e", "5a8f8fc5e21c93d785a8836ce4e5559cc4ab63ff58b1acdd5b2d518651ef2978", "aadc0ca926e62d1346098ddfcee546704a3b5c73baa5a8f5bae656ea5879f059", "7e5ea134f1451a623a9c85c1b02047a393c962a48f720898f839bf0807928bbf", "64fcd0988344b8f484d3796ddda7d91b5fbbda8ee4b81f1d3d06b1229c8191f5", "4d425a87518e413c15d168066014a655bf211328261ae03b4ec449f9ea004516", "e1ab95c654c0e060ea3d3856821d6d7e86b9c2de2dd6b9529d41595290dd9afd", "27cd4c16edf8d843bca4e77e867c0d73f7150bc5c9e35fa3ec0a6b12dcdc69ab", "afcf711e19edd9f41a8c76e7fd986ca80b1b0a1ba7113642c4f1bb9626a1e900", "4dcc9345bc2338e477262d5ee33c8eaf3ff508c6523773da15c69365f27446e8", "85374c7a08c332315b1be90394ae5af3403e23ba3c102e3c6b473b3575f5f1e9", "5c657ca4bd035007b60980d6d6a8870932b71d7d7300fcc70973830f718d5857", "905188f9e9b9cf038ca25703caf84f642c751bbff6ddf0cc679f08e2823b3bd4", "d4f5fe1e2ecefda6ba59dedb20410ea1fd62f17b2e8eb39a75f49658afc15eea", "7569cb54014a7a816bf61f1fa257c28096810c7051f0ca499d7b5eb2a3530cd1", "470b0f491e0ab46834f79cd4a4a676d5d1a31962ca04ebdc98e831209f0d713f", "c625aede56528a6ab259e47ad9cb5cb278a91be1fb3144ea2284dbbbcf43dd0f", "dd1b9f7e6d45c577de88ce29621215389070eabe43c772b7c31d097ba48f4c0c", "430010c799408c2db192f86153f93daf56513681699db9f9302afbc27651a664", "d47576d9d3a06df7de91325b8f053b0618e078c6c22bb16c90fbd4bbf3a6fe1c", "3a8511540168d12ac8f3c578229a5802d47951fe5cda88de32adb616f3d21c40", "8ba1b0a1c76438c92e1fc2b1c74065663972e178b968fb1b38010aade79093c4", "2896464d1c7262e5814b6a5fa7815d653f45402becf361fec52f91c869ddfe9b", "8403be459379d2b1df31d9c8351fc1535744b42a98dfe8fc4cff43b0edceb718", "eae0b5ab322393fdfc619ab713340884d7ed9df3b00db77263a5a5959d5033d1", "cff0af99943f1ef3a584adfac14b912093820a903f5200aa25a048586207298c", "33449ad916c0d8a13401a613977517305f0f48acc8e166f3778d4e3503c60535", "af37c38b384dd5db130b4ccd3f3ee50de8ed96196821eac9c8b974da07823b26", "3ed66f463c4eee5fecd88fad9b09335d76918991ccf8654f4e50e4c19aaab34a", "fd2b13649c262ad93cd5618005d14880053f88187db54c9a1670a4846d5a1f1d", "f7908d2173c0f7cc63d7c1124bd02730fc0cd01137a2cf606b169c5b957e2cad", "5b42796ff7c5ed58bd1d01c347f8c0efd2b56735288a40996f3ba98f48bd41d3", "bbf012c155fe2159a47d5a0152bde4a05f40bed2a7d0716377aee3f74c066646", "1f5ea3538d4cb382d828a641b4a031409a30ac03b47cf255eeb6dd4263b5084f", "9040bb9837c2f586c11286c86bc4abafa0ba93a18fe3f697908e1361febbdb47", "ae7b5a489bf9f1d3a8371fe37b0172a11e0808e6e4fe8b3a06f53fbeec6d1227", "c0ae487aa31ad3358232871fcde111106a9281b147677e870e32e8258b345e87", "cb3280742375116c8421f2ae9f8eb8df16dc8475e66541da5769fa95ef3d2b2d", "0e25390e7fc9fce1968c6a969f8b9357db57fda16bb54d5a65fa5643fdb16de3", "12860425d50190b536d87535ee1b56338912450bf3d3d4902ea207906d07dfb4", "0f17f6165c894d51bdbf95ea05b555fd044d3d6a460bcc01a181f9225dfe9a90", "e31be590be90738ebb3f38d87fa8588bbb82a113c3ba61acdfbe183c29e927ba", "df860cb614ceb90a958c02138763e7ed095fd374b943daa97b00273f5bf71d21", "f4f00bf4e18c5fa737c59cf71456190c8f795cbc8cc8a21932c1518ca9f38acc", "0f09a3ed15c29defd10e40b905605a090ad689310cb20143aabbea03885e020c", "a5308153890c7a8516bcf2c34c276dd03b9ece03ee1e420622e6e32a4a84958e", "0b71f0b34facea029e3a86ffda4e2ffc7f0f1ce618092da590d983a7224a25f3", "d66ae4d28c0cc8721cd048330fd11e9c918e7c8f68dc4e2267c15fab0552a077", "c63f99664ffe058f572def4197e4d2d3159e9280fb49d7767d438a298e21a3ad", "8a3e32f4b9eec6ae8121046491378daf2a9f5bd8203dab243346a4908e0af75a", "95e5752046bd80bd286abb9c403c9619e895cf771167bb1076bcef9dce1abce2", "fbff4cd3733cebee0e9753b75171ce301d09067564d66143956d2e1f91ddc0c9", "f0d350d576a3fc9916453115ae85f71a92714b983ee58516f23ffb27aefdefb6", "9c332e56efee056976d7dfb23a85d5513a907754bbf44db724f822c96592be9e", "cbd32ec3bdb5891b24b64cfa6dbe20ac833ac19ae78b8f7fe1a6b621ef926a3a", "2fddeeeed186ecb0d4a2c521f12f9d9663dfcce6c47e12bdea8a2f89846478ba", "1137a358ee46a9059ea6a05a5a364f115fdbdc7d1dfe9f0f3a5d7e50e59881e7", "7d3f404b00d47d8853ae0901796f1e0acc9b924be3db5ed7a4ee053879fa806f", "9b9a2d9798b288c1984032c6b39ccffa899ed5da7009b18a78c1b1fe4d4e35c1", "0424cd09e9f3aaf12df7e0c3de974d164d2c55dc344aa25e576086611ad06797", "2798748206b8a7c3cfc6e0acc3a381c62f17a2f03ca2f7535ae34b19b96d6474", "888ca353fc29a5834a369185cc56d5c67f193803ae192fef5ab62827387c201f", "e6416d949e5e1ebdd3a6b940eb2382dbb22aefd05841b6521df86e0e3019f8be", "d85763b6388b633c0b52b0961e0c705f9a92d2897d226e7a7facba6e52672511", "0add640d379249c606a13c3068c8ba2da012dbe32410706594dd4756d4c9f461", "8f3c2d29be3cb75c362f06fe069a8f8212d774397074561da0c3bb5679f1ccca", "121868293555b5bfe163fec55e7bd671dad82f4086bb05b66022138ba5735e5f", "cb477520a638da77926ac129a700996f3f608ff292382e2c4db900e9b22176f5", "cb9cf49ecc1d810a691f5c0d12d29c24477611057f44347c4f13119e868363e7", "cfe135d91ad19b62916ffc9329dd87db64e9114015e7655eba345892e2c1a735", "c4276699fd1d1bef69a7613a9f7557f233b42c735fd45dc58aaba41be0f2e41b", "476b614d21ff41f266c1178e0d2038c76aeb8d382fc196fef8ce63399b7085c1", "882b372039327b80d76b02d21fd71744a3985ab31cee3be65af41af300ed5dac", "46d4b6da1daacf0bb002063dbb7c23db1d406c9061232072db221ea87d1cccfa", "39ee67abdd467f6da895665b8022b571ee715c8c4a73cf223560682371342d33", "46145eb1aea16d8a58f64f7d26df9e4f485c075e9f921f4fbb9889ba417ef78b", "635074b800a616faf22c3d61312e58759fd975de54e9f32a9b4cc75e80dd5801", "e01b2d6a1fc8735bf8796332f3c1df6a9043162e90ce46a9d7d5de304105cadc", "547f9afe9e2d15dcabd185ba926dea9f9c40668a08b790e609f57c0bf15ee794", "788bf36f52ad1d4d938b3bc0195d7b90c51d49c20fb90c9b69eb3197189b1bf7", "70b96baa6deb2d7bc551ac722ce0ff873ccc04a812bf0d3e3f2af150051c464b", "a0698a4aa046d4ed4b5a7c2cba2316e1c283626144e719b7fcd1576a5b8afd1a", "4fc930f397aefba2c08a43dd0f5884f5a8076ae16429a27bd2edcbcb33e73da7", "eccf8c35b37c1c964e564b41c64592ea2178b1f1f879ccfd33660775bed55739", "972e733adb0f9ac039b094530994f97b889e9120e721e126dc70d277fddc7309", "583cc84eee5b9154f9389bf05ec76ed0ba0b2133d0e7f572129628a228476767", "cc320407cd302c4f5b66109a80ab934277b97c876507c3ce6bb46c8733563e97", "98f0add44f122e8ccaae8f1f8e87199760ec8d144c7eb1868fa5fe641fd0ac0f", "8e9aab75cf3b1e02ae4dd56c5d0fd4b73bd9592c66c6eee6663357558121ec99", "6705cce27ce2f5ec4f74b7bc488601d385c8cbcf9cfb8184a634e175318efbe1", "043bd057e9e663a67072146012f88626bcde569283a3fcd8c12e936680077430", "c3b4448219b5a48917c45c0cb736bf476555f1a75828a7e986bcd2de727a71de", "54359d6e8c2740d2c3fd8e4b4452ff523d58dced07ff7fff8c6c23f26668afc7", "badd9844ff301e6eeafde8076af915554e50b021c3c2f89573486e2b5c0d62d0", "642cec4b68e003950fc0812b1c753b93a7569a88b68ed0eab50bbddd24e965f9", "976a60253593e49c56ca518c40c2a1db38f0e9c2b7b65c10e25356385722aa4f", "3dc2318d4bf03c57fd629f6903cd99f1020087403bf2ca6060d8aed87c7e8bc1", "ba0d7c0b33b2c548b64af28b61c247eaf93716314c87ba6c4e0ebe2954f2366a", "ba932b9ec4a6066ee07c21ba5db07da203cce8d3bcae1667d2b47a1470551487", "2280cd020c9ec99b08efa837d1ac582738d37441a973e8bc662029bacb719c2d", "ae3ef577a5e460c99ae114ed480de83e20483db9bbc29438fd658ee0885cb9fc", "0288b65c86aa42e5f68ef330f606df04ed7cb6315cbafbc2d67aae2ef80f8ea1", "0621da5faa117d6e15ee7d38aac5bfde3a2475c7c740d83d7881a9b922a963c6", "2614fbfbb22cd4ce7abc37735620ec9c226ec9a696de1c2274bb697abf738cee", "41bd7d4e0296d60c7d428dfca3b7c7567d6563a2c916cfe5919fa1f94d923a67", "62408a7dd115ab92a6302464c49f089836b5d79cb33b4dfc4a042d1d695466b9", "662e767c62a15497693a2d275dafbaadf88c6017f2ae3382779c6b1d8195bb01", "72a1291b18ebbf0c56fcb38f8580cd4f534e4dc20cb1843290dd0f11160f1677", "9845d4ea02bb62bb4c745f5f270ec37328ee1c6b0ffc51e0a4020906412c47d5", "a65fe6e974bd73f51d477614e54d76d1deaa38d895a5799590f11c02c3f21298", "b6eead6c6803829715a561785c7caa93e4dca559f5a73b6592000adf7b546ca0", "cb2012ccfe7cf91fb3521db70fe9e4ada2ab96e56ec6c452d8c9b8a9c9d514e3", "cec49e1bdf7da08655e8126e3ca9cbc70d37c17fbea3109f3b37a89b711f0e85", "e188440a598670321711ea05f9dd2360177485b3f22eeb4ba3f6106bc3aa0d5a", "f7e5832bd3cd497af4cdad5616466465499b7f8f2120d6b7c5868cf8f15a97df", "5100cd04c4668657b9f1a35174a54b01ec4a4b17487434cb64b105cb6934a1f8", "271172784f17b4ba016ee48e961405f19c5d5afc7fd8413e10e98ec6ee7f7f56", "16b5d55413d5d3f74ebcbf4da79007e53f7f9fa656be46ba5fcb2275455f6863", "6b7119b535326b87ecf9bfa22ec322814e32272c134859b6faa1c68fb05401cc", "9cbd83f533e85bc30d551c254575f222db2975a00b4334c57d8ed5da0f758410", "0b4995da91505e73e4b85fb2c80c3dac3ba9854d6ea0202b3e6cd3c049bbe7a7", "0b739c10cff463dd2bfb9062b7323f18d0d3a4a6fdded608a7d4cde4dad677d8", "c5bb859194ac4bc079a9dfbed5ac056e736d7e19a3a921143e18982b3f9b63e9", "f9fddf9e0ed57ea1bcf259f14c804f9972b956f5c8ef8519baeec0d958bcdfe3", "ce91a311bd0e08962f69dfa420e2b2f121ed63e4980024333554c82630277afd", "9807e097617a2199ad41dd9ebcd3a788dda5746fd7110f538c2be7407c598938", "ac0a2bacb2649f33fe908ae24294fa967f1254994f638e2e884483485b37bcbc", "27b3cee36cb1ef721ee6e8ab4e6a9297ff1a269ba7fbb8af45832704a04bf219", "e9922a3c91d232195d4020efbf3ed1d2204ea7e5c026046bd95713a6dd7216ef", "097e2e6fb3ec63b252f5b3694826aa4f492e5bf12e8ab3736cfcb090a6a289ab", "ce5e2a424ba4ab9ab0487b989ea93581148a56cc1b1f5758633bf95afb6a3449", "a96bf37ae3c577e6def4dc2ce65854df957f6764594ac96c280c27d63275aa1b", "50a29796ffff7a5d338f89fa3ec8c8a84fc0d4bba6907c9d491014c69e2ed920", "e9ddf694bfffabcaad8644cb5ddbac2d5e16da3901c597610f7c8d4378278171", "9ffe4a53faec7c261a2a8b4f5979cf8569dc8c1dcea6e378c030cefda16fad49", "4c43e13d43c97ef521f09503b27d12fdbe53be12709e0e36ac59799a4f726963", "0fff55f0fc02acb88eb409350180373ee9e010f50da0343518e44880f869938b", "5cf9b289199defe11db14e8a151feb46fa482ec9a9c8bb0579d3b5a2f74f1378", "9f2f242f665d2538bc5b17d660d14e317997d8601a7f6f07709c4e996548348b", "eeb71f876f7ba106ad68e657ab8b7d22878834fa87894c930dfffe0b0f95e2d0", "e9673a73a2649de9d549a69fd52fef316b2955135629aaee057ba9403268f72c", "3197f6ed6b6f189205076841731be2b9f937650f38f7169c4b6b21a97df441e9", "7ecfd8c057b0379a642e4ad743b0d38cecd23140fbcbf8d0607a4bc5ae873505", "25832eab3557ecebec285e0ac353ba3d07be13432d7b67dcd2a962bab6988c2f", "498850b5fd51ef4f7338556b47dea997536da59382cbd214ca1a99ed57cd06b5", "8a2a297ae45178c168e7bfe62681872eee59b53e3dcf38c5c8afeae03480dd69", "43e6b7f012beab97754f813d6b0aaea07726e68185b9a45a6fecb012739643e2", "719057193e55bc966d43f16fe4df649dfea7e50c08cb01d917c83cf05086280c", "be1b303ab7f3d4b8da87cb19447de24e1b4a2a20e4d8f321ad9fd376e208c6ba", "8d2ef097aa2b3c46ddcdd16b3ec3cb974b5d911032625a7a56f870c755f82dda", "d5bdbaaab35758c94faafa0749752193a5f99fbe233918c7b76e7b8bf2bf34bf", "4009c698c5af2e3e4661e1012d1d66f7255b893bbfd28cfe0eea4262267e0d5b", "15591ad23733167915386fa4bcdda1836b4ee07bd336577fdbd7e17ea3c9abbb", "51e0eb04365ebebba639f528354f578d397d199ceeda451c12aef1be8a06b58c", "a86f8eb4da7cfa154f796f8f2bb7fca09b5a2564167bbe9bd174223e70d7b7f1", "8c7ed4406a394825393542da829ebd35781fa7aae9cb56919d6e72ac7fce881c", "d97b0c72ee5fa892d802943605938dd8acaf08e8e6bd4a7bff1b3414e1b0be74", "fef4548d3248ac28a3760938ec851f438478eb69eae4521e2453432074a3c63c", "a4e8a658e2a5ad62f32d16fb535974c545c8eba381d307523e85e097e13f61ae", "7c0265cfffbadd0f75d381f76a717ef216a58d01b4831419963e31bb61a36079", "f4ff6eee165c17441d22d6db587ac7b657a34bb04a6a6befedfbffa24a01b3e7", "e2c5c8184f1dfefc19e1900e10f028f5ce39a52f7f2b8f9ceafd4a1175127a44", "b43cf65ff5a526a6b98074b54a302f1ed1b692c063160ae067b97193d071c663", "2327d1387dfdf657e255fdce313e5e977f0cad7a8f9e05c09fb8c1885aba8a39", "e1a81e00dfce2c8e507678a45e11b3a941e0c5e135bdd880eda62a46e7822715", "8aa7d5be5daf5e40a7ce3f1f9d5dd24937a3648073b75a3a41cb83d8e592a6b1", "69043c966b016a3c283e19386914324be722977fb4c9beb6ec254c378d214e64", "5b0575a5e9d264d5858c5d93626d7a5468c99df2a4798dab764f054be346a496", "968a9031263d9e51f19e504bcd8c22c509d88b956ea6886e398107db87118950", "024d300d18bb42097fbc7dbc85af7c40d0b8db5874b110513e3c6baa77becf15", "5ea6afc2643432a12439420a7955777ac3ee36df468ca49d7bbe6288ba0af567", "5fc2197ecc36e2240c6b4e4dd48ebdd9fba31214205ee9b200bc044fcddb7246", "c49641cf77361db3d836306713210cce6e24f64b2bd4a377617e4d9709c24cbf", "ca7f46f7ba7880b8dc333bd2d2cff543eaaddab47c610c2a966c21f7db6c7b6d", "abeb4bbd986199b737bc9d9bde27f9748b981ed0bc4d66824f4376b0ef368498", "7e3b9744e8dd51a4df6cacdf55b7e1578b964ddc47a92675325cd8cb4e2975a7", "f1c9a94c0a0502cbc5266a71acb05044e0fb0598f066b30c1ad49a59bad02fbc", "45abd9019cdfd140fa360d256a6a46a4df54887ad919de5071f2d7e229f5946d", "b8d61e4bad08663fc24efa89260d743ce673f7f9b31aeaab9cdf73929af9cf1e", "7282547d14852a65ce4d3e32d2197ac40c57ad21329bd24d2ae0b71f6afb494f", "fec1822f3e799607092c1cbae039057334ff83c88e4e495b3be773883f82d8ea", "f4aa9e46d7ffed5e55488991efa8ee7ca7e1a75924257a5d00cd00995d8c72e2", "098533c7387f3a10bef43ceb362070f922e727c1b3a52b9d284165cb812d2ae0", "c2c2467dea9294e1b7008179be57c4f20b8760312ea0387a3532bf673e9bf58e", "f70af2dc4b9a5961ec3b70e8c96f825a29db6eb73049f2dad1d2792d77dc829c", "978b03edf92633b43ac0cc6bcfe67cdeb9e2f142de6d32aa3c8931120cfe4701", "6793b6a24c34b6392497bfb1bc15f70979ff4d3f15c15dc69a12f11b7a0a215c", "19e8952db0bb46ce6eb22e9e2bcb615d21a13860ab959c4a44bebae93023cd67", "b1edd55cca11e20b7083415cd367bbca82937460f2d4a2476c0aed9d02266233", "3ddd9b2ccaa97a2bbd778ea734d4950d9441a6d94967b414b92cb90f79bc4d9b", "bbf7ba641f3f1d89ee63002c919b763bace501133e050ee988ed7489ac575e79", "80fa9b43459baf18dc3a126551085227fc201fd0917f67fca32716f83e32b001", "17aab62ff3e9ea04ee647259c91b0f0fb876abd2b2db591fede4751ea07a0841", "05157d9a234b484be63b8dff9655cc71d3f7f2a3b0b8aa94ef8072cdf21cce6d", "5994280cf3329b343dafa3a276c120eaa001ba1306cc2c1b8016fed9ab2db756", "cc13de98c86c084f2b34f405198167bed86ea14690f95184189cc9efa56ef364", "44b0962c773224a528d9843e3ae05260528fc83e543ae52de91a610b00592cf6", "48395264d987fd1c39e3133b7271f71eccbe0bf1b9a308f7571633f779431244", "096fa8a0d2de6931332d02fb350600404eb5d72135ab7f2cfff9ebe2cc2dfb83", "4ee0a6f43b6343d62d9e47640342c7f820b525285f1735b10f8475a153e6ae1a", "0808f8f58b3f960443e6b9fc236c8ef04e9a0eeb8f11f1c485d6f5c713b337a9", "834ad730a015ff0797e866fbbf59adf9f91314354b19da3284b7404ceda43797", "f4225919e7d11817841ff9c4907c9f6fcf09f26057516b2122537586f14f205e", "94bc3dad8144c8806a2029efdb34d0705c46670551c5198ba65d98bc5dd2728c", "a82c0032da2c9486c5964fe517f43412278edcbbbaf3f624474ac519a8db7406", "615a30bb4ca3d2aa91c15ae9791ddf9c409457973567e0e42d58fdd0fa39bae7", "ec1f94b695b310beff43a84b44e994b0a39f32ee0254af9d5e65529f565fcf84", "5c256b66b2834961d0751859f0a92e846ae8477f8ade546584ce1e249a586756", "ca3378f65cc1648ba6d0ea0b718d27532b541a1b393fdc2b6330f6a208bce86c", "df92d63a58491eb1e3473a3dc2445cde877735cc7a7825d6194881c6a29048bb", "8576ee81461293e9bc1aca53ac76726c4d1784c1d53d263ab80342c616c57f3f", "f447da315bdf571d4aaeb066552f7c096130d924601ab0bf6b57a34f3bf9b3a4", "35097accfe1895267c5a02712cb8197944aa9c9a05656393c8fee7df5a8436d8", "8bcd86700bbdb8cd1f662743de4199210ed471cea36e0b1ac760cfceb64010f1", "ada459272aff70cc57b25bc359d5221d422f5438e421726efbbf2b8e8c0450f7", "b8a39508a2ce86ad6c8ca9f2ad5e01e387fb1ea9a1af0081cbc856e95ef147e5"]) {
    const comparison = compareRuns({ ...run, evaluatorHash }, run);
    assert.equal(comparison.compatible, false);
    assert.ok(comparison.reasons.includes('evaluatorHash differs or is missing.'));
  }
});
