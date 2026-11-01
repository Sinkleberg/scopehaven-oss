// Frozen copy of scopehaven/src/key-identity.mjs at cfb545c (main with IDR-4, #363, before in-doubt resolution IDR-3; imports re-pointed: the frozen
// in-doubt, http-effects, effect-outcome, effect-events, idempotency, only.mjs, suspend-clock, request-feed-rules, key-identity and custody
// import one another (only.mjs reads integrations/observers/events.mjs, a pure re-export, as the frozen effect-events), everything else the live
// src/; unchanged through da27674). For test/in-doubt-r2.test.mjs differentials only. Not in any identity list.
// The key collapse's identity and retention rule (W6 keyed retries, src/idempotency.mjs; moved here unchanged by IDR-4 so that resolver R1,
// src/request-feed-rules.mjs, reads one application exactly as the collapse does, through this one function, PR363-REVIEW major 1 and
// minor 5). Pure: no I/O, and no imports, so src/idempotency.mjs and src/request-feed-rules.mjs (which src/in-doubt.mjs imports) both read it
// without a cycle. src/idempotency.mjs re-exports IDEMPOTENCY_SIGNATURE_SCHEMES.
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));

// The timestamped schemes. A declared header leaves head on a send only when its scheme's values parse (src/idempotency.mjs signedHead), and re-signed
// sends count as one application only when their signed items agree (keyGroupIdentity). The recorder never verifies a MAC, so without
// the secret a re-sign and a send under a second secret in another second look the same: declaring one asserts that the
// destination verifies one signing secret per URL. form: v0 is "v0=" and 64 hex; v1-list is one to four space-separated
// "v1," and base64 of 32 bytes; stripe is "t=" and a Unix time, then one to four "v1=" or "v0=" and 64 hex, at least one v1.
export const IDEMPOTENCY_SIGNATURE_SCHEMES = Object.freeze({
  slack: Object.freeze({ timestamp: 'x-slack-request-timestamp', signature: 'x-slack-signature', form: 'v0' }),
  'standard-webhooks': Object.freeze({ timestamp: 'webhook-timestamp', signature: 'webhook-signature', form: 'v1-list' }),
  stripe: Object.freeze({ timestamp: null, signature: 'stripe-signature', form: 'stripe' }),
  svix: Object.freeze({ timestamp: 'svix-timestamp', signature: 'svix-signature', form: 'v1-list' }),
  zoom: Object.freeze({ timestamp: 'x-zm-request-timestamp', signature: 'x-zm-signature', form: 'v0' }),
});
// The timestamped schemes a declaration's volatile list names (by its signature or its timestamp header), in a fixed order.
export const declaredSchemes = volatile => Object.keys(IDEMPOTENCY_SIGNATURE_SCHEMES).filter(name => {
  const s = IDEMPOTENCY_SIGNATURE_SCHEMES[name];
  return volatile.includes(s.signature) || (s.timestamp !== null && volatile.includes(s.timestamp));
});
// One application's identity: the exact key, content, head and settlement token.
export const sendIdentity = e => `${e.idempotency.key}\n${e.contentDigest}\n${e.idempotency.head}\n${e.correlation.settlementToken ?? ''}`;
// Whether a key group's members compare without their signed items (IDEMPOTENCY_SIGNATURE_SCHEMES), read only through the window's
// own declaration for host. For each timestamped scheme it declares, either no member's values parsed (they stay in head), or every
// member's did, their timestamps never go back in window order, and two members carry one MAC whenever they carry one timestamp
// (under one secret the same timestamp and body give the same MAC, so two MACs for one timestamp show a second secret or a nonce).
// The scheme must also not be disproved in the window: no two committed sends to host carry one MAC with another timestamp or
// content, which a MAC over the timestamp and body never does. Otherwise each member's signed items join its identity, so
// re-signed members read content-differs and only exact replays still compare equal. A group with a record whose schemes differ
// from the declaration (the recorder writes one item per declared scheme on every record) compares by send, so nothing in it
// collapses. Returns the identity function for one group, identityOf(all members of the group, rejected ones included).
export function keyGroupIdentity(window, host, sends) {
  const decl = window.scope?.idempotency?.[host];
  if (plain(decl) && plain(decl.signing)) return signingGate(decl.signing);
  const schemes = plain(decl) && Array.isArray(decl.volatile) ? declaredSchemes(decl.volatile) : [];
  const disproved = new Set();
  for (const name of schemes) {
    const seen = new Map();
    for (const e of sends) {
      const s = e.idempotency?.signed?.[name];
      if (!plain(s)) continue;
      const prior = seen.get(s.mac);
      if (!prior) seen.set(s.mac, { t: s.t, content: e.contentDigest });
      else if (prior.t !== s.t || prior.content !== e.contentDigest) disproved.add(name);
    }
  }
  const declared = [...schemes].sort().join(',');
  const matches = e => !Object.hasOwn(e.idempotency, 'signing') && (schemes.length ? plain(e.idempotency.signed) && Object.keys(e.idempotency.signed).sort().join(',') === declared : !Object.hasOwn(e.idempotency, 'signed'));
  const agree = members => schemes.every(name => {
    const items = members.map(e => e.idempotency.signed[name]);
    if (items.every(s => s === null)) return true;
    if (disproved.has(name) || items.some(s => s === null)) return false;
    const macAt = new Map();
    for (let i = 0; i < items.length; i++) {
      if (i > 0 && items[i].t < items[i - 1].t) return false;
      if (macAt.has(items[i].t) && macAt.get(items[i].t) !== items[i].mac) return false;
      macAt.set(items[i].t, items[i].mac);
    }
    return true;
  });
  return members => (!members.every(matches) ? e => `${sendIdentity(e)}\nsend ${e.seq}`
    : agree(members) ? sendIdentity : e => `${sendIdentity(e)}\n${JSON.stringify(e.idempotency.signed)}`);
}
// The identity of a key group on a host that declares verified signature headers (signing: the window's published declaration).
// Every member must carry a signing item of the declared scheme, or the group compares by send. Members compare by head: a verified
// one's head left the signature headers out and names the secret's slot and entry count, any other keeps every header's raw value,
// so an unverified member matches another only as an exact replay. A mixed group, or a verified group whose timestamps go back in
// window order, keeps every member's signing item in its identity. And on a signing destination every collapse, exact replays
// included, is bounded by signing.dedupeSeconds, the time the receiver keeps a key: each later member must have arrived within it of
// the first member's base, the earlier of its signing timestamp (when verified; the sender chooses it) and its own arrival second.
// A later member that arrived after that, or whose arrival second is unknown (a recorder without a signing clock), is its own
// application.
const signingGate = signing => members => {
  if (!members.every(e => plain(e.idempotency.signing) && e.idempotency.signing.scheme === signing.scheme && !Object.hasOwn(e.idempotency, 'signed'))) return e => `${sendIdentity(e)}\nsend ${e.seq}`;
  const items = members.map(e => e.idempotency.signing), verified = items.filter(s => s.verified === true).length;
  if ((verified && verified < items.length) || (verified && items.some((s, i) => i > 0 && !(s.t >= items[i - 1].t)))) return e => `${sendIdentity(e)}\n${JSON.stringify(e.idempotency.signing)}`;
  const first = members[0], base = items[0].verified === true ? Math.min(items[0].t, items[0].at) : items[0].at;
  const within = s => Number.isSafeInteger(base) && Number.isSafeInteger(s.at) && s.at - base <= signing.dedupeSeconds;
  return e => (e === first || within(e.idempotency.signing) ? sendIdentity(e) : `${sendIdentity(e)}\nlate ${e.seq}`);
};
