// The outbound canary sink (lane E1 step 1): seeded canaries looked for in everything the app sent out, and the verdict a
// check reads from them. It defines no canary of its own: the declaration, the folding rules and the matcher are the shared
// module's (src/canary.mjs). This module adds three things a sink needs:
//
//   1. Declarations with destinations. A canary is the shared { id, valueEnv } plus `owner` (whose value it is: a tenant, a
//      role or an actor, for the finding's text) and `allow` (where that value may go: exact lowercase host or domain names,
//      or "*.<suffix>" for any name under a suffix, never the suffix itself). The value is read from its SCOPEHAVEN_TARGET_
//      variable, never from a profile.
//   2. A scanner the sinks call as each unit arrives (the DNS stub's scanner option today; the egress recorder's and the SMTP
//      sink's receive-time hook once it lands). It reads the unit in memory and returns only hits: { canary, channel, via?,
//      layers? }, never the value or the text it was found in. Beside the unit's own text it reads decoded forms, so a value an
//      app re-encoded is still found: percent and quoted-printable decoding, JSON and JavaScript escapes, bytes hidden in
//      invisible characters (Unicode tags, variation selectors, zero-width binary, whitespace bits), rot13, reversal, hex,
//      base32 and base64 (standard and URL-safe) runs at every alignment (also over the text with its line breaks removed),
//      and, for a DNS name, its labels joined (a value split across labels). `via` names the decoding that found it; the
//      channel is the shared matcher's (verbatim, folded, skeleton) on that text. These decodings are one deep and are not
//      applied to each other's output. Then, for a canary those readings did not find, the shared module's own reading
//      (readCorpus), on the unit's own text and on what the invisible-character decodings found: its encoded channel and its
//      decoded layers (base64, base64url, hex and base32, two deep, escapes undone and gzip, zlib and raw deflate inflated at
//      any of them), reported as canaryVerdict reports them: channel 'encoded', via the outer encoding (a CANARY_ENCODINGS
//      name; for bytes hidden in invisible characters, that decoding's name), layers outermost first. The shared coverage rule
//      holds: a unit any part of which the shared module could not examine (a corpus reason: compressed, binary, too deep, too
//      large, past the time budget) is not fully scanned, so it can never pass; a hit in it still fails. A transform outside
//      those (rot13 or reversal combined with an encoding, a cipher, a hash) is not found (CANARY-SINK.md, Limits).
//   3. The judgement. For each canary over a check's windows:
//        fail          a unit in any window, complete or not, carries the canary and goes to a destination its allow list
//                      does not name (an unknown destination, including one that is not a host name, is never allowed when
//                      the list is empty; a unit under a declared name, exact: false, only under a wildcard);
//        inconclusive  the value cannot be judged (the shared reasons); a hit whose destination is unknown while the list
//                      names some (or under a declared name that an entry lies under); a required collector with no window; a
//                      window that is partial, failed or not drained (drained must be true); a required collector whose
//                      windows are not authoritative (presence-only, or written by the app); a unit of a required collector
//                      not fully scanned (scanned must be true and no reason given: the shared module's corpus reason or the
//                      sink's own, scan-too-large or scan-capped, which the verdict then names, or none, an unreadable body);
//                      a required window whose scanner did not hold the canary (scannedCanaries);
//        pass          none of that, and every required collector has a complete, drained, authoritative window that
//                      scanned for the canary.
//      Missing evidence never passes: a collector that was not running reads inconclusive, as a partial window does.
//
// Pure apart from one read of its own files when it loads (the identity record below): no clock, no randomness, no network.
import { validateCanaries, resolveCanary, matchValue, matchEncoded, readCorpus, foldForMatch, skeletonFold, SKELETON_KIND, CanaryError, CANARY_REASONS, CANARY_ENCODINGS } from '../../src/canary.mjs';
import { collectorDigest } from '../../src/collector-identity.mjs';

// The identity of what decided a canary verdict: this module and the shared canary module it matches with (H2's note: a
// consumer that decides with src/canary.mjs lists it in its identity set). Every judgement carries it, so a run judged by
// another build of either file compares as a different judge. Paths are relative to the scopehaven folder.
export const CANARY_SINK_FILES = Object.freeze(['integrations/observers/canary-sink.mjs', 'src/canary.mjs']);
export const CANARY_SINK_RECORD = Object.freeze({ label: 'canary-sink/1', digest: await collectorDigest(CANARY_SINK_FILES, new URL('../../', import.meta.url)), node: process.versions.node });

export const CANARY_SINK_KEYS = Object.freeze(['owner', 'allow']);
// viewChars counts UTF-16 code units (JavaScript string length). The decoding budgets count the characters of the decoded forms
// a view yields, each form once (a repeated word or id decodes to the same forms and is counted once): one decoding may yield
// three times the bound (one base64 run as long as the view, read at four alignments), all of them together eight times.
export const CANARY_SINK_LIMITS = Object.freeze({ allow: 32, runMin: 8, viewChars: 1024 * 1024, decodedChars: 8 * 1024 * 1024, perDecodingChars: 3 * 1024 * 1024 });
// The sink's own reasons for a unit it did not read in full, after the shared corpus reasons: scan-too-large, the view was
// longer than viewChars (read to that bound); scan-capped, a decoding budget dropped a form.
export const CANARY_SINK_REASONS = Object.freeze(['scan-too-large', 'scan-capped']);
export const CANARY_VIAS = Object.freeze(['labels', 'percent', 'quoted-printable', 'unicode-escape', 'tags', 'selectors', 'zero-width', 'whitespace-bits', 'hex', 'base32', 'base64', 'rot13', 'reversed']);
const OWNER_KINDS = Object.freeze(['tenant', 'role', 'actor']);
const NAME = /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)*$/;
const OWNER_VALUE = /^[A-Za-z0-9_.:-]{1,80}$/;
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// The declarations, normalized: [{ id, valueEnv, owner, allow }]. Errors name positions and field names only.
export function validateSinkCanaries(list) {
  validateCanaries(list, { extraKeys: CANARY_SINK_KEYS });
  return list.map((c, i) => {
    const where = `canaries ${i + 1}`;
    let owner = null;
    if (c.owner !== undefined) {
      if (!plain(c.owner) || Object.keys(c.owner).length !== 1 || !OWNER_KINDS.includes(Object.keys(c.owner)[0]) || typeof Object.values(c.owner)[0] !== 'string' || !OWNER_VALUE.test(Object.values(c.owner)[0])) throw new CanaryError('owner', where);
      owner = { kind: Object.keys(c.owner)[0], name: Object.values(c.owner)[0] };
    }
    const allow = c.allow ?? [];
    if (!Array.isArray(allow) || allow.length > CANARY_SINK_LIMITS.allow || !allow.every(a => typeof a === 'string' && NAME.test(a.startsWith('*.') ? a.slice(2) : a)) || new Set(allow).size !== allow.length) throw new CanaryError('allow', where);
    return Object.freeze({ id: c.id, valueEnv: c.valueEnv, owner, allow: Object.freeze([...allow]) });
  });
}

// Whether a destination (a lowercase host or domain name, or null when the sink could not tell) is on an allow list.
// A destination that is not a lowercase host name (an empty label, a path, a stray dot) is unknown, never allowed.
// exact: false says the unit went to some name strictly under the destination, not to it (the DNS stub records a lookup under
// a declared parent that declares subdomains by that parent's name). Such a unit is allowed only by a wildcard naming the
// destination or an ancestor of it, never by an exact entry: the name it went to is not the destination.
export const knownDestination = destination => typeof destination === 'string' && NAME.test(destination);
export function destinationAllowed(destination, allow, { exact = true } = {}) {
  if (!knownDestination(destination)) return false;
  if (!exact) return allow.some(a => a.startsWith('*.') && (destination === a.slice(2) || destination.endsWith(a.slice(1))));
  return allow.some(a => a.startsWith('*.') ? destination.endsWith(a.slice(1)) : destination === a);
}
// Whether an entry names something strictly under a destination (an exact name, or a wildcard's suffix): the name a unit with
// exact: false went to could be that entry, so it is unknown rather than disallowed.
const allowedUnder = (destination, allow) => allow.some(a => (a.startsWith('*.') ? a.slice(2) : a).endsWith(`.${destination}`));

// Decoded forms of a text, each { via, text }. Bounded: runs of at least runMin characters, and the budgets in CANARY_SINK_LIMITS.
const lossy = new TextDecoder('utf-8', { fatal: false });
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
// No form decoding ("+" as a space): a canary has no whitespace, and a "+" in it arrives as %2B, which this reads.
const percentDecode = text => text.replace(/(?:%[0-9a-f]{2})+/gi, run => lossy.decode(Buffer.from(run.replace(/%/g, ''), 'hex')));
// Quoted-printable (mail bodies): soft line breaks joined, then =XX escapes read as bytes.
const quotedPrintable = text => /=(?:[0-9a-f]{2}|\r?\n)/i.test(text) ? text.replace(/=\r?\n/g, '').replace(/(?:=[0-9a-f]{2})+/gi, run => lossy.decode(Buffer.from(run.replace(/=/g, ''), 'hex'))) : null;
function hexDecode(run) {
  return [0, 1].filter(start => run.length - start >= CANARY_SINK_LIMITS.runMin).map(start => lossy.decode(Buffer.from(run.slice(start), 'hex')));
}
function base32Decode(run) {
  const out = [], upper = run.toUpperCase();
  for (let start = 0; start < 8; start++) {
    const s = upper.slice(start);
    if (s.length < CANARY_SINK_LIMITS.runMin) break;
    let bits = 0, acc = 0; const bytes = [];
    for (const ch of s) { acc = (acc << 5) | B32.indexOf(ch); bits += 5; if (bits >= 8) { bytes.push((acc >> (bits - 8)) & 0xff); bits -= 8; acc &= (1 << bits) - 1; } }
    out.push(lossy.decode(Buffer.from(bytes)));
  }
  return out;
}
// Node reads unpadded base64 and a partial final group, so the whole remainder is decoded at each alignment.
function base64Decode(run) {
  const std = run.replace(/-/g, '+').replace(/_/g, '/');
  return [0, 1, 2, 3].filter(start => run.length - start >= CANARY_SINK_LIMITS.runMin).map(start => lossy.decode(Buffer.from(std.slice(start), 'base64')));
}
// Base64 first, the commonest encoding an app or an injected instruction uses; each decoding then has its own budget, so a flood of
// runs of one kind never starves another.
const RUNS = [
  ['base64', /[a-z0-9+/_-]{8,}/gi, base64Decode],
  ['hex', /[0-9a-f]{8,}/gi, hexDecode],
  ['base32', /[a-z2-7]{8,}/gi, base32Decode],
];
// JSON and JavaScript escapes (\\uXXXX, \\u{X...}, \\xXX), and Unicode tag characters (U+E0020 to U+E007E), each read as the
// ASCII it stands for: a value written in invisible tag characters is otherwise removed by the fold, not found.
const unescape = text => text.replace(/\\u\{([0-9a-f]{1,6})\}|\\u([0-9a-f]{4})|\\x([0-9a-f]{2})/gi, (m, a, b, c) => { const n = parseInt(a ?? b ?? c, 16); return n <= 0x10ffff ? String.fromCodePoint(n) : m; });
const untag = text => text.replace(/[\u{e0020}-\u{e007e}]/gu, ch => String.fromCharCode(ch.codePointAt(0) - 0xe0000));
// Bytes hidden in invisible characters: variation selectors (U+FE00 to U+FE0F for 0 to 15, U+E0100 to U+E01EF for 16 to
// 255), zero-width binary (two of U+200B, U+200C, U+200D, U+2060 and U+FEFF as the bits, either way round, any other as a
// byte separator) and whitespace bits (consecutive lines ending in exactly eight spaces and tab characters, space 0 and tab 1).
// Each returns the bytes; the form is those bytes read as UTF-8, and the bytes themselves go to the shared reading (scan).
const VS = /(?:[\u{fe00}-\u{fe0f}\u{e0100}-\u{e01ef}]){8,}/gu, ZW_RUN = /[\u200b\u200c\u200d\u2060\ufeff]{16,}/g;
const fromSelectors = run => Buffer.from([...run].map(ch => { const p = ch.codePointAt(0); return p >= 0xe0100 ? p - 0xe0100 + 16 : p - 0xfe00; }));
function fromZeroWidth(run) {
  const chars = [...new Set(run)], out = [];
  for (const zero of chars) for (const one of chars) {
    if (zero === one) continue;
    const bytes = run.split(new RegExp(`[^${zero}${one}]`)).flatMap(part => part.match(/[^]{8}/g) ?? []).map(bits => parseInt([...bits].map(c => (c === one ? '1' : '0')).join(''), 2));
    if (bytes.length >= CANARY_SINK_LIMITS.runMin) out.push(Buffer.from(bytes));
  }
  return out;
}
function fromWhitespaceBits(text) {
  const out = [];
  let bytes = [];
  for (const line of [...text.split('\n'), '']) {
    const bits = /(?:^|[^ \t])([ \t]{8})$/.exec(line)?.[1];
    if (bits) { bytes.push(parseInt(bits.replace(/ /g, '0').replace(/\t/g, '1'), 2)); continue; }
    if (bytes.length >= CANARY_SINK_LIMITS.runMin) out.push(Buffer.from(bytes));
    bytes = [];
  }
  return out;
}
const rot13 = text => text.replace(/[a-z]/gi, ch => String.fromCharCode((ch <= 'Z' ? 65 : 97) + (ch.toLowerCase().charCodeAt(0) - 84) % 26));
// Each decoding has its own budget (perDecodingChars characters of forms) inside the total (decodedChars), so ordinary words
// that read as base32 cannot crowd out a base64 run read later. A form equal to one the same decoding already gave (a repeated
// word, key or id) is kept once and costs nothing. A form dropped by either bound marks the result capped: the scanner then
// reports the unit as not fully read (complete: false, scan-capped), and the judgement can never pass on it.
// hidden lists what the invisible-character decodings found, for the shared reading: { via, entry }, the bytes for selectors,
// zero-width and whitespace bits, and the text with its tag characters read for tags.
export function decodedForms(text) { return decodeAll(text).forms; }
export function decodeAll(text) {
  const forms = [], hidden = [], used = new Map(), seen = new Set();
  let capped = false, total = 0;
  const add = (via, value) => {
    if (typeof value !== 'string' || !value || value === text) return false;
    const key = `${via}\n${value}`;
    if (seen.has(key)) return false;
    if (total + value.length > CANARY_SINK_LIMITS.decodedChars || (used.get(via) ?? 0) + value.length > CANARY_SINK_LIMITS.perDecodingChars) { capped = true; return false; }
    seen.add(key); used.set(via, (used.get(via) ?? 0) + value.length); total += value.length; forms.push({ via, text: value });
    return true;
  };
  const addBytes = (via, bytes) => { if (add(via, lossy.decode(bytes))) hidden.push({ via, entry: bytes }); };
  add('percent', percentDecode(text));
  add('quoted-printable', quotedPrintable(text));
  add('unicode-escape', unescape(text));
  const untagged = untag(text);
  if (add('tags', untagged)) hidden.push({ via: 'tags', entry: untagged });
  for (const run of text.match(VS) ?? []) addBytes('selectors', fromSelectors(run));
  for (const run of text.match(ZW_RUN) ?? []) for (const bytes of fromZeroWidth(run)) addBytes('zero-width', bytes);
  for (const bytes of fromWhitespaceBits(text)) addBytes('whitespace-bits', bytes);
  add('rot13', rot13(text));
  add('reversed', [...text].reverse().join(''));
  // Runs are also read over the text with its line breaks removed, so a value in a body wrapped at 76 characters (MIME
  // base64) is not split across two runs.
  const unwrapped = /\r?\n/.test(text) ? text.replace(/\r?\n/g, '') : null;
  for (const [via, pattern, decode] of RUNS) for (const source of unwrapped === null ? [text] : [text, unwrapped]) for (const run of source.match(pattern) ?? []) for (const value of decode(run)) add(via, value);
  return { forms, hidden, capped };
}

// The texts a view is read as: [{ via, text }], via null for the unit's own text.
//   { where: 'dns-qname', labels, name }: the presentation name, each label as sent (case kept), the labels joined with no
//     separator (a value split across labels), and the decoded forms of the joined labels and of each label;
//   { where, text }: the text (a body, a header value, a query, a mail message) and its decoded forms.
// hidden: the invisible-character decodings' entries (decodeAll). reasons: the sink's own (CANARY_SINK_REASONS): scan-too-large
// when the view was longer than viewChars, scan-capped when a decoding was capped.
export function viewTexts(view) {
  if (!plain(view) || typeof view.where !== 'string') throw new CanaryError('view');
  if (Array.isArray(view.labels)) {
    const labels = view.labels.map(String), joined = labels.join('');
    const own = [{ via: null, text: String(view.name ?? labels.join('.')) }, ...labels.map(text => ({ via: null, text }))];
    const split = { via: 'labels', text: joined };
    const decoded = [joined, ...labels].map(decodeAll);
    return { texts: [...own, split, ...decoded.flatMap(d => d.forms)], hidden: decoded.flatMap(d => d.hidden), reasons: decoded.some(d => d.capped) ? ['scan-capped'] : [] };
  }
  if (typeof view.text !== 'string') throw new CanaryError('view-text');
  const truncated = view.text.length > CANARY_SINK_LIMITS.viewChars, text = truncated ? view.text.slice(0, CANARY_SINK_LIMITS.viewChars) : view.text;
  const decoded = decodeAll(text);
  return { texts: [{ via: null, text }, ...decoded.forms], hidden: decoded.hidden, reasons: [...(truncated ? ['scan-too-large'] : []), ...(decoded.capped ? ['scan-capped'] : [])] };
}

// The shared matcher (src/canary.mjs matchValue) over groups of texts, each prepared once: { text, folded, skeleton }. Its
// verbatim and folded channels are the same two tests matchValue makes (the value in the text; the folded value in the
// folded text). Its skeleton channel is matchValue's own, asked only for a text whose skeleton contains the value's
// skeleton: an anchored skeleton hit needs exactly that, so the prefilter never drops a hit. canary-sink.test.mjs holds this
// equal to matchValue, channel included, on a corpus. Returns { channel, via } or null.
export function sharedMatch(prepared, { value, folded, skeleton }) {
  for (const [via, group] of prepared) {
    if (group.some(t => t.text.includes(value))) return { channel: 'verbatim', via };
    if (group.some(t => t.folded.includes(folded))) return { channel: 'folded', via };
  }
  for (const [via, group] of prepared) {
    const candidates = group.filter(t => t.skeleton.includes(skeleton)).map(t => t.text);
    if (candidates.length && matchValue(candidates, value, SKELETON_KIND).channel === 'skeleton') return { channel: 'skeleton', via };
  }
  return null;
}

// The shared module's reading of a unit (src/canary.mjs readCorpus, after an earlier review round): { texts, reasons,
// decoded }, read once for every canary. reasons lists each part of the unit it could not examine (CANARY_REASONS); any
// reason makes the unit not fully scanned. It never throws on an array; anything else that goes wrong reads undecodable.
export function sharedCoverage(texts) {
  try { return readCorpus(texts); } catch { return { texts: [], reasons: ['corpus-undecodable'], decoded: [] }; }
}
// A canary the sink's own readings did not find, looked for as canaryVerdict looks: the encoded channel on the unit's texts,
// then each decoded layer in the order found, on the shared channels (the layers that revealed it) or under one more
// encoding (that encoding added). { channel: 'encoded', via, layers? } or null; via is the outer encoding.
export function sharedEncodedHit(corpus, value) {
  const encoded = matchEncoded(corpus.texts, value);
  if (encoded.hit) return { channel: 'encoded', via: encoded.encoding };
  const texts = corpus.decoded.map(d => d.text);
  // One pass over every layer first, and the layer that shows it only on a hit.
  if (!texts.length || !(matchValue(texts, value, SKELETON_KIND).hit || matchEncoded(texts, value).hit)) return null;
  for (const { text, layers } of corpus.decoded) {
    let shown = matchValue([text], value, SKELETON_KIND).hit ? layers : null;
    if (!shown) { const { encoding } = matchEncoded([text], value); if (encoding) shown = [...layers, encoding]; }
    if (shown) return { channel: 'encoded', ...(shown.length ? { via: shown[0] } : {}), layers: Object.freeze([...shown]) };
  }
  return null;
}

// A scanner over the declared canaries: { scan(view) -> { hits: [{ canary, channel, via?, layers? }], complete, reasons },
// canaries, unavailable }. A canary whose value cannot be judged is never matched; it is listed in `unavailable` with the
// shared reason, and judges inconclusive. complete is false, with or without hits, exactly when reasons names something: the
// shared module could not examine some part of the unit or of what the invisible-character decodings found in it (shared
// CANARY_REASONS names, first, in the shared order), the view was longer than viewChars (scan-too-large; it is read to that
// bound), or a decoding budget dropped a form (scan-capped). A sink records complete as the unit's scanned flag and reasons[0]
// as its reason.
export function createCanaryScanner({ canaries, env = process.env }) {
  const declared = validateSinkCanaries(canaries);
  const resolved = declared.map(c => ({ c, ...resolveCanary(env, { id: c.id, valueEnv: c.valueEnv }) }));
  const live = resolved.filter(r => r.value !== undefined).map(r => ({ ...r, folded: foldForMatch(r.value), skeleton: skeletonFold(r.value) }));
  return Object.freeze({
    canaries: declared,
    unavailable: Object.freeze(resolved.filter(r => r.reason).map(r => Object.freeze({ canary: r.c.id, reason: r.reason }))),
    scan(view) {
      const { texts, hidden, reasons: bounds } = viewTexts(view);
      // The unit's own texts (and a DNS name's labels joined) as the shared module reads them, whatever canaries are live.
      const corpus = sharedCoverage(texts.filter(t => t.via === null || t.via === 'labels').map(t => t.text));
      // What the invisible-character decodings found (tags, selectors, zero-width, whitespace bits), read by the shared module
      // too, one reading per decoding: the shared module counts those characters as examined text, so bytes hidden in them that
      // are compressed, binary or encoded get the shared reading and its coverage rule here (an earlier review, finding 1).
      const byVia = new Map();
      for (const { via, entry } of hidden) byVia.set(via, [...(byVia.get(via) ?? []), entry]);
      const hiddenRead = [...byVia].map(([via, entries]) => [via, sharedCoverage(entries)]);
      const shared = new Set([corpus, ...hiddenRead.map(([, read]) => read)].flatMap(read => read.reasons));
      const reasonsNow = () => Object.freeze([...CANARY_REASONS.filter(r => shared.has(r)), ...bounds]);
      const groups = [null, ...CANARY_VIAS].map(via => [via, texts.filter(t => t.via === via).map(t => t.text)]).filter(([, group]) => group.length);
      const hits = [];
      if (!live.length) { const reasons = reasonsNow(); return { hits, complete: !reasons.length, reasons }; }
      // Each text is folded once for every canary (prepared), not once per canary.
      const prepared = groups.map(([via, group]) => [via, group.map(text => ({ text, folded: foldForMatch(text), skeleton: skeletonFold(text) }))]);
      for (const { c, value, folded, skeleton } of live) {
        // The strongest reading first: verbatim and folded over the unit's own text and then each decoded form, and only
        // then the skeleton, so a hit is reported as verbatim or folded wherever one exists; the shared encoded reading last,
        // on the unit and then on each invisible-character decoding (via that decoding, layers the shared ones under it).
        let hit = sharedMatch(prepared, { value, folded, skeleton });
        if (!hit) try {
          hit = sharedEncodedHit(corpus, value);
          for (const [via, read] of hiddenRead) {
            if (hit) break;
            const under = sharedEncodedHit(read, value);
            if (under) hit = { channel: 'encoded', via, layers: Object.freeze(under.layers?.length ? [...under.layers] : under.via ? [under.via] : []) };
          }
        } catch { shared.add('corpus-undecodable'); }
        if (hit) hits.push({ canary: c.id, channel: hit.channel, ...(hit.via ? { via: hit.via } : {}), ...(hit.layers?.length ? { layers: hit.layers } : {}) });
      }
      // A shared reading that failed is a part not examined, as canaryVerdict reads it.
      const reasons = reasonsNow();
      return { hits, complete: !reasons.length, reasons };
    },
  });
}

// A window as the judgement reads it: { collector, coverage, authoritative, drained, scannedCanaries, units: [{ destination,
// exact?, canaries, scanned, reason? }] }. Every flag must be present and true to count: a window without drained: true, a unit
// without scanned: true (or with a reason: the scan's reasons[0]), or a canary missing from scannedCanaries reads inconclusive,
// never pass. destination: the name the unit went to, or null when the sink could not tell (an undeclared DNS name, a mail
// recipient the sink names "*"); exact: false when it went to a name strictly under destination (destinationAllowed). The DNS
// stub's windows read this way through fromDnsWindow, which carries each lookup's exact flag (a lookup that does not say exact:
// true reads as under its declared name): a stub window closes on its witness and quiet period, so it is drained once complete.
// A lookup the stub receives after the witness request is not in the window's lookups (dns-stub.mjs): the window reads partial,
// never pass, but a hit in that lookup does not reach the judgement.
export function fromDnsWindow(w, stub) {
  return { collector: 'dns-stub', coverage: w.coverage, reason: w.reason ?? null, authoritative: stub?.scope?.evidence === 'authoritative' && stub?.scope?.scanned === true,
    drained: w.coverage === 'complete', scannedCanaries: [...(stub?.scope?.scannedCanaries ?? [])],
    units: (w.lookups ?? []).map(l => ({ destination: l.name === '*' ? null : l.name, exact: l.exact === true, canaries: l.canaries ?? [], scanned: l.scanned === true })) };
}

// A unit is fully scanned only with scanned: true and no reason. A reason that is one of the shared module's corpus reasons
// (CANARY_REASONS) or the sink's own (CANARY_SINK_REASONS) is carried into the verdict (corpus-compressed:<collector>,
// scan-capped:<collector>); any other, or none, reads scan-incomplete:<collector>. Only those names are ever copied, never a
// sink's own text.
const NAMED_REASONS = new Set([...CANARY_REASONS.filter(r => r.startsWith('corpus-')), ...CANARY_SINK_REASONS]);
const unread = u => u.scanned !== true || (u.reason ?? null) !== null;
// The verdict per canary and for the check: { outcome, canaries: [{ canary, owner, outcome, reason?, findings }], judge }.
// required: the collectors the check's outbound paths go through; each must have a complete, drained, authoritative window
// for a pass. A finding names the canary, its owner, the collector, the destination (a declared name or "*", with subdomain:
// true when the unit went to a name under it), the channel, the decoding and, for a hit in a decoded layer, the layers
// (CANARY_ENCODINGS names): never the value or the text.
export function judgeCanaries({ scanner, windows, required }) {
  if (!Array.isArray(windows) || !Array.isArray(required) || !required.length || !required.every(r => typeof r === 'string')) throw new CanaryError('judge');
  const unavailable = new Map(scanner.unavailable.map(u => [u.canary, u.reason]));
  // Why no window set can pass, the same for every canary: the first reason found, in a fixed order.
  const gaps = [];
  for (const collector of required) {
    const own = windows.filter(w => w.collector === collector);
    if (!own.length) gaps.push(`collector-missing:${collector}`);
    else if (own.some(w => w.coverage === 'failed')) gaps.push(`window-failed:${collector}`);
    else if (own.some(w => w.coverage !== 'complete')) gaps.push(`window-partial:${collector}`);
    else if (!own.every(w => w.drained === true)) gaps.push(`not-drained:${collector}`);
    else if (!own.every(w => w.authoritative === true)) gaps.push(`not-authoritative:${collector}`);
    else {
      const first = own.flatMap(w => w.units ?? []).find(unread);
      if (first) gaps.push(`${NAMED_REASONS.has(first.reason) ? first.reason : 'scan-incomplete'}:${collector}`);
    }
  }
  // A required window whose scanner did not hold this canary never stands for it.
  const unscanned = c => required.find(collector => windows.some(w => w.collector === collector && !(Array.isArray(w.scannedCanaries) && w.scannedCanaries.includes(c.id))));
  const results = scanner.canaries.map(c => {
    const findings = [], unknown = [];
    for (const w of windows) for (const u of w.units ?? []) for (const h of u.canaries ?? []) {
      if (h.canary !== c.id) continue;
      const known = knownDestination(u.destination), exact = u.exact !== false;
      const finding = { canary: c.id, owner: c.owner, collector: w.collector, destination: known ? u.destination : '*', ...(known && !exact ? { subdomain: true } : {}), channel: h.channel, ...(h.via ? { via: h.via } : {}),
        ...(Array.isArray(h.layers) && h.layers.length && h.layers.every(l => CANARY_ENCODINGS.includes(l)) ? { layers: [...h.layers] } : {}), ...(h.part ? { part: h.part } : {}) };
      if (!known) { if (c.allow.length) unknown.push(finding); else findings.push(finding); }
      else if (destinationAllowed(u.destination, c.allow, { exact })) continue;
      // Under a declared name, where an entry names something under it: the name it went to may be that entry.
      else if (!exact && allowedUnder(u.destination, c.allow)) unknown.push(finding);
      else findings.push(finding);
    }
    // A hit to a destination the canary may not go to fails, in a partial window too: the corpus that shows it showed it.
    if (findings.length) return { canary: c.id, owner: c.owner, outcome: 'fail', findings };
    if (unavailable.has(c.id)) return { canary: c.id, owner: c.owner, outcome: 'inconclusive', reason: unavailable.get(c.id), findings: [] };
    if (unknown.length) return { canary: c.id, owner: c.owner, outcome: 'inconclusive', reason: 'destination-unknown', findings: unknown };
    if (gaps.length) return { canary: c.id, owner: c.owner, outcome: 'inconclusive', reason: gaps[0], findings: [] };
    const notScanned = unscanned(c);
    if (notScanned) return { canary: c.id, owner: c.owner, outcome: 'inconclusive', reason: `not-scanned:${notScanned}`, findings: [] };
    return { canary: c.id, owner: c.owner, outcome: 'pass', findings: [] };
  });
  const outcome = results.some(r => r.outcome === 'fail') ? 'fail' : results.some(r => r.outcome === 'inconclusive') ? 'inconclusive' : 'pass';
  return { outcome, canaries: results, judge: CANARY_SINK_RECORD };
}
