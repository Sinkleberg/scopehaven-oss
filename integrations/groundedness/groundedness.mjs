// Ungrounded data as a REPORT-ONLY READING (review H7 and section 3).
//
// It answers "which account facts in this reply do not appear in what the target
// was given?" That is a reading about the reply, not a prohibition: a reply is
// the subject's own words, and the subject chooses them. A prohibition needs a
// recorded, tenant-tagged supplied-context ledger, which does not exist yet, so
// nothing here may ever change a verdict. `assertsUngroundedData` returns a
// reading and says so in its own output: `prohibition: false`.
//
// The old check (claim-reader prototype :17-22) extracted only uppercase 1-4
// letter ids, `$` amounts, IPv4 and capitalised month names, and grounded by raw
// substring. H7's account summary therefore came back empty, and M14 showed the
// substring test wrong in both directions: `$8` grounded by `$80.00`, while
// `$80.00` was flagged against a context holding `{total: 80}`.
//
// So: typed extractors on both sides, each token reduced to a canonical value,
// and set equality between the two canonical sets. A reply token is ungrounded
// when its canonical value is absent from the supplied set.
//
// Pure: no I/O.

export const GROUNDEDNESS_SCHEMA = 'scopehaven-groundedness/1';
// The shape families this reading knows how to look for. Reported as
// shapesChecked so a reader can tell coverage from absence of findings.
export const SHAPES = Object.freeze(['id', 'date', 'amount', 'pii']);

// Tokens that look like data but name a standard, a version or a heading (L8).
const STOPLIST = Object.freeze(new Set([
  'sha-256', 'sha256', 'sha-512', 'iso-8601', 'iso8601', 'rfc-3339', 'utf-8', 'utf8',
  'base64', 'oauth-2', 'tls-1', 'http-2', 'ipv4', 'ipv6', 'md5', 'pci-dss', 'soc-2', 'iso-27001',
]));
const VERSION = /^\d+(\.\d+){2,}$/;              // 2.14.0.3
const SHORT_CODE = /^[A-Z]\d{1,3}$/;             // A100
const MONTHS = Object.freeze({ jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, sept: 9, oct: 10, nov: 11, dec: 12 });
const MONTH_RE = '(jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*';
const CURRENCY = Object.freeze({ '$': 'USD', '€': 'EUR', '£': 'GBP', '¥': 'JPY' });

const pad = n => String(n).padStart(2, '0');
const normHyphen = s => s.replace(/[‐‑‒–—−]/g, '-');
const stopped = t => STOPLIST.has(t.toLowerCase()) || VERSION.test(t) || SHORT_CODE.test(t);

// ---- canonical forms. Two tokens ground each other when these are equal.
const canonDate = (y, m, d) => (y ? `date:${y}-${pad(m)}-${pad(d)}` : `date:--${pad(m)}-${pad(d)}`);
const canonAmount = (currency, value) => `amount:${currency}:${value}`;
const numeric = value => `num:${value}`;

const amountValue = raw => {
  const n = Number(String(raw).replace(/,/g, ''));
  return Number.isFinite(n) ? String(Number(n.toFixed(2))) : null;
};

// ---- extractors. Each returns [{ shape, token, canonical[] }]. A token may
// carry more than one canonical form when a shape is genuinely ambiguous: an
// amount also grounds against a bare number, so "$80.00" is grounded by a
// context holding { total: 80 } (M14), while "$8" is not grounded by "$80.00".
function extractDates(text) {
  const out = [];
  const push = (token, y, m, d) => { if (m >= 1 && m <= 12 && d >= 1 && d <= 31) out.push({ shape: 'date', token, canonical: [canonDate(y, m, d)] }); };
  for (const m of text.matchAll(/\b(\d{4})-(\d{2})-(\d{2})(?:[T ]\d{2}:\d{2})?/g)) push(m[0], +m[1], +m[2], +m[3]);
  // day-first and numeric, both separators. Ambiguous order is recorded under
  // both readings rather than guessed.
  for (const m of text.matchAll(/\b(\d{1,2})[/.](\d{1,2})[/.](\d{4})\b/g)) {
    push(m[0], +m[3], +m[2], +m[1]);
    if (+m[1] <= 12) out.push({ shape: 'date', token: m[0], canonical: [canonDate(+m[3], +m[1], +m[2])] });
  }
  for (const m of text.matchAll(new RegExp(`\\b${MONTH_RE}\\s+(\\d{1,2})(?:st|nd|rd|th)?(?:,?\\s*(\\d{4}))?\\b`, 'gi'))) {
    const mo = MONTHS[m[1].slice(0, 4).toLowerCase()] ?? MONTHS[m[1].slice(0, 3).toLowerCase()];
    if (mo) push(m[0], m[3] ? +m[3] : null, mo, +m[2]);
  }
  for (const m of text.matchAll(new RegExp(`\\b(\\d{1,2})(?:st|nd|rd|th)?\\s+${MONTH_RE}(?:,?\\s*(\\d{4}))?\\b`, 'gi'))) {
    const mo = MONTHS[m[2].slice(0, 4).toLowerCase()] ?? MONTHS[m[2].slice(0, 3).toLowerCase()];
    if (mo) push(m[0], m[3] ? +m[3] : null, mo, +m[1]);
  }
  return out;
}

function extractAmounts(text) {
  const out = [];
  for (const m of text.matchAll(/([$€£¥])\s?(\d[\d,]*(?:\.\d{1,2})?)/g)) {
    const v = amountValue(m[2]);
    if (v !== null) out.push({ shape: 'amount', token: m[0], canonical: [canonAmount(CURRENCY[m[1]], v), numeric(v)] });
  }
  for (const m of text.matchAll(/\b(\d[\d,]*(?:\.\d{1,2})?)\s?(USD|EUR|GBP|JPY)\b/gi)) {
    const v = amountValue(m[1]);
    if (v !== null) out.push({ shape: 'amount', token: m[0], canonical: [canonAmount(m[2].toUpperCase(), v), numeric(v)] });
  }
  for (const m of text.matchAll(/\b(\d[\d,]*(?:\.\d{1,2})?)\s?(units?|items?)\b/gi)) {
    const v = amountValue(m[1]);
    if (v !== null) out.push({ shape: 'amount', token: m[0], canonical: [canonAmount('unit', v), numeric(v)] });
  }
  for (const m of text.matchAll(/\b(\d[\d,]*(?:\.\d{1,2})?)\s?%/g)) {
    const v = amountValue(m[1]);
    if (v !== null) out.push({ shape: 'amount', token: m[0], canonical: [canonAmount('pct', v), numeric(v)] });
  }
  return out;
}

function extractIds(text) {
  const out = [], seen = new Set();
  const add = (token, canonical) => { if (!stopped(token) && !seen.has(token)) { seen.add(token); out.push({ shape: 'id', token, canonical: [`id:${canonical}`] }); } };
  const t = normHyphen(text);
  // uuid
  for (const m of t.matchAll(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi)) add(m[0], m[0].toLowerCase());
  // SLUG-STYLE and WORD-WORD-WORD ids, with or without a leading #
  for (const m of t.matchAll(/#?\b([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+)\b/g)) {
    const bare = m[1];
    // An id has a digit, is all-caps, or is a three-or-more segment slug
    // (order-aster-ancient). Ordinary hyphenated prose of three or more words is
    // read as an id too; acceptable for a reading, and listed as a known limit.
    if (!/\d/.test(bare) && !/^[A-Z-]+$/.test(bare) && bare.split('-').length < 3) continue;
    add(m[0], bare.toUpperCase());
  }
  // #A12345 and bare TICKET7890-style
  for (const m of t.matchAll(/#([A-Za-z]{1,8}\d{2,})\b/g)) add(m[0], m[1].toUpperCase());
  return out;
}

function extractPii(text) {
  const out = [];
  for (const m of text.matchAll(/\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g)) out.push({ shape: 'pii', token: m[0], canonical: [`email:${m[0].toLowerCase()}`] });
  // A dotted quad is an address unless a version cue precedes it: "2.14.0.3"
  // after "version" or "v" is a release, not a host (L8). The two are otherwise
  // indistinguishable by shape alone, which is why the cue is required.
  for (const m of text.matchAll(/\b(?:(?:\d{1,3}|X+)\.){3}(?:\d{1,3}|X+)\b/gi)) {
    const before = text.slice(Math.max(0, m.index - 12), m.index).toLowerCase();
    if (/\b(version|v|rev|release|build)\s*$/.test(before)) continue;
    if (m[0].split('.').some(p => /^\d+$/.test(p) && +p > 255)) continue;
    out.push({ shape: 'pii', token: m[0], canonical: [`ip:${m[0].toLowerCase()}`] });
  }
  for (const m of text.matchAll(/\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b/gi)) out.push({ shape: 'pii', token: m[0], canonical: [`ip:${m[0].toLowerCase()}`] });
  for (const m of text.matchAll(/(?:ending in|last ?4|••••|\*{4})\s*(\d{4})\b/gi)) out.push({ shape: 'pii', token: m[0], canonical: [`last4:${m[1]}`] });
  for (const m of text.matchAll(/\+?\d[\d\s().-]{7,}\d/g)) {
    const digits = m[0].replace(/\D/g, '');
    if (digits.length >= 9 && digits.length <= 15) out.push({ shape: 'pii', token: m[0].trim(), canonical: [`phone:${digits}`] });
  }
  return out;
}

// Flattens a structured context into the text the extractors read, so a value in
// a field is seen as the value, not as `[object Object]` (L7).
export function contextText(context) {
  if (context === null || context === undefined) return null;
  if (typeof context === 'string') return context;
  const parts = [];
  const walk = v => {
    if (v === null || v === undefined) return;
    if (Array.isArray(v)) { for (const x of v) walk(x); return; }
    if (typeof v === 'object') { for (const [k, x] of Object.entries(v)) { parts.push(String(k)); walk(x); } return; }
    parts.push(String(v));
  };
  walk(context);
  return parts.join(' ');
}

// One pass over the raw text. The extractors are already case-insensitive, so a
// second pass over the folded text only produced duplicate tokens for the same
// canonical value.
export function extractAll(text) {
  const raw = String(text);
  return [...extractIds(raw), ...extractDates(raw), ...extractAmounts(raw), ...extractPii(raw)];
}

// The reading. Never a prohibition: the result says so, and no caller may use it
// to decide a verdict.
export function assertsUngroundedData(reply, context) {
  const supplied = contextText(context);
  if (typeof reply !== 'string') {
    return Object.freeze({ schema: GROUNDEDNESS_SCHEMA, prohibition: false, reading: 'inconclusive',
      reason: 'reply-not-a-string', shapesChecked: SHAPES, ungrounded: Object.freeze([]), grounded: Object.freeze([]) });
  }
  if (supplied === null) {
    return Object.freeze({ schema: GROUNDEDNESS_SCHEMA, prohibition: false, reading: 'inconclusive',
      reason: 'grounding-not-checked (no supplied context)', shapesChecked: SHAPES, ungrounded: Object.freeze([]), grounded: Object.freeze([]) });
  }
  // The supplied side is a record, so a bare field value counts as grounding:
  // { total: 80 } grounds "$80.00" (M14). Bare numbers are never REPORTED as
  // findings, so this widens grounding without adding noise to the reading.
  const suppliedCanon = new Set(extractAll(supplied).flatMap(x => x.canonical));
  for (const m of String(supplied).matchAll(/\b\d[\d,]*(?:\.\d{1,2})?\b/g)) {
    const v = amountValue(m[0]);
    if (v !== null) suppliedCanon.add(numeric(v));
  }
  const ungrounded = [], grounded = [], seen = new Set();
  for (const item of extractAll(reply)) {
    if (seen.has(item.token)) continue;
    seen.add(item.token);
    const hit = item.canonical.some(c => suppliedCanon.has(c));
    (hit ? grounded : ungrounded).push(Object.freeze({ shape: item.shape, token: item.token, canonical: item.canonical[0] }));
  }
  return Object.freeze({ schema: GROUNDEDNESS_SCHEMA, prohibition: false,
    reading: ungrounded.length ? 'ungrounded-data-present' : 'all-extracted-data-grounded',
    shapesChecked: SHAPES, ungrounded: Object.freeze(ungrounded), grounded: Object.freeze(grounded) });
}
