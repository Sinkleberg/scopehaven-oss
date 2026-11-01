// Scopehaven evidence ledger, verifier side (scopehaven-ledger/1).
// The ledger is an append-only, hash-chained log of signed run envelopes (integrations/attest).
// Each entry names the previous entry's leaf hash, the envelope digest, the run identities the
// envelope's signed statement gives, and that run's per-check verdicts. Checkpoints are DSSE-signed
// Merkle tree heads over the entries (RFC 9162 hashing: leaf 0x00, node 0x01), with inclusion and
// consistency proofs in the transparency-log style.
//
// This module imports nothing from ledger.mjs. It recomputes every hash and tree head itself and uses
// the attest verifier only for signatures; verify_ledger.py repeats every check in Python.
// A verified ledger shows that the log operator's key signed these entries in this order and that
// each entry's envelope was signed by the evidence key. It does not show the results are correct,
// and a checkpoint is not externally witnessed: the operator could show different histories to
// different readers unless checkpoints are compared.
import { createHash, createPublicKey, generateKeyPairSync, verify as verifySignature } from 'node:crypto';
import { PAYMENTS_RUN_SCHEMA, Rejected, keyIdOf, readSignedStatement, savedRun, signatureValid, trustedKey } from '../attest/verify.mjs';

export const LEDGER_VERSION = 'scopehaven-ledger/1';
export const CHECKPOINT_VERSION = 'scopehaven-ledger-checkpoint/1';
export const CHECKPOINT_TYPE = 'application/vnd.scopehaven.ledger-checkpoint+json';
export const INCLUSION_VERSION = 'scopehaven-ledger-inclusion/1';
export const CONSISTENCY_VERSION = 'scopehaven-ledger-consistency/1';
export const CHECKPOINT_MEANING = 'Signed by the log operator\'s own key over this log\'s first treeSize entries. Not externally witnessed: an operator could show different histories to different readers, so compare checkpoints with others who hold them, or keep your own.';
export const STATUSES = Object.freeze(['pass', 'fail', 'inconclusive', 'error', 'not_applicable']);
// EVID-SUBJECT's custody vocabulary (integrations/evid-subject/custody.mjs CUSTODY), checked as a schema enum only.
export const CUSTODY = Object.freeze(['subject-writable', 'observer-held', 'independent']);
export const LIMITS = Object.freeze({ depth: 256, entries: 100000, lineBytes: 262144, checkpoints: 100000, runsPerEntry: 64, checksPerRun: 1000, proofLength: 64, anchorsPerRun: 64, cosignatures: 100000, witnesses: 64 });

const reject = (reason, detail) => { throw new Rejected(reason, detail); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exactKeys = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const scalar = value => value === null || ['string', 'number', 'boolean'].includes(typeof value);
const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
// Observer source names: one ASCII rule in both verifiers.
const SOURCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HEX64 = /^[0-9a-f]{64}$/, ISO = /^2\d{3}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/, LOG_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
// Surrounding whitespace both verifiers ignore: space, tab, CR and LF only.
const trimmed = value => String(value).replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');
const isoTime = value => typeof value === 'string' && ISO.test(value) && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value;

// RFC 9162 section 2.1.1: leaf and interior node hashes, and the tree head.
export const leafHash = bytes => sha(Buffer.from([0]), Buffer.from(bytes));
const nodeHash = (left, right) => sha(Buffer.from([1]), left, right);
const split = n => { let k = 1; while (k * 2 < n) k *= 2; return k; };
// Tree heads of every requested prefix size in one pass, from the frontier of perfect subtrees
// (a right fold of the frontier is the RFC 9162 head), so a log with a checkpoint per entry
// verifies in O(n log n) instead of recomputing each head.
export function treeHeadsAt(leaves, sizes) {
  const wanted = new Set(sizes), heads = new Map(), stack = [];
  leaves.forEach((leaf, i) => {
    let size = 1, hash = leaf;
    while (stack.length && stack.at(-1)[0] === size) { const [s, h] = stack.pop(); size = s * 2; hash = nodeHash(h, hash); }
    stack.push([size, hash]);
    if (wanted.has(i + 1)) { let r = stack.at(-1)[1]; for (let j = stack.length - 2; j >= 0; j--) r = nodeHash(stack[j][1], r); heads.set(i + 1, r); }
  });
  return heads;
}
export function treeHead(leaves) {
  if (!leaves.length) return sha();
  if (leaves.length === 1) return leaves[0];
  const k = split(leaves.length);
  return nodeHash(treeHead(leaves.slice(0, k)), treeHead(leaves.slice(k)));
}

// Canonical JSON text (what JSON.stringify writes) for one line, or a rejection.
// JSON nesting depth of a text, counted outside strings. Both verifiers refuse anything deeper than
// LIMITS.depth before parsing it, so neither language's parser limits ever decide an outcome.
export function tooDeep(text, limit = LIMITS.depth) {
  let depth = 0, inString = false, escaped = false;
  for (const ch of String(text)) {
    if (inString) { if (escaped) escaped = false; else if (ch === '\\') escaped = true; else if (ch === '"') inString = false; continue; }
    if (ch === '"') inString = true;
    else if (ch === '[' || ch === '{') { if (++depth > limit) return true; }
    else if (ch === ']' || ch === '}') depth--;
  }
  return false;
}
function canonical(text, shapeReason, canonicalReason) {
  if (tooDeep(text)) reject(shapeReason, 'nested too deep');
  let value;
  try { value = JSON.parse(text); } catch { reject(shapeReason, 'not JSON'); }
  let same;
  try { same = JSON.stringify(value) === text; } catch { reject(shapeReason, 'nested beyond this verifier\'s limits'); }
  if (!same) reject(canonicalReason);
  return value;
}
function lines(bytes, limit, reason) {
  let text;
  try { text = utf8.decode(Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes ?? ''))); } catch { reject(reason, 'not UTF-8'); }
  if (!text.length) return [];
  if (!text.endsWith('\n')) reject(reason, 'the last line is incomplete');
  const list = text.slice(0, -1).split('\n');
  if (list.length > limit || list.some(line => !line.length || Buffer.byteLength(line) > LIMITS.lineBytes)) reject(reason, 'empty or oversized line, or too many lines');
  return list;
}
function strictBase64(text) {
  if (typeof text !== 'string' || text.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return null;
  const bytes = Buffer.from(text, 'base64');
  return bytes.toString('base64') === text ? bytes : null;
}

export function readMetadata(bytes) {
  let text;
  try { text = utf8.decode(Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes ?? ''))); } catch { reject('ledger-shape'); }
  const meta = canonical(text.endsWith('\n') ? text.slice(0, -1) : text, 'ledger-shape', 'ledger-shape');
  if (!exactKeys(meta, ['ledger', 'log', 'createdAt']) || meta.ledger !== LEDGER_VERSION || typeof meta.log !== 'string' || !LOG_ID.test(meta.log) || !isoTime(meta.createdAt)) reject('ledger-shape');
  return meta;
}

function entryShape(entry) {
  if (!exactKeys(entry, ['index', 'prev', 'recordedAt', 'envelope', 'runs'])) reject('entry-shape');
  if (!Number.isSafeInteger(entry.index) || entry.index < 0 || !(entry.prev === null || (typeof entry.prev === 'string' && HEX64.test(entry.prev))) || !isoTime(entry.recordedAt)) reject('entry-shape', `entry ${entry.index}`);
  if (!exactKeys(entry.envelope, ['sha256', 'keyid']) || ![entry.envelope.sha256, entry.envelope.keyid].every(v => typeof v === 'string' && HEX64.test(v))) reject('entry-shape', `entry ${entry.index} envelope`);
  if (!Array.isArray(entry.runs) || entry.runs.length > LIMITS.runsPerEntry) reject('entry-shape', `entry ${entry.index} runs`);
  if (Array.isArray(entry.runs) && new Set(entry.runs.map(r => r?.id)).size !== entry.runs.length) reject('entry-shape', `entry ${entry.index} records one run id twice`);
  for (const run of entry.runs) {
    if (!plain(run) || typeof run.subject !== 'string' || typeof run.id !== 'string' || !run.id || !Array.isArray(run.verdicts) || typeof run.verdictDigest !== 'string' || !HEX64.test(run.verdictDigest)) reject('entry-shape', `entry ${entry.index} run`);
    if (Object.entries(run).some(([key, value]) => !RECORDED.includes(key) && !scalar(value))) reject('entry-shape', `entry ${entry.index} run identity`);
    // Custody anchors: the head and count of an observer-kept evidence chain (EVID-SUBJECT anchorOf).
    if (!Array.isArray(run.anchors) || run.anchors.length > LIMITS.anchorsPerRun || !run.anchors.every(a => exactKeys(a, ['source', 'custody', 'count', 'head']) && typeof a.source === 'string'
      && SOURCE.test(a.source) && CUSTODY.includes(a.custody) && Number.isSafeInteger(a.count) && a.count >= 0
      && (a.count === 0 ? a.head === null : typeof a.head === 'string' && HEX64.test(a.head))) || new Set(run.anchors.map(a => a.source)).size !== run.anchors.length) reject('entry-shape', `entry ${entry.index} anchors`);
    if (run.verdicts.length > LIMITS.checksPerRun || !run.verdicts.every(v => Array.isArray(v) && v.length === 2 && typeof v[0] === 'string' && v[0].length && STATUSES.includes(v[1]))
      || new Set(run.verdicts.map(v => v[0])).size !== run.verdicts.length) reject('entry-shape', `entry ${entry.index} verdicts`);
  }
}
// What the ledger records about a run beyond the identity its signed statement gives.
const RECORDED = ['verdicts', 'verdictDigest', 'anchors'];
// The writer runs this on every entry it builds, so it never writes one the verifiers reject.
export function checkEntry(entry) {
  entryShape(entry);
  if (Buffer.byteLength(JSON.stringify(entry)) > LIMITS.lineBytes) reject('entry-shape', 'line too long');
}
const identityOf = run => Object.fromEntries(Object.entries(run).filter(([key]) => !RECORDED.includes(key)));
export const verdictDigest = verdicts => createHash('sha256').update(JSON.stringify(verdicts)).digest('hex');

// Each entry in order: shape, position, chain link, time order and verdict digest. Returns leaves.
function checkChain(entries, createdAt) {
  const leaves = [];
  entries.forEach(({ entry, line }, i) => {
    entryShape(entry);
    if (entry.index !== i) reject('index-mismatch', `line ${i + 1} holds entry ${entry.index}`);
    if (entry.prev !== (i ? leaves[i - 1].toString('hex') : null)) reject('chain-broken', `entry ${i} does not follow entry ${i - 1}`);
    const before = i ? entries[i - 1].entry.recordedAt : createdAt;
    if (Date.parse(entry.recordedAt) < Date.parse(before)) reject('time-regression', `entry ${i} is dated before ${i ? `entry ${i - 1}` : 'the ledger'}`);
    for (const run of entry.runs) if (verdictDigest(run.verdicts) !== run.verdictDigest) reject('verdict-digest-mismatch', `entry ${i}`);
    leaves.push(leafHash(Buffer.from(line)));
  });
  return leaves;
}

// One checkpoint line: a DSSE envelope over the canonical checkpoint payload, signed by the ledger key.
export function readCheckpoint(text, key, keyid, log, sig = signatureValid, createdAt) {
  let env;
  if (tooDeep(text)) reject('checkpoint-shape', 'nested too deep');
  try { env = JSON.parse(text); } catch { reject('checkpoint-shape', 'not JSON'); }
  // Canonical lines, so holders can compare checkpoints byte for byte.
  let same;
  try { same = JSON.stringify(env) === text; } catch { reject('checkpoint-shape', 'nested beyond this verifier\'s limits'); }
  if (!same) reject('checkpoint-shape', 'not canonical');
  if (!exactKeys(env, ['payload', 'payloadType', 'signatures']) || env.payloadType !== CHECKPOINT_TYPE || !Array.isArray(env.signatures) || env.signatures.length !== 1
    || !exactKeys(env.signatures[0], ['keyid', 'sig']) || typeof env.signatures[0].keyid !== 'string') reject('checkpoint-shape');
  const payload = strictBase64(env.payload), signature = strictBase64(env.signatures[0].sig);
  if (!payload || !signature || payload.length > LIMITS.lineBytes) reject('checkpoint-shape', 'base64');
  if (env.signatures[0].keyid !== keyid) reject('keyid-mismatch', 'checkpoint signed by a different key than the trusted ledger key');
  if (signature.length !== 64 || !sig(key, CHECKPOINT_TYPE, payload, signature)) reject('checkpoint-signature');
  let body;
  try { body = utf8.decode(payload); } catch { reject('checkpoint-shape'); }
  const point = canonical(body, 'checkpoint-shape', 'checkpoint-shape');
  if (!exactKeys(point, ['_type', 'log', 'ledgerCreatedAt', 'treeSize', 'rootHash', 'headHash', 'signedAt', 'witness', 'meaning']) || point._type !== CHECKPOINT_VERSION
    || (log !== undefined && point.log !== log) || typeof point.log !== 'string' || !LOG_ID.test(point.log) || !isoTime(point.ledgerCreatedAt)
    || !Number.isSafeInteger(point.treeSize) || point.treeSize < 1 || point.treeSize > LIMITS.entries
    || ![point.rootHash, point.headHash].every(v => typeof v === 'string' && HEX64.test(v)) || !isoTime(point.signedAt)
    || point.witness !== 'none' || point.meaning !== CHECKPOINT_MEANING) reject('checkpoint-shape');
  // The ledger metadata is signed through every checkpoint.
  if (createdAt !== undefined && point.ledgerCreatedAt !== createdAt) reject('ledger-mismatch', 'ledger.json does not match the signed checkpoint');
  return point;
}

// The whole log: metadata, entries, their envelopes, and every checkpoint. envelopes maps the
// envelope digest (hex) to its bytes. The ledger key signs checkpoints; the evidence key signs
// envelopes (often the same key). `checks` replaces internals only so tests can prove a verifier
// that accepts everything is caught by its own negative controls.
// runFiles (optional): Map of SHA-256 -> run export bytes. Each run whose signed file is supplied has
// its recorded verdicts compared with that file's results, which binds them beyond the ledger key.
export function verifyLedger({ metadata, entries, checkpoints, envelopes, ledgerKey, evidenceKey = ledgerKey, runFiles, cosignatures, witnesses, quorum }, checks = {}) {
  const key = trustedKey(ledgerKey), keyid = keyIdOf(key), evidence = trustedKey(evidenceKey);
  const sig = checks.signature ?? signatureValid;
  let state;
  try {
    const policy = witnessPolicy(witnesses, quorum);
    state = examine({ metadata, entries, checkpoints, envelopes, key, keyid, evidence, sig, runFiles });
    if (policy) state.witnessing = examineCosignatures(state, policy, cosignatures);
  }
  catch (error) {
    if (!(error instanceof Rejected)) throw error;
    return { ledger: LEDGER_VERSION, verified: false, verdict: 'rejected', reason: error.reason, detail: error.message, keyid, selfChecks: [] };
  }
  const selfChecks = [...negativeControls(state, key, sig, evidence), ...cosignatureControls(state)], accepted = selfChecks.filter(c => c.observed !== 'rejected').map(c => c.id);
  const covered = state.points.at(-1).treeSize;
  return { ledger: LEDGER_VERSION, verified: !accepted.length, verdict: accepted.length ? 'self-check-failed' : 'verified', reason: accepted.length ? 'negative-control-accepted' : null,
    detail: accepted.length ? `This verifier accepted tampered input (${accepted.join(', ')}); do not rely on it.` : null,
    keyid, log: state.meta.log, size: state.entries.length, covered, unsignedTail: state.entries.length - covered,
    witness: state.witnessing?.witnessedSize ? witnessSummary(state.witnessing) : 'none',
    witnessCoverage: !state.witnessing ? 'no-policy' : state.witnessing.witnessedSize ? 'met' : 'not-met', ...(state.witnessing ? { witnessing: reportedWitnessing(state.witnessing) } : {}),
    verdictsCheckedAgainstRunFiles: state.verdictsChecked, runs: state.runCount, checkpoints: state.points.map(p => ({ treeSize: p.treeSize, rootHash: p.rootHash, signedAt: p.signedAt })),
    entries: state.entries.slice(0, covered).map(({ entry }) => entry), selfChecks };
}

// ---- Witness cosignatures (C2SP tlog-cosignature, cosignature/v1) ----
// A witness is a party other than the operator that keeps the last checkpoint it saw for this log,
// checks each new one is a consistent extension of it, and countersigns. The cosigned message is the
// C2SP checkpoint note for this log (origin, tree size, base64 root) under "cosignature/v1" and the
// witness's time. Cosignatures are stored one per line in cosignatures.jsonl as
// {"treeSize","rootHash","cosignature"}, where cosignature is the signed-note signature line.
// The reader decides which witnesses to trust (vkeys) and how many must agree (quorum); without a
// policy nothing here is read and the result says witness "none", as before.
export const COSIGNATURE_ORIGIN = log => `scopehaven-ledger/${log}`;
export const checkpointNote = (origin, treeSize, rootHash) => `${origin}\n${treeSize}\n${Buffer.from(rootHash, 'hex').toString('base64')}\n`;
export const cosignedMessage = (time, note) => Buffer.from(`cosignature/v1\ntime ${time}\n${note}`);
// Cosigner names (C2SP tlog-cosignature): a non-empty UTF-8 string of at most 255 bytes with no Unicode
// spaces (the White_Space property, as Go's unicode.IsSpace), no '+' and no control characters below
// U+0020. The same test in both verifiers and in witness.mjs.
const UNICODE_SPACE = /[\t-\r \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/;
export const cosignerName = name => typeof name === 'string' && name.length > 0 && name.isWellFormed() && Buffer.byteLength(name) <= 255
  && !/[\x00-\x1f+]/.test(name) && !UNICODE_SPACE.test(name);
// The signed-note signature line; the name holds no space, so the first space ends it.
export const SIGNATURE_LINE = /^\u2014 ([^ ]+) ([A-Za-z0-9+/]+={0,2})$/;
// The signed-note key ID of a cosignature/v1 key: SHA-256(name || "\n" || 0x04 || public key)[:4].
export const witnessKeyId = (name, rawPublic) => sha(Buffer.from(`${name}\n`), Buffer.from([4]), rawPublic).subarray(0, 4).toString('hex');
// vkey: <name>+<hex key id>+<base64(0x04 || Ed25519 public key)>, as signed-note writes it.
export function readWitnessKey(vkey) {
  // The name and key id hold no '+'; the base64 key may, so split at the first two only.
  const first = typeof vkey === 'string' ? vkey.indexOf('+') : -1, second = first < 0 ? -1 : vkey.indexOf('+', first + 1);
  const parts = second < 0 ? [] : [vkey.slice(0, first), vkey.slice(first + 1, second), vkey.slice(second + 1)];
  if (parts.length !== 3 || !cosignerName(parts[0]) || !/^[0-9a-f]{8}$/.test(parts[1])) reject('witness-policy', 'a witness key is not <name>+<key id>+<key>');
  const data = strictBase64(parts[2]);
  if (!data || data.length !== 33 || data[0] !== 4) reject('witness-policy', `witness ${parts[0]}: not a cosignature/v1 Ed25519 key`);
  const raw = data.subarray(1);
  if (witnessKeyId(parts[0], raw) !== parts[1]) reject('witness-policy', `witness ${parts[0]}: key id does not match the key`);
  let publicKey;
  try { publicKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') }, format: 'jwk' }); } catch { reject('witness-policy', `witness ${parts[0]}: not an Ed25519 key`); }
  return { name: parts[0], keyId: parts[1], raw: raw.toString('hex'), publicKey };
}
function witnessPolicy(witnesses, quorum) {
  if (witnesses === undefined || witnesses === null) return null;
  if (!Array.isArray(witnesses) || !witnesses.length || witnesses.length > LIMITS.witnesses) reject('witness-policy', 'witnesses must be a list of 1 to 64 vkeys');
  const keys = witnesses.map(readWitnessKey);
  if (new Set(keys.map(k => k.name)).size !== keys.length) reject('witness-policy', 'two witness keys share a name');
  // C2SP: distinct cosigners use distinct Ed25519 keys (the signed message does not name the cosigner),
  // so one key listed under two names would count twice toward the quorum. Refused.
  if (new Set(keys.map(k => k.raw)).size !== keys.length) reject('witness-policy', 'two witness names share a key');
  // Omitted or null (the API) means all of the trusted keys, as Python's None and the CLI without --quorum.
  const k = quorum === undefined || quorum === null ? keys.length : quorum;
  if (!Number.isSafeInteger(k) || k < 1 || k > keys.length) reject('witness-policy', 'quorum must be between 1 and the number of witnesses');
  return { keys, quorum: k };
}
// Every cosignature line is read; lines from keys the reader does not trust are counted and ignored
// (signed-note: a key must match on both name and key id). A trusted key's cosignature must verify,
// and must name a tree this ledger has: a larger tree than the ledger holds is a rollback, a different
// root at that size a fork. Either is reported even when every operator checkpoint verifies.
function examineCosignatures(state, policy, cosignatures) {
  const origin = COSIGNATURE_ORIGIN(state.meta.log), valid = [];
  let ignored = 0;
  for (const text of lines(cosignatures, LIMITS.cosignatures, 'cosignature-shape')) {
    const line = canonical(text, 'cosignature-shape', 'cosignature-shape');
    if (!exactKeys(line, ['treeSize', 'rootHash', 'cosignature']) || !Number.isSafeInteger(line.treeSize) || line.treeSize < 1 || line.treeSize > LIMITS.entries
      || typeof line.rootHash !== 'string' || !HEX64.test(line.rootHash) || typeof line.cosignature !== 'string') reject('cosignature-shape');
    const match = SIGNATURE_LINE.exec(line.cosignature), data = match && cosignerName(match[1]) && strictBase64(match[2]);
    if (!data || data.length !== 76) reject('cosignature-shape', 'not a signed-note cosignature line');
    const name = match[1], keyId = data.subarray(0, 4).toString('hex'), time = data.readBigUInt64BE(4);
    if (time > BigInt(Number.MAX_SAFE_INTEGER)) reject('cosignature-shape', 'time');
    const trusted = policy.keys.find(k => k.name === name && k.keyId === keyId);
    if (!trusted) { ignored++; continue; }
    const message = cosignedMessage(time.toString(), checkpointNote(origin, line.treeSize, line.rootHash));
    if (!verifySignature(null, message, trusted.publicKey, data.subarray(12))) reject('cosignature-invalid', `witness ${name} at size ${line.treeSize}`);
    valid.push({ witness: name, treeSize: line.treeSize, rootHash: line.rootHash, time: Number(time), message, signature: data.subarray(12), publicKey: trusted.publicKey });
  }
  const beyond = valid.find(c => c.treeSize > state.leaves.length);
  if (beyond) reject('witness-rollback', `witness ${beyond.witness} cosigned ${beyond.treeSize} entries; this ledger has ${state.leaves.length}`);
  const heads = treeHeadsAt(state.leaves, [...new Set(valid.map(c => c.treeSize))]);
  const forked = valid.find(c => heads.get(c.treeSize).toString('hex') !== c.rootHash);
  if (forked) reject('witness-fork', `witness ${forked.witness} cosigned a different tree at size ${forked.treeSize}`);
  const bySize = new Map();
  for (const c of valid) bySize.set(c.treeSize, [...new Set([...(bySize.get(c.treeSize) ?? []), c.witness])].sort());
  const sizes = [...bySize.keys()].sort((a, b) => a - b), met = sizes.filter(size => bySize.get(size).length >= policy.quorum);
  return { origin, quorum: policy.quorum, trusted: policy.keys.map(k => k.name), witnessedSize: met.length ? met.at(-1) : null,
    latestCheckpointWitnessed: met.includes(state.points.at(-1).treeSize), cosigned: sizes.map(size => ({ treeSize: size, witnesses: bySize.get(size) })), ignored, valid };
}
const reportedWitnessing = ({ valid, ...reported }) => reported;
function witnessSummary(w) { return { quorum: w.quorum, witnessedSize: w.witnessedSize, latestCheckpointWitnessed: w.latestCheckpointWitnessed }; }
// The cosignature path checks itself too: a flipped signature, and a valid one moved to another size.
function cosignatureControls(state) {
  const c = state.witnessing?.valid?.[0];
  if (!c) return [];
  const flipped = Buffer.from(c.signature); flipped[flipped.length >> 1] ^= 1;
  const moved = cosignedMessage(String(c.time), checkpointNote(state.witnessing.origin, c.treeSize + 1, c.rootHash));
  return [['cosignature-tampered', () => verifySignature(null, c.message, c.publicKey, flipped)], ['cosignature-moved', () => verifySignature(null, moved, c.publicKey, c.signature)]]
    .map(([id, attempt]) => ({ id, expected: 'rejected', observed: attempt() ? 'accepted' : 'rejected' }));
}

// The [id, status] verdicts of a run file as both verifiers read it, or null: UTF-8 (a BOM is not
// stripped), nested at most LIMITS.depth, and results a list of objects with a string id and status,
// as a run export writes it. A payments-pack run's verdicts are its rows', read only from a run that
// passes attest's payments checks (the pack's own reader rules). The writer uses it too, so it never
// records a run it cannot read back.
export const isPaymentsRun = run => run.schema === PAYMENTS_RUN_SCHEMA;
export function runFileVerdicts(bytes, { payments = false } = {}) {
  try {
    const text = utf8.decode(bytes);
    if (tooDeep(text)) return null;
    if (payments) {
      const run = savedRun('run file', Buffer.from(bytes));
      return run?.payments ? run.core.rows.map(r => [r.id, r.status]) : null;
    }
    const list = JSON.parse(text).results;
    if (!Array.isArray(list) || !list.every(r => plain(r) && typeof r.id === 'string' && typeof r.status === 'string')) return null;
    return list.map(r => [r.id, r.status]);
  } catch { return null; }
}

// Everything about the entries, without checkpoints: what the writer checks before it appends or signs.
export function verifyEntries({ metadata, entries, envelopes, evidenceKey, runFiles }) {
  return entriesOf({ metadata, entries, envelopes, evidence: trustedKey(evidenceKey), runFiles });
}
function entriesOf({ metadata, entries, envelopes, evidence, runFiles }) {
  const meta = readMetadata(metadata);
  const parsed = lines(entries, LIMITS.entries, 'entry-shape').map(line => ({ line, entry: canonical(line, 'entry-shape', 'entry-not-canonical') }));
  const leaves = checkChain(parsed, meta.createdAt);
  // Every entry's envelope: present, the digest it names, signed by the evidence key, and the run
  // identities it states are the ones the entry recorded, in order. Not before the envelope was signed.
  // Each envelope and each run id appears once. A run id recorded twice would let a later entry
  // replace an earlier run's verdicts or custody anchors, so anchors are append-only per run.
  const seen = new Set(), runIds = new Set();
  let verdictsChecked = 0, runCount = 0;
  for (const { entry } of parsed) {
    if (seen.has(entry.envelope.sha256)) reject('envelope-duplicate', `entry ${entry.index} repeats an earlier envelope`);
    seen.add(entry.envelope.sha256);
    for (const run of entry.runs) {
      if (runIds.has(run.id)) reject('run-replayed', `entry ${entry.index} records run ${run.id} again`);
      runIds.add(run.id);
    }
    const bytes = envelopes instanceof Map ? envelopes.get(entry.envelope.sha256) : envelopes?.[entry.envelope.sha256];
    if (!Buffer.isBuffer(bytes)) reject('envelope-missing', `entry ${entry.index}`);
    if (createHash('sha256').update(bytes).digest('hex') !== entry.envelope.sha256) reject('envelope-mismatch', `entry ${entry.index}`);
    let read;
    try { read = readSignedStatement(bytes, evidence); }
    catch (error) { if (error instanceof Rejected) reject('envelope-invalid', `entry ${entry.index}: ${error.reason}`); throw error; }
    if (read.keyid !== entry.envelope.keyid) reject('envelope-invalid', `entry ${entry.index}: keyid`);
    if (Date.parse(entry.recordedAt) < Date.parse(read.statement.predicate.signedAt)) reject('time-regression', `entry ${entry.index} is dated before its evidence was signed`);
    if (JSON.stringify(entry.runs.map(identityOf)) !== JSON.stringify(read.statement.predicate.runs)) reject('run-mismatch', `entry ${entry.index}`);
    for (const run of entry.runs) {
      runCount++;
      const digest = read.statement.subject.find(s => s.name === run.subject)?.digest.sha256, file = digest && runFiles?.get(digest);
      if (!file) continue;
      const results = runFileVerdicts(file, { payments: isPaymentsRun(run) });
      if (results === null) reject('verdict-mismatch', `entry ${entry.index}: run file unreadable or not a ${isPaymentsRun(run) ? 'payments run the pack\'s reader takes' : 'run export'}`);
      if (JSON.stringify(results) !== JSON.stringify(run.verdicts)) reject('verdict-mismatch', `entry ${entry.index}: recorded verdicts differ from the signed run file`);
      verdictsChecked++;
    }
  }
  return { meta, parsed, leaves, verdictsChecked, runCount };
}

function examine({ metadata, entries, checkpoints, envelopes, key, keyid, evidence, sig, runFiles }) {
  const { meta, parsed, leaves, verdictsChecked, runCount } = entriesOf({ metadata, entries, envelopes, evidence, runFiles });
  const raw = lines(checkpoints, LIMITS.checkpoints, 'checkpoint-shape');
  if (!raw.length) reject('no-checkpoint', 'no signed checkpoint covers this log');
  const points = raw.map(text => readCheckpoint(text, key, keyid, meta.log, sig, meta.createdAt));
  const bySize = new Map();
  for (const p of points) {
    const seen = bySize.get(p.treeSize);
    if (seen && (seen.rootHash !== p.rootHash || seen.headHash !== p.headHash)) reject('fork', `two signed heads at size ${p.treeSize}`);
    bySize.set(p.treeSize, p);
  }
  points.forEach((point, i) => {
    if (i && (point.treeSize < points[i - 1].treeSize || Date.parse(point.signedAt) < Date.parse(points[i - 1].signedAt))) reject('checkpoint-regression', `checkpoint ${i + 1} goes back in size or time`);
  });
  const heads = treeHeadsAt(leaves, points.map(p => p.treeSize));
  for (const point of points) {
    if (point.treeSize > leaves.length) reject('checkpoint-mismatch', `a checkpoint covers ${point.treeSize} entries; the log has ${leaves.length}`);
    if (heads.get(point.treeSize).toString('hex') !== point.rootHash || leaves[point.treeSize - 1].toString('hex') !== point.headHash) reject('checkpoint-mismatch', `size ${point.treeSize}`);
    // Entry times never decrease (checked above), so the last covered entry is the latest.
    if (Date.parse(parsed[point.treeSize - 1].entry.recordedAt) > Date.parse(point.signedAt)) reject('time-regression', `an entry is dated after the checkpoint at size ${point.treeSize}`);
  }
  return { meta, entries: parsed, leaves, points, rawPoints: raw, envelopes, verdictsChecked, runCount };
}

// After a pass, tampered copies go through the same checks and must be rejected.
function negativeControls({ meta, entries, leaves, points, rawPoints, envelopes }, key, sig, evidence) {
  const flip = bytes => { const copy = Buffer.from(bytes); copy[copy.length >> 1] ^= 1; return copy; };
  const passes = attempt => { try { attempt(); return true; } catch (error) { if (error instanceof Rejected) return false; throw error; } };
  const last = points.at(-1), env = JSON.parse(rawPoints.at(-1)), payload = Buffer.from(env.payload, 'base64'), signature = Buffer.from(env.signatures[0].sig, 'base64');
  const other = generateKeyPairSync('ed25519').publicKey;
  const controls = [
    ['checkpoint-payload-tampered', () => sig(key, CHECKPOINT_TYPE, flip(payload), signature)],
    ['checkpoint-wrong-key', () => sig(other, CHECKPOINT_TYPE, payload, signature)],
    ['entry-rewritten', () => treeHead([leafHash(flip(Buffer.from(entries[0].line))), ...leaves.slice(1, last.treeSize)]).toString('hex') === last.rootHash],
    ['inclusion-path-tampered', () => last.treeSize > 1 && verifyInclusionPath(leaves[0], 0, last.treeSize, inclusionPathFor(leaves.slice(0, last.treeSize), 0).map((h, i) => i ? h : flip(h)), Buffer.from(last.rootHash, 'hex'))],
  ];
  // The envelope signature path: a stored envelope with one signature bit flipped must not read.
  const stored = JSON.parse((envelopes instanceof Map ? envelopes.get(entries[0].entry.envelope.sha256) : envelopes[entries[0].entry.envelope.sha256]).toString('utf8'));
  stored.signatures[0].sig = flip(Buffer.from(stored.signatures[0].sig, 'base64')).toString('base64');
  controls.push(['envelope-signature-tampered', () => passes(() => readSignedStatement(Buffer.from(JSON.stringify(stored)), evidence))]);
  if (entries.length > 1) controls.push(['entries-reordered', () => passes(() => checkChain([entries[1], entries[0], ...entries.slice(2)], meta.createdAt))]);
  return controls.map(([id, attempt]) => {
    let accepted;
    try { accepted = attempt() === true; } catch (error) { if (!(error instanceof Rejected)) throw error; accepted = false; }
    return { id, expected: 'rejected', observed: accepted ? 'accepted' : 'rejected' };
  });
}

// The audit path a verifier recomputes for its own control (RFC 9162 section 2.1.3.1).
function inclusionPathFor(leaves, m) {
  if (leaves.length <= 1) return [];
  const k = split(leaves.length);
  return m < k ? [...inclusionPathFor(leaves.slice(0, k), m), treeHead(leaves.slice(k))] : [...inclusionPathFor(leaves.slice(k), m - k), treeHead(leaves.slice(0, k))];
}

// RFC 9162 section 2.1.3.2.
export function verifyInclusionPath(leaf, index, treeSize, path, root) {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(treeSize) || index < 0 || index >= treeSize || path.length > LIMITS.proofLength) return false;
  let fn = index, sn = treeSize - 1, r = leaf;
  for (const p of path) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else r = nodeHash(r, p);
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return sn === 0 && r.equals(root);
}

// RFC 9162 section 2.1.4.2, with the equal-size and empty-first cases made explicit.
export function verifyConsistencyPath(first, second, path, firstRoot, secondRoot) {
  if (!Number.isSafeInteger(first) || !Number.isSafeInteger(second) || first < 1 || first > second || path.length > LIMITS.proofLength) return false;
  if (first === second) return path.length === 0 && firstRoot.equals(secondRoot);
  if (!path.length) return false;
  const list = (first & (first - 1)) === 0 ? [firstRoot, ...path] : [...path];
  let fn = first - 1, sn = second - 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  let fr = list[0], sr = list[0];
  for (const c of list.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr); sr = nodeHash(c, sr);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else sr = nodeHash(sr, c);
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return sn === 0 && fr.equals(firstRoot) && sr.equals(secondRoot);
}

const hexList = (list, reason) => {
  if (!Array.isArray(list) || list.length > LIMITS.proofLength || !list.every(h => typeof h === 'string' && HEX64.test(h))) reject(reason, 'path');
  return list.map(h => Buffer.from(h, 'hex'));
};
const result = (attempt, keyid) => {
  try { return { verified: true, verdict: 'verified', reason: null, keyid, ...attempt() }; }
  catch (error) { if (!(error instanceof Rejected)) throw error; return { verified: false, verdict: 'rejected', reason: error.reason, detail: error.message, keyid }; }
};

// One entry, without the rest of the log: its line, an inclusion proof and a signed checkpoint.
export function verifyInclusion({ entryLine, proof, checkpoint, ledgerKey }) {
  const key = trustedKey(ledgerKey), keyid = keyIdOf(key);
  return result(() => {
    const point = readCheckpoint(trimmed(checkpoint), key, keyid);
    const entry = canonical(String(entryLine).replace(/\n$/, ''), 'entry-shape', 'entry-not-canonical');
    entryShape(entry);
    if (!exactKeys(proof, ['_type', 'log', 'index', 'treeSize', 'path']) || proof._type !== INCLUSION_VERSION || proof.log !== point.log) reject('inclusion-proof-invalid', 'shape');
    if (proof.index !== entry.index || proof.treeSize !== point.treeSize) reject('inclusion-proof-invalid', 'the proof is for another entry or tree size');
    const leaf = leafHash(Buffer.from(String(entryLine).replace(/\n$/, '')));
    if (!verifyInclusionPath(leaf, entry.index, point.treeSize, hexList(proof.path, 'inclusion-proof-invalid'), Buffer.from(point.rootHash, 'hex'))) reject('inclusion-proof-invalid');
    return { log: point.log, index: entry.index, treeSize: point.treeSize, witness: 'none' };
  }, keyid);
}

// Two signed checkpoints of one log and a proof that the older is a prefix of the newer.
export function verifyConsistency({ older, newer, proof, ledgerKey }) {
  const key = trustedKey(ledgerKey), keyid = keyIdOf(key);
  return result(() => {
    const a = readCheckpoint(trimmed(older), key, keyid), b = readCheckpoint(trimmed(newer), key, keyid, a.log);
    if (a.treeSize === b.treeSize && (a.rootHash !== b.rootHash || a.headHash !== b.headHash)) reject('fork', `two signed heads at size ${a.treeSize}`);
    if (b.treeSize < a.treeSize || Date.parse(b.signedAt) < Date.parse(a.signedAt)) reject('checkpoint-regression');
    if (!exactKeys(proof, ['_type', 'log', 'from', 'to', 'path']) || proof._type !== CONSISTENCY_VERSION || proof.log !== a.log || proof.from !== a.treeSize || proof.to !== b.treeSize) reject('consistency-proof-invalid', 'shape');
    if (!verifyConsistencyPath(a.treeSize, b.treeSize, hexList(proof.path, 'consistency-proof-invalid'), Buffer.from(a.rootHash, 'hex'), Buffer.from(b.rootHash, 'hex'))) reject('consistency-proof-invalid', 'the newer checkpoint does not extend the older one');
    return { log: a.log, from: a.treeSize, to: b.treeSize, witness: 'none' };
  }, keyid);
}
