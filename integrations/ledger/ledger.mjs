// Scopehaven evidence ledger, writer side (scopehaven-ledger/1). One directory per log:
//   ledger.json       { ledger, log, createdAt }
//   entries.jsonl     one canonical JSON entry per line, each naming the previous entry's leaf hash
//   checkpoints.jsonl one DSSE-signed Merkle tree head per line (RFC 9162 hashing)
//   envelopes/        a copy of every signed run envelope, named by its SHA-256
//   pending.json      only while a signed append is being written: its entry line, envelope and
//                     signed checkpoint, so `checkpoint` can finish it exactly as signed
// An envelope enters only after integrations/attest verifies it against its files; the entry records
// the run identities its signed statement gives and each run's per-check verdicts from the run file
// (a run export's results, or a payments-pack run's rows).
// Tree heads and proofs are computed here with code verify.mjs does not share. The directory must be
// private (0700, owned, not a symlink); every file is written new or appended, never rewritten.
import { constants } from 'node:fs';
import { link, lstat, mkdir, open, readdir, rename, unlink } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { createHash, createPrivateKey, createPublicKey, randomUUID, sign, verify, KeyObject } from 'node:crypto';
import { verifyEnvelope } from '../attest/verify.mjs';
import { Rejected } from '../attest/verify.mjs';
import { CHECKPOINT_MEANING, CHECKPOINT_TYPE, CHECKPOINT_VERSION, CONSISTENCY_VERSION, INCLUSION_VERSION, LEDGER_VERSION, LIMITS, SIGNATURE_LINE, checkEntry, cosignerName, isPaymentsRun, runFileVerdicts, verifyEntries, verifyLedger } from './verify.mjs';

const sha256 = (...parts) => createHash('sha256').update(Buffer.concat(parts.map(p => Buffer.from(p)))).digest();
const hex = bytes => Buffer.from(bytes).toString('hex');

// RFC 9162 section 2.1: leaf 0x00, node 0x01, the tree head, audit paths and consistency proofs.
const leaf = line => sha256(Buffer.from([0]), Buffer.from(line));
const node = (l, r) => sha256(Buffer.from([1]), l, r);
const largestPowerBelow = n => 2 ** Math.floor(Math.log2(n - 1));
function head(hashes) {
  if (hashes.length === 0) return sha256();
  if (hashes.length === 1) return hashes[0];
  const k = largestPowerBelow(hashes.length);
  return node(head(hashes.slice(0, k)), head(hashes.slice(k)));
}
function auditPath(hashes, m) {
  if (hashes.length <= 1) return [];
  const k = largestPowerBelow(hashes.length);
  return m < k ? [...auditPath(hashes.slice(0, k), m), head(hashes.slice(k))] : [...auditPath(hashes.slice(k), m - k), head(hashes.slice(0, k))];
}
function subproof(m, hashes, complete) {
  if (m === hashes.length) return complete ? [] : [head(hashes)];
  const k = largestPowerBelow(hashes.length);
  return m <= k ? [...subproof(m, hashes.slice(0, k), complete), head(hashes.slice(k))] : [...subproof(m - k, hashes.slice(k), false), head(hashes.slice(0, k))];
}

const signingKey = input => {
  let key = input;
  if (!(key instanceof KeyObject)) try { key = createPrivateKey(input); } catch { key = null; }
  if (key?.type !== 'private' || key.asymmetricKeyType !== 'ed25519') throw new Error('Checkpoints need an Ed25519 private key.');
  return key;
};
const pae = (type, body) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${body.length} `), body]);

// Pure: the entry for an envelope that attest verified (`check`), given the previous line.
// anchors: Map of run subject -> [{ source, custody, count, head }], already classified.
export function buildEntry({ previousLine, index, recordedAt, envelope, check, files, anchors = new Map() }) {
  const runs = check.runs.map(identity => {
    let verdicts;
    if (isPaymentsRun(identity)) {
      // Attest checked this run when it verified the envelope; its rows are read through the same checks.
      verdicts = runFileVerdicts(files.get(identity.subject), { payments: true });
      if (!verdicts) throw new Error(`${identity.subject} is not a run file the verifiers can read back (not UTF-8, nested deeper than ${LIMITS.depth}, or not a payments run the pack's reader takes); nothing was appended.`);
    } else {
      const run = JSON.parse(files.get(identity.subject).toString('utf8'));
      if (!Array.isArray(run.results)) throw new Error(`${identity.subject} has no results.`);
      verdicts = run.results.map(r => [r.id, r.status]);
    }
    return { ...identity, verdicts, verdictDigest: hex(sha256(JSON.stringify(verdicts))), anchors: anchors.get(identity.subject) ?? [] };
  });
  return { index, prev: previousLine === null ? null : hex(leaf(previousLine)), recordedAt, envelope: { sha256: hex(sha256(envelope)), keyid: check.keyid }, runs };
}

// Pure: a signed checkpoint line over the first treeSize entry lines. createdAt is ledger.json's,
// so the metadata is signed through every checkpoint.
export function signCheckpoint({ log, createdAt, lines, treeSize = lines.length, signedAt, privateKey }) {
  const key = signingKey(privateKey), hashes = lines.slice(0, treeSize).map(leaf);
  const payload = Buffer.from(JSON.stringify({ _type: CHECKPOINT_VERSION, log, ledgerCreatedAt: createdAt, treeSize, rootHash: hex(head(hashes)), headHash: hex(hashes.at(-1)), signedAt, witness: 'none', meaning: CHECKPOINT_MEANING }));
  const keyid = hex(sha256(createPublicKey(key).export({ type: 'spki', format: 'der' })));
  return JSON.stringify({ payloadType: CHECKPOINT_TYPE, payload: payload.toString('base64'), signatures: [{ keyid, sig: sign(null, pae(CHECKPOINT_TYPE, payload), key).toString('base64') }] });
}

// The signed intent a signed append keeps in pending.json while it writes. It fixes the head the
// append's checkpoint will have (size, root, head, time) under its own payload type, so it is never a
// checkpoint: both verifiers refuse it as one, and an abandoned intent is not a second signed head.
// Recovery re-signs the checkpoint from it; Ed25519 signatures are deterministic, so that checkpoint
// is byte for byte the line the append would have written.
export const INTENT_TYPE = 'application/vnd.scopehaven.ledger-intent+json';
export const INTENT_VERSION = 'scopehaven-ledger-intent/1';
export const INTENT_MEANING = 'Not a checkpoint. The log operator intends to append the entry with this head; a checkpoint over it exists only as a line in checkpoints.jsonl.';
export function signIntent({ log, createdAt, lines, signedAt, privateKey }) {
  const key = signingKey(privateKey), hashes = lines.map(leaf);
  const payload = Buffer.from(JSON.stringify({ _type: INTENT_VERSION, log, ledgerCreatedAt: createdAt, treeSize: lines.length, rootHash: hex(head(hashes)), headHash: hex(hashes.at(-1)), signedAt, meaning: INTENT_MEANING }));
  const keyid = hex(sha256(createPublicKey(key).export({ type: 'spki', format: 'der' })));
  return JSON.stringify({ payloadType: INTENT_TYPE, payload: payload.toString('base64'), signatures: [{ keyid, sig: sign(null, pae(INTENT_TYPE, payload), key).toString('base64') }] });
}
// The intent's fields when it is signed by publicKey under INTENT_TYPE, else null.
function readIntent(line, publicKey) {
  try {
    const env = JSON.parse(line), keyid = hex(sha256(publicKey.export({ type: 'spki', format: 'der' })));
    if (env.payloadType !== INTENT_TYPE || !Array.isArray(env.signatures) || env.signatures.length !== 1 || env.signatures[0].keyid !== keyid) return null;
    const payload = Buffer.from(env.payload, 'base64'), signature = Buffer.from(env.signatures[0].sig, 'base64');
    if (signature.length !== 64 || !verify(null, pae(INTENT_TYPE, payload), publicKey, signature)) return null;
    const body = JSON.parse(payload.toString('utf8'));
    if (body._type !== INTENT_VERSION || body.meaning !== INTENT_MEANING || !Number.isSafeInteger(body.treeSize) || body.treeSize < 1) return null;
    return body;
  } catch { return null; }
}

export function inclusionProof({ log, lines, index, treeSize }) {
  if (!(Number.isSafeInteger(index) && Number.isSafeInteger(treeSize) && index >= 0 && index < treeSize && treeSize <= lines.length)) throw new Error('No such entry in a tree of that size.');
  return { _type: INCLUSION_VERSION, log, index, treeSize, path: auditPath(lines.slice(0, treeSize).map(leaf), index).map(hex) };
}

export function consistencyProof({ log, lines, from, to }) {
  if (!(Number.isSafeInteger(from) && Number.isSafeInteger(to) && from >= 1 && from <= to && to <= lines.length)) throw new Error('Consistency needs 1 <= from <= to <= the log size.');
  return { _type: CONSISTENCY_VERSION, log, from, to, path: (from === to ? [] : subproof(from, lines.slice(0, to).map(leaf), true)).map(hex) };
}

// ---- Files ----
async function privateDirectory(dir) {
  const stat = await lstat(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o7777) !== 0o700) throw new Error(`${dir} must be a private directory (mode 0700), owned by you and not a symlink.`);
  return stat;
}
// A new or removed name is durable only once its directory is synced.
async function syncDirectory(dir) {
  const handle = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await handle.sync(); } finally { await handle.close(); }
}
async function readBounded(path, limit) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > limit) throw new Error(`${path} must be a regular file of at most ${limit} bytes.`);
    return await handle.readFile();
  } finally { await handle.close(); }
}
async function writeNew(path, content, mode = 0o600) {
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
  let stat;
  try { await handle.writeFile(content); await handle.sync(); stat = await handle.stat(); }
  catch (error) { await handle.close(); await unlink(path).catch(() => {}); throw error; }
  await handle.close();
  try { await syncDirectory(dirname(path)); } catch (error) { await removeOwn(path, stat); throw error; }
  return stat;
}
// A file that appears whole or not at all: written and synced under a temporary name (dot-prefixed,
// so neither verifier reads it), then linked into place, which never replaces an existing name, and
// the folder synced. A crash leaves at most a stray temporary file, never a torn `path`.
async function writeWhole(path, content) {
  const temp = join(dirname(path), `.${basename(path)}.${randomUUID()}.tmp`);
  const own = await writeNew(temp, content);
  try { await link(temp, path); } finally { await removeOwn(temp, own); }
  await syncDirectory(dirname(path));
  return own;
}
async function appendLine(path, line) {
  const handle = await open(path, constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW);
  try { await handle.writeFile(`${line}\n`); await handle.sync(); } finally { await handle.close(); }
}
// One writer at a time. A leftover lock after a crash is reported, never broken automatically, and a
// writer removes the lock only while it still holds this writer's own token.
async function withLock(dir, work) {
  const lock = join(dir, '.lock'), token = `${process.pid} ${randomUUID()}\n`;
  try { await writeNew(lock, token); }
  catch (error) { if (error.code === 'EEXIST') throw new Error(`${lock} exists: another writer is active, or one stopped early. Remove it only if no writer is running.`); throw error; }
  try { await removeStrayTemps(dir); return await work(); }
  finally {
    const held = await readBounded(lock, 4096).catch(() => null);
    if (held?.toString('utf8') === token) await unlink(lock).then(() => syncDirectory(dir)).catch(() => {});
  }
}
// Temporary files a write that stopped part way can leave: a whole signed pending record or envelope
// under a dot-prefixed name. No other writer of ours can be writing one while we hold the lock, so they
// are removed then (a stray signed pending record is the same fork material as a stale pending.json).
const STRAY = { top: /^\.pending\.json\.[0-9a-f-]{36}\.tmp$/, envelopes: /^\.[0-9a-f]{64}\.[0-9a-f-]{36}\.tmp$/ };
async function removeStrayTemps(dir) {
  for (const [folder, pattern] of [[dir, STRAY.top], [join(dir, 'envelopes'), STRAY.envelopes]]) {
    let names;
    try { names = await readdir(folder); } catch { continue; }
    let removed = false;
    for (const name of names.filter(n => pattern.test(n))) {
      const stat = await lstat(join(folder, name)).catch(() => null);
      if (stat?.isFile()) { await unlink(join(folder, name)).catch(() => {}); removed = true; }
    }
    if (removed) await syncDirectory(folder);
  }
}
const MAX = { meta: 4096, entries: LIMITS.entries * LIMITS.lineBytes, checkpoints: LIMITS.checkpoints * LIMITS.lineBytes, envelope: 2 * 1024 * 1024 };
MAX.pending = 2 * MAX.envelope + 2 * LIMITS.lineBytes;
const PENDING = 'pending.json', PENDING_VERSION = 'scopehaven-ledger-pending/2';
const splitLines = bytes => { const text = bytes.toString('utf8'); return text ? text.slice(0, -1).split('\n') : []; };

export async function initLedger(dir, { now = new Date() } = {}) {
  await privateDirectory(dir);
  const meta = { ledger: LEDGER_VERSION, log: randomUUID(), createdAt: now.toISOString() };
  await writeNew(join(dir, 'ledger.json'), `${JSON.stringify(meta)}\n`);
  await writeNew(join(dir, 'entries.jsonl'), '');
  await writeNew(join(dir, 'checkpoints.jsonl'), '');
  await mkdir(join(dir, 'envelopes'), { mode: 0o700 });
  return meta;
}

export async function readLedgerFiles(dir) {
  const [metadata, entries, checkpoints] = await Promise.all([readBounded(join(dir, 'ledger.json'), MAX.meta), readBounded(join(dir, 'entries.jsonl'), MAX.entries), readBounded(join(dir, 'checkpoints.jsonl'), MAX.checkpoints)]);
  const envelopes = new Map();
  for (const name of await readdir(join(dir, 'envelopes'))) {
    if (!/^[0-9a-f]{64}\.json$/.test(name)) continue;
    try { envelopes.set(name.slice(0, 64), await readBounded(join(dir, 'envelopes', name), MAX.envelope)); }
    catch (error) {
      if (error.code === 'ELOOP' || /must be a regular file/.test(error.message)) throw new Error(`envelopes/${name} is a symlink, a folder or too large, not an envelope copy. Nothing was written; remove it (or put the real envelope there), then run again.`);
      throw error;
    }
  }
  // Witness cosignatures (verify.mjs, C2SP cosignature/v1): optional, added by witnesses, never by this writer.
  let cosignatures = Buffer.alloc(0);
  try { cosignatures = await readBounded(join(dir, 'cosignatures.jsonl'), MAX.checkpoints); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  return { metadata, entries, checkpoints, envelopes, cosignatures };
}

// Custody anchors for EVID-SUBJECT (integrations/evid-subject/custody.mjs): per run subject, the
// { count, head } of anchorOf() over an observer-kept evidence chain, with its source. Custody is
// never taken from the caller: custodyOf() derives it from the source, and a declaration can only
// lower it. Loaded only when anchors are given, so the ledger works without that module.
export async function classifyAnchors(raw) {
  const anchors = new Map();
  if (!raw || !raw.size) return anchors;
  let module;
  try { module = await import('../evid-subject/custody.mjs'); }
  catch { throw new Error('Custody anchors need integrations/evid-subject (EVID-SUBJECT).'); }
  const { custodyOf, CUSTODY, CUSTODY_BY_SOURCE } = module;
  for (const [subject, list] of raw) {
    if (!Array.isArray(list) || new Set(list.map(a => a?.source)).size !== list.length) throw new Error(`Anchors for ${subject} must be a list with one entry per source.`);
    anchors.set(subject, list.map(({ source, count, head, declaredCustody = null }) => {
      // Only an observer source EVID-SUBJECT knows. The source is the caller's statement of which
      // observer kept the chain; custody follows from it and can only be lowered by a declaration.
      if (typeof source !== 'string' || !Object.hasOwn(CUSTODY_BY_SOURCE, source)) throw new Error(`Unknown observer source for ${subject}: ${String(source)}.`);
      if (!Number.isSafeInteger(count) || count < 0 || (count === 0 ? head !== null : !/^[0-9a-f]{64}$/.test(head ?? ''))) throw new Error(`Invalid anchor for ${subject}.`);
      const custody = custodyOf({ source }, { declared: declaredCustody });
      if (!CUSTODY.includes(custody)) throw new Error(`Unknown custody for ${subject}.`);
      return { source, custody, count, head };
    }));
  }
  return anchors;
}

// The writer never builds on a ledger it cannot verify: a rewritten or torn entry stops it.
// With the ledger key it also checks every checkpoint, and refuses to extend an unsigned tail.
async function checkExisting(dir, evidenceKey, privateKey) {
  const files = await readLedgerFiles(dir);
  // With checkpoints and the key, one full verification covers the entries too (they are checked once).
  if (privateKey && files.checkpoints.length) {
    const result = verifyLedger({ ...files, ledgerKey: createPublicKey(privateKey), evidenceKey });
    if (!result.verified) throw new Error(`The existing ledger does not verify (${result.reason}: ${result.detail}); nothing was written. ${CRASH}`);
    if (result.unsignedTail) throw new Error(`${result.unsignedTail} entries are not covered by a checkpoint in this folder. ${unexplained(result.covered)}`);
    return files;
  }
  let parsed;
  try { ({ parsed } = verifyEntries({ ...files, evidenceKey })); }
  catch (error) { if (error instanceof Rejected) throw new Error(`The existing ledger does not verify (${error.reason}: ${error.message}); nothing was written. ${CRASH}`); throw error; }
  if (privateKey && parsed.length) throw new Error(`Entries exist with no checkpoint in this folder. ${unexplained(0)}`);
  return files;
}
const CRASH = 'If the last line was cut off by a crash, restore the folder from your last verified copy.';
// This folder only shows which lines its own checkpoints.jsonl covers. A checkpoint line can be lost
// (deleted by someone who can write the folder, or an older copy of the file restored) while a reader
// still holds it, so advice to remove lines or append again always says to check held checkpoints first.
const forkWarning = covered => `Before removing anything or appending again, compare with the last checkpoint you or an auditor hold: if it covers more than ${covered} entries, this folder has lost checkpoint lines or was restored from an older copy, so restore checkpoints.jsonl and entries.jsonl from a copy that verifies against that checkpoint instead. Removing lines and appending again would sign a second history at a size someone already holds (a fork).`;
const unexplained = covered => `A signed append never leaves such lines: it finishes, or it keeps pending.json for \`checkpoint\` to finish. So they came from an unsigned append, from someone else who can write the folder, or from a checkpoints.jsonl that lost lines. Nothing was written. ${forkWarning(covered)} Otherwise remove those lines from entries.jsonl (no checkpoint in this folder covers them), then append again.`;

// The lock keeps out other runs of this writer, not someone else who can write the folder. So the new
// entry and its checkpoint are built only from the bytes just verified, and both files are compared
// with those bytes immediately before writing and again after. A line this writer did not write is
// never inside a checkpoint it signs: it stays an unsigned tail, or the ledger stops verifying.
async function unchanged(dir, verified) {
  const [entries, checkpoints] = await Promise.all([readBounded(join(dir, 'entries.jsonl'), MAX.entries), readBounded(join(dir, 'checkpoints.jsonl'), MAX.checkpoints)]);
  return entries.equals(verified.entries) && checkpoints.equals(verified.checkpoints);
}
const CHANGED = 'The ledger changed while this write was being prepared (another writer?); nothing was written.';
const STOPPED = 'pending.json keeps this write exactly as signed. Run `checkpoint` to finish it: it signs only the checkpoint the signed intent of this write already fixes, refuses any line this write did not make, and says what to remove first if something else changed.';
const CHANGED_DURING = `The ledger changed during this write, so it was not finished. Lines this writer did not write are not inside its checkpoint; the ledger may still verify with them as an unsigned tail, and they must not be signed. ${STOPPED}`;

// The envelope copy. envelopes/ is checked, the copy is written whole under a temporary name and
// linked into place (renamed over an existing file only when the caller allows it), and the folder is
// checked again before and after: if it was swapped for a symlink or another folder, the files this
// writer just made are removed and the write refused.
const sameFolder = (a, b) => a.isDirectory() && !a.isSymbolicLink() && a.dev === b.dev && a.ino === b.ino;
async function removeOwn(path, own) {
  const now = await lstat(path).catch(() => null);
  if (now && now.dev === own.dev && now.ino === own.ino) await unlink(path).catch(() => {});
}
// replace: an existing file at this digest with other bytes (a copy torn by a crash in an older
// writer, or anything else) may be replaced. Callers allow it only when no entry a checkpoint already
// covers names this envelope, so a copy the signed history relies on is never touched.
async function writeEnvelopeCopy(dir, digest, envelope, { hooks = {}, replace = false } = {}) {
  const folder = join(dir, 'envelopes'), path = join(folder, `${digest}.json`), REPLACED = 'envelopes/ was replaced during this write.';
  const before = await privateDirectory(folder);
  const sameAsBefore = async () => sameFolder(await lstat(folder), before);
  await hooks.beforeEnvelope?.();
  let existing = null;
  try { existing = await readBounded(path, MAX.envelope); }
  catch (error) {
    if (error.code === 'ENOENT') existing = null;
    else if (error.code === 'ELOOP' || /must be a regular file/.test(error.message)) throw new Error(`envelopes/${digest}.json is a symlink, a folder or too large, not an envelope copy. Nothing was written to it; remove it, then run again.`);
    else throw error;
  }
  if (existing?.equals(envelope)) { if (!(await sameAsBefore())) throw new Error(REPLACED); return; }
  if (existing && !replace) throw new Error(`envelopes/${digest}.json holds other bytes, and an entry a checkpoint covers names it; nothing was written.`);
  if (!(await sameAsBefore())) throw new Error(REPLACED);
  const temp = join(folder, `.${digest}.${randomUUID()}.tmp`);
  let own = null;
  try {
    own = await writeNew(temp, envelope);
    if (!(await sameAsBefore())) throw new Error(REPLACED);
    if (existing) await rename(temp, path); else await link(temp, path);
  } finally { if (own) await removeOwn(temp, own); }
  const placed = await lstat(path).catch(() => null);
  if (!(await sameAsBefore()) || !placed || placed.dev !== own.dev || placed.ino !== own.ino) { await removeOwn(path, own); throw new Error(REPLACED); }
  await syncDirectory(folder);
}

const pendingRecord = ({ line, intent, envelope }) => `${JSON.stringify({ _type: PENDING_VERSION, line, intent, envelope: Buffer.from(envelope).toString('base64') })}\n`;
// null when there is no pending.json; { unreadable: true } when it is not a whole record in this
// writer's format (this writer places it whole, so that means someone else wrote or changed it).
async function readPending(dir) {
  let bytes;
  try { bytes = await readBounded(join(dir, PENDING), MAX.pending); }
  catch (error) {
    if (error.code === 'ENOENT') return null;
    if (error.code === 'ELOOP' || /must be a regular file/.test(error.message)) throw new Error('pending.json is a symlink, a folder or too large, not a pending record this writer made; nothing was signed. Remove it, then run again (if it pointed at a real pending record, copy that record into place first).');
    throw error;
  }
  let record;
  try { record = JSON.parse(bytes.toString('utf8')); } catch { record = null; }
  const ok = record && record._type === PENDING_VERSION && Object.keys(record).length === 4 && ['line', 'intent', 'envelope'].every(k => typeof record[k] === 'string');
  if (!ok) return { unreadable: true };
  return { line: record.line, intent: record.intent, envelope: Buffer.from(record.envelope, 'base64') };
}
// What the operator should do when pending.json cannot be finished, judged from the ledger on its own,
// so the advice is to restore the whole folder only when nothing narrower would do.
function pendingAdvice(problem, verified, ledgerKey, evidenceKey) {
  const alone = verifyLedger({ ...verified, ledgerKey, evidenceKey });
  if (alone.verified && !alone.unsignedTail) return `${problem} Nothing was signed. The ledger verifies on its own and a checkpoint covers every entry, so nothing in this folder depends on pending.json: delete it (it holds a signed intent, never a checkpoint), then append again. ${forkWarning(alone.covered)}`;
  if (alone.verified) return `${problem} Nothing was signed. The ledger verifies up to its last checkpoint (${alone.covered} entries), and no checkpoint in this folder covers the ${alone.unsignedTail} lines after it. ${forkWarning(alone.covered)} Otherwise remove those lines from entries.jsonl, then run \`checkpoint\` again. It finishes the pending write if that write follows entry ${alone.covered}, and otherwise says pending.json can be deleted.`;
  return `${problem} Nothing was signed. The ledger does not verify on its own (${alone.reason}). ${RESTORE}`;
}
async function removePending(dir) { await unlink(join(dir, PENDING)); await syncDirectory(dir); }
const payloadOf = line => JSON.parse(Buffer.from(JSON.parse(line).payload, 'base64').toString('utf8'));

// Appends one verified envelope. files: Map of subject name -> Buffer, as attest verifies them.
// anchors (optional): Map of run subject -> [{ source, count, head, declaredCustody? }].
// privateKey (the supported path): signs a checkpoint over the new entry before anything is written,
// keeps it with the entry in pending.json until both are appended, so a write that stops part way is
// finished by `checkpoint` exactly as signed, and no unsigned entry is left for someone to edit first.
// Without privateKey the entry is left unsigned; checkpointLedger signs it only given its lineSha256.
// hooks is a test seam only: afterVerify, afterSign, beforeWrite and beforeEnvelope run at those points.
export async function appendEnvelope(dir, { envelope, files, evidenceKey, privateKey, anchors: rawAnchors, now = new Date() }, hooks = {}) {
  const key = privateKey === undefined ? null : signingKey(privateKey);
  await privateDirectory(dir);
  const anchors = await classifyAnchors(rawAnchors);
  return withLock(dir, async () => {
    if (await readPending(dir)) throw new Error('pending.json exists: an earlier append did not finish. Run `checkpoint` to finish it (it signs only the checkpoint the intent of that append fixes, and says what to do if it cannot); nothing was written.');
    const verified = await checkExisting(dir, evidenceKey, key);
    await hooks.afterVerify?.();
    const check = verifyEnvelope({ envelope, publicKey: evidenceKey, files });
    if (!check.verified) throw new Error(`The envelope did not verify (${check.verdict}: ${check.detail ?? check.reason}); nothing was appended.`);
    if (new Set(check.runs.map(run => run.id)).size !== check.runs.length) throw new Error('This envelope names one run more than once; nothing was appended.');
    const meta = JSON.parse(verified.metadata.toString('utf8'));
    const lines = splitLines(verified.entries), points = splitLines(verified.checkpoints);
    if (lines.length >= LIMITS.entries) throw new Error('The ledger is full.');
    const digest = hex(sha256(envelope)), recorded = lines.map(line => JSON.parse(line));
    if (recorded.some(entry => entry.envelope.sha256 === digest)) throw new Error('This envelope is already in the ledger.');
    // A run is recorded once: a second entry for the same run id could replace its verdicts or anchors.
    const ids = new Set(recorded.flatMap(entry => entry.runs.map(run => run.id)));
    for (const run of check.runs) if (ids.has(run.id)) throw new Error(`Run ${run.id} is already in the ledger; nothing was appended.`);
    const lastSigned = points.length ? [payloadOf(points.at(-1)).signedAt] : [];
    const recordedAt = now.toISOString(), floor = [meta.createdAt, check.signedAt, ...(lines.length ? [JSON.parse(lines.at(-1)).recordedAt] : []), ...lastSigned];
    if (floor.some(time => Date.parse(recordedAt) < Date.parse(time))) throw new Error('The clock is earlier than the ledger, the envelope or the previous entry; nothing was appended.');
    for (const subject of anchors.keys()) if (!check.runs.some(run => run.subject === subject)) throw new Error(`Anchors name ${subject}, which is not a run in this envelope.`);
    const entry = buildEntry({ previousLine: lines.at(-1) ?? null, index: lines.length, recordedAt, envelope, check, files, anchors });
    try { checkEntry(entry); } catch (error) { if (error instanceof Rejected) throw new Error(`This run cannot be recorded (${error.message}); nothing was appended.`); throw error; }
    // Never record verdicts that --run-files could not read back from the same file in either verifier.
    for (const run of entry.runs) {
      const back = runFileVerdicts(files.get(run.subject), { payments: isPaymentsRun(run) });
      if (back === null || JSON.stringify(back) !== JSON.stringify(run.verdicts)) throw new Error(`${run.subject} is not a run file the verifiers can read back (not UTF-8, nested deeper than ${LIMITS.depth}, or not a run export or a payments run the pack's reader takes); nothing was appended.`);
    }
    const line = JSON.stringify(entry), lineSha256 = hex(sha256(line));
    const checkpoint = key ? signCheckpoint({ log: meta.log, createdAt: meta.createdAt, lines: [...lines, line], signedAt: recordedAt, privateKey: key }) : null;
    const intent = key ? signIntent({ log: meta.log, createdAt: meta.createdAt, lines: [...lines, line], signedAt: recordedAt, privateKey: key }) : null;
    await hooks.afterSign?.();
    await privateDirectory(join(dir, 'envelopes'));
    if (!(await unchanged(dir, verified))) throw new Error(CHANGED);
    await hooks.beforeWrite?.();
    if (key) await writeWhole(join(dir, PENDING), pendingRecord({ line, intent, envelope }));
    try {
      // Not in the ledger yet (duplicates were refused above), so a stray copy at this digest may be replaced.
      await writeEnvelopeCopy(dir, digest, envelope, { hooks, replace: true });
      await appendLine(join(dir, 'entries.jsonl'), line);
      if (checkpoint) await appendLine(join(dir, 'checkpoints.jsonl'), checkpoint);
    } catch (error) { throw new Error(key ? `This write stopped part way (${error.message}). ${STOPPED}` : `This unsigned write stopped part way (${error.message}).`); }
    if (!(await unchanged(dir, { entries: Buffer.concat([verified.entries, Buffer.from(`${line}\n`)]), checkpoints: checkpoint ? Buffer.concat([verified.checkpoints, Buffer.from(`${checkpoint}\n`)]) : verified.checkpoints }))) throw new Error(key ? CHANGED_DURING : 'The ledger changed during this unsigned write.');
    if (key) await removePending(dir);
    return { index: entry.index, envelope: digest, runs: entry.runs.length, line, lineSha256, signed: Boolean(key), checkpoint };
  });
}

// Recovery, never a new head over lines it cannot account for:
// - with pending.json, finishes that signed append: checks its intent is signed by the ledger key for
//   this log, appends its entry line if missing, and signs and appends the one checkpoint the intent
//   fixes (same size, root, head and time; deterministic, so the line the append would have written),
//   only when the result verifies with that checkpoint covering every entry;
// - without it, signs a new checkpoint only over a tail whose lines the caller names by SHA-256
//   (expectedTail: the lineSha256 values of its own unsigned appends, in order).
// Anything else (a forged line, a rewritten tail, a missing pending.json) is refused.
// hooks is a test seam only: afterVerify runs once the folder has been read and checked, afterSign once a
// new checkpoint is signed, afterWrite once a pending write's lines are appended.
export async function checkpointLedger(dir, { privateKey, evidenceKey, expectedTail, now = new Date() }, hooks = {}) {
  const key = signingKey(privateKey), ledgerKey = createPublicKey(key);
  await privateDirectory(dir);
  return withLock(dir, async () => {
    const verified = await readLedgerFiles(dir), pending = await readPending(dir);
    const lines = splitLines(verified.entries), points = splitLines(verified.checkpoints);
    const evidence = evidenceKey ?? ledgerKey;
    if (pending?.unreadable) throw new Error(pendingAdvice('pending.json is not a whole pending record in this writer\'s format, so it cannot be finished.', verified, ledgerKey, evidence));
    if (pending) {
      // The intent fixes the head; the checkpoint over it is re-signed here and must match it exactly.
      let meta; try { meta = JSON.parse(verified.metadata.toString('utf8')); } catch { meta = {}; }
      const intent = readIntent(pending.intent, ledgerKey);
      if (!intent || intent.log !== meta.log || intent.ledgerCreatedAt !== meta.createdAt) throw new Error(pendingAdvice('pending.json holds no intent signed by this ledger key for this log.', verified, ledgerKey, evidence));
      const treeSize = intent.treeSize;
      const addLine = lines.length === treeSize - 1;
      if (!addLine && !(lines.length === treeSize && lines.at(-1) === pending.line)) throw new Error(pendingAdvice(`entries.jsonl does not match the pending write: it has ${lines.length} entries, and the pending intent covers ${treeSize}, ending with its own line.`, verified, ledgerKey, evidence));
      const intended = addLine ? [...lines, pending.line] : lines;
      const checkpointLine = signCheckpoint({ log: meta.log, createdAt: meta.createdAt, lines: intended, treeSize, signedAt: intent.signedAt, privateKey: key });
      const signedHead = payloadOf(checkpointLine);
      if (signedHead.rootHash !== intent.rootHash || signedHead.headHash !== intent.headHash) throw new Error(pendingAdvice('The entries do not have the head the pending intent signed.', verified, ledgerKey, evidence));
      const addCheckpoint = points.at(-1) !== checkpointLine;
      const digest = hex(sha256(pending.envelope));
      const candidate = { ...verified, envelopes: new Map(verified.envelopes).set(digest, pending.envelope),
        entries: addLine ? Buffer.concat([verified.entries, Buffer.from(`${pending.line}\n`)]) : verified.entries,
        checkpoints: addCheckpoint ? Buffer.concat([verified.checkpoints, Buffer.from(`${checkpointLine}\n`)]) : verified.checkpoints };
      const result = verifyLedger({ ...candidate, ledgerKey, evidenceKey: evidence });
      if (!result.verified || result.unsignedTail || result.covered !== treeSize) throw new Error(pendingAdvice(`The pending write does not verify against this folder (${result.reason ?? `${result.unsignedTail} entries outside it`}).`, verified, ledgerKey, evidence));
      await hooks.afterVerify?.();
      if (!(await unchanged(dir, verified))) throw new Error(CHANGED);
      // A copy at this digest with other bytes may be replaced unless an entry an earlier checkpoint covers names it.
      const earlier = addCheckpoint ? points : points.slice(0, -1), coveredBefore = earlier.length ? payloadOf(earlier.at(-1)).treeSize : 0;
      const referenced = lines.slice(0, coveredBefore).some(text => JSON.parse(text).envelope.sha256 === digest);
      await writeEnvelopeCopy(dir, digest, pending.envelope, { hooks, replace: !referenced });
      if (addLine) await appendLine(join(dir, 'entries.jsonl'), pending.line);
      if (addCheckpoint) await appendLine(join(dir, 'checkpoints.jsonl'), checkpointLine);
      await hooks.afterWrite?.();
      if (!(await unchanged(dir, candidate))) throw new Error(CHANGED_DURING);
      await removePending(dir);
      return { treeSize, signedAt: intent.signedAt, line: checkpointLine, finished: true };
    }
    let covered = 0;
    try {
      verifyEntries({ ...verified, evidenceKey: evidence });
      if (points.length) {
        const result = verifyLedger({ ...verified, ledgerKey, evidenceKey: evidence });
        if (!result.verified) throw new Error(`The existing ledger does not verify (${result.reason}: ${result.detail}); nothing was signed.`);
        covered = result.covered;
      }
    } catch (error) { if (error instanceof Rejected) throw new Error(`The entries do not verify (${error.reason}: ${error.message}); nothing was signed.`); throw error; }
    const tail = lines.slice(covered);
    if (!tail.length) throw new Error('Nothing new since the last checkpoint.');
    if (!Array.isArray(expectedTail) || expectedTail.length !== tail.length || tail.some((line, i) => hex(sha256(line)) !== expectedTail[i])) {
      throw new Error(`${tail.length} entries are not covered by a checkpoint in this folder, and nothing shows this writer wrote them: there is no pending.json, and they are not the lines named by expected digests. Nothing was signed. ${forkWarning(covered)} Otherwise remove those lines from entries.jsonl (no checkpoint in this folder covers them), or restore the folder from your last verified copy.`);
    }
    await hooks.afterVerify?.();
    const meta = JSON.parse(verified.metadata.toString('utf8'));
    const previous = points.length ? payloadOf(points.at(-1)) : null, signedAt = now.toISOString();
    if ([JSON.parse(lines.at(-1)).recordedAt, ...(previous ? [previous.signedAt] : [])].some(time => Date.parse(signedAt) < Date.parse(time))) throw new Error('The clock is earlier than the last entry or checkpoint; nothing was signed.');
    const line = signCheckpoint({ log: meta.log, createdAt: meta.createdAt, lines, signedAt, privateKey: key });
    await hooks.afterSign?.();
    if (!(await unchanged(dir, verified))) throw new Error(CHANGED);
    await appendLine(join(dir, 'checkpoints.jsonl'), line);
    return { treeSize: lines.length, signedAt, line, finished: false };
  });
}
const RESTORE = 'Restore the folder from your last verified copy.';

// ---- Witnessing (operator side) ----
// The request a witness needs to cosign the latest checkpoint: that checkpoint line, the size the
// witness last cosigned (it says so in a 409 answer) and a consistency proof from there.
export async function witnessRequest(dir, { oldSize = 0 } = {}) {
  const files = await readLedgerFiles(dir);
  const meta = JSON.parse(files.metadata.toString('utf8')), lines = splitLines(files.entries), points = splitLines(files.checkpoints);
  if (!points.length) throw new Error('The ledger has no checkpoint to witness yet.');
  const checkpoint = points.at(-1), treeSize = payloadOf(checkpoint).treeSize;
  if (!Number.isSafeInteger(oldSize) || oldSize < 0 || oldSize > treeSize) throw new Error(`oldSize must be between 0 and ${treeSize}.`);
  const proof = oldSize === 0 || oldSize === treeSize ? [] : consistencyProof({ log: meta.log, lines, from: oldSize, to: treeSize }).path;
  return { checkpoint, oldSize, proof };
}

// Stores a witness's cosignature (the record witness.mjs returns) in cosignatures.jsonl, after checking
// it names a tree this ledger has at that size. The witness signature itself is checked by the
// verifiers against the witness keys a reader trusts; this writer holds no witness key.
export async function addCosignature(dir, record) {
  await privateDirectory(dir);
  const keys = record && typeof record === 'object' ? Object.keys(record).sort().join(',') : '';
  if (keys !== 'cosignature,rootHash,treeSize' || !Number.isSafeInteger(record.treeSize) || record.treeSize < 1 || !/^[0-9a-f]{64}$/.test(record.rootHash)
    || typeof record.cosignature !== 'string' || !cosignerName(SIGNATURE_LINE.exec(record.cosignature)?.[1])) throw new Error('Not a cosignature record ({ treeSize, rootHash, cosignature }); nothing was stored.');
  return withLock(dir, async () => {
    const lines = splitLines((await readLedgerFiles(dir)).entries);
    if (record.treeSize > lines.length || hex(head(lines.slice(0, record.treeSize).map(leaf))) !== record.rootHash) throw new Error(`This ledger has no tree with that root at size ${record.treeSize}; nothing was stored.`);
    const path = join(dir, 'cosignatures.jsonl'), line = JSON.stringify({ treeSize: record.treeSize, rootHash: record.rootHash, cosignature: record.cosignature });
    const handle = await open(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
    try { await handle.writeFile(`${line}\n`); await handle.sync(); } finally { await handle.close(); }
    await syncDirectory(dir);
    return { stored: true, treeSize: record.treeSize };
  });
}
