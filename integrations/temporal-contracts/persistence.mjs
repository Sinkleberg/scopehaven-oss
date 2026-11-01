import { generateKeyPairSync, createPublicKey, createHash, sign, verify, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { open, mkdir, lstat, realpath, link, unlink } from 'node:fs/promises';
import { dirname, basename, join, resolve, relative, sep, isAbsolute } from 'node:path';
import { isFinalizedRun } from './evaluator.mjs';
import { refundSuite, deriveExpectedAuthorities } from './contract.mjs';
import { digest } from '../../src/domain.mjs';

const ENVELOPE_SCHEMA = 'scopehaven-refund-signed-run/1';
const ADJUDICATION_SCHEMA = 'scopehaven-refund-adjudication/1';
const PRODUCER = 'scopehaven-trusted-refund-evaluator/1';
const MAX_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const signedEnvelopes = new WeakSet();
const verifiedRuns = new WeakSet();
const statuses = ['pass', 'fail', 'inconclusive', 'error'];
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const id = value => typeof value === 'string' && /^[A-Za-z0-9_.:/-]{1,160}$/.test(value);
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const strings = value => Array.isArray(value) && value.length <= 1000 && value.every(id) && new Set(value).size === value.length;
const sameSet = (a, b) => strings(a) && strings(b) && a.length === b.length && a.every(value => b.includes(value));
const uid = process.getuid?.();

export class TemporalPersistenceError extends Error {
  constructor(code) { super(code); this.name = 'TemporalPersistenceError'; this.code = code; }
}
export const isVerifiedRun = value => object(value) && verifiedRuns.has(value) && Object.isFrozen(value);
const requireShape = (condition, code = 'invalid-refund-finalized-run') => { if (!condition) throw new TemporalPersistenceError(code); };

function trustedPublicKey(publicKey) {
  requireShape(typeof publicKey === 'string' && publicKey.length <= 4096 && publicKey.startsWith('-----BEGIN PUBLIC KEY-----'), 'missing-refund-trusted-public-key');
  let key;
  try { key = createPublicKey(publicKey); } catch { throw new TemporalPersistenceError('invalid-refund-trusted-public-key'); }
  requireShape(key.asymmetricKeyType === 'ed25519', 'invalid-refund-trusted-public-key');
  return key;
}

const keyFingerprint = key => createHash('sha256').update(key.export({ format: 'der', type: 'spki' })).digest('hex');
/** SHA256 of canonical Ed25519 SPKI DER, independent of PEM whitespace. */
export const publicKeyFingerprint = publicKey => keyFingerprint(trustedPublicKey(publicKey));

function requirePinnedKey(key, expectedPublicKeyFingerprint) {
  requireShape(expectedPublicKeyFingerprint !== undefined, 'missing-refund-trusted-key-fingerprint');
  requireShape(hash(expectedPublicKeyFingerprint), 'invalid-refund-trusted-key-fingerprint');
  requireShape(keyFingerprint(key) === expectedPublicKeyFingerprint, 'refund-trust-key-fingerprint-mismatch');
}

// JSON-only deterministic signing, with bounded nesting/work even for an
// untrusted deserialized envelope. No toJSON hook or object coercion is run.
function canonical(value) {
  let nodes = 0;
  function visit(item, depth) {
    requireShape(++nodes <= 100000 && depth <= 40, 'refund-result-too-large');
    if (item === null || typeof item === 'boolean' || typeof item === 'string') return JSON.stringify(item);
    if (typeof item === 'number') { requireShape(Number.isFinite(item), 'invalid-refund-json'); return JSON.stringify(item); }
    if (Array.isArray(item)) return `[${item.map(entry => visit(entry, depth + 1)).join(',')}]`;
    requireShape(object(item) && [Object.prototype, null].includes(Object.getPrototypeOf(item)), 'invalid-refund-json');
    return `{${Object.keys(item).sort().map(key => {
      const descriptor = Object.getOwnPropertyDescriptor(item, key);
      requireShape(Object.hasOwn(descriptor, 'value'), 'invalid-refund-json');
      return `${JSON.stringify(key)}:${visit(descriptor.value, depth + 1)}`;
    }).join(',')}}`;
  }
  const result = visit(value, 0);
  requireShape(Buffer.byteLength(result) <= MAX_BYTES, 'refund-result-too-large');
  return result;
}

function freeze(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); if (!Object.isFrozen(value)) Object.freeze(value); }
  return value;
}

function validateExpected(expectedSuite, expectedRunId) {
  requireShape(object(expectedSuite) && id(expectedSuite.id) && id(expectedSuite.version) && hash(expectedSuite.hash) &&
    hash(expectedSuite.evaluatorHash) && id(expectedSuite.targetId) && hash(expectedSuite.buildHash) && id(expectedRunId), 'missing-refund-trusted-expectations');
  requireShape(Array.isArray(expectedSuite.checks) && expectedSuite.checks.length > 0 && expectedSuite.checks.length <= 1000 &&
    expectedSuite.checks.every(check => object(check) && id(check.id) && id(check.kind)) &&
    new Set(expectedSuite.checks.map(check => check.id)).size === expectedSuite.checks.length, 'invalid-refund-expected-checks');
  requireShape(object(expectedSuite.horizon) && id(expectedSuite.horizon.id) && Number.isSafeInteger(expectedSuite.horizon.deadlineMs) &&
    expectedSuite.horizon.deadlineMs > 0, 'invalid-refund-expected-horizon');
  requireShape(Array.isArray(expectedSuite.authorityTemplate) && expectedSuite.authorityTemplate.length > 0 && expectedSuite.authorityTemplate.length <= 1000 &&
    expectedSuite.authorityTemplate.every(authority => object(authority) &&
      id(authority.instructionId) && ['revoked', 'control'].includes(authority.principalRole) && ['revoked', 'control'].includes(authority.tenantRole) &&
      authority.chargeRole === 'workflow' && authority.operation === 'refund' &&
      Number.isSafeInteger(authority.amount) && authority.amount > 0 && typeof authority.currency === 'string' && /^[a-z]{3}$/.test(authority.currency) &&
      hash(authority.destinationDigest) && !Object.hasOwn(authority, 'authorityId')) &&
    new Set(expectedSuite.authorityTemplate.map(authority => authority.instructionId)).size === expectedSuite.authorityTemplate.length,
  'invalid-refund-expected-authorities');
}

function validateRun(run, expectedSuite, expectedRunId) {
  validateExpected(expectedSuite, expectedRunId);
  requireShape(object(run) && run.schemaVersion === 1 && run.id === expectedRunId && run.targetId === expectedSuite.targetId &&
    run.suiteId === expectedSuite.id && run.suiteVersion === expectedSuite.version && run.suiteHash === expectedSuite.hash &&
    run.evaluatorHash === expectedSuite.evaluatorHash && run.targetBuildHash === expectedSuite.buildHash, 'refund-run-identity-mismatch');
  const adjudication = run.refundAdjudication;
  requireShape(object(adjudication) && adjudication.schema === ADJUDICATION_SCHEMA && adjudication.finalized === true &&
    adjudication.producer === PRODUCER, 'refund-run-not-finalized');
  requireShape(adjudication.contractHash === expectedSuite.hash && object(adjudication.identity) &&
    adjudication.identity.runId === expectedRunId && adjudication.identity.targetId === expectedSuite.targetId &&
    adjudication.identity.buildHash === expectedSuite.buildHash && adjudication.identity.evaluatorHash === expectedSuite.evaluatorHash,
  'refund-adjudication-identity-mismatch');
  const horizon = adjudication.horizon;
  requireShape(object(horizon) && horizon.id === expectedSuite.horizon.id && horizon.deadlineMs === expectedSuite.horizon.deadlineMs &&
    typeof horizon.closed === 'boolean' && Number.isSafeInteger(horizon.watermark) && horizon.watermark >= 0 &&
    Number.isSafeInteger(horizon.pending) && horizon.pending >= 0, 'refund-horizon-mismatch');
  const expectedIds = expectedSuite.checks.map(check => check.id);
  requireShape(sameSet(adjudication.requiredCheckIds, expectedIds) && Array.isArray(adjudication.results) &&
    Array.isArray(run.results) && adjudication.results.length === expectedIds.length && run.results.length === expectedIds.length &&
    run.checksTotal === expectedIds.length && sameSet(adjudication.results.map(check => check?.id), expectedIds) &&
    sameSet(run.results.map(check => check?.id), expectedIds), 'refund-required-checks-mismatch');
  const counts = Object.fromEntries(statuses.map(status => [status, 0]));
  for (const expected of expectedSuite.checks) {
    const result = adjudication.results.find(check => check.id === expected.id);
    const standard = run.results.find(check => check.id === expected.id);
    requireShape(object(result) && result.kind === expected.kind && statuses.includes(result.status) &&
      ['reasons', 'instructionIds', 'attemptIds', 'effectIds'].every(key => strings(result[key])), 'invalid-refund-check-result');
    if (expected.instructionIds !== undefined) requireShape(sameSet(result.instructionIds, expected.instructionIds), 'refund-check-instructions-mismatch');
    requireShape(object(standard) && standard.kind === result.kind && standard.status === result.status &&
      ['reasons', 'instructionIds', 'attemptIds', 'effectIds'].every(key => sameSet(standard[key], result[key])), 'refund-standard-results-mismatch');
    counts[result.status]++;
  }
  requireShape(object(run.counts) && statuses.every(status => run.counts[status] === counts[status]) &&
    Object.keys(run.counts).every(status => statuses.includes(status) || (status === 'not_applicable' && run.counts[status] === 0)), 'refund-result-counts-mismatch');
  requireShape(object(adjudication.evidenceSummary), 'invalid-refund-evidence-summary');
  const authorities = deriveExpectedAuthorities(expectedSuite.authorityTemplate, expectedRunId);
  requireShape(Array.isArray(adjudication.evidenceSummary.instructions) && digest(adjudication.evidenceSummary.instructions) === digest(authorities),
    'refund-authority-content-mismatch');
  const expectedContractHash = digest({ schema: 'scopehaven-refund-contract/1', definitionHash: expectedSuite.hash, runId: expectedRunId,
    targetId: expectedSuite.targetId, buildHash: expectedSuite.buildHash, horizon: expectedSuite.horizon, authorities });
  requireShape(adjudication.runContractHash === expectedContractHash, 'refund-run-contract-hash-mismatch');
  if (counts.pass === expectedIds.length) {
    requireShape(horizon.closed && horizon.pending === 0 && (!Object.hasOwn(horizon, 'sealed') || horizon.sealed === true), 'refund-passing-horizon-incomplete');
    const summary = adjudication.evidenceSummary, timing = summary.timing;
    requireShape(summary.coverage === 'complete' && Array.isArray(summary.problems) && summary.problems.length === 0, 'refund-passing-evidence-incomplete');
    requireShape(object(timing) && typeof timing.clockId === 'string' && timing.clockId.trim().length > 0 && timing.clockId.length <= 200 &&
      Number.isFinite(timing.startedAtMs) && timing.startedAtMs >= 0 && Number.isFinite(timing.closedAtMs) &&
      timing.closedAtMs >= timing.startedAtMs, 'refund-passing-timing-incomplete');
    // A source may close after the completion deadline. The evaluator checks
    // each required completion's time; late collection alone is not a failure.
  }
  requireShape(typeof run.createdAt === 'string' && typeof adjudication.createdAt === 'string' &&
    run.createdAt === adjudication.createdAt && Number.isFinite(Date.parse(run.createdAt)), 'invalid-refund-created-at');
  return run;
}

/** The signing key stays in this trusted evaluator closure, outside the app. */
export function createResultSigner() {
  const keys = generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  return Object.freeze({ publicKey, publicKeyFingerprint: keyFingerprint(keys.publicKey), signRun(run) {
    requireShape(isFinalizedRun(run), 'refund-run-not-live-finalized');
    const adjudication = run.refundAdjudication;
    requireShape(object(adjudication), 'refund-run-not-finalized');
    const expectedSuite = refundSuite({ targetId: run.targetId, buildHash: run.targetBuildHash, evaluatorHash: run.evaluatorHash });
    validateRun(run, expectedSuite, run.id);
    const normalizedRun = JSON.parse(canonical(run));
    const payload = canonical({ schema: ENVELOPE_SCHEMA, run: normalizedRun });
    const envelope = freeze({ schema: ENVELOPE_SCHEMA, run: normalizedRun, signature: sign(null, Buffer.from(payload), keys.privateKey).toString('base64url') });
    signedEnvelopes.add(envelope);
    return envelope;
  } });
}

/** The expected fingerprint is operator-held input, never taken from an artifact. */
export function verifySignedRun(envelope, { publicKey, expectedPublicKeyFingerprint, expectedSuite, expectedRunId, now = Date.now(), maxAgeMs = DEFAULT_MAX_AGE_MS } = {}) {
  validateExpected(expectedSuite, expectedRunId);
  const key = trustedPublicKey(publicKey);
  requirePinnedKey(key, expectedPublicKeyFingerprint);
  requireShape(object(envelope) && Object.keys(envelope).sort().join(',') === 'run,schema,signature' && envelope.schema === ENVELOPE_SCHEMA &&
    typeof envelope.signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(envelope.signature), 'invalid-refund-signed-envelope');
  const signature = Buffer.from(envelope.signature, 'base64url');
  const payload = canonical({ schema: envelope.schema, run: envelope.run });
  requireShape(signature.length === 64 && signature.toString('base64url') === envelope.signature &&
    verify(null, Buffer.from(payload), key, signature), 'refund-signature-invalid');
  // Brand a snapshot of the authenticated bytes, never mutable caller aliases.
  const normalizedRun = JSON.parse(payload).run;
  validateRun(normalizedRun, expectedSuite, expectedRunId);
  const current = now instanceof Date ? now.getTime() : now;
  requireShape(Number.isSafeInteger(current) && Number.isSafeInteger(maxAgeMs) && maxAgeMs > 0, 'invalid-refund-freshness-policy');
  const created = Date.parse(normalizedRun.createdAt);
  requireShape(created <= current && current - created <= maxAgeMs, 'refund-result-stale');
  const run = freeze(normalizedRun);
  verifiedRuns.add(run);
  return run;
}

const inside = (directory, file) => {
  const fromDirectory = relative(directory, file);
  return fromDirectory !== '..' && !fromDirectory.startsWith(`..${sep}`) && !isAbsolute(fromDirectory);
};
const resultTree = directory => basename(directory) === 'signed-results' ? dirname(directory) : directory;

/** Load only an external key; a pin supplied separately by the operator is required. */
export async function readTrustedPublicKey(file, { resultFile, expectedPublicKeyFingerprint } = {}) {
  requireShape(typeof file === 'string' && isAbsolute(file) && file.length <= 4096 &&
    typeof resultFile === 'string' && isAbsolute(resultFile) && resultFile.length <= 4096, 'invalid-refund-trust-key-path');
  let handle;
  try {
    const requested = resolve(file), resultDirectory = dirname(resolve(resultFile));
    const resolvedResultDirectory = await realpath(resultDirectory);
    const trees = [resultTree(resultDirectory), resultTree(resolvedResultDirectory)];
    requireShape(trees.every(tree => !inside(tree, requested)), 'refund-trust-key-must-be-external');
    const resolvedKey = await realpath(requested);
    requireShape(trees.every(tree => !inside(tree, resolvedKey)), 'refund-trust-key-must-be-external');
    handle = await open(requested, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const metadata = await handle.stat(), pathMetadata = await lstat(resolvedKey);
    requireShape(metadata.isFile() && (uid === undefined || metadata.uid === uid) && (metadata.mode & 0o022) === 0 &&
      metadata.size > 0 && metadata.size <= 4096 && metadata.dev === pathMetadata.dev && metadata.ino === pathMetadata.ino,
    'refund-trust-key-invalid');
    const buffer = Buffer.alloc(4097); let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await handle.read(buffer, size, buffer.length - size, size);
      if (!bytesRead) break;
      size += bytesRead;
    }
    requireShape(size <= 4096, 'refund-trust-key-invalid');
    const publicKey = buffer.subarray(0, size).toString('utf8');
    requirePinnedKey(trustedPublicKey(publicKey), expectedPublicKeyFingerprint);
    // Recheck directory resolution after the read so changed path aliases do not
    // move a result-tree key outside the lexical check during loading.
    requireShape(await realpath(requested) === resolvedKey && await realpath(resultDirectory) === resolvedResultDirectory,
      'refund-trust-key-path-changed');
    return publicKey;
  } catch (error) {
    if (error instanceof TemporalPersistenceError) throw error;
    throw new TemporalPersistenceError('refund-trust-key-read-failed');
  } finally { await handle?.close(); }
}

async function secureParent(file, create) {
  requireShape(typeof file === 'string' && file.length > 0 && file.length <= 4096, 'invalid-refund-result-path');
  const destination = resolve(file), directory = dirname(destination);
  if (create) await mkdir(directory, { recursive: true, mode: 0o700 });
  const metadata = await lstat(directory);
  requireShape(metadata.isDirectory() && !metadata.isSymbolicLink() && (uid === undefined || metadata.uid === uid) &&
    (metadata.mode & 0o7777) === 0o700, 'unsafe-refund-result-directory');
  return join(await realpath(directory), basename(destination));
}

/** Only this process's signer-created envelope may be published; no overwrite. */
export async function writeFinalizedRun(file, envelope) {
  requireShape(object(envelope) && signedEnvelopes.has(envelope), 'refund-envelope-not-live-signed');
  const content = `${canonical(envelope)}\n`;
  let handle, temporary;
  try {
    const destination = await secureParent(file, true);
    temporary = join(dirname(destination), `.${randomUUID()}.tmp`);
    handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    await handle.writeFile(content); await handle.sync(); await handle.close(); handle = null;
    await secureParent(file, false);
    await link(temporary, destination);
    return destination;
  } catch (error) {
    if (error instanceof TemporalPersistenceError) throw error;
    throw new TemporalPersistenceError(error.code === 'EEXIST' ? 'refund-result-already-exists' : 'refund-result-write-failed');
  } finally { await handle?.close(); if (temporary) await unlink(temporary).catch(() => {}); }
}

/** Bounded private regular-file reload followed by external-key verification. */
export async function readFinalizedRun(file, options) {
  let handle;
  try {
    const destination = await secureParent(file, false);
    handle = await open(destination, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const metadata = await handle.stat();
    requireShape(metadata.isFile() && (uid === undefined || metadata.uid === uid) && (metadata.mode & 0o7777 & ~0o600) === 0 &&
      metadata.size > 0 && metadata.size <= MAX_BYTES, 'unsafe-refund-result-file');
    const chunks = [], buffer = Buffer.alloc(65536); let size = 0;
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, size);
      if (!bytesRead) break;
      size += bytesRead; requireShape(size <= MAX_BYTES, 'refund-result-too-large');
      chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    }
    let envelope;
    try { envelope = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new TemporalPersistenceError('invalid-refund-result-json'); }
    return verifySignedRun(envelope, options);
  } catch (error) {
    if (error instanceof TemporalPersistenceError) throw error;
    throw new TemporalPersistenceError('refund-result-read-failed');
  } finally { await handle?.close(); }
}
