// Scopehaven signed evidence, signer side (scopehaven-attest/1).
// Builds an in-toto Statement v1 naming exported evidence files (a run's JSON,
// HTML or SARIF export, a comparison, a sequence result) and signs it into a DSSE
// envelope with a local Ed25519 key. The statement and run identities are built
// here; verify.mjs then recomputes them independently, and nothing is returned
// unless that verification and its negative controls pass.
// It refuses a run export or a payments run whose results no longer match its own
// integrity hash (a payments run's sha256). That hash has no key, so this catches a
// careless edit, not someone who edits a result and recomputes the hash: a signature
// says who signed, never that the results are true.
// The statement's producer names the build that signed (src/producer.mjs). A run's own producer names the build that ran it, which may
// be another: the verifiers print both.
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, KeyObject } from 'node:crypto';
import { ATTEST_VERSION, CLOCK, LIMITS, MEANING, PAYLOAD_TYPE, PAYMENTS_RUN_FIELDS, PAYMENTS_RUN_SCHEMA, PREDICATE_TYPE, RUN_FIELDS, STATEMENT_TYPE, SUBJECT_NAME, verifyEnvelope } from './verify.mjs';
import { PRODUCER_RELEASE } from '../../src/producer.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fingerprint = publicKey => hash(publicKey.export({ type: 'spki', format: 'der' }));
const encode = (type, body) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${body.length} `), body]);

export function generateSigningKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicPem: publicKey.export({ type: 'spki', format: 'pem' }), keyid: fingerprint(publicKey) };
}

function signingKey(input) {
  let key = input;
  if (!(key instanceof KeyObject)) try { key = createPrivateKey(input); } catch { key = null; }
  if (key?.type !== 'private' || key.asymmetricKeyType !== 'ed25519') throw new Error('Signing needs an Ed25519 private key.');
  return key;
}

// The store's run core (src/store.mjs) hashed with the canonical form of src/domain.mjs.
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
// A run export's core is all but `integrity` and `notes`. A payments run's sha256 covers all but itself and a comparison that
// `payments run --baseline` stores beside the run. The pack's other rules for a payments run (its fields, scope, row statuses
// and counts) are checked by the verifier, so signFiles refuses a run they refuse.
function savedRun(content) {
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(content)); } catch { return null; }
  const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
  if (!isObject(value)) return null;
  if (value.schemaVersion === 1 && typeof value.id === 'string' && typeof value.suiteHash === 'string'
    && isObject(value.integrity) && value.integrity.algorithm === 'SHA-256' && typeof value.integrity.sha256 === 'string') {
    const { integrity, notes, ...core } = value;
    return { fields: RUN_FIELDS, core, stated: integrity.sha256, edited: 'its results no longer match its integrity hash, so it was edited after export' };
  }
  if (value.schema !== PAYMENTS_RUN_SCHEMA) return null;
  const { comparison, sha256, ...core } = value;
  return { fields: PAYMENTS_RUN_FIELDS, core, stated: sha256, edited: 'its results no longer match its sha256, so it was edited after it was produced' };
}

// files: [{ name, content: Buffer }]; names are the published file names.
export function buildStatement(files, { version, release = PRODUCER_RELEASE, now = new Date() }) {
  if (!Array.isArray(files) || !files.length || files.length > LIMITS.subjects) throw new Error(`Sign between 1 and ${LIMITS.subjects} files.`);
  if (typeof version !== 'string' || !/^\d+\.\d+\.\d+$/.test(version)) throw new Error('A producer version (x.y.z) is required.');
  const subject = [], runs = [], seen = new Set();
  for (const { name, content } of files) {
    if (typeof name !== 'string' || !SUBJECT_NAME.test(name) || seen.has(name)) throw new Error(`Each file needs a unique plain name (letters, digits, dot, dash, underscore; up to 128): ${name}`);
    if (!Buffer.isBuffer(content) || content.length > LIMITS.subjectBytes) throw new Error(`${name} must be at most ${LIMITS.subjectBytes} bytes.`);
    seen.add(name);
    subject.push({ name, digest: { sha256: hash(content) } });
    const run = savedRun(content);
    if (!run) continue;
    const { fields, core, stated, edited } = run, coreSha256 = hash(canonical(core));
    if (coreSha256 !== stated) throw new Error(`Refusing to sign ${name}: ${edited}.`);
    const identity = { subject: name };
    for (const field of fields) if (Object.hasOwn(core, field) && (core[field] === null || ['string', 'number', 'boolean'].includes(typeof core[field]))) identity[field] = core[field];
    runs.push({ ...identity, coreSha256 });
  }
  return { _type: STATEMENT_TYPE, subject, predicateType: PREDICATE_TYPE,
    predicate: { meaning: MEANING, clock: CLOCK, producer: { name: 'scopehaven', version, attest: ATTEST_VERSION, release }, signedAt: now.toISOString(), runs } };
}

// Signs a statement as given, with no checks. signFiles is the supported path;
// tests use this to show the verifier rejects well-signed but wrong statements.
export function signStatement(statement, privateKey) {
  const key = signingKey(privateKey), payload = Buffer.from(JSON.stringify(statement));
  if (payload.length > LIMITS.payloadBytes) throw new Error('The statement exceeds its size limit.');
  const sig = sign(null, encode(PAYLOAD_TYPE, payload), key);
  return `${JSON.stringify({ payloadType: PAYLOAD_TYPE, payload: payload.toString('base64'), signatures: [{ keyid: fingerprint(createPublicKey(key)), sig: sig.toString('base64') }] }, null, 2)}\n`;
}

// `verify` is replaceable only so tests can prove a failed check stops signing.
export function signFiles(files, { privateKey, version, release, now }, { verify = verifyEnvelope } = {}) {
  const key = signingKey(privateKey);
  const envelope = signStatement(buildStatement(files, { version, release, now }), key);
  const check = verify({ envelope, publicKey: createPublicKey(key), files: new Map(files.map(f => [f.name, f.content])) });
  if (!check.verified) throw new Error(`Signing self-check failed (${check.verdict}: ${check.detail}); nothing was written.`);
  return { envelope, check };
}
