// Scopehaven signed evidence, verifier side (scopehaven-attest/1).
// A DSSE envelope (github.com/secure-systems-lab/dsse, protocol v1) carries an
// in-toto Statement v1 whose subjects are exported evidence files. This module
// checks one envelope against one trusted Ed25519 public key and the files
// themselves. It imports only Node built-ins, nothing from sign.mjs or src/, and
// verify_envelope.py repeats every check in Python with its own Ed25519.
//
// A signature shows that the key holder produced these exact files. It does not
// show that the checks, the application or the results inside them are correct.
// The run identities in the statement (native run exports and payments-pack runs)
// are recomputed from the run files, never trusted. After an envelope passes,
// negative controls (tampered payload, signature, payload type, key and file, and
// for each kind of run present an edited run file and a misstated run identity) go
// through the same code and must be rejected; if any is accepted the verdict is
// self-check-failed.
import { createHash, createPublicKey, generateKeyPairSync, verify, KeyObject } from 'node:crypto';

export const ATTEST_VERSION = 'scopehaven-attest/1';
export const PAYLOAD_TYPE = 'application/vnd.in-toto+json';
export const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
export const PREDICATE_TYPE = 'https://scopehaven.dev/attestation/evidence-export/v1';
export const MEANING = 'The holder of this signing key produced these exact files. The signature does not show that the checks, the application or the results inside them are correct.';
export const CLOCK = "Signer's local clock; not a trusted timestamp.";
// Identity fields copied from a run export when present with a scalar value, in this order.
export const RUN_FIELDS = Object.freeze(['id', 'schemaVersion', 'createdAt', 'targetId', 'build', 'suiteId', 'suiteHash', 'policyHash', 'fixtureVersion', 'fixtureHash',
  'applicationId', 'adapterVersion', 'evaluatorHash', 'targetBuildHash', 'targetConfigHash', 'runtimeMode', 'evidenceOrigin', 'assertionSchemaVersion', 'contextId', 'profileHash', 'scopeLabel']);
// A payments-pack run (integrations/payments-pack/pack.mjs), read by the rules of the pack's own reader
// (integrations/payments-pack/output.mjs savedPaymentsRun), written out here. Its identity fields are copied like a run
// export's; its name (free text), scope and nested records (provider, authorization, counts, rows, settlement) are covered
// by coreSha256 only.
export const PAYMENTS_RUN_SCHEMA = 'scopehaven-payments-run/1';
export const PAYMENTS_SCOPE = 'Owned or operator-run app on loopback, judged from a Stripe-shaped test-mode payments double the app cannot edit. No real provider, no live money, no production assurance.';
export const PAYMENTS_RUN_FIELDS = Object.freeze(['id', 'schema', 'startedAt', 'finishedAt', 'targetId', 'applicationId', 'build', 'packSha256']);
// Every field a payments run has, and no other (a comparison stored beside it aside).
const PAYMENTS_KEYS = ['schema', 'id', 'targetId', 'applicationId', 'name', 'build', 'packSha256', 'startedAt', 'finishedAt', 'scope', 'provider', 'authorization', 'counts', 'rows', 'settlement', 'sha256'];
const PAYMENTS_RUN_ID = /^pay-[0-9]{14}-[0-9a-f]{8}$/, CHECK_ID = /^[A-Za-z0-9_-]{1,64}$/, STATUSES = ['pass', 'fail', 'inconclusive'], ROLES = ['boundary', 'control'];
export const LIMITS = Object.freeze({ subjects: 64, subjectBytes: 8 * 1024 * 1024, envelopeBytes: 2 * 1024 * 1024, payloadBytes: 1024 * 1024 });
export const SUBJECT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
// The build a statement or a run names (src/producer.mjs). Older statements and runs have none, and read as not recorded.
const RELEASE_KEYS = ['source', 'version', 'commit', 'manifestSha256'], COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/, HEX64 = /^[0-9a-f]{64}$/;
const validRelease = release => exactKeys(release, RELEASE_KEYS) && typeof release.version === 'string' && (release.version === 'unknown' || /^\d+\.\d+\.\d+$/.test(release.version))
  && typeof release.commit === 'string' && (release.source === 'release-manifest' ? COMMIT.test(release.commit) && typeof release.manifestSha256 === 'string' && HEX64.test(release.manifestSha256)
    : release.source === 'git' ? COMMIT.test(release.commit) && release.manifestSha256 === null
      : release.source === 'unknown' && release.commit === 'unknown' && release.manifestSha256 === null);

export class Rejected extends Error {
  constructor(reason, detail) { super(detail ? `${reason}: ${detail}` : reason); this.name = 'Rejected'; this.reason = reason; }
}
const reject = (reason, detail) => { throw new Rejected(reason, detail); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exactKeys = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const scalar = value => value === null || ['string', 'number', 'boolean'].includes(typeof value);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
// Fatal on invalid UTF-8 and keeps a BOM, so JSON.parse rejects it the way Python does.
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
// Years 2000-2999 only: Python and JavaScript disagree on dates before year 1000.
const ISO = /^2\d{3}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const isoTime = value => typeof value === 'string' && ISO.test(value) && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value;

// DSSE pre-authentication encoding: the signature covers the payload type too.
export const pae = (type, body) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${body.length} `), body]);
export const keyIdOf = publicKey => sha256(publicKey.export({ type: 'spki', format: 'der' }));

// The trusted key is a public key only: an auditor never needs the private key.
export function trustedKey(input) {
  let key = input;
  if (typeof input === 'string' || Buffer.isBuffer(input)) {
    // Exactly one PEM block with nothing around it but whitespace, as verify_envelope.py reads it.
    const pem = String(input).replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');
    if (!/^-----BEGIN PUBLIC KEY-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END PUBLIC KEY-----$/.test(pem)) throw new Error('Pass the signer\'s public key (PEM "BEGIN PUBLIC KEY"); verification never needs the private key.');
    key = createPublicKey(pem);
  }
  if (!(key instanceof KeyObject) || key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') throw new Error('The trusted key must be an Ed25519 public key.');
  return key;
}

export function signatureValid(key, type, payload, sig) {
  try { return verify(null, pae(type, payload), key, sig) === true; } catch { return false; }
}

function strictBase64(text, what) {
  if (typeof text !== 'string' || text.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) reject('base64', what);
  const bytes = Buffer.from(text, 'base64');
  if (bytes.toString('base64') !== text) reject('base64', what);
  return bytes;
}

// Same canonical form as the store's run digest (src/domain.mjs), written out here.
function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function coreDigest(name, core) {
  try { return sha256(stable(core)); }
  catch (error) { if (error instanceof RangeError) reject('subject-unparseable', `${name} is nested too deeply to recompute`); throw error; }
}
// The pack's rule for a row (savedPaymentsRun readableRow): its status is the worst of its assertions', a pass needs the
// check request answered, and a boundary with a settlement finding is never a pass (a control keeps its verdict and a tag).
const worst = statuses => statuses.includes('fail') ? 'fail' : statuses.includes('inconclusive') ? 'inconclusive' : 'pass';
function readableRow(r) {
  if (!plain(r) || typeof r.id !== 'string' || !CHECK_ID.test(r.id) || !STATUSES.includes(r.status) || !ROLES.includes(r.severity) || typeof r.rule !== 'string'
    || !Array.isArray(r.standards) || !plain(r.request) || !Array.isArray(r.assertions) || !r.assertions.length || !r.assertions.every(a => plain(a) && STATUSES.includes(a.status))) return false;
  if (r.status !== worst(r.assertions.map(a => a.status))) return false;
  if (!Array.isArray(r.settlement) || !r.settlement.every(f => plain(f) && f.effect === (r.severity === 'control' ? 'tag' : 'withheld'))) return false;
  return r.status !== 'pass' || (plain(r.reach) && r.reach.reached === true && (r.severity === 'control' || !r.settlement.length));
}
// A payments run's body, checked in savedPaymentsRun's order: its run id, its sha256 over everything but itself (a comparison
// `payments run --baseline` stores beside the run is outside it, as in the pack), exactly a run's fields, the pack's scope, rows
// whose statuses follow from their assertions, reach and settlement, counts that are those statuses, a test-mode provider and
// its times. A run the pack's reader refuses gets no identity: the envelope is rejected, as the export refuses it. Times must be
// ISO strings as the pack writes them, where the pack's reader takes whatever Date.parse reads, which Python cannot match.
function paymentsRun(name, value) {
  const refused = detail => reject('payments-run-refused', `${name} ${detail}`);
  const { comparison: _, ...run } = value, { sha256: stated, ...core } = run;
  if (typeof run.id !== 'string' || !PAYMENTS_RUN_ID.test(run.id)) refused('has no payments run id');
  const coreSha256 = coreDigest(name, core);
  // Unkeyed, like a run export's integrity hash: this catches a careless edit, not a resealed one.
  if (typeof stated !== 'string' || coreSha256 !== stated) reject('run-integrity-mismatch', `${name} was edited after it was produced`);
  const keys = Object.hasOwn(run, 'producer') ? [...PAYMENTS_KEYS, 'producer'] : PAYMENTS_KEYS; // Runs saved before F9 have no producer.
  if (Object.keys(run).length !== keys.length || !keys.every(key => Object.hasOwn(run, key))) refused('does not have exactly the fields a payments run has');
  if (run.scope !== PAYMENTS_SCOPE) refused('does not state the payments pack\'s scope');
  const rows = run.rows;
  if (!Array.isArray(rows) || !rows.length || !rows.every(readableRow) || new Set(rows.map(r => r.id)).size !== rows.length) refused('has a row whose status is not what its assertions, reach and settlement give');
  if (!plain(run.counts) || Object.keys(run.counts).length !== STATUSES.length || STATUSES.some(s => run.counts[s] !== rows.filter(r => r.status === s).length)) refused('has counts that are not its rows\' statuses');
  if (!plain(run.provider) || run.provider.livemode !== false || typeof run.provider.kind !== 'string') refused('does not say its provider was in test mode');
  if (!isoTime(run.startedAt) || !isoTime(run.finishedAt)) refused('has no ISO start and finish times');
  return { core, coreSha256 };
}
// A saved run: a run export (the store's run core plus `integrity` and `notes`, src/store.mjs readRun), or else any JSON object
// that declares the payments run schema. Any other file is no run, covered by its digest only. Exported for integrations/ledger.
export function savedRun(name, content) {
  let value;
  try { value = JSON.parse(utf8.decode(content)); } catch { return null; }
  if (!plain(value)) return null;
  const native = value.schemaVersion === 1 && typeof value.id === 'string' && typeof value.suiteHash === 'string'
    && plain(value.integrity) && value.integrity.algorithm === 'SHA-256' && typeof value.integrity.sha256 === 'string';
  if (!native && value.schema !== PAYMENTS_RUN_SCHEMA) return null;
  // The negative controls re-serialize the whole run, its notes or stored comparison included, so that must work here.
  try { JSON.stringify(value); }
  catch (error) { if (error instanceof RangeError) reject('subject-unparseable', `${name} is nested too deeply to recompute`); throw error; }
  if (native) {
    const { integrity, notes, ...core } = value, coreSha256 = coreDigest(name, core);
    // The integrity hash has no key: this catches a careless edit, not a deliberate one.
    if (coreSha256 !== integrity.sha256) reject('run-integrity-mismatch', `${name} was edited after export`);
    return { payments: false, fields: RUN_FIELDS, core, coreSha256 };
  }
  return { payments: true, fields: PAYMENTS_RUN_FIELDS, ...paymentsRun(name, value) };
}
// Every run among the subjects, in subject order: { payments, identity }.
function recomputeRuns(subjects, files) {
  const runs = [];
  for (const { name } of subjects) {
    const run = savedRun(name, files.get(name));
    if (!run) continue;
    const identity = { subject: name };
    for (const field of run.fields) if (Object.hasOwn(run.core, field) && scalar(run.core[field])) identity[field] = run.core[field];
    runs.push({ payments: run.payments, identity: { ...identity, coreSha256: run.coreSha256 } });
  }
  return runs;
}
const sameRuns = (computed, stated) => JSON.stringify(computed) === JSON.stringify(stated);
// The statement must name every run export's identity, exactly and in subject order. A payments run's identity it may leave
// out, as envelopes signed before payments runs had identities do: that needs the key and claims less. Any identity it does
// name must be the recomputed one, and a payments run is checked whether or not its identity is named.
function matchRuns(computed, stated) {
  const claimed = new Set(stated.filter(plain).map(entry => entry.subject));
  const runs = computed.filter(run => !run.payments || claimed.has(run.identity.subject));
  if (!sameRuns(runs.map(run => run.identity), stated)) reject('run-identity-mismatch', 'the statement does not match the run files it names');
  return { runs: runs.map(run => run.identity), unclaimed: computed.filter(run => !runs.includes(run)).map(run => run.identity.subject) };
}

function parseStatement(payload) {
  let text, statement;
  try { text = utf8.decode(payload); statement = JSON.parse(text); } catch { reject('payload-json'); }
  if (JSON.stringify(statement) !== text) reject('payload-not-canonical');
  if (!exactKeys(statement, ['_type', 'subject', 'predicateType', 'predicate']) || statement._type !== STATEMENT_TYPE) reject('statement-shape');
  if (statement.predicateType !== PREDICATE_TYPE) reject('predicate-type');
  const { subject, predicate } = statement, names = new Set();
  if (!Array.isArray(subject) || !subject.length || subject.length > LIMITS.subjects) reject('subject-shape');
  for (const entry of subject) {
    if (!exactKeys(entry, ['name', 'digest']) || typeof entry.name !== 'string' || !SUBJECT_NAME.test(entry.name) || names.has(entry.name)) reject('subject-shape');
    if (!exactKeys(entry.digest, ['sha256']) || typeof entry.digest.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(entry.digest.sha256)) reject('subject-shape', entry.name);
    names.add(entry.name);
  }
  if (!exactKeys(predicate, ['meaning', 'clock', 'producer', 'signedAt', 'runs']) || predicate.meaning !== MEANING || predicate.clock !== CLOCK) reject('predicate-shape');
  const { producer, signedAt, runs } = predicate;
  if ((!exactKeys(producer, ['name', 'version', 'attest']) && !(exactKeys(producer, ['name', 'version', 'attest', 'release']) && validRelease(producer.release))) || producer.name !== 'scopehaven' || typeof producer.version !== 'string' || !/^\d+\.\d+\.\d+$/.test(producer.version) || producer.attest !== ATTEST_VERSION) reject('predicate-shape', 'producer');
  if (!isoTime(signedAt)) reject('predicate-shape', 'signedAt');
  if (!Array.isArray(runs) || runs.length > subject.length) reject('predicate-shape', 'runs');
  return statement;
}

function checkSubjects(subjects, files) {
  const results = [];
  for (const { name, digest } of subjects) {
    const content = files.get(name);
    if (!Buffer.isBuffer(content)) reject('subject-missing', name);
    if (sha256(content) !== digest.sha256) reject('subject-digest-mismatch', name);
    results.push({ name, sha256: digest.sha256, bytes: content.length });
  }
  const named = new Set(subjects.map(s => s.name));
  for (const name of files.keys()) if (!named.has(name)) reject('unsigned-file', `${name} is not covered by this signature`);
  return results;
}

// Envelope shape, trusted key and signature, then the statement: everything except the files.
function signedStatement(envelope, key, keyid, checkSignature) {
  const bytes = Buffer.isBuffer(envelope) ? envelope : Buffer.from(String(envelope));
  if (bytes.length > LIMITS.envelopeBytes) reject('envelope-size');
  let env;
  try { env = JSON.parse(utf8.decode(bytes)); } catch { reject('envelope-json'); }
  if (!exactKeys(env, ['payload', 'payloadType', 'signatures'])) reject('envelope-shape');
  if (env.payloadType !== PAYLOAD_TYPE) reject('payload-type');
  if (!Array.isArray(env.signatures) || env.signatures.length !== 1) reject('signature-count', 'exactly one signature is accepted');
  const [entry] = env.signatures;
  if (!exactKeys(entry, ['keyid', 'sig']) || typeof entry.keyid !== 'string') reject('signature-shape');
  const payload = strictBase64(env.payload, 'payload'), sig = strictBase64(entry.sig, 'sig');
  if (payload.length > LIMITS.payloadBytes) reject('payload-size');
  if (entry.keyid !== keyid) reject('keyid-mismatch', 'signed by a different key than the trusted one');
  if (sig.length !== 64 || !checkSignature(key, env.payloadType, payload, sig)) reject('signature-invalid');
  // Only a payload signed by the trusted key is parsed.
  return { type: env.payloadType, payload, sig, statement: parseStatement(payload) };
}

function examine(envelope, key, keyid, files, checkSignature) {
  const { type, payload, sig, statement } = signedStatement(envelope, key, keyid, checkSignature);
  const subjects = checkSubjects(statement.subject, files);
  const computed = recomputeRuns(statement.subject, files), { runs, unclaimed } = matchRuns(computed, statement.predicate.runs);
  return { type, payload, sig, statement, subjects, computed, runs, unclaimed };
}

// The signed statement alone, for a holder without the files (the evidence ledger checks
// old envelopes this way). Throws Rejected with the same reasons verifyEnvelope reports.
// It proves who signed which digests and run identities, not that any file still matches.
export function readSignedStatement(envelope, publicKey) {
  const key = trustedKey(publicKey), keyid = keyIdOf(key);
  return { keyid, statement: signedStatement(envelope, key, keyid, signatureValid).statement };
}

// Negative controls: each copies one input, changes one thing, and sends it through
// the same check the envelope just passed. Each must be rejected.
function negativeControls({ type, payload, sig, statement, computed, runs }, key, files, checkSignature) {
  const flip = bytes => { const copy = Buffer.from(bytes.length ? bytes : [0]); copy[copy.length >> 1] ^= 1; return copy; };
  const other = generateKeyPairSync('ed25519').publicKey, first = statement.subject[0].name;
  const passes = attempt => { try { attempt(); return true; } catch (error) { if (error instanceof Rejected) return false; throw error; } };
  const controls = [
    ['payload-tampered', () => checkSignature(key, type, flip(payload), sig)],
    ['signature-tampered', () => checkSignature(key, type, payload, flip(sig))],
    ['payload-type-changed', () => checkSignature(key, `${type}+x`, payload, sig)],
    ['wrong-key', () => checkSignature(other, type, payload, sig)],
    ['subject-tampered', () => passes(() => checkSubjects(statement.subject, new Map([...files, [first, flip(files.get(first))]])))],
  ];
  // For the first run export and the first payments run: its file with one edit only its digest covers must fail the
  // recomputed checks, and a statement naming its identity (named or not in this one) with one changed digest must not match.
  // A run export gets an added field. A payments run's name changes instead, since its field-set rule would refuse an added
  // field even with the digest check broken.
  for (const [label, target] of [['run', computed.find(run => !run.payments)], ['payments-run', computed.find(run => run.payments)]]) {
    if (!target) continue;
    const name = target.identity.subject, run = JSON.parse(utf8.decode(files.get(name))), { coreSha256 } = target.identity;
    if (target.payments) run.name = typeof run.name === 'string' ? `${run.name}.` : 'selfCheckEdit';
    else run.selfCheckEdit = true;
    // Serialized here, fewer frames deep than savedRun's check that this run serializes, so it cannot overflow the stack where
    // that check did not. Inside the control, the same check turns an overflow into a rejection.
    const editedFile = Buffer.from(JSON.stringify(run));
    controls.push([`${label}-file-edited`, () => passes(() => recomputeRuns([{ name }], new Map([[name, editedFile]])))]);
    const edited = computed.filter(entry => entry === target || runs.includes(entry.identity))
      .map(entry => entry === target ? { ...entry.identity, coreSha256: `${coreSha256.slice(0, -1)}${coreSha256.endsWith('0') ? '1' : '0'}` } : entry.identity);
    controls.push([`${label}-identity-edited`, () => passes(() => matchRuns(computed, edited))]);
  }
  return controls.map(([id, attempt]) => {
    let accepted;
    try { accepted = attempt() === true; } catch (error) { if (!(error instanceof Rejected)) throw error; accepted = false; }
    return { id, expected: 'rejected', observed: accepted ? 'accepted' : 'rejected' };
  });
}

// Two builds, printed separately because a pack can be made by another version than the run: `packing` is the signed statement's
// (null for a statement older than the field), and `running` each run's own, read from a file whose digest was just checked (null
// for a run older than the field, or one this verifier cannot read). Each is what that install said of itself, not proof of what ran.
function buildsOf(statement, computed, files) {
  const running = computed.map(({ identity: { subject } }) => {
    const release = JSON.parse(utf8.decode(files.get(subject))).producer?.release;
    return { subject, release: validRelease(release) ? release : null };
  });
  return { packing: statement.predicate.producer.release ?? null, running };
}

// files: Map (or object) of subject name -> Buffer. `checkSignature` is replaceable
// only so tests can prove a verifier that accepts everything is caught.
export function verifyEnvelope({ envelope, publicKey, files }, { checkSignature = signatureValid } = {}) {
  const key = trustedKey(publicKey), keyid = keyIdOf(key);
  const inputs = files instanceof Map ? files : new Map(Object.entries(files ?? {}));
  let checked;
  try { checked = examine(envelope, key, keyid, inputs, checkSignature); }
  catch (error) {
    if (!(error instanceof Rejected)) throw error;
    return { attest: ATTEST_VERSION, verified: false, verdict: 'rejected', reason: error.reason, detail: error.message, keyid, selfChecks: [] };
  }
  const selfChecks = negativeControls(checked, key, inputs, checkSignature), accepted = selfChecks.filter(c => c.observed !== 'rejected').map(c => c.id);
  const { predicate } = checked.statement;
  return { attest: ATTEST_VERSION, verified: !accepted.length, verdict: accepted.length ? 'self-check-failed' : 'verified',
    reason: accepted.length ? 'negative-control-accepted' : null, detail: accepted.length ? `This verifier accepted tampered input (${accepted.join(', ')}); do not rely on it.` : null,
    keyid, meaning: predicate.meaning, signedAt: predicate.signedAt, clock: predicate.clock, producer: predicate.producer, builds: buildsOf(checked.statement, checked.computed, inputs), subjects: checked.subjects, runs: checked.runs,
    unclaimedRuns: checked.unclaimed, note: unclaimedNote(checked.unclaimed), selfChecks };
}
// `runs` holds only the identities the signer named. A payments run it left unnamed was still checked like the others.
const unclaimedNote = names => names.length ? `The statement names no run identity for ${names.join(', ')}. The signature covers those files' bytes, and each is a well-formed payments run by the pack's own rules, but no run identity is signed for it (envelopes signed before payments runs had identities name none). None of this says whether the results are right.` : null;

// Names the envelope says it covers, before any trust: used only to choose which
// files to read from a directory. Invalid input yields no names.
export function subjectNames(envelope) {
  try {
    const env = JSON.parse(utf8.decode(Buffer.isBuffer(envelope) ? envelope : Buffer.from(String(envelope))));
    const statement = JSON.parse(utf8.decode(strictBase64(env.payload, 'payload')));
    const names = statement.subject.map(s => s?.name).filter(name => typeof name === 'string' && SUBJECT_NAME.test(name));
    return [...new Set(names)].slice(0, LIMITS.subjects);
  } catch { return []; }
}
