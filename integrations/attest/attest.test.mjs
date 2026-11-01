import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { existsSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFile } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { runAssessment } from '../../src/runner.mjs';
import { createStore } from '../../src/store.mjs';
import { exportRun } from '../../src/export-cli.mjs';
import { evidencePack, PACK_ENVELOPE } from '../../src/evidence-pack.mjs';
import { digest, stable } from '../../src/domain.mjs';
import { exportPaymentsRun, savedPaymentsRun } from '../payments-pack/output.mjs';
import { PAYMENTS_RUN_SCHEMA as PACK_RUN_SCHEMA, PAYMENTS_SCOPE as PACK_SCOPE } from '../payments-pack/pack.mjs';
import { buildStatement, generateSigningKey, signFiles, signStatement } from './sign.mjs';
import { LIMITS, MEANING, PAYLOAD_TYPE, PAYMENTS_RUN_FIELDS, PAYMENTS_RUN_SCHEMA, PAYMENTS_SCOPE, keyIdOf, pae, verifyEnvelope } from './verify.mjs';
import { KEY_FILE, PUBLIC_KEY_FILE, main } from './cli.mjs';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const scratch = async t => { const dir = await mkdtemp(join(tmpdir(), 'scopehaven-attest-')); t.after(() => rm(dir, { recursive: true, force: true })); return dir; };

// Real exports: a planted-defect baseline and a repaired candidate from the owned
// synthetic fixture, saved and exported through the product's own export path.
const work = await mkdtemp(join(tmpdir(), 'scopehaven-attest-exports-'));
process.on('exit', () => rmSync(work, { recursive: true, force: true }));
const baseline = await runAssessment('demo-vulnerable'), repaired = await runAssessment('demo-repaired');
const dataDir = join(work, 'data'), exportsDir = join(work, 'exports');
await mkdir(exportsDir, { mode: 0o700 });
const store = createStore(dataDir); await store.save(baseline); await store.save(repaired);
const exported = {};
for (const [name, options] of Object.entries({ 'baseline.json': { runId: baseline.id, format: 'json' }, 'repaired.json': { runId: repaired.id, format: 'json' },
  'repaired.sarif': { runId: repaired.id, format: 'sarif' }, 'repaired.html': { runId: repaired.id, format: 'html' },
  'comparison.json': { runId: repaired.id, baselineRunId: baseline.id, format: 'json' } })) {
  await exportRun({ ...options, outputFile: join(exportsDir, name), dataDir });
  exported[name] = await readFile(join(exportsDir, name));
}
// Payments-pack runs: the checked-in sample runs (integrations/payments-pack/sample), exported through the pack's own export
// path, which drops the comparison `payments run --baseline` stores beside a run (after-repaired.json holds one).
const SAMPLE = name => fileURLToPath(new URL(`../payments-pack/sample/${name}`, import.meta.url));
const SAVED_AFTER = await readFile(SAMPLE('after-repaired.json'));
const payments = { before: JSON.parse(await readFile(SAMPLE('before-vulnerable.json'), 'utf8')), after: JSON.parse(SAVED_AFTER.toString('utf8')) };
for (const [name, run, format] of [['payments-before.json', payments.before, 'json'], ['payments-after.json', payments.after, 'json'], ['payments-after.sarif', payments.after, 'sarif']]) {
  await exportPaymentsRun({ run, format, outputFile: join(exportsDir, name) });
  exported[name] = await readFile(join(exportsDir, name));
}
// A payments run's identity, written out from the run itself: its fields in this order, and coreSha256 equal to the sha256 the
// pack gave it (a stored comparison is outside both).
const paymentsIdentity = (subject, run) => ({ subject, id: run.id, schema: run.schema, startedAt: run.startedAt, finishedAt: run.finishedAt, targetId: run.targetId,
  applicationId: run.applicationId, build: run.build, packSha256: run.packSha256, coreSha256: run.sha256 });
const FILES = Object.entries(exported).map(([name, content]) => ({ name, content }));
const filesMap = (overrides = {}) => {
  const map = new Map(FILES.map(f => [f.name, f.content]));
  for (const [name, content] of Object.entries(overrides)) content === undefined ? map.delete(name) : map.set(name, content);
  return map;
};
const KEY = generateSigningKey(), OTHER = generateSigningKey();
const version = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8')).version;
// Signed without signFiles' self-check, so a broken verifier fails the tests below rather than this setup.
const ENVELOPE = signStatement(buildStatement(FILES, { version }), KEY.privatePem);
const statementOf = envelope => JSON.parse(Buffer.from(JSON.parse(envelope).payload, 'base64').toString('utf8'));
const STATEMENT = statementOf(ENVELOPE);
const verifyWith = (envelope, files = filesMap(), publicKey = KEY.publicPem, options) => verifyEnvelope({ envelope, publicKey, files }, options);
const editEnvelope = edit => { const env = JSON.parse(ENVELOPE); edit(env); return JSON.stringify(env); };
const flipBase64 = text => { const bytes = Buffer.from(text, 'base64'); bytes[bytes.length >> 1] ^= 1; return bytes.toString('base64'); };
// Same bytes, different text: sets an unused low bit in the character before '=='.
const nonCanonicalBase64 = text => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', i = text.length - 3;
  return `${text.slice(0, i)}${alphabet[alphabet.indexOf(text[i]) | 1]}${text.slice(i + 1)}`;
};
// An Ed25519 signature with S replaced by S + L verifies under the bare group equation;
// RFC 8032 requires rejecting S >= L.
const malleable = sigText => {
  const bytes = Buffer.from(sigText, 'base64'), L = 2n ** 252n + 27742317777372353535851937790883648493n;
  let s = 0n; for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(bytes[i]);
  s += L; for (let i = 32; i < 64; i++) { bytes[i] = Number(s & 255n); s >>= 8n; }
  return bytes.toString('base64');
};
const forged = edit => { const statement = structuredClone(STATEMENT); edit(statement); return signStatement(statement, KEY.privatePem); };
const rawEnvelope = (payload, privatePem = KEY.privatePem) => {
  const key = createPrivateKey(privatePem);
  return JSON.stringify({ payloadType: PAYLOAD_TYPE, payload: payload.toString('base64'), signatures: [{ keyid: keyIdOf(createPublicKey(key)), sig: sign(null, pae(PAYLOAD_TYPE, payload), key).toString('base64') }] });
};
// A run export whose result was edited after export, without fixing its integrity hash.
const editedRun = (() => { const run = JSON.parse(exported['baseline.json']); const failing = run.results.find(r => r.status === 'fail'); failing.status = 'pass'; return Buffer.from(`${JSON.stringify(run, null, 2)}\n`); })();
const forcedEditedRun = forged(statement => { statement.subject.find(s => s.name === 'baseline.json').digest.sha256 = sha256(editedRun); });
const NATIVE_CONTROLS = ['payload-tampered', 'signature-tampered', 'payload-type-changed', 'wrong-key', 'subject-tampered', 'run-file-edited', 'run-identity-edited'];
const PAYMENTS_CONTROLS = ['payments-run-file-edited', 'payments-run-identity-edited'];
const CONTROLS = [...NATIVE_CONTROLS, ...PAYMENTS_CONTROLS];
// A payments run edited after export (a failing row now reads pass), its sha256 left as it was.
const editedPayments = (() => { const run = JSON.parse(exported['payments-before.json']); run.rows.find(r => r.status === 'fail').status = 'pass'; return Buffer.from(`${JSON.stringify(run, null, 2)}\n`); })();
const forcedEditedPayments = forged(statement => { statement.subject.find(s => s.name === 'payments-before.json').digest.sha256 = sha256(editedPayments); });
// A payments run edited and resealed: its unkeyed sha256 recomputed over the edit, as anyone can.
const reseal = (run, edit) => {
  const copy = structuredClone(run); edit(copy);
  const { sha256: _, comparison, ...body } = copy;
  return Buffer.from(`${JSON.stringify({ ...body, sha256: digest(body), ...(comparison === undefined ? {} : { comparison }) }, null, 2)}\n`);
};
const withoutComparison = ({ comparison: _, ...run }) => run;
// A failing row read as passing, with the counts made to agree, so only the rule that a status is the worst of its assertions refuses it.
const flipStatus = run => { run.rows.find(r => r.status === 'fail').status = 'pass'; for (const s of ['pass', 'fail', 'inconclusive']) run.counts[s] = run.rows.filter(r => r.status === s).length; };
const flipLast = hex => `${hex.slice(0, -1)}${hex.endsWith('0') ? '1' : '0'}`;
const paymentsEntry = (s, subject) => s.predicate.runs.find(r => r.subject === subject);
// A baseline export rewritten as raw text (extra members go before the integrity field), with its
// integrity hash recomputed or left stale. The hash has no key, so recomputing it is always possible.
const runText = (members, { fix = true, edit = text => text } = {}) => {
  const original = JSON.parse(exported['baseline.json']), { integrity, notes, ...core } = original;
  const body = JSON.stringify(core).slice(0, -1), placeholder = 'f'.repeat(64);
  const text = edit(`${body},${members},"integrity":${JSON.stringify({ ...integrity, sha256: placeholder })},"notes":${JSON.stringify(notes)}}`);
  const parsed = JSON.parse(text); delete parsed.integrity; delete parsed.notes;
  return Buffer.from(text.replace(placeholder, fix ? digest(parsed) : integrity.sha256));
};
// Signed by the key holder with no run identity claimed: only the verifier's own recomputation can catch the edit.
const signedWithoutRuns = (name, content) => {
  const statement = buildStatement([{ name: 'plain.txt', content: Buffer.from('x') }], { version });
  statement.subject = [{ name, digest: { sha256: sha256(content) } }];
  return [signStatement(statement, KEY.privatePem), new Map([[name, content]])];
};
const nested = depth => `${'['.repeat(depth)}1${']'.repeat(depth)}`;

// The independent Python verifier, when a Python 3.8+ is installed at a fixed path.
const PYTHON = ['/Library/Frameworks/Python.framework/Versions/3.13/bin/python3', '/opt/homebrew/bin/python3', '/usr/bin/python3'].find(path => existsSync(path));
const SCRIPT = fileURLToPath(new URL('./verify_envelope.py', import.meta.url));
const python = (args, input) => new Promise(resolve => {
  const child = execFile(PYTHON, args, { maxBuffer: 16 << 20, timeout: 60000 }, (error, stdout, stderr) => resolve({ code: error ? error.code : 0, stdout, stderr }));
  if (input !== undefined) child.stdin.end(input);
});
test('the DSSE encoding matches the specification example and Node Ed25519 matches RFC 8032 test 1', () => {
  assert.equal(pae('http://example.com/HelloWorld', Buffer.from('hello world')).toString(), 'DSSEv1 29 http://example.com/HelloWorld 11 hello world');
  const b64url = hex => Buffer.from(hex, 'hex').toString('base64url');
  const key = createPrivateKey({ format: 'jwk', key: { kty: 'OKP', crv: 'Ed25519', d: b64url('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'), x: b64url('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a') } });
  assert.equal(sign(null, Buffer.alloc(0), key).toString('hex'), 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
});

test('signed real exports verify, with run identities recomputed from the run files', () => {
  const result = verifyWith(ENVELOPE);
  assert.equal(result.verdict, 'verified'); assert.equal(result.verified, true); assert.equal(result.keyid, KEY.keyid);
  assert.equal(result.meaning, MEANING); assert.deepEqual(result.runs, STATEMENT.predicate.runs);
  assert.deepEqual(result.unclaimedRuns, []); assert.equal(result.note, null);
  assert.deepEqual(result.subjects.map(s => [s.name, s.sha256]), FILES.map(f => [f.name, sha256(f.content)]));
  assert.deepEqual(result.selfChecks.map(c => [c.id, c.observed]), CONTROLS.map(id => [id, 'rejected']));
  // The run exports and the payments runs carry run identities; SARIF, HTML and the comparison are digests only.
  assert.deepEqual(result.runs.map(r => r.subject), ['baseline.json', 'repaired.json', 'payments-before.json', 'payments-after.json']);
  for (const [run, identity] of [[baseline, result.runs[0]], [repaired, result.runs[1]]]) {
    for (const field of ['id', 'build', 'suiteId', 'suiteHash', 'policyHash', 'fixtureVersion', 'fixtureHash', 'applicationId', 'evaluatorHash', 'evidenceOrigin', 'profileHash']) assert.equal(identity[field], run[field], field);
    assert.equal(identity.coreSha256, JSON.parse(exported[`${identity.subject}`]).integrity.sha256);
  }
  // The signer named them as the verifier recomputed them, the payments runs with exactly these fields.
  assert.deepEqual(STATEMENT.predicate.runs.slice(2), [paymentsIdentity('payments-before.json', payments.before), paymentsIdentity('payments-after.json', payments.after)]);
  assert.deepEqual(PAYMENTS_RUN_FIELDS, ['id', 'schema', 'startedAt', 'finishedAt', 'targetId', 'applicationId', 'build', 'packSha256']);
  assert.equal(STATEMENT._type, 'https://in-toto.io/Statement/v1');
  assert.match(STATEMENT.predicate.signedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
});

test('signFiles verifies its own envelope first, and run exports alone keep the controls they had', () => {
  const { envelope, check } = signFiles(FILES, { privateKey: KEY.privatePem, version });
  assert.equal(check.verdict, 'verified'); assert.deepEqual(check.runs, STATEMENT.predicate.runs); assert.deepEqual(statementOf(envelope).predicate.runs, STATEMENT.predicate.runs);
  const native = signFiles(FILES.filter(f => !f.name.startsWith('payments-')), { privateKey: KEY.privatePem, version }).check;
  assert.deepEqual(native.selfChecks.map(c => [c.id, c.observed]), NATIVE_CONTROLS.map(id => [id, 'rejected']));
  const alone = signFiles([{ name: 'payments-after.json', content: exported['payments-after.json'] }], { privateKey: KEY.privatePem, version }).check;
  assert.deepEqual(alone.runs, [paymentsIdentity('payments-after.json', payments.after)]);
  assert.deepEqual(alone.selfChecks.map(c => [c.id, c.observed]), [...NATIVE_CONTROLS.slice(0, 5), ...PAYMENTS_CONTROLS].map(id => [id, 'rejected']));
});

const TAMPERS = [
  ['payload bit flipped', () => [editEnvelope(env => { env.payload = flipBase64(env.payload); })], 'signature-invalid'],
  ['signature bit flipped', () => [editEnvelope(env => { env.signatures[0].sig = flipBase64(env.signatures[0].sig); })], 'signature-invalid'],
  ['payload type changed', () => [editEnvelope(env => { env.payloadType = 'application/json'; })], 'payload-type'],
  ['keyid changed', () => [editEnvelope(env => { env.signatures[0].keyid = OTHER.keyid; })], 'keyid-mismatch'],
  ['second signature added', () => [editEnvelope(env => { env.signatures.push({ ...env.signatures[0] }); })], 'signature-count'],
  ['signatures removed', () => [editEnvelope(env => { env.signatures = []; })], 'signature-count'],
  ['extra envelope field', () => [editEnvelope(env => { env.note = 'trust me'; })], 'envelope-shape'],
  ['signature re-encoded with non-zero padding bits', () => [editEnvelope(env => { env.signatures[0].sig = nonCanonicalBase64(env.signatures[0].sig); })], 'base64'],
  ['signature made malleable (S + L)', () => [editEnvelope(env => { env.signatures[0].sig = malleable(env.signatures[0].sig); })], 'signature-invalid'],
  ['payload re-encoded with a line break', () => [editEnvelope(env => { env.payload = `${env.payload.slice(0, 8)}\n${env.payload.slice(8)}`; })], 'base64'],
  ['envelope not JSON', () => ['not json'], 'envelope-json'],
  ['the HTML report changed', () => [ENVELOPE, filesMap({ 'repaired.html': Buffer.from(exported['repaired.html'].toString().replace('<', '<!---->')) })], 'subject-digest-mismatch'],
  ['a run export missing', () => [ENVELOPE, filesMap({ 'repaired.json': undefined })], 'subject-missing'],
  ['an unsigned file presented with the signed ones', () => [ENVELOPE, filesMap({ 'extra.json': Buffer.from('{}') })], 'unsigned-file'],
  ['verified against a different trusted key', () => [ENVELOPE, filesMap(), OTHER.publicPem], 'keyid-mismatch'],
  ['keyid pointed at a different trusted key', () => [editEnvelope(env => { env.signatures[0].keyid = OTHER.keyid; }), filesMap(), OTHER.publicPem], 'signature-invalid'],
  ['signed statement misstates a run identity', () => [forged(s => { s.predicate.runs[0].suiteHash = '0'.repeat(64); })], 'run-identity-mismatch'],
  ['signed statement omits the run identities', () => [forged(s => { s.predicate.runs = []; })], 'run-identity-mismatch'],
  ['signed statement changes what a signature means', () => [forged(s => { s.predicate.meaning = 'Certified safe.'; })], 'predicate-shape'],
  ['signed statement adds a predicate field', () => [forged(s => { s.predicate.verdict = 'pass'; })], 'predicate-shape'],
  ['signed statement with an impossible date', () => [forged(s => { s.predicate.signedAt = '2026-02-30T00:00:00.000Z'; })], 'predicate-shape'],
  ['signed statement dated before year 2000', () => [forged(s => { s.predicate.signedAt = '0999-01-01T00:00:00.000Z'; })], 'predicate-shape'],
  ['signed statement with another predicate type', () => [forged(s => { s.predicateType = 'https://slsa.dev/provenance/v1'; })], 'predicate-type'],
  ['signed statement with another statement type', () => [forged(s => { s._type = 'https://in-toto.io/Statement/v0.1'; })], 'statement-shape'],
  ['signed statement with another clock note', () => [forged(s => { s.predicate.clock = 'Trusted timestamp.'; })], 'predicate-shape'],
  ['signed statement with another attest version', () => [forged(s => { s.predicate.producer.attest = 'scopehaven-attest/9'; })], 'predicate-shape'],
  ['signed statement naming one file twice', () => [forged(s => { s.subject.push({ ...s.subject[0] }); })], 'subject-shape'],
  ['signed statement with an uppercase digest', () => [forged(s => { s.subject[0].digest.sha256 = s.subject[0].digest.sha256.toUpperCase(); })], 'subject-shape'],
  ['signed statement naming no files', () => [forged(s => { s.subject = []; })], 'subject-shape'],
  ['signed statement whose runs are not a list', () => [forged(s => { s.predicate.runs = {}; })], 'predicate-shape'],
  ['signed statement with more runs than files', () => [forged(s => { s.predicate.runs = Array(s.subject.length + 1).fill(s.predicate.runs[0]); })], 'predicate-shape'],
  ['signature entry with an extra field', () => [editEnvelope(env => { env.signatures[0].cert = 'x'; })], 'signature-shape'],
  ['signed payload over its size limit', () => [rawEnvelope(Buffer.alloc(LIMITS.payloadBytes + 1, 32))], 'payload-size'],
  ['envelope over its size limit', () => [' '.repeat(LIMITS.envelopeBytes + 1)], 'envelope-size'],
  ['signed statement with a non-ASCII digit in its version', () => [forged(s => { s.predicate.producer.version = '\u0661.0.0'; })], 'predicate-shape'],
  ['signed payload whose integer-like keys are out of JavaScript order', () => [rawEnvelope(Buffer.from(JSON.stringify(STATEMENT).replace('"runs":[', '"runs":[{"b":1,"1":2},')))], 'payload-not-canonical'],
  ['signed statement with a path as a subject name', () => [forged(s => { s.subject[0].name = '../baseline.json'; })], 'subject-shape'],
  ['signed payload that is not canonical JSON', () => [rawEnvelope(Buffer.from(JSON.stringify(STATEMENT, null, 1)))], 'payload-not-canonical'],
  ['run export edited after export, signed anyway', () => [forcedEditedRun, filesMap({ 'baseline.json': editedRun })], 'run-integrity-mismatch'],
  ['edited run export signed with no run identities claimed', () => signedWithoutRuns('baseline.json', editedRun), 'run-integrity-mismatch'],
  ['edited run export nested too deeply to recompute', () => signedWithoutRuns('baseline.json', runText(`"deep":${nested(20000)}`, { fix: false })), 'subject-unparseable'],
  ['payments run edited after export, signed anyway', () => [forcedEditedPayments, filesMap({ 'payments-before.json': editedPayments })], 'run-integrity-mismatch'],
  ['edited payments run signed with no run identities claimed', () => signedWithoutRuns('payments-before.json', editedPayments), 'run-integrity-mismatch'],
  ['payments run with its sha256 removed', () => signedWithoutRuns('payments-before.json', Buffer.from(JSON.stringify((({ sha256: _, ...run }) => run)(payments.before)))), 'run-integrity-mismatch'],
  ['resealed payments run whose row status no longer follows its assertions', () => signedWithoutRuns('payments-before.json', reseal(payments.before, flipStatus)), 'payments-run-refused'],
  ['resealed payments run signed with the identity its signer built', () => {
    const content = reseal(payments.before, flipStatus);
    return [signStatement(buildStatement([{ name: 'payments-before.json', content }], { version }), KEY.privatePem), new Map([['payments-before.json', content]])];
  }, 'payments-run-refused'],
  ['resealed payments run whose counts are not its rows', () => signedWithoutRuns('payments-before.json', reseal(payments.before, run => { run.counts.pass += 1; })), 'payments-run-refused'],
  ['file declaring the payments run schema with no run id', () => signedWithoutRuns('payments.json', Buffer.from(JSON.stringify({ schema: PAYMENTS_RUN_SCHEMA, sha256: '0'.repeat(64) }))), 'payments-run-refused'],
  ['edited payments run nested too deeply to recompute', () => signedWithoutRuns('payments-before.json', Buffer.from(JSON.stringify(payments.before).replace('"scope":', `"deep":${nested(20000)},"scope":`))), 'subject-unparseable'],
  ['signed statement misstates a payments run identity', () => [forged(s => { paymentsEntry(s, 'payments-before.json').packSha256 = '0'.repeat(64); })], 'run-identity-mismatch'],
  ['signed statement misstates a payments run checksum', () => [forged(s => { const entry = paymentsEntry(s, 'payments-after.json'); entry.coreSha256 = flipLast(entry.coreSha256); })], 'run-identity-mismatch'],
  ['signed statement drops a field from a payments run identity', () => [forged(s => { delete paymentsEntry(s, 'payments-after.json').build; })], 'run-identity-mismatch'],
  ['signed statement names a payments run identity twice', () => [forged(s => { s.predicate.runs.push({ ...paymentsEntry(s, 'payments-after.json') }); })], 'run-identity-mismatch'],
  ['signed statement names the payments runs out of order', () => [forged(s => { s.predicate.runs = [...s.predicate.runs.slice(0, 2), s.predicate.runs[3], s.predicate.runs[2]]; })], 'run-identity-mismatch'],
  ['signed statement gives a payments run identity to its SARIF export', () => [forged(s => { s.predicate.runs.push({ ...paymentsEntry(s, 'payments-after.json'), subject: 'payments-after.sarif' }); })], 'run-identity-mismatch'],
  ['signed statement keeps the payments identities and drops the run exports\'', () => [forged(s => { s.predicate.runs = s.predicate.runs.slice(2); })], 'run-identity-mismatch'],
];

test('every tamper is rejected with its reason', () => {
  for (const [label, make, reason] of TAMPERS) {
    const [envelope, files, publicKey] = make();
    const result = verifyWith(envelope, files, publicKey);
    assert.equal(result.verdict, 'rejected', label); assert.equal(result.verified, false, label); assert.equal(result.reason, reason, label);
  }
});

test('the signer refuses an edited run export, an edited or self-inconsistent payments run, and unsafe names', () => {
  assert.throws(() => buildStatement([{ name: 'baseline.json', content: editedRun }], { version }), /Refusing to sign baseline.json/);
  assert.throws(() => signFiles([{ name: 'baseline.json', content: editedRun }], { privateKey: KEY.privatePem, version }), /edited after export/);
  assert.throws(() => buildStatement([{ name: 'payments-before.json', content: editedPayments }], { version }), /^Error: Refusing to sign payments-before.json: its results no longer match its sha256, so it was edited after it was produced\.$/);
  // Resealed, it passes the signer's own check; the verifier's run of the pack's rules refuses it, so nothing is signed.
  assert.throws(() => signFiles([{ name: 'payments-before.json', content: reseal(payments.before, flipStatus) }], { privateKey: KEY.privatePem, version }), /self-check failed \(rejected: payments-run-refused/);
  assert.throws(() => buildStatement([{ name: '../x.json', content: Buffer.from('{}') }], { version }), /unique plain name/);
  assert.throws(() => buildStatement([{ name: 'a.json', content: Buffer.from('1') }, { name: 'a.json', content: Buffer.from('2') }], { version }), /unique plain name/);
  assert.throws(() => signFiles(FILES, { privateKey: KEY.publicPem, version }), /private key/i);
  assert.throws(() => signFiles(FILES, { privateKey: KEY.privatePem, version }, { verify: () => ({ verified: false, verdict: 'rejected', detail: 'stub' }) }), /nothing was written/);
});

test('a verifier that accepts every signature fails its own negative controls', () => {
  const result = verifyWith(ENVELOPE, filesMap(), KEY.publicPem, { checkSignature: () => true });
  assert.equal(result.verdict, 'self-check-failed'); assert.equal(result.verified, false);
  assert.deepEqual(result.selfChecks.filter(c => c.observed === 'accepted').map(c => c.id), ['payload-tampered', 'signature-tampered', 'payload-type-changed', 'wrong-key']);
  // Tampering the signer could not have done still gets caught by a sound verifier.
  assert.equal(verifyWith(editEnvelope(env => { env.payload = flipBase64(env.payload); })).reason, 'signature-invalid');
});

test('the CLI creates keys and envelopes without overwriting, and verifies a directory', { timeout: 30000 }, async t => {
  const keys = await scratch(t), out = await scratch(t);
  const created = await main(['keygen', '--dir', keys]);
  assert.equal(created.code, 0); assert.match(created.output.keyid, /^[0-9a-f]{64}$/);
  assert.equal((await stat(join(keys, KEY_FILE))).mode & 0o777, 0o600);
  assert.ok(!JSON.stringify(created.output).includes('PRIVATE KEY'));
  assert.equal((await main(['keygen', '--dir', keys])).code, 2, 'never overwrites a key');
  const files = ['repaired.json', 'repaired.sarif', 'repaired.html'].map(name => join(exportsDir, name)), envelope = join(out, 'repaired.dsse.json');
  const signed = await main(['sign', '--key', join(keys, KEY_FILE), '--out', envelope, ...files]);
  assert.equal(signed.code, 0, JSON.stringify(signed.output)); assert.equal(signed.output.runs, 1);
  assert.equal((await main(['sign', '--key', join(keys, KEY_FILE), '--out', envelope, ...files])).code, 2, 'never overwrites an envelope');
  const verified = await main(['verify', '--key', join(keys, PUBLIC_KEY_FILE), '--envelope', envelope, '--dir', exportsDir]);
  assert.equal(verified.code, 0); assert.equal(verified.output.verdict, 'verified'); assert.equal(verified.output.keyid, created.output.keyid);
  // A received copy with one changed byte is rejected with exit code 1.
  const received = await scratch(t);
  for (const name of ['repaired.json', 'repaired.sarif']) await writeFile(join(received, name), exported[name]);
  await writeFile(join(received, 'repaired.html'), `${exported['repaired.html']}<!-- -->`);
  const rejected = await main(['verify', '--key', join(keys, PUBLIC_KEY_FILE), '--envelope', envelope, '--dir', received]);
  assert.equal(rejected.code, 1); assert.equal(rejected.output.reason, 'subject-digest-mismatch');
  assert.equal((await main(['verify', '--key', join(keys, KEY_FILE), '--envelope', envelope, '--dir', exportsDir])).code, 2, 'verification takes only the public key');
  await chmod(join(keys, KEY_FILE), 0o644);
  assert.match((await main(['sign', '--key', join(keys, KEY_FILE), '--out', join(out, 'other.dsse.json'), ...files])).output.error, /mode 0600/);
  const open = await scratch(t); await chmod(open, 0o755);
  assert.match((await main(['keygen', '--dir', open])).output.error, /mode 0700/);
  assert.equal((await main(['sign', '--key', join(keys, KEY_FILE), '--out', 'relative.json', ...files])).code, 2);
  await chmod(join(keys, KEY_FILE), 0o600);
  assert.match((await main(['sign', '--key', join(keys, KEY_FILE), '--out', join(open, 'x.dsse.json'), ...files])).output.error, /mode 0700/, 'the envelope goes only to a private directory');
  assert.match((await main(['sign', '--key', join(keys, KEY_FILE), '--out', join(out, 'key.dsse.json'), join(keys, KEY_FILE)])).output.error, /private key file/);
  await writeFile(join(out, 'copy.pem'), await readFile(join(keys, KEY_FILE)));
  assert.match((await main(['sign', '--key', join(keys, KEY_FILE), '--out', join(out, 'copy.dsse.json'), join(out, 'copy.pem')])).output.error, /a copy of it/);
  const linked = await scratch(t); symlinkSync(join(exportsDir, 'repaired.json'), join(linked, 'repaired.json'));
  assert.equal((await main(['sign', '--key', join(keys, KEY_FILE), '--out', join(out, 'link.dsse.json'), join(linked, 'repaired.json')])).code, 2, 'a symlinked file is not followed');
  // A FIFO named like a signed file is refused at once instead of blocking the verifier.
  const fifo = await scratch(t);
  for (const name of ['repaired.json', 'repaired.sarif']) await writeFile(join(fifo, name), exported[name]);
  await new Promise((done, fail) => execFile('mkfifo', [join(fifo, 'repaired.html')], error => error ? fail(error) : done()));
  assert.equal((await main(['verify', '--key', join(keys, PUBLIC_KEY_FILE), '--envelope', envelope, '--dir', fifo])).code, 2);
  if (PYTHON) assert.equal((await python([SCRIPT, '--key', join(keys, PUBLIC_KEY_FILE), '--envelope', envelope, '--dir', fifo])).code, 2);
});

const pythonVerify = async (t, envelope, files, publicPem = KEY.publicPem) => {
  const dir = await scratch(t), paths = [];
  await writeFile(join(dir, 'key.pub.pem'), publicPem); await writeFile(join(dir, 'envelope.json'), envelope);
  await mkdir(join(dir, 'files'));
  for (const [name, content] of files) { await writeFile(join(dir, 'files', name), content); paths.push(join(dir, 'files', name)); }
  const { code, stdout, stderr } = await python([SCRIPT, '--key', join(dir, 'key.pub.pem'), '--envelope', join(dir, 'envelope.json'), ...paths]);
  return { code, result: stdout ? JSON.parse(stdout) : null, stderr };
};

test('the Python verifier accepts what the Node signer signed and recomputes the same run identities', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async t => {
  const { code, result, stderr } = await pythonVerify(t, ENVELOPE, filesMap());
  assert.equal(code, 0, stderr); assert.equal(result.verdict, 'verified'); assert.equal(result.keyid, KEY.keyid);
  assert.deepEqual(result.runs, STATEMENT.predicate.runs); assert.deepEqual(result.unclaimedRuns, []); assert.equal(result.note, null);
  assert.deepEqual(result.selfChecks.map(c => [c.id, c.observed]), [...CONTROLS.map(id => [id, 'rejected']), ['rfc8032-test-1', 'accepted']]);
});

test('the Python verifier rejects the same tampers for the same reasons', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async t => {
  for (const [label, make, reason] of TAMPERS) {
    const [envelope, files = filesMap(), publicKey] = make();
    const { code, result, stderr } = await pythonVerify(t, envelope, files, publicKey);
    assert.equal(code, 1, `${label}: ${stderr}`); assert.equal(result.reason, reason, label);
  }
});

test('the Python verifier catches a signature check that accepts everything', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async t => {
  const dir = await scratch(t);
  await writeFile(join(dir, 'key.pub.pem'), KEY.publicPem); await writeFile(join(dir, 'envelope.json'), ENVELOPE);
  for (const [name, content] of filesMap()) await writeFile(join(dir, name), content);
  const program = `import sys; sys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('.', import.meta.url)))})
import verify_envelope as v
v.ed25519_verify = lambda *args: True
sys.exit(v.main(["--key", ${JSON.stringify(join(dir, 'key.pub.pem'))}, "--envelope", ${JSON.stringify(join(dir, 'envelope.json'))}, "--dir", ${JSON.stringify(dir)}]))`;
  const { code, stdout } = await python(['-B', '-c', program]);
  assert.equal(code, 3); assert.equal(JSON.parse(stdout).verdict, 'self-check-failed');
});

test('the Python canonical digest matches the store digest on awkward values', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async () => {
  const values = [0.1, 1e21, 1.5e-7, 1e-7, 123.456, -0, 2 ** 53, -2.5e-300, 5e-324, 1.7976931348623157e308, 100, 'tab\tquote"back\\slash', '\u0001\u001f\u007f', ' ', '\uD800', '😀',
    { b: 1, a: 2, 'é': 3, '': 4, '😀': 5, '': 6 }, [true, false, null, [], {}]];
  const program = `import sys, json; sys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('.', import.meta.url)))})
import verify_envelope as v
print(json.dumps([v._stable(x) for x in json.loads(sys.stdin.read())]))`;
  const { code, stdout, stderr } = await python(['-B', '-c', program], JSON.stringify(values));
  assert.equal(code, 0, stderr);
  assert.deepEqual(JSON.parse(stdout), JSON.parse(JSON.stringify(values)).map(stable));
});

test('both verifiers accept run exports that write the same numbers in other valid forms', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async t => {
  const content = Buffer.from(runText('"big":12345678901234567890,"x":1.2345678901234567e19,"e16":1e16,"tiny":1e-7,"one":1.0,"neg":-0.0,"keys":{"b":1,"10":2,"1":3}').toString().replace('"schemaVersion":1,', '"schemaVersion":1.0,'));
  const files = [{ name: 'numbers.json', content }], { envelope, check } = signFiles(files, { privateKey: KEY.privatePem, version });
  assert.equal(check.verdict, 'verified'); assert.equal(check.runs.length, 1);
  const { code, result, stderr } = await pythonVerify(t, envelope, new Map([['numbers.json', content]]));
  assert.equal(code, 0, stderr); assert.deepEqual(result.runs, check.runs);
});

test('JSON beyond the Python parser\'s limits is refused there, never skipped', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async t => {
  // Valid and intact, but deeper than Python recurses: Node verifies, Python refuses rather than skipping the run checks.
  const deep = runText(`"deep":${nested(2000)}`), signed = signFiles([{ name: 'deep.json', content: deep }], { privateKey: KEY.privatePem, version });
  assert.equal(signed.check.verdict, 'verified');
  const intact = await pythonVerify(t, signed.envelope, new Map([['deep.json', deep]]));
  assert.equal(intact.code, 1, intact.stderr); assert.equal(intact.result.reason, 'subject-unparseable');
  // Edited, with a 5000-digit integer and no run identity claimed: Python 3.11+ cannot parse it, older Pythons can.
  const [envelope, files] = signedWithoutRuns('huge.json', runText(`"huge":${'9'.repeat(5000)}`, { fix: false }));
  assert.equal(verifyWith(envelope, files).reason, 'run-integrity-mismatch');
  const huge = await pythonVerify(t, envelope, files);
  assert.equal(huge.code, 1, huge.stderr); assert.ok(['run-integrity-mismatch', 'subject-unparseable'].includes(huge.result.reason), huge.result.reason);
});

test('small-order keys and points are refused, so they cannot forge in either verifier', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async () => {
  // Searches for a signature that satisfies the bare group equation under an order-8 public key.
  const program = `import sys, json, hashlib; sys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('.', import.meta.url)))})
import verify_envelope as v
public = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
a, found = v._decompress(public), None
for n in range(200):
    message, point = b"scopehaven-%d" % n, v.IDENTITY
    for j in range(8):
        r = v._compress(point)
        k = int.from_bytes(hashlib.sha512(r + public + message).digest(), "little") % v.L
        if v._equal(v.IDENTITY, v._add(v._decompress(r), v._mul(k, a))):
            found = (message, r + bytes(32))
            break
        point = v._add(point, a)
    if found:
        break
print(json.dumps({"message": found[0].hex(), "sig": found[1].hex(), "accepted": v.ed25519_verify(public, found[0], found[1]),
    "yNotBelowP": v._decompress(v.P.to_bytes(32, "little")) is None, "zeroXWithSign": v._decompress(((1 << 255) | 1).to_bytes(32, "little")) is None}))`;
  const { code, stdout, stderr } = await python(['-B', '-c', program]);
  assert.equal(code, 0, stderr);
  const forgery = JSON.parse(stdout);
  assert.equal(forgery.accepted, false); assert.equal(forgery.yNotBelowP, true); assert.equal(forgery.zeroXWithSign, true);
  let nodeAccepts = false;
  try {
    const key = createPublicKey({ format: 'jwk', key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', 'hex').toString('base64url') } });
    nodeAccepts = verify(null, Buffer.from(forgery.message, 'hex'), key, Buffer.from(forgery.sig, 'hex'));
  } catch {}
  assert.equal(nodeAccepts, false);
});

test('both verifiers verify unusual but intact files: infinities, a lone surrogate, a huge number in plain text', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async t => {
  const files = [
    { name: 'infinite.json', content: runText('"far":1e400,"near":-1e400') },
    { name: 'surrogate.json', content: runText('"y":1', { edit: text => text.replace(`"id":"${baseline.id}"`, '"id":"g\\ud800"') }) },
    { name: 'digits.txt', content: Buffer.from(`${'9'.repeat(5000)} is not JSON`) },
  ];
  const { envelope, check } = signFiles(files, { privateKey: KEY.privatePem, version });
  assert.equal(check.verdict, 'verified'); assert.equal(check.runs.find(r => r.subject === 'surrogate.json').id, 'g\ud800');
  const { code, result, stderr } = await pythonVerify(t, envelope, new Map(files.map(f => [f.name, f.content])));
  assert.equal(code, 0, stderr); assert.deepEqual(result.runs, check.runs);
});

test('a payload nested past Python\'s limits is refused there with a reason, not a crash', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async t => {
  const envelope = rawEnvelope(Buffer.from(JSON.stringify(STATEMENT).replace('"runs":[', `"runs":[${nested(600)},`)));
  assert.equal(verifyWith(envelope).reason, 'run-identity-mismatch');
  const { code, result, stderr } = await pythonVerify(t, envelope, filesMap());
  assert.equal(code, 1, stderr); assert.equal(result.reason, 'payload-json');
});

test('both verifiers read key files by the same rule', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async t => {
  const dir = await scratch(t), envelopePath = join(dir, 'envelope.json');
  await writeFile(envelopePath, ENVELOPE);
  const filePaths = [];
  for (const [name, content] of filesMap()) { await writeFile(join(dir, name), content); filePaths.push(join(dir, name)); }
  for (const [label, text, expected] of [['CRLF line endings', KEY.publicPem.replace(/\n/g, '\r\n'), 0], ['surrounding blank lines', `\n\n${KEY.publicPem}\n\n`, 0],
    ['a byte-order mark', `\ufeff${KEY.publicPem}`, 2], ['CR-only line endings', KEY.publicPem.replace(/\n/g, '\r'), 2], ['text after the block', `${KEY.publicPem}junk\n`, 2]]) {
    await writeFile(join(dir, 'key.pem'), text);
    assert.equal((await main(['verify', '--key', join(dir, 'key.pem'), '--envelope', envelopePath, ...filePaths])).code, expected, `node: ${label}`);
    assert.equal((await python([SCRIPT, '--key', join(dir, 'key.pem'), '--envelope', envelopePath, ...filePaths])).code, expected, `python: ${label}`);
  }
});

// Many envelopes through the Python verifier in one process. For each: its verdict and reason, the canonical bytes of the
// run identities it recomputed and the statement named, the payments runs left unnamed, its note and any control it got wrong.
const PY_BATCH = `import sys, json; sys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('.', import.meta.url)))})
import verify_envelope as v
out = []
for case in json.loads(sys.stdin.read()):
    files = dict((name, bytes.fromhex(data)) for name, data in case["files"].items())
    result = v.verify_envelope(bytes.fromhex(case["envelope"]), case["key"], files)
    out.append({"verdict": result["verdict"], "reason": result["reason"], "runs": v._canonical_json(result["runs"]).hex() if "runs" in result else None,
                "unclaimedRuns": result.get("unclaimedRuns"), "note": result.get("note"),
                "selfChecks": [c["id"] for c in result["selfChecks"] if c["observed"] != c["expected"]]})
print(json.dumps(out))`;
const pythonBatch = async cases => {
  const input = cases.map(([envelope, files, publicKey = KEY.publicPem]) => ({ envelope: Buffer.from(envelope).toString('hex'), key: publicKey,
    files: Object.fromEntries([...files].map(([name, content]) => [name, content.toString('hex')])) }));
  const { code, stdout, stderr } = await python(['-B', '-c', PY_BATCH], JSON.stringify(input));
  assert.equal(code, 0, stderr);
  return JSON.parse(stdout);
};
// The same summary from the Node verifier, run identities as the bytes JSON.stringify gives them.
const nodeSummary = (envelope, files, publicKey = KEY.publicPem) => {
  const result = verifyWith(envelope, files, publicKey);
  return { verdict: result.verdict, reason: result.reason, runs: result.runs ? Buffer.from(JSON.stringify(result.runs)).toString('hex') : null,
    unclaimedRuns: result.unclaimedRuns ?? null, note: result.note ?? null, selfChecks: result.selfChecks.filter(c => c.observed !== c.expected).map(c => c.id) };
};
const signedAs = entries => [signFiles(entries.map(([name, content]) => ({ name, content })), { privateKey: KEY.privatePem, version }).envelope, new Map(entries)];

// A payments run file, the verdict or reason both verifiers give it when it is signed with no identity named (as envelopes
// made before payments runs had identities are), and whether the pack's own reader (savedPaymentsRun) takes it, when that
// differs from the verifiers.
const NUMBERS = Buffer.from(JSON.stringify(payments.before).replace('"counts":{"pass":2,', '"counts":{"pass":2.0e0,').replace('"settleMs":150', '"settleMs":1.5e2'));
const after = withoutComparison(payments.after);
const PACK_AGREEMENT = [
  ['as exported', exported['payments-before.json'], 'verified'],
  ['as saved, with the comparison stored beside the run', SAVED_AFTER, 'verified'],
  ['as saved, with that stored comparison edited: it is outside the checksum, as in the pack', Buffer.from(JSON.stringify({ ...payments.after, comparison: { ...payments.after.comparison, verdict: 'still passing' } })), 'verified'],
  ['with numbers written another way', NUMBERS, 'verified'],
  ['edited, not resealed', editedPayments, 'run-integrity-mismatch'],
  ['with its sha256 removed', Buffer.from(JSON.stringify((({ sha256: _, ...run }) => run)(payments.before))), 'run-integrity-mismatch'],
  ['resealed, a row status that no longer follows its assertions', reseal(payments.before, flipStatus), 'payments-run-refused'],
  ['resealed, counts that are not its rows', reseal(payments.before, run => { run.counts.pass += 1; }), 'payments-run-refused'],
  ['resealed, a count given as text', reseal(payments.before, run => { run.counts.pass = String(run.counts.pass); }), 'payments-run-refused'],
  ['resealed, counts with a fourth key', reseal(payments.before, run => { run.counts.skipped = 0; }), 'payments-run-refused'],
  ['resealed, a count of zero given as false', reseal(payments.before, run => { run.counts.inconclusive = false; }), 'payments-run-refused'],
  ['resealed, an extra field', reseal(payments.before, run => { run.verdict = 'certified'; }), 'payments-run-refused'],
  ['resealed, a field missing', reseal(payments.before, run => { delete run.name; }), 'payments-run-refused'],
  ['resealed, another scope', reseal(payments.before, run => { run.scope = 'Production assurance.'; }), 'payments-run-refused'],
  ['resealed, a live-mode provider', reseal(payments.before, run => { run.provider.livemode = true; }), 'payments-run-refused'],
  ['resealed, a provider with no kind', reseal(payments.before, run => { delete run.provider.kind; }), 'payments-run-refused'],
  ['resealed, a provider that is null', reseal(payments.before, run => { run.provider = null; }), 'payments-run-refused'],
  ['resealed, a provider given as text', reseal(payments.before, run => { run.provider = 'test mode'; }), 'payments-run-refused'],
  ['resealed, a malformed run id', reseal(payments.before, run => { run.id = 'pay-1'; }), 'payments-run-refused'],
  ['resealed, two rows with one id', reseal(payments.before, run => { run.rows[1].id = run.rows[0].id; }), 'payments-run-refused'],
  ['resealed, no rows', reseal(payments.before, run => { run.rows = []; run.counts = { pass: 0, fail: 0, inconclusive: 0 }; }), 'payments-run-refused'],
  ['resealed, an assertion with an unknown status beside passing ones', reseal(payments.before, run => { run.rows[0].assertions[0].status = 'unknown'; }), 'payments-run-refused'],
  ['resealed, an assertion that is null', reseal(payments.before, run => { run.rows[0].assertions[0] = null; }), 'payments-run-refused'],
  ['resealed, a passing row with no assertions', reseal(payments.before, run => { run.rows[0].assertions = []; }), 'payments-run-refused'],
  ['resealed, a row status of no known kind', reseal(payments.before, run => { run.rows[2].status = 'maybe'; }), 'payments-run-refused'],
  ['resealed, a row severity of no known kind', reseal(payments.before, run => { run.rows[2].severity = 'critical'; }), 'payments-run-refused'],
  ['resealed, a row id that is a number', reseal(payments.before, run => { run.rows[2].id = 7; }), 'payments-run-refused'],
  ['resealed, a row id of 65 characters', reseal(payments.before, run => { run.rows[2].id = 'a'.repeat(65); }), 'payments-run-refused'],
  ['resealed, a row id ending in a newline', reseal(payments.before, run => { run.rows[2].id = `${run.rows[2].id}\n`; }), 'payments-run-refused'],
  ['resealed, a row rule that is a number', reseal(payments.before, run => { run.rows[2].rule = 1; }), 'payments-run-refused'],
  ['resealed, row standards given as text', reseal(payments.before, run => { run.rows[2].standards = 'x'; }), 'payments-run-refused'],
  ['resealed, a row request that is null', reseal(payments.before, run => { run.rows[2].request = null; }), 'payments-run-refused'],
  ['resealed, a row request that is a list', reseal(payments.before, run => { run.rows[2].request = []; }), 'payments-run-refused'],
  ['resealed, a row that is not an object', reseal(payments.before, run => { run.rows[2] = null; }), 'payments-run-refused'],
  ['resealed, a null settlement finding', reseal(payments.before, run => { run.rows[0].settlement = [null]; }), 'payments-run-refused'],
  ['resealed, a passing control whose request reached reads 1', reseal(payments.before, run => { run.rows[0].reach.reached = 1; }), 'payments-run-refused'],
  ['resealed, a passing control whose request reached reads "true"', reseal(payments.before, run => { run.rows[0].reach.reached = 'true'; }), 'payments-run-refused'],
  ['resealed, a failing row with no reach: only a pass needs one', reseal(payments.before, run => { delete run.rows[2].reach; }), 'verified'],
  ['resealed, a passing control whose request never reached the app', reseal(payments.before, run => { run.rows[0].reach = { reached: false, basis: 'The app answered 502.' }; }), 'payments-run-refused'],
  ['resealed, a passing boundary with a settlement finding', reseal(after, run => { run.rows[2].settlement = [{ ...run.rows[0].settlement[0], effect: 'withheld' }]; }), 'payments-run-refused'],
  ['resealed, a control\'s settlement finding marked withheld', reseal(payments.before, run => { run.rows[0].settlement[0].effect = 'withheld'; }), 'payments-run-refused'],
  ['resealed, a finish time Date.parse cannot read', reseal(payments.before, run => { run.finishedAt = 'yesterday'; }), 'payments-run-refused'],
  // Stricter than the pack: its reader takes any time Date.parse reads, which Python cannot match. The pack writes toISOString.
  ['resealed, a start time without milliseconds', reseal(payments.before, run => { run.startedAt = run.startedAt.replace(/\.\d{3}Z$/, 'Z'); }), 'payments-run-refused', 'the pack takes it'],
  ['a file that declares the payments run schema and is no run at all', Buffer.from(JSON.stringify({ schema: PAYMENTS_RUN_SCHEMA })), 'payments-run-refused'],
];
const packTakes = content => { try { savedPaymentsRun(JSON.parse(content.toString('utf8'))); return true; } catch (error) { if (error.code === 'payments-run-refused') return false; throw error; } };

test('payments runs are checked by the pack\'s own rules, in both verifiers, whether or not their identity is named', { timeout: 120000 }, async () => {
  assert.ok(NUMBERS.toString().includes('"pass":2.0e0,') && NUMBERS.toString().includes('"settleMs":1.5e2'));
  const unnamed = PACK_AGREEMENT.map(([, content]) => signedWithoutRuns('payments-run.json', content));
  const node = unnamed.map(([envelope, files]) => nodeSummary(envelope, files));
  for (const [i, [label, content, expected, deviation]] of PACK_AGREEMENT.entries()) {
    assert.equal(node[i].reason ?? node[i].verdict, expected, label);
    assert.equal(packTakes(content), deviation ? true : expected === 'verified', `the pack's reader on: ${label}`);
    if (expected === 'verified') { assert.deepEqual([node[i].runs, node[i].unclaimedRuns], [Buffer.from('[]').toString('hex'), ['payments-run.json']], label); assert.deepEqual(node[i].selfChecks, [], label); }
  }
  // Named by the signer, an accepted run's identity is its own fields; a stored comparison, edited or not, changes no identity.
  const named = PACK_AGREEMENT.filter(([, , expected]) => expected === 'verified').map(([label, content]) => [label, signedAs([['payments-run.json', content]])]);
  for (const [label, [envelope, files]] of named) {
    const result = verifyWith(envelope, files), run = JSON.parse(files.get('payments-run.json'));
    assert.equal(result.verdict, 'verified', label); assert.deepEqual(result.runs, [paymentsIdentity('payments-run.json', run)], label); assert.deepEqual(result.unclaimedRuns, [], label);
  }
  assert.deepEqual(verifyWith(...named[2][1]).runs, [paymentsIdentity('payments-run.json', payments.after)]);
  assert.deepEqual(verifyWith(...named[3][1]).runs, [paymentsIdentity('payments-run.json', payments.before)]);
  if (PYTHON) assert.deepEqual(await pythonBatch([...unnamed, ...named.map(([, signed]) => signed)]), [...node, ...named.map(([, [envelope, files]]) => nodeSummary(envelope, files))]);
});

const MAIN_FIXTURE = name => fileURLToPath(new URL(`./fixtures/payments-main-848cb8a6/${name}`, import.meta.url));
test('an envelope `payments export` signed on an earlier private build, naming no run identity, still verifies in both verifiers', async () => {
  // Made before payments runs had identities: a fresh owned-demo run over loopback (`./scopehaven payments demo`), then
  // `./scopehaven payments export --format json --signing-key-dir DIR` with a throwaway key whose private half was deleted.
  const envelope = await readFile(MAIN_FIXTURE('payments-run.json.dsse.json')), publicPem = await readFile(MAIN_FIXTURE('scopehaven-signing-key.pub.pem'), 'utf8');
  const content = await readFile(MAIN_FIXTURE('payments-run.json')), run = JSON.parse(content), files = new Map([['payments-run.json', content]]);
  const statement = statementOf(envelope);
  assert.deepEqual(statement.predicate.runs, []); assert.equal(statement.predicate.producer.version, '0.7.0'); assert.ok(packTakes(content));
  const result = verifyWith(envelope, files, publicPem);
  assert.equal(result.verdict, 'verified'); assert.deepEqual(result.runs, []); assert.deepEqual(result.unclaimedRuns, ['payments-run.json']);
  assert.match(result.note, /^The statement names no run identity for payments-run\.json\. The signature covers those files' bytes, .* None of this says whether the results are right\.$/);
  assert.deepEqual(result.selfChecks.map(c => [c.id, c.observed]), [...NATIVE_CONTROLS.slice(0, 5), ...PAYMENTS_CONTROLS].map(id => [id, 'rejected']));
  if (PYTHON) {
    const { code, stdout, stderr } = await python([SCRIPT, '--key', MAIN_FIXTURE('scopehaven-signing-key.pub.pem'), '--envelope', MAIN_FIXTURE('payments-run.json.dsse.json'), '--dir', MAIN_FIXTURE('')]);
    const printed = JSON.parse(stdout);
    assert.equal(code, 0, stderr); assert.deepEqual([printed.verdict, printed.runs, printed.unclaimedRuns, printed.note], ['verified', [], ['payments-run.json'], result.note]);
    assert.deepEqual(printed.selfChecks.map(c => [c.id, c.observed]), [...NATIVE_CONTROLS.slice(0, 5), ...PAYMENTS_CONTROLS].map(id => [id, 'rejected']).concat([['rfc8032-test-1', 'accepted']]));
  }
  // It claims less, never something else. The same statement signed with our key verifies naming the recomputed identity, and
  // is rejected naming a wrong one; a run file edited after signing no longer matches its digest.
  const claim = identity => { const copy = structuredClone(statement); copy.predicate.runs = [identity]; return signStatement(copy, KEY.privatePem); };
  const cases = [[envelope, files, publicPem], [claim(paymentsIdentity('payments-run.json', run)), files], [claim({ ...paymentsIdentity('payments-run.json', run), build: 'refund-agent-vulnerable' }), files],
    [envelope, new Map([['payments-run.json', Buffer.from(content.toString().replace('"refund-agent-repaired"', '"refund-agent-vulnerable"'))]]), publicPem]];
  const node = cases.map(c => nodeSummary(...c));
  assert.deepEqual(node.map(n => n.reason ?? n.verdict), ['verified', 'verified', 'run-identity-mismatch', 'subject-digest-mismatch']);
  assert.equal(Buffer.from(node[1].runs, 'hex').toString(), JSON.stringify([paymentsIdentity('payments-run.json', run)]));
  if (PYTHON) assert.deepEqual(await pythonBatch(cases), node);
});

test('both verifiers recompute the same run identities, byte for byte, and the signer named those bytes', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async () => {
  // A run export that also declares the payments run schema is read as a run export, by both.
  const dual = runText(`"schema":"${PAYMENTS_RUN_SCHEMA}","sha256":"${'0'.repeat(64)}"`);
  const cases = [[ENVELOPE, filesMap()], signedAs([['payments-after.json', exported['payments-after.json']]]), signedAs([['saved.json', SAVED_AFTER]]), signedAs([['numbers.json', NUMBERS]]),
    signedAs([['surrogate.json', reseal(payments.before, run => { run.build = 'b\ud800'; })]]), signedAs([['dual.json', dual], ['payments-before.json', exported['payments-before.json']]]),
    // The pack puts no type on a run's name; the payments self-check must still change it.
    signedAs([['unnamed.json', reseal(payments.before, run => { run.name = null; })]]), signedAs([['numbered.json', reseal(payments.before, run => { run.name = 5; })]])];
  const node = cases.map(([envelope, files]) => nodeSummary(envelope, files));
  assert.deepEqual(await pythonBatch(cases), node);
  for (const [i, [envelope]] of cases.entries()) {
    assert.equal(node[i].verdict, 'verified');
    assert.equal(node[i].runs, Buffer.from(JSON.stringify(statementOf(envelope).predicate.runs)).toString('hex'));
  }
  const [dualIdentity, beforeIdentity] = JSON.parse(Buffer.from(node[5].runs, 'hex').toString());
  assert.ok(Object.hasOwn(dualIdentity, 'suiteHash') && !Object.hasOwn(dualIdentity, 'packSha256')); assert.equal(dualIdentity.coreSha256, JSON.parse(dual).integrity.sha256);
  assert.deepEqual(beforeIdentity, paymentsIdentity('payments-before.json', payments.before));
  assert.equal(JSON.parse(Buffer.from(node[4].runs, 'hex').toString())[0].build, 'b\ud800');
});

test('payments export and the evidence pack name the payments run\'s identity, and both verifiers recompute it', { timeout: 60000 }, async t => {
  const root = await scratch(t), keys = join(root, 'keys'), out = join(root, 'out'), pack = join(root, 'pack');
  await mkdir(keys, { mode: 0o700 }); await mkdir(out, { mode: 0o700 });
  await exportPaymentsRun({ run: payments.after, format: 'json', outputFile: join(out, 'run.json'), signingKeyDir: keys });
  const publicPem = await readFile(join(keys, PUBLIC_KEY_FILE), 'utf8'), envelope = await readFile(join(out, 'run.json.dsse.json'));
  const files = new Map([['run.json', await readFile(join(out, 'run.json'))]]), identity = paymentsIdentity('run.json', payments.after);
  assert.deepEqual(statementOf(envelope).predicate.runs, [identity]);
  const result = verifyWith(envelope, files, publicPem);
  assert.equal(result.verdict, 'verified'); assert.deepEqual(result.runs, [identity]); assert.deepEqual(result.unclaimedRuns, []);
  // The pack signs each export beside it and every file in its folder at once; the payments run's identity is named in both.
  await evidencePack({ paymentsRun: payments.before, outputDir: pack, signingKeyDir: keys });
  const inPack = paymentsIdentity('payments-run.json', payments.before);
  for (const name of ['payments-run.json.dsse.json', PACK_ENVELOPE]) assert.deepEqual(statementOf(await readFile(join(pack, name))).predicate.runs, [inPack], name);
  if (PYTHON) {
    const own = await python([SCRIPT, '--key', join(keys, PUBLIC_KEY_FILE), '--envelope', join(out, 'run.json.dsse.json'), '--dir', out]);
    assert.equal(own.code, 0, own.stderr); assert.deepEqual(JSON.parse(own.stdout).runs, [identity]);
    const whole = await python([SCRIPT, '--key', join(keys, PUBLIC_KEY_FILE), '--envelope', join(pack, PACK_ENVELOPE), '--dir', pack]);
    assert.equal(whole.code, 0, whole.stderr); assert.deepEqual(JSON.parse(whole.stdout).runs, [inPack]);
  }
});

test('the verifiers\' payments rules name the pack\'s schema, scope and fields', async () => {
  assert.equal(PAYMENTS_RUN_SCHEMA, PACK_RUN_SCHEMA); assert.equal(PAYMENTS_SCOPE, PACK_SCOPE);
  for (const field of PAYMENTS_RUN_FIELDS) assert.equal(typeof payments.before[field], 'string', field);
  if (!PYTHON) return;
  const program = `import sys, json; sys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('.', import.meta.url)))})
import verify_envelope as v
print(json.dumps([v.PAYMENTS_RUN_SCHEMA, v.PAYMENTS_SCOPE, list(v.PAYMENTS_RUN_FIELDS), list(v.PAYMENTS_KEYS)]))`;
  const { code, stdout, stderr } = await python(['-B', '-c', program]);
  assert.equal(code, 0, stderr);
  // Exactly the fields of a run as the pack writes it.
  assert.deepEqual(JSON.parse(stdout), [PACK_RUN_SCHEMA, PACK_SCOPE, [...PAYMENTS_RUN_FIELDS], Object.keys(after)]);
});

test('a verifier whose payments digest check is broken fails its own negative controls', { timeout: 60000 }, async t => {
  // A copy of each verifier with only the payments run's sha256 comparison removed. Its payments-run-file-edited control must
  // catch that: the edited copy changes the run's name, which no rule but the digest reads.
  const dir = await scratch(t), source = await readFile(new URL('./verify.mjs', import.meta.url), 'utf8');
  const broken = source.replace("if (typeof stated !== 'string' || coreSha256 !== stated) reject(", 'if (false) reject(');
  assert.notEqual(broken, source);
  await writeFile(join(dir, 'verify.mjs'), broken);
  const { verifyEnvelope: brokenVerify } = await import(pathToFileURL(join(dir, 'verify.mjs')).href);
  const [envelope, files] = signedAs([['payments-after.json', exported['payments-after.json']]]);
  const result = brokenVerify({ envelope, publicKey: KEY.publicPem, files });
  assert.equal(result.verdict, 'self-check-failed'); assert.deepEqual(result.selfChecks.filter(c => c.observed === 'accepted').map(c => c.id), ['payments-run-file-edited']);
  assert.equal(verifyWith(envelope, files).verdict, 'verified');
  if (!PYTHON) return;
  const program = `import sys, json; sys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('.', import.meta.url)))})
import verify_envelope as v
original = v._payments_run
def without_digest_check(name, value):
    run = dict((key, item) for key, item in value.items() if key != "comparison")
    return original(name, dict(value, sha256=v._core_digest(name, dict((key, item) for key, item in run.items() if key != "sha256"))))
v._payments_run = without_digest_check
case = json.loads(sys.stdin.read())
result = v.verify_envelope(bytes.fromhex(case["envelope"]), case["key"], {"payments-after.json": bytes.fromhex(case["file"])})
print(json.dumps([result["verdict"], [c["id"] for c in result["selfChecks"] if c["observed"] != c["expected"]]]))`;
  const { code, stdout, stderr } = await python(['-B', '-c', program], JSON.stringify({ envelope: Buffer.from(envelope).toString('hex'), key: KEY.publicPem, file: exported['payments-after.json'].toString('hex') }));
  assert.equal(code, 0, stderr); assert.deepEqual(JSON.parse(stdout), ['self-check-failed', ['payments-run-file-edited']]);
});

test('a run whose notes or stored comparison nest past a parser\'s limits is refused with a reason, never a crash', { timeout: 60000 }, async t => {
  // Notes and a stored comparison are outside the run's checksum, but the negative controls serialize them.
  const deepComparison = depth => Buffer.from(JSON.stringify(payments.after).replace('"comparison":{', `"comparison":{"deep":${nested(depth)},`));
  const deepNotes = depth => { const run = JSON.parse(exported['baseline.json']); run.notes = 'NOTES'; return Buffer.from(JSON.stringify(run).replace('"notes":"NOTES"', `"notes":${nested(depth)}`)); };
  assert.ok(packTakes(deepComparison(600)));
  // Node holds 600 levels and verifies; it refuses 200000 with a reason instead of throwing.
  for (const [label, content, node] of [['comparison 600 deep', deepComparison(600), 'verified'], ['notes 600 deep', deepNotes(600), 'verified'],
    ['comparison 200000 deep', deepComparison(200000), 'subject-unparseable'], ['notes 200000 deep', deepNotes(200000), 'subject-unparseable']]) {
    // A run export's identity must be named; signed without signFiles' self-check, which would refuse the deepest.
    const files = new Map([['deep.json', content]]), envelope = signStatement(buildStatement([{ name: 'deep.json', content }], { version }), KEY.privatePem);
    const result = verifyWith(envelope, files);
    assert.equal(result.reason ?? result.verdict, node, label);
    if (!PYTHON) continue;
    // Python cannot hold either depth: it refuses both, printing a result.
    const { code, result: printed, stderr } = await pythonVerify(t, envelope, files);
    assert.equal(code, 1, `${label}: ${stderr}`); assert.equal(printed?.reason, 'subject-unparseable', label);
  }
});

test('both CLIs print a run identity field beyond a double as null, so their output stays JSON', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async t => {
  // The pack's reader puts no type on build; 1e400 is Infinity in both languages and null in canonical JSON.
  const text = JSON.stringify(payments.before).replace(`"build":"${payments.before.build}"`, '"build":1e400');
  const { sha256: stale, ...body } = JSON.parse(text), content = Buffer.from(text.replace(stale, digest(body)));
  assert.notEqual(text, JSON.stringify(payments.before));
  const [envelope, files] = signedAs([['infinite.json', content]]), node = verifyWith(envelope, files);
  assert.equal(node.verdict, 'verified'); assert.equal(node.runs[0].build, Infinity); assert.equal(JSON.parse(JSON.stringify(node)).runs[0].build, null);
  const { code, result, stderr } = await pythonVerify(t, envelope, files);
  assert.equal(code, 0, stderr); assert.equal(result.runs[0].build, null);
});

test('around the depth where Node stops verifying, every run file gets a verdict, never a throw', { timeout: 180000 }, async t => {
  // The negative controls serialize a run again. At no depth may that overflow the stack where the first check did not.
  const deepComparison = depth => Buffer.from(JSON.stringify(payments.after).replace('"comparison":{', `"comparison":{"deep":${nested(depth)},`));
  const deepRuns = {
    'a stored comparison': depth => signedWithoutRuns('deep.json', deepComparison(depth)),
    'run export notes': depth => {
      const run = JSON.parse(exported['baseline.json']); run.notes = 'NOTES';
      const content = Buffer.from(JSON.stringify(run).replace('"notes":"NOTES"', `"notes":${nested(depth)}`));
      return [signStatement(buildStatement([{ name: 'deep.json', content }], { version }), KEY.privatePem), new Map([['deep.json', content]])];
    },
  };
  const library = make => depth => {
    const [envelope, files] = make(depth);
    try { const result = verifyWith(envelope, files); return result.verdict === 'verified' ? 'verified' : result.reason; } catch (error) { return `threw ${error.name}`; }
  };
  const dir = await scratch(t);
  await writeFile(join(dir, 'key.pub.pem'), KEY.publicPem);
  const cli = async depth => {
    const [envelope, files] = deepRuns['a stored comparison'](depth);
    await writeFile(join(dir, 'envelope.json'), envelope); await writeFile(join(dir, 'deep.json'), files.get('deep.json'));
    const { code, output } = await main(['verify', '--key', join(dir, 'key.pub.pem'), '--envelope', join(dir, 'envelope.json'), '--dir', dir]);
    return code === 0 ? 'verified' : code === 1 ? output.reason : `exit ${code} ${output.error ?? ''}`;
  };
  for (const [label, outcome] of [['library, a stored comparison', library(deepRuns['a stored comparison'])], ['library, run export notes', library(deepRuns['run export notes'])], ['CLI, a stored comparison', cli]]) {
    let low = 100, high = 400000;
    assert.equal(await outcome(low), 'verified', label); assert.notEqual(await outcome(high), 'verified', label);
    while (high - low > 1) { const mid = (low + high) >> 1; if (await outcome(mid) === 'verified') low = mid; else high = mid; }
    for (let depth = low - 10; depth <= low + 10; depth++) {
      const seen = await outcome(depth);
      assert.ok(['verified', 'subject-unparseable'].includes(seen), `${label} at depth ${depth} (Node stops verifying near ${high}): ${seen}`);
    }
  }
});

test('a payments run with an all-digit key past 4300 digits verifies in both verifiers, and a 10-digit index key orders as an index in both', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async () => {
  const longKey = '9'.repeat(4301);
  // In the stored comparison (outside the checksum) and in a row's request (inside it, resealed over what JavaScript reads).
  const inComparison = Buffer.from(JSON.stringify({ ...payments.after, comparison: { ...payments.after.comparison, [longKey]: 1 } }));
  const inRequest = reseal(payments.before, run => { run.rows[0].request[longKey] = 1; run.rows[0].request['4294967294'] = 2; });
  const cases = [signedAs([['long-key-comparison.json', inComparison]]), signedAs([['long-key-request.json', inRequest]])];
  const node = cases.map(([envelope, files]) => nodeSummary(envelope, files));
  assert.deepEqual(node.map(n => n.verdict), ['verified', 'verified']);
  assert.deepEqual(await pythonBatch(cases), node);
  for (const [i, [envelope]] of cases.entries()) assert.equal(node[i].runs, Buffer.from(JSON.stringify(statementOf(envelope).predicate.runs)).toString('hex'));
  // Key order, as JavaScript keeps it: an array index (at most 10 digits, below 2**32 - 1) first in numeric order, then every
  // other key in insertion order, the 4301-digit one included.
  const text = `{"b":1,"4294967294":2,"4294967295":3,"10000000000":4,"1":5,"${longKey}":6,"01":7}`;
  const program = `import sys, json; sys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('.', import.meta.url)))})
import verify_envelope as v
sys.stdout.write(v._js_json(json.loads(sys.stdin.read())))`;
  const { code, stdout, stderr } = await python(['-B', '-c', program], text);
  assert.equal(code, 0, stderr);
  assert.equal(stdout, JSON.stringify(JSON.parse(text)));
  assert.ok(stdout.startsWith('{"1":5,"4294967294":2,"b":1,"4294967295":3,"10000000000":4,'), stdout.slice(0, 80));
});
