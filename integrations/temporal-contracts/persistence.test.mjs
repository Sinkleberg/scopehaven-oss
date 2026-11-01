import test, { before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, rm, chmod, lstat, readFile, writeFile, symlink, mkdir, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { stable } from '../../src/domain.mjs';
import { runRefundAssessment, currentRefundSuite } from './runner.mjs';
import { createResultSigner, publicKeyFingerprint, verifySignedRun, writeFinalizedRun, readFinalizedRun, isVerifiedRun } from './persistence.mjs';

let run, expectedSuite, signer, envelope;
before(async () => {
  // This is the actual owned loopback HTTP workflow and private evaluator brand.
  // No serialized record or test override can create a signer-accepted Run.
  run = await runRefundAssessment('refund-clean');
  expectedSuite = await currentRefundSuite('refund-clean');
  signer = createResultSigner(); envelope = signer.signRun(run);
});
const options = () => ({ publicKey: signer.publicKey, expectedPublicKeyFingerprint: signer.publicKeyFingerprint, expectedSuite, expectedRunId: run.id });
const copy = value => JSON.parse(JSON.stringify(value));
const coded = code => error => error?.code === code;

async function directory(t) {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-refund-persistence-'));
  await chmod(dir, 0o700); t.after(() => rm(dir, { recursive: true, force: true })); return dir;
}

// Deliberately malformed records are signed with an independent test-only key to
// exercise structural verification after a cryptographically valid signature.
// This does not call or override the trusted live writer/finalization boundary.
function signedMutation(mutate, original = run) {
  const altered = copy(original); mutate(altered);
  const keys = generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  return { envelope: { schema: 'scopehaven-refund-signed-run/1', run: altered,
    signature: sign(null, Buffer.from(stable({ schema: 'scopehaven-refund-signed-run/1', run: altered })), keys.privateKey).toString('base64url') },
  publicKey, expectedPublicKeyFingerprint: publicKeyFingerprint(publicKey) };
}

test('live evaluator-finalized clean run signs and verifies with external expectations', () => {
  assert.equal(run.counts.pass, expectedSuite.checks.length);
  const verified = verifySignedRun(copy(envelope), options());
  assert.deepEqual(verified, run);
  assert.equal(isVerifiedRun(verified), true); assert.equal(isVerifiedRun(copy(verified)), false);
  assert.equal(isVerifiedRun(run), false); assert.equal(isVerifiedRun(null), false);
  assert.ok(Object.isFrozen(envelope)); assert.ok(Object.isFrozen(envelope.run.results));
  assert.equal(Object.hasOwn(envelope, 'publicKey'), false);
  assert.throws(() => signer.signRun(copy(run)), coded('refund-run-not-live-finalized'));
  assert.throws(() => signer.signRun({ finalized: true }), coded('refund-run-not-live-finalized'));
});

test('signature detects result edits, key substitution and adjacent self-authentication', () => {
  const changed = copy(envelope); changed.run.results[0].status = 'fail';
  assert.throws(() => verifySignedRun(changed, options()), coded('refund-signature-invalid'));
  assert.throws(() => verifySignedRun(envelope, { ...options(), publicKey: createResultSigner().publicKey }), coded('refund-trust-key-fingerprint-mismatch'));
  assert.throws(() => verifySignedRun({ ...copy(envelope), publicKey: signer.publicKey }, options()), coded('invalid-refund-signed-envelope'));
  assert.throws(() => verifySignedRun(envelope, { expectedSuite, expectedRunId: run.id }), coded('missing-refund-trusted-public-key'));
  assert.throws(() => verifySignedRun(envelope), coded('missing-refund-trusted-expectations'));
});

test('operator-held fingerprint is mandatory and cannot be supplied by the result', () => {
  const { expectedPublicKeyFingerprint, ...unpinned } = options();
  assert.throws(() => verifySignedRun(envelope, unpinned), coded('missing-refund-trusted-key-fingerprint'));
  for (const value of ['', 'invalid', 'A'.repeat(64), null]) {
    assert.throws(() => verifySignedRun(envelope, { ...options(), expectedPublicKeyFingerprint: value }), coded('invalid-refund-trusted-key-fingerprint'));
  }
  assert.throws(() => verifySignedRun({ ...copy(envelope), publicKeyFingerprint: expectedPublicKeyFingerprint }, unpinned),
    coded('missing-refund-trusted-key-fingerprint'));
});

test('all-pass forgery signed by an attacker cannot substitute its key for the operator pin', async () => {
  const failing = await runRefundAssessment('refund-duplicate-effect');
  const suite = await currentRefundSuite(failing.targetId);
  assert.ok(failing.counts.fail > 0);
  const forged = signedMutation(value => {
    value.results.forEach(result => { result.status = 'pass'; });
    value.refundAdjudication.results.forEach(result => { result.status = 'pass'; });
    value.counts = { pass: value.results.length, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 };
    value.refundAdjudication.horizon.closed = true;
    value.refundAdjudication.horizon.pending = 0;
    value.refundAdjudication.evidenceSummary.coverage = 'complete';
    value.refundAdjudication.evidenceSummary.problems = [];
  }, failing);
  const expected = { ...options(), expectedSuite: suite, expectedRunId: failing.id, publicKey: forged.publicKey };
  assert.throws(() => verifySignedRun(forged.envelope, expected),
    coded('refund-trust-key-fingerprint-mismatch'));
  // Only an explicit independent trust decision admitting the attacker key can
  // accept it; possession of a valid signature never establishes operator trust.
  assert.equal(verifySignedRun(forged.envelope, { ...expected,
    expectedPublicKeyFingerprint: forged.expectedPublicKeyFingerprint }).counts.pass, suite.checks.length);
});

test('verification freezes nested results even when input run is already shallow-frozen', () => {
  const supplied = copy(envelope); Object.freeze(supplied.run);
  const verified = verifySignedRun(supplied, options());
  assert.notEqual(verified, supplied.run);
  assert.equal(isVerifiedRun(verified), true); assert.equal(Object.isFrozen(verified.results[0]), true);
  assert.equal(Object.isFrozen(verified.refundAdjudication.results[0].reasons), true);
  assert.throws(() => { verified.results[0].status = 'fail'; }, TypeError);
});

const malformed = [
  ['empty checks', value => { value.results = []; value.refundAdjudication.results = []; value.refundAdjudication.requiredCheckIds = []; value.checksTotal = 0; }, 'refund-required-checks-mismatch'],
  ['omitted required check', value => { value.results.pop(); value.refundAdjudication.results.pop(); value.checksTotal--; }, 'refund-required-checks-mismatch'],
  ['duplicate check', value => { value.results[1] = value.results[0]; value.refundAdjudication.results[1] = value.refundAdjudication.results[0]; }, 'refund-required-checks-mismatch'],
  ['omitted required id', value => value.refundAdjudication.requiredCheckIds.pop(), 'refund-required-checks-mismatch'],
  ['unknown status', value => { value.refundAdjudication.results[0].status = 'complete'; value.results[0].status = 'complete'; }, 'invalid-refund-check-result'],
  ['unfinished adjudication', value => { value.refundAdjudication.finalized = false; }, 'refund-run-not-finalized'],
  ['wrong producer', value => { value.refundAdjudication.producer = 'app-self-reported'; }, 'refund-run-not-finalized'],
  ['contract mismatch', value => { value.refundAdjudication.contractHash = '0'.repeat(64); }, 'refund-adjudication-identity-mismatch'],
  ['run mismatch', value => { value.id = 'different-run'; }, 'refund-run-identity-mismatch'],
  ['target mismatch', value => { value.targetId = 'different-target'; }, 'refund-run-identity-mismatch'],
  ['build mismatch', value => { value.targetBuildHash = '0'.repeat(64); }, 'refund-run-identity-mismatch'],
  ['evaluator mismatch', value => { value.evaluatorHash = '0'.repeat(64); }, 'refund-run-identity-mismatch'],
  ['version mismatch', value => { value.suiteVersion = 'refund-lifecycle/0'; }, 'refund-run-identity-mismatch'],
  ['identity mismatch', value => { value.refundAdjudication.identity.runId = 'different-run'; }, 'refund-adjudication-identity-mismatch'],
  ['shortened horizon', value => { value.refundAdjudication.horizon.deadlineMs--; }, 'refund-horizon-mismatch'],
  ['passing incomplete horizon', value => { value.refundAdjudication.horizon.closed = false; }, 'refund-passing-horizon-incomplete'],
  ['passing pending horizon', value => { value.refundAdjudication.horizon.pending = 1; }, 'refund-passing-horizon-incomplete'],
  ['passing unsealed horizon', value => { value.refundAdjudication.horizon.sealed = false; }, 'refund-passing-horizon-incomplete'],
  ['passing incomplete coverage', value => { value.refundAdjudication.evidenceSummary.coverage = 'incomplete'; }, 'refund-passing-evidence-incomplete'],
  ['passing missing problems', value => { delete value.refundAdjudication.evidenceSummary.problems; }, 'refund-passing-evidence-incomplete'],
  ['passing unresolved evidence problem', value => { value.refundAdjudication.evidenceSummary.problems = ['source-gap']; }, 'refund-passing-evidence-incomplete'],
  ['passing missing timing', value => { delete value.refundAdjudication.evidenceSummary.timing; }, 'refund-passing-timing-incomplete'],
  ['passing missing clock', value => { delete value.refundAdjudication.evidenceSummary.timing.clockId; }, 'refund-passing-timing-incomplete'],
  ['passing blank clock', value => { value.refundAdjudication.evidenceSummary.timing.clockId = ' '; }, 'refund-passing-timing-incomplete'],
  ['passing nonnumeric clock time', value => { value.refundAdjudication.evidenceSummary.timing.startedAtMs = null; }, 'refund-passing-timing-incomplete'],
  ['passing negative clock time', value => { value.refundAdjudication.evidenceSummary.timing.startedAtMs = -1; }, 'refund-passing-timing-incomplete'],
  ['passing missing closure time', value => { delete value.refundAdjudication.evidenceSummary.timing.closedAtMs; }, 'refund-passing-timing-incomplete'],
  ['passing reversed timing', value => { value.refundAdjudication.evidenceSummary.timing.closedAtMs = value.refundAdjudication.evidenceSummary.timing.startedAtMs - 1; }, 'refund-passing-timing-incomplete'],
  ['wrong check kind', value => { value.refundAdjudication.results[0].kind = 'effect-count'; }, 'invalid-refund-check-result'],
  ['standard result disagrees', value => { value.results[0].status = 'inconclusive'; }, 'refund-standard-results-mismatch'],
  ['lineage disagrees', value => { value.results[0].effectIds = ['invented-effect']; }, 'refund-standard-results-mismatch'],
  ['duplicate lineage id', value => { value.refundAdjudication.results[0].effectIds = ['a', 'a']; }, 'invalid-refund-check-result'],
  ['counts disagree', value => { value.counts.pass--; }, 'refund-result-counts-mismatch'],
  ['authority content changed', value => { value.refundAdjudication.evidenceSummary.instructions[0].amount++; }, 'refund-authority-content-mismatch'],
  ['authority identity changed', value => { value.refundAdjudication.evidenceSummary.instructions[0].authorityId = 'different-authority'; }, 'refund-authority-content-mismatch'],
  ['principal identity changed', value => { value.refundAdjudication.evidenceSummary.instructions[0].principalId = 'old-principal'; }, 'refund-authority-content-mismatch'],
  ['tenant identity changed', value => { value.refundAdjudication.evidenceSummary.instructions[0].tenantId = 'old-tenant'; }, 'refund-authority-content-mismatch'],
  ['charge identity changed', value => { value.refundAdjudication.evidenceSummary.instructions[0].chargeId = 'old-charge'; }, 'refund-authority-content-mismatch'],
  ['instruction binding changed', value => { value.results[2].instructionIds = ['other']; value.refundAdjudication.results[2].instructionIds = ['other']; }, 'refund-check-instructions-mismatch'],
  ['run contract hash changed', value => { value.refundAdjudication.runContractHash = '0'.repeat(64); }, 'refund-run-contract-hash-mismatch'],
];
for (const [name, mutate, code] of malformed) test(`valid signature cannot admit ${name}`, () => {
  const altered = signedMutation(mutate);
  assert.throws(() => verifySignedRun(altered.envelope, { ...options(), publicKey: altered.publicKey,
    expectedPublicKeyFingerprint: altered.expectedPublicKeyFingerprint }), coded(code));
});

test('source closure after the completion deadline does not itself invalidate a passing record', () => {
  const altered = signedMutation(value => {
    value.refundAdjudication.horizon.sealed = true;
    value.refundAdjudication.evidenceSummary.timing.closedAtMs = value.refundAdjudication.evidenceSummary.timing.startedAtMs + expectedSuite.horizon.deadlineMs + 100;
  });
  assert.equal(verifySignedRun(altered.envelope, { ...options(), publicKey: altered.publicKey,
    expectedPublicKeyFingerprint: altered.expectedPublicKeyFingerprint }).counts.pass, expectedSuite.checks.length);
});

test('finalized non-passing records can retain missing timing and incomplete/problematic evidence', () => {
  const altered = signedMutation(value => {
    for (const results of [value.results, value.refundAdjudication.results]) results[0].status = 'inconclusive';
    value.counts.pass--; value.counts.inconclusive++;
    value.refundAdjudication.horizon.closed = false;
    delete value.refundAdjudication.evidenceSummary.timing;
    value.refundAdjudication.evidenceSummary.coverage = 'incomplete';
    value.refundAdjudication.evidenceSummary.problems = ['source-gap'];
  });
  assert.equal(verifySignedRun(altered.envelope, { ...options(), publicKey: altered.publicKey,
    expectedPublicKeyFingerprint: altered.expectedPublicKeyFingerprint }).counts.inconclusive, 1);
});

test('external expected check set and identities cannot be taken from the result', () => {
  for (const changed of [
    { ...expectedSuite, checks: [] },
    { ...expectedSuite, checks: [...expectedSuite.checks, expectedSuite.checks[0]] },
    { ...expectedSuite, targetId: 'another-target' },
    { ...expectedSuite, buildHash: '1'.repeat(64) },
    { ...expectedSuite, evaluatorHash: '1'.repeat(64) },
    { ...expectedSuite, hash: '1'.repeat(64) },
    { ...expectedSuite, authorityTemplate: expectedSuite.authorityTemplate.map((a, i) => i === 0 ? { ...a, principalRole: 'control' } : a) },
    { ...expectedSuite, authorityTemplate: expectedSuite.authorityTemplate.map((a, i) => i === 0 ? { ...a, tenantRole: 'control' } : a) },
    { ...expectedSuite, authorityTemplate: expectedSuite.authorityTemplate.map((a, i) => i === 0 ? { ...a, chargeRole: 'different' } : a) },
    { ...expectedSuite, horizon: { ...expectedSuite.horizon, id: 'another-horizon' } },
  ]) assert.throws(() => verifySignedRun(envelope, { ...options(), expectedSuite: changed }));
  assert.throws(() => verifySignedRun(envelope, { ...options(), expectedRunId: 'another-run' }), coded('refund-run-identity-mismatch'));
});

test('freshness rejects expired and future results using external clock/policy', () => {
  const created = Date.parse(run.createdAt);
  assert.equal(verifySignedRun(envelope, { ...options(), now: created + 1000, maxAgeMs: 1000 }).id, run.id);
  assert.throws(() => verifySignedRun(envelope, { ...options(), now: created + 1001, maxAgeMs: 1000 }), coded('refund-result-stale'));
  assert.throws(() => verifySignedRun(envelope, { ...options(), now: created - 1 }), coded('refund-result-stale'));
  assert.throws(() => verifySignedRun(envelope, { ...options(), maxAgeMs: -1 }), coded('invalid-refund-freshness-policy'));
});

test('exclusive mode-0600 durable write reloads without accepting copied envelopes', async t => {
  const dir = await directory(t), file = join(dir, 'finalized.json');
  const published = await writeFinalizedRun(file, envelope); assert.equal(published, await realpath(file));
  assert.equal((await lstat(file)).mode & 0o7777, 0o600);
  assert.deepEqual(await readFinalizedRun(file, options()), run);
  const content = await readFile(file, 'utf8');
  await assert.rejects(writeFinalizedRun(file, envelope), coded('refund-result-already-exists'));
  assert.equal(await readFile(file, 'utf8'), content);
  await assert.rejects(writeFinalizedRun(join(dir, 'copy.json'), copy(envelope)), coded('refund-envelope-not-live-signed'));
});

test('file reads reject symlinks, non-private/oversized/malformed files and unsafe directories', async t => {
  const dir = await directory(t), file = join(dir, 'finalized.json'); await writeFinalizedRun(file, envelope);
  const linked = join(dir, 'symlink.json'); await symlink(file, linked);
  await assert.rejects(readFinalizedRun(linked, options()));
  await assert.rejects(writeFinalizedRun(linked, envelope), coded('refund-result-already-exists'));
  await chmod(file, 0o644); await assert.rejects(readFinalizedRun(file, options()), coded('unsafe-refund-result-file')); await chmod(file, 0o600);
  const large = join(dir, 'large.json'); await writeFile(large, ' '.repeat(2 * 1024 * 1024 + 1), { mode: 0o600 });
  await assert.rejects(readFinalizedRun(large, options()), coded('unsafe-refund-result-file'));
  const invalid = join(dir, 'invalid.json'); await writeFile(invalid, '{unfinished', { mode: 0o600 });
  await assert.rejects(readFinalizedRun(invalid, options()), coded('invalid-refund-result-json'));
  const subdirectory = join(dir, 'directory.json'); await mkdir(subdirectory, { mode: 0o700 });
  await assert.rejects(readFinalizedRun(subdirectory, options()), coded('unsafe-refund-result-file'));
  const linkdir = join(dir, 'linked-dir'); await symlink(dir, linkdir);
  await assert.rejects(readFinalizedRun(join(linkdir, 'finalized.json'), options()), coded('unsafe-refund-result-directory'));
  await chmod(dir, 0o755); await assert.rejects(readFinalizedRun(file, options()), coded('unsafe-refund-result-directory'));
  await assert.rejects(writeFinalizedRun(join(dir, 'another.json'), envelope), coded('unsafe-refund-result-directory')); await chmod(dir, 0o700);
});

test('JSON persistence verifies in a fresh process with separately supplied trusted inputs', async t => {
  const dir = await directory(t), file = join(dir, 'finalized.json'); await writeFinalizedRun(file, envelope);
  const moduleURL = new URL('./persistence.mjs', import.meta.url).href;
  const script = `import { readFinalizedRun } from ${JSON.stringify(moduleURL)};
    const [file,options]=process.argv.slice(1); const run=await readFinalizedRun(file,JSON.parse(options));
    process.stdout.write(JSON.stringify({id:run.id,pass:run.counts.pass}));`;
  const env = { ...process.env }; delete env.SCOPEHAVEN_PG_LIVE; delete env.SCOPEHAVEN_MYSQL_LIVE;
  const child = spawn(process.execPath, ['--input-type=module', '-e', script, file, JSON.stringify(options())], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = ''; child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', data => { stdout += data; }); child.stderr.on('data', data => { stderr += data; });
  const status = await new Promise((resolve, reject) => { child.on('error', reject); child.on('close', resolve); });
  assert.equal(status, 0, stderr); assert.deepEqual(JSON.parse(stdout), { id: run.id, pass: expectedSuite.checks.length });
});

test('legitimate finalized inconclusive runs with incomplete horizons remain durable and non-passing', async t => {
  const unfinished = await runRefundAssessment('refund-never-completing');
  const suite = await currentRefundSuite('refund-never-completing'), signed = signer.signRun(unfinished);
  assert.ok(unfinished.counts.inconclusive > 0); assert.equal(unfinished.refundAdjudication.horizon.closed, false);
  const dir = await directory(t), file = join(dir, 'inconclusive.json'); await writeFinalizedRun(file, signed);
  const restored = await readFinalizedRun(file, { publicKey: signer.publicKey,
    expectedPublicKeyFingerprint: signer.publicKeyFingerprint, expectedSuite: suite, expectedRunId: unfinished.id });
  assert.ok(restored.counts.inconclusive > 0); assert.equal(restored.refundAdjudication.horizon.closed, false);
});
