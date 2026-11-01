// Cryptography and disposable local files only; no provider/model/database calls.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createResultSigner, publicKeyFingerprint, readTrustedPublicKey } from './persistence.mjs';

const signer = createResultSigner();
const coded = code => error => error?.code === code;

async function workspace(t) {
  const root = await mkdtemp(join(tmpdir(), 'scopehaven-refund-key-trust-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const output = join(root, 'gate-output'), results = join(output, 'signed-results');
  await mkdir(results, { recursive: true, mode: 0o700 });
  return { root, output, results, resultFile: join(results, 'run.json') };
}
const options = resultFile => ({ resultFile, expectedPublicKeyFingerprint: signer.publicKeyFingerprint });
async function keyFile(file, publicKey = signer.publicKey) {
  await writeFile(file, publicKey, { mode: 0o600 });
  return file;
}

test('fingerprint is canonical Ed25519 SPKI sha256 and independent of PEM line endings', () => {
  const expected = createHash('sha256').update(createPublicKey(signer.publicKey).export({ format: 'der', type: 'spki' })).digest('hex');
  assert.equal(signer.publicKeyFingerprint, expected);
  assert.equal(publicKeyFingerprint(signer.publicKey), expected);
  assert.equal(publicKeyFingerprint(signer.publicKey.replaceAll('\n', '\r\n')), expected);
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'pem', type: 'spki' }).toString();
  assert.throws(() => publicKeyFingerprint(rsa), coded('invalid-refund-trusted-public-key'));
});

test('separately pinned external key loads from outside the complete gate result tree', async t => {
  const { root, resultFile } = await workspace(t);
  const file = await keyFile(join(root, 'operator-public.pem'));
  assert.equal(await readTrustedPublicKey(file, options(resultFile)), signer.publicKey);
});

test('attacker key cannot replace an external key while the operator fingerprint stays pinned', async t => {
  const { root, resultFile } = await workspace(t);
  const file = await keyFile(join(root, 'attacker-public.pem'), createResultSigner().publicKey);
  await assert.rejects(readTrustedPublicKey(file, options(resultFile)), coded('refund-trust-key-fingerprint-mismatch'));
});

test('key reader requires the separately supplied operator fingerprint', async t => {
  const { root, resultFile } = await workspace(t);
  const file = await keyFile(join(root, 'operator-public.pem'));
  await assert.rejects(readTrustedPublicKey(file, { resultFile }), coded('missing-refund-trusted-key-fingerprint'));
});

test('a matching key inside signed results, its parent output, or output subtrees is refused', async t => {
  const { output, results, resultFile } = await workspace(t);
  const nested = join(output, 'notes'); await mkdir(nested, { mode: 0o700 });
  for (const directory of [results, output, nested]) {
    const file = await keyFile(join(directory, 'public.pem'));
    await assert.rejects(readTrustedPublicKey(file, options(resultFile)), coded('refund-trust-key-must-be-external'));
  }
});

test('resolved key directories cannot alias a key within the saved result tree', async t => {
  const { root, results, resultFile } = await workspace(t);
  await keyFile(join(results, 'public.pem'));
  const alias = join(root, 'outside-alias'); await symlink(results, alias);
  await assert.rejects(readTrustedPublicKey(join(alias, 'public.pem'), options(resultFile)), coded('refund-trust-key-must-be-external'));
});

test('a key symlink outside results cannot point into the saved result tree', async t => {
  const { root, results, resultFile } = await workspace(t);
  const inside = await keyFile(join(results, 'public.pem')), outside = join(root, 'outside.pem');
  await symlink(inside, outside);
  await assert.rejects(readTrustedPublicKey(outside, options(resultFile)), coded('refund-trust-key-must-be-external'));
});

test('an inside key symlink cannot escape the lexical saved result tree', async t => {
  const { root, results, resultFile } = await workspace(t);
  const outside = await keyFile(join(root, 'operator.pem')), inside = join(results, 'alias.pem');
  await symlink(outside, inside);
  await assert.rejects(readTrustedPublicKey(inside, options(resultFile)), coded('refund-trust-key-must-be-external'));
});

test('resolved result-directory aliases retain the whole gate output boundary', async t => {
  const { root, output, results } = await workspace(t);
  const file = await keyFile(join(output, 'public.pem')), alias = join(root, 'result-alias');
  await symlink(results, alias);
  await assert.rejects(readTrustedPublicKey(file, options(join(alias, 'run.json'))), coded('refund-trust-key-must-be-external'));
});

test('generic saved result trees permit a real sibling with a similar path prefix', async t => {
  const { root } = await workspace(t), results = join(root, 'records'), sibling = join(root, 'records-trusted');
  await mkdir(results, { mode: 0o700 }); await mkdir(sibling, { mode: 0o700 });
  const inside = await keyFile(join(results, 'public.pem')), outside = await keyFile(join(sibling, 'public.pem'));
  const expected = options(join(results, 'run.json'));
  await assert.rejects(readTrustedPublicKey(inside, expected), coded('refund-trust-key-must-be-external'));
  assert.equal(await readTrustedPublicKey(outside, expected), signer.publicKey);
});

test('unbounded, non-regular, malformed and non-Ed25519 external key files are refused', async t => {
  const { root, resultFile } = await workspace(t), expected = options(resultFile);
  const oversized = await keyFile(join(root, 'oversized.pem'), `${signer.publicKey}${' '.repeat(4096)}`);
  await assert.rejects(readTrustedPublicKey(oversized, expected), coded('refund-trust-key-invalid'));
  const directory = join(root, 'directory.pem'); await mkdir(directory, { mode: 0o700 });
  await assert.rejects(readTrustedPublicKey(directory, expected), coded('refund-trust-key-invalid'));
  const invalid = await keyFile(join(root, 'invalid.pem'), 'invalid');
  await assert.rejects(readTrustedPublicKey(invalid, expected), coded('missing-refund-trusted-public-key'));
  const wrongAlgorithm = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'pem', type: 'spki' }).toString();
  await assert.rejects(readTrustedPublicKey(await keyFile(join(root, 'ec.pem'), wrongAlgorithm), expected), coded('invalid-refund-trusted-public-key'));
});
